import Foundation
import CoreGraphics

/// Wraps the private CGVirtualDisplay API: makes macOS believe a real monitor
/// is attached. Sized in points at HiDPI (@2x), so a phone with native pixels
/// W×H gets a virtual display of (W/2)×(H/2) points backed by a W×H framebuffer.
final class VirtualDisplay {

    private let display: CGVirtualDisplay
    let pointsWide: Int
    let pointsHigh: Int

    var displayID: CGDirectDisplayID { display.displayID }

    /// Must be called on the main thread. `serialNum` must be unique per
    /// concurrent display AND stable per device — macOS keys saved display
    /// arrangement on vendor/product/serial, so a stable serial means each
    /// device keeps its position in System Settings across sessions.
    init?(name: String, pointsWide: Int, pointsHigh: Int, sizeInMillimeters: CGSize,
          serialNum: UInt32 = 0x0001) {
        self.pointsWide = pointsWide
        self.pointsHigh = pointsHigh

        let descriptor = CGVirtualDisplayDescriptor()
        descriptor.setDispatchQueue(DispatchQueue.main)
        descriptor.name = name
        descriptor.maxPixelsWide = UInt32(pointsWide * 2)
        descriptor.maxPixelsHigh = UInt32(pointsHigh * 2)
        descriptor.sizeInMillimeters = sizeInMillimeters
        descriptor.productID = 0x4F53   // "OS"
        descriptor.vendorID = 0x5043    // "PC"
        descriptor.serialNum = serialNum
        descriptor.terminationHandler = { _, _ in
            Log.info("virtual display terminated by the system")
        }

        display = CGVirtualDisplay(descriptor: descriptor)

        let settings = CGVirtualDisplaySettings()
        settings.hiDPI = 1
        settings.modes = [
            CGVirtualDisplayMode(width: UInt(pointsWide), height: UInt(pointsHigh), refreshRate: 60)
        ]
        guard display.apply(settings) else {
            Log.info("CGVirtualDisplay applySettings FAILED")
            return nil
        }
        Log.info("virtual display created: id=\(display.displayID) \(pointsWide)x\(pointsHigh)pt @2x")

        // macOS defaults the new display to its 1x mode; explicitly select the
        // HiDPI (@2x) variant so UI renders at Retina sharpness. The mode list
        // populates asynchronously after applySettings, so retry briefly.
        Task { @MainActor [weak self] in
            for _ in 0..<10 {
                if self?.selectHiDPIMode() == true { return }
                try? await Task.sleep(for: .milliseconds(200))
            }
            Log.info("HiDPI mode never appeared — staying at 1x")
        }
    }

    @discardableResult
    private func selectHiDPIMode() -> Bool {
        let opts = [kCGDisplayShowDuplicateLowResolutionModes: kCFBooleanTrue] as CFDictionary
        guard let modes = CGDisplayCopyAllDisplayModes(display.displayID, opts) as? [CGDisplayMode],
              let hidpi = modes.first(where: {
                  $0.width == pointsWide && $0.pixelWidth == pointsWide * 2
              }) else {
            return false
        }
        if let current = CGDisplayCopyDisplayMode(display.displayID),
           current.width == hidpi.width, current.pixelWidth == hidpi.pixelWidth {
            Log.info("HiDPI mode already active")
            return true
        }
        var config: CGDisplayConfigRef?
        CGBeginDisplayConfiguration(&config)
        CGConfigureDisplayWithDisplayMode(config, display.displayID, hidpi, nil)
        let err = CGCompleteDisplayConfiguration(config, .permanently)
        Log.info("HiDPI mode selected: \(hidpi.width)x\(hidpi.height)@2x (result \(err.rawValue))")
        return err == .success
    }
}
