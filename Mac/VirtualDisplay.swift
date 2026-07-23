import Foundation
import CoreGraphics

/// Wraps the private CGVirtualDisplay API: makes macOS believe a real monitor
/// is attached. Sized in points at HiDPI (@2x), so a phone with native pixels
/// W×H gets a virtual display of (W/2)×(H/2) points backed by a W×H framebuffer.

final class VirtualDisplay {
    /// Limits display dimensions before they reach the private CoreGraphics API.
    /// 32K pixels is already beyond currently practical capture/encode surfaces.
    static let maximumPixelsPerAxis = 32_768
    /// 8K UHD is the largest practical virtual capture surface (four 4K frames);
    /// this prevents a narrow but enormous surface from exhausting WindowServer.
    static let maximumTotalPixels = 7_680 * 4_320

    private static func fitsPixelBudget(width: Int, height: Int, budget: Int) -> Bool {
        width > 0 && height <= budget / width
    }

    static func acceptsPixelGeometry(width: Int, height: Int) -> Bool {
        width >= 2 && height >= 2
            && width <= maximumPixelsPerAxis && height <= maximumPixelsPerAxis
            && fitsPixelBudget(width: width, height: height, budget: maximumTotalPixels)
    }

    static func acceptsPointGeometry(width: Int, height: Int) -> Bool {
        width > 0 && height > 0
            && width <= maximumPixelsPerAxis / 2 && height <= maximumPixelsPerAxis / 2
            // The display is @2x, so validate the native pixel budget without
            // multiplying pointsWide * pointsHigh * 4.
            && width <= maximumTotalPixels / 4 / height
    }

    static func performConfiguration<Transaction>(
        begin: () -> (CGError, Transaction?),
        configure: (Transaction) -> CGError,
        complete: (Transaction) -> CGError,
        cancel: (Transaction) -> Void
    ) -> Bool {
        let (beginResult, transaction) = begin()
        guard beginResult == .success, let transaction else { return false }
        var completed = false
        defer {
            if !completed {
                cancel(transaction)
            }
        }
        guard configure(transaction) == .success else { return false }
        guard complete(transaction) == .success else { return false }
        completed = true
        return true
    }

    static func matchesHiDPIGeometry(pointsWide: Int, pointsHigh: Int,
                                     modeWidth: Int, modeHeight: Int,
                                     pixelWidth: Int, pixelHeight: Int) -> Bool {
        modeWidth == pointsWide && modeHeight == pointsHigh
            && pixelWidth == pointsWide * 2 && pixelHeight == pointsHigh * 2
    }


    private let display: CGVirtualDisplay
    private let settings: CGVirtualDisplaySettings
    let pointsWide: Int
    let pointsHigh: Int
    /// The refresh rate the display actually runs at — the requested rate
    /// when macOS accepted it, 60 when it fell back. The sender paces the
    /// encoder off this, not off the request.
    private(set) var appliedRefreshRate: Int
    /// True when the display was created with the EDR transfer function —
    /// WindowServer then composites it with real HDR headroom (measured
    /// potentialEDR 5.0), so HDR content survives into the capture.
    private(set) var appliedHDR = false

    var displayID: CGDirectDisplayID { display.displayID }

    /// Must be called on the main thread. `serialNum` must be unique per
    /// concurrent display AND stable per device — macOS keys saved display
    /// arrangement on vendor/product/serial, so a stable serial means each
    /// device keeps its position in System Settings across sessions.
    /// `refreshRate` above 60 and `hdr` are best-effort: attempted first,
    /// with fallback through (hdr, 60Hz) and plain SDR — the private API's
    /// support for both varies by macOS version (EDR needs the newer
    /// transferFunction initializer — see CGVirtualDisplayPrivate.h).
    init?(name: String, pointsWide: Int, pointsHigh: Int, sizeInMillimeters: CGSize,
          refreshRate: Int = 60, hdr: Bool = false, serialNum: UInt32 = 0x0001) {
        self.pointsWide = pointsWide
        self.pointsHigh = pointsHigh
        self.appliedRefreshRate = max(refreshRate, 1)
        guard Self.acceptsPointGeometry(width: pointsWide, height: pointsHigh) else {
            Log.info("refusing invalid virtual display geometry: \(pointsWide)x\(pointsHigh) points")
            return nil
        }

        // Weak-linked private API (see CGVirtualDisplayPrivate.h): touching
        // the classes when a macOS update removed them would crash — bail to
        // the caller's no-display error path instead. Surfaced at launch by
        // CapabilityProbe/the control window's Compatibility section.
        guard CapabilityProbe.virtualDisplayAPI else {
            Log.info("CGVirtualDisplay API missing on this macOS — cannot create virtual displays")
            return nil
        }

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

        // EDR (transferFunction:1) needs the newer initializer; observed on
        // macOS 26 and re-verified on macOS 27 as the only value that yields
        // EDR compositing headroom.
        let tfAvailable = CapabilityProbe.edrVirtualDisplay
        if hdr && !tfAvailable {
            Log.info("EDR virtual display unavailable (no transferFunction initializer on this macOS) — SDR framebuffer")
        }

        func mode(_ rate: Int, edr: Bool) -> CGVirtualDisplayMode {
            edr && tfAvailable
                ? CGVirtualDisplayMode(width: UInt(pointsWide), height: UInt(pointsHigh),
                                       refreshRate: Double(rate), transferFunction: 1)
                : CGVirtualDisplayMode(width: UInt(pointsWide), height: UInt(pointsHigh),
                                       refreshRate: Double(rate))
        }

        settings = CGVirtualDisplaySettings()
        settings.hiDPI = 1
        // Preference order: everything requested → drop 120Hz → drop EDR.
        var attempts: [(rate: Int, edr: Bool)] = [(appliedRefreshRate, hdr && tfAvailable)]
        if appliedRefreshRate > 60 { attempts.append((60, hdr && tfAvailable)) }
        if hdr && tfAvailable {
            attempts.append((appliedRefreshRate, false))
            if appliedRefreshRate > 60 { attempts.append((60, false)) }
        }
        var applied = false
        for attempt in attempts {
            settings.modes = [mode(attempt.rate, edr: attempt.edr)]
            if display.apply(settings) {
                if attempt.rate != appliedRefreshRate || attempt.edr != (hdr && tfAvailable) {
                    Log.info("virtual display fell back to \(attempt.rate)Hz edr=\(attempt.edr)")
                }
                appliedRefreshRate = attempt.rate
                appliedHDR = attempt.edr
                applied = true
                break
            }
        }
        guard applied else {
            Log.info("CGVirtualDisplay applySettings FAILED (all mode variants)")
            return nil
        }
        Log.info("virtual display created: id=\(display.displayID) \(pointsWide)x\(pointsHigh)pt @2x \(appliedRefreshRate)Hz edr=\(appliedHDR)")

        // macOS defaults the new display to its 1x mode AND can restore a
        // stale saved mode for this serial asynchronously, seconds after the
        // display appears (observed: a display checked as @2x at creation
        // sitting at 1x later, and a rotated rebuild pillarboxed by the
        // previous orientation's mode). So mode selection is enforcement,
        // not a one-shot: keep watching for the lifetime of the display and
        // re-assert the HiDPI mode whenever something else changes it.
        Task { @MainActor [weak self] in
            var settled = false
            while true {
                // Scoped strong ref: a rotation rebuild relies on release
                // removing the display — never hold it across the sleep.
                do {
                    guard let self else { return }
                    self.ensureNotMirrored()
                    if self.selectHiDPIMode(recover: settled) { settled = true }
                }
                try? await Task.sleep(for: .milliseconds(settled ? 2000 : 200))
            }
        }
    }

    /// Returns true when the display is (now) in its HiDPI mode. Silent when
    /// nothing needed doing — this runs every 2s as enforcement. With
    /// `recover`, a missing @2x mode (macOS can replace the whole mode list
    /// when it restores saved display state) re-applies our settings to
    /// publish it again instead of failing silently forever.
    @discardableResult
    private func selectHiDPIMode(recover: Bool = false) -> Bool {
        let opts = [kCGDisplayShowDuplicateLowResolutionModes: kCFBooleanTrue] as CFDictionary
        guard let modes = CGDisplayCopyAllDisplayModes(display.displayID, opts) as? [CGDisplayMode],
              // Among @2x matches prefer the highest refresh — macOS can list
              // a derived 60Hz duplicate next to the published 120Hz mode.
              let hidpi = modes
                  .filter({
                      Self.matchesHiDPIGeometry(pointsWide: pointsWide, pointsHigh: pointsHigh,
                                                 modeWidth: $0.width, modeHeight: $0.height,
                                                 pixelWidth: $0.pixelWidth, pixelHeight: $0.pixelHeight)
                  })
                  .max(by: { $0.refreshRate < $1.refreshRate }) else {
            if recover {
                Log.info("@2x mode vanished from display \(display.displayID) — re-applying settings")
                _ = display.apply(settings)
            }
            return false
        }
        if let current = CGDisplayCopyDisplayMode(display.displayID),
           Self.matchesHiDPIGeometry(pointsWide: pointsWide, pointsHigh: pointsHigh,
                                     modeWidth: current.width, modeHeight: current.height,
                                     pixelWidth: current.pixelWidth, pixelHeight: current.pixelHeight),
           // Refresh check only when both sides report one (virtual displays
           // can report 0) — otherwise this would reconfigure every 2s.
           hidpi.refreshRate <= 0 || current.refreshRate <= 0
               || current.refreshRate >= hidpi.refreshRate - 0.5 {
            return true
        }
        var config: CGDisplayConfigRef?
        return Self.performConfiguration(
            begin: {
                let result = CGBeginDisplayConfiguration(&config)
                if result != .success {
                    Log.info("HiDPI mode selection could not begin (result \(result.rawValue))")
                }
                return (result, config)
            },
            configure: { config in
                let result = CGConfigureDisplayWithDisplayMode(config, display.displayID, hidpi, nil)
                if result != .success {
                    Log.info("HiDPI mode selection could not configure (result \(result.rawValue))")
                }
                return result
            },
            complete: { config in
                let result = CGCompleteDisplayConfiguration(config, .permanently)
                if result != .success {
                    Log.info("HiDPI mode selection could not complete (result \(result.rawValue))")
                } else {
                    Log.info("HiDPI mode (re)selected: \(hidpi.width)x\(hidpi.height)@2x (result \(result.rawValue))")
                }
                return result
            },
            cancel: { config in
                CGCancelDisplayConfiguration(config)
            }
        )
    }

    /// An extend-mode virtual display must never sit in a system mirror set.
    /// macOS can drop it there on its own — e.g. when it misclassifies the
    /// display as a TV, whose arrangement default is "Mirror Entire Screen"
    /// (issue #100) — and that arrangement is saved per vendor/product/serial,
    /// so a stable serial means it's restored every session and the device is
    /// stuck mirroring. Detaching is enforcement, not a one-shot: like the
    /// HiDPI mode, re-break it whenever macOS re-mirrors it. Mirror mode never
    /// builds a VirtualDisplay (it captures the main display instead), so a
    /// VirtualDisplay in a mirror set is always wrong — safe to always undo.
    private func ensureNotMirrored() {
        let id = display.displayID
        guard CGDisplayIsInMirrorSet(id) != 0 else { return }

        var config: CGDisplayConfigRef?
        _ = Self.performConfiguration(
            begin: {
                let result = CGBeginDisplayConfiguration(&config)
                if result != .success {
                    Log.info("virtual display \(id) mirror detach could not begin (result \(result.rawValue))")
                }
                return (result, config)
            },
            configure: { config in
                // Detach the virtual display itself (covers "macOS mirrors the VD onto
                // the main display")...
                let ownConfigure = CGConfigureDisplayMirrorOfDisplay(config, id, kCGNullDirectDisplay)
                guard ownConfigure == .success else {
                    Log.info("virtual display \(id) mirror detach could not configure (result \(ownConfigure.rawValue))")
                    return ownConfigure
                }
                // ...and any display currently mirroring the VD (covers the reporter's
                // arrangement: the device set as Main, with the built-in mirroring it).
                var n: UInt32 = 0
                CGGetActiveDisplayList(0, nil, &n)
                var list = [CGDirectDisplayID](repeating: 0, count: Int(n))
                CGGetActiveDisplayList(n, &list, &n)
                for other in list where other != id && CGDisplayMirrorsDisplay(other) == id {
                    let result = CGConfigureDisplayMirrorOfDisplay(config, other, kCGNullDirectDisplay)
                    guard result == .success else {
                        Log.info("virtual display \(id) mirror detach could not configure peer (result \(result.rawValue))")
                        return result
                    }
                }
                return .success
            },
            complete: { config in
                let result = CGCompleteDisplayConfiguration(config, .forSession)
                if result != .success {
                    Log.info("virtual display \(id) mirror detach could not complete (result \(result.rawValue))")
                } else {
                    Log.info("virtual display \(id) was in a mirror set — detached to extend (result \(result.rawValue))")
                }
                return result
            },
            cancel: { config in
                CGCancelDisplayConfiguration(config)
            }
        )
    }
}
