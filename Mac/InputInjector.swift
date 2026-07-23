import CoreGraphics
import AppKit

/// Turns normalized touch coordinates from the phone into mouse events on a
/// target display. Touch semantics: finger down = left button down, finger
/// move = drag, finger up = button up — i.e. the phone acts as a touchscreen.
final class InputInjector {

    private let displayID: CGDirectDisplayID
    private var isDown = false
    private var lastPointerLocation: CGPoint
    private let pointerLock = NSLock()
    // A real event source (vs nil) plus clickState=1 below: menu tracking
    // treats sourceless/zero-click synthetic clicks as malformed — menus
    // open but their tracking session breaks, leaving zombie menu windows
    // composited on the display (visible in the stream, unclickable).
    private let source = CGEventSource(stateID: .hidSystemState)
    private lazy var scrollCoalescer = ScrollEventCoalescer { [weak self] pending in
        self?.injectScroll(pending)
    }

    init(displayID: CGDirectDisplayID) {
        self.displayID = displayID
        self.lastPointerLocation = Self.insetPoint(in: CGDisplayBounds(displayID))
    }

    static func ensureAccessibilityPermission() -> Bool {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue(): true] as CFDictionary
        let trusted = AXIsProcessTrustedWithOptions(options)
        if !trusted {
            Log.info("Accessibility permission missing — prompt requested")
        }
        return trusted
    }

    /// x/y are normalized [0,1] in video space (origin top-left).
    func handleTouch(phase: String, x: Double, y: Double) {
        let bounds = CGDisplayBounds(displayID)   // global CG coords, y-down
        let point = Self.touchPoint(x: x, y: y, in: bounds)

        let type: CGEventType
        switch phase {
        case "began":
            // A duplicate begin is a new contact boundary. Balance the old
            // contact first so a dropped end cannot leave the physical button held.
            releasePressedInput()
            type = .leftMouseDown
            isDown = true
        case "moved":
            type = isDown ? .leftMouseDragged : .mouseMoved
        case "ended", "cancelled":
            guard isDown else { return }   // spurious up without a down
            type = .leftMouseUp
            isDown = false
        default:
            return
        }

        setLastPointerLocation(point)
        postMouse(type, at: point)
    }

    /// Balances the injected button state and discards deferred scroll work.
    /// Safe at every session boundary and when called more than once.
    func releasePressedInput() {
        scrollCoalescer.cancel()
        guard isDown else { return }
        isDown = false
        postMouse(.leftMouseUp, at: currentPointerLocation())
    }

    static func touchPoint(x: Double, y: Double, in bounds: CGRect) -> CGPoint {
        let point = CGPoint(
            x: bounds.origin.x + x * bounds.width,
            y: bounds.origin.y + y * bounds.height
        )
        return clampedPoint(point, in: bounds)
    }

    static func insetPoint(in bounds: CGRect) -> CGPoint {
        clampedPoint(CGPoint(x: bounds.midX, y: bounds.midY), in: bounds)
    }

    private static func clampedPoint(_ point: CGPoint, in bounds: CGRect) -> CGPoint {
        guard bounds.width > 0, bounds.height > 0 else { return bounds.origin }
        let upperX = bounds.origin.x + bounds.width.nextDown
        let upperY = bounds.origin.y + bounds.height.nextDown
        return CGPoint(
            x: min(max(point.x, bounds.origin.x), upperX),
            y: min(max(point.y, bounds.origin.y), upperY)
        )
    }
    private func setLastPointerLocation(_ point: CGPoint) {
        pointerLock.lock()
        lastPointerLocation = point
        pointerLock.unlock()
    }

    private func currentPointerLocation() -> CGPoint {
        pointerLock.lock()
        defer { pointerLock.unlock() }
        return lastPointerLocation
    }


    private func postMouse(_ type: CGEventType, at point: CGPoint) {
        guard let event = CGEvent(mouseEventSource: source, mouseType: type,
                                  mouseCursorPosition: point, mouseButton: .left) else { return }
        event.setIntegerValueField(.mouseEventClickState, value: 1)
        event.post(tap: .cghidEventTap)
    }

    /// dx/dy in display pixels, natural-scrolling sign from the phone.
    /// Scroll events take points, so convert via the display's pixel scale.
    func handleScroll(dx: Double, dy: Double) {
        _ = scrollCoalescer.enqueue(dx: dx, dy: dy)
    }

    private func injectScroll(_ pending: ScrollDelta) {
        let bounds = CGDisplayBounds(displayID)
        guard bounds.width > 0 else { return }
        let displayScale = Double(CGDisplayPixelsWide(displayID)) / bounds.width
        guard let wheel = ScrollWheelConversion.nativeWheelDelta(
            dx: pending.dx,
            dy: pending.dy,
            displayScale: displayScale
        ) else { return }

        guard let event = CGEvent(scrollWheelEvent2Source: source, units: .pixel,
                                  wheelCount: 2,
                                  wheel1: wheel.dy,
                                  wheel2: wheel.dx,
                                  wheel3: 0) else { return }
        // ScrollWheelEvent has no target display. Pin its location to this
        // session's display, including before the first touch arrives.
        event.location = currentPointerLocation()
        event.post(tap: .cghidEventTap)
    }
}
