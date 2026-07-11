// SPDX-License-Identifier: GPL-3.0-only
// Part of PhotonPort.

import Foundation

enum ScrollInputPolicy {
    /// Conservative per-message absolute bound in display pixels: 120 display pixels is enough for a deliberate scroll tick
    /// while rejecting pathological deltas before they can create injection backlog or oversized events.
    static let messageDeltaLimit = 120.0
    /// Absolute bound applied to each coalesced injected axis in display pixels and native wheel units.
    static let injectedDeltaLimit = 120.0
    /// Minimum spacing between native scroll injections so bursts collapse into bounded display-rate work.
    static let injectionInterval: TimeInterval = 1.0 / 120.0
}

struct ScrollDelta: Equatable {
    let dx: Double
    let dy: Double
}

struct NativeScrollWheelDelta: Equatable {
    let dx: Int32
    let dy: Int32
}

enum ScrollWheelConversion {
    static func nativeWheelDelta(dx: Double, dy: Double, displayScale: Double) -> NativeScrollWheelDelta? {
        guard dx.isFinite, dy.isFinite, displayScale.isFinite, displayScale > 0 else { return nil }
        return NativeScrollWheelDelta(
            dx: nativeAxis(dx, displayScale: displayScale),
            dy: nativeAxis(dy, displayScale: displayScale)
        )
    }

    private static func nativeAxis(_ value: Double, displayScale: Double) -> Int32 {
        let scaled = (value / displayScale).rounded(.toNearestOrAwayFromZero)
        let bounded = min(max(scaled, -ScrollInputPolicy.injectedDeltaLimit), ScrollInputPolicy.injectedDeltaLimit)
        return Int32(bounded)
    }
}

final class ScrollEventCoalescer {
    typealias Callback = (ScrollDelta) -> Void

    private let lock = NSLock()
    private let callback: Callback?
    private let timerQueue: DispatchQueue
    private var timer: DispatchSourceTimer?
    private var pendingDX = 0.0
    private var pendingDY = 0.0
    private var hasPending = false

    init() {
        self.callback = nil
        self.timerQueue = DispatchQueue(label: "org.photonport.scroll-coalescer")
    }

    init(callback: @escaping Callback, queue: DispatchQueue = DispatchQueue(label: "org.photonport.scroll-coalescer")) {
        self.callback = callback
        self.timerQueue = queue
        startInjectionTimer()
    }

    deinit {
        timer?.setEventHandler {}
        timer?.cancel()
    }

    var pendingWorkCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return hasPending ? 1 : 0
    }

    func enqueue(dx: Double, dy: Double) -> Bool {
        guard Self.isAdmissible(dx), Self.isAdmissible(dy) else { return false }

        lock.lock()
        pendingDX = Self.clampedInjectedDelta(pendingDX + dx)
        pendingDY = Self.clampedInjectedDelta(pendingDY + dy)
        hasPending = true
        lock.unlock()
        return true
    }

    func takePending() -> ScrollDelta? {
        lock.lock()
        defer { lock.unlock() }
        guard hasPending else { return nil }
        let value = ScrollDelta(dx: pendingDX, dy: pendingDY)
        pendingDX = 0
        pendingDY = 0
        hasPending = false
        return value
    }

    private func startInjectionTimer() {
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: .now() + ScrollInputPolicy.injectionInterval,
                       repeating: ScrollInputPolicy.injectionInterval)
        timer.setEventHandler { [weak self] in
            self?.drain()
        }
        self.timer = timer
        timer.resume()
    }

    private func drain() {
        guard let pending = takePending() else { return }
        guard let callback else {
            preconditionFailure("timer-backed scroll coalescer requires a callback")
        }
        callback(pending)
    }

    private static func isAdmissible(_ value: Double) -> Bool {
        value.isFinite && abs(value) <= ScrollInputPolicy.messageDeltaLimit
    }

    private static func clampedInjectedDelta(_ value: Double) -> Double {
        min(max(value, -ScrollInputPolicy.injectedDeltaLimit), ScrollInputPolicy.injectedDeltaLimit)
    }
}
