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
    private let callbackQueue = DispatchQueue(label: "org.photonport.scroll-coalescer.callback")
    private let callbackQueueKey = DispatchSpecificKey<Void>()
    private let beforeCallbackDispatch: (() -> Void)?
    private var timer: DispatchSourceTimer?
    private var generation: UInt64 = 0
    private var pendingDX = 0.0
    private var pendingDY = 0.0
    private var hasPending = false

    init() {
        self.callback = nil
        self.timerQueue = DispatchQueue(label: "org.photonport.scroll-coalescer")
        self.beforeCallbackDispatch = nil
        callbackQueue.setSpecific(key: callbackQueueKey, value: ())
    }

    init(callback: @escaping Callback, queue: DispatchQueue = DispatchQueue(label: "org.photonport.scroll-coalescer"),
         beforeCallbackDispatch: (() -> Void)? = nil) {
        self.callback = callback
        self.timerQueue = queue
        self.beforeCallbackDispatch = beforeCallbackDispatch
        callbackQueue.setSpecific(key: callbackQueueKey, value: ())
    }

    deinit {
        cancel()
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
        let needsArm = timer == nil && callback != nil
        lock.unlock()
        if needsArm { armTimer() }
        return true
    }

    var isArmed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return timer != nil
    }

    /// Cancels deferred injection and makes teardown/reconnect idempotent.
    func cancel() {
        lock.lock()
        generation &+= 1
        let activeTimer = timer
        timer = nil
        pendingDX = 0
        pendingDY = 0
        hasPending = false
        lock.unlock()
        activeTimer?.setEventHandler {}
        activeTimer?.cancel()

        // Every callback is serialized here. Waiting for the queue establishes
        // a teardown fence without invoking user code while holding `lock`.
        if DispatchQueue.getSpecific(key: callbackQueueKey) == nil {
            callbackQueue.sync {}
        }
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

    private func armTimer() {
        lock.lock()
        guard timer == nil, hasPending, callback != nil else {
            lock.unlock()
            return
        }
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        let timerGeneration = generation
        self.timer = timer
        lock.unlock()

        timer.schedule(deadline: .now() + ScrollInputPolicy.injectionInterval)
        timer.setEventHandler { [weak self] in
            self?.drain(timer, generation: timerGeneration)
        }
        timer.resume()
    }

    private func drain(_ firedTimer: DispatchSourceTimer, generation timerGeneration: UInt64) {
        lock.lock()
        guard timer === firedTimer, generation == timerGeneration else {
            lock.unlock()
            return
        }
        timer = nil
        guard hasPending else {
            lock.unlock()
            return
        }
        let pending = ScrollDelta(dx: pendingDX, dy: pendingDY)
        pendingDX = 0
        pendingDY = 0
        hasPending = false
        lock.unlock()

        beforeCallbackDispatch?()
        callbackQueue.async { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let mayDispatch = self.generation == timerGeneration
            self.lock.unlock()
            guard mayDispatch else { return }
            self.callback?(pending)
        }

        lock.lock()
        let needsArm = hasPending && timer == nil
        lock.unlock()
        if needsArm { armTimer() }
    }

    private static func isAdmissible(_ value: Double) -> Bool {
        value.isFinite && abs(value) <= ScrollInputPolicy.messageDeltaLimit
    }

    private static func clampedInjectedDelta(_ value: Double) -> Double {
        min(max(value, -ScrollInputPolicy.injectedDeltaLimit), ScrollInputPolicy.injectedDeltaLimit)
    }
}
