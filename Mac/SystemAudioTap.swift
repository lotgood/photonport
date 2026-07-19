// SPDX-License-Identifier: GPL-3.0-only
// Part of PhotonPort, a GPL-3.0 fork of OpenDisplay
// (https://github.com/peetzweg/opendisplay, (c) peetzweg and contributors).
// This file (c) 2026 hyupji, added in the fork.

// SystemAudioTap — Sidecar-style audio routing without a HAL driver.
//
// A CoreAudio process tap (macOS 14.2+) on the global mixdown with
// muteBehavior = .mutedWhenTapped: while the tap lives, macOS mutes the
// local speakers and hands us the audio — the device becomes the ONLY
// place the Mac's sound plays, exactly like Sidecar's routing. Destroying
// the tap restores local playback instantly.
//
// The tap is read through a private aggregate device whose IO buffer is
// pinned small (256 frames ≈ 5.3ms), which also cuts the forwarding
// latency to a quarter of the SCK audio path's fixed 20ms chunks.

import Foundation
import CoreAudio
import AudioToolbox
import os

final class SystemAudioTap {
    static func supportsTapFormat(_ format: AudioStreamBasicDescription) -> Bool {
        format.mSampleRate.isFinite && format.mSampleRate > 0
            && format.mBitsPerChannel == 32
            && format.mFormatFlags & kAudioFormatFlagIsFloat != 0
            && (format.mChannelsPerFrame == 1 || format.mChannelsPerFrame == 2)
    }

    static func pcm16(_ value: Float) -> Int16 {
        guard value.isFinite else { return 0 }
        return Int16(max(-1, min(1, value)) * 32767)
    }

    private var tapID = AudioObjectID(kAudioObjectUnknown)
    private var aggregateID = AudioObjectID(kAudioObjectUnknown)
    private var ioProcID: AudioDeviceIOProcID?
    private var sampleRate = 48_000
    private let onPCM: (_ slot: PCMSlot, _ frames: Int, _ sampleRate: Int) -> Void
    private var readySource: DispatchSourceUserDataOr?
    private var lifecycleLock = os_unfair_lock_s()
    private var stopping = false
    private let callbacks = DispatchGroup()
    final class PCMSlot {
        let index: Int
        var data: Data
        weak var pool: PCMPool?
        var frames = 0
        var sampleRate = 0

        init(index: Int, bytes: Int) {
            self.index = index
            self.data = Data(count: bytes)
        }

        func release() { pool?.release(index) }
    }

    final class PCMPool {
        private var lock = os_unfair_lock_s()
        private var claimed = 0
        private var consuming = 0
        let slots: [PCMSlot]

        init(slotCount: Int, bytes: Int) {
            slots = (0..<slotCount).map { PCMSlot(index: $0, bytes: bytes) }
            slots.forEach { $0.pool = self }
        }

        func claim() -> PCMSlot? {
            guard os_unfair_lock_trylock(&lock) else { return nil }
            defer { os_unfair_lock_unlock(&lock) }
            for slot in slots where (claimed | consuming) & (1 << slot.index) == 0 {
                claimed |= 1 << slot.index
                return slot
            }
            return nil
        }

        func release(_ index: Int) {
            os_unfair_lock_lock(&lock)
            claimed &= ~(1 << index)
            consuming &= ~(1 << index)
            os_unfair_lock_unlock(&lock)
        }

        func takeSignaled(_ index: Int) -> PCMSlot? {
            os_unfair_lock_lock(&lock)
            defer { os_unfair_lock_unlock(&lock) }
            let bit = 1 << index
            guard claimed & bit != 0, consuming & bit == 0 else { return nil }
            consuming |= bit
            return slots[index]
        }

        func releaseAll() {
            os_unfair_lock_lock(&lock)
            claimed = 0
            consuming = 0
            os_unfair_lock_unlock(&lock)
        }


    }

    private static let poolSlots = 8
    private static let maxFrames = 2048
    private let pcmPool = PCMPool(slotCount: poolSlots,
                                  bytes: maxFrames * 2 * MemoryLayout<Int16>.size)


    /// nil when the tap can't be built (pre-14.2, TCC denied, HAL error) —
    /// callers fall back to the SCK audio path.
    init?(queue: DispatchQueue,
          onPCM: @escaping (_ slot: PCMSlot, _ frames: Int, _ sampleRate: Int) -> Void) {
        self.onPCM = onPCM
        guard #available(macOS 14.2, *) else { return nil }
        let source = DispatchSource.makeUserDataOrSource(queue: queue)
        readySource = source
        source.setEventHandler { [weak self] in
            guard let self else { return }
            let bits = source.data
            for index in 0..<Self.poolSlots where bits & (1 << index) != 0 {
                guard let slot = self.pcmPool.takeSignaled(index) else { continue }
                self.onPCM(slot, slot.frames, slot.sampleRate)
            }
        }
        source.resume()

        // Per-instance identity: multi-device sessions run one tap each, and
        // aggregate-device UIDs are system-global — a fixed UID makes the
        // SECOND session's AudioHardwareCreateAggregateDevice fail with
        // 'nope' (verified), silently demoting that device to the dual-
        // playing SCK fallback. Unique UIDs give every session its own
        // working tap: all devices hear the mixdown, the Mac stays muted
        // until the last muting tap is destroyed.
        let instanceID = UUID().uuidString
        let desc = CATapDescription(stereoGlobalTapButExcludeProcesses: [])
        desc.name = "PhotonPort System Tap \(instanceID)"
        desc.isPrivate = true
        // The whole point: local speakers go quiet while we forward.
        desc.muteBehavior = .mutedWhenTapped
        var tap = AudioObjectID(kAudioObjectUnknown)
        var status = AudioHardwareCreateProcessTap(desc, &tap)
        guard status == noErr, tap != kAudioObjectUnknown else {
            Log.info("process tap creation failed (\(status)) — falling back to SCK audio")
            return nil
        }
        tapID = tap

        // The tap's mixdown format tells us the true sample rate.
        var fmt = AudioStreamBasicDescription()
        var fmtSize = UInt32(MemoryLayout<AudioStreamBasicDescription>.size)
        var fmtAddr = AudioObjectPropertyAddress(
            mSelector: kAudioTapPropertyFormat,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain)
        guard AudioObjectGetPropertyData(tapID, &fmtAddr, 0, nil, &fmtSize, &fmt) == noErr,
              Self.supportsTapFormat(fmt) else {
            Log.info("tap reported unsupported stream format — falling back to SCK audio")
            AudioHardwareDestroyProcessTap(tapID)
            return nil
        }
        sampleRate = Int(fmt.mSampleRate)

        let aggDesc: [String: Any] = [
            kAudioAggregateDeviceNameKey: "PhotonPort Tap Device",
            kAudioAggregateDeviceUIDKey: "dev.hyupji.photonport.tap.\(instanceID)",
            kAudioAggregateDeviceIsPrivateKey: true,
            kAudioAggregateDeviceTapAutoStartKey: true,
            kAudioAggregateDeviceTapListKey: [
                [kAudioSubTapUIDKey: desc.uuid.uuidString]
            ],
        ]
        var agg = AudioObjectID(kAudioObjectUnknown)
        status = AudioHardwareCreateAggregateDevice(aggDesc as CFDictionary, &agg)
        guard status == noErr, agg != kAudioObjectUnknown else {
            Log.info("tap aggregate device failed (\(status)) — falling back to SCK audio")
            AudioHardwareDestroyProcessTap(tapID)
            return nil
        }
        aggregateID = agg

        // Small IO buffer = low forwarding latency (best effort).
        var frames: UInt32 = 256
        var bufAddr = AudioObjectPropertyAddress(
            mSelector: kAudioDevicePropertyBufferFrameSize,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain)
        AudioObjectSetPropertyData(agg, &bufAddr, 0, nil,
                                   UInt32(MemoryLayout<UInt32>.size), &frames)

        status = AudioDeviceCreateIOProcIDWithBlock(&ioProcID, agg, nil) {
            [weak self] _, inInputData, _, _, _ in
            self?.forward(inInputData)
        }
        guard status == noErr, let ioProcID else {
            Log.info("tap IO proc failed (\(status)) — falling back to SCK audio")
            AudioHardwareDestroyAggregateDevice(aggregateID)
            AudioHardwareDestroyProcessTap(tapID)
            return nil
        }
        status = AudioDeviceStart(agg, ioProcID)
        guard status == noErr else {
            Log.info("tap device start failed (\(status)) — falling back to SCK audio")
            stop()
            return nil
        }
        Log.info("system audio tap live: \(sampleRate)Hz, Mac speakers muted while forwarding")
    }

    /// HAL real-time thread: writes only into a preallocated pool slot.
    private func beginCallback() -> Bool {
        callbacks.enter()
        guard os_unfair_lock_trylock(&lifecycleLock) else {
            callbacks.leave()
            return false
        }
        let active = !stopping
        os_unfair_lock_unlock(&lifecycleLock)
        if !active { callbacks.leave() }
        return active
    }

    private func endCallback() {
        callbacks.leave()
    }

    private func forward(_ ablPtr: UnsafePointer<AudioBufferList>) {
        guard beginCallback() else { return }
        defer { endCallback() }
        let abl = UnsafeMutableAudioBufferListPointer(UnsafeMutablePointer(mutating: ablPtr))
        guard abl.count > 0, let first = abl[0].mData else { return }
        let channels = Int(abl[0].mNumberChannels)
        let frames = abl.count >= 2
            ? Int(abl[0].mDataByteSize) / MemoryLayout<Float>.size
            : Int(abl[0].mDataByteSize) / MemoryLayout<Float>.size / max(channels, 1)
        guard frames > 0, frames <= Self.maxFrames,
              let slot = pcmPool.claim() else { return }
        slot.data.withUnsafeMutableBytes { raw in
            let out = raw.bindMemory(to: Int16.self)
            if abl.count >= 2, let l = abl[0].mData, let r = abl[1].mData {
                let left = l.assumingMemoryBound(to: Float.self)
                let right = r.assumingMemoryBound(to: Float.self)
                for i in 0..<frames {
                    out[i * 2] = Self.pcm16(left[i])
                    out[i * 2 + 1] = Self.pcm16(right[i])
                }
            } else {
                let input = first.assumingMemoryBound(to: Float.self)
                for i in 0..<frames {
                    out[i * 2] = Self.pcm16(channels >= 2 ? input[i * 2] : input[i])
                    out[i * 2 + 1] = Self.pcm16(channels >= 2 ? input[i * 2 + 1] : input[i])
                }
            }
        }
        slot.frames = frames
        slot.sampleRate = sampleRate
        readySource?.or(data: 1 << slot.index)
    }

    func stop() {
        os_unfair_lock_lock(&lifecycleLock)
        guard !stopping else {
            os_unfair_lock_unlock(&lifecycleLock)
            return
        }
        stopping = true
        os_unfair_lock_unlock(&lifecycleLock)

        // Stop produces the HAL quiescence boundary while the source remains
        // valid for every callback that entered before `stopping`.
        if let ioProcID, aggregateID != kAudioObjectUnknown {
            AudioDeviceStop(aggregateID, ioProcID)
        }
        callbacks.wait()
        readySource?.cancel()
        readySource = nil
        pcmPool.releaseAll()
        guard #available(macOS 14.2, *) else { return }
        if let ioProcID, aggregateID != kAudioObjectUnknown {
            AudioDeviceDestroyIOProcID(aggregateID, ioProcID)
        }
        ioProcID = nil
        if aggregateID != kAudioObjectUnknown {
            AudioHardwareDestroyAggregateDevice(aggregateID)
            aggregateID = AudioObjectID(kAudioObjectUnknown)
        }
        if tapID != kAudioObjectUnknown {
            AudioHardwareDestroyProcessTap(tapID)   // un-mutes the Mac
            tapID = AudioObjectID(kAudioObjectUnknown)
        }
    }

    deinit { stop() }
}
