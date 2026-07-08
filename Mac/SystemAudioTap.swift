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

final class SystemAudioTap {
    private var tapID = AudioObjectID(kAudioObjectUnknown)
    private var aggregateID = AudioObjectID(kAudioObjectUnknown)
    private var ioProcID: AudioDeviceIOProcID?
    private var sampleRate = 48_000
    private let onPCM: (_ pcm16: Data, _ sampleRate: Int) -> Void

    /// nil when the tap can't be built (pre-14.2, TCC denied, HAL error) —
    /// callers fall back to the SCK audio path.
    init?(onPCM: @escaping (_ pcm16: Data, _ sampleRate: Int) -> Void) {
        self.onPCM = onPCM
        guard #available(macOS 14.2, *) else { return nil }

        let desc = CATapDescription(stereoGlobalTapButExcludeProcesses: [])
        desc.name = "PhotonPort System Tap"
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
        if AudioObjectGetPropertyData(tapID, &fmtAddr, 0, nil, &fmtSize, &fmt) == noErr,
           fmt.mSampleRate > 0 {
            sampleRate = Int(fmt.mSampleRate)
        }

        let aggDesc: [String: Any] = [
            kAudioAggregateDeviceNameKey: "PhotonPort Tap Device",
            kAudioAggregateDeviceUIDKey: "dev.hyupji.photonport.tap",
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

    /// HAL real-time thread: convert float32 → interleaved 16-bit stereo and
    /// hand off. The closure hops to the sender's queue immediately.
    private func forward(_ ablPtr: UnsafePointer<AudioBufferList>) {
        let abl = UnsafeMutableAudioBufferListPointer(
            UnsafeMutablePointer(mutating: ablPtr))
        guard abl.count > 0, let first = abl[0].mData else { return }
        let interleavedChannels = Int(abl[0].mNumberChannels)
        let frames: Int
        if abl.count >= 2 {   // deinterleaved: one buffer per channel
            frames = Int(abl[0].mDataByteSize) / MemoryLayout<Float>.size
        } else {
            frames = Int(abl[0].mDataByteSize) / MemoryLayout<Float>.size
                / max(interleavedChannels, 1)
        }
        guard frames > 0 else { return }

        var pcm = Data(count: frames * 2 * MemoryLayout<Int16>.size)
        pcm.withUnsafeMutableBytes { raw in
            let out = raw.bindMemory(to: Int16.self)
            func clamp16(_ v: Float) -> Int16 { Int16(max(-1, min(1, v)) * 32767) }
            if abl.count >= 2, let l = abl[0].mData, let r = abl[1].mData {
                let lf = l.assumingMemoryBound(to: Float.self)
                let rf = r.assumingMemoryBound(to: Float.self)
                for i in 0..<frames {
                    out[i * 2] = clamp16(lf[i])
                    out[i * 2 + 1] = clamp16(rf[i])
                }
            } else {
                let f = first.assumingMemoryBound(to: Float.self)
                let stereo = interleavedChannels >= 2
                for i in 0..<frames {
                    out[i * 2] = clamp16(stereo ? f[i * 2] : f[i])
                    out[i * 2 + 1] = clamp16(stereo ? f[i * 2 + 1] : f[i])
                }
            }
        }
        onPCM(pcm, sampleRate)
    }

    func stop() {
        guard #available(macOS 14.2, *) else { return }
        if let ioProcID, aggregateID != kAudioObjectUnknown {
            AudioDeviceStop(aggregateID, ioProcID)
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
