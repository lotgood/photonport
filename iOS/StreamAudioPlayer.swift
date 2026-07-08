// SPDX-License-Identifier: GPL-3.0-only
// Part of PhotonPort, a GPL-3.0 fork of OpenDisplay
// (https://github.com/peetzweg/opendisplay, (c) peetzweg and contributors).
// This file (c) 2026 hyupji, added in the fork.

// StreamAudioPlayer — plays the Mac's forwarded system audio.
//
// The wire carries interleaved 16-bit stereo PCM chunks (~10-20ms each) on
// the control framing. Chunks are converted to float and scheduled
// back-to-back on an AVAudioPlayerNode: as long as the network keeps up the
// node's internal queue plays them gaplessly; a late chunk is an audible
// gap rather than growing latency — the right trade for a second screen.

import Foundation
import AVFoundation

final class StreamAudioPlayer {
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private var format: AVAudioFormat?
    // Engine mutations and scheduling stay on one queue; chunks arrive on
    // the receiver's network queue.
    private let queue = DispatchQueue(label: "audio.stream")
    // Jitter buffer. Consumption is exactly realtime, so the queue never
    // grows a cushion on its own — after a start or an underrun we hold
    // back PREBUFFER chunks (~16ms at the tap's 5.3ms cadence) and schedule
    // them as one burst, giving arrival jitter something to eat. Without
    // this, every >5ms hiccup was an audible thump.
    // The other direction is capped by TIME (not chunk count — chunk size
    // halved when the Mac moved to the audio tap and a count cap silently
    // became 4× tighter): backlog above ~60ms sheds chunks so latency can
    // never ratchet upward permanently.
    private var pendingChunks = 0
    private var droppedChunks = 0
    private var prebuffer: [AVAudioPCMBuffer] = []
    private var needsPrebuffer = true
    // Jitter tolerance depends on the link. USB (dedicated audio socket,
    // ~5ms buffers) has almost none, so the buffer stays shallow for low
    // latency. WiFi shares the video socket and rides a radio with periodic
    // 100–700ms RTT spikes: the shallow thresholds shed backlog every few
    // seconds (constant audible glitching). WiFi uses a moderately deeper
    // buffer — it parks around ~55–100ms instead of USB's ~35–60ms, enough
    // to ride typical radio jitter without the constant full-flush glitches,
    // without piling on the audio latency. Set from the receiver's transport.
    var highJitter = false
    private var prebufferChunks: Int { highJitter ? 6 : 3 }     // ~32ms vs ~16ms
    private var freshnessSeconds: TimeInterval { highJitter ? 0.15 : 0.08 }
    private var hardShedMs: Double { highJitter ? 100 : 60 }
    private var driftFloorMs: Double { highJitter ? 55 : 35 }
    private var driftSeconds: TimeInterval { highJitter ? 3 : 2 }
    private var generation = 0
    private var lastLowQueueAt = Date()
    // Telemetry (racy cross-thread reads are fine for an overlay number):
    // audio sitting in the player queue right now, and the output stage.
    private(set) var queuedMs: Double = 0
    var outputLatencyMs: Double {
        let s = AVAudioSession.sharedInstance()
        return (s.outputLatency + s.ioBufferDuration) * 1000
    }

    func enqueue(_ pcm16: Data, sampleRate: Double) {
        // Freshness gate: engine startup blocks this queue for ~200ms and
        // chunks pile up behind it; playing them late is pure latency
        // (measured: a startup flood parked the queue just under the cap,
        // pinning audio at 75ms forever). Stale audio is worthless — drop
        // anything that waited more than 80ms for its turn.
        let deadline = Date().addingTimeInterval(freshnessSeconds)
        queue.async {
            guard Date() < deadline else { return }
            self.schedule(pcm16, sampleRate: sampleRate)
        }
    }

    func stop() {
        queue.async {
            self.player.stop()
            self.engine.stop()
            self.format = nil
            self.generation += 1
            self.prebuffer.removeAll()
            self.needsPrebuffer = true
            self.pendingChunks = 0
            self.queuedMs = 0
        }
    }

    private func schedule(_ pcm16: Data, sampleRate: Double) {
        let frames = pcm16.count / (2 * MemoryLayout<Int16>.size)   // stereo
        guard frames > 0 else { return }

        if format == nil || format?.sampleRate != sampleRate {
            do {
                // .mixWithOthers: the stream is a monitor's audio, not a
                // takeover — don't kill whatever the iPad is playing.
                try AVAudioSession.sharedInstance().setCategory(.playback, options: [.mixWithOthers])
                // Small IO buffer shaves ~5ms off the output stage.
                try AVAudioSession.sharedInstance().setPreferredIOBufferDuration(0.005)
                try AVAudioSession.sharedInstance().setActive(true)
            } catch {
                Log.info("audio session failed: \(error)")
            }
            engine.stop()
            guard let fmt = AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 2) else { return }
            if player.engine == nil { engine.attach(player) }
            engine.connect(player, to: engine.mainMixerNode, format: fmt)
            do { try engine.start() } catch {
                Log.info("audio engine failed: \(error)")
                return
            }
            player.play()
            format = fmt
            Log.info("audio playback started (\(Int(sampleRate))Hz stereo)")
        }

        // Backlog control. Consumption always equals production, so a queue
        // that got tall NEVER drains by itself — skipping forward is the
        // only way down. Two triggers:
        //  - hard: ≥60ms right now (startup flood, burst)
        //  - drift: parked above ~35ms for 2s straight (a transient that
        //    settled below the hard cap; measured parking spots at 37-58ms
        //    turned into permanent latency without this)
        if queuedMs < driftFloorMs { lastLowQueueAt = Date() }
        if queuedMs >= hardShedMs || Date().timeIntervalSince(lastLowQueueAt) > driftSeconds {
            droppedChunks += 1
            if droppedChunks % 20 == 1 {
                Log.info("audio: skipped ahead to shed \(Int(queuedMs))ms backlog (\(droppedChunks) resets)")
            }
            generation += 1   // void completions of the flushed buffers
            player.stop()
            pendingChunks = 0
            queuedMs = 0
            prebuffer.removeAll()
            needsPrebuffer = true
            lastLowQueueAt = Date()
            player.play()
        }
        guard let format,
              let buf = AVAudioPCMBuffer(pcmFormat: format,
                                         frameCapacity: AVAudioFrameCount(frames)) else { return }
        buf.frameLength = AVAudioFrameCount(frames)
        pcm16.withUnsafeBytes { raw in
            let input = raw.bindMemory(to: Int16.self)
            guard let channels = buf.floatChannelData else { return }
            let l = channels[0]
            let r = channels[1]
            for i in 0..<frames {
                l[i] = Float(input[i * 2]) / 32767.0
                r[i] = Float(input[i * 2 + 1]) / 32767.0
            }
        }
        let chunkMs = Double(frames) / sampleRate * 1000
        if needsPrebuffer {
            prebuffer.append(buf)
            if prebuffer.count >= prebufferChunks {
                needsPrebuffer = false
                for queued in prebuffer { scheduleOne(queued, chunkMs: chunkMs) }
                prebuffer.removeAll()
            }
            return
        }
        scheduleOne(buf, chunkMs: chunkMs)
    }

    private func scheduleOne(_ buf: AVAudioPCMBuffer, chunkMs: Double) {
        pendingChunks += 1
        queuedMs = Double(pendingChunks) * chunkMs
        // player.stop() (skip-ahead reset) fires the completion handlers of
        // everything still queued — a stale flood that would drag the
        // counter negative. The generation stamp voids them.
        let gen = generation
        player.scheduleBuffer(buf) { [weak self] in
            self?.queue.async {
                guard let self, gen == self.generation else { return }
                self.pendingChunks = max(0, self.pendingChunks - 1)
                self.queuedMs = Double(self.pendingChunks) * chunkMs
                if self.pendingChunks == 0 {
                    // Underrun: one silent gap now, then rebuild the cushion
                    // instead of limping chunk-to-chunk with constant thumps.
                    self.needsPrebuffer = true
                }
            }
        }
    }
}
