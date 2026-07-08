// MacSender — captures a display, video-encodes it, streams it to the phone.
//
// Milestone 1 (mirror):  capture the main display.
// Milestone 2 (extend):  create a CGVirtualDisplay sized to the phone panel
//                        (announced by the phone in a "hello" message) and
//                        capture that — macOS gains a true second monitor.
//
// Pipeline:  ScreenCaptureKit -> VideoToolbox (H.264, or HEVC Main10 HLG when
//            the receiver announces an EDR panel and the Mac runs macOS 15+)
//            -> framed TCP
// Roles: the PHONE listens, the MAC connects (required for usbmux/USB).
//
// Wire protocol, Mac -> phone:   [4-byte big-endian length][Annex B payload]
//   (keyframes prefixed with the parameter sets, NALUs delimited by
//    00 00 00 01; a JSON telemetry prefix before the first start code
//    carries timing + a "hevc" codec flag)
// Wire protocol, phone -> Mac:   [4-byte big-endian length][JSON message]
//   e.g. {"type":"hello","pixelsWide":2556,"pixelsHigh":1179,"scale":3,
//         "maxFps":120,"hdr":true}

import ScreenCaptureKit
import IOSurface
import VideoToolbox
import Network
import CoreMedia
import AppKit

enum CaptureMode: String {
    case mirror   // main display (Milestone 1)
    case extend   // virtual display (Milestone 2)
}

/// Capture-resolution / bitrate trade-off. The virtual display always runs at
/// native size — only the captured/encoded stream is scaled, so lower presets
/// cut encode, transmit, and decode time at the cost of sharpness.
enum StreamQuality: String, CaseIterable {
    case best, balanced, fast

    var scale: Double {
        switch self {
        case .best: return 1.0
        case .balanced: return 0.75
        case .fast: return 0.5
        }
    }

    // Sized for the measured transport: usbmux sustains ~1Gbps, so even
    // Best@120fps (60Mbps) uses <7% of the wire. WiFi users can pick Fast.
    var bitrate: Int {
        switch self {
        case .best: return 40_000_000
        case .balanced: return 24_000_000
        case .fast: return 10_000_000
        }
    }

    var label: String {
        switch self {
        case .best: return "Best (native)"
        case .balanced: return "Balanced (75%)"
        case .fast: return "Fast (50%)"
        }
    }

    var explanation: String {
        switch self {
        case .best: return "Pixel-perfect at the device's native resolution. Highest bandwidth and latency — on 120Hz devices the encoder tops out below 120fps at native size (use Balanced for full 120)."
        case .balanced: return "75% capture resolution — noticeably lower latency, slight softness."
        case .fast: return "Half resolution — lowest latency and bandwidth, visibly softer. Good for WiFi."
        }
    }
}

struct PhoneInfo: Decodable {
    let pixelsWide: Int   // landscape-oriented (long edge)
    let pixelsHigh: Int
    let scale: Double
    let device: String?   // "iPad" / "iPhone" (older receivers omit it)
    let id: String?       // per-install identity (older receivers omit it) —
                          // lets the controller match the same physical device
                          // across USB and WiFi
    let maxFps: Int?      // panel refresh cap (older receivers omit it → 60)
    let hdr: Bool?        // panel has EDR headroom + receiver can decode
                          // 10-bit HEVC (older receivers omit it → false)

    var kind: String { device ?? "device" }
    /// Refresh rate to drive the pipeline at, clamped to what the wire and
    /// the virtual display can plausibly do.
    var refreshRate: Int { min(max(maxFps ?? 60, 60), 120) }
}

/// How the sender reaches the receiver. Reconnects re-dial from scratch, so
/// a USB device that was replugged (new usbmuxd DeviceID) is found again.
enum SenderTransport {
    case tcp(NWEndpoint)                   // WiFi (Bonjour) or -host/-port override
    case usb(udid: String?, port: UInt16)  // native usbmuxd dial; nil = first device
}

@available(macOS 14.0, *)
final class MacSender: NSObject, SCStreamOutput, SCStreamDelegate {

    // Status surfaced to the UI (updated on main thread).
    @MainActor var onStatus: ((String) -> Void)?
    @MainActor var onStats: ((Int, Double) -> Void)?   // framesSent, mbps
    // Fired when a previously connected device stays gone past the grace
    // period — the controller ends the session (capture, virtual display,
    // recording indicator all torn down) instead of dialing forever or
    // silently coming back over a different transport.
    @MainActor var onDisconnected: (() -> Void)?
    // Fired on every hello — carries the receiver's install id so the
    // controller can deduplicate USB/WiFi sessions to the same device.
    @MainActor var onHello: ((PhoneInfo) -> Void)?

    private var stream: SCStream?
    private var encoder: VTCompressionSession?
    private var connection: NWConnection?
    private var virtualDisplay: VirtualDisplay?
    private let queue = DispatchQueue(label: "sender.video")
    private let startCode: [UInt8] = [0, 0, 0, 1]

    private let transport: SenderTransport
    private let endpointName: String
    private let mode: CaptureMode
    private let quality: StreamQuality
    // HDR opt-out from the controller UI (persisted "hdr" default). Actual
    // use still requires macOS 15+ AND the receiver announcing EDR support.
    private let hdrAllowed: Bool
    // System-audio forwarding: primary path is a CoreAudio process tap
    // (Sidecar-style — mutes the Mac while forwarding); fallback is an
    // audio-only SCStream that plays on both ends. See startCapture.
    private let audioEnabled: Bool
    private var audioTap: SystemAudioTap?
    // Audio rides its own queue — see the tap wiring in startCapture.
    private let audioQueue = DispatchQueue(label: "sender.audio", qos: .userInteractive)
    // Stable per-device serial for the virtual display, so macOS can tell
    // multiple PhotonPort monitors apart and persist their arrangement.
    private let displaySerial: UInt32

    // Negotiated per session from the receiver's hello (and, in extend mode,
    // from what the virtual display actually accepted).
    private var streamFps = 60
    private var hdrActive = false
    // Frame pacing: mirror mode can capture a 120Hz ProMotion Mac panel for
    // a 60Hz receiver — skip frames that arrive faster than the negotiated
    // rate. Pre-encode skips don't break the P-frame chain (the encoder only
    // references frames it was fed), so no forced keyframe needed.
    private var lastEncodedAt = Date.distantPast

    // Backpressure: outstanding sends. If the socket can't keep up we drop
    // frames instead of queueing latency. Kept tight as a TIME budget
    // (~50ms): at 60fps each queued send is ~17ms of added latency, at
    // 120fps ~8ms — so the count scales with the negotiated rate, otherwise
    // 120Hz streams drop constantly on normal socket jitter (measured:
    // capFps 119 vs delivered ~40fps with the fixed limit of 3).
    private var pendingSends = 0
    private var maxPendingSends: Int { streamFps > 60 ? 6 : 3 }
    // Encoder saturation gate (see the capture callback): frames handed to
    // VTCompressionSession whose output handler hasn't fired yet.
    private var pendingEncodes = 0
    // Codec actually in use (HEVC for HDR and for >60fps; see setupEncoder).
    private var usingHEVC = false
    // ProRes wire path (see setupEncoder): raw frames in a PRRS envelope
    // instead of Annex B — ProRes has no NAL structure.
    private var usingProRes = false
    // Rejected encodes (output handler status != noErr) — rate-limit logging.
    private var encodeFailures = 0
    // Pipeline diagnosis flag (`defaults write … diag -bool true`).
    private let diagEnabled = UserDefaults.standard.bool(forKey: "diag")
    private var diagFrameCounter = 0
    private var dropsThisWindow = 0
    private var needsKeyframe = true
    private var connectionReady = false
    private var stopped = false
    // The liveness monitors are self-rescheduling chains guarded only by
    // `stopped`; arm them at most once per instance so a double start() can't
    // stack parallel loops (the failure mode behind #75). Mirrors the
    // `monitorsStarted` guard the iOS PhoneReceiver already uses.
    private var monitorsStarted = false

    // Disconnect detection: before the first connection we dial patiently
    // (the user may start the Mac side first); once connected, a device that
    // stays gone past the grace ends the session via onDisconnected.
    private var everConnected = false
    private var disconnectedSince: Date?
    private let disconnectGraceSeconds: TimeInterval = 10

    private var lastHello: PhoneInfo?
    private var helloContinuation: CheckedContinuation<PhoneInfo, Error>?
    private var inputInjector: InputInjector?

    // Liveness: both sides ping every 2s; if nothing arrives for 5s the link
    // is half-open (e.g. usbmuxd accepted but the device is gone) — reconnect.
    private var lastReceived = Date()
    private var dropsTotal = 0

    // Local cursor echo: a cursor baked into the video carries the full
    // capture→encode→stream→display latency (~30ms perceived). Instead we
    // hide it from capture and stream its position on the control channel —
    // the phone draws it locally on the ~2ms path the touches use.
    // Escape hatch: `defaults write dev.hyupji.photonport.mac localCursor -bool false`.
    private let localCursor = UserDefaults.standard.object(forKey: "localCursor") == nil
        || UserDefaults.standard.bool(forKey: "localCursor")
    private var cursorTimer: DispatchSourceTimer?
    private var cursorImageTimer: DispatchSourceTimer?
    private var lastCursorSent: (x: Double, y: Double, visible: Bool) = (-1, -1, false)
    private var lastCursorPNGHash = 0
    private var captureDisplayID: CGDirectDisplayID = 0

    // Input latency: touches arrive stamped in our clock (the phone applies
    // its sync offset); delta to now = network + deframe + dispatch.
    private var inputLatencies: [Double] = []
    // Capture cadence: SCK only emits on content change, so the phone can't
    // tell "Mac rendered 45fps" from "frames got lost" — count deliveries here.
    private var capFrames = 0
    private var capWindowStart = Date()

    private var framesSent = 0
    private var bytesSent = 0
    private var statsWindowStart = Date()

    // ScreenCaptureKit emits frames only when content changes. After a
    // reconnect on a static screen there is nothing to hang the forced
    // keyframe on — so keep the last frame around and re-encode it.
    private var lastPixelBuffer: CVPixelBuffer?
    private var lastCaptureAt = Date.distantPast

    init(transport: SenderTransport, name: String, mode: CaptureMode,
         quality: StreamQuality = .best, hdrAllowed: Bool = true,
         audioEnabled: Bool = true, displaySerial: UInt32 = 0x0001) {
        self.transport = transport
        self.endpointName = name
        self.mode = mode
        self.quality = quality
        self.hdrAllowed = hdrAllowed
        self.audioEnabled = audioEnabled
        self.displaySerial = displaySerial
        super.init()
    }

    // MARK: - Lifecycle

    func start() async throws {
        stopped = false
        queue.async { self.connect() }   // dial state lives on `queue`
        if !monitorsStarted {
            monitorsStarted = true
            schedulePing()
            scheduleWatchdog()
        }
        if UserDefaults.standard.bool(forKey: "blast"), !blastStarted {
            blastStarted = true
            Log.info("BLAST mode: saturating the wire to measure usbmux throughput")
            scheduleBlast()
        }

        // Screen Recording permission: poll until granted. No auto-prompt at
        // launch — the permission panel's Grant button triggers the system
        // dialog, so the request always has visible context.
        if !CGPreflightScreenCaptureAccess() {
            await status("Screen Recording permission needed — see Permissions below")
            Log.info("Screen Recording permission missing — waiting for grant via the permission panel")
            while !CGPreflightScreenCaptureAccess() {
                try await Task.sleep(for: .seconds(2))
                if stopped { return }
            }
            Log.info("Screen Recording permission granted")
        }

        switch mode {
        case .mirror:
            // The hello carries the receiver's refresh/HDR capabilities —
            // wait for it so mirror negotiates too. Frames only flow once
            // the device is connected anyway, so nothing is lost by waiting
            // (and the recording indicator no longer runs with no receiver).
            await status("Waiting for the device to connect…")
            let info = try await waitForHello()
            streamFps = info.refreshRate
            hdrActive = resolveHDR(info)
            let content = try await SCShareableContent.current
            guard let display = content.displays.first else {
                throw NSError(domain: "MacSender", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "no displays found"])
            }
            // SCDisplay reports points; capture at point resolution for M1.
            let captureW = (Int(Double(display.width) * quality.scale)) & ~1
            let captureH = (Int(Double(display.height) * quality.scale)) & ~1
            try await startCapture(display: display, pixelsWide: captureW, pixelsHigh: captureH)

        case .extend:
            await status("Waiting for the device to connect…")
            let info = try await waitForHello()
            try await setupExtend(info)

            // Touch back-channel (Milestone 3). Needs Accessibility trust;
            // streaming works without it, so don't interrupt with a prompt —
            // the permission panel's Grant button asks when the user is ready.
            if !AXIsProcessTrusted() {
                await status("Extending — grant Accessibility for touch input")
                // Event posting is trust-checked per-post, so it starts working
                // the moment the user grants — poll just to log/report it.
                while !AXIsProcessTrusted() {
                    try await Task.sleep(for: .seconds(2))
                    if stopped { return }
                }
                Log.info("Accessibility permission granted — touch input live")
            }
        }
    }

    /// Build (or rebuild) the virtual display + capture for the announced
    /// phone dimensions. Called at startup and again whenever the phone
    /// rotates (it re-sends hello with swapped dimensions).
    private func setupExtend(_ info: PhoneInfo) async throws {
        Log.info("phone hello: \(info.pixelsWide)x\(info.pixelsHigh) @\(info.scale)x maxFps=\(info.maxFps ?? 60) hdr=\(info.hdr ?? false)")

        // Phone panel is @3x; the virtual display runs @2x HiDPI, so points
        // = native pixels / 2 (rounded down to even for the encoder).
        let pointsWide = (info.pixelsWide / 2) & ~1
        let pointsHigh = (info.pixelsHigh / 2) & ~1
        // Rough physical size so macOS picks a sane default UI scale.
        let mm = info.pixelsWide >= info.pixelsHigh
            ? CGSize(width: 147, height: 68)
            : CGSize(width: 68, height: 147)

        // USB sessions can start before lockdown resolves the device name —
        // fall back to the kind from the hello rather than the generic label.
        let displayName = endpointName.hasPrefix("iPhone / iPad")
            ? "PhotonPort — \(info.kind)"
            : "PhotonPort — \(endpointName)"
        // Orientation-specific serial: macOS persists the chosen mode per
        // serial, and a portrait mode restored onto a landscape display
        // pillarboxes the desktop INTO the framebuffer (streamed as-is).
        // Distinct serials per orientation keep the two configs apart.
        let serial = info.pixelsWide >= info.pixelsHigh
            ? displaySerial
            : displaySerial ^ 0x8000_0000
        let requestedFps = info.refreshRate
        // Resolve HDR before building the display: an EDR virtual display
        // (macOS 26 transferFunction hook) makes WindowServer composite HDR
        // content with real headroom, so the capture carries true HDR — not
        // just a 10-bit container around tone-mapped SDR.
        let wantHDR = resolveHDR(info)
        let vd = await MainActor.run {
            VirtualDisplay(name: displayName,
                           pointsWide: pointsWide, pointsHigh: pointsHigh,
                           sizeInMillimeters: mm, refreshRate: requestedFps,
                           hdr: wantHDR, serialNum: serial)
        }
        guard let vd else {
            throw NSError(domain: "MacSender", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "CGVirtualDisplay creation failed"])
        }
        virtualDisplay = vd
        // Pace the encoder at what the display actually runs — a rejected
        // 120Hz mode means macOS only renders 60 new frames a second.
        streamFps = vd.appliedRefreshRate
        // 10-bit HEVC HLG stays worthwhile even if the EDR framebuffer fell
        // back to SDR (less banding), so hdrActive follows the negotiation,
        // not the framebuffer.
        hdrActive = wantHDR
        inputInjector = InputInjector(displayID: vd.displayID)

        let display = try await findSCDisplay(id: vd.displayID)
        // Quality scaling: capture/encode below native when requested — the
        // display itself stays native so window layout is unaffected.
        let captureW = (Int(Double(pointsWide * 2) * quality.scale)) & ~1
        let captureH = (Int(Double(pointsHigh * 2) * quality.scale)) & ~1
        try await startCapture(display: display, pixelsWide: captureW, pixelsHigh: captureH)

        // Debug aid (`defaults write dev.hyupji.photonport.mac testPattern -bool true`):
        // an animated window on the virtual display generates a constant frame
        // stream so steady-state latency can be measured without user activity.
        if UserDefaults.standard.bool(forKey: "testPattern") {
            let id = vd.displayID
            Task { @MainActor in TestPattern.show(on: id) }
        }
    }

    /// Tear down and rebuild when the phone announces new dimensions. Loops
    /// until the built display matches the latest hello, so rotations that
    /// arrive mid-rebuild aren't lost (and rapid flip-flops settle once).
    private var reconfiguring = false
    private func reconfigure(_ info: PhoneInfo) async {
        guard !reconfiguring, !stopped else { return }
        reconfiguring = true
        defer { reconfiguring = false }
        var target = info
        while !stopped {
            Log.info("reconfiguring for \(target.pixelsWide)x\(target.pixelsHigh)")
            if let stream { try? await stream.stopCapture() }
            stream = nil
            audioStream?.stopCapture { _ in }
            audioStream = nil
            audioTap?.stop()   // un-mutes the Mac between rebuilds
            audioTap = nil
            cgStream?.stop()
            cgStream = nil
            if let encoder { VTCompressionSessionInvalidate(encoder) }
            encoder = nil
            virtualDisplay = nil   // removes the old display
            needsKeyframe = true
            do {
                try await setupExtend(target)
            } catch {
                Log.info("reconfigure failed: \(error)")
                await status("Rotation failed: \(error.localizedDescription)")
                return
            }
            if let latest = lastHello,
               latest.pixelsWide != target.pixelsWide || latest.pixelsHigh != target.pixelsHigh {
                target = latest   // rotated again while we were rebuilding
                continue
            }
            return
        }
    }

    /// The virtual display takes a moment to show up in shareable content.
    private func findSCDisplay(id: CGDirectDisplayID) async throws -> SCDisplay {
        for _ in 0..<20 {
            let content = try await SCShareableContent.current
            if let display = content.displays.first(where: { $0.displayID == id }) {
                return display
            }
            try await Task.sleep(for: .milliseconds(250))
        }
        throw NSError(domain: "MacSender", code: 3,
                      userInfo: [NSLocalizedDescriptionKey: "virtual display never appeared in SCShareableContent"])
    }

    /// HDR is used only when every link in the chain supports it: the
    /// receiver announced an EDR panel, the user hasn't disabled it, and
    /// this Mac runs macOS 15+ (SCK HDR capture). The encoder can still
    /// demote to SDR if HEVC Main10 session creation fails (setupEncoder).
    private func resolveHDR(_ info: PhoneInfo) -> Bool {
        guard info.hdr == true, hdrAllowed else { return false }
        guard #available(macOS 15.0, *) else {
            Log.info("receiver supports HDR but SCK HDR capture needs macOS 15+ — staying SDR")
            return false
        }
        return true
    }

    private func startCapture(display: SCDisplay, pixelsWide: Int, pixelsHigh: Int) async throws {
        // Encoder first: a failed HEVC Main10 session demotes hdrActive, and
        // the capture config below must match the encoder's final input.
        setupEncoder(width: pixelsWide, height: pixelsHigh)

        // Backend choice: ScreenCaptureKit tone-maps VIRTUAL displays to SDR
        // even with its HDR presets (measured: EDR 4× test pattern captured
        // pinned at SDR white on canonical, local, and float16 output, while
        // NSScreen reported the display compositing at EDR 5.0). The legacy
        // CGDisplayStream delivers the float16 EDR composite unclipped
        // (peaks 1.0↔1.83 tracking the pattern), so the EDR-extend path
        // rides it. Mirror/SDR stay on SCK. (`-cgcapture NO` for A/B.)
        let wantCGCapture = hdrActive && mode == .extend
            && virtualDisplay?.appliedHDR == true
            && (UserDefaults.standard.object(forKey: "cgcapture") == nil
                || UserDefaults.standard.bool(forKey: "cgcapture"))
        if wantCGCapture, startCGCapture(displayID: display.displayID,
                                         pixelsWide: pixelsWide, pixelsHigh: pixelsHigh) {
            // EDR capture running — no SCK stream needed.
        } else {
            let config: SCStreamConfiguration
            if hdrActive, #available(macOS 15.0, *) {
                // 10-bit HLG capture — for virtual displays this is
                // tone-mapped SDR in an HDR container (see above), but it
                // still cuts banding vs 8-bit; for mirror mode of a real
                // HDR display it carries true HDR.
                config = UserDefaults.standard.string(forKey: "hdrpreset") == "canonical"
                    ? SCStreamConfiguration(preset: .captureHDRStreamCanonicalDisplay)
                    : SCStreamConfiguration(preset: .captureHDRStreamLocalDisplay)
            } else {
                config = SCStreamConfiguration()
                // 420v matches the encoder's native input — skips a BGRA→YUV conversion
                // inside VideoToolbox. (`-pixfmt bgra` reverts for A/B testing.)
                config.pixelFormat = UserDefaults.standard.string(forKey: "pixfmt") == "bgra"
                    ? kCVPixelFormatType_32BGRA
                    : kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
            }
            config.width = pixelsWide
            config.height = pixelsHigh
            // Ask for double the highest target rate: requesting exactly 1/rate
            // makes SCK's rate limiter skip frames that arrive a hair early
            // (beat frequency) — measured ~51fps instead of 60 at 1/60. Receivers
            // slower than the source display are paced in the capture callback.
            config.minimumFrameInterval = CMTime(value: 1, timescale: 240)
            // One buffer is held permanently (keyframe replay) and one sits in
            // the encoder for ~13ms — headroom prevents SCK starvation drops.
            config.queueDepth = 8
            config.showsCursor = !localCursor

            let filter = SCContentFilter(display: display, excludingWindows: [])
            let stream = SCStream(filter: filter, configuration: config, delegate: self)
            try stream.addStreamOutput(self, type: .screen, sampleHandlerQueue: queue)
            try await stream.startCapture()
            self.stream = stream
        }
        captureDisplayID = display.displayID
        lastCursorPNGHash = 0      // rotation rebuilds: re-send the sprite
        lastCursorSent = (-1, -1, false)
        startCursorEcho()
        if audioEnabled {
            // Preferred: system-audio tap (macOS 14.2+) — routes sound to
            // the device Sidecar-style (Mac speakers mute while forwarding)
            // at ~5ms buffers. SCK audio is the dual-playing 20ms fallback.
            // (`-audiotap NO` forces the fallback.)
            let tapAllowed = UserDefaults.standard.object(forKey: "audiotap") == nil
                || UserDefaults.standard.bool(forKey: "audiotap")
            if tapAllowed {
                audioTap = SystemAudioTap { [weak self] pcm, sr in
                    guard let self else { return }
                    // Dedicated queue: audio must never wait behind the
                    // video queue's per-frame convert/encode work — that
                    // head-of-line jitter reached the receiver as dropouts.
                    self.audioQueue.async { self.sendAudioPCM(pcm, sampleRate: sr) }
                }
            }
            if audioTap == nil {
                do { try await startAudioCapture(display: display) }
                catch { Log.info("audio capture failed (video unaffected): \(error)") }
            }
        }
        Log.info("capture started: \(pixelsWide)x\(pixelsHigh) display \(display.displayID) mode \(mode.rawValue) backend=\(cgStream != nil ? "CGDisplayStream-EDR" : "SCK") localCursor=\(localCursor) fps=\(streamFps) hdr=\(hdrActive)")
        let kind = lastHello?.kind ?? "device"
        await status("\(mode == .extend ? "Extending to" : "Mirroring to") \(kind) (\(pixelsWide)×\(pixelsHigh)\(streamFps > 60 ? " @\(streamFps)Hz" : "")\(hdrActive ? " HDR" : ""))")
    }

    // MARK: - System audio forwarding

    private var audioStream: SCStream?

    /// Dedicated audio-only SCStream — independent of the video backend so
    /// the CGDisplayStream EDR path gets audio too. SCK audio is system-wide
    /// (not per-display); the display filter is just a required parameter.
    private func startAudioCapture(display: SCDisplay) async throws {
        let config = SCStreamConfiguration()
        config.capturesAudio = true
        config.excludesCurrentProcessAudio = true
        config.sampleRate = 48_000
        config.channelCount = 2
        // No .screen output attached — tiny video config keeps SCK's
        // internal video path cheap.
        config.width = 2
        config.height = 2
        config.minimumFrameInterval = CMTime(value: 1, timescale: 1)
        let filter = SCContentFilter(display: display, excludingWindows: [])
        let stream = SCStream(filter: filter, configuration: config, delegate: self)
        try stream.addStreamOutput(self, type: .audio, sampleHandlerQueue: audioQueue)
        try await stream.startCapture()
        audioStream = stream
        Log.info("audio forwarding started (48kHz stereo PCM)")
    }

    private var audioChunksSeen = 0

    // Wire-throughput test (`-blast`): saturates the video channel with
    // parser-inert junk frames (bytes 1–255: no start codes, not JSON) so
    // the receiver's stats report the transport's real ceiling.
    private var blastStarted = false
    private static let blastPayload = Data((0..<(1 << 20)).map { _ in UInt8.random(in: 1...255) })
    private var blastBytes = 0
    private var blastLogAt = Date()
    private func scheduleBlast() {
        queue.asyncAfter(deadline: .now() + .milliseconds(1)) { [weak self] in
            guard let self, !self.stopped else { return }
            // pendingSends-gated: the loop only refills as completions land,
            // so bytes/interval ≈ the transport's sustained throughput.
            while self.connectionReady, self.pendingSends < 8 {
                self.sendFramed(Self.blastPayload)
                self.blastBytes += Self.blastPayload.count
            }
            let elapsed = Date().timeIntervalSince(self.blastLogAt)
            if elapsed >= 2 {
                Log.info(String(format: "blast: %.0f Mbit/s sustained",
                                Double(self.blastBytes) * 8 / elapsed / 1_000_000))
                self.blastBytes = 0
                self.blastLogAt = Date()
            }
            self.scheduleBlast()
        }
    }

    /// float32 (SCK native) → interleaved 16-bit PCM → base64 JSON on the
    /// existing control framing. ~1.5Mbps — noise next to the video stream,
    /// and old receivers ignore the unknown message type.
    private func handleAudio(_ sample: CMSampleBuffer) {
        guard connectionReady,
              let fmt = CMSampleBufferGetFormatDescription(sample),
              let asbd = CMAudioFormatDescriptionGetStreamBasicDescription(fmt)?.pointee,
              asbd.mFormatFlags & kAudioFormatFlagIsFloat != 0 else { return }
        let frames = CMSampleBufferGetNumSamples(sample)
        guard frames > 0 else { return }
        if audioChunksSeen == 0 {
            Log.info("audio chunk size: \(frames) frames (\(String(format: "%.1f", Double(frames) / asbd.mSampleRate * 1000))ms) — the floor of the forwarding latency")
        }
        audioChunksSeen += 1
        let maxBuffers = max(Int(asbd.mChannelsPerFrame), 1)
        let abl = AudioBufferList.allocate(maximumBuffers: maxBuffers)
        defer { free(abl.unsafeMutablePointer) }
        var blockBuffer: CMBlockBuffer?
        guard CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(
            sample, bufferListSizeNeededOut: nil,
            bufferListOut: abl.unsafeMutablePointer,
            bufferListSize: AudioBufferList.sizeInBytes(maximumBuffers: maxBuffers),
            blockBufferAllocator: kCFAllocatorDefault,
            blockBufferMemoryAllocator: kCFAllocatorDefault,
            flags: 0, blockBufferOut: &blockBuffer) == noErr else { return }
        let buffers = Array(abl)
        guard let firstData = buffers.first?.mData else { return }
        let nonInterleaved = asbd.mFormatFlags & kAudioFormatFlagIsNonInterleaved != 0

        var pcm = Data(count: frames * 2 * MemoryLayout<Int16>.size)
        pcm.withUnsafeMutableBytes { raw in
            let out = raw.bindMemory(to: Int16.self)
            func clamp16(_ v: Float) -> Int16 { Int16(max(-1, min(1, v)) * 32767) }
            if nonInterleaved, buffers.count >= 2,
               let l = buffers[0].mData, let r = buffers[1].mData {
                let lf = l.assumingMemoryBound(to: Float.self)
                let rf = r.assumingMemoryBound(to: Float.self)
                for i in 0..<frames {
                    out[i * 2] = clamp16(lf[i])
                    out[i * 2 + 1] = clamp16(rf[i])
                }
            } else {
                let f = firstData.assumingMemoryBound(to: Float.self)
                let stereo = !nonInterleaved && asbd.mChannelsPerFrame >= 2
                for i in 0..<frames {
                    out[i * 2] = clamp16(stereo ? f[i * 2] : f[i])
                    out[i * 2 + 1] = clamp16(stereo ? f[i * 2 + 1] : f[i])
                }
            }
        }
        sendAudioPCM(pcm, sampleRate: Int(asbd.mSampleRate))
    }

    /// Shared by the SCK audio path and the system-audio tap. `t` (Mac wall
    /// clock) lets the receiver compute audio forwarding latency the same
    /// way video e2e works.
    private func sendAudioPCM(_ pcm: Data, sampleRate: Int) {
        let t = Date().timeIntervalSince1970 * 1000
        let payload = Data("{\"type\":\"audio\",\"sr\":\(sampleRate),\"ch\":2,\"t\":\(t),\"d\":\"\(pcm.base64EncodedString())\"}".utf8)
        var header = UInt32(payload.count).bigEndian
        var frame = Data(bytes: &header, count: 4)
        frame.append(payload)
        // Dedicated socket when it's up; the video socket as fallback.
        if audioConnectionReady, let audioConnection {
            audioConnection.send(content: frame, completion: .contentProcessed { _ in })
        } else if connectionReady, let connection {
            connection.send(content: frame, completion: .contentProcessed { _ in })
        }
    }

    // MARK: - EDR capture backend (CGDisplayStream)

    private var cgStream: CGDisplayStream?
    private var hlgConverter: EDRToHLGConverter?

    /// float16 extended-sRGB capture of the EDR virtual display, converted
    /// on-GPU to reference-pinned HLG (see EDRToHLGConverter — VideoToolbox's
    /// own float16→HLG mapping blew highlights out on the receiver). Returns
    /// false when the stream or converter can't be built — caller falls back
    /// to SCK.
    private func startCGCapture(displayID: CGDirectDisplayID,
                                pixelsWide: Int, pixelsHigh: Int) -> Bool {
        guard let converter = hlgConverter ?? EDRToHLGConverter() else {
            Log.info("EDR→HLG converter unavailable — falling back to SCK")
            return false
        }
        hlgConverter = converter
        let props: [CFString: Any] = [
            CGDisplayStream.showCursor: !localCursor,
            CGDisplayStream.minimumFrameTime: 1.0 / 240.0,
            CGDisplayStream.queueDepth: 8,
        ]
        let stream = CGDisplayStream(
            dispatchQueueDisplay: displayID,
            outputWidth: pixelsWide,
            outputHeight: pixelsHigh,
            pixelFormat: Int32(kCVPixelFormatType_64RGBAHalf),
            properties: props as CFDictionary,
            queue: queue
        ) { [weak self] status, _, surface, _ in
            guard let self, status == .frameComplete, let surface else { return }
            var pbUnmanaged: Unmanaged<CVPixelBuffer>?
            // Wrapping retains the IOSurface; the converter reads it into its
            // own pooled output before this handler returns, so stream reuse
            // can't tear the frame the encoder sees.
            CVPixelBufferCreateWithIOSurface(nil, surface, nil, &pbUnmanaged)
            guard let pb = pbUnmanaged?.takeRetainedValue(),
                  let hlg = self.hlgConverter?.convert(pb) else { return }
            self.handleCapturedFrame(hlg, pts: CMClockGetTime(CMClockGetHostTimeClock()))
        }
        guard let stream, stream.start() == .success else {
            Log.info("CGDisplayStream EDR capture failed to start — falling back to SCK")
            return false
        }
        cgStream = stream
        return true
    }

    func stop() {
        stopped = true
        cursorTimer?.cancel()
        cursorTimer = nil
        cursorImageTimer?.cancel()
        cursorImageTimer = nil
        stream?.stopCapture { _ in }
        stream = nil
        audioStream?.stopCapture { _ in }
        audioStream = nil
        audioTap?.stop()   // un-mutes the Mac
        audioTap = nil
        cgStream?.stop()
        cgStream = nil
        connection?.cancel()
        connection = nil
        audioConnection?.cancel()
        audioConnection = nil
        audioConnectionReady = false
        if let encoder { VTCompressionSessionInvalidate(encoder) }
        encoder = nil
        virtualDisplay = nil   // releasing it removes the display
        queue.async { [weak self] in
            // Unblock a start() that is still waiting for the hello.
            self?.helloContinuation?.resume(throwing: CancellationError())
            self?.helloContinuation = nil
        }
    }

    /// Drop the current connection and dial again — fresh TCP through the
    /// tunnel, fresh accept on the phone. Bound to the UI Reconnect button.
    func forceReconnect() {
        queue.async { [weak self] in
            guard let self, !self.stopped else { return }
            Log.info("manual reconnect requested")
            self.disconnectedSince = Date()   // fresh grace window
            self.scheduleReconnect()
        }
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        if stream === audioStream {
            // Audio is best-effort — losing it must never rebuild the
            // video pipeline.
            Log.info("audio stream stopped: \(error)")
            audioStream = nil
            return
        }
        Log.info("stream stopped with error: \(error)")
        Task { await status("Capture stopped: \(error.localizedDescription)") }
        // E.g. display sleep can tear the virtual display down underneath the
        // stream — rebuild instead of sitting dead until an app restart.
        guard !stopped, mode == .extend else { return }
        self.stream = nil
        scheduleCaptureRecovery()
    }

    /// Retry until capture is back (a rebuild during display sleep can fail).
    private func scheduleCaptureRecovery() {
        queue.asyncAfter(deadline: .now() + 3.0) { [weak self] in
            guard let self, !self.stopped, self.stream == nil,
                  let hello = self.lastHello else { return }
            Log.info("capture died — rebuilding pipeline")
            Task {
                await self.reconfigure(hello)
                self.queue.async {
                    if self.stream == nil { self.scheduleCaptureRecovery() }
                }
            }
        }
    }

    // MARK: - Connection (with retry)

    // Guards against a stale async USB dial adopting after a newer one (or a
    // manual reconnect) superseded it. Only touched on `queue`.
    private var dialGeneration = 0

    private func connect() {
        guard !stopped else { return }
        switch transport {
        case .tcp(let endpoint): connectTCP(endpoint)
        case .usb(let udid, let port): connectUSB(udid: udid, port: port)
        }
    }

    /// Bookkeeping shared by both transports once a connection is live.
    private func becomeReady(_ conn: NWConnection) {
        Log.info("connection ready to \(endpointName)")
        connectionReady = true
        everConnected = true
        disconnectedSince = nil
        needsKeyframe = true   // new peer needs SPS/PPS + IDR
        // A reconnect can recreate the phone's video view with no cursor
        // sprite; the sprite is otherwise only sent on shape change, so the
        // cursor would stay invisible until the user hovers something that
        // changes it. Reset the dedup state to re-send sprite + position to
        // the fresh peer — the cursor analogue of forcing a keyframe.
        lastCursorPNGHash = 0
        lastCursorSent = (-1, -1, false)
        lastReceived = Date()  // fresh grace period for the watchdog
        receiveControl(on: conn)
        dialAudioConnection()
        Task { await self.status("Connected to \(self.endpointName)") }
    }

    // MARK: - Dedicated audio connection (port+1)
    //
    // Audio shares no socket with video: on the main connection a ~5ms PCM
    // chunk queues behind hundreds of KB of in-flight ProRes frames
    // (head-of-line blocking measured as ~60ms of audio arrival latency at
    // 240Mbps). A second TCP connection makes audio delivery independent.
    // Bonjour WiFi endpoints can't derive port+1 — they keep the shared
    // socket (audio still works, just with the old latency).
    private var audioConnection: NWConnection?
    private var audioConnectionReady = false

    private func dialAudioConnection() {
        audioConnection?.cancel()
        audioConnection = nil
        audioConnectionReady = false
        let generation = dialGeneration
        switch transport {
        case .usb(let udid, let port):
            Task { [weak self] in
                guard let self else { return }
                do {
                    let conn = try await Usbmux.dial(udid: udid, port: port + 1, queue: queue)
                    queue.async {
                        guard generation == self.dialGeneration, !self.stopped else {
                            conn.cancel()
                            return
                        }
                        self.adoptAudioConnection(conn)
                    }
                } catch {
                    Log.info("audio connection dial failed (audio rides the video socket): \(error)")
                }
            }
        case .tcp(let endpoint):
            guard case .hostPort(let host, let port) = endpoint,
                  let nextPort = NWEndpoint.Port(rawValue: port.rawValue + 1) else {
                Log.info("audio connection: endpoint has no derivable port — audio rides the video socket")
                return
            }
            let options = NWProtocolTCP.Options()
            options.noDelay = true
            let conn = NWConnection(host: host, port: nextPort,
                                    using: NWParameters(tls: nil, tcp: options))
            conn.start(queue: queue)
            adoptAudioConnection(conn)
        }
    }

    private func adoptAudioConnection(_ conn: NWConnection) {
        audioConnection = conn
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.audioConnectionReady = true
                Log.info("audio connection ready (dedicated socket)")
            case .failed, .cancelled:
                self.audioConnectionReady = false
            default: break
            }
        }
        if conn.state == .ready { audioConnectionReady = true }
    }

    private func connectTCP(_ endpoint: NWEndpoint) {
        let options = NWProtocolTCP.Options()
        options.noDelay = true   // latency matters more than throughput here
        let params = NWParameters(tls: nil, tcp: options)
        let conn = NWConnection(to: endpoint, using: params)
        connection = conn
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.becomeReady(conn)
            case .failed(let error):
                Log.info("connection failed: \(error)")
                self.connectionReady = false
                self.scheduleReconnect()
            case .waiting(let error):
                // On loopback there is no "path change" to wake us up again
                // (e.g. a manual -host tunnel not started yet) — treat
                // waiting as failure and poll by reconnecting.
                Log.info("connection waiting: \(error) — will retry")
                self.connectionReady = false
                Task { await self.status("Waiting for receiver at \(self.endpointName)…") }
                self.scheduleReconnect()
            case .cancelled:
                self.connectionReady = false
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    /// Dial through macOS's built-in usbmuxd — no external tunnel needed.
    /// The handshake is async, so adoption is gated on `dialGeneration`.
    private func connectUSB(udid: String?, port: UInt16) {
        dialGeneration += 1
        let generation = dialGeneration
        Task { [weak self] in
            guard let self else { return }
            do {
                let conn = try await Usbmux.dial(udid: udid, port: port, queue: queue)
                queue.async {
                    guard generation == self.dialGeneration, !self.stopped else {
                        conn.cancel()
                        return
                    }
                    self.connection = conn
                    conn.stateUpdateHandler = { [weak self] state in
                        guard let self else { return }
                        switch state {
                        case .failed(let error):
                            Log.info("usb connection failed: \(error)")
                            self.connectionReady = false
                            self.scheduleReconnect()
                        case .cancelled:
                            self.connectionReady = false
                        default:
                            break
                        }
                    }
                    self.becomeReady(conn)
                }
            } catch {
                // Distinct guidance per failure: cable missing vs app closed.
                let hint: String
                switch error as? Usbmux.Failure {
                case .noDevice:
                    hint = "Waiting for a USB device — plug in the iPhone or iPad…"
                case .refused:
                    hint = "Device found — open the PhotonPort app on it…"
                default:
                    Log.info("usb dial failed: \(error)")
                    hint = "USB connection failed: \(error.localizedDescription)"
                }
                queue.async {
                    guard generation == self.dialGeneration, !self.stopped else { return }
                    Task { await self.status(hint) }
                    self.scheduleReconnect()
                }
            }
        }
    }

    private func scheduleReconnect() {
        guard !stopped else { return }
        if everConnected {
            if let since = disconnectedSince {
                if Date().timeIntervalSince(since) > disconnectGraceSeconds {
                    Log.info("device gone for >\(Int(disconnectGraceSeconds))s — ending session")
                    Task { @MainActor in self.onDisconnected?() }
                    return
                }
            } else {
                disconnectedSince = Date()
                Task { await status("Connection lost — retrying for \(Int(disconnectGraceSeconds))s…") }
            }
        }
        connectionReady = false
        dialGeneration += 1   // a USB dial still in flight must not adopt
        connection?.cancel()
        connection = nil
        audioConnection?.cancel()
        audioConnection = nil
        audioConnectionReady = false
        pendingSends = 0
        pendingEncodes = 0
        queue.asyncAfter(deadline: .now() + 1.0) { [weak self] in
            self?.connect()
        }
    }

    // MARK: - Liveness (ping + watchdog)

    private func schedulePing() {
        queue.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            guard let self, !self.stopped else { return }
            if self.connectionReady {
                // Liveness + send-side health for the phone's overlay.
                let elapsed = Date().timeIntervalSince(self.capWindowStart)
                let capFps = elapsed > 0 ? Int(Double(self.capFrames) / elapsed) : 0
                self.capFrames = 0
                self.capWindowStart = Date()
                let sorted = self.inputLatencies.sorted()
                let inp50 = sorted.isEmpty ? 0 : sorted[sorted.count / 2].rounded()
                let inp95 = sorted.isEmpty ? 0 : sorted[min(sorted.count - 1, Int(Double(sorted.count) * 0.95))].rounded()
                self.sendJSONFrame("{\"type\":\"ping\",\"drops\":\(self.dropsTotal),\"pending\":\(self.pendingSends),\"inp50\":\(inp50),\"inp95\":\(inp95),\"capFps\":\(capFps)}")
                // Pipeline diagnosis (`defaults write … diag -bool true`):
                // one line per ping with every gate's state.
                if UserDefaults.standard.bool(forKey: "diag") {
                    Log.info("diag: capFps=\(capFps) drops=\(self.dropsTotal) pendingEncodes=\(self.pendingEncodes) pendingSends=\(self.pendingSends) needsKF=\(self.needsKeyframe)")
                }
            }
            self.schedulePing()
        }
    }

    private func scheduleWatchdog() {
        queue.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            guard let self, !self.stopped else { return }
            if self.connectionReady, Date().timeIntervalSince(self.lastReceived) > 5 {
                Log.info("watchdog: nothing from the phone for >5s — reconnecting")
                Task { await self.status("Connection stale — reconnecting…") }
                self.scheduleReconnect()
            }
            // A reconnect on a static screen produces no capture frames, so
            // the receiver would stay black — replay the last frame as IDR.
            if self.connectionReady, self.needsKeyframe,
               Date().timeIntervalSince(self.lastCaptureAt) > 1,
               let pixelBuffer = self.lastPixelBuffer {
                Log.info("static screen after reconnect — replaying last frame as keyframe")
                self.encode(pixelBuffer, pts: CMClockGetTime(CMClockGetHostTimeClock()))
            }
            self.scheduleWatchdog()
        }
    }

    // MARK: - Local cursor echo (Mac -> phone)

    private func startCursorEcho() {
        guard localCursor else { return }
        cursorTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(8))   // 120Hz
        timer.setEventHandler { [weak self] in self?.pollCursorPosition() }
        timer.resume()
        cursorTimer = timer
        scheduleCursorImagePoll()
    }

    /// Sprite changes (arrow ↔ I-beam ↔ resize…) must land fast or the wrong
    /// cursor shows over hot areas — poll at 30Hz on the main thread (NSCursor
    /// is AppKit), hash the raw bitmap, and only PNG-encode + send on change.
    ///
    /// A dedicated timer (cancelled+replaced here, like cursorTimer above) — not
    /// a self-rescheduling asyncAfter chain. Every rebuild re-enters
    /// startCursorEcho, and sleep/wake rebuilds happen often; a recursive chain
    /// guarded only by `stopped` would stack one extra 30Hz main-thread
    /// TIFF-encode loop per rebuild, creeping CPU to ~50% until a restart (#75).
    private func scheduleCursorImagePoll() {
        cursorImageTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + 0.033, repeating: .milliseconds(33))
        timer.setEventHandler { [weak self] in
            guard let self, !self.stopped, self.localCursor else { return }
            self.pollCursorImage()
        }
        timer.resume()
        cursorImageTimer = timer
    }

    private func pollCursorPosition() {
        guard connectionReady, captureDisplayID != 0,
              let loc = CGEvent(source: nil)?.location else { return }
        let bounds = CGDisplayBounds(captureDisplayID)
        guard bounds.width > 0, bounds.height > 0 else { return }
        if bounds.contains(loc) {
            let x = (loc.x - bounds.minX) / bounds.width
            let y = (loc.y - bounds.minY) / bounds.height
            if !lastCursorSent.visible
                || abs(x - lastCursorSent.x) > 0.0004 || abs(y - lastCursorSent.y) > 0.0004 {
                lastCursorSent = (x, y, true)
                sendJSONFrame(String(format: "{\"type\":\"cursor\",\"x\":%.4f,\"y\":%.4f,\"v\":1}", x, y))
            }
        } else if lastCursorSent.visible {
            lastCursorSent.visible = false
            sendJSONFrame("{\"type\":\"cursor\",\"v\":0}")
        }
    }

    private func pollCursorImage() {
        // Display size read LIVE, not snapshotted at capture start: the
        // HiDPI mode settles (and macOS re-flips it) asynchronously, and a
        // sprite normalized against the 1x size renders at half size on the
        // device. Mixing the size into the dedup hash re-sends the sprite
        // whenever the mode flips, so the proportion always heals.
        guard connectionReady, captureDisplayID != 0,
              let cursor = NSCursor.currentSystem else { return }
        let displaySize = CGDisplayBounds(captureDisplayID).size   // points, current mode
        guard displaySize.width > 0, displaySize.height > 0 else { return }
        let image = cursor.image
        guard let tiff = image.tiffRepresentation else { return }
        let hash = tiff.hashValue ^ Int(displaySize.width) &* 31
        guard hash != lastCursorPNGHash else { return }
        guard let rep = NSBitmapImageRep(data: tiff),
              let png = rep.representation(using: .png, properties: [:]),
              png.count < 24_000 else { return }
        lastCursorPNGHash = hash
        let size = image.size            // Mac points
        let hot = cursor.hotSpot
        // Normalized against the display so the phone can size/anchor the
        // sprite without knowing capture scale or HiDPI factor.
        let msg = String(format:
            "{\"type\":\"cursorImg\",\"nw\":%.5f,\"nh\":%.5f,\"ax\":%.3f,\"ay\":%.3f,\"png\":\"%@\"}",
            size.width / displaySize.width,
            size.height / displaySize.height,
            size.width > 0 ? hot.x / size.width : 0,
            size.height > 0 ? hot.y / size.height : 0,
            png.base64EncodedString())
        queue.async { self.sendJSONFrame(msg) }
    }

    // MARK: - Control messages (phone -> Mac)

    private func receiveControl(on conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] data, _, _, error in
            guard let self, error == nil, let data, data.count == 4 else { return }
            let len = Int(UInt32(bigEndian: data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
            guard len > 0, len < 1 << 20 else { return }
            conn.receive(minimumIncompleteLength: len, maximumLength: len) { [weak self] payload, _, _, error in
                guard let self, error == nil, let payload, payload.count == len else { return }
                self.handleControl(payload)
                self.receiveControl(on: conn)
            }
        }
    }

    private func handleControl(_ payload: Data) {
        lastReceived = Date()
        guard let obj = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let type = obj["type"] as? String else {
            Log.info("unparseable control message (\(payload.count) bytes)")
            return
        }
        switch type {
        case "ping":
            // Echo with our clock so the phone can estimate the offset
            // (NTP-style) and compute true end-to-end frame latency.
            if let t = obj["t"] as? Double {
                let mt = Date().timeIntervalSince1970 * 1000
                sendJSONFrame("{\"type\":\"pong\",\"t\":\(t),\"mt\":\(mt)}")
            }
        case "stats":
            // Aggregated pipeline health measured on the phone — logged here
            // so one file holds both ends of the story.
            if let json = try? JSONSerialization.data(withJSONObject: obj),
               let line = String(data: json, encoding: .utf8) {
                Log.info("PHONE-STATS \(line) | mac drops=\(dropsThisWindow) pending=\(pendingSends)")
                dropsThisWindow = 0
            }
        case "hello":
            if let info = try? JSONDecoder().decode(PhoneInfo.self, from: payload) {
                let previous = lastHello
                lastHello = info
                Task { @MainActor in self.onHello?(info) }
                if let continuation = helloContinuation {
                    helloContinuation = nil
                    continuation.resume(returning: info)
                } else if mode == .extend, stream != nil, let previous,
                          previous.pixelsWide != info.pixelsWide
                          || previous.pixelsHigh != info.pixelsHigh {
                    // Phone rotated — rebuild after a short debounce so a
                    // flurry of orientation flips settles into one rebuild.
                    Task {
                        try? await Task.sleep(for: .milliseconds(300))
                        guard let current = self.lastHello,
                              current.pixelsWide == info.pixelsWide,
                              current.pixelsHigh == info.pixelsHigh else { return }
                        await self.reconfigure(info)
                    }
                }
            }
        case "touch":
            if let phase = obj["phase"] as? String,
               let x = obj["x"] as? Double,
               let y = obj["y"] as? Double {
                inputInjector?.handleTouch(phase: phase, x: x, y: y)
                if let t = obj["t"] as? Double {
                    let delta = Date().timeIntervalSince1970 * 1000 - t
                    if delta > -50, delta < 1000 {
                        inputLatencies.append(max(delta, 0))
                        if inputLatencies.count > 240 { inputLatencies.removeFirst(120) }
                    }
                }
            }
        case "scroll":
            if let dx = obj["dx"] as? Double, let dy = obj["dy"] as? Double {
                inputInjector?.handleScroll(dx: dx, dy: dy)
            }
        case "kf":
            // The phone's decoder lost sync (e.g. it attached mid-GOP and
            // periodic keyframes are off) — force an IDR on the next frame.
            Log.info("phone requested keyframe")
            needsKeyframe = true
        default:
            Log.info("unknown control message type: \(type)")
        }
    }

    private func waitForHello() async throws -> PhoneInfo {
        if let lastHello { return lastHello }
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                if let hello = self.lastHello {
                    continuation.resume(returning: hello)
                } else {
                    self.helloContinuation = continuation
                }
            }
        }
    }

    // MARK: - Encoder setup

    private func setupEncoder(width: Int, height: Int) {
        // A fresh session never owes us output handlers — clear the gate so
        // callbacks the invalidated session swallowed can't wedge it shut.
        queue.async { self.pendingEncodes = 0 }

        // Experimental (`-prores`): intra-only ProRes 422 on the media
        // engine's DEDICATED ProRes block — sidesteps the HEVC engine's
        // ~430Mpx/s ceiling entirely, so native panels run at full 120fps.
        // Proxy ≈330Mbps / LT ≈540Mbps at native 120 — the measured ~1Gbps
        // usbmux wire takes either. 10-bit 4:2:2, so the HDR path's HLG
        // buffers ride through losslessly. (`-prores lt` for the LT flavor.)
        if let flavor = UserDefaults.standard.string(forKey: "prores") {
            usingProRes = true
            usingHEVC = false
            let codec: CMVideoCodecType = flavor == "lt"
                ? kCMVideoCodecType_AppleProRes422LT
                : kCMVideoCodecType_AppleProRes422Proxy
            VTCompressionSessionCreate(
                allocator: nil,
                width: Int32(width), height: Int32(height),
                codecType: codec,
                encoderSpecification: [kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: kCFBooleanTrue] as CFDictionary,
                imageBufferAttributes: nil,
                compressedDataAllocator: nil,
                outputCallback: nil,
                refcon: nil,
                compressionSessionOut: &encoder
            )
            if let encoder {
                VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_RealTime, value: kCFBooleanTrue)
                VTCompressionSessionPrepareToEncodeFrames(encoder)
                Log.info("encoder ready: \(width)x\(height) ProRes-422-\(flavor == "lt" ? "LT" : "Proxy") (intra, no rate control) \(streamFps)fps quality=\(quality.rawValue)")
                return
            }
            Log.info("ProRes session creation failed — falling back to the standard codecs")
            usingProRes = false
        }

        // Low-latency rate control: the hardware encoder emits every frame
        // immediately instead of pipelining. (`-lowlatency NO` for A/B.)
        let lowLatency = UserDefaults.standard.object(forKey: "lowlatency") == nil
            || UserDefaults.standard.bool(forKey: "lowlatency")
        let spec: CFDictionary? = lowLatency
            ? [kVTVideoEncoderSpecification_EnableLowLatencyRateControl: kCFBooleanTrue] as CFDictionary
            : nil
        // Codec choice:
        //  - HDR rides HEVC Main10 (H.264 has no 10-bit hardware path here).
        //  - SDR above 60fps ALSO needs HEVC: H.264 levels top out at 5.2
        //    (~535M luma samples/s) and a native panel at 120fps exceeds
        //    that — VideoToolbox then rejects EVERY frame with noErr +
        //    nil buffer (measured: 2816×1940@120 H.264 = zero output).
        //    HEVC levels reach 6.2 (8K120), so it has headroom for years.
        //  - SDR at ≤60fps stays H.264: universally fast, proven default.
        // If an HEVC session can't be created, demote to SDR H.264 (and 60).
        usingHEVC = hdrActive || streamFps > 60
        if usingHEVC {
            VTCompressionSessionCreate(
                allocator: nil,
                width: Int32(width), height: Int32(height),
                codecType: kCMVideoCodecType_HEVC,
                encoderSpecification: spec,
                imageBufferAttributes: nil,
                compressedDataAllocator: nil,
                outputCallback: nil,
                refcon: nil,
                compressionSessionOut: &encoder
            )
            if encoder == nil {
                Log.info("HEVC session creation failed — falling back to SDR H.264 60fps")
                hdrActive = false
                usingHEVC = false
                streamFps = min(streamFps, 60)
            }
        }
        if encoder == nil {
            VTCompressionSessionCreate(
                allocator: nil,
                width: Int32(width), height: Int32(height),
                codecType: kCMVideoCodecType_H264,
                encoderSpecification: spec,
                imageBufferAttributes: nil,
                compressedDataAllocator: nil,
                outputCallback: nil,
                refcon: nil,
                compressionSessionOut: &encoder
            )
        }
        guard let encoder else {
            Log.info("FATAL: VTCompressionSessionCreate failed")
            return
        }
        // Low-latency settings: real-time, no B-frames, periodic keyframes.
        VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_RealTime, value: kCFBooleanTrue)
        VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_AllowFrameReordering, value: kCFBooleanFalse)
        if hdrActive {
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_ProfileLevel, value: kVTProfileLevel_HEVC_Main10_AutoLevel)
            // BT.2100 HLG tags — written into the HEVC VUI so the receiver's
            // decoder/display layer knows to render EDR. Matches the canonical
            // HDR capture preset's output color space.
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_ColorPrimaries, value: kCMFormatDescriptionColorPrimaries_ITU_R_2020)
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_TransferFunction, value: kCMFormatDescriptionTransferFunction_ITU_R_2100_HLG)
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_YCbCrMatrix, value: kCMFormatDescriptionYCbCrMatrix_ITU_R_2020)
        } else if usingHEVC {
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_ProfileLevel, value: kVTProfileLevel_HEVC_Main_AutoLevel)
        } else {
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_ProfileLevel, value: kVTProfileLevel_H264_High_AutoLevel)
        }
        // No periodic IDRs: each one is a bitrate spike → transmit-time hiccup.
        // TCP never loses data, and we force a keyframe on reconnect/drop.
        VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_MaxKeyFrameInterval, value: 3600 as CFNumber)
        VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration, value: 60 as CFNumber)
        VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_MaxFrameDelayCount, value: 0 as CFNumber)
        // 120Hz halves the per-frame budget — give the rate controller 50%
        // more headroom so high-motion 120fps doesn't smear. (HEVC's better
        // quality-per-bit absorbs the 10-bit overhead on the HDR path.)
        let bitrate = streamFps > 60 ? quality.bitrate * 3 / 2 : quality.bitrate
        VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_AverageBitRate, value: bitrate as CFNumber)
        VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_ExpectedFrameRate, value: streamFps as CFNumber)
        VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_PrioritizeEncodingSpeedOverQuality, value: kCFBooleanTrue)
        VTCompressionSessionPrepareToEncodeFrames(encoder)
        Log.info("encoder ready: \(width)x\(height) \(hdrActive ? "HEVC-Main10-HLG" : usingHEVC ? "HEVC-Main" : "H.264") \(bitrate / 1_000_000)Mbps \(streamFps)fps quality=\(quality.rawValue) lowLatencyRC=\(lowLatency)")
    }

    // MARK: - Capture callback

    func stream(_ stream: SCStream,
                didOutputSampleBuffer sampleBuffer: CMSampleBuffer,
                of type: SCStreamOutputType) {
        if type == .audio {
            handleAudio(sampleBuffer)
            return
        }
        guard type == .screen,
              CMSampleBufferIsValid(sampleBuffer),
              let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer)
        else { return }
        handleCapturedFrame(pixelBuffer, pts: CMSampleBufferGetPresentationTimeStamp(sampleBuffer))
    }

    /// Shared by both capture backends (SCK sample buffers and the
    /// CGDisplayStream EDR path) — gates, pacing, then encode.
    private func handleCapturedFrame(_ pixelBuffer: CVPixelBuffer, pts: CMTime) {
        lastPixelBuffer = pixelBuffer
        lastCaptureAt = Date()
        capFrames += 1
        if diagEnabled {
            diagFrameCounter += 1
            if diagFrameCounter % 240 == 1 { logCapturePeak(pixelBuffer) }
        }

        // No receiver, or the socket is backed up: skip this frame entirely.
        guard connectionReady else { return }
        if pendingSends > maxPendingSends {
            // Pre-encode skip: the P-frame chain stays valid — the encoder
            // references its own last output, and TCP delivers every encoded
            // frame. Forcing an IDR here (as this path once did) turned each
            // drop into a multi-hundred-KB keyframe, which backed the socket
            // up further — a drop→IDR→drop spiral at 120fps (measured: fps
            // collapsing to 0 while capFps held 80+).
            dropsThisWindow += 1
            dropsTotal += 1
            return
        }

        // Encoder saturation: at native res a single HEVC encode takes
        // ~13ms (~79fps ceiling), so 120fps input queues INSIDE VideoToolbox
        // — pure latency (measured: cap→socket 62ms under load vs 14ms
        // idle, exactly ~5 queued frames). Keep at most 2 in flight and
        // skip the rest; delivered fps = whatever the encoder sustains,
        // at ~1 frame of latency instead of 5.
        if pendingEncodes >= 2 {
            dropsThisWindow += 1
            dropsTotal += 1
            return
        }

        // Pace to the negotiated rate: mirror mode can capture a 120Hz Mac
        // panel for a 60Hz receiver. Skipping before the encoder keeps the
        // P-frame chain intact (the encoder only references frames it saw).
        // 2ms slack absorbs vsync jitter so a clean 60→60 stream isn't cut.
        if Date().timeIntervalSince(lastEncodedAt) < 1.0 / Double(streamFps) - 0.002 {
            return
        }
        lastEncodedAt = Date()

        encode(pixelBuffer, pts: pts)
    }

    // HDR ground truth (`-diag`): peak luma of the captured buffer. For the
    // 10-bit biplanar formats the HDR preset uses, HLG SDR-white sits around
    // signal ~0.75 (≈770/1023) — sustained peaks near 1023 while HDR content
    // plays prove the EDR composite survives into the capture; peaks pinned
    // ≤~770 mean the Mac side is serving tone-mapped SDR.
    private func logCapturePeak(_ buffer: CVPixelBuffer) {
        let fmt = CVPixelBufferGetPixelFormatType(buffer)
        let cc = String(bytes: [UInt8(fmt >> 24 & 0xff), UInt8(fmt >> 16 & 0xff),
                                UInt8(fmt >> 8 & 0xff), UInt8(fmt & 0xff)],
                        encoding: .ascii) ?? "?"
        if fmt == kCVPixelFormatType_64RGBAHalf {
            CVPixelBufferLockBaseAddress(buffer, .readOnly)
            defer { CVPixelBufferUnlockBaseAddress(buffer, .readOnly) }
            guard let base = CVPixelBufferGetBaseAddress(buffer) else { return }
            let width = CVPixelBufferGetWidth(buffer)
            let height = CVPixelBufferGetHeight(buffer)
            let stride = CVPixelBufferGetBytesPerRow(buffer)
            var peak: Float = 0
            var y = 0
            while y < height {
                let row = base.advanced(by: y * stride).assumingMemoryBound(to: Float16.self)
                var x = 0
                while x < width * 4 {            // RGBA; alpha rides along, harmless
                    let v = Float(row[x])
                    if v > peak { peak = v }
                    x += 32                      // every 8th pixel
                }
                y += 8
            }
            Log.info("diag capture: format=RGhA peakLinear=\(peak) (SDR white = 1.0)")
            return
        }
        // Plane 0 is 16-bit luma words in all the 10-bit biplanar variants
        // (420 and the 4:4:4 'xf44' the canonical HDR preset delivers).
        guard [kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange,
               kCVPixelFormatType_420YpCbCr10BiPlanarFullRange,
               kCVPixelFormatType_444YpCbCr10BiPlanarVideoRange,
               kCVPixelFormatType_444YpCbCr10BiPlanarFullRange].contains(fmt) else {
            Log.info("diag capture: format=\(cc) (peak scan is 10-bit-only)")
            return
        }
        CVPixelBufferLockBaseAddress(buffer, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(buffer, .readOnly) }
        guard let base = CVPixelBufferGetBaseAddressOfPlane(buffer, 0) else { return }
        let width = CVPixelBufferGetWidthOfPlane(buffer, 0)
        let height = CVPixelBufferGetHeightOfPlane(buffer, 0)
        let stride = CVPixelBufferGetBytesPerRowOfPlane(buffer, 0)
        var peak: UInt16 = 0
        var y = 0
        while y < height {                       // every 8th row/col is plenty
            let row = base.advanced(by: y * stride).assumingMemoryBound(to: UInt16.self)
            var x = 0
            while x < width {
                let v = row[x] >> 6              // P010 layout: 10 bits high
                if v > peak { peak = v }
                x += 8
            }
            y += 8
        }
        Log.info("diag capture: format=\(cc) peakLuma=\(peak)/1023")
    }

    private func encode(_ pixelBuffer: CVPixelBuffer, pts: CMTime) {
        guard let encoder else { return }
        let capturedAtMs = Int64(Date().timeIntervalSince1970 * 1000)
        var frameProperties: CFDictionary?
        if needsKeyframe {
            frameProperties = [kVTEncodeFrameOptionKey_ForceKeyFrame: kCFBooleanTrue!] as CFDictionary
            needsKeyframe = false
        }
        pendingEncodes += 1
        let status = VTCompressionSessionEncodeFrame(
            encoder,
            imageBuffer: pixelBuffer,
            presentationTimeStamp: pts,
            duration: .invalid,
            frameProperties: frameProperties,
            infoFlagsOut: nil
        ) { [weak self] status, _, buffer in
            guard let self else { return }
            // The handler runs on VideoToolbox's thread; counter lives on `queue`.
            self.queue.async { self.pendingEncodes = max(0, self.pendingEncodes - 1) }
            if status != noErr || buffer == nil {
                // Encode failures must not be silent: an encoder/property
                // mismatch that rejects EVERY frame looks exactly like a
                // healthy-but-idle pipeline in the other counters (#diag).
                self.encodeFailures += 1
                if self.encodeFailures % 120 == 1 {
                    Log.info("encode output failed: status=\(status) buffer=\(buffer != nil) (\(self.encodeFailures) total)")
                }
                return
            }
            guard let buffer else { return }
            if self.usingProRes {
                self.sendProRes(buffer, capturedAtMs: capturedAtMs)
                return
            }
            if let data = self.annexB(from: buffer) {
                // Telemetry prefix before the first start code — the receiver
                // parses it and skips to the video payload. cap = capture time,
                // snd = handoff to the socket (so cap→snd ≈ encode duration);
                // hevc flags the codec so the receiver picks the right parser.
                let sndMs = Int64(Date().timeIntervalSince1970 * 1000)
                let codecTag = self.usingHEVC ? ",\"hevc\":1" : ""
                var framed = Data("{\"cap\":\(capturedAtMs),\"snd\":\(sndMs)\(codecTag)}".utf8)
                framed.append(data)
                self.sendFramed(framed)
            } else if self.encodeFailures % 120 == 0 {
                self.encodeFailures += 1
                Log.info("annexB conversion returned nil")
            }
        }
        if status != noErr {
            // Call failed synchronously — the handler never fires. max(0,·)
            // keeps a rare double-decrement from wedging the gate shut.
            pendingEncodes = max(0, pendingEncodes - 1)
        }
    }

    // MARK: - ProRes wire envelope
    //
    // [PRRS][4B BE meta length][meta JSON][raw ProRes frame]
    // Every ProRes frame is self-contained (intra-only); the meta carries
    // the dimensions/codec/color info the receiver needs to build its
    // CMVideoFormatDescription, plus the usual cap/snd telemetry.
    private func sendProRes(_ sample: CMSampleBuffer, capturedAtMs: Int64) {
        guard let block = CMSampleBufferGetDataBuffer(sample),
              let fmt = CMSampleBufferGetFormatDescription(sample) else { return }
        var len = 0, total = 0
        var ptr: UnsafeMutablePointer<Int8>?
        guard CMBlockBufferGetDataPointer(block, atOffset: 0,
                lengthAtOffsetOut: &len, totalLengthOut: &total,
                dataPointerOut: &ptr) == noErr, let ptr else { return }
        let dims = CMVideoFormatDescriptionGetDimensions(fmt)
        let codec = CMFormatDescriptionGetMediaSubType(fmt)
        let sndMs = Int64(Date().timeIntervalSince1970 * 1000)
        let meta = "{\"cap\":\(capturedAtMs),\"snd\":\(sndMs),\"codec\":\(codec),\"w\":\(dims.width),\"h\":\(dims.height),\"hdr\":\(hdrActive ? 1 : 0)}"
        let metaData = Data(meta.utf8)
        var framed = Data(capacity: 8 + metaData.count + total)
        framed.append(contentsOf: [0x50, 0x52, 0x52, 0x53])   // "PRRS"
        var metaLen = UInt32(metaData.count).bigEndian
        framed.append(Data(bytes: &metaLen, count: 4))
        framed.append(metaData)
        framed.append(Data(bytes: ptr, count: total))
        sendFramed(framed)
    }

    // MARK: - H.264/HEVC -> Annex B

    private func annexB(from sample: CMSampleBuffer) -> Data? {
        guard let block = CMSampleBufferGetDataBuffer(sample) else { return nil }
        var len = 0, total = 0
        var ptr: UnsafeMutablePointer<Int8>?
        guard CMBlockBufferGetDataPointer(block, atOffset: 0,
                lengthAtOffsetOut: &len, totalLengthOut: &total,
                dataPointerOut: &ptr) == noErr, let ptr else { return nil }

        var out = Data(capacity: total + 128)
        // On keyframes, prepend the parameter sets (they live in the format
        // description): SPS+PPS for H.264, VPS+SPS+PPS for HEVC.
        if isKeyframe(sample), let fmt = CMSampleBufferGetFormatDescription(sample) {
            let hevc = CMFormatDescriptionGetMediaSubType(fmt) == kCMVideoCodecType_HEVC
            var count = 0
            var psPtr: UnsafePointer<UInt8>?
            var psLen = 0
            let countStatus = hevc
                ? CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(
                      fmt, parameterSetIndex: 0, parameterSetPointerOut: &psPtr,
                      parameterSetSizeOut: &psLen, parameterSetCountOut: &count,
                      nalUnitHeaderLengthOut: nil)
                : CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                      fmt, parameterSetIndex: 0, parameterSetPointerOut: &psPtr,
                      parameterSetSizeOut: &psLen, parameterSetCountOut: &count,
                      nalUnitHeaderLengthOut: nil)
            if countStatus == noErr {
                for i in 0..<count {
                    psPtr = nil
                    psLen = 0
                    let status = hevc
                        ? CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(
                              fmt, parameterSetIndex: i, parameterSetPointerOut: &psPtr,
                              parameterSetSizeOut: &psLen, parameterSetCountOut: nil,
                              nalUnitHeaderLengthOut: nil)
                        : CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                              fmt, parameterSetIndex: i, parameterSetPointerOut: &psPtr,
                              parameterSetSizeOut: &psLen, parameterSetCountOut: nil,
                              nalUnitHeaderLengthOut: nil)
                    if status == noErr, let psPtr {
                        out.append(contentsOf: startCode)
                        out.append(Data(bytes: psPtr, count: psLen))
                    }
                }
            }
        }
        // Convert AVCC (4-byte length-prefixed NALUs) to Annex B start codes.
        let raw = UnsafeRawPointer(ptr)
        var offset = 0
        while offset + 4 <= total {
            var nalLen: UInt32 = 0
            memcpy(&nalLen, raw + offset, 4)
            nalLen = CFSwapInt32BigToHost(nalLen)
            offset += 4
            guard offset + Int(nalLen) <= total else { break }
            out.append(contentsOf: startCode)
            out.append(Data(bytes: raw + offset, count: Int(nalLen)))
            offset += Int(nalLen)
        }
        return out
    }

    private func isKeyframe(_ sample: CMSampleBuffer) -> Bool {
        guard let arr = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: false),
              let dict = (arr as? [[CFString: Any]])?.first else { return true }
        return !(dict[kCMSampleAttachmentKey_NotSync] as? Bool ?? false)
    }

    // MARK: - Wire framing: [4-byte big-endian length][payload]

    /// Control messages on the video channel (pong etc.) — framed JSON without
    /// start codes; the receiver routes payloads starting with '{'.
    private func sendJSONFrame(_ json: String) {
        guard let connection, connectionReady else { return }
        let payload = Data(json.utf8)
        var header = UInt32(payload.count).bigEndian
        var frame = Data(bytes: &header, count: 4)
        frame.append(payload)
        connection.send(content: frame, completion: .contentProcessed { _ in })
    }

    private func sendFramed(_ payload: Data) {
        guard let connection, connectionReady else { return }
        var header = UInt32(payload.count).bigEndian
        var frame = Data(bytes: &header, count: 4)
        frame.append(payload)
        pendingSends += 1
        connection.send(content: frame, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            self.pendingSends -= 1
            if let error {
                Log.info("send error: \(error)")
                return
            }
            self.framesSent += 1
            self.bytesSent += frame.count
            // Report stats roughly once a second.
            let elapsed = Date().timeIntervalSince(self.statsWindowStart)
            if elapsed >= 1.0 {
                let mbps = Double(self.bytesSent) * 8 / elapsed / 1_000_000
                let frames = self.framesSent
                self.bytesSent = 0
                self.statsWindowStart = Date()
                Task { @MainActor in self.onStats?(frames, mbps) }
            }
        })
    }

    // MARK: - Helpers

    private func status(_ text: String) async {
        await MainActor.run { onStatus?(text) }
    }
}
