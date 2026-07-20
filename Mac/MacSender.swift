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
// Wire protocol, Mac -> phone:
//   [4-byte big-endian outer length]
//   [4-byte big-endian telemetry JSON length][telemetry JSON][Annex-B payload]
// Wire protocol, phone -> Mac: [4-byte big-endian length][JSON message]

import ScreenCaptureKit
import IOSurface
import CoreAudio
import VideoToolbox
import Network
import CoreMedia
import AppKit
import CryptoKit
import os


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

    // Transport-sized: usbmux sustains ~1Gbps (measured), so USB gets
    // generous rates; WiFi keeps upstream's conservative numbers — an
    // unencrypted, contended radio link is no place for 40Mbps.
    func bitrate(usb: Bool) -> Int {
        switch self {
        case .best: return usb ? 40_000_000 : 18_000_000
        case .balanced: return usb ? 24_000_000 : 10_000_000
        case .fast: return usb ? 10_000_000 : 6_000_000
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

struct PhoneInfo {
    let pixelsWide: Int
    let pixelsHigh: Int
    let scale: Double
    let device: String?
    let id: String?
    let maxFps: Int?
    let hdr: Bool?
    let sessionVersion: Int?
    let deviceNonce: Data
    let wifiSessionSeed: Data?

    init(_ hello: ProtocolParser.ServerHello) {
        pixelsWide = hello.pixelsWide
        pixelsHigh = hello.pixelsHigh
        scale = hello.scale
        device = hello.device
        id = hello.id
        maxFps = hello.maxFps
        hdr = hello.hdr
        sessionVersion = SessionCrypto.version
        deviceNonce = hello.deviceNonce
        wifiSessionSeed = hello.wifiSessionSeed
    }

    var kind: String { device ?? "device" }
    var refreshRate: Int { min(max(maxFps ?? 60, 60), 120) }
}

/// How the sender reaches the receiver. Reconnects re-dial from scratch, so
/// a USB device that was replugged (new usbmuxd DeviceID) is found again.
enum SenderTransport {
    case tcp(NWEndpoint, security: TCPTransportSecurity)
    case usb(udid: String?, port: UInt16)  // native usbmuxd dial; nil = first device
    case authenticatedUSB(udid: String?, port: UInt16, deviceInstallID: String, psk: Data)
}

enum TCPTransportSecurity {
    case plaintext
    case pairedTLS(identity: String, key: Data)
}

enum SessionAdmissionError: LocalizedError, Equatable {
    case invalidProtocolBuildPin(String)
    case plaintextTCPRequiresLoopback

    var errorDescription: String? {
        switch self {
        case .invalidProtocolBuildPin(let reason):
            return "Protocol build pin validation failed: \(reason)"
        case .plaintextTCPRequiresLoopback:
            return "Plaintext TCP is allowed only for loopback endpoints"
        }
    }
}

struct ProtocolBuildPin: Decodable, Equatable {
    let schemaVersion: Int
    let protocolCommit: String
    let compatibilityDigest: String
    let normativeManifestDigest: String

    private static let expected = ProtocolBuildPin(
        schemaVersion: 1,
        protocolCommit: "1f7d0ef5c43a585ebc29ea0f4d772e88364699fc",
        compatibilityDigest: "72bd252b2ff888a96889ef3b578b6d864d6e937f30de6c5a3d6c6df0413e0ce2",
        normativeManifestDigest: "1711266e97dc06b1877ca75838f8e788d6519ba4c258e060119aff0dbc2d4033")

    static func validate(at url: URL?) throws {
        guard let url else {
            throw SessionAdmissionError.invalidProtocolBuildPin("resource is missing")
        }
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw SessionAdmissionError.invalidProtocolBuildPin("resource cannot be read")
        }
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw SessionAdmissionError.invalidProtocolBuildPin("resource is malformed")
        }
        guard let dictionary = object as? [String: Any],
              Set(dictionary.keys) == [
                "schemaVersion",
                "protocolCommit",
                "compatibilityDigest",
                "normativeManifestDigest",
              ] else {
            throw SessionAdmissionError.invalidProtocolBuildPin("resource has an unexpected schema or tag")
        }
        let pin: ProtocolBuildPin
        do {
            pin = try JSONDecoder().decode(ProtocolBuildPin.self, from: data)
        } catch {
            throw SessionAdmissionError.invalidProtocolBuildPin("resource is malformed")
        }
        guard pin == expected else {
            throw SessionAdmissionError.invalidProtocolBuildPin("resource does not match the bundled protocol contract")
        }
    }
}

protocol SenderLifecycleSender: AnyObject {
    @MainActor var onStatus: ((String) -> Void)? { get set }
    @MainActor var onStats: ((Int, Double) -> Void)? { get set }
    @MainActor var onDisconnected: (() -> Void)? { get set }
    @MainActor var onHello: ((PhoneInfo) -> Void)? { get set }
    func start() async throws
    func stop() async
    func forceReconnect()
}

struct SenderConfiguration {
    let transport: SenderTransport
    let name: String
    let mode: CaptureMode
    let quality: StreamQuality
    let hdrAllowed: Bool
    let audioEnabled: Bool
    let displaySerial: UInt32
}

protocol SenderFactory {
    @MainActor func makeSender(configuration: SenderConfiguration) -> any SenderLifecycleSender
}

struct DefaultSenderFactory: SenderFactory {
    @MainActor func makeSender(configuration: SenderConfiguration) -> any SenderLifecycleSender {
        MacSender(transport: configuration.transport, name: configuration.name,
                  mode: configuration.mode, quality: configuration.quality,
                  hdrAllowed: configuration.hdrAllowed, audioEnabled: configuration.audioEnabled,
                  displaySerial: configuration.displaySerial)
    }
}

@available(macOS 14.0, *)
// Mutable transport/capture state is confined to `queue`; UI callbacks hop to
// MainActor explicitly. The unchecked conformance documents that invariant
// for Dispatch's @Sendable closures until this type can become an actor.
final class MacSender: NSObject, SCStreamOutput, SCStreamDelegate, @unchecked Sendable, SenderLifecycleSender {

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
    private var isUSBTransport: Bool {
        if case .usb = transport { return true }
        if case .authenticatedUSB = transport { return true }
        return false
    }
    // Only the usbmux path is treated as the fast link. Any other TCP path
    // (WiFi Bonjour, or a manual -host/-port tunnel which is typically an
    // SSH/iproxy hop of unknown bandwidth) gets the conservative profile.
    private var effectiveScale: Double {
        isUSBTransport ? quality.scale : min(quality.scale, 0.6)
    }
    private func cappedFps(_ fps: Int) -> Int {
        isUSBTransport ? fps : min(fps, 60)
    }
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
    private var pendingFrameAdmissions = 0
    struct VideoAdmissionPolicy {
        struct State {
            let stopped: Bool
            let connected: Bool
            let generationCurrent: Bool
            let encoderConfigured: Bool
            let pendingEncodes: Int
            let pendingAdmissions: Int
            let pendingSends: Int
            let maxPendingSends: Int
            let lastAdmission: Date
            let now: Date
            let minimumInterval: TimeInterval
        }

        static func evaluate(_ state: State) -> Bool {
            !state.stopped &&
            state.connected &&
            state.generationCurrent &&
            state.encoderConfigured &&
            state.pendingSends < state.maxPendingSends &&
            state.pendingEncodes + state.pendingAdmissions < 2 &&
            state.now.timeIntervalSince(state.lastAdmission) >= state.minimumInterval
        }
    }

    struct FrameAdmission {
        let generation: Int
    }

    final class FrameAdmissionPipeline {
        let reserve: (CMTime) -> FrameAdmission?
        let cancel: (FrameAdmission) -> Void
        let admitted: (CVPixelBuffer, CMTime, FrameAdmission) -> Void

        init(reserve: @escaping (CMTime) -> FrameAdmission?,
             cancel: @escaping (FrameAdmission) -> Void,
             admitted: @escaping (CVPixelBuffer, CMTime, FrameAdmission) -> Void) {
            self.reserve = reserve
            self.cancel = cancel
            self.admitted = admitted
        }

        func submitSCK(_ buffer: CVPixelBuffer, pts: CMTime) {
            guard let admission = reserve(pts) else { return }
            admitted(buffer, pts, admission)
        }

        func submitCG(pts: CMTime, convert: () -> CVPixelBuffer?) {
            guard let admission = reserve(pts) else { return }
            guard let buffer = convert() else {
                cancel(admission)
                return
            }
            admitted(buffer, pts, admission)
        }
    }

    private lazy var framePipeline = FrameAdmissionPipeline(
        reserve: { [weak self] in self?.reserveFrameAdmission(pts: $0) },
        cancel: { [weak self] in self?.cancelFrameAdmission($0) },
        admitted: { [weak self] in self?.handleAdmittedFrame($0, pts: $1, admission: $2) })
    // Codec actually in use: H.264 for SDR, HEVC Main10 HLG for HDR.
    private var usingHEVC = false
    // Rejected encodes (output handler status != noErr) — rate-limit logging.
    private var encodeFailures = 0
    // Pipeline diagnosis flag (`defaults write … diag -bool true`).
    private let diagEnabled = UserDefaults.standard.bool(forKey: "diag")
    private var diagFrameCounter = 0
    private var dropsThisWindow = 0
    private var needsKeyframe = true
    private var connectionReady = false
    private let stoppedLock = NSLock()
    private var stoppedValue = false
    private var stopped: Bool {
        get {
            stoppedLock.lock()
            defer { stoppedLock.unlock() }
            return stoppedValue
        }
        set {
            stoppedLock.lock()
            stoppedValue = newValue
            stoppedLock.unlock()
        }
    }
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
    private let disconnectGraceSeconds = SessionTiming.macDisconnectGrace

    private var lastHello: PhoneInfo?
    private var helloContinuation: CheckedContinuation<PhoneInfo, Error>?
    private struct PendingStreamSession {
        let info: PhoneInfo
        let macNonce: Data
        let deviceNonce: Data
        let primaryKey: SymmetricKey
    }
    private struct BoundStreamSession {
        let info: PhoneInfo
        let sessionID: Data
        let generation: UInt64
        let channelSecret: SymmetricKey
    }

    private var pendingStreamSession: PendingStreamSession?
    private var boundStreamSession: BoundStreamSession?
    private var usbChannelBindingKey: Data?
    private var usbPrimaryRecordState: USBRecordState?
    private var usbAudioRecordState: USBRecordState?
    private var consumedWifiSessionSeeds = Set<Data>()
    private var inputInjector: InputInjector?
    // Monotonic lifetime token for display-owned UI work; never sent on the wire.
    private var virtualDisplayGeneration: UInt64 = 0

    // Liveness: both sides ping every 2s; if nothing arrives for 5s the link
    // is half-open (e.g. usbmuxd accepted but the device is gone) — reconnect.
    private var controlLiveness = ProtocolParser.ControlLivenessState()
    private var handshakeStartedAt: Date?
    private var dropsTotal = 0

    // Local cursor echo: a cursor baked into the video carries the full
    // capture→encode→stream→display latency (~30ms perceived). Instead we
    // hide it from capture and stream its position on the control channel —
    // the phone draws it locally on the ~2ms path the touches use.
    // Escape hatch: `defaults write dev.hyupji.photonport.mac localCursor -bool false`.
    private let localCursor = UserDefaults.standard.object(forKey: "localCursor") == nil
        || UserDefaults.standard.bool(forKey: "localCursor")
    private var cursorTimer: DispatchSourceTimer?
    private var lastCursorSent: (x: Double, y: Double, visible: Bool) = (-1, -1, false)
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
    static func validateAdmission(transport: SenderTransport, pinURL: URL?) throws {
        try ProtocolBuildPin.validate(at: pinURL)
        guard case .tcp(let endpoint, let security) = transport,
              case .plaintext = security else {
            return
        }
        guard isLoopback(endpoint) else {
            throw SessionAdmissionError.plaintextTCPRequiresLoopback
        }
    }
    private var wifiPSK: (identity: String, key: Data)? {
        guard case .tcp(_, security: .pairedTLS(let identity, let key)) = transport else {
            return nil
        }
        return (identity, key)
    }
    private var sessionTransport: ProtocolParser.Transport {
        if case .usb = transport { return .usb }
        if case .authenticatedUSB = transport { return .usb }
        return .wifi
    }


    private static func isLoopback(_ endpoint: NWEndpoint) -> Bool {
        guard case .hostPort(let host, _) = endpoint else { return false }
        switch host {
        case .ipv4(let address):
            return address == IPv4Address("127.0.0.1")
        case .ipv6(let address):
            return address == IPv6Address("::1")
        case .name(let name, _):
            return name.lowercased() == "localhost"
        @unknown default:
            return false
        }
    }

    // MARK: - Lifecycle

    func start() async throws {
        do {
            try Self.validateAdmission(transport: transport,
                                       pinURL: Bundle.main.url(forResource: "ProtocolBuildPin",
                                                               withExtension: "json"))
        } catch {
            await status("Failed: \(error.localizedDescription)")
            throw error
        }
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
            streamFps = cappedFps(info.refreshRate)
            hdrActive = resolveHDR(info)
            let content = try await SCShareableContent.current
            guard let display = content.displays.first else {
                throw NSError(domain: "MacSender", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "no displays found"])
            }
            // SCDisplay reports points; capture at point resolution for M1.
            let captureW = (Int(Double(display.width) * effectiveScale)) & ~1
            let captureH = (Int(Double(display.height) * effectiveScale)) & ~1
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

        guard VirtualDisplay.acceptsPixelGeometry(width: info.pixelsWide, height: info.pixelsHigh) else {
            Log.info("refusing invalid receiver display geometry: \(info.pixelsWide)x\(info.pixelsHigh)")
            throw NSError(domain: "MacSender", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "receiver announced invalid display geometry"])
        }

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
        let requestedFps = cappedFps(info.refreshRate)
        // Resolve HDR before building the display: an EDR virtual display
        // (macOS 26/27 transferFunction hook) makes WindowServer composite HDR
        // content with real headroom, so the capture carries true HDR — not
        // just a 10-bit container around tone-mapped SDR.
        let wantHDR = resolveHDR(info)
        virtualDisplayGeneration &+= 1
        let displayGeneration = virtualDisplayGeneration
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
        streamFps = cappedFps(vd.appliedRefreshRate)
        // 10-bit HEVC HLG stays worthwhile even if the EDR framebuffer fell
        // back to SDR (less banding), so hdrActive follows the negotiation,
        // not the framebuffer.
        hdrActive = wantHDR
        inputInjector?.releasePressedInput()
        inputInjector = InputInjector(displayID: vd.displayID)

        let display = try await findSCDisplay(id: vd.displayID)
        // Quality scaling: capture/encode below native when requested — the
        // display itself stays native so window layout is unaffected.
        let captureW = (Int(Double(pointsWide * 2) * effectiveScale)) & ~1
        let captureH = (Int(Double(pointsHigh * 2) * effectiveScale)) & ~1
        try await startCapture(display: display, pixelsWide: captureW, pixelsHigh: captureH)

        // Debug aid (`defaults write dev.hyupji.photonport.mac testPattern -bool true`):
        // an animated window on the virtual display generates a constant frame
        // stream so steady-state latency can be measured without user activity.
        if UserDefaults.standard.bool(forKey: "testPattern") {
            let id = vd.displayID
            await MainActor.run { TestPattern.show(on: id, generation: displayGeneration) }
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
            if let audioStream { try? await audioStream.stopCapture() }
            audioStream = nil
            audioTap?.stop()   // un-mutes the Mac between rebuilds
            audioTap = nil
            cgStream?.stop()
            cgStream = nil
            if let encoder { VTCompressionSessionInvalidate(encoder) }
            encoder = nil
            if let displayID = virtualDisplay?.displayID {
                let generation = virtualDisplayGeneration
                Task { @MainActor in TestPattern.hide(on: displayID, generation: generation) }
            }
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
        // Capture must never start behind a partially configured encoder: that
        // leaves SCK recording while every frame is silently discarded.
        try setupEncoder(width: pixelsWide, height: pixelsHigh)

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
        lastCursorSent = (-1, -1, false)
        startCursorEcho()
        if audioEnabled {
            captureSCDisplay = display
            installDefaultOutputListener()
            refreshAudioForwarding()
        }
        Log.info("capture started: \(pixelsWide)x\(pixelsHigh) display \(display.displayID) mode \(mode.rawValue) backend=\(cgStream != nil ? "CGDisplayStream-EDR" : "SCK") localCursor=\(localCursor) fps=\(streamFps) hdr=\(hdrActive)")
        let kind = lastHello?.kind ?? "device"
        await status("\(mode == .extend ? "Extending to" : "Mirroring to") \(kind) (\(pixelsWide)×\(pixelsHigh)\(streamFps > 60 ? " @\(streamFps)Hz" : "")\(hdrActive ? " HDR" : ""))")
    }

    // MARK: - System audio forwarding


    // Audio follows the Mac's output device: forwarding (and the Mac-side
    // mute) only makes sense when sound would otherwise come out of the
    // Mac's speakers. With Bluetooth headphones (AirPods) as the default
    // output, the user's ears are already on the Mac — keep audio local
    // and pause forwarding; resume automatically when they disconnect.
    private var captureSCDisplay: SCDisplay?
    private var audioRouteListenerInstalled = false

    private func isDefaultOutputBluetooth() -> Bool {
        var addr = AudioObjectPropertyAddress(
            mSelector: kAudioHardwarePropertyDefaultOutputDevice,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain)
        var device = AudioObjectID(kAudioObjectUnknown)
        var size = UInt32(MemoryLayout<AudioObjectID>.size)
        guard AudioObjectGetPropertyData(AudioObjectID(kAudioObjectSystemObject),
                                         &addr, 0, nil, &size, &device) == noErr,
              device != kAudioObjectUnknown else { return false }
        var taddr = AudioObjectPropertyAddress(
            mSelector: kAudioDevicePropertyTransportType,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain)
        var transport: UInt32 = 0
        size = UInt32(MemoryLayout<UInt32>.size)
        guard AudioObjectGetPropertyData(device, &taddr, 0, nil, &size, &transport) == noErr
        else { return false }
        return transport == kAudioDeviceTransportTypeBluetooth
            || transport == kAudioDeviceTransportTypeBluetoothLE
    }

    private func installDefaultOutputListener() {
        guard !audioRouteListenerInstalled else { return }
        audioRouteListenerInstalled = true
        var addr = AudioObjectPropertyAddress(
            mSelector: kAudioHardwarePropertyDefaultOutputDevice,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain)
        AudioObjectAddPropertyListenerBlock(
            AudioObjectID(kAudioObjectSystemObject), &addr, queue
        ) { [weak self] _, _ in
            guard let self, !self.stopped else { return }
            Log.info("default output device changed — re-evaluating audio route")
            self.refreshAudioForwarding()
        }
    }

    /// Idempotent: builds or tears down the forwarding path to match the
    /// current default output device.
    private func refreshAudioForwarding() {
        guard audioEnabled, !stopped else { return }
        if isDefaultOutputBluetooth() {
            if audioTap != nil || audioStream != nil {
                Log.info("Mac output is Bluetooth headphones — audio stays local, forwarding paused")
            }
            audioTap?.stop()          // un-mutes the Mac → AirPods play
            audioTap = nil
            audioStream?.stopCapture { _ in }
            audioStream = nil
            return
        }
        guard audioTap == nil, audioStream == nil else { return }
        // Preferred: system-audio tap (macOS 14.2+) — routes sound to the
        // device Sidecar-style (Mac speakers mute while forwarding) at ~5ms
        // buffers. SCK audio is the dual-playing 20ms fallback.
        // (`-audiotap NO` forces the fallback.)
        let tapAllowed = UserDefaults.standard.object(forKey: "audiotap") == nil
            || UserDefaults.standard.bool(forKey: "audiotap")
        if tapAllowed {
            audioTap = SystemAudioTap(queue: queue) { [weak self] slot, frames, sr in
                guard let self else { slot.release(); return }
                let byteCount = frames * 2 * MemoryLayout<Int16>.size
                self.enqueueAudioPCM(Data(slot.data.prefix(byteCount)), sampleRate: sr)
                slot.release()
            }
        }
        if audioTap == nil, let display = captureSCDisplay {
            Task { [weak self] in
                do { try await self?.startAudioCapture(display: display) }
                catch { Log.info("audio capture failed (video unaffected): \(error)") }
            }
        }
    }
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
        fallbackAudioIngress.submit(sample)
    }

    private func handleAudioOnQueue(_ sample: CMSampleBuffer) {
        guard !stopped else { return }
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
        enqueueAudioPCM(pcm, sampleRate: Int(asbd.mSampleRate))
    }

    final class AudioReservationGate: @unchecked Sendable {
        private var lock = os_unfair_lock_s()
        private var generation = 0
        private var outstanding = 0
        private let capacity = 8

        func reserve() -> Int? {
            guard os_unfair_lock_trylock(&lock) else { return nil }
            defer { os_unfair_lock_unlock(&lock) }
            guard outstanding < capacity else { return nil }
            outstanding += 1
            return generation
        }

        func isCurrent(_ token: Int) -> Bool {
            os_unfair_lock_lock(&lock)
            defer { os_unfair_lock_unlock(&lock) }
            return token == generation
        }

        func release(_ reservedGeneration: Int) {
            os_unfair_lock_lock(&lock)
            if reservedGeneration == generation { outstanding = max(0, outstanding - 1) }
            os_unfair_lock_unlock(&lock)
        }

        func reset() {
            os_unfair_lock_lock(&lock)
            outstanding = 0
            generation += 1
            os_unfair_lock_unlock(&lock)
        }
        func isIdle() -> Bool {
            os_unfair_lock_lock(&lock)
            defer { os_unfair_lock_unlock(&lock) }
            return outstanding == 0
        }
    }

    final class FallbackAudioIngress<Payload>: @unchecked Sendable {
        private let gate: AudioReservationGate
        private let queue: DispatchQueue
        private let consume: (Payload) -> Void

        init(queue: DispatchQueue, gate: AudioReservationGate = AudioReservationGate(),
             consume: @escaping (Payload) -> Void) {
            self.gate = gate
            self.queue = queue
            self.consume = consume
        }

        func submit(_ payload: Payload) {
            guard let token = gate.reserve() else { return }
            let gate = gate
            queue.async { [weak self, gate] in
                defer { gate.release(token) }
                guard gate.isCurrent(token) else { return }
                self?.consume(payload)
            }
        }

        func reset() {
            gate.reset()
        }

        func isIdle() -> Bool {
            gate.isIdle()
        }
    }

    private lazy var fallbackAudioIngress = FallbackAudioIngress<CMSampleBuffer>(
        queue: queue,
        consume: { [weak self] sample in
            self?.handleAudioOnQueue(sample)
        })

    /// Shared by the SCK audio path and the system-audio tap. `t` (Mac wall
    /// clock) lets the receiver compute audio forwarding latency the same
    /// way video e2e works.
    private let maxQueuedAudioFrames = 8
    private var queuedAudioFrames: [(Data, Int)] = []
    private var pendingAudioSends = 0


    private func enqueueAudioPCM(_ pcm: Data, sampleRate: Int) {
        guard !stopped, connectionReady else { return }
        guard queuedAudioFrames.count + pendingAudioSends < maxQueuedAudioFrames else {
            dropsTotal += 1
            return
        }
        queuedAudioFrames.append((pcm, sampleRate))
        drainAudioQueue()
    }

    private func drainAudioQueue() {
        guard pendingAudioSends < maxQueuedAudioFrames,
              !queuedAudioFrames.isEmpty else { return }
        let (pcm, sampleRate) = queuedAudioFrames.removeFirst()
        sendAudioPCM(pcm, sampleRate: sampleRate)
    }

    private func sendAudioPCM(_ pcm: Data, sampleRate: Int) {
        let t = Date().timeIntervalSince1970 * 1000
        let payload = Data("{\"type\":\"audio\",\"sr\":\(sampleRate),\"ch\":2,\"t\":\(t),\"d\":\"\(pcm.base64EncodedString())\"}".utf8)
        do {
            try ProtocolParser.validatePayload(payload, expectedLength: payload.count, kind: .audioData)
        } catch {
            Log.info("audio payload rejected before send: \(payload.count) bytes")
            return
        }
        let frame: Data
        if isUSBTransport {
            guard let state = audioConnectionReady ? usbAudioRecordState : usbPrimaryRecordState,
                  let protected = state.frame(payload, cap: 1 << 20) else { return }
            frame = protected
        } else {
            var header = UInt32(payload.count).bigEndian
            frame = Data(bytes: &header, count: 4) + payload
        }
        let generation = dialGeneration
        let completion: (NWError?) -> Void = { [weak self] _ in
            guard let self else { return }
            self.queue.async {
                guard generation == self.dialGeneration else { return }
                self.pendingAudioSends = max(0, self.pendingAudioSends - 1)
                self.drainAudioQueue()
            }
        }
        if audioConnectionReady, let audioConnection {
            pendingAudioSends += 1
            audioConnection.send(content: frame, completion: .contentProcessed(completion))
        } else if connectionReady, let connection {
            pendingAudioSends += 1
            connection.send(content: frame, completion: .contentProcessed(completion))
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
            let pts = CMClockGetTime(CMClockGetHostTimeClock())
            guard self.hdrActive, self.hlgConverter != nil else { return }
            self.framePipeline.submitCG(pts: pts) {
                guard let converter = self.hlgConverter else { return nil }
                var pbUnmanaged: Unmanaged<CVPixelBuffer>?
                CVPixelBufferCreateWithIOSurface(nil, surface, nil, &pbUnmanaged)
                guard let pb = pbUnmanaged?.takeRetainedValue() else { return nil }
                return converter.convert(pb)
            }
        }
        guard let stream, stream.start() == .success else {
            Log.info("CGDisplayStream EDR capture failed to start — falling back to SCK")
            return false
        }
        cgStream = stream
        return true
    }

    func stop() async {
        stopped = true
        await withCheckedContinuation { continuation in
            queue.async { [weak self] in
                self?.stopOnQueue()
                continuation.resume()
            }
        }
    }

    private func stopOnQueue() {
        cursorTimer?.cancel()
        inputInjector?.releasePressedInput()
        cursorTimer = nil
        stream?.stopCapture { _ in }
        stream = nil
        audioStream?.stopCapture { _ in }
        audioStream = nil
        audioTap?.stop()
        audioTap = nil
        cgStream?.stop()
        cgStream = nil
        connection?.cancel()
        connection = nil
        audioConnection?.cancel()
        audioConnection = nil
        audioConnectionReady = false
        audioHandshakeInFlight = false
        queuedAudioFrames.removeAll(keepingCapacity: false)
        fallbackAudioIngress.reset()
        pendingAudioSends = 0
        pendingStreamSession = nil
        boundStreamSession = nil
        usbChannelBindingKey = nil
        usbPrimaryRecordState?.clear()
        usbPrimaryRecordState = nil
        usbAudioRecordState?.clear()
        usbAudioRecordState = nil
        consumedWifiSessionSeeds.removeAll(keepingCapacity: false)
        handshakeStartedAt = nil
        pendingSends = 0
        pendingEncodes = 0
        pendingFrameAdmissions = 0
        if let encoder { VTCompressionSessionInvalidate(encoder) }
        encoder = nil
        if let displayID = virtualDisplay?.displayID {
            let generation = virtualDisplayGeneration
            Task { @MainActor in TestPattern.hide(on: displayID, generation: generation) }
        }
        virtualDisplay = nil
        helloContinuation?.resume(throwing: CancellationError())
        helloContinuation = nil
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
        case .tcp(let endpoint, _): connectTCP(endpoint)
        case .usb:
            Log.info("unauthenticated USB transport refused")
            scheduleReconnect()
        case .authenticatedUSB(let udid, let port, let deviceInstallID, let psk):
            connectUSB(udid: udid, port: port, deviceInstallID: deviceInstallID, psk: psk)
        }
    }

    /// Start reading the receiver-first hello. The stream is not usable until
    /// the v3 session-accept proof succeeds.
    private func becomeReady(_ conn: NWConnection) {
        Log.info("transport ready to \(endpointName); waiting for session v3 hello")
        if case .tcp = transport {
            Log.info("TCP transport awaiting paired Wi-Fi session challenge")
        }
        inputInjector?.releasePressedInput()
        connectionReady = false
        pendingStreamSession = nil
        boundStreamSession = nil
        lastHello = nil
        controlLiveness.reset()
        handshakeStartedAt = Date()
        receiveControl(on: conn)
        Task { await self.status("Authenticating \(self.endpointName)…") }
    }

    private func activateBoundSession(_ session: BoundStreamSession) {
        boundStreamSession = session
        connectionReady = true
        handshakeStartedAt = nil
        everConnected = true
        disconnectedSince = nil
        needsKeyframe = true
        lastCursorSent = (-1, -1, false)
        controlLiveness.reset()
        dialAudioConnection()
        if let continuation = helloContinuation {
            helloContinuation = nil
            continuation.resume(returning: session.info)
        }
        Task { await self.status("Connected to \(self.endpointName)") }
    }

    // MARK: - Dedicated audio connection (port+1)
    //
    // Audio uses a second TCP connection so delivery remains independent of
    // in-flight video frames.
    // USB derives port+1; WiFi (Bonjour) opens a second TLS connection to the
    // same secure service tagged as the audio channel (see dialAudioConnection).
    private var audioConnection: NWConnection?
    private var audioConnectionReady = false
    private var audioDialInFlight = false
    private var audioHandshakeInFlight = false


    /// Called from becomeReady AND retried by the ping loop — a reconnect
    /// racing the first dial cancels it via the generation guard, and
    /// without a retry the session silently falls back to the shared
    /// socket forever (measured as aud50 jumping 30→65ms).
    private func dialAudioConnection() {
        guard !audioDialInFlight, connectionReady, boundStreamSession != nil else { return }

        audioConnection?.cancel()
        audioConnection = nil
        audioConnectionReady = false
        let generation = dialGeneration
        switch transport {
        case .usb:
            return
        case .authenticatedUSB(let udid, let port, let deviceInstallID, let psk):
            audioDialInFlight = true
            Task { [weak self] in
                guard let self else { return }
                do {
                    let dialed = try await Usbmux.dial(
                        udid: udid,
                        port: port + 1,
                        queue: queue,
                        macInstallID: PairingStore.macInstallID,
                        deviceInstallID: deviceInstallID,
                        psk: psk,
                        purpose: "audio"
                    )
                    let conn = dialed.connection
                    queue.async {
                        self.audioDialInFlight = false
                        guard generation == self.dialGeneration, !self.stopped else {
                            conn.cancel()
                            return
                        }
                        self.usbAudioRecordState = dialed.recordState
                        self.adoptAudioConnection(conn, tag: false)
                    }
                } catch {
                    queue.async { self.audioDialInFlight = false }
                    Log.info("audio connection dial failed (audio rides the video socket): \(error)")
                }
            }
        case .tcp(let endpoint, _):
            if case .hostPort(let host, let port) = endpoint,
               let nextPort = NWEndpoint.Port(rawValue: port.rawValue + 1) {
                // Manual -host/-port endpoint (loopback tunnel): dial the
                // plaintext audio port directly, same as before.
                let options = NWProtocolTCP.Options()
                options.noDelay = true
                let conn = NWConnection(host: host, port: nextPort,
                                        using: NWParameters(tls: nil, tcp: options))
                conn.start(queue: queue)
                adoptAudioConnection(conn, tag: false)
            } else {
                // WiFi (Bonjour service): a fixed audio port isn't derivable,
                // so open a SECOND TLS connection to the same service and tag
                // it as the audio channel. Audio then rides its own TCP
                // connection — no head-of-line blocking behind video frames on
                // a lossy radio (the periodic-freeze amplifier). Same TLS-PSK.
                let options = NWProtocolTCP.Options()
                options.noDelay = true
                let params: NWParameters
                if let wifiPSK {
                    params = NWParameters(
                        tls: PairingCrypto.clientTLSOptions(identity: wifiPSK.identity,
                                                            psk: wifiPSK.key),
                        tcp: options)
                } else {
                    params = NWParameters(tls: nil, tcp: options)
                }
                params.serviceClass = .interactiveVoice
                let conn = NWConnection(to: endpoint, using: params)
                conn.start(queue: queue)
                adoptAudioConnection(conn, tag: true)
            }
        }
    }

    private func adoptAudioConnection(_ conn: NWConnection, tag: Bool) {
        audioConnection = conn
        audioConnectionReady = false
        audioHandshakeInFlight = false
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            guard conn === self.audioConnection else {
                if case .ready = state { conn.cancel() }
                return
            }
            switch state {
            case .ready:
                guard !self.audioHandshakeInFlight else { return }
                self.audioHandshakeInFlight = true
                self.receiveAudioServerHello(on: conn, tagged: tag)
            case .failed, .cancelled:
                self.audioConnectionReady = false
                self.audioHandshakeInFlight = false
            default:
                break
            }
        }
        if conn.state == .ready, !audioHandshakeInFlight {
            audioHandshakeInFlight = true
            receiveAudioServerHello(on: conn, tagged: tag)
        }
    }

    private func receiveAudioServerHello(on conn: NWConnection, tagged: Bool) {
        conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] header, _, _, error in
            guard let self, conn === self.audioConnection,
                  error == nil, let header, header.count == 4 else {
                conn.cancel()
                return
            }
            let rawLength = Int(UInt32(bigEndian: header.withUnsafeBytes {
                $0.loadUnaligned(as: UInt32.self)
            }))
            let protected = !tagged
            let bodyLength: Int
            if protected {
                guard rawLength > 40, rawLength <= (1 << 20) + 40 else {
                    conn.cancel()
                    return
                }
                bodyLength = rawLength
            } else {
                guard let length = try? ProtocolParser.framedPayloadLength(
                    from: header,
                    kind: .audioControl
                ) else {
                    conn.cancel()
                    return
                }
                bodyLength = length
            }
            conn.receive(minimumIncompleteLength: bodyLength, maximumLength: bodyLength) {
                [weak self] body, _, _, error in
                guard let self, conn === self.audioConnection,
                      error == nil, let body else {
                    conn.cancel()
                    return
                }
                let payload: Data
                if protected {
                    guard let state = self.usbAudioRecordState,
                          let consumed = state.consume(header + body, cap: 1 << 20),
                          consumed.1.isEmpty else {
                        conn.cancel()
                        return
                    }
                    payload = consumed.0
                } else {
                    payload = body
                }
                guard (try? ProtocolParser.validatePayload(
                    payload,
                    expectedLength: payload.count,
                    kind: .audioControl
                )) != nil,
                let parsed = try? ProtocolParser.parseServerHello(
                    payload,
                    transport: tagged ? .wifi : .usb
                ),
                let session = self.boundStreamSession,
                parsed.id == session.info.id,
                let nonce = SessionCrypto.randomBytes(count: 32) else {
                    conn.cancel()
                    return
                }
                let proof = SessionCrypto.channelProof(
                    key: session.channelSecret,
                    sessionID: session.sessionID,
                    generation: session.generation,
                    channel: "audio",
                    nonce: nonce
                )
                let open = SessionChannelOpen(
                    v: SessionCrypto.version,
                    macInstallID: PairingStore.macInstallID,
                    sessionID: session.sessionID.base64EncodedString(),
                    generation: session.generation,
                    channel: "audio",
                    nonce: nonce.base64EncodedString(),
                    proof: proof.base64EncodedString()
                )
                let frame: Data?
                if protected, let encoded = try? JSONEncoder().encode(open) {
                    frame = self.usbAudioRecordState?.frame(encoded, cap: 1 << 20)
                } else {
                    frame = PairingWire.frame(open, kind: .audioControl)
                }
                guard let frame else {
                    conn.cancel()
                    return
                }
                conn.send(content: frame, completion: .contentProcessed { [weak self] error in
                    guard let self, conn === self.audioConnection else { return }
                    self.audioHandshakeInFlight = false
                    if let error {
                        Log.info("audio session open failed: \(error)")
                        conn.cancel()
                    } else {
                        self.audioConnectionReady = true
                        Log.info("session v3 audio ready (dedicated socket\(tagged ? ", TLS" : ", USB"))")
                    }
                })
            }
        }
    }

    private func connectTCP(_ endpoint: NWEndpoint) {
        let options = NWProtocolTCP.Options()
        options.noDelay = true   // latency matters more than throughput here
        let params: NWParameters
        switch transport {
        case .tcp(_, security: .pairedTLS(let identity, let key)):
            params = NWParameters(
                tls: PairingCrypto.clientTLSOptions(identity: identity, psk: key),
                tcp: options)
        case .tcp(_, security: .plaintext):
            params = NWParameters(tls: nil, tcp: options)
        case .usb, .authenticatedUSB:
            preconditionFailure("TCP connection requires a TCP transport")
        }
        // WMM QoS: the video frames flow Mac -> device on THIS connection, and
        // packets are marked by their sender — without this the video stream
        // rides best-effort AC_BE and eats WiFi contention as p95 frame-latency
        // spikes (the audio dial and the device's listeners already mark
        // theirs). No effect on USB/loopback.
        params.serviceClass = .interactiveVideo
        let conn = NWConnection(to: endpoint, using: params)
        connection = conn
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            // Ignore late transitions from a connection a reconnect has
            // already replaced. Without this, a stale socket's delayed .failed
            // tears down the healthy session that superseded it (connectionReady
            // flipped false + a spurious scheduleReconnect on the wrong session).
            guard conn === self.connection else {
                if case .ready = state { conn.cancel() }
                return
            }
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
    private func connectUSB(udid: String?, port: UInt16, deviceInstallID: String, psk: Data) {
        dialGeneration += 1
        let generation = dialGeneration
        Task { [weak self] in
            guard let self else { return }
            do {
                let dialed = try await Usbmux.dial(
                    udid: udid,
                    port: port,
                    queue: queue,
                    macInstallID: PairingStore.macInstallID,
                    deviceInstallID: deviceInstallID,
                    psk: psk,
                    purpose: "primary"
                )
                let conn = dialed.connection
                queue.async { [weak self] in
                    guard let self else { conn.cancel(); return }
                    guard generation == self.dialGeneration, !self.stopped else {
                        conn.cancel()
                        return
                    }
                    self.usbChannelBindingKey = dialed.authenticatedChannelBindingKey
                    self.usbPrimaryRecordState = dialed.recordState
                    self.connection = conn
                    conn.stateUpdateHandler = { [weak self] state in
                        guard let self else { return }
                        guard conn === self.connection else {
                            if case .ready = state { conn.cancel() }
                            return
                        }
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
                queue.async { [weak self] in
                    guard let self else { return }
                    guard generation == self.dialGeneration, !self.stopped else { return }
                    Task { await self.status(hint) }
                    self.scheduleReconnect()
                }
            }
        }
    }

    private func scheduleReconnect(after delay: TimeInterval = 1,
                                   status reconnectStatus: String? = nil) {
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
        inputInjector?.releasePressedInput()
        pendingStreamSession = nil
        boundStreamSession = nil
        lastHello = nil
        usbChannelBindingKey = nil
        usbPrimaryRecordState?.clear()
        usbPrimaryRecordState = nil
        usbAudioRecordState?.clear()
        usbAudioRecordState = nil
        handshakeStartedAt = nil
        dialGeneration += 1   // a USB dial still in flight must not adopt
        connection?.cancel()
        connection = nil
        audioConnection?.cancel()
        audioConnection = nil
        audioConnectionReady = false
        audioHandshakeInFlight = false
        queuedAudioFrames.removeAll(keepingCapacity: false)
        fallbackAudioIngress.reset()
        pendingAudioSends = 0
        pendingSends = 0
        pendingEncodes = 0
        pendingFrameAdmissions = 0
        if let reconnectStatus {
            Task { await status(reconnectStatus) }
        }
        queue.asyncAfter(deadline: .now() + delay) { [weak self] in
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
                let pingTime = Date().timeIntervalSince1970 * 1000
                let pingID = UInt64(pingTime)
                self.sendJSONFrame("{\"type\":\"ping\",\"id\":\(pingID),\"t\":\(pingTime)}")
                // The dedicated audio socket is best-effort — keep retrying
                // while the main connection is healthy but audio isn't.
                if !self.audioConnectionReady { self.dialAudioConnection() }
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
            let idle = Date().timeIntervalSince(self.controlLiveness.lastReceived)
            if self.connection != nil, !self.connectionReady,
               let started = self.handshakeStartedAt,
               Date().timeIntervalSince(started) > SessionTiming.handshakeTimeout {
                Log.info("session v3 authentication timed out — reconnecting")
                self.scheduleReconnect(
                    status: "Session authentication timed out — retrying…")
            } else if self.connectionReady,
                      idle > SessionTiming.livenessDeadline {
                Log.info("watchdog: nothing from the phone for >5s — reconnecting")
                self.scheduleReconnect(status: "Connection stale — reconnecting…")
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
                sendJSONFrame(String(format: "{\"type\":\"cursor\",\"x\":%.4f,\"y\":%.4f,\"visible\":true}", x, y))
            }
        } else if lastCursorSent.visible {
            lastCursorSent.visible = false
            sendJSONFrame(String(format:
                "{\"type\":\"cursor\",\"x\":%.4f,\"y\":%.4f,\"visible\":false}",
                lastCursorSent.x, lastCursorSent.y))
        }
    }

    // MARK: - Control messages (phone -> Mac)

    private func receiveControl(on conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] header, _, _, error in
            guard let self, conn === self.connection,
                  error == nil, let header, header.count == 4 else {
                conn.cancel()
                return
            }
            let rawLength = Int(UInt32(bigEndian: header.withUnsafeBytes {
                $0.loadUnaligned(as: UInt32.self)
            }))
            let protected = self.isUSBTransport
            let bodyLength: Int
            if protected {
                guard rawLength > 40, rawLength <= (1 << 20) + 40 else {
                    conn.cancel()
                    return
                }
                bodyLength = rawLength
            } else {
                guard let length = try? ProtocolParser.framedPayloadLength(
                    from: header,
                    kind: .session
                ) else {
                    conn.cancel()
                    return
                }
                bodyLength = length
            }
            conn.receive(minimumIncompleteLength: bodyLength, maximumLength: bodyLength) {
                [weak self] body, _, _, error in
                guard let self, conn === self.connection,
                      error == nil, let body else {
                    conn.cancel()
                    return
                }
                let payload: Data
                if protected {
                    guard let state = self.usbPrimaryRecordState,
                          let consumed = state.consume(header + body, cap: 1 << 20),
                          consumed.1.isEmpty else {
                        conn.cancel()
                        return
                    }
                    payload = consumed.0
                } else {
                    payload = body
                }
                guard (try? ProtocolParser.validatePayload(
                    payload,
                    expectedLength: payload.count,
                    kind: .session
                )) != nil else {
                    conn.cancel()
                    return
                }
                self.handleControl(payload)
                guard conn === self.connection else { return }
                self.receiveControl(on: conn)
            }
        }
    }

    private func beginSessionHandshake(_ info: PhoneInfo) {
        guard pendingStreamSession == nil, boundStreamSession == nil,
              info.sessionVersion == SessionCrypto.version,
              let deviceID = info.id,
              let macNonce = SessionCrypto.randomBytes(count: 32),
              info.deviceNonce.count == 32 else {
            Log.info("session v3 server hello invalid")
            scheduleReconnect()
            return
        }
        let ikm: Data
        switch sessionTransport {
        case .wifi:
            guard let wifiPSK,
                  let seed = info.wifiSessionSeed,
                  seed.count == 32,
                  consumedWifiSessionSeeds.insert(seed).inserted else {
                Log.info("session v3 Wi-Fi challenge or paired PSK rejected")
                scheduleReconnect()
                return
            }
            ikm = wifiPSK.key
        case .usb:
            guard info.wifiSessionSeed == nil,
                  let binding = usbChannelBindingKey,
                  binding.count == 32 else {
                Log.info("session v3 USB channel binding unavailable")
                scheduleReconnect()
                return
            }
            ikm = binding
        }
        let macID = PairingStore.macInstallID
        let primaryKey = SessionCrypto.primaryKey(
            ikm: ikm, macInstallID: macID, deviceInstallID: deviceID,
            macNonce: macNonce, deviceNonce: info.deviceNonce)
        let proof = SessionCrypto.primaryProof(
            key: primaryKey, macInstallID: macID, deviceInstallID: deviceID,
            macNonce: macNonce, deviceNonce: info.deviceNonce)
        pendingStreamSession = PendingStreamSession(
            info: info, macNonce: macNonce, deviceNonce: info.deviceNonce,
            primaryKey: primaryKey)
        let message = SessionOpen(
            v: SessionCrypto.version,
            macInstallID: macID,
            deviceInstallID: deviceID,
            macNonce: macNonce.base64EncodedString(),
            primaryProof: proof.base64EncodedString())
        guard sendSessionMessage(message, on: connection) else { scheduleReconnect(); return }
        Log.info("session v3 open sent")
    }

    private func handleSessionAccept(_ payload: Data) {
        if pendingStreamSession == nil, boundStreamSession != nil {
            Log.info("duplicate session v3 accept ignored")
            return
        }
        guard let pending = pendingStreamSession,
              let deviceID = pending.info.id,
              let verified = try? ProtocolParser.parseVerifiedSessionAccept(
                payload,
                primaryKey: pending.primaryKey,
                macInstallID: PairingStore.macInstallID,
                deviceInstallID: deviceID,
                macNonce: pending.macNonce,
                deviceNonce: pending.deviceNonce) else {
            Log.info("session v3 accept invalid")
            scheduleReconnect()
            return
        }
        pendingStreamSession = nil
        let session = BoundStreamSession(
            info: pending.info, sessionID: verified.sessionID,
            generation: verified.message.generation, channelSecret: verified.channelSecret)
        activateBoundSession(session)
        Log.info("session v3 accepted (generation \(verified.message.generation))")
    }

    @discardableResult
    private func sendSessionMessage<T: Encodable>(_ message: T,
                                                   on conn: NWConnection?) -> Bool {
        guard let conn, let payload = try? JSONEncoder().encode(message) else { return false }
        let frame: Data
        if isUSBTransport {
            guard let protected = usbPrimaryRecordState?.frame(payload, cap: 1 << 20) else { return false }
            frame = protected
        } else {
            guard let plain = PairingWire.frame(message) else { return false }
            frame = plain
        }
        conn.send(content: frame, completion: .contentProcessed { error in
            if let error { Log.info("session send error: \(error)") }
        })
        return true
    }


    private func handleControl(_ payload: Data) {
        guard let control = try? ProtocolParser.parseControl(payload, transport: sessionTransport) else {
            Log.info("invalid control message (\(payload.count) bytes)")
            scheduleReconnect()
            return
        }
        if case .pong(let id, _) = control {
            // Mac sends untracked diagnostic pings, so every inbound pong is
            // unsolicited. Parse it strictly, but do not refresh liveness or
            // participate in authenticated session ownership.
            _ = controlLiveness.receive(control)
            Log.info("unsolicited pong \(id) ignored")
            return
        }
        switch control {
        case .serverHello(_), .sessionAccept(_), .sessionBusy(_):
            break
        default:
            guard connectionReady, boundStreamSession != nil else {
                Log.info("pre-auth application control rejected")
                scheduleReconnect()
                return
            }
        }
        _ = controlLiveness.receive(control)
        switch control {
        case .ping(let id, let t):
            // Echo the authority-defined correlation id and finite timestamp.
            sendJSONFrame("{\"type\":\"pong\",\"id\":\(id),\"t\":\(t)}")
        case .pong:
            preconditionFailure("pong must be handled before application control admission")
        case .stats(_, _, _, let raw):
            // Aggregated pipeline health measured on the phone — logged here
            // so one file holds both ends of the story.
            Log.info("PHONE-STATS \(raw) | mac drops=\(dropsThisWindow) pending=\(pendingSends)")
            dropsThisWindow = 0
        case .serverHello(let parsed):
            let info = PhoneInfo(parsed)
            let previous = lastHello
            lastHello = info
            Task { @MainActor in self.onHello?(info) }
            if boundStreamSession == nil {
                beginSessionHandshake(info)
            } else if mode == .extend, stream != nil || cgStream != nil,
                      let previous,
                      previous.pixelsWide != info.pixelsWide
                      || previous.pixelsHigh != info.pixelsHigh {
                Task {
                    try? await Task.sleep(for: .milliseconds(300))
                    guard let current = self.lastHello,
                          current.pixelsWide == info.pixelsWide,
                          current.pixelsHigh == info.pixelsHigh else { return }
                    await self.reconfigure(info)
                }
            }
        case .sessionAccept:
            handleSessionAccept(payload)
        case .sessionBusy(let busy):
            let reason = busy.reason
            guard boundStreamSession == nil else {
                Log.info("post-bind session busy ignored: \(reason)")
                break
            }
            Log.info("session v3 rejected by receiver: \(reason)")
            let message = reason == "session_busy"
                ? "Receiver is in use by another Mac — disconnect it on the device"
                : "Session rejected (\(reason)) — retrying…"
            scheduleReconnect(after: SessionTiming.busyRetryDelay, status: message)

        case .touch(let phase, let x, let y, let t):
            inputInjector?.handleTouch(phase: phase, x: x, y: y)
            if let t {
                let delta = Date().timeIntervalSince1970 * 1000 - t
                if delta > -50, delta < 1000 {
                    inputLatencies.append(max(delta, 0))
                    if inputLatencies.count > 240 { inputLatencies.removeFirst(120) }
                }
            }
        case .scroll(let dx, let dy):
            inputInjector?.handleScroll(dx: dx, dy: dy)
        case .keyframe:
            // The phone's decoder lost sync (e.g. it attached mid-GOP and
            // periodic keyframes are off) — force an IDR on the next frame.
            Log.info("phone requested keyframe")
            needsKeyframe = true
        }
    }

    private func waitForHello() async throws -> PhoneInfo {
        if let session = boundStreamSession { return session.info }
        return try await withCheckedThrowingContinuation { continuation in
            queue.async { [weak self] in
                guard let self else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                if let session = self.boundStreamSession {
                    continuation.resume(returning: session.info)
                } else {
                    self.helloContinuation = continuation
                }
            }
        }
    }

    // MARK: - Encoder setup

    private func setupEncoder(width: Int, height: Int) throws {
        guard width > 0, height > 0 else {
            throw NSError(domain: "MacSender", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "invalid encoder dimensions"])
        }
        // A fresh session never owes us output handlers — clear the gate so
        // callbacks the invalidated session swallowed can't wedge it shut.
        pendingEncodes = 0
        pendingFrameAdmissions = 0
        encoder.map(VTCompressionSessionInvalidate)
        encoder = nil

        // Session v3 permits only H.264 and HEVC Main10/HLG Annex-B media.

        // Low-latency rate control: the hardware encoder emits every frame
        // immediately instead of pipelining. (`-lowlatency NO` for A/B.)
        let lowLatency = UserDefaults.standard.object(forKey: "lowlatency") == nil
            || UserDefaults.standard.bool(forKey: "lowlatency")
        let spec: CFDictionary? = lowLatency
            ? [kVTVideoEncoderSpecification_EnableLowLatencyRateControl: kCFBooleanTrue] as CFDictionary
            : nil
        // HDR rides HEVC Main10/HLG; SDR is always H.264.
        usingHEVC = hdrActive
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
            throw NSError(domain: "MacSender", code: 5,
                          userInfo: [NSLocalizedDescriptionKey: "VideoToolbox encoder creation failed"])
        }
        // Configuration is transactional: any rejected contract property
        // invalidates the session before ScreenCaptureKit can start.
        var statuses: [OSStatus] = [
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_RealTime, value: kCFBooleanTrue),
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_AllowFrameReordering, value: kCFBooleanFalse),
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_MaxKeyFrameInterval, value: 3600 as CFNumber),
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration, value: 60 as CFNumber),
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_MaxFrameDelayCount, value: 0 as CFNumber),
        ]
        if hdrActive {
            statuses += [
                VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_ProfileLevel, value: kVTProfileLevel_HEVC_Main10_AutoLevel),
                VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_ColorPrimaries, value: kCMFormatDescriptionColorPrimaries_ITU_R_2020),
                VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_TransferFunction, value: kCMFormatDescriptionTransferFunction_ITU_R_2100_HLG),
                VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_YCbCrMatrix, value: kCMFormatDescriptionYCbCrMatrix_ITU_R_2020),
            ]
        } else {
            statuses.append(VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_ProfileLevel,
                                                value: usingHEVC ? kVTProfileLevel_HEVC_Main_AutoLevel : kVTProfileLevel_H264_High_AutoLevel))
        }
        let bitrate = streamFps > 60 ? quality.bitrate(usb: isUSBTransport) * 3 / 2
                                     : quality.bitrate(usb: isUSBTransport)
        statuses.append(VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_AverageBitRate,
                                             value: bitrate as CFNumber))
        if !isUSBTransport {
            let capBytesPerSec = bitrate / 8 * 5 / 4
            statuses.append(VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_DataRateLimits,
                                                 value: [NSNumber(value: capBytesPerSec), NSNumber(value: 1.0)] as CFArray))
        }
        statuses += [
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_ExpectedFrameRate, value: streamFps as CFNumber),
            VTSessionSetProperty(encoder, key: kVTCompressionPropertyKey_PrioritizeEncodingSpeedOverQuality, value: kCFBooleanTrue),
            VTCompressionSessionPrepareToEncodeFrames(encoder),
        ]
        guard statuses.allSatisfy({ $0 == noErr }) else {
            VTCompressionSessionInvalidate(encoder)
            self.encoder = nil
            throw NSError(domain: "MacSender", code: 6,
                          userInfo: [NSLocalizedDescriptionKey: "VideoToolbox encoder configuration failed"])
        }
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
        let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        framePipeline.submitSCK(pixelBuffer, pts: pts)
    }

    /// Queue-confined admission shared by SCK and CGDisplayStream.  CG calls
    /// this before IOSurface wrapping or synchronous GPU conversion.
    private func reserveFrameAdmission(pts: CMTime) -> FrameAdmission? {
        let now = Date()
        let state = VideoAdmissionPolicy.State(
            stopped: stopped,
            connected: connectionReady,
            generationCurrent: true,
            encoderConfigured: encoder != nil,
            pendingEncodes: pendingEncodes,
            pendingAdmissions: pendingFrameAdmissions,
            pendingSends: pendingSends,
            maxPendingSends: maxPendingSends,
            lastAdmission: lastEncodedAt,
            now: now,
            minimumInterval: 1.0 / Double(streamFps) - 0.002)
        guard VideoAdmissionPolicy.evaluate(state) else {
            dropsThisWindow += 1
            dropsTotal += 1
            return nil
        }
        lastEncodedAt = now
        pendingFrameAdmissions += 1
        return FrameAdmission(generation: dialGeneration)
    }

    private func cancelFrameAdmission(_ admission: FrameAdmission) {
        guard admission.generation == dialGeneration else { return }
        pendingFrameAdmissions = max(0, pendingFrameAdmissions - 1)
        dropsThisWindow += 1
        dropsTotal += 1
        needsKeyframe = true
    }

    private func handleAdmittedFrame(_ pixelBuffer: CVPixelBuffer, pts: CMTime,
                                     admission: FrameAdmission) {
        guard admission.generation == dialGeneration, !stopped else {
            cancelFrameAdmission(admission)
            return
        }
        pendingFrameAdmissions = max(0, pendingFrameAdmissions - 1)
        lastPixelBuffer = pixelBuffer
        lastCaptureAt = Date()
        capFrames += 1
        if diagEnabled {
            diagFrameCounter += 1
            if diagFrameCounter % 240 == 1 { logCapturePeak(pixelBuffer) }
        }
        encode(pixelBuffer, pts: pts)
    }

    // HDR ground truth (`-diag`): peak luma of the captured buffer. For the
    // 10-bit biplanar formats the HDR preset uses, HLG SDR-white sits around
    // signal ~0.75 (≈770/1023) — sustained peaks near 1023 while HDR content
    // plays prove the EDR composite survives into the capture; peaks pinned
    // ≤~770 mean the Mac side is serving tone-mapped SDR.
    private func floatFromHalfBits(_ bits: UInt16) -> Float {
        let sign = UInt32(bits & 0x8000) << 16
        let exponent = Int((bits >> 10) & 0x1f)
        var fraction = UInt32(bits & 0x03ff)
        let floatBits: UInt32

        switch exponent {
        case 0 where fraction == 0:
            floatBits = sign
        case 0:
            var normalizedExponent = -14
            while fraction & 0x0400 == 0 {
                fraction <<= 1
                normalizedExponent -= 1
            }
            fraction &= 0x03ff
            floatBits = sign | UInt32(normalizedExponent + 127) << 23 | fraction << 13
        case 0x1f:
            floatBits = sign | 0x7f80_0000 | fraction << 13
        default:
            floatBits = sign | UInt32(exponent - 15 + 127) << 23 | fraction << 13
        }

        return Float(bitPattern: floatBits)
    }

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
                let row = base.advanced(by: y * stride).assumingMemoryBound(to: UInt16.self)
                var x = 0
                while x < width * 4 {            // RGBA; alpha rides along, harmless
                    let v = floatFromHalfBits(row[x])
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
        let requestingKeyframe = needsKeyframe
        if requestingKeyframe {
            frameProperties = [kVTEncodeFrameOptionKey_ForceKeyFrame: kCFBooleanTrue!] as CFDictionary
        }
        pendingEncodes += 1
        let generation = dialGeneration
        let status = VTCompressionSessionEncodeFrame(
            encoder,
            imageBuffer: pixelBuffer,
            presentationTimeStamp: pts,
            duration: .invalid,
            frameProperties: frameProperties,
            infoFlagsOut: nil
        ) { [weak self] status, _, buffer in
            guard let self else { return }
            // The handler runs on VideoToolbox's thread; every mutable sender
            // field, including keyframe demand, is updated on its executor.
            self.queue.async {
                guard generation == self.dialGeneration else { return }
                self.pendingEncodes = max(0, self.pendingEncodes - 1)
                guard status == noErr, let buffer else {
                    if requestingKeyframe { self.needsKeyframe = true }
                    self.encodeFailures += 1
                    if self.encodeFailures % 120 == 1 {
                        Log.info("encode output failed: status=\(status) buffer=false (\(self.encodeFailures) total)")
                    }
                    return
                }
                guard let data = self.annexB(from: buffer) else {
                    if requestingKeyframe { self.needsKeyframe = true }
                    self.encodeFailures += 1
                    Log.info("annexB conversion returned nil")
                    return
                }
                let keyframe = self.isKeyframe(buffer)
                guard let framed = self.videoPayload(
                    annexB: data, capturedAtMs: capturedAtMs, keyframe: keyframe) else {
                    if requestingKeyframe { self.needsKeyframe = true }
                    self.encodeFailures += 1
                    Log.info("video framing rejected")
                    return
                }
                if self.sendFramed(framed) {
                    self.needsKeyframe = false
                } else if requestingKeyframe {
                    self.needsKeyframe = true
                }
            }
        }
        if status != noErr {
            // Call failed synchronously — the handler never fires.
            pendingEncodes = max(0, pendingEncodes - 1)
            if requestingKeyframe { needsKeyframe = true }
        }
    }


    private func videoPayload(annexB: Data, capturedAtMs: Int64, keyframe: Bool) -> Data? {
        let startCode3 = Data([0, 0, 1])
        let startCode4 = Data([0, 0, 0, 1])
        guard annexB.starts(with: startCode3) || annexB.starts(with: startCode4) else { return nil }

        var nalStarts: [Data.Index] = []
        var index = annexB.startIndex
        while index < annexB.endIndex {
            let remaining = annexB.distance(from: index, to: annexB.endIndex)
            if remaining >= 4, annexB[index] == 0, annexB[index + 1] == 0,
               annexB[index + 2] == 0, annexB[index + 3] == 1 {
                nalStarts.append(index + 4)
                index += 4
            } else if remaining >= 3, annexB[index] == 0, annexB[index + 1] == 0,
                      annexB[index + 2] == 1 {
                nalStarts.append(index + 3)
                index += 3
            } else {
                index += 1
            }
        }
        guard !nalStarts.isEmpty else { return nil }

        var h264Types = Set<UInt8>()
        var hevcTypes = Set<UInt8>()
        for start in nalStarts where start < annexB.endIndex {
            let byte = annexB[start]
            h264Types.insert(byte & 0x1F)
            hevcTypes.insert((byte >> 1) & 0x3F)
        }
        let hevc = usingHEVC
        if hevc {
            guard !hevcTypes.isEmpty else { return nil }
            let hasIRAP = hevcTypes.contains { (16...23).contains($0) }
            guard keyframe ? hevcTypes.isSuperset(of: [32, 33, 34]) && hasIRAP : !hasIRAP else { return nil }
        } else {
            guard hevcTypes.isDisjoint(with: [32, 33, 34]),
                  !h264Types.isEmpty else { return nil }
            let hasIDR = h264Types.contains(5)
            guard keyframe ? h264Types.isSuperset(of: [7, 8]) && hasIDR : !hasIDR else { return nil }
        }

        let codec = hevc ? "hevc-main10-hlg" : "h264"
        let telemetry = Data("{\"codec\":\"\(codec)\",\"keyframe\":\(keyframe),\"t\":\(Double(capturedAtMs) / 1_000),\"type\":\"video\"}".utf8)
        guard (1...4_096).contains(telemetry.count) else { return nil }
        var telemetryLength = UInt32(telemetry.count).bigEndian
        var payload = Data(bytes: &telemetryLength, count: 4)
        payload.append(telemetry)
        payload.append(annexB)
        guard payload.count <= ProtocolParser.videoDataCap else { return nil }
        return payload
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
            guard countStatus == noErr, count == (hevc ? 3 : 2) else {
                // A reconnect keyframe must carry every decoder parameter set.
                return nil
            }
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
                guard status == noErr, let psPtr, psLen > 0 else { return nil }
                out.append(contentsOf: startCode)
                out.append(Data(bytes: psPtr, count: psLen))
            }
        }
        // Convert AVCC (4-byte length-prefixed NALUs) to Annex B start codes.
        // The data pointer only covers `len` bytes; a non-contiguous block
        // buffer has len < total, so reading `total` off it would be OOB.
        // Fast path when contiguous; otherwise copy to a contiguous scratch.
        func parseAVCC(_ raw: UnsafeRawPointer) {
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
        }
        if len == total {
            parseAVCC(UnsafeRawPointer(ptr))
        } else {
            var contiguous = Data(count: total)
            let ok = contiguous.withUnsafeMutableBytes {
                CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: total,
                                           destination: $0.baseAddress!) == noErr
            }
            guard ok else { return nil }
            contiguous.withUnsafeBytes { parseAVCC($0.baseAddress!) }
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
        do {
            try ProtocolParser.validatePayload(payload, expectedLength: payload.count, kind: .session)
        } catch {
            Log.info("session payload rejected before send: \(payload.count) bytes")
            return
        }
        let frame: Data
        if isUSBTransport {
            guard let protected = usbPrimaryRecordState?.frame(payload, cap: 1 << 20) else { return }
            frame = protected
        } else {
            var header = UInt32(payload.count).bigEndian
            frame = Data(bytes: &header, count: 4) + payload
        }
        connection.send(content: frame, completion: .contentProcessed { _ in })
    }

    @discardableResult
    private func sendFramed(_ payload: Data) -> Bool {
        guard let connection, connectionReady else { return false }
        do {
            try ProtocolParser.validatePayload(payload, expectedLength: payload.count, kind: .videoData)
        } catch {
            Log.info("video payload rejected before send: \(payload.count) bytes")
            return false
        }
        let frame: Data
        if isUSBTransport {
            guard let protected = usbPrimaryRecordState?.frame(payload, cap: 16 << 20) else { return false }
            frame = protected
        } else {
            var header = UInt32(payload.count).bigEndian
            frame = Data(bytes: &header, count: 4) + payload
        }
        pendingSends += 1
        connection.send(content: frame, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            // A completion from a connection a reconnect has already replaced
            // must not touch the current session: scheduleReconnect() zeroes
            // pendingSends, so decrementing here would under-count in-flight
            // frames and slacken the backpressure gate on the live socket.
            guard connection === self.connection else { return }
            // Defensive clamp: pendingSends is queue-confined and now only
            // decremented for the live connection, so it should never underflow.
            self.pendingSends = max(0, self.pendingSends - 1)
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
        return true
    }

    // MARK: - Helpers

    private func status(_ text: String) async {
        await MainActor.run { onStatus?(text) }
    }
}
