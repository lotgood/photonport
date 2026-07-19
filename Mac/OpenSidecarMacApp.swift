import SwiftUI
import Network
import Combine
import Sparkle

/// How the app presents itself. One bundle, switched at runtime via the
/// activation policy — like Raycast/Hammerspoon style background agents.
enum AppPresentation: String, CaseIterable {
    case menuBar, dock, background

    var label: String {
        switch self {
        case .menuBar: return "Menu bar"
        case .dock: return "Dock"
        case .background: return "Background only"
        }
    }
}

@main
struct OpenSidecarMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var controller = SenderController.shared

    var body: some Scene {
        MenuBarExtra(isInserted: Binding(
            get: { controller.presentation == .menuBar },
            set: { _ in }
        )) {
            ContentView(controller: controller, updater: appDelegate.updater)
        } label: {
            Image(systemName: controller.running
                  ? "rectangle.on.rectangle.fill" : "rectangle.on.rectangle")
        }
        .menuBarExtraStyle(.window)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    // True when the fork's Sparkle feed is configured (SUFeedURL in
    // Info.plist). Keep the updater dormant only for local/custom builds that
    // omit the feed; release builds use the EdDSA-verified Pages appcast and
    // expose scheduled and manual update checks.
    static let updateFeedConfigured =
        Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") != nil

    // Sparkle's standard updater. `startingUpdater` boots the updater
    // immediately so scheduled background checks (SUEnableAutomaticChecks)
    // run; the menu item drives manual "Check for Updates…". Held for the
    // app's lifetime here so every window (menu bar + control window) shares
    // one updater instance.
    let updater = SPUStandardUpdaterController(
        startingUpdater: AppDelegate.updateFeedConfigured,
        updaterDelegate: nil, userDriverDelegate: nil)

    func applicationDidFinishLaunching(_ notification: Notification) {
        // One line of ground truth for "which OS-gated features exist here"
        // — the first thing to check in a log from an unfamiliar setup.
        CapabilityProbe.logSummary()
        // Hand the updater to the control window, which is built outside the
        // SwiftUI App scene (NSHostingView), so it can offer the same button.
        MainWindow.updater = updater
        let presentation = SenderController.shared.presentation
        NSApp.setActivationPolicy(presentation == .dock ? .regular : .accessory)
        if presentation != .menuBar {
            MainWindow.show()
        }
    }

    // Background/Dock modes: opening the app again (Spotlight, Finder, Dock
    // click) brings up the control window — Hammerspoon-style.
    func applicationShouldHandleReopen(_ sender: NSApplication,
                                       hasVisibleWindows: Bool) -> Bool {
        MainWindow.show()
        return false
    }
}

/// The control panel as a regular window, for Dock/background presentation.
@MainActor
enum MainWindow {
    private static var window: NSWindow?
    // Set once at launch by AppDelegate so the control window can share the
    // app's single Sparkle updater.
    static var updater: SPUStandardUpdaterController?

    static func show() {
        if window == nil {
            let w = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 440, height: 540),
                styleMask: [.titled, .closable, .miniaturizable],
                backing: .buffered, defer: false)
            w.title = "PhotonPort"
            w.contentView = NSHostingView(
                rootView: ContentView(controller: SenderController.shared,
                                      updater: updater))
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

/// Pairing runs in its own real NSWindow, never a SwiftUI `.sheet`. In the
/// default menu-bar presentation the panel lives inside a MenuBarExtra
/// popover, and presenting a sheet there makes the popover resign key and
/// auto-dismiss — the sheet vanishes the instant it appears (looks like an
/// outside click). A standalone window is independent of the popover, so it
/// behaves the same in menu-bar, Dock, and background modes.
@MainActor
enum PairWindow {
    private static var window: NSWindow?

    static func show(entry: SenderController.DeviceEntry, controller: SenderController) {
        close()
        let host = NSHostingController(
            rootView: PairSheet(entry: entry, controller: controller, onClose: close))
        let w = NSWindow(contentViewController: host)
        w.styleMask = [.titled, .closable]
        w.title = "Pair with \(entry.name)"
        w.isReleasedWhenClosed = false
        w.center()
        window = w
        // Menu-bar mode runs as .accessory, so the app must foreground itself
        // for the pairing window to take key and show the SAS code to compare.
        NSApp.activate(ignoringOtherApps: true)
        w.makeKeyAndOrderFront(nil)
    }

    static func close() {
        window?.close()
        window = nil
    }
}

enum ConnectionTarget: Hashable {
    case usb(udid: String?)           // wired via built-in usbmuxd; nil = first device
    case wifi(NWBrowser.Result)       // discovered via Bonjour

    /// Stable identity for sessions and persistence — survives Bonjour
    /// re-discovery (fresh NWBrowser.Result) and USB replugs (new DeviceID).
    var sessionID: String {
        switch self {
        case .usb(let udid): return "usb:\(udid ?? "first")"
        case .wifi(let result):
            if case .service(let name, _, _, _) = result.endpoint { return "wifi:\(name)" }
            return "wifi:unknown"
        }
    }
}

enum SessionLifecyclePresentation: Equatable {
    case connected, starting, failed, stopping, stopped, idle

    init(lifecycle: SessionLifecycleState?) {
        guard let lifecycle else {
            self = .idle
            return
        }
        switch lifecycle {
        case .connected: self = .connected
        case .starting: self = .starting
        case .failed: self = .failed
        case .stopping: self = .stopping
        case .stopped: self = .stopped
        }
    }

    var color: Color {
        switch self {
        case .connected: return .green
        case .starting, .stopping: return .orange
        case .failed: return .red
        case .stopped, .idle: return .secondary.opacity(0.5)
        }
    }
}

/// One connected (or connecting) device: its target, its sender pipeline,
/// and the per-device status the UI shows. Each session owns a full pipeline
/// — virtual display, capture, encoder, socket — so devices are independent:
/// one disconnecting never stalls the others.
@MainActor
final class DeviceSession: ObservableObject, Identifiable {
    nonisolated let id: String
    let target: ConnectionTarget
    let name: String
    let sender: any SenderLifecycleSender

    @Published var status = "Starting…"
    @Published var framesSent = 0
    @Published var mbps = 0.0
    // Receiver's per-install identity (from hello) — the key for recognizing
    // the same physical device across USB and WiFi.
    var deviceID: String?
    // "iPhone" / "iPad" from hello — naming fallback while (or in case)
    // lockdown hasn't resolved the device's real name.
    var deviceKind: String?
    @Published private(set) var lifecycle: SessionLifecycleState

    var transportLabel: String {
        if case .usb = target { return "USB" }
        return "WiFi"
    }

    init(id: String, target: ConnectionTarget, name: String,
         sender: any SenderLifecycleSender, generation: UInt64) {
        self.lifecycle = .starting(generation)
        self.id = id
        self.target = target
        self.name = name
        self.sender = sender
    }

    func transition(to next: SessionLifecycleState) -> Bool {
        guard SessionLifecycleState.mayTransition(from: lifecycle, to: next) else { return false }
        lifecycle = next
        return true
    }
}

protocol DiscoveryBrowser: AnyObject {
    var browseResultsChangedHandler: (@Sendable (Set<NWBrowser.Result>, Set<NWBrowser.Result.Change>) -> Void)? { get set }
    var stateUpdateHandler: (@Sendable (NWBrowser.State) -> Void)? { get set }
    func start(queue: DispatchQueue)
    func cancel()
}

final class NetworkDiscoveryBrowser: DiscoveryBrowser {
    private let browser = NWBrowser(
        for: .bonjourWithTXTRecord(type: "_photonport._tcp", domain: nil),
        using: .tcp)

    var browseResultsChangedHandler: (@Sendable (Set<NWBrowser.Result>, Set<NWBrowser.Result.Change>) -> Void)? {
        didSet { browser.browseResultsChangedHandler = browseResultsChangedHandler }
    }
    var stateUpdateHandler: (@Sendable (NWBrowser.State) -> Void)? {
        didSet { browser.stateUpdateHandler = stateUpdateHandler }
    }

    func start(queue: DispatchQueue) { browser.start(queue: queue) }
    func cancel() { browser.cancel() }
}

@MainActor
final class SenderController: ObservableObject {
    static let shared = SenderController()

    @Published var presentation = AppPresentation(
        rawValue: UserDefaults.standard.string(forKey: "presentation") ?? "") ?? .menuBar {
        didSet {
            UserDefaults.standard.set(presentation.rawValue, forKey: "presentation")
            NSApp.setActivationPolicy(presentation == .dock ? .regular : .accessory)
            // Never strand the user without UI: leaving menu-bar mode opens
            // the window immediately.
            if presentation != .menuBar { MainWindow.show() }
        }
    }

    @Published var sessions: [DeviceSession] = []
    @Published var discovered: [NWBrowser.Result] = []
    @Published var usbDevices: [UsbmuxDevice] = []
    // `-host x.x.x.x` / `-port n` bypass usbmuxd with a manual TCP endpoint
    // (debugging escape hatch, e.g. an iproxy or SSH tunnel).
    @Published var host = UserDefaults.standard.string(forKey: "host") ?? "127.0.0.1"
    @Published var port = UserDefaults.standard.string(forKey: "port") ?? "9000"
    // `-mode mirror` / `-mode extend` is an explicit process-lifetime override.
    // Without it, the controller owns the persisted selection.
    @Published var mode: CaptureMode {
        didSet {
            if let commandLineMode {
                if mode != commandLineMode { mode = commandLineMode }
            } else {
                defaults.set(mode.rawValue, forKey: Self.modeDefaultsKey)
            }
        }
    }
    private static let modeDefaultsKey = "mode"
    private let defaults: UserDefaults
    private let commandLineMode: CaptureMode?
    @Published var quality = StreamQuality(rawValue: UserDefaults.standard.string(forKey: "quality") ?? "") ?? .best {
        didSet { UserDefaults.standard.set(quality.rawValue, forKey: "quality") }
    }
    // HDR streaming (10-bit HEVC HLG) when the device's panel supports EDR
    // and the Mac runs macOS 15+. On by default; the toggle exists because
    // HDR costs encode time and bandwidth vs plain H.264.
    @Published var hdr = UserDefaults.standard.object(forKey: "hdr") == nil
        || UserDefaults.standard.bool(forKey: "hdr") {
        didSet { UserDefaults.standard.set(hdr, forKey: "hdr") }
    }
    // System-audio forwarding. v1 caveat: macOS keeps playing locally too
    // (no public output-routing API) — mute the Mac if doubles bother you.
    @Published var audio = UserDefaults.standard.object(forKey: "audio") == nil
        || UserDefaults.standard.bool(forKey: "audio") {
        didSet { UserDefaults.standard.set(audio, forKey: "audio") }
    }

    /// Global streaming indicators reflect only fully connected pipelines.
    var running: Bool { connectedSessionCount > 0 }
    var connectedSessionCount: Int {
        sessions.count { Self.isConnected($0.lifecycle) }
    }
    /// Retained sessions may still be starting, stopping, or expose an error.
    /// Keep this separate from the connected indicator.
    var hasSessionActivity: Bool { !sessions.isEmpty }
    var globalLifecyclePresentation: SessionLifecyclePresentation {
        let priority: [SessionLifecyclePresentation] = [.connected, .starting, .failed, .stopping]
        for presentation in priority {
            if let session = sessions.first(where: {
                SessionLifecyclePresentation(lifecycle: $0.lifecycle) == presentation
            }) {
                return SessionLifecyclePresentation(lifecycle: session.lifecycle)
            }
        }
        return SessionLifecyclePresentation(lifecycle: sessions.first?.lifecycle)
    }

    private var browser: (any DiscoveryBrowser)?
    private let makeBrowser: () -> any DiscoveryBrowser
    private let scheduleRestart: (TimeInterval, @escaping @Sendable () -> Void) -> Void
    private let senderFactory: any SenderFactory
    private var nextSessionGeneration: UInt64 = 0
    private var browserGeneration = 0
    private var browserRestartAttempt = 0
    private var usbWatcher: UsbmuxDeviceWatcher?

    // Connection policy — deliberately simple, no automatic transport
    // switching. One session per physical device; whichever transport
    // connected first keeps the device until the session ends. Unplugging
    // the cable ENDS the session (it does not migrate to WiFi), and a WiFi
    // drop does not migrate to the cable: silent transport handover
    // surprised users more than it helped (and every virtual-display
    // create/destroy flashes all screens).
    //
    //  - USB devices connect on attach ("plug in and go") unless the user
    //    explicitly disconnected them once (usbDisabled).
    //  - WiFi devices the user connected before (wifiRemembered) reconnect
    //    in a short window at LAUNCH only — never mid-session.
    // `-autostart NO` disables all auto-connecting.
    private var usbDisabled = Set(UserDefaults.standard.stringArray(forKey: "usbDisabled") ?? []) {
        didSet { UserDefaults.standard.set(Array(usbDisabled), forKey: "usbDisabled") }
    }
    private var wifiRemembered = Set(UserDefaults.standard.stringArray(forKey: "wifiRemembered") ?? []) {
        didSet { UserDefaults.standard.set(Array(wifiRemembered), forKey: "wifiRemembered") }
    }
    // Install id learned from each USB device's hello, persisted, so the
    // same hardware is recognized across transports even when the user
    // renamed the advertised service. @Published so the device list regroups
    // the moment an identity is learned.
    @Published private var installIDByUDID: [String: String] =
        UserDefaults.standard.dictionary(forKey: "installIDByUDID") as? [String: String] ?? [:] {
        didSet { UserDefaults.standard.set(installIDByUDID, forKey: "installIDByUDID") }
    }
    private let autoConnectEnabled = UserDefaults.standard.object(forKey: "autostart") == nil
        || UserDefaults.standard.bool(forKey: "autostart")

    // Bonjour usually reports devices before usbmuxd does — WiFi reconnects
    // wait out this window so a cabled device is dialed over USB first. The
    // deadline closes the window for good: a remembered WiFi device that
    // appears later was brought near the Mac mid-session, which is a user
    // action to confirm, not auto-grab.
    private var wifiAutoConnectArmed = false
    private let wifiAutoConnectDeadline = Date().addingTimeInterval(12)

    init(
        makeBrowser: @escaping () -> any DiscoveryBrowser = { NetworkDiscoveryBrowser() },
        senderFactory: any SenderFactory = DefaultSenderFactory(),
        scheduleRestart: @escaping (TimeInterval, @escaping @Sendable () -> Void) -> Void = {
            delay, work in
            DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
        },
        defaults: UserDefaults = .standard,
        arguments: [String] = ProcessInfo.processInfo.arguments
    ) {
        self.defaults = defaults
        commandLineMode = Self.captureModeOverride(arguments: arguments)
        _mode = Published(initialValue: commandLineMode
            ?? CaptureMode(rawValue: defaults.string(forKey: Self.modeDefaultsKey) ?? "") ?? .extend)
        self.makeBrowser = makeBrowser
        self.senderFactory = senderFactory
        self.scheduleRestart = scheduleRestart
        startBrowsing()
        usbWatcher = UsbmuxDeviceWatcher { [weak self] devices in
            guard let self else { return }
            self.usbDevices = devices
            self.autoConnect()
        }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            self.wifiAutoConnectArmed = true
            self.autoConnect()
        }
    }

    static func discoveryRestartDelay(for attempt: Int) -> TimeInterval {
        min(30, pow(2, Double(min(attempt, 5))))
    }

    static func discoveryCallbackMayApply(callbackGeneration: Int,
                                          currentGeneration: Int) -> Bool {
        callbackGeneration == currentGeneration
    }
    static func captureModeOverride(arguments: [String]) -> CaptureMode? {
        guard let index = arguments.firstIndex(of: "-mode"),
              arguments.indices.contains(arguments.index(after: index))
        else { return nil }
        return CaptureMode(rawValue: arguments[arguments.index(after: index)])
    }
    static func isConnected(_ lifecycle: SessionLifecycleState) -> Bool {
        if case .connected = lifecycle { return true }
        return false
    }


    private func startBrowsing() {
        browserGeneration += 1
        let generation = browserGeneration
        browser?.cancel()

        let browser = makeBrowser()
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            DispatchQueue.main.async {
                guard let self,
                      Self.discoveryCallbackMayApply(
                        callbackGeneration: generation,
                        currentGeneration: self.browserGeneration)
                else { return }
                Log.info("video browse: \(results.count) result(s)")
                // A device showing its pairing screen advertises a second
                // instance of this type with pair=1 — that's the pairing
                // endpoint, not a streamable device, so keep it out of the list.
                self.discovered = results.filter { result in
                    if case .bonjour(let txt) = result.metadata,
                       txt[PairingCrypto.pairTXTKey] == "1" { return false }
                    return true
                }
                self.autoConnect()
            }
        }
        browser.stateUpdateHandler = { [weak self] state in
            DispatchQueue.main.async {
                guard let self,
                      Self.discoveryCallbackMayApply(
                        callbackGeneration: generation,
                        currentGeneration: self.browserGeneration)
                else { return }

                switch state {
                case .failed(let error):
                    Log.info("video browse: FAILED \(error)")
                    self.restartBrowsing(afterFailureAt: generation)
                case .waiting(let error): Log.info("video browse: waiting \(error)")
                case .ready:
                    self.browserRestartAttempt = 0
                    Log.info("video browse: ready")
                default: break
                }
            }
        }
        self.browser = browser
        browser.start(queue: .main)
    }

    private func restartBrowsing(afterFailureAt generation: Int) {
        guard Self.discoveryCallbackMayApply(
            callbackGeneration: generation, currentGeneration: browserGeneration)
        else { return }

        browserGeneration += 1 // invalidate callbacks before waiting to restart
        browser?.cancel()
        browser = nil

        let delay = Self.discoveryRestartDelay(for: browserRestartAttempt)
        browserRestartAttempt += 1
        let restartGeneration = browserGeneration
        scheduleRestart(delay) { [weak self] in
            DispatchQueue.main.async {
                guard let self,
                      Self.discoveryCallbackMayApply(
                        callbackGeneration: restartGeneration,
                        currentGeneration: self.browserGeneration)
                else { return }
                self.startBrowsing()
            }
        }
    }

    // MARK: - Physical-device identity

    private func serviceName(of result: NWBrowser.Result) -> String? {
        if case .service(let name, _, _, _) = result.endpoint { return name }
        return nil
    }

    private func txtID(of result: NWBrowser.Result) -> String? {
        if case .bonjour(let txt) = result.metadata { return txt["id"] }
        return nil
    }
    /// Stable identifiers are authoritative. Names identify a device only
    /// when neither transport has supplied a stable identifier.
    static func samePhysicalDevice(wifiID: String?, usbID: String?,
                                   wifiName: String?, usbName: String?) -> Bool {
        switch (wifiID, usbID) {
        case let (.some(wifiID), .some(usbID)):
            return wifiID == usbID
        case (.none, .none):
            guard let wifiName, let usbName else { return false }
            return wifiName == usbName
        default:
            return false
        }
    }


    // MARK: - Pairing

    /// True when a pairing PSK exists for this WiFi service (keyed by the
    /// receiver's install id from the Bonjour TXT record).
    func isPaired(_ result: NWBrowser.Result) -> Bool {
        guard let deviceID = txtID(of: result) else { return false }
        return PairingStore.psk(for: deviceID) != nil
    }

    /// Step 1 of SAS pairing: swap keys with the device's pairing service and
    /// return the 6-digit code to compare against the device's screen, plus
    /// the (not-yet-stored) deviceID/psk. Nothing is persisted here.
    struct PendingPairing { let deviceID: String; let psk: Data }

    func beginPair(with result: NWBrowser.Result) async throws -> (sas: String, pending: PendingPairing) {
        guard let name = serviceName(of: result), let targetID = txtID(of: result) else {
            throw PairingError.serviceNotFound   // old receiver: no install id
        }
        let macName = Host.current().localizedName ?? "Mac"
        Log.info("pairing: begin with \"\(name)\" (mac id \(PairingStore.macInstallID.prefix(8)))")
        let (deviceID, sas, psk) = try await PairingClient.pair(
            targetID: targetID, macName: macName, macInstallID: PairingStore.macInstallID)
        return (sas, PendingPairing(deviceID: deviceID, psk: psk))
    }

    /// Step 2: the user confirmed the code matches the device's — store the
    /// PSK and connect. Only reached after a human compared both screens,
    /// which is what authenticates the channel against an active MITM.
    func commitPair(with result: NWBrowser.Result, pending: PendingPairing) throws {
        guard let targetID = txtID(of: result), pending.deviceID == targetID else {
            throw PairingError.rejected("Pairing failed — the device identity did not match.")
        }
        guard PairingStore.setPSK(pending.psk, for: pending.deviceID) else {
            throw PairingError.rejected("Pairing failed — couldn't save the key to the Keychain.")
        }
        Log.info("pairing: confirmed with device \(pending.deviceID.prefix(8)) — connecting")
        connect(to: .wifi(result), userInitiated: true)
    }


    /// Same hardware? Strong match: the service's install id equals the id
    /// this USB device announced in a (past or present) hello. Fallback for
    /// old receivers: lockdown device name equals the service name.
    private func sameDevice(_ result: NWBrowser.Result, _ device: UsbmuxDevice) -> Bool {
        Self.samePhysicalDevice(
            wifiID: txtID(of: result),
            usbID: installIDByUDID[device.udid],
            wifiName: serviceName(of: result),
            usbName: device.name)
    }

    /// The session (over either transport) already serving this USB device.
    private func activeSession(coveringUSB device: UsbmuxDevice) -> DeviceSession? {
        if let direct = session(for: "usb:\(device.udid)") { return direct }
        return sessions.first { s in
            guard case .wifi(let result) = s.target else { return false }
            return Self.samePhysicalDevice(
                wifiID: s.deviceID ?? txtID(of: result),
                usbID: installIDByUDID[device.udid],
                wifiName: serviceName(of: result),
                usbName: device.name)
        }
    }

    /// The session (over either transport) already serving this WiFi service.
    private func activeSession(coveringWiFi result: NWBrowser.Result) -> DeviceSession? {
        if let name = serviceName(of: result), let direct = session(for: "wifi:\(name)") {
            return direct
        }
        return sessions.first { s in
            guard case .usb(let udid) = s.target,
                  let udid,
                  let device = usbDevices.first(where: { $0.udid == udid })
            else { return false }
            return Self.samePhysicalDevice(
                wifiID: txtID(of: result),
                usbID: s.deviceID ?? installIDByUDID[udid],
                wifiName: serviceName(of: result),
                usbName: device.name)
        }
    }

    // MARK: - Connection policy

    private func autoConnect() {
        guard autoConnectEnabled else { return }
        dedupeSessions()
        // The -host/-port escape hatch is an explicit choice — dial it like
        // the wired devices (it joins them, not replaces them).
        if UserDefaults.standard.object(forKey: "host") != nil,
           !usbDisabled.contains("usb:first"), session(for: "usb:first") == nil {
            connect(to: .usb(udid: nil))
        }
        for device in usbDevices
            where !usbDisabled.contains("usb:\(device.udid)")
            && activeSession(coveringUSB: device) == nil {
            connect(to: .usb(udid: device.udid))
        }
        guard wifiAutoConnectArmed, Date() < wifiAutoConnectDeadline else { return }
        for result in discovered {
            let target = ConnectionTarget.wifi(result)
            if wifiRemembered.contains(target.sessionID),
               activeSession(coveringWiFi: result) == nil,
               !cabled(result) {
                connect(to: target)
            }
        }
    }

    /// An attached, auto-connectable USB device is (about to be) dialed over
    /// the cable — its WiFi service must not be grabbed in the launch race.
    private func cabled(_ result: NWBrowser.Result) -> Bool {
        usbDevices.contains {
            sameDevice(result, $0) && !usbDisabled.contains("usb:\($0.udid)")
        }
    }

    /// Safety net, not a feature: if identity was learned too late (old
    /// receiver, renamed service) and one physical device ended up with two
    /// sessions, the transports steal the receiver's single connection from
    /// each other forever. Keep the cable, drop the WiFi twin.
    private func dedupeSessions() {
        for wifiSession in sessions {
            guard case .wifi(let result) = wifiSession.target else { continue }
            let duplicate = sessions.contains { usbSession in
                guard case .usb(let udid) = usbSession.target,
                      let udid
                else { return false }
                let device = usbDevices.first { $0.udid == udid }
                return Self.samePhysicalDevice(
                    wifiID: wifiSession.deviceID ?? txtID(of: result),
                    usbID: usbSession.deviceID ?? installIDByUDID[udid],
                    wifiName: serviceName(of: result),
                    usbName: device?.name)
            }
            if duplicate {
                Log.info("two sessions for one device — keeping the cable, dropping \(wifiSession.id)")
                end(wifiSession)
            }
        }
    }

    /// Human-readable device name for a target (no transport suffix — the
    /// UI shows transports separately).
    func label(for target: ConnectionTarget) -> String {
        switch target {
        case .usb(let udid):
            if let device = usbDevices.first(where: { $0.udid == udid }), let name = device.name {
                return name
            }
            return udid == nil ? "Manual (\(host):\(port))" : "iPhone / iPad"
        case .wifi(let result):
            return serviceName(of: result) ?? "WiFi device"
        }
    }

    func session(for id: String) -> DeviceSession? {
        sessions.first { $0.id == id }
    }

    /// Derive a stable, per-device display serial from the session identity.
    /// FNV-1a over the id string; macOS keys saved display arrangement on
    /// vendor/product/serial, so each device keeps its screen position.
    private static func displaySerial(for id: String) -> UInt32 {
        var hash: UInt32 = 2_166_136_261
        for byte in id.utf8 { hash = (hash ^ UInt32(byte)) &* 16_777_619 }
        return hash == 0 ? 1 : hash
    }

    func connect(to target: ConnectionTarget, userInitiated: Bool = false) {
        let id = target.sessionID
        guard session(for: id) == nil else { return }

        // Never create a second session for the same physical device — the
        // receiver holds one connection, so a twin would steal it. But an
        // explicit user click overrides: e.g. right after unplugging the
        // cable, the dying USB session sits in its 10s reconnect grace and
        // would otherwise swallow the tap on the WiFi row.
        let covering: DeviceSession?
        switch target {
        case .usb(let udid?):
            covering = usbDevices.first(where: { $0.udid == udid })
                .flatMap { activeSession(coveringUSB: $0) }
        case .wifi(let result):
            covering = activeSession(coveringWiFi: result)
        default:
            covering = nil
        }
        if let covering {
            guard userInitiated else { return }
            Log.info("user chose \(id) — taking over from \(covering.id)")
            end(covering) { [weak self] in
                self?.connect(to: target, userInitiated: true)
            }
            return
        }

        // Connecting a device clears its "don't auto-connect" state.
        switch target {
        case .usb: usbDisabled.remove(id)
        case .wifi: wifiRemembered.insert(id)
        }

        let transport: SenderTransport
        switch target {
        case .usb(let udid):
            guard let portNum = UInt16(port) else { return }
            if UserDefaults.standard.object(forKey: "host") != nil, udid == nil {
                // Manual overrides are deliberately plaintext, and admission
                // accepts them only for a local iproxy/SSH loopback tunnel.
                transport = .tcp(.hostPort(host: NWEndpoint.Host(host),
                                           port: NWEndpoint.Port(rawValue: portNum)!),
                                 security: .plaintext)
            } else {
                transport = .usb(udid: udid, port: portNum)
            }
        case .wifi(let result):
            // WiFi requires a pairing-established PSK — the receiver's TLS
            // listener rejects everything else. Auto-connect quietly skips
            // unpaired devices; the UI offers "Pair…" instead of "Connect".
            guard let deviceID = txtID(of: result),
                  let key = PairingStore.psk(for: deviceID) else {
                if userInitiated {
                    Log.info("wifi connect to unpaired device \(id) refused — pair first")
                }
                wifiRemembered.remove(id)
                return
            }
            transport = .tcp(result.endpoint,
                             security: .pairedTLS(identity: PairingStore.macInstallID, key: key))
        }

        let name = label(for: target)
        nextSessionGeneration &+= 1
        let generation = nextSessionGeneration
        let sender = senderFactory.makeSender(configuration: SenderConfiguration(
            transport: transport, name: name, mode: mode, quality: quality,
            hdrAllowed: hdr, audioEnabled: audio, displaySerial: Self.displaySerial(for: id)))
        let session = DeviceSession(id: id, target: target, name: name, sender: sender,
                                    generation: generation)
        sender.onStatus = { [weak session] text in
            session?.status = text
            Log.info("status[\(id)]: \(text)")
        }
        sender.onHello = { [weak self, weak session] info in
            guard let self, let session else { return }
            session.deviceID = info.id
            session.deviceKind = info.device
            if case .usb(let udid?) = session.target, let installID = info.id {
                self.installIDByUDID[udid] = installID
            }
            self.dedupeSessions()
        }
        sender.onStats = { [weak session] frames, mbps in
            session?.framesSent = frames
            session?.mbps = mbps
        }
        sender.onDisconnected = { [weak self, weak session] in
            // Device unplugged / left the network and stayed gone: end this
            // session fully (virtual display + capture + indicator). No
            // transport fallback — reconnecting is the user's call.
            guard let self, let session else { return }
            Log.info("device disconnected — session \(session.id) stopped")
            self.end(session)
        }
        sessions.append(session)
        Task { [weak self, weak session] in
            guard let self, let session else { return }
            do {
                try await sender.start()
                guard self.owns(session, generation: generation) else { return }
                _ = session.transition(to: .connected(generation))
            } catch is CancellationError {
                // Stopping owns the completion; cancellation is not a failure.
            } catch {
                guard self.owns(session, generation: generation) else { return }
                Log.info("sender failed to start: \(error)")
                session.status = "Failed: \(error.localizedDescription)"
                _ = session.transition(to: .failed(generation, error.localizedDescription))
            }
        }
    }

    /// User-initiated disconnect: also opt the device out of auto-connect.
    func disconnect(_ session: DeviceSession) {
        switch session.target {
        case .usb: usbDisabled.insert(session.id)
        case .wifi: wifiRemembered.remove(session.id)
        }
        end(session)
    }

    func disconnectAll() {
        sessions.forEach { disconnect($0) }
    }

    private func owns(_ session: DeviceSession, generation: UInt64) -> Bool {
        self.session(for: session.id) === session && session.lifecycle.generation == generation
    }

    private func end(_ session: DeviceSession, completion: (() -> Void)? = nil) {
        let generation = session.lifecycle.generation
        guard session.transition(to: .stopping(generation)) else { return }
        Task { [weak self, weak session] in
            guard let session else { return }
            await session.sender.stop()
            guard let self, self.owns(session, generation: generation) else { return }
            guard session.transition(to: .stopped(generation)) else { return }
            self.sessions.removeAll { $0 === session }
            completion?()
        }
    }

    /// Mode/quality apply per-pipeline at construction — rebuild every session.
    func restartAll() {
        guard hasSessionActivity else { return }
        let targets = sessions.map(\.target)
        var remaining = targets.count
        for session in sessions {
            end(session) { [weak self] in
                remaining -= 1
                guard remaining == 0, let self else { return }
                targets.forEach { self.connect(to: $0) }
            }
        }
    }

    // MARK: - Device list (one row per physical device)

    struct DeviceEntry: Identifiable {
        let id: String
        let name: String
        let usbTarget: ConnectionTarget?
        let wifiTarget: ConnectionTarget?

        var transportLabel: String {
            switch (usbTarget != nil, wifiTarget != nil) {
            case (true, true): return "USB · WiFi"
            case (true, false): return "USB"
            case (false, true): return "WiFi"
            default: return ""
            }
        }
        /// Lowest latency first.
        var preferredTarget: ConnectionTarget? { usbTarget ?? wifiTarget }
    }

    var deviceEntries: [DeviceEntry] {
        var entries: [DeviceEntry] = []
        var mergedServices = Set<String>()
        var coveredSessionIDs = Set<String>()

        for device in usbDevices {
            // A discovered WiFi service for the same hardware folds into
            // this row instead of appearing as a second device.
            let twin = discovered.first { sameDevice($0, device) }
            if let twin, let name = serviceName(of: twin) { mergedServices.insert(name) }
            let usbTarget = ConnectionTarget.usb(udid: device.udid)
            coveredSessionIDs.insert(usbTarget.sessionID)
            if let twin { coveredSessionIDs.insert(ConnectionTarget.wifi(twin).sessionID) }
            entries.append(DeviceEntry(
                id: "device:\(device.udid)",
                name: device.name
                    ?? twin.flatMap(serviceName)
                    ?? session(for: usbTarget.sessionID)?.deviceKind
                    ?? "iPhone / iPad",
                usbTarget: usbTarget,
                wifiTarget: twin.map { .wifi($0) }))
        }
        if UserDefaults.standard.object(forKey: "host") != nil {
            let target = ConnectionTarget.usb(udid: nil)
            coveredSessionIDs.insert(target.sessionID)
            entries.append(DeviceEntry(id: target.sessionID, name: label(for: target),
                                       usbTarget: target, wifiTarget: nil))
        }
        for result in discovered {
            guard let name = serviceName(of: result), !mergedServices.contains(name)
            else { continue }
            let target = ConnectionTarget.wifi(result)
            coveredSessionIDs.insert(target.sessionID)
            entries.append(DeviceEntry(id: "service:\(name)", name: name,
                                       usbTarget: nil, wifiTarget: target))
        }
        // Sessions whose device vanished from discovery (e.g. Bonjour record
        // gone while the stream is still alive) keep a row to disconnect.
        for session in sessions where !coveredSessionIDs.contains(session.id) {
            entries.append(DeviceEntry(id: session.id, name: session.name,
                                       usbTarget: nil, wifiTarget: nil))
        }
        return entries
    }

    func session(for entry: DeviceEntry) -> DeviceSession? {
        if let target = entry.usbTarget, let s = session(for: target.sessionID) { return s }
        if let target = entry.wifiTarget, let s = session(for: target.sessionID) { return s }
        return session(for: entry.id)   // dangling-session rows
    }
}

/// Polls the permission states the app depends on so the UI can surface
/// exactly what's missing instead of failing silently.
protocol PermissionMonitorObservation: AnyObject {
    func cancel()
}

private final class TimerPermissionMonitorObservation: PermissionMonitorObservation {
    private var timer: Timer?

    init(interval: TimeInterval, refresh: @escaping () -> Void) {
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { _ in refresh() }
    }

    func cancel() {
        timer?.invalidate()
        timer = nil
    }
}

@MainActor
final class PermissionMonitor: ObservableObject {
    @Published var screenRecording = false
    @Published var accessibility = false
    private let readPermissionState: () -> (screenRecording: Bool, accessibility: Bool)
    private var observation: (any PermissionMonitorObservation)?
    private var isObserving = true

    init(
        readPermissionState: @escaping () -> (screenRecording: Bool, accessibility: Bool) = {
            (CGPreflightScreenCaptureAccess(), AXIsProcessTrusted())
        },
        scheduleRefresh: @escaping (TimeInterval, @escaping () -> Void) -> any PermissionMonitorObservation = {
            interval, refresh in TimerPermissionMonitorObservation(interval: interval, refresh: refresh)
        }
    ) {
        self.readPermissionState = readPermissionState
        refresh()
        observation = scheduleRefresh(3) { [weak self] in
            guard let self, self.isObserving else { return }
            self.refresh()
        }
    }

    deinit {
        observation?.cancel()
    }

    func stop() {
        isObserving = false
        observation?.cancel()
        observation = nil
    }

    func refresh() {
        let state = readPermissionState()
        screenRecording = state.screenRecording
        accessibility = state.accessibility
    }

    /// Fire the system permission dialog on demand. macOS only shows each
    /// dialog once per reset — after that the call just (re)registers the
    /// app in System Settings, so the row exists to toggle manually.
    func requestScreenRecording() {
        CGRequestScreenCaptureAccess()
        refresh()
    }

    func requestAccessibility() {
        _ = InputInjector.ensureAccessibilityPermission()
        refresh()
    }

    static func openPrivacyPane(_ anchor: String) {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?\(anchor)") {
            NSWorkspace.shared.open(url)
        }
    }
}

struct ContentView: View {
    @ObservedObject var controller: SenderController
    @StateObject private var permissions = PermissionMonitor()
    // Optional so the view still compiles/previews without an updater (e.g.
    // if Sparkle ever fails to start); the button just disables itself then.
    let updater: SPUStandardUpdaterController?


    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 12) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("PhotonPort")
                        .font(.title3.bold())
                    Text("Your iPads and iPhones as extra displays")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if controller.hasSessionActivity {
                    Button("Disconnect All") { controller.disconnectAll() }
                        .controlSize(.large)
                }
            }
            .padding(16)

            Divider()

            // Settings
            Form {
                Section("Devices") {
                    if controller.deviceEntries.isEmpty {
                        Text("No devices found — plug one in via USB, or open the PhotonPort app on a device on this WiFi network.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(controller.deviceEntries) { entry in
                        if let session = controller.session(for: entry) {
                            // Title from the entry, not the session: the
                            // session name was snapshotted at connect time,
                            // often before lockdown resolved the real name.
                            SessionRow(title: entry.name, session: session,
                                       controller: controller)
                        } else {
                            HStack(alignment: .firstTextBaseline) {
                                Circle()
                                    .fill(.secondary.opacity(0.5))
                                    .frame(width: 9, height: 9)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(entry.name)
                                    Text(entry.transportLabel)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if let target = entry.preferredTarget {
                                    if case .wifi(let result) = target,
                                       !controller.isPaired(result) {
                                        Button("Pair…") {
                                            PairWindow.show(entry: entry, controller: controller)
                                        }
                                            .controlSize(.small)
                                            .help("WiFi streaming is encrypted and requires a one-time pairing. Open Settings → Pair a Mac on the device, then enter the code here.")
                                    } else {
                                        Button("Connect") {
                                            controller.connect(to: target, userInitiated: true)
                                        }
                                        .controlSize(.small)
                                    }
                                }
                            }
                        }
                    }
                }

                Picker("Mode", selection: $controller.mode) {
                    Text("Extend").tag(CaptureMode.extend)
                    Text("Mirror").tag(CaptureMode.mirror)
                }
                .pickerStyle(.segmented)
                .onChange(of: controller.mode) { controller.restartAll() }

                VStack(alignment: .leading, spacing: 4) {
                    Picker("Quality", selection: $controller.quality) {
                        ForEach(StreamQuality.allCases, id: \.self) { q in
                            Text(q.label).tag(q)
                        }
                    }
                    .onChange(of: controller.quality) { controller.restartAll() }
                    Text(controller.quality.explanation)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Toggle("HDR (10-bit HEVC)", isOn: $controller.hdr)
                        .onChange(of: controller.hdr) { controller.restartAll() }
                    Text("Streams 10-bit HDR to devices with an EDR display. Needs macOS 15 or later; devices without HDR keep getting H.264 automatically.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Toggle("Forward system audio", isOn: $controller.audio)
                        .onChange(of: controller.audio) { controller.restartAll() }
                    Text("Routes the Mac's sound to the device — the Mac mutes while forwarding, like Sidecar. Bluetooth headphones keep playing locally instead. (Before macOS 14.2 the sound plays on both ends.)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Picker("Show app in", selection: $controller.presentation) {
                        ForEach(AppPresentation.allCases, id: \.self) { p in
                            Text(p.label).tag(p)
                        }
                    }
                    if controller.presentation == .background {
                        Text("No menu bar or Dock icon — streaming keeps running. Open the PhotonPort app again (Spotlight/Finder) to show this window.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                LabeledContent("Display layout") {
                    Button("Arrange Displays…") {
                        if let url = URL(string: "x-apple.systempreferences:com.apple.Displays-Settings.extension") {
                            NSWorkspace.shared.open(url)
                        }
                    }
                    .controlSize(.small)
                }
                .help("Opens System Settings → Displays, where you can position the extended displays relative to your Mac screen (Arrange…). Each device shows up as its own display, named after the device.")

                Section("Permissions") {
                    permissionRow(
                        "Screen Recording",
                        granted: permissions.screenRecording,
                        help: "Required to capture the display.",
                        anchor: "Privacy_ScreenCapture",
                        request: { permissions.requestScreenRecording() }
                    )
                    permissionRow(
                        "Accessibility",
                        granted: permissions.accessibility,
                        help: "Required for touch input from the device.",
                        anchor: "Privacy_Accessibility",
                        request: { permissions.requestAccessibility() }
                    )
                    // macOS offers no API to query Local Network access, so
                    // infer from discovery results and let the user check.
                    permissionRow(
                        "Local Network",
                        granted: !controller.discovered.isEmpty,
                        uncertain: controller.discovered.isEmpty,
                        help: "Required for WiFi mode. If no device appears in the Devices list, allow PhotonPort under Privacy & Security → Local Network on this Mac AND on the device — and keep the PhotonPort app open there.",
                        anchor: "Privacy_LocalNetwork"
                    )
                }

                // Private-API / OS-version misses. Hidden entirely when
                // everything probes fine: this section existing IS the alarm.
                if !CapabilityProbe.allGood {
                    Section("Compatibility") {
                        if !CapabilityProbe.virtualDisplayAPI {
                            capabilityRow(broken: true, "Virtual display API missing",
                                "This macOS no longer ships the private CGVirtualDisplay API — Extend mode cannot work. Mirror mode is unaffected.")
                        }
                        if !CapabilityProbe.edrVirtualDisplay {
                            capabilityRow(broken: false, "HDR compositing unavailable",
                                "This macOS has no EDR virtual-display mode — streams stay SDR even with HDR enabled.")
                        }
                        if !CapabilityProbe.audioTapAPI {
                            capabilityRow(broken: false, "Audio tap unavailable (needs macOS 14.2)",
                                "Audio falls back to playing on both the Mac and the device.")
                        }
                    }
                }
            }
            .formStyle(.grouped)
            // Scrollable + fixed panel height: MenuBarExtra windows mis-measure
            // grouped Forms (clipping on small displays), so size explicitly
            // and let the form scroll when it doesn't fit.

            Divider()

            // Status bar
            HStack(spacing: 8) {
                Circle()
                    .fill(controller.globalLifecyclePresentation.color)
                    .frame(width: 9, height: 9)
                Text(controller.running
                     ? "\(controller.connectedSessionCount) device\(controller.connectedSessionCount == 1 ? "" : "s") connected"
                     : controller.hasSessionActivity ? "No connected devices" : "Idle")
                    .font(.callout)
                    .lineLimit(1)
                Spacer()
                if let updater, AppDelegate.updateFeedConfigured {
                    CheckForUpdatesView(updater: updater)
                }
                Button("Quit") { NSApp.terminate(nil) }
                    .controlSize(.small)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
        }
        .frame(width: 440, height: 540)
    }

    @ViewBuilder
    private func permissionRow(_ title: String, granted: Bool, uncertain: Bool = false,
                               help: String, anchor: String,
                               request: (() -> Void)? = nil) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: uncertain ? "questionmark.circle.fill"
                            : granted ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(uncertain ? .orange : granted ? .green : .red)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                if uncertain || !granted {
                    Text(help)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if uncertain || !granted {
                if let request {
                    Button("Grant…") { request() }
                        .controlSize(.small)
                        .help("Ask macOS for this permission. If the system dialog was already dismissed once, this registers the app under \(title) in System Settings — flip the toggle there.")
                }
                Button("Open Settings") {
                    PermissionMonitor.openPrivacyPane(anchor)
                }
                .controlSize(.small)
            }
        }
    }

    @ViewBuilder
    private func capabilityRow(broken: Bool, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: broken ? "xmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(broken ? Color.red : Color.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

/// "Check for Updates…" button wired to Sparkle. Follows Sparkle 2's
/// documented SwiftUI pattern: a small view model publishes the updater's
/// `canCheckForUpdates` so the button disables itself while a check is
/// already running (or the updater isn't ready).
@MainActor
final class CheckForUpdatesViewModel: ObservableObject {
    @Published var canCheckForUpdates = false

    init(updater: SPUUpdater) {
        updater.publisher(for: \.canCheckForUpdates)
            .assign(to: &$canCheckForUpdates)
    }
}

/// One-time WiFi pairing (SAS numeric comparison). The Mac and the device
/// each derive and display the same 6-digit code from a fresh key exchange;
/// the user confirms the two screens match, which is what authenticates the
/// channel against an active same-LAN attacker. Only on confirmation is the
/// TLS-PSK stored and the connection made.
struct PairSheet: View {
    let entry: SenderController.DeviceEntry
    let controller: SenderController
    let onClose: () -> Void
    @State private var sas: String?
    @State private var pending: SenderController.PendingPairing?
    @State private var busy = true
    @State private var error: String?

    private var wifiResult: NWBrowser.Result? {
        if case .wifi(let r)? = entry.wifiTarget { return r }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Pair with \(entry.name)")
                .font(.headline)
            if let error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
                HStack { Spacer(); Button("Close") { onClose() } }
            } else if let sas {
                Text("Confirm this code matches the one on \(entry.name):")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Text(sas)
                    .font(.system(size: 44, weight: .bold, design: .monospaced))
                    .kerning(6)
                    .frame(maxWidth: .infinity)
                Text("If the codes differ, do NOT confirm — someone may be intercepting. Cancel and try again.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Cancel") { onClose() }.disabled(busy)
                    Button(busy ? "Connecting…" : "Codes match") { confirm() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(busy)
                }
            } else {
                HStack { ProgressView(); Text("Exchanging keys…").foregroundStyle(.secondary) }
            }
        }
        .padding(20)
        .frame(width: 340)
        .task { await begin() }
    }

    private func begin() async {
        guard let result = wifiResult else { error = "No WiFi service for this device."; busy = false; return }
        do {
            let (code, p) = try await controller.beginPair(with: result)
            sas = code; pending = p; busy = false
        } catch {
            self.error = error.localizedDescription; busy = false
        }
    }

    private func confirm() {
        guard let result = wifiResult, let pending else { return }
        busy = true; error = nil
        do {
            try controller.commitPair(with: result, pending: pending)
            onClose()
        } catch {
            self.error = error.localizedDescription; busy = false
        }
    }
}

struct CheckForUpdatesView: View {
    @ObservedObject private var viewModel: CheckForUpdatesViewModel
    private let updater: SPUUpdater

    init(updater: SPUStandardUpdaterController) {
        self.updater = updater.updater
        self.viewModel = CheckForUpdatesViewModel(updater: updater.updater)
    }

    var body: some View {
        Button("Check for Updates…") { updater.checkForUpdates() }
            .controlSize(.small)
            .disabled(!viewModel.canCheckForUpdates)
    }
}

/// One device session: live descriptive status, throughput, reconnect + disconnect.
struct SessionRow: View {
    let title: String
    @ObservedObject var session: DeviceSession
    let controller: SenderController

    var lifecyclePresentation: SessionLifecyclePresentation {
        SessionLifecyclePresentation(lifecycle: session.lifecycle)
    }

    private var statusColor: Color {
        lifecyclePresentation.color
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Circle()
                .fill(statusColor)
                .frame(width: 9, height: 9)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text("\(session.transportLabel) · \(session.status)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer()
            if session.mbps > 0 {
                Text("\(String(format: "%.1f", session.mbps)) Mbit/s")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Button {
                session.sender.forceReconnect()
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .controlSize(.small)
            .help("Drop the connection and pair with the device again")
            Button("Disconnect") { controller.disconnect(session) }
                .controlSize(.small)
        }
    }
}
