import Network
import XCTest
@testable import PhotonPort

@MainActor
final class S09SettingsTests: XCTestCase {
    private final class FakeBrowser: DiscoveryBrowser {
        var browseResultsChangedHandler: (@Sendable (Set<NWBrowser.Result>, Set<NWBrowser.Result.Change>) -> Void)?
        var stateUpdateHandler: (@Sendable (NWBrowser.State) -> Void)?

        func start(queue: DispatchQueue) {}
        func cancel() {}
    }

    private final class FakeObservation: PermissionMonitorObservation {
        var cancelled = false
        var refresh: (() -> Void)?

        func cancel() { cancelled = true }

        func fire() {
            guard !cancelled else { return }
            refresh?()
        }
    }

    private func makeDefaults() -> UserDefaults {
        let suiteName = "S09SettingsTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return defaults
    }

    private func makeController(defaults: UserDefaults, arguments: [String]) -> SenderController {
        SenderController(makeBrowser: { FakeBrowser() }, defaults: defaults, arguments: arguments)
    }

    func testCaptureModePersistsAndReloadsFromControllerDefaultsBoundary() {
        let defaults = makeDefaults()
        let first = makeController(defaults: defaults, arguments: ["PhotonPort"])

        first.mode = .mirror
        XCTAssertEqual(defaults.string(forKey: "mode"), CaptureMode.mirror.rawValue)

        let reloaded = makeController(defaults: defaults, arguments: ["PhotonPort"])
        XCTAssertEqual(reloaded.mode, .mirror)
    }

    func testCommandLineCaptureModeOverrideRemainsAuthoritativeWithoutRewritingDefaults() {
        let defaults = makeDefaults()
        defaults.set(CaptureMode.extend.rawValue, forKey: "mode")
        let controller = makeController(
            defaults: defaults, arguments: ["PhotonPort", "-mode", CaptureMode.mirror.rawValue])

        XCTAssertEqual(controller.mode, .mirror)
        controller.mode = .extend

        XCTAssertEqual(controller.mode, .mirror)
        XCTAssertEqual(defaults.string(forKey: "mode"), CaptureMode.extend.rawValue)
    }
    func testConnectedClassificationAcceptsOnlyConnectedLifecycleState() {
        XCTAssertFalse(SenderController.isConnected(.starting(1)))
        XCTAssertTrue(SenderController.isConnected(.connected(1)))
        XCTAssertFalse(SenderController.isConnected(.failed(1, "startup")))
        XCTAssertFalse(SenderController.isConnected(.stopping(1)))
        XCTAssertFalse(SenderController.isConnected(.stopped(1)))
    }
    func testLifecyclePresentationHasExplicitStateForEveryLifecycle() {
        XCTAssertEqual(SessionLifecyclePresentation(lifecycle: .starting(1)), .starting)
        XCTAssertEqual(SessionLifecyclePresentation(lifecycle: .connected(1)), .connected)
        XCTAssertEqual(SessionLifecyclePresentation(lifecycle: .failed(1, "startup")), .failed)
        XCTAssertEqual(SessionLifecyclePresentation(lifecycle: .stopping(1)), .stopping)
        XCTAssertEqual(SessionLifecyclePresentation(lifecycle: .stopped(1)), .stopped)
        XCTAssertEqual(SessionLifecyclePresentation(lifecycle: nil), .idle)
    }

    func testPermissionMonitorStopsObservationAndDoesNotRefreshAfterCancellation() {
        let observation = FakeObservation()
        var reads = 0
        let monitor = PermissionMonitor(
            readPermissionState: {
                reads += 1
                return (true, false)
            },
            scheduleRefresh: { _, refresh in
                observation.refresh = refresh
                return observation
            })

        XCTAssertEqual(reads, 1)
        monitor.stop()
        observation.fire()

        XCTAssertTrue(observation.cancelled)
        XCTAssertEqual(reads, 1)
    }

    func testPermissionMonitorDeallocatesAfterItsObservationIsCancelled() {
        let observation = FakeObservation()
        weak var weakMonitor: PermissionMonitor?
        var reads = 0

        autoreleasepool {
            var monitor: PermissionMonitor? = PermissionMonitor(
                readPermissionState: {
                    reads += 1
                    return (false, false)
                },
                scheduleRefresh: { _, refresh in
                    observation.refresh = refresh
                    return observation
                })
            weakMonitor = monitor
            monitor = nil
        }

        observation.fire()
        XCTAssertNil(weakMonitor)
        XCTAssertTrue(observation.cancelled)
        XCTAssertEqual(reads, 1)
    }
}
