import Network
import XCTest
@testable import PhotonPort

    private final class FakeBrowser: DiscoveryBrowser {
        var browseResultsChangedHandler: (@Sendable (Set<NWBrowser.Result>, Set<NWBrowser.Result.Change>) -> Void)?
        var stateUpdateHandler: (@Sendable (NWBrowser.State) -> Void)?
        func start(queue: DispatchQueue) {}
        func cancel() {}
    }

    private final class FakeSender: SenderLifecycleSender {
        @MainActor var onStatus: ((String) -> Void)?
        @MainActor var onStats: ((Int, Double) -> Void)?
        @MainActor var onDisconnected: (() -> Void)?
        @MainActor var onHello: ((PhoneInfo) -> Void)?
        var startError: Error?
        private(set) var starts = 0
        private(set) var stops = 0

        func start() async throws {
            starts += 1
            if let startError { throw startError }
        }

        func stop() async { stops += 1 }

        func forceReconnect() {}
    }

    private final class FakeFactory: SenderFactory {
        let senders: [FakeSender]
        private var index = 0

        init(_ senders: [FakeSender]) { self.senders = senders }

        @MainActor func makeSender(configuration: SenderConfiguration) -> any SenderLifecycleSender {
            defer { index += 1 }
            return senders[index]
        }
    }

@MainActor
final class S05AppLifecycleTests: XCTestCase {
    func testLegalLifecycleTransitionsAndGenerationOwnership() {
        let starting = SessionLifecycleState.starting(7)
        XCTAssertTrue(SessionLifecycleState.mayTransition(from: starting, to: .connected(7)))
        XCTAssertTrue(SessionLifecycleState.mayTransition(from: starting, to: .failed(7, "startup")))
        XCTAssertFalse(SessionLifecycleState.mayTransition(from: starting, to: .connected(8)))
        XCTAssertFalse(SessionLifecycleState.mayTransition(from: .stopped(7), to: .connected(7)))
    }

    func testStoppingRequiresCompletionBeforeReplacement() {
        XCTAssertTrue(SessionLifecycleState.mayTransition(from: .connected(3), to: .stopping(3)))
        XCTAssertTrue(SessionLifecycleState.mayTransition(from: .stopping(3), to: .stopped(3)))
        XCTAssertFalse(SessionLifecycleState.mayTransition(from: .stopping(3), to: .connected(3)))
    }

    func testDiscoveryGenerationRejectsStaleCompletion() {
        XCTAssertFalse(SenderController.discoveryCallbackMayApply(
            callbackGeneration: 4, currentGeneration: 5))
        XCTAssertTrue(SenderController.discoveryCallbackMayApply(
            callbackGeneration: 5, currentGeneration: 5))
    }
    func testGlobalConnectedIndicatorExcludesRetainedLifecycleStates() {
        let controller = SenderController(makeBrowser: { FakeBrowser() })
        let session = DeviceSession(
            id: "audit", target: .usb(udid: nil), name: "Audit",
            sender: FakeSender(), generation: 1)
        controller.sessions = [session]

        XCTAssertFalse(controller.running)
        XCTAssertEqual(controller.connectedSessionCount, 0)
        XCTAssertTrue(controller.hasSessionActivity)

        XCTAssertTrue(session.transition(to: .connected(1)))
        XCTAssertTrue(controller.running)
        XCTAssertEqual(controller.connectedSessionCount, 1)

        XCTAssertTrue(session.transition(to: .stopping(1)))
        XCTAssertFalse(controller.running)
        XCTAssertEqual(controller.connectedSessionCount, 0)

        XCTAssertTrue(session.transition(to: .stopped(1)))
        XCTAssertFalse(controller.running)
        XCTAssertTrue(controller.hasSessionActivity)
    }

    func testFailedSessionIsNotGloballyConnected() {
        let controller = SenderController(makeBrowser: { FakeBrowser() })
        let session = DeviceSession(
            id: "failed", target: .usb(udid: nil), name: "Failed",
            sender: FakeSender(), generation: 1)
        controller.sessions = [session]

        XCTAssertTrue(session.transition(to: .failed(1, "startup")))
        XCTAssertFalse(controller.running)
        XCTAssertEqual(controller.connectedSessionCount, 0)
        XCTAssertTrue(controller.hasSessionActivity)
    }
    func testSessionRowProjectionIgnoresDescriptiveStatusText() {
        let controller = SenderController(makeBrowser: { FakeBrowser() })
        let session = DeviceSession(
            id: "projection", target: .usb(udid: nil), name: "Projection",
            sender: FakeSender(), generation: 1)
        controller.sessions = [session]
        let row = SessionRow(title: "Projection", session: session, controller: controller)

        session.status = "Connected, but still starting"
        XCTAssertEqual(row.lifecyclePresentation, .starting)
        XCTAssertEqual(controller.globalLifecyclePresentation, .starting)

        XCTAssertTrue(session.transition(to: .connected(1)))
        session.status = "Failed text must not change connected presentation"
        XCTAssertEqual(row.lifecyclePresentation, .connected)
        XCTAssertEqual(controller.globalLifecyclePresentation, .connected)

        XCTAssertTrue(session.transition(to: .stopping(1)))
        session.status = "Connected text must not change stopping presentation"
        XCTAssertEqual(row.lifecyclePresentation, .stopping)
        XCTAssertEqual(controller.globalLifecyclePresentation, .stopping)

        XCTAssertTrue(session.transition(to: .stopped(1)))
        XCTAssertEqual(row.lifecyclePresentation, .stopped)
        XCTAssertEqual(controller.globalLifecyclePresentation, .stopped)
    }

    func testSessionRowProjectionUsesFailedLifecycleState() {
        let controller = SenderController(makeBrowser: { FakeBrowser() })
        let session = DeviceSession(
            id: "failed-projection", target: .usb(udid: nil), name: "Failed",
            sender: FakeSender(), generation: 1)
        let row = SessionRow(title: "Failed", session: session, controller: controller)

        XCTAssertTrue(session.transition(to: .failed(1, "startup")))
        session.status = "Connected"
        XCTAssertEqual(row.lifecyclePresentation, .failed)
    }
    func testInjectedSenderStartupFailureAndDelayedReplacement() async throws {
        enum Failure: Error { case startup }
        let failed = FakeSender()
        failed.startError = Failure.startup
        let replacement = FakeSender()
        let factory = FakeFactory([failed, replacement])
        let controller = SenderController(makeBrowser: { FakeBrowser() }, senderFactory: factory)
        UserDefaults.standard.set("127.0.0.1", forKey: "host")
        defer { UserDefaults.standard.removeObject(forKey: "host") }

        controller.connect(to: .usb(udid: nil), userInitiated: true)
        try await Task.sleep(for: .milliseconds(20))
        guard case .failed(1, _) = controller.sessions.first?.lifecycle else {
            return XCTFail("Expected injected startup failure")
        }

        controller.restartAll()
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertEqual(failed.stops, 1)
        XCTAssertEqual(replacement.starts, 1)
        XCTAssertEqual(controller.sessions.first?.lifecycle, .connected(2))
    }
}
