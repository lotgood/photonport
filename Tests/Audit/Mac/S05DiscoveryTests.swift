import Network
import XCTest
@testable import PhotonPort

@MainActor
final class S05DiscoveryTests: XCTestCase {
    private final class FakeBrowser: DiscoveryBrowser {
        var browseResultsChangedHandler: (@Sendable (Set<NWBrowser.Result>, Set<NWBrowser.Result.Change>) -> Void)?
        var stateUpdateHandler: (@Sendable (NWBrowser.State) -> Void)?
        private(set) var started = false
        private(set) var cancelled = false

        func start(queue: DispatchQueue) { started = true }
        func cancel() { cancelled = true }

        func fail() {
            stateUpdateHandler?(.failed(NWError.posix(.ECONNABORTED)))
        }

    }

    func testStableIdentityTable() {
        XCTAssertTrue(SenderController.samePhysicalDevice(
            wifiID: "A", usbID: "A", wifiName: "same", usbName: "same"))
        XCTAssertFalse(SenderController.samePhysicalDevice(
            wifiID: "A", usbID: "B", wifiName: "same", usbName: "same"))
        XCTAssertTrue(SenderController.samePhysicalDevice(
            wifiID: nil, usbID: nil, wifiName: "same", usbName: "same"))
        XCTAssertFalse(SenderController.samePhysicalDevice(
            wifiID: "A", usbID: nil, wifiName: "same", usbName: "same"))
        XCTAssertFalse(SenderController.samePhysicalDevice(
            wifiID: nil, usbID: "B", wifiName: "same", usbName: "same"))
    }

    func testFailedBrowserRestartsAndDiscardsStaleResults() async throws {
        let first = FakeBrowser()
        let second = FakeBrowser()
        var browsers = [first, second]
        var scheduledRestart: (() -> Void)?
        let controller = SenderController(
            makeBrowser: { browsers.removeFirst() },
            scheduleRestart: { _, work in scheduledRestart = work })
        XCTAssertTrue(first.started)

        first.fail()
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertTrue(first.cancelled)
        XCTAssertNotNil(scheduledRestart)

        scheduledRestart?()
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertTrue(second.started)

        let stale = DiscoveryResultView(
            stableID: "stale-install", serviceName: "Stale Device")
        let current = DiscoveryResultView(
            stableID: "current-install", serviceName: "Current Device")
        controller.publishDiscoveryResults([stale], callbackGeneration: 1)
        XCTAssertFalse(SenderController.discoveryCallbackMayApply(
            callbackGeneration: 1, currentGeneration: 3))
        XCTAssertTrue(controller.discovered.isEmpty)

        controller.publishDiscoveryResults([current], callbackGeneration: 3)
        XCTAssertTrue(SenderController.discoveryCallbackMayApply(
            callbackGeneration: 3, currentGeneration: 3))
        XCTAssertEqual(controller.discovered.count, 1)
        XCTAssertEqual(controller.discovered.first?.stableID, "current-install")
        XCTAssertEqual(controller.discovered.first?.serviceName, "Current Device")
        XCTAssertTrue(second.started)
    }
}
