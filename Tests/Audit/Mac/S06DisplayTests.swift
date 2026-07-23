import XCTest
@testable import PhotonPort

final class S06DisplayTests: XCTestCase {
    func testHiDPIModeRejectsWrongHeightAtHighRefresh() {
        XCTAssertTrue(VirtualDisplay.matchesHiDPIGeometry(pointsWide: 1280, pointsHigh: 720,
                                                           modeWidth: 1280, modeHeight: 720,
                                                           pixelWidth: 2560, pixelHeight: 1440))
        XCTAssertFalse(VirtualDisplay.matchesHiDPIGeometry(pointsWide: 1280, pointsHigh: 720,
                                                            modeWidth: 1280, modeHeight: 700,
                                                            pixelWidth: 2560, pixelHeight: 1440))
        XCTAssertFalse(VirtualDisplay.matchesHiDPIGeometry(pointsWide: 1280, pointsHigh: 720,
                                                            modeWidth: 1280, modeHeight: 720,
                                                            pixelWidth: 2560, pixelHeight: 1400))
    }

    func testPixelGeometryRejectsInvalidAxisAndOverbudgetSurfaces() {
        XCTAssertFalse(VirtualDisplay.acceptsPixelGeometry(width: 0, height: 1179))
        XCTAssertFalse(VirtualDisplay.acceptsPixelGeometry(width: -1, height: 1179))
        XCTAssertFalse(VirtualDisplay.acceptsPixelGeometry(width: 2556, height: 0))
        XCTAssertFalse(VirtualDisplay.acceptsPixelGeometry(width: 32_769, height: 1179))
        XCTAssertFalse(VirtualDisplay.acceptsPixelGeometry(width: 32_768, height: 32_768))

        XCTAssertTrue(VirtualDisplay.acceptsPixelGeometry(width: 7_680, height: 4_320))
        XCTAssertFalse(VirtualDisplay.acceptsPixelGeometry(width: 7_680, height: 4_321))
        XCTAssertFalse(VirtualDisplay.acceptsPixelGeometry(width: 32_768, height: 1_014))
        XCTAssertTrue(VirtualDisplay.acceptsPixelGeometry(width: 32_768, height: 1_012))
    }

    func testPointGeometryUsesNativePixelBudgetWithoutOverflow() {
        XCTAssertFalse(VirtualDisplay.acceptsPointGeometry(width: 0, height: 1))
        XCTAssertFalse(VirtualDisplay.acceptsPointGeometry(width: -1, height: 1))
        XCTAssertTrue(VirtualDisplay.acceptsPointGeometry(width: 3_840, height: 2_160))
        XCTAssertFalse(VirtualDisplay.acceptsPointGeometry(width: 3_840, height: 2_161))
        XCTAssertFalse(VirtualDisplay.acceptsPointGeometry(width: 16_384, height: 16_384))
        XCTAssertFalse(VirtualDisplay.acceptsPointGeometry(width: 16_385, height: 1))
    }

    func testInjectedCoreGraphicsFailuresCancelExactlyOnceAfterBegin() {
        enum Event: Equatable {
            case begin, configure, complete, cancel
        }

        func run(begin: CGError, configure: CGError, complete: CGError) -> (Bool, [Event]) {
            var events: [Event] = []
            let succeeded = VirtualDisplay.performConfiguration(
                begin: {
                    events.append(.begin)
                    return (begin, begin == .success ? 1 : nil)
                },
                configure: { _ in
                    events.append(.configure)
                    return configure
                },
                complete: { _ in
                    events.append(.complete)
                    return complete
                },
                cancel: { _ in
                    events.append(.cancel)
                }
            )
            return (succeeded, events)
        }

        let beginFailure = run(begin: .failure, configure: .success, complete: .success)
        XCTAssertFalse(beginFailure.0)
        XCTAssertEqual(beginFailure.1, [.begin])

        let configureFailure = run(begin: .success, configure: .failure, complete: .success)
        XCTAssertFalse(configureFailure.0)
        XCTAssertEqual(configureFailure.1, [.begin, .configure, .cancel])

        let completeFailure = run(begin: .success, configure: .success, complete: .failure)
        XCTAssertFalse(completeFailure.0)
        XCTAssertEqual(completeFailure.1, [.begin, .configure, .complete, .cancel])

        let success = run(begin: .success, configure: .success, complete: .success)
        XCTAssertTrue(success.0)
        XCTAssertEqual(success.1, [.begin, .configure, .complete])
    }

    @MainActor
    func testImmediateHideAndTeardownInvalidatePatternRetry() {
        let displayID: CGDirectDisplayID = 0x53_06
        TestPattern.show(on: displayID, generation: 7)
        XCTAssertTrue(TestPattern.retryMayShow(on: displayID, requestedGeneration: 7, screenAvailable: true))
        TestPattern.hide(on: displayID, generation: 7)
        XCTAssertFalse(TestPattern.retryMayShow(on: displayID, requestedGeneration: 7, screenAvailable: true))
        XCTAssertFalse(TestPattern.retryMayShow(on: displayID, requestedGeneration: 6, screenAvailable: true))
    }
}
