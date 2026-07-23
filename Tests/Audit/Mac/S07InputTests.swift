import XCTest
@testable import PhotonPort

final class S07InputTests: XCTestCase {
    func testTouchEndpointsStayStrictlyInsideNegativeOriginScaledBounds() {
        let bounds = CGRect(x: -1440.5, y: -900.25, width: 2880, height: 1800)
        let start = InputInjector.touchPoint(x: 0, y: 0, in: bounds)
        let end = InputInjector.touchPoint(x: 1, y: 1, in: bounds)
        XCTAssertEqual(start.x, bounds.minX)
        XCTAssertEqual(start.y, bounds.minY)
        XCTAssertGreaterThan(end.x, bounds.minX)
        XCTAssertGreaterThan(end.y, bounds.minY)
        XCTAssertLessThan(end.x, bounds.maxX)
        XCTAssertLessThan(end.y, bounds.maxY)
    }

    func testScrollAnchorExistsBeforeTouch() {
        let bounds = CGRect(x: -200, y: -100, width: 400, height: 200)
        let anchor = InputInjector.insetPoint(in: bounds)
        XCTAssertTrue(bounds.contains(anchor))
    }

    func testParserAdmitsOnlyFiniteApprovedLocalScrollVectors() throws {
        XCTAssertTrue(ProtocolParser.acceptsApprovedLocalScrollVector(dx: -120, dy: 120))
        XCTAssertFalse(ProtocolParser.acceptsApprovedLocalScrollVector(dx: .infinity, dy: 0))
        XCTAssertFalse(ProtocolParser.acceptsApprovedLocalScrollVector(dx: .nan, dy: 0))
        XCTAssertFalse(ProtocolParser.acceptsApprovedLocalScrollVector(dx: 120.000_001, dy: 0))

        XCTAssertNoThrow(try ProtocolParser.parseControl(
            Data("{\"type\":\"scroll\",\"dx\":-120,\"dy\":120}".utf8), transport: .usb))
        XCTAssertThrowsError(try ProtocolParser.parseControl(
            Data("{\"type\":\"scroll\",\"dx\":1e999,\"dy\":0}".utf8), transport: .usb))
    }

    func testCoalescerIsDemandArmedAndTeardownCancelsPendingWork() {
        let queue = DispatchQueue(label: "S07InputTests.coalescer")
        let fired = expectation(description: "coalesced scroll")
        let coalescer = ScrollEventCoalescer(callback: { delta in
            XCTAssertEqual(delta, ScrollDelta(dx: 3, dy: -2))
            fired.fulfill()
        }, queue: queue)
        XCTAssertFalse(coalescer.isArmed)
        XCTAssertEqual(coalescer.pendingWorkCount, 0)
        XCTAssertTrue(coalescer.enqueue(dx: 1, dy: -1))
        XCTAssertTrue(coalescer.enqueue(dx: 2, dy: -1))
        XCTAssertTrue(coalescer.isArmed)
        wait(for: [fired], timeout: 1)
        XCTAssertFalse(coalescer.isArmed)
        XCTAssertEqual(coalescer.pendingWorkCount, 0)

        XCTAssertTrue(coalescer.enqueue(dx: 1, dy: 1))
        coalescer.cancel()
        coalescer.cancel()
        XCTAssertFalse(coalescer.isArmed)
        XCTAssertEqual(coalescer.pendingWorkCount, 0)
    }
    func testCancelFencesPausedDrainAndAllowsNextGeneration() {
        let timerQueue = DispatchQueue(label: "S07InputTests.paused-drain")
        let drainPaused = expectation(description: "drain paused after consuming pending work")
        let resumeDrain = DispatchSemaphore(value: 0)
        let hookLock = NSLock()
        var hookCount = 0
        let staleCallback = expectation(description: "cancelled generation does not inject")
        staleCallback.isInverted = true
        let freshCallback = expectation(description: "next generation injects")

        let coalescer = ScrollEventCoalescer(callback: { delta in
            if delta == ScrollDelta(dx: 1, dy: 0) {
                staleCallback.fulfill()
            } else {
                XCTAssertEqual(delta, ScrollDelta(dx: 2, dy: 0))
                freshCallback.fulfill()
            }
        }, queue: timerQueue, beforeCallbackDispatch: {
            hookLock.lock()
            hookCount += 1
            let shouldPause = hookCount == 1
            hookLock.unlock()
            if shouldPause {
                drainPaused.fulfill()
                resumeDrain.wait()
            }
        })

        XCTAssertTrue(coalescer.enqueue(dx: 1, dy: 0))
        wait(for: [drainPaused], timeout: 1)
        coalescer.cancel()
        resumeDrain.signal()
        wait(for: [staleCallback], timeout: 0.1)

        XCTAssertTrue(coalescer.enqueue(dx: 2, dy: 0))
        wait(for: [freshCallback], timeout: 1)
    }

    func testCoalescerBoundsBurstWorkToOnePendingDelta() {
        let coalescer = ScrollEventCoalescer()
        for _ in 0..<10_000 {
            XCTAssertTrue(coalescer.enqueue(dx: 120, dy: -120))
        }
        XCTAssertEqual(coalescer.pendingWorkCount, 1)
        XCTAssertEqual(coalescer.takePending(), ScrollDelta(dx: 120, dy: -120))
    }
}
