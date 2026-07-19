import XCTest
import CoreVideo
@testable import PhotonPort

final class S02SenderStateTests: XCTestCase {
    private func pixelBuffer() throws -> CVPixelBuffer {
        var buffer: CVPixelBuffer?
        XCTAssertEqual(CVPixelBufferCreate(nil, 2, 2, kCVPixelFormatType_32BGRA, nil, &buffer), kCVReturnSuccess)
        return try XCTUnwrap(buffer)
    }
    private func policyState(connected: Bool = true, stopped: Bool = false,
                             generationCurrent: Bool = true, pendingEncodes: Int = 0,
                             pendingSends: Int = 0, maxPendingSends: Int = 3,
                             lastAdmission: Date = .distantPast) -> MacSender.VideoAdmissionPolicy.State {
        .init(stopped: stopped, connected: connected, generationCurrent: generationCurrent,
              encoderConfigured: true, pendingEncodes: pendingEncodes, pendingAdmissions: 0,
              pendingSends: pendingSends, maxPendingSends: maxPendingSends,
              lastAdmission: lastAdmission, now: Date(), minimumInterval: 0.01)
    }


    func testSenderStopIsAwaitableAndIdempotent() async {
        let sender = MacSender(transport: .tcp(.hostPort(host: "localhost", port: 59999), security: .plaintext), name: "audit", mode: .mirror)
        await sender.stop()
        await sender.stop()
    }

    func testFallbackAudioIngressBoundsStalledConsumerAndRejectsStaleEpoch() {
        let queue = DispatchQueue(label: "audit.fallback-audio")
        let blockerStarted = DispatchSemaphore(value: 0)
        let unblock = DispatchSemaphore(value: 0)
        let consumed = expectation(description: "eight accepted samples consumed")
        consumed.expectedFulfillmentCount = 8
        var count = 0
        queue.async {
            blockerStarted.signal()
            unblock.wait()
        }
        XCTAssertEqual(blockerStarted.wait(timeout: .now() + 1), .success)

        let ingress = MacSender.FallbackAudioIngress<Int>(queue: queue) { _ in
            count += 1
            consumed.fulfill()
        }
        for sample in 0..<9 { ingress.submit(sample) }
        unblock.signal()
        wait(for: [consumed], timeout: 1)
        XCTAssertEqual(count, 8)

        let staleQueue = DispatchQueue(label: "audit.fallback-audio.stale")
        let staleBlocked = DispatchSemaphore(value: 0)
        let staleUnblock = DispatchSemaphore(value: 0)
        let current = expectation(description: "new epoch is consumed")
        var staleCount = 0
        staleQueue.async {
            staleBlocked.signal()
            staleUnblock.wait()
        }
        XCTAssertEqual(staleBlocked.wait(timeout: .now() + 1), .success)
        let staleIngress = MacSender.FallbackAudioIngress<Int>(queue: staleQueue) { _ in
            staleCount += 1
            current.fulfill()
        }
        staleIngress.submit(1)
        staleIngress.reset()
        staleUnblock.signal()
        staleIngress.submit(2)
        wait(for: [current], timeout: 1)
        XCTAssertEqual(staleCount, 1)
    }
    func testFallbackAudioIngressReleasesReservationAfterDeallocation() {
        let queue = DispatchQueue(label: "audit.fallback-audio.deinit")
        let entered = DispatchSemaphore(value: 0)
        let unblock = DispatchSemaphore(value: 0)
        queue.async {
            entered.signal()
            unblock.wait()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)

        let gate = MacSender.AudioReservationGate()
        weak var weakIngress: MacSender.FallbackAudioIngress<Int>?
        do {
            let ingress = MacSender.FallbackAudioIngress<Int>(queue: queue, gate: gate) { _ in }
            weakIngress = ingress
            ingress.submit(1)
        }
        XCTAssertNil(weakIngress)
        unblock.signal()
        queue.sync {}
        XCTAssertTrue(gate.isIdle())
    }


    func testVideoAdmissionPolicyRejectsDistinctBoundaryStates() {
        XCTAssertFalse(MacSender.VideoAdmissionPolicy.evaluate(policyState(connected: false)))
        XCTAssertFalse(MacSender.VideoAdmissionPolicy.evaluate(policyState(pendingSends: 3, maxPendingSends: 3)))
        XCTAssertFalse(MacSender.VideoAdmissionPolicy.evaluate(policyState(pendingEncodes: 2)))
        XCTAssertFalse(MacSender.VideoAdmissionPolicy.evaluate(policyState(generationCurrent: false)))
        XCTAssertFalse(MacSender.VideoAdmissionPolicy.evaluate(policyState(lastAdmission: Date())))
        XCTAssertTrue(MacSender.VideoAdmissionPolicy.evaluate(policyState()))
    }

    func testFrameAdmissionPipelineConvertsOnceAndCancelsFailure() throws {
        let buffer = try pixelBuffer()
        var reservations = 0
        var conversions = 0
        var encodes = 0
        var cancellations = 0
        let pipeline = MacSender.FrameAdmissionPipeline(
            reserve: { _ in
                reservations += 1
                return MacSender.FrameAdmission(generation: 1)
            },
            cancel: { _ in cancellations += 1 },
            admitted: { _, _, _ in encodes += 1 })

        pipeline.submitSCK(buffer, pts: .zero)
        XCTAssertEqual(reservations, 1)
        XCTAssertEqual(encodes, 1)

        pipeline.submitCG(pts: .zero) {
            conversions += 1
            return nil
        }
        XCTAssertEqual(reservations, 2)
        XCTAssertEqual(conversions, 1)
        XCTAssertEqual(encodes, 1)
        XCTAssertEqual(cancellations, 1)
    }
}
