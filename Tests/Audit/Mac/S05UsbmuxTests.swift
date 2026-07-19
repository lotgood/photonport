import XCTest
@testable import PhotonPort

@MainActor
final class S05UsbmuxTests: XCTestCase {
    private func header(length: UInt32 = 16, version: UInt32 = 1,
                        type: UInt32 = 8, tag: UInt32 = 1) -> Data {
        var data = Data()
        for value in [length, version, type, tag] {
            withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
        }
        return data
    }

    func testDelayedNameCannotApplyAfterDetachAndDeviceIDReuse() {
        let reusedID = 42
        let detachedA = UsbmuxDevice(deviceID: reusedID, udid: "A", name: nil)
        let attachedB = UsbmuxDevice(deviceID: reusedID, udid: "B", name: nil)

        XCTAssertFalse(UsbmuxDeviceWatcher.nameMayApply(
            lookupUDID: detachedA.udid, lookupGeneration: 1,
            device: nil, currentGeneration: 2))
        XCTAssertFalse(UsbmuxDeviceWatcher.nameMayApply(
            lookupUDID: detachedA.udid, lookupGeneration: 1,
            device: attachedB, currentGeneration: 3))
        XCTAssertTrue(UsbmuxDeviceWatcher.nameMayApply(
            lookupUDID: attachedB.udid, lookupGeneration: 3,
            device: attachedB, currentGeneration: 3))
    }

    func testDeadlineCancellationAndBoundedRetry() async {
        do {
            _ = try await Usbmux.withRequestDeadline(timeout: .milliseconds(10)) {
                try await Task.sleep(for: .seconds(1))
                return 1
            }
            XCTFail("no-reply request must time out")
        } catch let error as Usbmux.Failure {
            guard case .timeout = error else { return XCTFail("unexpected \(error)") }
        } catch {
            XCTFail("unexpected \(error)")
        }

        let cancelled = Task {
            try await Usbmux.withRequestDeadline(timeout: .seconds(1)) {
                try await Task.sleep(for: .seconds(1))
                return 1
            }
        }
        cancelled.cancel()
        do {
            _ = try await cancelled.value
            XCTFail("cancelled request must not succeed")
        } catch is CancellationError {
        } catch {
            XCTFail("unexpected \(error)")
        }

        actor Attempts {
            var count = 0
            func next() -> Int { count += 1; return count }
        }
        let attempts = Attempts()
        let value = try? await Usbmux.withBoundedRetry {
            if await attempts.next() == 1 { throw Usbmux.Failure.timeout }
            return "retried"
        }
        XCTAssertEqual(value, "retried")
        let count = await attempts.count
        XCTAssertEqual(count, 2)
    }

    func testRejectsMalformedUsbmuxHeaders() {
        XCTAssertThrowsError(try Usbmux.decodeHeader(Data(repeating: 0, count: 15)))
        XCTAssertThrowsError(try Usbmux.decodeHeader(header(length: 15)))
        XCTAssertThrowsError(try Usbmux.decodeHeader(header(version: 2)))
        XCTAssertThrowsError(try Usbmux.decodeHeader(header(type: 7)))
        XCTAssertThrowsError(try Usbmux.decodeHeader(header(tag: 2)))
        XCTAssertEqual(try? Usbmux.decodeHeader(header(length: 32)), 16)
    }

    func testRejectsMalformedOrMismatchedResults() {
        XCTAssertNoThrow(try Usbmux.decodeResult(["MessageType": "Result", "Number": 0], operation: "Listen"))
        XCTAssertThrowsError(try Usbmux.decodeResult(["MessageType": "Result"], operation: "Connect"))
        XCTAssertThrowsError(try Usbmux.decodeResult(["MessageType": "DeviceList", "Number": 0], operation: "Connect"))
        XCTAssertThrowsError(try Usbmux.decodeResult(["MessageType": "Result", "Number": 2], operation: "Connect"))
    }
}
