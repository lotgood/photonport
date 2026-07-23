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
        // Listen event packets are daemon-initiated: tag 0 (or an echoed
        // subscribe tag) is valid for events, still rejected for replies.
        XCTAssertThrowsError(try Usbmux.decodeHeader(header(length: 32, tag: 0)))
        XCTAssertEqual(try? Usbmux.decodeHeader(header(length: 32, tag: 0), accepting: .event), 16)
        XCTAssertEqual(try? Usbmux.decodeHeader(header(length: 32, tag: 1), accepting: .event), 16)
        XCTAssertThrowsError(try Usbmux.decodeHeader(header(length: 32, tag: 2), accepting: .event))
    }

    func testRejectsMalformedOrMismatchedResults() {
        XCTAssertNoThrow(try Usbmux.decodeResult(["MessageType": "Result", "Number": 0], operation: "Listen"))
        XCTAssertThrowsError(try Usbmux.decodeResult(["MessageType": "Result"], operation: "Connect"))
        XCTAssertThrowsError(try Usbmux.decodeResult(["MessageType": "DeviceList", "Number": 0], operation: "Connect"))
        XCTAssertThrowsError(try Usbmux.decodeResult(["MessageType": "Result", "Number": 2], operation: "Connect"))
    }
    func testUSBPrefaceDeterministicHandshakeAndDirectionalRecords() {
        let psk = Data(repeating: 0xA5, count: 32)
        let macNonce = Data(repeating: 0x11, count: 32)
        let deviceNonce = Data(repeating: 0x22, count: 32)
        let mac = USBPrefaceClient(psk: psk, macInstallID: "mac", deviceInstallID: "receiver",
                                   purpose: "primary", startedAt: 0, token: 7, macNonce: macNonce)!
        let device = USBPrefaceServer(psk: psk, macInstallID: "mac", deviceInstallID: "receiver",
                                      purpose: "primary", startedAt: 0, token: 7)!
        let initial = mac.start(now: 0, token: 7)!
        XCTAssertEqual(initial.prefix(8), USBPrefaceMessage.magic)
        let initPayload = USBPrefaceMessage.unframe(Data(initial.dropFirst(8)))!.0
        XCTAssertTrue(device.consumeMagic(USBPrefaceMessage.magic, now: 0, token: 7))
        let challenge = device.consume(initPayload, now: 0, token: 7, nonce: deviceNonce)!
        let finish = mac.consume(USBPrefaceMessage.unframe(challenge)!.0, now: 0, token: 7)!
        let accept = device.consume(USBPrefaceMessage.unframe(finish)!.0, now: 0, token: 7)!
        XCTAssertEqual(mac.consume(USBPrefaceMessage.unframe(accept)!.0, now: 0, token: 7), Data())
        let binding = mac.authenticatedBinding()
        XCTAssertEqual(binding, device.authenticatedBinding())

        let sender = USBRecordState(role: "mac", binding: binding!, macInstallID: "mac",
                                    deviceInstallID: "receiver", purpose: "primary",
                                    macNonce: macNonce, deviceNonce: deviceNonce)!
        let receiver = USBRecordState(role: "device", binding: binding!, macInstallID: "mac",
                                      deviceInstallID: "receiver", purpose: "primary",
                                      macNonce: macNonce, deviceNonce: deviceNonce)!
        XCTAssertEqual(receiver.consume(sender.frame(Data("hello".utf8), cap: 32)!, cap: 32)?.0, Data("hello".utf8))
    }

    func testUSBRejectsDuplicatePrefaceAndTamperedRecordBeforePayload() {
        let duplicate = Data(#"{"type":"usb-bind-init","type":"usb-bind-init","v":1,"macInstallID":"m","deviceInstallID":"d","purpose":"primary","macNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","proof":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#.utf8)
        XCTAssertNil(USBPrefaceMessage.decode(duplicate, expectedType: "usb-bind-init"))

        let binding = Data(repeating: 1, count: 32), nonce = Data(repeating: 2, count: 32)
        let sender = USBRecordState(role: "mac", binding: binding, macInstallID: "m", deviceInstallID: "d",
                                    purpose: "primary", macNonce: nonce, deviceNonce: nonce)!
        let receiver = USBRecordState(role: "device", binding: binding, macInstallID: "m", deviceInstallID: "d",
                                      purpose: "primary", macNonce: nonce, deviceNonce: nonce)!
        var record = sender.frame(Data([1]), cap: 1)!
        record[record.index(before: record.endIndex)] ^= 1
        XCTAssertNil(receiver.consume(record, cap: 1))
        XCTAssertTrue(receiver.closed)
    }
}
