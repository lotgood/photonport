import Foundation
import Network
import XCTest
@testable import PhotonPort

final class S01AdmissionTests: XCTestCase {
    func testBundledFinalPinIsAcceptedAndTamperedOrOldPinsAreRejected() throws {
        let bundled = try bundledPinURL()
        XCTAssertNoThrow(try ProtocolBuildPin.validate(at: bundled))

        let validPin = try String(contentsOf: bundled, encoding: .utf8)
        // Mutate the commit the pin actually carries; a hardcoded historical
        // hash silently no-ops once the pin advances.
        let pinObject = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(validPin.utf8)) as? [String: Any])
        let pinnedCommit = try XCTUnwrap(pinObject["protocolCommit"] as? String)
        XCTAssertNotEqual(pinnedCommit, String(repeating: "0", count: 40))
        XCTAssertThrowsError(try ProtocolBuildPin.validate(at: nil))
        XCTAssertThrowsError(try ProtocolBuildPin.validate(at: temporaryFile(contents: "{")))
        XCTAssertThrowsError(try ProtocolBuildPin.validate(
            at: temporaryFile(contents: validPin.replacingOccurrences(
                of: pinnedCommit,
                with: String(repeating: "0", count: 40)))))
        XCTAssertThrowsError(try ProtocolBuildPin.validate(
            at: temporaryFile(contents: validPin.replacingOccurrences(
                of: pinnedCommit,
                with: "2280861313b2363b673089637d1c1dc544e208d8"))))
    }

    func testPlaintextTCPRequiresLoopback() throws {
        let pin = try bundledPinURL()
        XCTAssertNoThrow(try MacSender.validateAdmission(
            transport: .tcp(endpoint("127.0.0.1"), security: .plaintext), pinURL: pin))
        XCTAssertNoThrow(try MacSender.validateAdmission(
            transport: .tcp(endpoint("localhost"), security: .plaintext), pinURL: pin))
        XCTAssertThrowsError(try MacSender.validateAdmission(
            transport: .tcp(endpoint("192.168.1.20"), security: .plaintext), pinURL: pin))
        XCTAssertThrowsError(try MacSender.validateAdmission(
            transport: .tcp(endpoint("8.8.8.8"), security: .plaintext), pinURL: pin))
    }

    func testPairedTLSAndUSBAreAdmitted() throws {
        let pin = try bundledPinURL()
        XCTAssertNoThrow(try MacSender.validateAdmission(
            transport: .tcp(endpoint("192.168.1.20"), security: .pairedTLS(identity: "test", key: Data(repeating: 1, count: 32))),
            pinURL: pin))
        XCTAssertNoThrow(try MacSender.validateAdmission(
            transport: .usb(udid: nil, port: 9000), pinURL: pin))
    }

    private func endpoint(_ host: String) -> NWEndpoint {
        .hostPort(host: NWEndpoint.Host(host), port: 9000)
    }

    private func bundledPinURL() throws -> URL {
        guard let url = Bundle(for: MacSender.self).url(forResource: "ProtocolBuildPin",
                                                         withExtension: "json") else {
            throw SessionAdmissionError.invalidProtocolBuildPin("resource is missing")
        }
        return url
    }
    private func temporaryFile(contents: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try contents.write(to: url, atomically: true, encoding: .utf8)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }
}
