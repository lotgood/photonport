import Foundation
import Network
import XCTest
@testable import PhotonPort

final class S01AdmissionTests: XCTestCase {
    private let validPin = """
    {"schemaVersion":1,"protocolCommit":"2280861313b2363b673089637d1c1dc544e208d8","compatibilityDigest":"6e5e7faf195eff19fafcbdf388186641ef8f8c02586ae1d9f35df0bbc64ae3b3","normativeManifestDigest":"5265022d17d6a7c6ce962a8130b953fa0ae825b7284d66b2c5845ec7ee1388bc"}
    """

    func testMissingMalformedAndWrongPinsFailClosed() throws {
        XCTAssertThrowsError(try ProtocolBuildPin.validate(at: nil))
        XCTAssertThrowsError(try ProtocolBuildPin.validate(at: temporaryFile(contents: "{")))
        XCTAssertThrowsError(try ProtocolBuildPin.validate(at: temporaryFile(contents: validPin.replacingOccurrences(of: "2280861313b2363b673089637d1c1dc544e208d8", with: String(repeating: "0", count: 40)))))
    }

    func testPlaintextTCPRequiresLoopback() throws {
        let pin = try temporaryFile(contents: validPin)
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
        let pin = try temporaryFile(contents: validPin)
        XCTAssertNoThrow(try MacSender.validateAdmission(
            transport: .tcp(endpoint("192.168.1.20"), security: .pairedTLS(identity: "test", key: Data(repeating: 1, count: 32))),
            pinURL: pin))
        XCTAssertNoThrow(try MacSender.validateAdmission(
            transport: .usb(udid: nil, port: 9000), pinURL: pin))
    }

    private func endpoint(_ host: String) -> NWEndpoint {
        .hostPort(host: NWEndpoint.Host(host), port: 9000)
    }

    private func temporaryFile(contents: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try contents.write(to: url, atomically: true, encoding: .utf8)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }
}
