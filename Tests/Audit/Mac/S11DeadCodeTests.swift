import Foundation
import XCTest
@testable import PhotonPort

final class S11DeadCodeTests: XCTestCase {
    func testServerHelloUsesStrictProductionParser() throws {
        let payload = Data("""
        {"type":"server-hello","sessionVersion":3,"transport":"wifi","deviceNonce":"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=","wifiSessionSeed":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=","pixelsWide":2732,"pixelsHigh":2048,"scale":2.0,"device":"iPad","id":"device-a","maxFps":120,"hdr":true}
        """.utf8)

        let hello = try ProtocolParser.parseServerHello(payload, transport: .wifi)

        XCTAssertEqual(hello.pixelsWide, 2732)
        XCTAssertEqual(hello.pixelsHigh, 2048)
        XCTAssertEqual(hello.id, "device-a")
        XCTAssertEqual(hello.deviceNonce.count, 32)
        XCTAssertEqual(hello.wifiSessionSeed?.count, 32)
        XCTAssertThrowsError(try ProtocolParser.parseServerHello(payload, transport: .usb))
        XCTAssertThrowsError(try ProtocolParser.parseServerHello(
            Data("{\"type\":\"server-hello\"}".utf8), transport: .wifi))
    }

    func testPhoneInfoHasNoPermissiveDecodableEntryPoint() throws {
        let sender = try source("Mac/MacSender.swift")
        let phoneInfo = try XCTUnwrap(sender.components(separatedBy: "/// How the sender reaches").first)

        XCTAssertTrue(phoneInfo.contains("struct PhoneInfo"))
        XCTAssertFalse(phoneInfo.contains("PhoneInfo: Decodable"))
        XCTAssertFalse(phoneInfo.contains("CodingKeys"))
        XCTAssertFalse(phoneInfo.contains("init(from decoder:"))
        XCTAssertFalse(phoneInfo.contains("JSONDecoder().decode(PhoneInfo.self"))
        XCTAssertTrue(phoneInfo.contains("init(_ hello: ProtocolParser.ServerHello)"))
    }

    func testServerHelloProductionPathHasNoReflectionOrAlternateSource() throws {
        let sender = try source("Mac/MacSender.swift")
        let parser = try source("Mac/ProtocolParser.swift")

        XCTAssertFalse(sender.contains("Mirror("))
        XCTAssertFalse(sender.localizedCaseInsensitiveContains("storyboard"))
        XCTAssertFalse(sender.contains("JSONDecoder().decode(PhoneInfo.self"))
        XCTAssertTrue(sender.contains("case .serverHello(let parsed):"))
        XCTAssertTrue(sender.contains("let info = PhoneInfo(parsed)"))
        XCTAssertTrue(parser.contains("static func parseServerHello"))
    }

    private func source(_ relativePath: String) throws -> String {
        let testFile = URL(fileURLWithPath: #filePath)
        let root = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent(relativePath), encoding: .utf8)
    }
}
