// SPDX-License-Identifier: GPL-3.0-only
// Process launcher for cross-repo production protocol interop evidence.
import Foundation

private enum Failure: Error { case usage, invalidFrame, invalidPayload }

private func readAllStandardInput() -> Data { FileHandle.standardInput.readDataToEndOfFile() }
private func writeStandardOutput(_ data: Data) { FileHandle.standardOutput.write(data) }

private func payload(for vector: String) throws -> Data {
    switch vector {
    case "ping": return Data(#"{"id":7,"t":1.25,"type":"ping"}"#.utf8)
    case "touch": return Data(#"{"phase":"began","type":"touch","x":0.25,"y":0.75}"#.utf8)
    case "scroll": return Data(#"{"dx":12.5,"dy":-8,"type":"scroll"}"#.utf8)
    case "keyframe": return Data(#"{"type":"kf"}"#.utf8)
    default: throw Failure.usage
    }
}

private func framed(_ payload: Data) throws -> Data {
    guard (1...ProtocolParser.cap(for: .session)).contains(payload.count) else { throw Failure.invalidPayload }
    var length = UInt32(payload.count).bigEndian
    var data = Data(bytes: &length, count: 4)
    data.append(payload)
    return data
}

private func encodedFrame(for vector: String) throws -> Data {
    if vector == "session-open" {
        let message = SessionOpen(
            v: 3,
            macInstallID: "00000000-1111-2222-3333-444444444444",
            deviceInstallID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            macNonce: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
            primaryProof: "HsL0VUhmTZuCDxXzVzTzbQlu77xdUhX4jZ67KyoZNTI="
        )
        guard let frame = PairingWire.frame(message, kind: .session) else {
            throw Failure.invalidPayload
        }
        return frame
    }
    return try framed(payload(for: vector))
}

private func decodeFrame(_ data: Data) throws {
    guard data.count >= 4 else { throw Failure.invalidFrame }
    let expected = try ProtocolParser.framedPayloadLength(from: Data(data.prefix(4)), kind: .session)
    let payload = Data(data.dropFirst(4))
    try ProtocolParser.validatePayload(payload, expectedLength: expected, kind: .session)
    if (try? ProtocolParser.parseControl(payload, transport: .wifi)) == nil {
        _ = try ProtocolParser.parseSessionAccept(payload)
    }
}

private func verdict(_ id: String, _ passed: Bool) {
    let status = passed ? "passed" : "failed"
    print("{\"caseID\":\"\(id)\",\"result\":\"\(status)\"}")
}

private func runCase(_ id: String) -> Bool {
    do {
        switch id {
        case "duplicate-json-key":
            try decodeFrame(try framed(Data(#"{"type":"kf","type":"ping"}"#.utf8)))
            return false
        case "invalid-utf8-json":
            try decodeFrame(try framed(Data([0xff])))
            return false
        case "bad-length-prefix":
            var header = UInt32(261).bigEndian
            var frame = Data(bytes: &header, count: 4)
            frame.append(Data(repeating: UInt8(ascii: "{"), count: 260))
            try decodeFrame(frame)
            return false
        case "oversize-frame":
            var header = UInt32(65_536).bigEndian
            try decodeFrame(Data(bytes: &header, count: 4))
            return false
        default:
            return false
        }
    } catch {
        return true
    }
}

@main
private struct MacInteropLauncher {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        do {
            guard let mode = args.first else { throw Failure.usage }
            switch mode {
            case "encode":
                guard args.count == 2 else { throw Failure.usage }
                writeStandardOutput(try encodedFrame(for: args[1]))
            case "decode":
                try decodeFrame(readAllStandardInput())
                FileHandle.standardError.write(Data("OK\n".utf8))
            case "case":
                guard args.count == 2 else { throw Failure.usage }
                let passed = runCase(args[1])
                verdict(args[1], passed)
                if !passed { exit(1) }
            default:
                throw Failure.usage
            }
        } catch {
            FileHandle.standardError.write(Data("FAIL_CLOSED: \(error)\n".utf8))
            exit(1)
        }
    }
}
