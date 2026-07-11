// SPDX-License-Identifier: MIT
// Process launcher for cross-repo production protocol interop evidence.
import Foundation

private enum Failure: Error { case usage, invalidFrame, invalidPayload }

private func readAllStandardInput() -> Data { FileHandle.standardInput.readDataToEndOfFile() }
private func writeStandardOutput(_ data: Data) { FileHandle.standardOutput.write(data) }

private func message(for vector: String) throws -> [String: Any] {
    switch vector {
    case "pong": return ["type": "pong", "id": 7, "t": 2.5]
    case "cursor": return ["type": "cursor", "x": 0.5, "y": 0.125, "visible": true]
    case "stats": return ["type": "stats", "fps": 60.0, "bitrate": 12.0, "dropped": 0]
    case "keyframe": return ["type": "kf"]
    default: throw Failure.usage
    }
}

private func framed(_ payload: Data) throws -> Data {
    guard WireFrame.isValidPayloadLength(payload.count, for: .sessionControl) else { throw Failure.invalidPayload }
    var length = UInt32(payload.count).bigEndian
    var data = Data(bytes: &length, count: 4)
    data.append(payload)
    return data
}

private func encodedFrame(for vector: String) throws -> Data {
    if vector == "session-accept" {
        let message = SessionAccept(
            v: 3,
            sessionID: "QUJDREVGR0hJSktMTU5PUA==",
            generation: 72_623_859_790_382_856,
            acceptProof: "AuB3h/5eqUfJIXddq8/ZWtSYuzIcQy6T40Vg7TPPm9M="
        )
        guard let frame = PairingWire.frame(message) else {
            throw Failure.invalidPayload
        }
        return frame
    }
    guard let payload = SessionControlEncoder.payload(for: try message(for: vector)) else {
        throw Failure.invalidPayload
    }
    return try framed(payload)
}

private func decodeFrame(_ data: Data) throws {
    guard data.count >= 4,
          let expected = WireFrame.payloadLength(fromExactHeader: data.prefix(4), for: .sessionControl) else {
        throw Failure.invalidFrame
    }
    let payload = Data(data.dropFirst(4))
    guard payload.count == expected else { throw Failure.invalidPayload }
    if SessionControlValidator.validate(payload) == nil,
       SessionWireParser.parse(payload) == nil {
        throw Failure.invalidPayload
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
private struct IOSInteropLauncher {
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
