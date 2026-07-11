// SPDX-License-Identifier: GPL-3.0-only
// Part of PhotonPort.

import Foundation
import CryptoKit

enum ProtocolParser {
    enum FrameKind { case pairing, session, audioControl, audioData, videoData }
    enum Transport { case wifi, usb }

    static let smallControlCap = 65_535
    static let audioDataCap = 262_144
    static let videoDataCap = 16_777_216

    struct ServerHello {
        let pixelsWide: Int
        let pixelsHigh: Int
        let scale: Double
        let device: String
        let id: String
        let maxFps: Int
        let hdr: Bool
        let deviceNonce: Data
        let usbSessionSeed: Data?
    }

    struct VerifiedSessionAccept {
        let message: SessionAccept
        let sessionID: Data
        let channelSecret: SymmetricKey
    }

    enum Control {
        case ping(id: UInt64, t: Double)
        case stats(fps: Double, bitrate: Double, dropped: UInt64, raw: String)
        case touch(phase: String, x: Double, y: Double, t: Double?)
        case scroll(dx: Double, dy: Double)
        case keyframe
        case serverHello(ServerHello)
        case sessionAccept(SessionAccept)
        case sessionBusy(SessionBusy)
    }

    enum ParseError: Error { case invalidFrame, invalidJSON, duplicateKey, keySet, type, value }

    static func cap(for kind: FrameKind) -> Int {
        switch kind {
        case .pairing, .session, .audioControl: return smallControlCap
        case .audioData: return audioDataCap
        case .videoData: return videoDataCap
        }
    }

    static func framedPayloadLength(from header: Data, kind: FrameKind) throws -> Int {
        guard header.count == 4 else { throw ParseError.invalidFrame }
        let length = Int(UInt32(bigEndian: header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
        guard (1...cap(for: kind)).contains(length) else { throw ParseError.invalidFrame }
        return length
    }

    static func validatePayload(_ payload: Data, expectedLength: Int, kind: FrameKind) throws {
        guard payload.count == expectedLength, (1...cap(for: kind)).contains(payload.count) else {
            throw ParseError.invalidFrame
        }
    }

    static func parsePairCommit(_ data: Data) throws -> PairCommit {
        let object = try strictObject(data, keys: ["type", "v", "commit"])
        guard try string(object, "type") == "pair-commit", try int(object, "v") == PairingCrypto.version else { throw ParseError.value }
        _ = try base64(try string(object, "commit"), bytes: 32)
        return try JSONDecoder().decode(PairCommit.self, from: data)
    }

    static func parsePairHello(_ data: Data, role: String? = nil) throws -> PairHello {
        let allowed = Set(["type", "v", "role", "installID", "name", "pub", "nonce"])
        let object = try strictObject(data, allowedKeys: allowed)
        guard try string(object, "type") == "pair-hello", try int(object, "v") == PairingCrypto.version else { throw ParseError.value }
        let actualRole = try string(object, "role")
        if let role, actualRole != role { throw ParseError.value }
        guard actualRole == "mac" || actualRole == "device" else { throw ParseError.value }
        let required: Set<String> = actualRole == "mac" ? allowed : ["type", "v", "role", "installID", "pub", "nonce"]
        guard Set(object.keys) == required else { throw ParseError.keySet }
        try boundedString(object, "installID", 1, 256)
        if actualRole == "mac" { try boundedString(object, "name", 1, 256) }
        _ = try base64(try string(object, "pub"), bytes: 32)
        _ = try base64(try string(object, "nonce"), bytes: 16)
        return try JSONDecoder().decode(PairHello.self, from: data)
    }

    static func parseServerHello(_ data: Data, transport: Transport) throws -> ServerHello {
        let base: Set<String> = ["type", "sessionVersion", "deviceNonce", "pixelsWide", "pixelsHigh", "scale", "device", "id", "maxFps", "hdr"]
        let required = transport == .usb ? base.union(["usbSessionSeed"]) : base
        let object = try strictObject(data, keys: required)
        guard try string(object, "type") == "server-hello", try int(object, "sessionVersion") == SessionCrypto.version else { throw ParseError.value }
        let width = try rangedInt(object, "pixelsWide", 1, 65_535)
        let height = try rangedInt(object, "pixelsHigh", 1, 65_535)
        let scale = try finiteDouble(object, "scale", greaterThan: 0, max: 16)
        let device = try string(object, "device")
        guard device == "iPad" || device == "iPhone" else { throw ParseError.value }
        try boundedString(object, "id", 1, 256)
        let fps = try rangedInt(object, "maxFps", 1, 240)
        guard let hdr = object["hdr"] as? Bool else { throw ParseError.type }
        let deviceNonce = try base64(try string(object, "deviceNonce"), bytes: 32)
        let seed = transport == .usb ? try base64(try string(object, "usbSessionSeed"), bytes: 32) : nil
        return ServerHello(pixelsWide: width, pixelsHigh: height, scale: scale, device: device, id: try string(object, "id"), maxFps: fps, hdr: hdr, deviceNonce: deviceNonce, usbSessionSeed: seed)
    }

    static func parseSessionAccept(_ data: Data) throws -> SessionAccept {
        let object = try strictObject(data, keys: ["type", "v", "sessionID", "generation", "acceptProof"])
        guard try string(object, "type") == "session-accept", try int(object, "v") == SessionCrypto.version else { throw ParseError.value }
        _ = try base64(try string(object, "sessionID"), bytes: 16)
        guard try uint64(object, "generation") > 0 else { throw ParseError.value }
        _ = try base64(try string(object, "acceptProof"), bytes: 32)
        return try JSONDecoder().decode(SessionAccept.self, from: data)
    }

    static func parseVerifiedSessionAccept(_ data: Data, primaryKey: SymmetricKey,
                                           macInstallID: String, deviceInstallID: String,
                                           macNonce: Data, deviceNonce: Data) throws -> VerifiedSessionAccept {
        let message = try parseSessionAccept(data)
        let sessionID = try base64(message.sessionID, bytes: 16)
        let proof = try base64(message.acceptProof, bytes: 32)
        let secret = SessionCrypto.channelSecret(
            primaryKey: primaryKey, sessionID: sessionID, generation: message.generation)
        let expected = SessionCrypto.acceptProof(
            key: secret, sessionID: sessionID, generation: message.generation,
            macInstallID: macInstallID, deviceInstallID: deviceInstallID,
            macNonce: macNonce, deviceNonce: deviceNonce)
        guard SessionCrypto.constantTimeEqual(proof, expected) else { throw ParseError.value }
        return VerifiedSessionAccept(message: message, sessionID: sessionID, channelSecret: secret)
    }

    static func parseSessionBusy(_ data: Data) throws -> SessionBusy {
        let object = try strictObject(data, keys: ["type", "v", "reason"])
        guard try string(object, "type") == "session-busy", try int(object, "v") == SessionCrypto.version else { throw ParseError.value }
        let reasons: Set<String> = ["incompatible", "invalid_session_open", "primary_auth_failed", "random_failed", "session_busy", "audio_without_primary", "stale_audio_channel", "audio_proof_or_replay"]
        guard reasons.contains(try string(object, "reason")) else { throw ParseError.value }
        return try JSONDecoder().decode(SessionBusy.self, from: data)
    }

    static func parseChannelOpen(_ data: Data, channel: String? = nil) throws -> SessionChannelOpen {
        let object = try strictObject(data, keys: ["type", "v", "macInstallID", "sessionID", "generation", "channel", "nonce", "proof"])
        guard try string(object, "type") == "channel-open", try int(object, "v") == SessionCrypto.version else { throw ParseError.value }
        if let channel, try string(object, "channel") != channel { throw ParseError.value }
        try boundedString(object, "macInstallID", 1, 256)
        _ = try base64(try string(object, "sessionID"), bytes: 16)
        guard try uint64(object, "generation") > 0 else { throw ParseError.value }
        let c = try string(object, "channel"); guard c == "audio" else { throw ParseError.value }
        _ = try base64(try string(object, "nonce"), bytes: 32)
        _ = try base64(try string(object, "proof"), bytes: 32)
        return try JSONDecoder().decode(SessionChannelOpen.self, from: data)
    }

    static func parseGenerationSnapshot(_ data: Data) throws -> SessionOwnershipState.Snapshot {
        let object = try strictObject(data, keys: ["generation", "generationExhausted"])
        guard let generationExhausted = object["generationExhausted"] as? Bool else {
            throw ParseError.type
        }
        return SessionOwnershipState.Snapshot(
            generation: try uint64(object, "generation"),
            generationExhausted: generationExhausted)
    }

    static func parseControl(_ data: Data, transport: Transport) throws -> Control {
        let object = try strictAnyObject(data)
        switch try string(object, "type") {
        case "ping":
            guard Set(object.keys) == ["type", "id", "t"] else { throw ParseError.keySet }
            return .ping(id: try uint64(object, "id"), t: try finiteDouble(object, "t", greaterThanOrEqualTo: 0, max: Double.greatestFiniteMagnitude))
        case "stats":
            guard Set(object.keys) == ["type", "fps", "bitrate", "dropped"] else { throw ParseError.keySet }
            let raw = String(data: data, encoding: .utf8) ?? "{}"
            return .stats(fps: try finiteDouble(object, "fps", greaterThanOrEqualTo: 0, max: Double.greatestFiniteMagnitude),
                          bitrate: try finiteDouble(object, "bitrate", greaterThanOrEqualTo: 0, max: Double.greatestFiniteMagnitude),
                          dropped: try uint64(object, "dropped"),
                          raw: raw)
        case "touch":
            let keys = Set(object.keys)
            guard keys == ["type", "phase", "x", "y"] || keys == ["type", "phase", "x", "y", "t"] else {
                throw ParseError.keySet
            }
            let phase = try string(object, "phase")
            guard ["began", "moved", "ended", "cancelled"].contains(phase) else {
                throw ParseError.value
            }
            let x = try finiteDouble(object, "x", greaterThanOrEqualTo: 0, max: 1)
            let y = try finiteDouble(object, "y", greaterThanOrEqualTo: 0, max: 1)
            let t = keys.contains("t") ? try finiteDouble(object, "t", greaterThanOrEqualTo: 0, max: Double.greatestFiniteMagnitude) : nil
            return .touch(phase: phase, x: x, y: y, t: t)
        case "scroll":
            guard Set(object.keys) == ["type", "dx", "dy"] else { throw ParseError.keySet }
            return .scroll(dx: try finiteDouble(object, "dx"), dy: try finiteDouble(object, "dy"))
        case "kf":
            guard Set(object.keys) == ["type"] else { throw ParseError.keySet }
            return .keyframe
        case "server-hello":
            return .serverHello(try parseServerHello(data, transport: transport))
        case "session-accept":
            return .sessionAccept(try parseSessionAccept(data))
        case "session-busy":
            return .sessionBusy(try parseSessionBusy(data))
        default:
            throw ParseError.value
        }
    }


    private static func strictObject(_ data: Data, keys: Set<String>) throws -> [String: Any] {
        let object = try strictAnyObject(data)
        guard Set(object.keys) == keys else { throw ParseError.keySet }
        return object
    }

    private static func strictObject(_ data: Data, allowedKeys: Set<String>) throws -> [String: Any] {
        let object = try strictAnyObject(data)
        guard Set(object.keys).isSubset(of: allowedKeys) else { throw ParseError.keySet }
        return object
    }

    private static func strictAnyObject(_ data: Data) throws -> [String: Any] {
        try rejectDuplicateTopLevelKeys(data)
        let json = try JSONSerialization.jsonObject(with: data)
        guard let object = json as? [String: Any] else { throw ParseError.invalidJSON }
        return object
    }

    private static func rejectDuplicateTopLevelKeys(_ data: Data) throws {
        guard let s = String(data: data, encoding: .utf8) else { throw ParseError.invalidJSON }
        var i = s.startIndex
        func skipWS() { while i < s.endIndex, s[i].isWhitespace { i = s.index(after: i) } }
        func parseString() throws -> String {
            guard i < s.endIndex, s[i] == "\"" else { throw ParseError.invalidJSON }
            i = s.index(after: i); var out = ""
            while i < s.endIndex {
                let c = s[i]; i = s.index(after: i)
                if c == "\"" { return out }
                if c == "\\" {
                    guard i < s.endIndex else { throw ParseError.invalidJSON }
                    let esc = s[i]; i = s.index(after: i)
                    switch esc {
                    case "\"", "\\", "/": out.append(esc)
                    case "b": out.append("\u{08}")
                    case "f": out.append("\u{0c}")
                    case "n": out.append("\n")
                    case "r": out.append("\r")
                    case "t": out.append("\t")
                    case "u":
                        var hex = ""
                        for _ in 0..<4 {
                            guard i < s.endIndex else { throw ParseError.invalidJSON }
                            hex.append(s[i]); i = s.index(after: i)
                        }
                        guard let scalar = UInt32(hex, radix: 16),
                              let unicode = UnicodeScalar(scalar) else { throw ParseError.invalidJSON }
                        out.unicodeScalars.append(unicode)
                    default:
                        throw ParseError.invalidJSON
                    }
                } else { out.append(c) }
            }
            throw ParseError.invalidJSON
        }
        skipWS(); guard i < s.endIndex, s[i] == "{" else { throw ParseError.invalidJSON }
        i = s.index(after: i); var seen = Set<String>()
        while true {
            skipWS(); guard i < s.endIndex else { throw ParseError.invalidJSON }
            if s[i] == "}" { return }
            let key = try parseString()
            guard seen.insert(key).inserted else { throw ParseError.duplicateKey }
            skipWS(); guard i < s.endIndex, s[i] == ":" else { throw ParseError.invalidJSON }
            i = s.index(after: i)
            var depth = 0; var inString = false; var escape = false
            while i < s.endIndex {
                let c = s[i]
                if inString {
                    if escape { escape = false }
                    else if c == "\\" { escape = true }
                    else if c == "\"" { inString = false }
                } else if c == "\"" { inString = true }
                else if c == "{" || c == "[" { depth += 1 }
                else if c == "}" || c == "]" { if depth == 0 { break }; depth -= 1 }
                else if c == "," && depth == 0 { break }
                i = s.index(after: i)
            }
            skipWS(); if i < s.endIndex, s[i] == "," { i = s.index(after: i); continue }
            skipWS(); if i < s.endIndex, s[i] == "}" { return }
            throw ParseError.invalidJSON
        }
    }

    private static func string(_ object: [String: Any], _ key: String) throws -> String {
        guard let value = object[key] as? String else { throw ParseError.type }
        return value
    }
    private static func int(_ object: [String: Any], _ key: String) throws -> Int? {
        guard let value = object[key] as? Int else { throw ParseError.type }
        return value
    }
    private static func uint64(_ object: [String: Any], _ key: String) throws -> UInt64 {
        guard let n = object[key] as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else {
            throw ParseError.type
        }
        let text = NSDecimalNumber(decimal: n.decimalValue).stringValue
        guard !text.contains("."), !text.contains("e"), !text.contains("E") else {
            throw ParseError.value
        }
        let trimmed = text.drop(while: { $0 == "0" })
        let digits = trimmed.isEmpty ? "0" : String(trimmed)
        let max = String(UInt64.max)
        guard digits.count < max.count || (digits.count == max.count && digits <= max),
              let value = UInt64(digits) else {
            throw ParseError.value
        }
        return value
    }
    private static func base64(_ value: String, bytes: Int) throws -> Data {
        guard !value.contains(where: { $0.isWhitespace }), let data = Data(base64Encoded: value), data.count == bytes, data.base64EncodedString() == value else { throw ParseError.value }
        return data
    }
    private static func boundedString(_ object: [String: Any], _ key: String, _ min: Int, _ max: Int) throws {
        let value = try string(object, key); guard (min...max).contains(value.count) else { throw ParseError.value }
    }
    private static func rangedInt(_ object: [String: Any], _ key: String, _ min: Int, _ max: Int) throws -> Int {
        guard let value = object[key] as? Int, (min...max).contains(value) else { throw ParseError.value }
        return value
    }
    private static func finiteDouble(_ object: [String: Any], _ key: String) throws -> Double {
        if let value = object[key] as? Double, value.isFinite { return value }
        if let value = object[key] as? Int { return Double(value) }
        throw ParseError.value
    }
    private static func finiteDouble(_ object: [String: Any], _ key: String, greaterThan min: Double, max: Double) throws -> Double {
        let value = try finiteDouble(object, key)
        guard value > min, value <= max else { throw ParseError.value }
        return value
    }
    private static func finiteDouble(_ object: [String: Any], _ key: String, greaterThanOrEqualTo min: Double, max: Double) throws -> Double {
        let value = try finiteDouble(object, key)
        guard value >= min, value <= max else { throw ParseError.value }
        return value
    }
}
