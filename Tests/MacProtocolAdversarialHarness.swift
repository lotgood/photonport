import Foundation
import CryptoKit

private func json(_ text: String) -> Data { Data(text.utf8) }
private func b64(_ byte: UInt8, _ count: Int) -> String { Data(repeating: byte, count: count).base64EncodedString() }
private func expectAccepts(_ label: String, _ body: () throws -> Void) {
    do { try body() } catch { preconditionFailure("\(label) unexpectedly rejected: \(error)") }
}

private func expectRejects(_ label: String, _ body: () throws -> Void) {
    do {
        try body()
        preconditionFailure("\(label) unexpectedly accepted")
    } catch {}
}

private func quoted(_ value: String) -> String { "\"\(value)\"" }


private func replacing(_ data: Data, _ old: String, _ new: String) -> Data {
    json(String(data: data, encoding: .utf8)!.replacingOccurrences(of: old, with: new))
}

private func withoutField(_ data: Data, _ key: String) -> Data {
    var text = String(data: data, encoding: .utf8)!
    text = text.replacingOccurrences(of: ",\"\(key)\":", with: ",\"__drop__\":")
    text = text.replacingOccurrences(of: "\"\(key)\":", with: "\"__drop__\":")
    let marker = "\"__drop__\":"
    guard let start = text.range(of: marker)?.lowerBound else { return data }
    var index = text.index(start, offsetBy: marker.count)
    var depth = 0
    var inString = false
    var escape = false
    while index < text.endIndex {
        let c = text[index]
        if inString {
            if escape { escape = false }
            else if c == "\\" { escape = true }
            else if c == "\"" { inString = false }
        } else if c == "\"" { inString = true }
        else if c == "{" || c == "[" { depth += 1 }
        else if c == "}" || c == "]" {
            if depth == 0 { break }
            depth -= 1
        } else if c == "," && depth == 0 {
            index = text.index(after: index)
            break
        }
        index = text.index(after: index)
    }
    var out = text
    out.removeSubrange(start..<index)
    out = out.replacingOccurrences(of: "{,", with: "{").replacingOccurrences(of: ",}", with: "}")
    return json(out)
}
private func withFieldValue(_ data: Data, _ key: String, _ value: String) -> Data {
    var text = String(data: data, encoding: .utf8)!
    let marker = "\"\(key)\":"
    guard let valueStart = text.range(of: marker)?.upperBound else { return data }
    var index = valueStart
    var depth = 0
    var inString = false
    var escape = false
    while index < text.endIndex {
        let c = text[index]
        if inString {
            if escape { escape = false }
            else if c == "\\" { escape = true }
            else if c == "\"" { inString = false }
        } else if c == "\"" { inString = true }
        else if c == "{" || c == "[" { depth += 1 }
        else if c == "}" || c == "]" {
            if depth == 0 { break }
            depth -= 1
        } else if c == "," && depth == 0 {
            break
        }
        index = text.index(after: index)
    }
    text.replaceSubrange(valueStart..<index, with: value)
    return json(text)
}


fileprivate struct ParserCase {
    let name: String
    let valid: Data
    let requiredKeys: [String]
    let typeKey: String
    let typeValue: String
    let wrongTypeField: String
    let wrongTypeValue: String
    let parse: (Data) throws -> Void
}

@main
struct MacProtocolAdversarialHarness {
    static func main() {
        framingCaps()
        strictJSON()
        canonicalFields()
        transportRules()
        rawTokenStrictness()
        parserEntryPointShapeMutations()
        base64BoundaryMutations()
        inboundAndParserOnlyCapBoundaries()
        strictControls()
        scrollAdmissionAndBackpressure()
        scrollTimerAndConversionBehavior()
        sessionProofsAndOwnership()
        generationSnapshots()
        proofMutations()
        generationExhaustedPersistence()
        print("mac protocol adversarial harness passed")
    }

    static func framingCaps() {
        for (kind, cap) in [(ProtocolParser.FrameKind.pairing, 65_535), (.session, 65_535), (.audioControl, 65_535), (.audioData, 262_144), (.videoData, 16_777_216)] {
            for length in [0, cap + 1] {
                var n = UInt32(length).bigEndian
                precondition((try? ProtocolParser.framedPayloadLength(from: Data(bytes: &n, count: 4), kind: kind)) == nil)
            }
            var n = UInt32(cap).bigEndian
            precondition((try? ProtocolParser.framedPayloadLength(from: Data(bytes: &n, count: 4), kind: kind)) == cap)
            precondition((try? ProtocolParser.validatePayload(Data(repeating: 0, count: cap - 1), expectedLength: cap, kind: kind)) == nil)
        }
    }

    static func expectFrameLength(_ kind: ProtocolParser.FrameKind, _ length: Int, _ accepted: Bool, _ label: String) {
        var n = UInt32(length).bigEndian
        if accepted {
            expectAccepts(label) { _ = try ProtocolParser.framedPayloadLength(from: Data(bytes: &n, count: 4), kind: kind) }
        } else {
            expectRejects(label) { _ = try ProtocolParser.framedPayloadLength(from: Data(bytes: &n, count: 4), kind: kind) }
        }
    }

    static func strictJSON() {
        let good = json("{\"type\":\"session-busy\",\"v\":3,\"reason\":\"session_busy\"}")
        precondition((try? ProtocolParser.parseSessionBusy(good)) != nil)
        precondition((try? ProtocolParser.parseSessionBusy(json("{\"type\":\"session-busy\",\"type\":\"session-busy\",\"v\":3,\"reason\":\"session_busy\"}"))) == nil)
        precondition((try? ProtocolParser.parseSessionBusy(json("{\"type\":\"session-busy\",\"ty\\u0070e\":\"session-busy\",\"v\":3,\"reason\":\"session_busy\"}"))) == nil)
        precondition((try? ProtocolParser.parseSessionBusy(json("{\"type\":\"session-busy\",\"v\":3}"))) == nil)
        precondition((try? ProtocolParser.parseSessionBusy(json("{\"type\":\"session-busy\",\"v\":3,\"reason\":\"session_busy\",\"x\":1}"))) == nil)
        precondition((try? ProtocolParser.parseSessionBusy(json("{\"type\":\"session-busy\",\"v\":3,\"reason\":\"not_busy\"}"))) == nil)
        precondition((try? ProtocolParser.parsePairCommit(json("{\"type\":\"pair-commit\",\"v\":2,\"commit\":\"\(b64(0x11, 32))\"}"))) != nil)
    }

    static func canonicalFields() {
        let accept = json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(b64(0x51, 16))\",\"generation\":1,\"acceptProof\":\"\(b64(0x52, 32))\"}")
        precondition((try? ProtocolParser.parseSessionAccept(accept)) != nil)
        let canonicalSessionID = b64(0x51, 16)
        let noncanonicalAlias = String(canonicalSessionID.dropLast(3)) + "R=="
        precondition(Data(base64Encoded: canonicalSessionID) == Data(base64Encoded: noncanonicalAlias))
        precondition((try? ProtocolParser.parseSessionAccept(json(String(data: accept, encoding: .utf8)!.replacingOccurrences(of: canonicalSessionID, with: noncanonicalAlias)))) == nil)
        precondition((try? ProtocolParser.parseSessionAccept(json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(b64(0x51, 15))\",\"generation\":1,\"acceptProof\":\"\(b64(0x52, 32))\"}"))) == nil)
        precondition((try? ProtocolParser.parseSessionAccept(json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(b64(0x51, 16))\",\"generation\":0,\"acceptProof\":\"\(b64(0x52, 32))\"}"))) == nil)
        precondition((try? ProtocolParser.parseSessionAccept(json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(b64(0x51, 16))\",\"generation\":1.5,\"acceptProof\":\"\(b64(0x52, 32))\"}"))) == nil)
        precondition((try? ProtocolParser.parseSessionAccept(json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(b64(0x51, 16))\",\"generation\":18446744073709551616,\"acceptProof\":\"\(b64(0x52, 32))\"}"))) == nil)
        let channel = json("{\"type\":\"channel-open\",\"v\":3,\"macInstallID\":\"mac\",\"sessionID\":\"\(b64(0x51, 16))\",\"generation\":1,\"channel\":\"audio\",\"nonce\":\"\(b64(0x61, 32))\",\"proof\":\"\(b64(0x62, 32))\"}")
        precondition((try? ProtocolParser.parseChannelOpen(channel)) != nil)
        precondition((try? ProtocolParser.parseChannelOpen(json(String(data: channel, encoding: .utf8)!.replacingOccurrences(of: "audio", with: "video")))) == nil)
    }

    static func rawTokenStrictness() {
        let sid = b64(0x51, 16), proof = b64(0x52, 32), nonce = b64(0x61, 32)
        let cases: [(String, (String) -> Data, (Data) throws -> Void)] = [
            ("pair-commit v", { json("{\"type\":\"pair-commit\",\"v\":\($0),\"commit\":\"\(b64(0x11, 32))\"}") }, { _ = try ProtocolParser.parsePairCommit($0) }),
            ("pair-hello v", { json("{\"type\":\"pair-hello\",\"v\":\($0),\"role\":\"device\",\"installID\":\"dev\",\"pub\":\"\(b64(0x21, 32))\",\"nonce\":\"\(b64(0x22, 16))\"}") }, { _ = try ProtocolParser.parsePairHello($0, role: "device") }),
            ("server-hello sessionVersion", { json("{\"type\":\"server-hello\",\"sessionVersion\":\($0),\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("server-hello pixelsWide", { json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":\($0),\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("server-hello pixelsHigh", { json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":\($0),\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("server-hello maxFps", { json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":\($0),\"hdr\":true}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("session-accept v", { json("{\"type\":\"session-accept\",\"v\":\($0),\"sessionID\":\"\(sid)\",\"generation\":1,\"acceptProof\":\"\(proof)\"}") }, { _ = try ProtocolParser.parseSessionAccept($0) }),
            ("session-accept generation", { json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(sid)\",\"generation\":\($0),\"acceptProof\":\"\(proof)\"}") }, { _ = try ProtocolParser.parseSessionAccept($0) }),
            ("session-busy v", { json("{\"type\":\"session-busy\",\"v\":\($0),\"reason\":\"session_busy\"}") }, { _ = try ProtocolParser.parseSessionBusy($0) }),
            ("channel-open v", { json("{\"type\":\"channel-open\",\"v\":\($0),\"macInstallID\":\"mac\",\"sessionID\":\"\(sid)\",\"generation\":1,\"channel\":\"audio\",\"nonce\":\"\(nonce)\",\"proof\":\"\(proof)\"}") }, { _ = try ProtocolParser.parseChannelOpen($0) }),
            ("channel-open generation", { json("{\"type\":\"channel-open\",\"v\":3,\"macInstallID\":\"mac\",\"sessionID\":\"\(sid)\",\"generation\":\($0),\"channel\":\"audio\",\"nonce\":\"\(nonce)\",\"proof\":\"\(proof)\"}") }, { _ = try ProtocolParser.parseChannelOpen($0) }),
            ("generation snapshot", { json("{\"generation\":\($0),\"generationExhausted\":false}") }, { _ = try ProtocolParser.parseGenerationSnapshot($0) }),
            ("ping id", { json("{\"type\":\"ping\",\"id\":\($0),\"t\":1.0}") }, { _ = try ProtocolParser.parseControl($0, transport: .wifi) }),
            ("stats dropped", { json("{\"type\":\"stats\",\"fps\":60,\"bitrate\":12,\"dropped\":\($0)}") }, { _ = try ProtocolParser.parseControl($0, transport: .wifi) })
        ]
        for raw in ["1.0", "1e0", "\(Double(UInt64.max))", "true", "\"1\"", "-1", "18446744073709551616"] {
            for (name, make, parse) in cases {
                expectRejects("\(name) raw token \(raw)") { try parse(make(raw)) }
            }
        }
    }

    fileprivate static func parserCases() -> [ParserCase] {
        let sid = b64(0x51, 16), proof = b64(0x52, 32), nonce = b64(0x61, 32)
        return [
            ParserCase(name: "pair-commit", valid: json("{\"type\":\"pair-commit\",\"v\":2,\"commit\":\"\(b64(0x11, 32))\"}"), requiredKeys: ["type", "v", "commit"], typeKey: "type", typeValue: "pair-commit", wrongTypeField: "commit", wrongTypeValue: "1") { _ = try ProtocolParser.parsePairCommit($0) },
            ParserCase(name: "pair-hello", valid: json("{\"type\":\"pair-hello\",\"v\":2,\"role\":\"device\",\"installID\":\"dev\",\"pub\":\"\(b64(0x21, 32))\",\"nonce\":\"\(b64(0x22, 16))\"}"), requiredKeys: ["type", "v", "role", "installID", "pub", "nonce"], typeKey: "type", typeValue: "pair-hello", wrongTypeField: "pub", wrongTypeValue: "1") { _ = try ProtocolParser.parsePairHello($0, role: "device") },
            ParserCase(name: "server-hello", valid: json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true}"), requiredKeys: ["type", "sessionVersion", "deviceNonce", "pixelsWide", "pixelsHigh", "scale", "device", "id", "maxFps", "hdr"], typeKey: "type", typeValue: "server-hello", wrongTypeField: "hdr", wrongTypeValue: "\"true\"") { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) },
            ParserCase(name: "session-accept", valid: json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(sid)\",\"generation\":1,\"acceptProof\":\"\(proof)\"}"), requiredKeys: ["type", "v", "sessionID", "generation", "acceptProof"], typeKey: "type", typeValue: "session-accept", wrongTypeField: "sessionID", wrongTypeValue: "1") { _ = try ProtocolParser.parseSessionAccept($0) },
            ParserCase(name: "session-busy", valid: json("{\"type\":\"session-busy\",\"v\":3,\"reason\":\"session_busy\"}"), requiredKeys: ["type", "v", "reason"], typeKey: "type", typeValue: "session-busy", wrongTypeField: "reason", wrongTypeValue: "1") { _ = try ProtocolParser.parseSessionBusy($0) },
            ParserCase(name: "channel-open", valid: json("{\"type\":\"channel-open\",\"v\":3,\"macInstallID\":\"mac\",\"sessionID\":\"\(sid)\",\"generation\":1,\"channel\":\"audio\",\"nonce\":\"\(nonce)\",\"proof\":\"\(proof)\"}"), requiredKeys: ["type", "v", "macInstallID", "sessionID", "generation", "channel", "nonce", "proof"], typeKey: "type", typeValue: "channel-open", wrongTypeField: "nonce", wrongTypeValue: "1") { _ = try ProtocolParser.parseChannelOpen($0) },
            ParserCase(name: "control-ping", valid: json("{\"type\":\"ping\",\"id\":1,\"t\":1.0}"), requiredKeys: ["type", "id", "t"], typeKey: "type", typeValue: "ping", wrongTypeField: "id", wrongTypeValue: "\"1\"") { _ = try ProtocolParser.parseControl($0, transport: .wifi) },
            ParserCase(name: "generation-snapshot", valid: json("{\"generation\":1,\"generationExhausted\":false}"), requiredKeys: ["generation", "generationExhausted"], typeKey: "generationExhausted", typeValue: "false", wrongTypeField: "generationExhausted", wrongTypeValue: "\"false\"") { _ = try ProtocolParser.parseGenerationSnapshot($0) }
        ]
    }

    static func parserEntryPointShapeMutations() {
        for c in parserCases() {
            expectAccepts("\(c.name) baseline") { try c.parse(c.valid) }
            for key in c.requiredKeys {
                expectRejects("\(c.name) missing \(key)") { try c.parse(withoutField(c.valid, key)) }
            }
            expectRejects("\(c.name) extra field") { try c.parse(replacing(c.valid, "{", "{\"extra\":1,")) }
            expectRejects("\(c.name) wrong type") { try c.parse(withFieldValue(c.valid, c.wrongTypeField, c.wrongTypeValue)) }
            let text = String(data: c.valid, encoding: .utf8)!
            let duplicateFirst = text.replacingOccurrences(of: "\"\(c.typeKey)\":\(c.typeValue == "false" ? "false" : quoted(c.typeValue))", with: "\"\(c.typeKey)\":\"wrong\",\"\(c.typeKey)\":\(c.typeValue == "false" ? "false" : quoted(c.typeValue))")
            let duplicateLast = text.replacingOccurrences(of: "\"\(c.typeKey)\":\(c.typeValue == "false" ? "false" : quoted(c.typeValue))", with: "\"\(c.typeKey)\":\(c.typeValue == "false" ? "false" : quoted(c.typeValue)),\"\(c.typeKey)\":\"wrong\"")
            expectRejects("\(c.name) duplicate first") { try c.parse(json(duplicateFirst)) }
            expectRejects("\(c.name) duplicate last") { try c.parse(json(duplicateLast)) }
        }
    }

    static func base64BoundaryMutations() {
        let fields: [(String, Int, (String) -> Data, (Data) throws -> Void)] = [
            ("pair commit", 32, { json("{\"type\":\"pair-commit\",\"v\":2,\"commit\":\"\($0)\"}") }, { _ = try ProtocolParser.parsePairCommit($0) }),
            ("pair hello pub", 32, { json("{\"type\":\"pair-hello\",\"v\":2,\"role\":\"device\",\"installID\":\"dev\",\"pub\":\"\($0)\",\"nonce\":\"\(b64(0x22, 16))\"}") }, { _ = try ProtocolParser.parsePairHello($0, role: "device") }),
            ("pair hello nonce", 16, { json("{\"type\":\"pair-hello\",\"v\":2,\"role\":\"device\",\"installID\":\"dev\",\"pub\":\"\(b64(0x21, 32))\",\"nonce\":\"\($0)\"}") }, { _ = try ProtocolParser.parsePairHello($0, role: "device") }),
            ("server deviceNonce", 32, { json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"deviceNonce\":\"\($0)\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("server usbSessionSeed", 32, { json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true,\"usbSessionSeed\":\"\($0)\"}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .usb) }),
            ("session ID", 16, { json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\($0)\",\"generation\":1,\"acceptProof\":\"\(b64(0x52, 32))\"}") }, { _ = try ProtocolParser.parseSessionAccept($0) }),
            ("accept proof", 32, { json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(b64(0x51, 16))\",\"generation\":1,\"acceptProof\":\"\($0)\"}") }, { _ = try ProtocolParser.parseSessionAccept($0) }),
            ("channel nonce", 32, { json("{\"type\":\"channel-open\",\"v\":3,\"macInstallID\":\"mac\",\"sessionID\":\"\(b64(0x51, 16))\",\"generation\":1,\"channel\":\"audio\",\"nonce\":\"\($0)\",\"proof\":\"\(b64(0x62, 32))\"}") }, { _ = try ProtocolParser.parseChannelOpen($0) }),
            ("channel proof", 32, { json("{\"type\":\"channel-open\",\"v\":3,\"macInstallID\":\"mac\",\"sessionID\":\"\(b64(0x51, 16))\",\"generation\":1,\"channel\":\"audio\",\"nonce\":\"\(b64(0x61, 32))\",\"proof\":\"\($0)\"}") }, { _ = try ProtocolParser.parseChannelOpen($0) })
        ]
        for (name, count, make, parse) in fields {
            let canonical = b64(0x41, count)
            expectAccepts("\(name) canonical") { try parse(make(canonical)) }
            for bad in [b64(0x41, count - 1), b64(0x41, count + 1), canonical + " ", canonical.replacingOccurrences(of: "=", with: ""), String(canonical.dropLast()) + "!", String(canonical.dropLast(3)) + "R=="] {
                expectRejects("\(name) bad base64 \(bad)") { try parse(make(bad)) }
            }
        }
    }

    static func inboundAndParserOnlyCapBoundaries() {
        for (name, kind, cap) in [
            ("production inbound pairing", ProtocolParser.FrameKind.pairing, 65_535),
            ("production inbound session", .session, 65_535),
            ("production inbound audioControl", .audioControl, 65_535),
            ("parser-only audioData outbound boundary", .audioData, 262_144),
            ("parser-only videoData outbound boundary", .videoData, 16_777_216)
        ] {
            expectFrameLength(kind, 0, false, "\(name) rejects zero")
            expectFrameLength(kind, cap - 1, true, "\(name) accepts cap-1")
            expectFrameLength(kind, cap, true, "\(name) accepts exact cap")
            expectFrameLength(kind, cap + 1, false, "\(name) rejects cap+1")
        }
    }

    static func transportRules() {
        let common = "\"type\":\"server-hello\",\"sessionVersion\":3,\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true"
        let wifi = json("{\(common)}")
        let usb = json("{\(common),\"usbSessionSeed\":\"\(b64(0x43, 32))\"}")
        precondition((try? ProtocolParser.parseServerHello(wifi, transport: .wifi)) != nil)
        precondition((try? ProtocolParser.parseServerHello(usb, transport: .usb)) != nil)
        precondition((try? ProtocolParser.parseServerHello(usb, transport: .wifi)) == nil)
        precondition((try? ProtocolParser.parseServerHello(wifi, transport: .usb)) == nil)
        let nonfinite = common.replacingOccurrences(of: "2.0", with: "1e999")
        precondition((try? ProtocolParser.parseServerHello(json("{\(nonfinite)}"), transport: .wifi)) == nil)
    }

    static func strictControls() {
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"ping\",\"id\":18446744073709551615,\"t\":1.25}"), transport: .wifi)) != nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"ping\",\"t\":1.25}"), transport: .wifi)) == nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"ping\",\"id\":\"p1\",\"t\":1.25}"), transport: .wifi)) == nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"stats\",\"fps\":60.0,\"bitrate\":12.5,\"dropped\":0}"), transport: .wifi)) != nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"touch\",\"phase\":\"began\",\"x\":0.5,\"y\":1.0,\"t\":0}"), transport: .wifi)) != nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"touch\",\"phase\":\"began\",\"x\":1.5,\"y\":0}"), transport: .wifi)) == nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"touch\",\"phase\":\"invalid\",\"x\":0.5,\"y\":0}"), transport: .wifi)) == nil)
        let cap = 120.0
        for value in [cap - 1, cap] {
            precondition((try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":\(value),\"dy\":\(-value)}"), transport: .wifi)) != nil)
        }
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":\(cap + 1),\"dy\":0}"), transport: .wifi)) == nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":0,\"dy\":\(-(cap + 1))}"), transport: .wifi)) == nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":1e999,\"dy\":0}"), transport: .wifi)) == nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":0,\"dy\":-1e999}"), transport: .wifi)) == nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"kf\"}"), transport: .wifi)) != nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"hello\"}"), transport: .wifi)) == nil)
    }

    static func scrollAdmissionAndBackpressure() {
        let cap = ScrollInputPolicy.messageDeltaLimit
        precondition(cap == 120)
        precondition(ScrollInputPolicy.injectedDeltaLimit == 120)

        for value in [-(cap + 1), -cap, -(cap - 1), cap - 1, cap, cap + 1] {
            let accepted = abs(value) <= cap
            let parsedX = (try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":\(value),\"dy\":0}"), transport: .wifi)) != nil
            let parsedY = (try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":0,\"dy\":\(value)}"), transport: .wifi)) != nil
            precondition(parsedX == accepted)
            precondition(parsedY == accepted)
        }

        let single = ScrollEventCoalescer()
        precondition(single.pendingWorkCount == 0)
        precondition(single.enqueue(dx: cap, dy: -cap))
        precondition(single.pendingWorkCount == 1)
        precondition(single.takePending() == ScrollDelta(dx: cap, dy: -cap))
        precondition(single.pendingWorkCount == 0)
        precondition(single.takePending() == nil)

        let pendingPreserved = ScrollEventCoalescer()
        precondition(pendingPreserved.enqueue(dx: cap - 1, dy: -(cap - 1)))
        precondition(!pendingPreserved.enqueue(dx: cap + 1, dy: 0))
        precondition(!pendingPreserved.enqueue(dx: 0, dy: -(cap + 1)))
        precondition(!pendingPreserved.enqueue(dx: .infinity, dy: 0))
        precondition(!pendingPreserved.enqueue(dx: 0, dy: .nan))
        precondition(pendingPreserved.pendingWorkCount == 1)
        precondition(pendingPreserved.takePending() == ScrollDelta(dx: cap - 1, dy: -(cap - 1)))

        let burst = ScrollEventCoalescer()
        for _ in 0..<10_000 {
            precondition(burst.enqueue(dx: cap, dy: -cap))
        }
        precondition(burst.pendingWorkCount == 1)
        precondition(burst.takePending() == ScrollDelta(dx: cap, dy: -cap))
        precondition(burst.pendingWorkCount == 0)

        let cancelled = ScrollEventCoalescer()
        for index in 0..<10_000 {
            let sign = index.isMultiple(of: 2) ? 1.0 : -1.0
            precondition(cancelled.enqueue(dx: sign * cap, dy: -sign * cap))
        }
        precondition(cancelled.pendingWorkCount == 1)
        precondition(cancelled.takePending() == ScrollDelta(dx: 0, dy: 0))

        let saturated = ScrollEventCoalescer()
        precondition(saturated.enqueue(dx: cap, dy: cap))
        precondition(saturated.enqueue(dx: cap, dy: cap))
        precondition(saturated.takePending() == ScrollDelta(dx: cap, dy: cap))
        precondition(saturated.pendingWorkCount == 0)
    }

    static func scrollTimerAndConversionBehavior() {
        let cap = ScrollInputPolicy.injectedDeltaLimit
        var callbacks: [ScrollDelta] = []
        let lock = NSLock()
        let callbackSignal = DispatchSemaphore(value: 0)
        let coalescer = ScrollEventCoalescer { delta in
            lock.lock()
            callbacks.append(delta)
            lock.unlock()
            callbackSignal.signal()
        }

        precondition(coalescer.enqueue(dx: 1, dy: 1))
        precondition(callbackSignal.wait(timeout: .now() + 1) == .success)
        lock.lock()
        let firstCallbacks = callbacks
        callbacks.removeAll()
        lock.unlock()
        precondition(firstCallbacks.count == 1)
        precondition(firstCallbacks[0] == ScrollDelta(dx: 1, dy: 1))
        precondition(coalescer.pendingWorkCount == 0)

        precondition(coalescer.enqueue(dx: cap, dy: cap))
        precondition(coalescer.enqueue(dx: cap, dy: cap))
        precondition(callbackSignal.wait(timeout: .now() + 1) == .success)
        lock.lock()
        let saturatedCallbacks = callbacks
        callbacks.removeAll()
        lock.unlock()
        precondition(saturatedCallbacks.count == 1)
        precondition(abs(saturatedCallbacks[0].dx) <= cap && abs(saturatedCallbacks[0].dy) <= cap)

        Thread.sleep(forTimeInterval: ScrollInputPolicy.injectionInterval * 2)
        lock.lock()
        let idleCount = callbacks.count
        lock.unlock()
        precondition(idleCount == 0)

        lock.lock()
        callbacks.removeAll()
        lock.unlock()
        let rateStart = Date()
        while Date().timeIntervalSince(rateStart) < 0.06 {
            precondition(coalescer.enqueue(dx: cap, dy: 0))
            Thread.sleep(forTimeInterval: ScrollInputPolicy.injectionInterval / 10)
        }
        Thread.sleep(forTimeInterval: ScrollInputPolicy.injectionInterval * 2)
        let observed = Date().timeIntervalSince(rateStart)
        lock.lock()
        let rateCallbacks = callbacks
        callbacks.removeAll()
        lock.unlock()
        let permittedCallbacks = Int((observed / ScrollInputPolicy.injectionInterval).rounded(.up)) + 1
        precondition(rateCallbacks.count <= permittedCallbacks)
        precondition(!rateCallbacks.isEmpty)
        for delta in rateCallbacks {
            precondition(abs(delta.dx) <= cap && abs(delta.dy) <= cap)
        }

        let stress = ScrollEventCoalescer()
        let group = DispatchGroup()
        for worker in 0..<8 {
            group.enter()
            DispatchQueue.global().async {
                for index in 0..<1_250 {
                    let sign = (worker + index).isMultiple(of: 2) ? 1.0 : -1.0
                    precondition(stress.enqueue(dx: sign, dy: -sign))
                    _ = stress.takePending()
                    precondition(stress.enqueue(dx: sign, dy: sign))
                }
                group.leave()
            }
        }
        precondition(group.wait(timeout: .now() + 5) == .success)
        precondition(stress.pendingWorkCount == 0 || stress.pendingWorkCount == 1)
        if let pending = stress.takePending() {
            precondition(abs(pending.dx) <= cap && abs(pending.dy) <= cap)
        }

        for badScale in [0.0, -1.0, Double.nan, Double.infinity, -Double.infinity] {
            precondition(ScrollWheelConversion.nativeWheelDelta(dx: 1, dy: 1, displayScale: badScale) == nil)
        }
        precondition(ScrollWheelConversion.nativeWheelDelta(dx: .nan, dy: 1, displayScale: 2) == nil)
        precondition(ScrollWheelConversion.nativeWheelDelta(dx: 1, dy: .infinity, displayScale: 2) == nil)
        precondition(ScrollWheelConversion.nativeWheelDelta(dx: 1, dy: -1, displayScale: 0.01) == NativeScrollWheelDelta(dx: 100, dy: -100))
        precondition(ScrollWheelConversion.nativeWheelDelta(dx: 2.5, dy: -2.5, displayScale: 2) == NativeScrollWheelDelta(dx: 1, dy: -1))
        precondition(ScrollWheelConversion.nativeWheelDelta(dx: 3.0, dy: -3.0, displayScale: 2) == NativeScrollWheelDelta(dx: 2, dy: -2))
        precondition(ScrollWheelConversion.nativeWheelDelta(dx: 10_000, dy: -10_000, displayScale: 0.001) == NativeScrollWheelDelta(dx: 120, dy: -120))

        var teardownCallbacks = 0
        let teardownLock = NSLock()
        do {
            let owner = ScrollEventCoalescer { _ in
                teardownLock.lock()
                teardownCallbacks += 1
                teardownLock.unlock()
            }
            precondition(owner.enqueue(dx: 1, dy: 1))
        }
        Thread.sleep(forTimeInterval: ScrollInputPolicy.injectionInterval * 2)
        teardownLock.lock()
        let callbacksAfterTeardown = teardownCallbacks
        teardownLock.unlock()
        precondition(callbacksAfterTeardown == 0)
    }

    static func proofMutations() {
        let key = SymmetricKey(data: Data(repeating: 0x31, count: 32))
        let macID = "mac-a", deviceID = "device-a"
        let macNonce = Data(repeating: 0x41, count: 32), deviceNonce = Data(repeating: 0x42, count: 32)
        let sid = Data(repeating: 0x51, count: 16)
        let secret = SessionCrypto.channelSecret(primaryKey: key, sessionID: sid, generation: 1)
        let proof = SessionCrypto.acceptProof(key: secret, sessionID: sid, generation: 1, macInstallID: macID, deviceInstallID: deviceID, macNonce: macNonce, deviceNonce: deviceNonce)
        let accept = json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(sid.base64EncodedString())\",\"generation\":1,\"acceptProof\":\"\(proof.base64EncodedString())\"}")
        expectRejects("mutated accept proof") {
            _ = try ProtocolParser.parseVerifiedSessionAccept(replacing(accept, proof.base64EncodedString(), b64(0x99, 32)), primaryKey: key, macInstallID: macID, deviceInstallID: deviceID, macNonce: macNonce, deviceNonce: deviceNonce)
        }
        let nonce = Data(repeating: 0x61, count: 32)
        let channelProof = SessionCrypto.channelProof(key: secret, sessionID: sid, generation: 1, channel: "audio", nonce: nonce)
        let open = json("{\"type\":\"channel-open\",\"v\":3,\"macInstallID\":\"\(macID)\",\"sessionID\":\"\(sid.base64EncodedString())\",\"generation\":1,\"channel\":\"audio\",\"nonce\":\"\(nonce.base64EncodedString())\",\"proof\":\"\(channelProof.base64EncodedString())\"}")
        let mutatedOpen = replacing(open, channelProof.base64EncodedString(), b64(0x98, 32))
        let parsedMutatedOpen = try! ProtocolParser.parseChannelOpen(mutatedOpen, channel: "audio")
        let receivedProof = Data(base64Encoded: parsedMutatedOpen.proof)!
        precondition(!SessionCrypto.constantTimeEqual(receivedProof, channelProof))
    }

    static func generationExhaustedPersistence() {
        var state = try! SessionOwnershipState.restore(snapshot: .init(generation: UInt64.max - 1, generationExhausted: false))
        guard case .accepted = state.claim(macInstallID: "mac-max") else { preconditionFailure("max generation unavailable") }
        let encoded = try! state.encodeSnapshot()
        var restarted = try! SessionOwnershipState.restore(snapshot: encoded)
        precondition(restarted.exhausted && restarted.generation == UInt64.max)
        guard case .exhausted = restarted.claim(macInstallID: "after-restart") else { preconditionFailure("exhaustion did not persist after restart") }
    }

    static func sessionProofsAndOwnership() {
        let key = SymmetricKey(data: Data(repeating: 0x31, count: 32))
        let macID = "mac-a", deviceID = "device-a"
        let macNonce = Data(repeating: 0x41, count: 32), deviceNonce = Data(repeating: 0x42, count: 32)
        let sid = Data(repeating: 0x51, count: 16)
        let secret = SessionCrypto.channelSecret(primaryKey: key, sessionID: sid, generation: 1)
        let proof = SessionCrypto.acceptProof(key: secret, sessionID: sid, generation: 1, macInstallID: macID, deviceInstallID: deviceID, macNonce: macNonce, deviceNonce: deviceNonce)
        let accept = json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(sid.base64EncodedString())\",\"generation\":1,\"acceptProof\":\"\(proof.base64EncodedString())\"}")
        precondition((try? ProtocolParser.parseVerifiedSessionAccept(accept, primaryKey: key, macInstallID: macID, deviceInstallID: deviceID, macNonce: macNonce, deviceNonce: deviceNonce)) != nil)
        precondition((try? ProtocolParser.parseVerifiedSessionAccept(accept, primaryKey: key, macInstallID: "wrong", deviceInstallID: deviceID, macNonce: macNonce, deviceNonce: deviceNonce)) == nil)
        let channel = SessionCrypto.channelProof(key: key, sessionID: sid, generation: 1, channel: "video", nonce: Data(repeating: 0x61, count: 32))
        precondition(!SessionCrypto.constantTimeEqual(channel, SessionCrypto.channelProof(key: key, sessionID: sid, generation: 1, channel: "audio", nonce: Data(repeating: 0x61, count: 32))))
        var state = SessionOwnershipState.fresh()
        precondition(state.consumeChannelNonce(macInstallID: macID, generation: 1, nonce: sid) == false)
        guard case .accepted(let lease) = state.claim(macInstallID: macID) else { preconditionFailure("initial claim rejected") }
        guard case .busy(let owner) = state.claim(macInstallID: "mac-b") else { preconditionFailure("ownership was not exclusive") }
        precondition(owner == lease && state.authorizes(macInstallID: macID, generation: lease.generation))
        precondition(state.consumeChannelNonce(macInstallID: macID, generation: lease.generation, nonce: sid))
        precondition(!state.consumeChannelNonce(macInstallID: macID, generation: lease.generation, nonce: sid))
        precondition(state.release(macInstallID: macID, generation: lease.generation))
    }

    static func generationSnapshots() {
        let near = SessionOwnershipState.Snapshot(generation: UInt64.max - 1, generationExhausted: false)
        var restored = try! SessionOwnershipState.restore(snapshot: near)
        guard case .accepted(let maxLease) = restored.claim(macInstallID: "mac-max") else { preconditionFailure("max generation unavailable") }
        precondition(maxLease.generation == UInt64.max && restored.exhausted)
        let data = try! restored.encodeSnapshot()
        let restarted = try! SessionOwnershipState.restore(snapshot: data)
        precondition(restarted.exhausted && restarted.generation == UInt64.max)
        guard case .busy = restored.claim(macInstallID: "after") else { preconditionFailure("active max lease not busy") }
        precondition(restored.release(macInstallID: "mac-max", generation: UInt64.max))
        guard case .exhausted = restored.claim(macInstallID: "after") else { preconditionFailure("exhaustion not persistent") }
        precondition((try? SessionOwnershipState.restore(snapshot: .init(generation: 0, generationExhausted: false))) == nil)
        precondition((try? SessionOwnershipState.restore(snapshot: .init(generation: UInt64.max, generationExhausted: false))) == nil)
        precondition((try? SessionOwnershipState.restore(snapshot: .init(generation: 42, generationExhausted: true))) == nil)
        precondition((try? SessionOwnershipState.restore(snapshot: json("{\"generation\":42,\"generation\":43,\"generationExhausted\":false}"))) == nil)
        precondition((try? SessionOwnershipState.restore(snapshot: json("{\"generation\":42,\"generationExhausted\":false,\"extra\":1}"))) == nil)
    }
}
