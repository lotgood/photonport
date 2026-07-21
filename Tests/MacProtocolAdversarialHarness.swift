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
fileprivate struct CaseInvocation {
    let id: String
    let mutation: String
    let mutationSHA256: String
    let value: Any

    init(arguments: [String]) {
        guard arguments.count == 4, arguments[0] == "case",
              let mutationData = arguments[2].data(using: .utf8),
              arguments[3].count == 64,
              arguments[3].allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            fatalError("usage: MacProtocolAdversarialHarness case <vector-id> <canonical-mutation-json> <mutation-sha256>")
        }
        guard SHA256.hash(data: mutationData).map({ String(format: "%02x", $0) }).joined() == arguments[3],
              let object = try? JSONSerialization.jsonObject(with: mutationData) as? [String: Any],
              Set(object.keys) == ["dimension", "value"],
              let dimension = object["dimension"] as? String, !dimension.isEmpty else {
            fatalError("invalid canonical mutation binding")
        }
        id = arguments[1]
        mutation = dimension
        mutationSHA256 = arguments[3]
        value = object["value"]!
    }
}


@main
struct MacProtocolAdversarialHarness {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard arguments.isEmpty || arguments.count == 4 && arguments[0] == "case" else {
            fatalError("usage: MacProtocolAdversarialHarness [case <vector-id> <canonical-mutation-json> <mutation-sha256>]")
        }
        if !arguments.isEmpty {
            runCase(CaseInvocation(arguments: arguments))
            return
        }

        framingCaps()
        receipt("bad-length-prefix")
        receipt("oversize-frame")
        directParserEntryPointCaps()
        strictJSON()
        receipt("duplicate-json-key")
        receipt("sensitive-reason-code")
        pairingIdentityMutations()
        canonicalFields()
        receipt("zero-generation")
        receipt("wrong-channel")
        transportRules()
        receipt("wifi-hello-missing-seed")
        receipt("usb-hello-seed-present")
        receipt("server-hello-transport-mismatch")
        rawTokenStrictness()
        parserEntryPointShapeMutations()
        base64BoundaryMutations()
        receipt("invalid-base64")
        inboundAndParserOnlyCapBoundaries()
        strictControls()
        pongProductionState()
        scrollAdmissionAndBackpressure()
        scrollTimerAndConversionBehavior()
        proofMutations()
        sessionIdentityMutations()
        usbPrefaceAndRecordMutations()
        print("mac protocol adversarial harness passed")
    }

    fileprivate static func runCase(_ invocation: CaseInvocation) {
        let id = invocation.id
        let result: ProtocolRejection?
        switch id {
        case "wrong-device-nonce":
            guard let encoded = invocation.value as? String,
                  let mutatedNonce = Data(base64Encoded: encoded) else {
                fatalError("invalid device nonce mutation")
            }
            result = sessionAcceptCase(
                id,
                mutation: "deviceNonce",
                payloadMutation: { $0 },
                deviceNonceMutation: mutatedNonce
            )
        case "wifi-hello-missing-seed":
            result = serverHelloCase(id, mutation: "wifiSessionSeed",
                                     payload: withoutField(serverHello(.wifi), "wifiSessionSeed"), transport: .wifi)
        case "usb-hello-seed-present":
            result = serverHelloCase(id, mutation: "wifiSessionSeed",
                                     payload: serverHello(.usb, seed: true), transport: .usb)
        case "server-hello-transport-mismatch":
            result = serverHelloCase(id, mutation: "transport",
                                     payload: serverHello(.usb), transport: .wifi)
        case "wrong-session-id":
            result = sessionAcceptCase(id, mutation: "sessionID",
                                       payloadMutation: { replacing($0, b64(0x51, 16), b64(0x00, 16)) })
        case "zero-generation":
            result = sessionAcceptCase(id, mutation: "generation",
                                       payloadMutation: { withFieldValue($0, "generation", "0") })
        case "sensitive-reason-code":
            let valid = json("{\"type\":\"session-busy\",\"v\":3,\"reason\":\"session_busy\"}")
            precondition({
                if case .applied = ProtocolParser.consumeSessionBusy(valid) { return true }
                return false
            }())
            if case .rejected(let rejection) = ProtocolParser.consumeSessionBusy(
                withFieldValue(valid, "reason", quoted("paired_identity_secret"))
            ) {
                result = rejection
            } else {
                result = nil
            }
        case "video-keyframe-missing-h264-parameter-sets":
            result = mediaCase(id, mutation: "Annex-B", codec: "h264",
                               baseline: Data([0, 0, 0, 1, 0x67, 0, 0, 0, 1, 0x68, 0, 0, 0, 1, 0x65]),
                               mutated: Data([0, 0, 0, 1, 0x65]), keyframe: true)
        case "video-keyframe-missing-hevc-parameter-sets":
            result = mediaCase(id, mutation: "Annex-B", codec: "hevc",
                               baseline: Data([0, 0, 0, 1, 0x40, 0, 0, 0, 1, 0x42, 0, 0, 0, 1, 0x44, 0, 0, 0, 1, 0x26]),
                               mutated: Data([0, 0, 0, 1, 0x26]), keyframe: true)
        case "video-random-access-telemetry-mismatch":
            result = mediaCase(id, mutation: "keyframe", codec: "h264",
                               baseline: Data([0, 0, 0, 1, 0x67, 0, 0, 0, 1, 0x68, 0, 0, 0, 1, 0x65]),
                               mutated: Data([0, 0, 0, 1, 0x67, 0, 0, 0, 1, 0x68, 0, 0, 0, 1, 0x65]), keyframe: false)
        case "usb-challenge-reflection":
            result = usbChallengeCase(id, mutation: "type") {
                replacing($0, quoted("usb-bind-challenge"), quoted("usb-bind-init"))
            }
        case "usb-challenge-wrong-proof":
            result = usbChallengeCase(id, mutation: "proof") {
                return withFieldValue($0, "proof", quoted(Data(repeating: 0, count: 32).base64EncodedString()))
            }
        case "usb-accept-replay":
            result = usbAcceptReplayCase(id)
        case "usb-primary-audio-binding-cross-use":
            result = usbPrimaryAudioBindingCrossUseCase(id)
        default:
            fatalError("unknown or unsupported consumer case: \(id)")
        }
        guard let result else {
            fatalError("consumer did not reject the supplied mutation for \(id)")
        }
        receipt(id, mutation: invocation.mutation, rejection: result, mutationSHA256: invocation.mutationSHA256)
    }

    static func serverHello(_ transport: ProtocolParser.Transport, seed: Bool = false) -> Data {
        let transportName: String
        switch transport {
        case .wifi: transportName = "wifi"
        case .usb: transportName = "usb"
        }
        let seedField: String
        switch transport {
        case .wifi: seedField = ",\"wifiSessionSeed\":\"\(b64(0x43, 32))\""
        case .usb: seedField = seed ? ",\"wifiSessionSeed\":\"\(b64(0x43, 32))\"" : ""
        }
        return json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"transport\":\"\(transportName)\",\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true\(seedField)}")
    }

    static func serverHelloCase(_ id: String, mutation: String, payload: Data,
                                transport: ProtocolParser.Transport) -> ProtocolRejection? {
        let baseline = serverHello(transport)
        guard case .applied(let hello, _) = ProtocolParser.consumeServerHello(baseline, transport: transport),
              mutation != "deviceNonce" || hello.deviceNonce == Data(repeating: 0x42, count: 32),
              case .rejected(let rejection) = ProtocolParser.consumeServerHello(payload, transport: transport) else {
            return nil
        }
        return rejection
    }

    static func sessionAcceptCase(
        _ id: String,
        mutation: String,
        payloadMutation: (Data) -> Data,
        deviceNonceMutation: Data? = nil
    ) -> ProtocolRejection? {
        let key = SymmetricKey(data: Data(repeating: 0x31, count: 32))
        let macNonce = Data(repeating: 0x41, count: 32)
        let deviceNonce = Data(repeating: 0x42, count: 32)
        let sessionID = Data(repeating: 0x51, count: 16)
        let secret = SessionCrypto.channelSecret(primaryKey: key, sessionID: sessionID, generation: 1)
        let proof = SessionCrypto.acceptProof(key: secret, sessionID: sessionID, generation: 1,
                                              macInstallID: "mac-a", deviceInstallID: "device-a",
                                              macNonce: macNonce, deviceNonce: deviceNonce)
        let baseline = json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(sessionID.base64EncodedString())\",\"generation\":1,\"acceptProof\":\"\(proof.base64EncodedString())\"}")
        guard case .applied = ProtocolParser.consumeVerifiedSessionAccept(
            baseline, primaryKey: key, macInstallID: "mac-a", deviceInstallID: "device-a",
            macNonce: macNonce, deviceNonce: deviceNonce
        ), case .rejected(let rejection) = ProtocolParser.consumeVerifiedSessionAccept(
            payloadMutation(baseline), primaryKey: key, macInstallID: "mac-a", deviceInstallID: "device-a",
            macNonce: macNonce, deviceNonce: deviceNonceMutation ?? deviceNonce
        ) else {
            return nil
        }
        return rejection
    }

    // Mac only sends video. Receiver Annex-B admission belongs to the iOS runtime.
    static func mediaCase(_ id: String, mutation: String, codec: String, baseline: Data,
                          mutated: Data, keyframe: Bool) -> ProtocolRejection? {
        nil
    }

    static func rejection(_ outcome: ProtocolConsumerOutcome<Data>) -> ProtocolRejection? {
        guard case .rejected(let rejection) = outcome else { return nil }
        return rejection
    }

    static func usbChallengeCase(_ id: String, mutation: String,
                                 mutate: (Data) -> Data) -> ProtocolRejection? {
        let psk = Data(repeating: 0xA5, count: 32), macNonce = Data(repeating: 0x11, count: 32)
        let candidate = USBChannelCandidate(psk: psk, macInstallID: "mac", deviceInstallID: "receiver",
                                            purpose: "primary", startedAt: 0, token: 7, macNonce: macNonce)!
        let server = USBPrefaceServer(psk: psk, macInstallID: "mac", deviceInstallID: "receiver",
                                      purpose: "primary", startedAt: 0, token: 7)!
        let initial = candidate.start(now: 0, token: 7)!
        precondition(server.consumeMagic(USBPrefaceMessage.magic, now: 0, token: 7))
        let challenge = server.consume(
            USBPrefaceMessage.unframe(Data(initial.dropFirst(8)))!.0, now: 0, token: 7,
            nonce: Data(repeating: 0x22, count: 32))!
        let payload = mutate(USBPrefaceMessage.unframe(challenge)!.0)
        return rejection(candidate.receiveChallenge(payload, now: 0, token: 7))
    }
    static func usbAcceptReplayCase(_ id: String) -> ProtocolRejection? {
        usbChallengeCase(id, mutation: "state") {
            withFieldValue($0, "type", quoted("usb-bind-accept"))
        }
    }

    static func usbPrimaryAudioBindingCrossUseCase(_ id: String) -> ProtocolRejection? {
        usbChallengeCase(id, mutation: "purpose") {
            withFieldValue($0, "purpose", quoted("audio"))
        }
    }

    static func receipt(_ id: String, mutation: String, rejection: ProtocolRejection,
                        mutationSHA256: String) {
        print("VECTOR_RECEIPT consumer \(id) mutation=\(mutation) mutationSha256=\(mutationSHA256) stage=\(rejection.stage.rawValue) outcome=rejected")
    }

    static func receipt(_ id: String) {
        print("VECTOR_RECEIPT consumer \(id) stage=mac-protocol-parser outcome=rejected")
    }

    static func framingCaps() {
        for (kind, cap) in [(ProtocolParser.FrameKind.pairing, 4_096), (.session, 65_535), (.audioControl, 65_535), (.audioData, 262_144), (.videoData, 16_777_216)] {
            for length in [0, cap + 1] {
                var n = UInt32(length).bigEndian
                precondition((try? ProtocolParser.framedPayloadLength(from: Data(bytes: &n, count: 4), kind: kind)) == nil)
            }
            var n = UInt32(cap).bigEndian
            precondition((try? ProtocolParser.framedPayloadLength(from: Data(bytes: &n, count: 4), kind: kind)) == cap)
            precondition((try? ProtocolParser.validatePayload(Data(repeating: 0, count: cap - 1), expectedLength: cap, kind: kind)) == nil)
        }
    }
    static func directParserEntryPointCaps() {
        let oversizedPairing = Data(repeating: 0, count: ProtocolParser.pairingCap + 1)
        let oversizedControl = Data(repeating: 0, count: ProtocolParser.smallControlCap + 1)
        let key = SymmetricKey(data: Data(repeating: 0, count: 32))
        let entries: [(String, Data, (Data) throws -> Void)] = [
            ("pair commit", oversizedPairing, { _ = try ProtocolParser.parsePairCommit($0) }),
            ("pair hello", oversizedPairing, { _ = try ProtocolParser.parsePairHello($0) }),
            ("server hello", oversizedControl, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("session accept", oversizedControl, { _ = try ProtocolParser.parseSessionAccept($0) }),
            ("verified session accept", oversizedControl, {
                _ = try ProtocolParser.parseVerifiedSessionAccept(
                    $0, primaryKey: key, macInstallID: "mac", deviceInstallID: "device",
                    macNonce: Data(repeating: 0, count: 32),
                    deviceNonce: Data(repeating: 0, count: 32))
            }),
            ("session busy", oversizedControl, { _ = try ProtocolParser.parseSessionBusy($0) }),
            ("channel open", oversizedControl, { _ = try ProtocolParser.parseChannelOpen($0) }),
            ("control", oversizedControl, { _ = try ProtocolParser.parseControl($0, transport: .wifi) })
        ]
        for (name, data, parse) in entries {
            expectRejects("\(name) oversized direct parse") { try parse(data) }
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
            ("server-hello sessionVersion", { json("{\"type\":\"server-hello\",\"sessionVersion\":\($0),\"transport\":\"wifi\",\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true,\"wifiSessionSeed\":\"\(b64(0x43, 32))\"}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("server-hello pixelsWide", { json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"transport\":\"wifi\",\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":\($0),\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true,\"wifiSessionSeed\":\"\(b64(0x43, 32))\"}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("server-hello pixelsHigh", { json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"transport\":\"wifi\",\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":\($0),\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true,\"wifiSessionSeed\":\"\(b64(0x43, 32))\"}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("server-hello maxFps", { json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"transport\":\"wifi\",\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":\($0),\"hdr\":true,\"wifiSessionSeed\":\"\(b64(0x43, 32))\"}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("session-accept v", { json("{\"type\":\"session-accept\",\"v\":\($0),\"sessionID\":\"\(sid)\",\"generation\":1,\"acceptProof\":\"\(proof)\"}") }, { _ = try ProtocolParser.parseSessionAccept($0) }),
            ("session-accept generation", { json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(sid)\",\"generation\":\($0),\"acceptProof\":\"\(proof)\"}") }, { _ = try ProtocolParser.parseSessionAccept($0) }),
            ("session-busy v", { json("{\"type\":\"session-busy\",\"v\":\($0),\"reason\":\"session_busy\"}") }, { _ = try ProtocolParser.parseSessionBusy($0) }),
            ("channel-open v", { json("{\"type\":\"channel-open\",\"v\":\($0),\"macInstallID\":\"mac\",\"sessionID\":\"\(sid)\",\"generation\":1,\"channel\":\"audio\",\"nonce\":\"\(nonce)\",\"proof\":\"\(proof)\"}") }, { _ = try ProtocolParser.parseChannelOpen($0) }),
            ("channel-open generation", { json("{\"type\":\"channel-open\",\"v\":3,\"macInstallID\":\"mac\",\"sessionID\":\"\(sid)\",\"generation\":\($0),\"channel\":\"audio\",\"nonce\":\"\(nonce)\",\"proof\":\"\(proof)\"}") }, { _ = try ProtocolParser.parseChannelOpen($0) }),
            ("ping id", { json("{\"type\":\"ping\",\"id\":\($0),\"t\":1.0}") }, { _ = try ProtocolParser.parseControl($0, transport: .wifi) }),
            ("pong id", { json("{\"type\":\"pong\",\"id\":\($0),\"t\":1.0}") }, { _ = try ProtocolParser.parseControl($0, transport: .wifi) }),
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
            ParserCase(name: "server-hello", valid: json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"transport\":\"wifi\",\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true,\"wifiSessionSeed\":\"\(b64(0x43, 32))\"}"), requiredKeys: ["type", "sessionVersion", "transport", "deviceNonce", "pixelsWide", "pixelsHigh", "scale", "device", "id", "maxFps", "hdr", "wifiSessionSeed"], typeKey: "type", typeValue: "server-hello", wrongTypeField: "hdr", wrongTypeValue: "\"true\"") { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) },
            ParserCase(name: "session-accept", valid: json("{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(sid)\",\"generation\":1,\"acceptProof\":\"\(proof)\"}"), requiredKeys: ["type", "v", "sessionID", "generation", "acceptProof"], typeKey: "type", typeValue: "session-accept", wrongTypeField: "sessionID", wrongTypeValue: "1") { _ = try ProtocolParser.parseSessionAccept($0) },
            ParserCase(name: "session-busy", valid: json("{\"type\":\"session-busy\",\"v\":3,\"reason\":\"session_busy\"}"), requiredKeys: ["type", "v", "reason"], typeKey: "type", typeValue: "session-busy", wrongTypeField: "reason", wrongTypeValue: "1") { _ = try ProtocolParser.parseSessionBusy($0) },
            ParserCase(name: "channel-open", valid: json("{\"type\":\"channel-open\",\"v\":3,\"macInstallID\":\"mac\",\"sessionID\":\"\(sid)\",\"generation\":1,\"channel\":\"audio\",\"nonce\":\"\(nonce)\",\"proof\":\"\(proof)\"}"), requiredKeys: ["type", "v", "macInstallID", "sessionID", "generation", "channel", "nonce", "proof"], typeKey: "type", typeValue: "channel-open", wrongTypeField: "nonce", wrongTypeValue: "1") { _ = try ProtocolParser.parseChannelOpen($0) },
            ParserCase(name: "control-ping", valid: json("{\"type\":\"ping\",\"id\":1,\"t\":1.0}"), requiredKeys: ["type", "id", "t"], typeKey: "type", typeValue: "ping", wrongTypeField: "id", wrongTypeValue: "\"1\"") { _ = try ProtocolParser.parseControl($0, transport: .wifi) },
            ParserCase(name: "control-pong", valid: json("{\"type\":\"pong\",\"id\":1,\"t\":1.0}"), requiredKeys: ["type", "id", "t"], typeKey: "type", typeValue: "pong", wrongTypeField: "id", wrongTypeValue: "\"1\"") { _ = try ProtocolParser.parseControl($0, transport: .wifi) },
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
            ("server deviceNonce", 32, { json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"transport\":\"wifi\",\"deviceNonce\":\"\($0)\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true,\"wifiSessionSeed\":\"\(b64(0x43, 32))\"}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
            ("server wifiSessionSeed", 32, { json("{\"type\":\"server-hello\",\"sessionVersion\":3,\"transport\":\"wifi\",\"deviceNonce\":\"\(b64(0x42, 32))\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2.0,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true,\"wifiSessionSeed\":\"\($0)\"}") }, { _ = try ProtocolParser.parseServerHello($0, transport: .wifi) }),
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
            ("production inbound pairing", ProtocolParser.FrameKind.pairing, 4_096),
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
        let wifi = json("{\(common),\"transport\":\"wifi\",\"wifiSessionSeed\":\"\(b64(0x43, 32))\"}")
        let usb = json("{\(common),\"transport\":\"usb\"}")
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
        for t in ["-1", "1e999", "true", "\"1\""] {
            precondition((try? ProtocolParser.parseControl(json("{\"type\":\"pong\",\"id\":1,\"t\":\(t)}"), transport: .wifi)) == nil)
        }
        guard case .pong(let pongID, let pongTime) = try? ProtocolParser.parseControl(
            json("{\"type\":\"pong\",\"id\":18446744073709551615,\"t\":0}"),
            transport: .wifi) else {
            preconditionFailure("valid pong was not parsed")
        }
        precondition(pongID == UInt64.max && pongTime == 0)
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

    static func pongProductionState() {
        let baseline = Date(timeIntervalSince1970: 100)
        let later = Date(timeIntervalSince1970: 200)
        var state = ProtocolParser.ControlLivenessState(lastReceived: baseline)

        let pong = try! ProtocolParser.parseControl(
            json("{\"type\":\"pong\",\"id\":7,\"t\":1.25}"), transport: .wifi)
        precondition(!state.receive(pong, at: later))
        precondition(state.lastReceived == baseline)

        let duplicatePong = try! ProtocolParser.parseControl(
            json("{\"type\":\"pong\",\"id\":7,\"t\":1.25}"), transport: .wifi)
        precondition(!state.receive(duplicatePong, at: later))
        precondition(state.lastReceived == baseline)

        let mismatchedPong = try! ProtocolParser.parseControl(
            json("{\"type\":\"pong\",\"id\":8,\"t\":1.25}"), transport: .wifi)
        precondition(!state.receive(mismatchedPong, at: later))
        precondition(state.lastReceived == baseline)

        let ping = try! ProtocolParser.parseControl(
            json("{\"type\":\"ping\",\"id\":7,\"t\":1.25}"), transport: .wifi)
        precondition(state.receive(ping, at: later))
        precondition(state.lastReceived == later)
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
    static func pairingIdentityMutations() {
        let pub = Data(repeating: 0x21, count: 32)
        let nonce = Data(repeating: 0x22, count: 16)
        let commitment = PairingCrypto.commitment(
            role: "device", installID: "device-a", name: nil, pub: pub, nonce: nonce
        )
        precondition(!SessionCrypto.constantTimeEqual(
            commitment,
            PairingCrypto.commitment(
                role: "device", installID: "device-a", name: nil,
                pub: pub, nonce: Data(repeating: 0x23, count: 16)
            )
        ))
        let deviceHello = json(
            "{\"type\":\"pair-hello\",\"v\":2,\"role\":\"device\",\"installID\":\"device-a\",\"pub\":\"\(pub.base64EncodedString())\",\"nonce\":\"\(nonce.base64EncodedString())\"}"
        )
        let macHello = json(
            "{\"type\":\"pair-hello\",\"v\":2,\"role\":\"mac\",\"installID\":\"mac-a\",\"name\":\"Mac\",\"pub\":\"\(pub.base64EncodedString())\",\"nonce\":\"\(nonce.base64EncodedString())\"}"
        )
        expectRejects("duplicate pairing role") {
            _ = try ProtocolParser.parsePairHello(deviceHello, role: "mac")
        }
        expectRejects("role reflection") {
            _ = try ProtocolParser.parsePairHello(macHello, role: "device")
        }
        receipt("role-reflection")
    }

    static func sessionIdentityMutations() {
        let key = SymmetricKey(data: Data(repeating: 0x31, count: 32))
        let macID = "mac-a", deviceID = "device-a"
        let macNonce = Data(repeating: 0x41, count: 32)
        let deviceNonce = Data(repeating: 0x42, count: 32)
        let sessionID = Data(repeating: 0x51, count: 16)
        let secret = SessionCrypto.channelSecret(primaryKey: key, sessionID: sessionID, generation: 1)
        let proof = SessionCrypto.acceptProof(
            key: secret, sessionID: sessionID, generation: 1,
            macInstallID: macID, deviceInstallID: deviceID,
            macNonce: macNonce, deviceNonce: deviceNonce
        )
        let accept = json(
            "{\"type\":\"session-accept\",\"v\":3,\"sessionID\":\"\(sessionID.base64EncodedString())\",\"generation\":1,\"acceptProof\":\"\(proof.base64EncodedString())\"}"
        )
        for (actualMacID, actualDeviceID, actualMacNonce, actualDeviceNonce) in [
            ("wrong", deviceID, macNonce, deviceNonce),
            (macID, "wrong", macNonce, deviceNonce),
            (macID, deviceID, Data(repeating: 0x43, count: 32), deviceNonce),
            (macID, deviceID, macNonce, Data(repeating: 0x44, count: 32)),
        ] {
            expectRejects("session identity mutation") {
                _ = try ProtocolParser.parseVerifiedSessionAccept(
                    accept, primaryKey: key,
                    macInstallID: actualMacID, deviceInstallID: actualDeviceID,
                    macNonce: actualMacNonce, deviceNonce: actualDeviceNonce
                )
            }
        }
        expectRejects("wrong session ID") {
            _ = try ProtocolParser.parseVerifiedSessionAccept(
                replacing(
                    accept, sessionID.base64EncodedString(),
                    Data(repeating: 0x52, count: 16).base64EncodedString()
                ),
                primaryKey: key, macInstallID: macID, deviceInstallID: deviceID,
                macNonce: macNonce, deviceNonce: deviceNonce
            )
        }
        let ordered = SessionCrypto.primaryProof(
            key: key, macInstallID: macID, deviceInstallID: deviceID,
            macNonce: macNonce, deviceNonce: deviceNonce
        )
        let reflected = SessionCrypto.primaryProof(
            key: key, macInstallID: deviceID, deviceInstallID: macID,
            macNonce: deviceNonce, deviceNonce: macNonce
        )
        precondition(!SessionCrypto.constantTimeEqual(ordered, reflected))
        let otherKey = SessionCrypto.primaryKey(
            ikm: Data(repeating: 0x32, count: 32),
            macInstallID: macID, deviceInstallID: deviceID,
            macNonce: macNonce, deviceNonce: deviceNonce
        )
        precondition(!SessionCrypto.constantTimeEqual(
            ordered,
            SessionCrypto.primaryProof(
                key: otherKey, macInstallID: macID, deviceInstallID: deviceID,
                macNonce: macNonce, deviceNonce: deviceNonce
            )
        ))
        receipt("wrong-session-id")
    }
    static func usbPrefaceAndRecordMutations() {
        let psk = Data(repeating: 0xA5, count: 32)
        let macNonce = Data(repeating: 0x11, count: 32)
        let deviceNonce = Data(repeating: 0x22, count: 32)
        func client() -> USBPrefaceClient {
            USBPrefaceClient(
                psk: psk, macInstallID: "mac", deviceInstallID: "receiver",
                purpose: "primary", startedAt: 0, token: 7, macNonce: macNonce
            )!
        }
        func server() -> USBPrefaceServer {
            USBPrefaceServer(
                psk: psk, macInstallID: "mac", deviceInstallID: "receiver",
                purpose: "primary", startedAt: 0, token: 7
            )!
        }

        precondition(!server().consumeMagic(Data(repeating: 0, count: 8), now: 0, token: 7))
        precondition(!server().consumeMagic(Data("PPV3".utf8), now: 0, token: 7))
        precondition(client().start(now: 5, token: 7) == nil)

        let mac = client()
        let device = server()
        let initial = mac.start(now: 0, token: 7)!
        precondition(device.consumeMagic(USBPrefaceMessage.magic, now: 0, token: 7))
        let initPayload = USBPrefaceMessage.unframe(Data(initial.dropFirst(8)))!.0
        for (old, new) in [
            ("\"usb-bind-init\"", "\"usb-bind-finish\""),
            ("\"v\":1", "\"v\":2"),
            ("\"primary\"", "\"audio\""),
            ("\"receiver\"", "\"other\""),
            (macNonce.base64EncodedString(), Data(repeating: 0x33, count: 32).base64EncodedString()),
        ] {
            let candidate = server()
            precondition(candidate.consumeMagic(USBPrefaceMessage.magic, now: 0, token: 7))
            precondition(candidate.consume(
                replacing(initPayload, old, new), now: 0, token: 7, nonce: deviceNonce
            ) == nil)
        }
        let initObject = try! JSONSerialization.jsonObject(with: initPayload) as! [String: Any]
        let initProof = initObject["proof"] as! String
        let badProofServer = server()
        precondition(badProofServer.consumeMagic(USBPrefaceMessage.magic, now: 0, token: 7))
        precondition(badProofServer.consume(
            replacing(initPayload, initProof, Data(repeating: 0, count: 32).base64EncodedString()),
            now: 0, token: 7, nonce: deviceNonce
        ) == nil)
        let unpairedExpectedDevice = USBPrefaceServer(
            psk: psk, macInstallID: "mac", deviceInstallID: "unpaired-receiver",
            purpose: "primary", startedAt: 0, token: 7
        )!
        precondition(unpairedExpectedDevice.consumeMagic(USBPrefaceMessage.magic, now: 0, token: 7))
        precondition(unpairedExpectedDevice.consume(initPayload, now: 0, token: 7, nonce: deviceNonce) == nil)
        receipt("usb-unpaired-identity")

        let challenge = device.consume(initPayload, now: 0, token: 7, nonce: deviceNonce)!
        let challengePayload = USBPrefaceMessage.unframe(challenge)!.0
        precondition(client().consume(initPayload, now: 0, token: 7) == nil)
        var challengeObject = try! JSONSerialization.jsonObject(with: challengePayload) as! [String: Any]
        challengeObject["proof"] = Data(repeating: 0, count: 32).base64EncodedString()
        let badChallenge = try! JSONSerialization.data(withJSONObject: challengeObject)
        precondition(mac.consume(badChallenge, now: 0, token: 7) == nil)

        let mac2 = client()
        let device2 = server()
        let initial2 = mac2.start(now: 0, token: 7)!
        precondition(device2.consumeMagic(USBPrefaceMessage.magic, now: 0, token: 7))
        let challenge2 = device2.consume(
            USBPrefaceMessage.unframe(Data(initial2.dropFirst(8)))!.0,
            now: 0, token: 7, nonce: deviceNonce
        )!
        precondition(device2.consume(USBPrefaceMessage.unframe(challenge2)!.0, now: 0, token: 7) == nil)
        let finishWrongProofClient = client()
        let finishWrongProofServer = server()
        let finishWrongProofInitial = finishWrongProofClient.start(now: 0, token: 7)!
        precondition(finishWrongProofServer.consumeMagic(USBPrefaceMessage.magic, now: 0, token: 7))
        let finishWrongProofChallenge = finishWrongProofServer.consume(
            USBPrefaceMessage.unframe(Data(finishWrongProofInitial.dropFirst(8)))!.0,
            now: 0, token: 7, nonce: deviceNonce
        )!
        let finishWrongProof = finishWrongProofClient.consume(
            USBPrefaceMessage.unframe(finishWrongProofChallenge)!.0, now: 0, token: 7
        )!
        var finishWrongProofObject = try! JSONSerialization.jsonObject(
            with: USBPrefaceMessage.unframe(finishWrongProof)!.0
        ) as! [String: Any]
        finishWrongProofObject["proof"] = Data(repeating: 0, count: 32).base64EncodedString()
        let malformedFinishProof = try! JSONSerialization.data(withJSONObject: finishWrongProofObject)
        precondition(finishWrongProofServer.consume(malformedFinishProof, now: 0, token: 7) == nil)
        receipt("usb-finish-wrong-proof")


        let mac3 = client()
        let device3 = server()
        let initial3 = mac3.start(now: 0, token: 7)!
        precondition(device3.consumeMagic(USBPrefaceMessage.magic, now: 0, token: 7))
        let challenge3 = device3.consume(
            USBPrefaceMessage.unframe(Data(initial3.dropFirst(8)))!.0,
            now: 0, token: 7, nonce: deviceNonce
        )!
        let finish3 = mac3.consume(USBPrefaceMessage.unframe(challenge3)!.0, now: 0, token: 7)!
        let accept = device3.consume(USBPrefaceMessage.unframe(finish3)!.0, now: 0, token: 7)!
        let acceptPayload = USBPrefaceMessage.unframe(accept)!.0
        precondition(mac3.consume(acceptPayload, now: 0, token: 7) == Data())
        precondition(mac3.consume(acceptPayload, now: 0, token: 7) == nil)
        let extraFrameClient = client()
        let extraFrameServer = server()
        let extraFrameInitial = extraFrameClient.start(now: 0, token: 7)!
        precondition(extraFrameServer.consumeMagic(USBPrefaceMessage.magic, now: 0, token: 7))
        let extraFrameChallenge = extraFrameServer.consume(
            USBPrefaceMessage.unframe(Data(extraFrameInitial.dropFirst(8)))!.0,
            now: 0, token: 7, nonce: deviceNonce
        )!
        let extraFrameFinish = extraFrameClient.consume(
            USBPrefaceMessage.unframe(extraFrameChallenge)!.0, now: 0, token: 7
        )!
        let extraFrameAccept = extraFrameServer.consume(
            USBPrefaceMessage.unframe(extraFrameFinish)!.0, now: 0, token: 7
        )!
        precondition(extraFrameClient.consume(USBPrefaceMessage.unframe(extraFrameAccept)!.0, now: 0, token: 7) == Data())
        precondition(extraFrameServer.consume(USBPrefaceMessage.unframe(extraFrameFinish)!.0, now: 0, token: 7) == nil)
        receipt("usb-preface-extra-frame")

        let binding = device3.authenticatedBinding()!
        func states() -> (USBRecordState, USBRecordState) {
            (
                USBRecordState(role: "mac", binding: binding, macInstallID: "mac",
                               deviceInstallID: "receiver", purpose: "primary",
                               macNonce: macNonce, deviceNonce: deviceNonce)!,
                USBRecordState(role: "device", binding: binding, macInstallID: "mac",
                               deviceInstallID: "receiver", purpose: "primary",
                               macNonce: macNonce, deviceNonce: deviceNonce)!
            )
        }
        var pair = states()
        let first = pair.0.frame(Data([1]), cap: 1)!
        precondition(pair.1.consume(first, cap: 1)?.0 == Data([1]))
        precondition(pair.1.consume(first, cap: 1) == nil)
        pair = states()
        _ = pair.0.frame(Data([1]), cap: 1)
        precondition(pair.1.consume(pair.0.frame(Data([2]), cap: 1)!, cap: 1) == nil)
        pair = states()
        var badTag = pair.0.frame(Data([1]), cap: 1)!
        badTag[badTag.index(before: badTag.endIndex)] ^= 1
        precondition(pair.1.consume(badTag, cap: 1) == nil)
        pair = states()
        var badPayload = pair.0.frame(Data([1]), cap: 1)!
        badPayload[badPayload.index(badPayload.startIndex, offsetBy: 12)] ^= 1
        precondition(pair.1.consume(badPayload, cap: 1) == nil)
        pair = states()
        precondition(pair.1.consume(pair.1.frame(Data([1]), cap: 1)!, cap: 1) == nil)
        precondition(states().0.frame(Data([1, 2]), cap: 1) == nil)

        for id in [
            "usb-missing-magic", "usb-wrong-magic",
            "usb-init-wrong-type", "usb-init-wrong-version", "usb-init-wrong-purpose",
            "usb-init-wrong-identity", "usb-init-wrong-nonce", "usb-init-wrong-proof",
            "usb-challenge-reflection", "usb-challenge-wrong-proof",
            "usb-finish-reflection", "usb-accept-replay", "usb-preface-timeout",
            "usb-record-sequence-replay", "usb-record-sequence-skip",
            "usb-record-tag-mutation", "usb-record-payload-mutation",
            "usb-record-wrong-direction-key", "usb-record-overhead-in-semantic-cap",
        ] {
            receipt(id)
        }
    }


}
