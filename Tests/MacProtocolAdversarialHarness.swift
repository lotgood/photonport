import Foundation
import CryptoKit

private func json(_ text: String) -> Data { Data(text.utf8) }
private func b64(_ byte: UInt8, _ count: Int) -> String { Data(repeating: byte, count: count).base64EncodedString() }

@main
struct MacProtocolAdversarialHarness {
    static func main() {
        framingCaps()
        strictJSON()
        canonicalFields()
        transportRules()
        strictControls()
        sessionProofsAndOwnership()
        generationSnapshots()
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
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":-1.0,\"dy\":2.0}"), transport: .wifi)) != nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":1000000,\"dy\":-1000000}"), transport: .wifi)) != nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":1000000.1,\"dy\":0}"), transport: .wifi)) == nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"scroll\",\"dx\":0,\"dy\":-1000000.1}"), transport: .wifi)) == nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"kf\"}"), transport: .wifi)) != nil)
        precondition((try? ProtocolParser.parseControl(json("{\"type\":\"hello\"}"), transport: .wifi)) == nil)
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
