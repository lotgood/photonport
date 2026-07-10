import Foundation
import CryptoKit

private struct Blob: Codable { let value: String }

private enum Adapter {
    static let maxFrame = 65_535

    static func frameLength(_ frame: Data) -> Int? {
        guard frame.count >= 4 else { return nil }
        let length = Int(frame.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian })
        guard (1...maxFrame).contains(length), frame.count == length + 4 else { return nil }
        return length
    }

    static func canonicalBase64(_ value: String, count: Int) -> Data? {
        guard !value.isEmpty, !value.contains(where: { $0 == "\n" || $0 == "\r" || $0 == " " || $0 == "\t" }),
              let data = Data(base64Encoded: value), data.count == count,
              data.base64EncodedString() == value else { return nil }
        return data
    }
}

@main
struct MacProtocolAdversarialHarness {
    static func main() {
        framing()
        commitments()
        constantTimeComparison()
        canonicalFields()
        sessionProofsAndOwnership()
        print("mac protocol adversarial harness passed")
    }

    static func framing() {
        let small = PairingWire.frame(Blob(value: "ok"))!
        precondition(Adapter.frameLength(small) == 14, "framed JSON length changed unexpectedly")
        for length in [0, 65_536, 65_535] {
            var n = UInt32(length).bigEndian
            var candidate = Data(bytes: &n, count: 4)
            candidate.append(Data(repeating: 0, count: max(1, min(length, 65_535))))
            let accepted = Adapter.frameLength(candidate) != nil
            precondition(accepted == (length == 65_535), "frame bound drift at \(length)")
        }
        var truncated = small
        truncated.removeLast()
        precondition(Adapter.frameLength(truncated) == nil)
    }

    static func commitments() {
        let role = "mac", install = "install-a", name = "Studio Mac"
        let pub = Data(repeating: 0x11, count: 32), nonce = Data(repeating: 0x22, count: 16)
        let original = PairingCrypto.commitment(role: role, installID: install, name: name, pub: pub, nonce: nonce)
        precondition(original.count == 32)
        let mutations: [Data] = [
            PairingCrypto.commitment(role: "device", installID: install, name: name, pub: pub, nonce: nonce),
            PairingCrypto.commitment(role: role, installID: "install-b", name: name, pub: pub, nonce: nonce),
            PairingCrypto.commitment(role: role, installID: install, name: "Other Mac", pub: pub, nonce: nonce),
            PairingCrypto.commitment(role: role, installID: install, name: name, pub: Data(repeating: 0x12, count: 32), nonce: nonce),
            PairingCrypto.commitment(role: role, installID: install, name: name, pub: pub, nonce: Data(repeating: 0x23, count: 16)),
            PairingCrypto.commitment(role: role, installID: install, name: nil, pub: pub, nonce: nonce)
        ]
        for mutated in mutations { precondition(mutated != original, "commitment field mutation was not bound") }
    }

    static func constantTimeComparison() {
        let bytes = Data([1, 2, 3, 4, 5, 6])
        precondition(SessionCrypto.constantTimeEqual(bytes, bytes))
        precondition(!SessionCrypto.constantTimeEqual(bytes, Data([1, 2, 3, 4, 5, 7])))
        precondition(!SessionCrypto.constantTimeEqual(bytes, Data([1, 2, 3])))
        let slice = bytes[1..<5]
        let copy = Data([2, 3, 4, 5])
        precondition(SessionCrypto.constantTimeEqual(Data(slice), copy), "slice comparison must be offset-safe")
        precondition(!SessionCrypto.constantTimeEqual(Data(bytes[0..<4]), copy))
    }

    static func canonicalFields() {
        let pub = Data(repeating: 0xAB, count: 32), nonce = Data(repeating: 0xCD, count: 16)
        precondition(Adapter.canonicalBase64(pub.base64EncodedString(), count: 32) == pub)
        precondition(Adapter.canonicalBase64(nonce.base64EncodedString(), count: 16) == nonce)
        precondition(Adapter.canonicalBase64(pub.base64EncodedString() + "\n", count: 32) == nil)
        precondition(Adapter.canonicalBase64(pub.base64EncodedString() + "=", count: 32) == nil)
        precondition(Adapter.canonicalBase64(Data(repeating: 0, count: 31).base64EncodedString(), count: 32) == nil)
        precondition(Adapter.canonicalBase64(Data(repeating: 0, count: 33).base64EncodedString(), count: 32) == nil)
    }

    static func sessionProofsAndOwnership() {
        precondition(SessionCrypto.version == 3)
        precondition(SessionTiming.receiverOwnershipTimeout == 5 && SessionTiming.handshakeTimeout == 5)
        let key = SymmetricKey(data: Data(repeating: 0x31, count: 32))
        let macID = "mac-a", deviceID = "device-a"
        let macNonce = Data(repeating: 0x41, count: 16), deviceNonce = Data(repeating: 0x42, count: 16)
        let primary = SessionCrypto.primaryProof(key: key, macInstallID: macID, deviceInstallID: deviceID, macNonce: macNonce, deviceNonce: deviceNonce)
        precondition(primary.count == 32)
        precondition(SessionCrypto.constantTimeEqual(primary, SessionCrypto.primaryProof(key: key, macInstallID: macID, deviceInstallID: deviceID, macNonce: macNonce, deviceNonce: deviceNonce)))
        precondition(!SessionCrypto.constantTimeEqual(primary, SessionCrypto.primaryProof(key: key, macInstallID: "mac-b", deviceInstallID: deviceID, macNonce: macNonce, deviceNonce: deviceNonce)))
        let sid = Data(repeating: 0x51, count: 16)
        let accept = SessionCrypto.acceptProof(key: key, sessionID: sid, generation: 1, macInstallID: macID, deviceInstallID: deviceID, macNonce: macNonce, deviceNonce: deviceNonce)
        precondition(!SessionCrypto.constantTimeEqual(accept, SessionCrypto.acceptProof(key: key, sessionID: sid, generation: 2, macInstallID: macID, deviceInstallID: deviceID, macNonce: macNonce, deviceNonce: deviceNonce)))
        let channel = SessionCrypto.channelProof(key: key, sessionID: sid, generation: 1, channel: "video", nonce: Data(repeating: 0x61, count: 16))
        precondition(!SessionCrypto.constantTimeEqual(channel, SessionCrypto.channelProof(key: key, sessionID: sid, generation: 1, channel: "audio", nonce: Data(repeating: 0x61, count: 16))))

        var state = SessionOwnershipState()
        precondition(state.consumeChannelNonce(macInstallID: macID, generation: 1, nonce: sid) == false)
        guard case .accepted(let lease) = state.claim(macInstallID: macID) else { preconditionFailure("initial claim rejected") }
        guard case .busy(let owner) = state.claim(macInstallID: "mac-b") else { preconditionFailure("ownership was not exclusive") }
        precondition(owner == lease && state.authorizes(macInstallID: macID, generation: lease.generation))
        precondition(state.consumeChannelNonce(macInstallID: macID, generation: lease.generation, nonce: sid))
        precondition(!state.consumeChannelNonce(macInstallID: macID, generation: lease.generation, nonce: sid), "channel replay accepted")
        precondition(!state.release(macInstallID: "mac-b", generation: lease.generation))
        precondition(state.release(macInstallID: macID, generation: lease.generation))
        guard case .accepted(let next) = state.claim(macInstallID: "mac-b") else { preconditionFailure("generation did not advance") }
        precondition(next.generation == lease.generation + 1)
    }
}
