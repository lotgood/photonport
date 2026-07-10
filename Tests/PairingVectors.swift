import Foundation
import CryptoKit

@main
struct PairingVectors {
    static func main() throws {
        let macKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data((1...32).map(UInt8.init)))
        let deviceKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data((33...64).map(UInt8.init)))
        let macNonce = Data((101...116).map(UInt8.init))
        let deviceNonce = Data((151...166).map(UInt8.init))
        let macID = "00000000-1111-2222-3333-444444444444"
        let deviceID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"

        let macCommit = PairingCrypto.commitment(
            role: "mac", installID: macID, name: "Vector Mac",
            pub: macKey.publicKey.rawRepresentation, nonce: macNonce)
        let deviceCommit = PairingCrypto.commitment(
            role: "device", installID: deviceID, name: nil,
            pub: deviceKey.publicKey.rawRepresentation, nonce: deviceNonce)
        precondition(macCommit != deviceCommit)

        let transcript = PairingCrypto.transcript(
            macInstallID: macID, deviceInstallID: deviceID,
            macPub: macKey.publicKey.rawRepresentation,
            devicePub: deviceKey.publicKey.rawRepresentation,
            macNonce: macNonce, deviceNonce: deviceNonce)
        let shared = try macKey.sharedSecretFromKeyAgreement(with: deviceKey.publicKey)
        let sas = PairingCrypto.sasDigits(shared: shared, transcript: transcript)
        let psk = PairingCrypto.psk(shared: shared, transcript: transcript)

        let framed = PairingWire.frame(PairCommit(
            v: PairingCrypto.version,
            commit: macCommit.base64EncodedString()))!
        let payloadLength = Int(UInt32(bigEndian: framed.prefix(4).withUnsafeBytes {
            $0.loadUnaligned(as: UInt32.self)
        }))
        precondition(payloadLength == framed.count - 4)

        let sessionMacNonce = Data((1...32).map(UInt8.init))
        let sessionDeviceNonce = Data((33...64).map(UInt8.init))
        let sessionID = Data((65...80).map(UInt8.init))
        let audioNonce = Data((81...112).map(UInt8.init))
        let usbSeed = Data((201...232).map(UInt8.init))
        let generation: UInt64 = 0x0102_0304_0506_0708

        func sessionVector(ikm: Data) -> [String] {
            let primaryKey = SessionCrypto.primaryKey(
                ikm: ikm, macInstallID: macID, deviceInstallID: deviceID,
                macNonce: sessionMacNonce, deviceNonce: sessionDeviceNonce)
            let primaryProof = SessionCrypto.primaryProof(
                key: primaryKey, macInstallID: macID, deviceInstallID: deviceID,
                macNonce: sessionMacNonce, deviceNonce: sessionDeviceNonce)
            let channelSecret = SessionCrypto.channelSecret(
                primaryKey: primaryKey, sessionID: sessionID, generation: generation)
            let acceptProof = SessionCrypto.acceptProof(
                key: channelSecret, sessionID: sessionID, generation: generation,
                macInstallID: macID, deviceInstallID: deviceID,
                macNonce: sessionMacNonce, deviceNonce: sessionDeviceNonce)
            let audioProof = SessionCrypto.channelProof(
                key: channelSecret, sessionID: sessionID, generation: generation,
                channel: "audio", nonce: audioNonce)

            precondition(SessionCrypto.constantTimeEqual(audioProof, audioProof))
            precondition(!SessionCrypto.constantTimeEqual(
                audioProof, SessionCrypto.channelProof(
                    key: channelSecret, sessionID: sessionID, generation: generation + 1,
                    channel: "audio", nonce: audioNonce)))
            precondition(!SessionCrypto.constantTimeEqual(
                primaryProof, SessionCrypto.primaryProof(
                    key: primaryKey, macInstallID: macID, deviceInstallID: deviceID,
                    macNonce: Data(repeating: 0, count: 32), deviceNonce: sessionDeviceNonce)))
            precondition(!SessionCrypto.constantTimeEqual(
                primaryProof, SessionCrypto.primaryProof(
                    key: primaryKey, macInstallID: "wrong-mac",
                    deviceInstallID: deviceID, macNonce: sessionMacNonce,
                    deviceNonce: sessionDeviceNonce)))
            precondition(!SessionCrypto.constantTimeEqual(
                acceptProof, SessionCrypto.acceptProof(
                    key: channelSecret, sessionID: sessionID,
                    generation: generation + 1, macInstallID: macID,
                    deviceInstallID: deviceID, macNonce: sessionMacNonce,
                    deviceNonce: sessionDeviceNonce)))
            precondition(!SessionCrypto.constantTimeEqual(
                audioProof, SessionCrypto.channelProof(
                    key: channelSecret, sessionID: Data(repeating: 0, count: 16),
                    generation: generation, channel: "audio", nonce: audioNonce)))
            precondition(!SessionCrypto.constantTimeEqual(
                audioProof, SessionCrypto.channelProof(
                    key: channelSecret, sessionID: sessionID, generation: generation,
                    channel: "video", nonce: audioNonce)))

            return [primaryKey, channelSecret].map(SessionCrypto.data).map {
                $0.base64EncodedString()
            } + [primaryProof, acceptProof, audioProof].map {
                $0.base64EncodedString()
            }
        }

        let openFrame = PairingWire.frame(SessionOpen(
            v: SessionCrypto.version,
            macInstallID: macID,
            deviceInstallID: deviceID,
            macNonce: sessionMacNonce.base64EncodedString(),
            primaryProof: Data(repeating: 0xA5, count: 32).base64EncodedString()))!
        let openPayloadLength = Int(UInt32(bigEndian: openFrame.prefix(4).withUnsafeBytes {
            $0.loadUnaligned(as: UInt32.self)
        }))
        precondition(openPayloadLength == openFrame.count - 4)

        let fields = [
            macCommit.base64EncodedString(),
            deviceCommit.base64EncodedString(),
            transcript.base64EncodedString(),
            sas,
            psk.base64EncodedString(),
            String(payloadLength),
        ] + sessionVector(ikm: psk) + sessionVector(ikm: usbSeed) + [
            String(openPayloadLength),
        ]
        let vector = fields.joined(separator: "|")
        let expected = "oY3d7Ky85BqahvcwBA7QGPLA34DBgNXmEr0iLwnR700=|6NdDtoRQZGtSa/lZVq4mu/zL8RIEnbwijXvpuMFM1/U=|Bn1qQxA6lXwSMIU7ENmoGqpbwPVo8V8sSXK0spv/sDg=|606470|Yg0UWVxt3h3igmqEiufz0zyvBvAl88x3F6h6UX84Jqs=|84|CRVUk6Hq9BZQxNoRJEJ7gOcBrviXngz7Vhky3E7+x10=|fAAK022Z/sNKl1JGYrMP/Sl82pZlIjuMEUnyimrzh2A=|HsL0VUhmTZuCDxXzVzTzbQlu77xdUhX4jZ67KyoZNTI=|AuB3h/5eqUfJIXddq8/ZWtSYuzIcQy6T40Vg7TPPm9M=|DEXAF/W2R0EfU/EZXCfBaIl1m3XdbDEK/RPFX9tsxZ0=|ikX2TyUbd5JxE6W91v5qfhZZlr9ggM4RyE5IJ+mxXKg=|CuzR4vHeJWmyG7Yt0YIoTisOAT0P0BmlCdCK68aI8jY=|GsxWX59Rrhs50dNp00FF+b44CLJPuIiAnnRQ7DVJeM8=|KDsnHMlIhs9hqZbQdXMjemuUphamEDfVoBLGaLiiKzo=|apyMAvm2BEG2CxzmfaBiX+I7v6BooVo0dB3sgMtu3YM=|260"
        precondition(vector == expected, "pairing/session vector changed: \(vector)")
        print(vector)
    }
}
