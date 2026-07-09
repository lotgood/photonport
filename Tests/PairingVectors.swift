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

        let fields = [
            macCommit.base64EncodedString(),
            deviceCommit.base64EncodedString(),
            transcript.base64EncodedString(),
            sas,
            psk.base64EncodedString(),
            String(payloadLength),
        ]
        let vector = fields.joined(separator: "|")
        let expected = "oY3d7Ky85BqahvcwBA7QGPLA34DBgNXmEr0iLwnR700=|6NdDtoRQZGtSa/lZVq4mu/zL8RIEnbwijXvpuMFM1/U=|Bn1qQxA6lXwSMIU7ENmoGqpbwPVo8V8sSXK0spv/sDg=|606470|Yg0UWVxt3h3igmqEiufz0zyvBvAl88x3F6h6UX84Jqs=|84"
        precondition(vector == expected, "pairing vector changed: \(vector)")
        print(vector)
    }
}
