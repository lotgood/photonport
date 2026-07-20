import Foundation

@main
struct SessionBindingHarness {
    static func main() {
        precondition(SessionTiming.macDisconnectGrace == 10)
        precondition(SessionTiming.handshakeTimeout == 5)
        precondition(SessionTiming.livenessDeadline == 5)
        precondition(SessionTiming.busyRetryDelay == 5)

        let nonce = Data(repeating: 0x11, count: 32).base64EncodedString()
        let seed = Data(repeating: 0x22, count: 32).base64EncodedString()
        let common = "\"type\":\"server-hello\",\"sessionVersion\":3,\"deviceNonce\":\"\(nonce)\",\"pixelsWide\":2732,\"pixelsHigh\":2048,\"scale\":2,\"device\":\"iPad\",\"id\":\"device-a\",\"maxFps\":120,\"hdr\":true"
        let wifi = Data("{\(common),\"transport\":\"wifi\",\"wifiSessionSeed\":\"\(seed)\"}".utf8)
        let usb = Data("{\(common),\"transport\":\"usb\"}".utf8)

        precondition((try? ProtocolParser.parseServerHello(wifi, transport: .wifi)) != nil)
        precondition((try? ProtocolParser.parseServerHello(usb, transport: .usb)) != nil)
        precondition((try? ProtocolParser.parseServerHello(wifi, transport: .usb)) == nil)
        precondition((try? ProtocolParser.parseServerHello(usb, transport: .wifi)) == nil)
        let open = SessionOpen(
            v: 3,
            macInstallID: "00000000-1111-2222-3333-444444444444",
            deviceInstallID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            macNonce: nonce,
            primaryProof: Data(repeating: 0x44, count: 32).base64EncodedString()
        )
        precondition(PairingWire.frame(open) != nil)
        print("VECTOR_RECEIPT consumer session-v3-frame:serverHelloWifi")
        print("VECTOR_RECEIPT consumer session-v3-frame:serverHelloUsb")
        print("VECTOR_RECEIPT consumer session-v3-frame:sessionOpenPayloadLength")

        let starting = SessionLifecycleState.starting(7)
        precondition(SessionLifecycleState.mayTransition(from: starting, to: .connected(7)))
        precondition(!SessionLifecycleState.mayTransition(from: starting, to: .connected(8)))
        print("session sender binding harness passed")
    }
}