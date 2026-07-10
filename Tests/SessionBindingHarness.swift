import Foundation

@main
struct SessionBindingHarness {
    static func main() {
        var state = SessionOwnershipState()
        let macA = "mac-a"
        let macB = "mac-b"
        precondition(SessionTiming.receiverOwnershipTimeout == 5)
        precondition(SessionTiming.macDisconnectGrace == 10)
        precondition(SessionTiming.audioBeforePrimaryPending == 2)
        precondition(SessionTiming.handshakeTimeout == 5)
        precondition(SessionTiming.busyRetryDelay == 5)
        let firstNonce = Data(repeating: 0x11, count: 32)
        let secondNonce = Data(repeating: 0x22, count: 32)
        precondition(!state.consumeChannelNonce(
            macInstallID: macA, generation: 1, nonce: firstNonce),
            "audio must not bind before a primary lease exists")

        guard case .accepted(let first) = state.claim(macInstallID: macA) else {
            preconditionFailure("first primary claim must be accepted")
        }
        precondition(first.generation == 1)
        precondition(state.authorizes(macInstallID: macA, generation: first.generation))
        precondition(!state.authorizes(macInstallID: macB, generation: first.generation))
        precondition(!state.authorizes(macInstallID: macA, generation: first.generation + 1))

        guard case .busy(let sameIdentityOwner) = state.claim(macInstallID: macA) else {
            preconditionFailure("same identity must not open a second primary")
        }
        precondition(sameIdentityOwner == first)
        guard case .busy(let crossIdentityOwner) = state.claim(macInstallID: macB) else {
            preconditionFailure("cross identity must not preempt the receiver owner")
        }
        precondition(crossIdentityOwner == first)

        precondition(state.consumeChannelNonce(
            macInstallID: macA, generation: first.generation, nonce: firstNonce))
        precondition(!state.consumeChannelNonce(
            macInstallID: macA, generation: first.generation, nonce: firstNonce))
        precondition(!state.consumeChannelNonce(
            macInstallID: macB, generation: first.generation, nonce: secondNonce))
        precondition(!state.consumeChannelNonce(
            macInstallID: macA, generation: first.generation + 1, nonce: secondNonce))

        precondition(!state.release(macInstallID: macB, generation: first.generation))
        precondition(!state.release(macInstallID: macA, generation: first.generation + 1))
        precondition(state.release(macInstallID: macA, generation: first.generation))
        precondition(state.active == nil)

        guard case .accepted(let second) = state.claim(macInstallID: macB) else {
            preconditionFailure("new primary must be accepted after release or timeout")
        }
        precondition(second.generation == first.generation + 1)
        precondition(state.consumeChannelNonce(
            macInstallID: macB, generation: second.generation, nonce: firstNonce),
            "a nonce from an ended generation is valid only under the new generation proof")
        precondition(!state.authorizes(macInstallID: macA, generation: first.generation))

        print("session ownership harness passed")
    }
}
