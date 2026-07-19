import XCTest
@testable import PhotonPort

final class S01PairingCommitmentTests: XCTestCase {
    func testCommitmentComparisonAcceptsEqualValuesAndRejectsAllMismatches() {
        let commitment = PairingCrypto.commitment(
            role: "device",
            installID: "audit-device",
            name: nil,
            pub: Data(repeating: 0xA5, count: 32),
            nonce: Data(repeating: 0x5A, count: 16))

        XCTAssertTrue(SessionCrypto.constantTimeEqual(commitment, commitment))
        XCTAssertFalse(SessionCrypto.constantTimeEqual(commitment, Data(commitment.dropLast())))
        XCTAssertFalse(SessionCrypto.constantTimeEqual(commitment, commitment + Data([0])))

        for index in commitment.indices {
            var mismatched = commitment
            mismatched[index] ^= 0x01
            XCTAssertFalse(SessionCrypto.constantTimeEqual(commitment, mismatched),
                           "commitment mismatch at byte \(index) must reject")
        }
    }
}
