"""Static product-contract checks for the shipped Mac protocol callsites."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
PAIRING = (ROOT / "Mac" / "Pairing.swift").read_text(encoding="utf-8")
SENDER = (ROOT / "Mac" / "MacSender.swift").read_text(encoding="utf-8")


class MacProtocolContractTests(unittest.TestCase):
    def test_wire_versions_and_labels_are_canonical(self):
        self.assertRegex(PAIRING, r"static let version = 2")
        self.assertRegex(PAIRING, r'static let protocolLabel = "PhotonPort-pair-v2"')
        self.assertRegex(PAIRING, r'static let commitLabel = "PhotonPort-pair-v2-commit"')
        self.assertRegex(PAIRING, r"enum SessionCrypto\s*\{\s*static let version = 3")
        self.assertRegex(PAIRING, r'primaryInfo = Data\("PhotonPort-primary-v3"')
        self.assertRegex(PAIRING, r'channelInfo = Data\("PhotonPort-channels-v3"')

    def test_runtime_messages_bind_to_canonical_versions(self):
        for message in ("SessionOpen", "SessionChannelOpen"):
            self.assertRegex(SENDER, rf"{message}\([\s\S]{{0,500}}?v:\s*SessionCrypto\.version")
        self.assertRegex(PAIRING, r"PairCommit\(v:\s*PairingCrypto\.version")
        self.assertRegex(PAIRING, r"PairHello\([\s\S]{0,300}?v:\s*PairingCrypto\.version")
        self.assertRegex(SENDER, r"message\.v\s*==\s*SessionCrypto\.version")
        self.assertRegex(SENDER, r"info\.sessionVersion\s*==\s*SessionCrypto\.version")

    def test_accept_proof_is_fail_closed_before_binding(self):
        handler = SENDER[SENDER.index("private func handleSessionAccept"):]
        self.assertRegex(handler, r"message\.v\s*==\s*SessionCrypto\.version")
        self.assertRegex(handler, r"let proof = Data\(base64Encoded: message\.acceptProof\)")
        self.assertRegex(handler, r"guard\s+SessionCrypto\.constantTimeEqual\(proof, expected\)\s+else")
        self.assertRegex(handler, r"constantTimeEqual\(proof, expected\)[\s\S]{0,180}?scheduleReconnect\(\)")
        self.assertIn("pendingStreamSession = nil", handler)
        self.assertLess(handler.index("constantTimeEqual(proof, expected)"), handler.index("pendingStreamSession = nil"))

    def test_framing_and_fixed_lengths_remain_strict(self):
        self.assertRegex(PAIRING, r"guard len > 0, len < 64 \* 1024 else")
        self.assertRegex(PAIRING, r"deviceCommit\.count == 32")
        self.assertRegex(PAIRING, r"devicePub\.count == 32")
        self.assertRegex(PAIRING, r"deviceNonce\.count == 16")
        self.assertRegex(PAIRING, r"guard lhs\.count == rhs\.count else")


if __name__ == "__main__":
    unittest.main()
