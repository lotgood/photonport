"""Static product-contract checks for the shipped Mac protocol callsites."""
from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROJECT_YML = (ROOT / "project.yml").read_text(encoding="utf-8")
TARGETS_YML = PROJECT_YML.split("\ntargets:\n", 1)[1]
PAIRING = (ROOT / "Mac" / "Pairing.swift").read_text(encoding="utf-8")
SENDER = (ROOT / "Mac" / "MacSender.swift").read_text(encoding="utf-8")
HARNESS = (ROOT / "Tests" / "MacProtocolAdversarialHarness.swift").read_text(encoding="utf-8")
HARNESS_SCRIPT = (ROOT / "scripts" / "test-mac-protocol-adversarial.sh").read_text(encoding="utf-8")
PIN_PATH = ROOT / "Mac" / "ProtocolBuildPin.json"
PARSER_PATH = ROOT / "Mac" / "ProtocolParser.swift"
PARSER = PARSER_PATH.read_text(encoding="utf-8")


def target_block(target_name: str) -> str:
    match = re.search(rf"^  {re.escape(target_name)}:\n(?P<body>(?:    .+\n|      .+\n|        .+\n|          .+\n|            .+\n|              .+\n|                .+\n)*)", TARGETS_YML, re.MULTILINE)
    if not match:
        raise AssertionError(f"missing project.yml target {target_name}")
    return match.group("body")


def swiftc_inputs(script: str) -> set[str]:
    command = script[script.index("xcrun swiftc"):]
    return set(re.findall(r"(?:^|\s)(Mac/[^\s\\]+\.swift|Tests/[^\s\\]+\.swift)", command))

def swift_function(source: str, name: str) -> str:
    start = source.index(f"static func {name}")
    end = source.find("\n    static func ", start + 1)
    return source[start:] if end == -1 else source[start:end]

def swift_private_function(source: str, name: str) -> str:
    start = source.index(f"private func {name}")
    end = source.find("\n    private func ", start + 1)
    return source[start:] if end == -1 else source[start:end]


class MacProtocolContractTests(unittest.TestCase):
    def test_wire_versions_and_labels_are_canonical(self):
        self.assertRegex(PAIRING, r"static let version = 2")
        self.assertRegex(PAIRING, r'static let protocolLabel = "PhotonPort-pair-v2"')
        self.assertRegex(PAIRING, r'static let commitLabel = "PhotonPort-pair-v2-commit"')
        self.assertRegex(PAIRING, r"enum SessionCrypto\s*\{\s*static let version = 3")
        self.assertRegex(PAIRING, r'primaryInfo = Data\("PhotonPort-primary-v3"')
        self.assertRegex(PAIRING, r'channelInfo = Data\("PhotonPort-channels-v3"')

    def test_protocol_parser_enforces_canonical_versions_and_proof_fields(self):
        pair_commit = swift_function(PARSER, "parsePairCommit")
        pair_hello = swift_function(PARSER, "parsePairHello")
        server_hello = swift_function(PARSER, "parseServerHello")
        session_accept = swift_function(PARSER, "parseSessionAccept")
        channel_open = swift_function(PARSER, "parseChannelOpen")
        self.assertIn('try int(object, "v") == PairingCrypto.version', pair_commit)
        self.assertIn('try int(object, "v") == PairingCrypto.version', pair_hello)
        self.assertIn('try int(object, "sessionVersion") == SessionCrypto.version', server_hello)
        self.assertIn('try int(object, "v") == SessionCrypto.version', session_accept)
        self.assertIn('base64(try string(object, "sessionID"), bytes: 16)', session_accept)
        self.assertIn('base64(try string(object, "acceptProof"), bytes: 32)', session_accept)
        self.assertIn('try int(object, "v") == SessionCrypto.version', channel_open)
        self.assertIn('base64(try string(object, "proof"), bytes: 32)', channel_open)

    def test_accept_proof_is_fail_closed_before_binding(self):
        handler = swift_private_function(SENDER, "handleSessionAccept")
        self.assertRegex(handler, r"ProtocolParser\.parseVerifiedSessionAccept")
        verified_accept = swift_function(PARSER, "parseVerifiedSessionAccept")
        self.assertIn("SessionCrypto.constantTimeEqual(proof, expected)", verified_accept)
        self.assertIn("guard SessionCrypto.constantTimeEqual(proof, expected) else", verified_accept)
        self.assertIn("pendingStreamSession = nil", handler)
        self.assertLess(handler.index("parseVerifiedSessionAccept"), handler.index("pendingStreamSession = nil"))

    def test_project_yml_tracks_mac_source_tree_and_keeps_ios_separate(self):
        self.assertTrue(PARSER_PATH.exists(), "Mac/ProtocolParser.swift must be a tracked production source")
        mac_target = target_block("OpenSidecarMac")
        ios_target = target_block("OpenSidecariOS")
        self.assertRegex(mac_target, r"sources:\n\s+- Mac\b")
        self.assertRegex(ios_target, r"sources:\n\s+- iOS\b")
        self.assertNotRegex(mac_target, r"sources:\n(?:\s+- .+\n)*\s+- iOS\b")
        self.assertNotRegex(ios_target, r"sources:\n(?:\s+- .+\n)*\s+- Mac\b")

    def test_parser_is_shared_by_adversarial_harness(self):
        self.assertIn("Mac/ProtocolParser.swift", swiftc_inputs(HARNESS_SCRIPT))
        self.assertIn("Tests/MacProtocolAdversarialHarness.swift", swiftc_inputs(HARNESS_SCRIPT))

    def test_harness_calls_production_parser_without_policy_adapter(self):
        self.assertNotRegex(HARNESS, r"\b(Adapter|PolicyAdapter)\b")
        for symbol in ("ProtocolParser", "framedPayloadLength", "parsePairCommit", "parseSessionAccept", "parseChannelOpen"):
            self.assertIn(symbol, HARNESS)
        self.assertRegex(HARNESS, r"parseSessionAccept[\s\S]*?!= nil")

    def test_parser_caps_are_exact_and_legacy_mebibyte_receives_are_gone(self):
        for cap in ("65_535", "262_144", "16_777_216"):
            self.assertRegex(PARSER, rf"=\s*{cap}\b")
        self.assertNotRegex(SENDER, r"guard\s+\w+\s*>\s*0\s*,\s*\w+\s*<\s*1\s*<<\s*20\s+else")
        self.assertNotRegex(SENDER, r"receive\([^\n]*(?:control|audio)[^\n]*1\s*<<\s*20")

    def test_pairing_and_sender_use_strict_production_parser(self):
        self.assertRegex(PARSER, r"guard\s+\(1\.\.\.cap\(for:\s*kind\)\)\.contains\(length\)\s+else")
        self.assertRegex(PARSER, r"guard\s+payload\.count\s*==\s*expectedLength\s*,\s*\(1\.\.\.cap\(for:\s*kind\)\)\.contains\(payload\.count\)\s+else")
        self.assertRegex(PAIRING, r"ProtocolParser\.(framedPayloadLength|parsePairCommit|parsePairHello)")
        self.assertRegex(SENDER, r"ProtocolParser\.(framedPayloadLength|parseServerHello|parseSessionAccept|parseSessionBusy|parseChannelOpen)")

    def test_application_controls_require_bound_session(self):
        handler = swift_private_function(SENDER, "handleControl")
        gate = "guard connectionReady, boundStreamSession != nil else"
        self.assertIn(gate, handler)
        self.assertLess(handler.index(gate), handler.index("case .touch"))
        self.assertLess(handler.index(gate), handler.index("case .scroll"))
    def test_outbound_control_shapes_match_authority(self):
        ping = swift_private_function(SENDER, "schedulePing")
        cursor = swift_private_function(SENDER, "pollCursorPosition")
        for field in ('\\"type\\":\\"ping\\"', '\\"id\\":\\(pingID)', '\\"t\\":\\(pingTime)'):
            self.assertIn(field, ping)
        for legacy_key in ("drops", "pending", "inp50", "inp95", "capFps"):
            self.assertNotIn(f'\\"{legacy_key}\\"', ping)
        self.assertIn('\\"visible\\":true', cursor)
        self.assertIn('\\"visible\\":false', cursor)
        self.assertNotIn('\\"cursorImg\\"', SENDER)
        self.assertNotRegex(cursor, r'\\"v\\"\s*:')
    def test_persistent_generation_increment_is_checked_nonwrapping(self):
        self.assertNotIn("generation &+= 1", PAIRING)
        self.assertRegex(PAIRING, r"guard\s+!exhausted\s*,\s*generation\s*<\s*UInt64\.max\s+else")
        self.assertRegex(PAIRING, r"exhausted\s*=\s*true")
        self.assertRegex(PAIRING, r"generation\s*\+=\s*1")

    def test_build_pin_values_and_mac_resource_inclusion_are_exact(self):
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            pin,
            {
                "schemaVersion": 1,
                "protocolCommit": "2280861313b2363b673089637d1c1dc544e208d8",
                "compatibilityDigest": "6e5e7faf195eff19fafcbdf388186641ef8f8c02586ae1d9f35df0bbc64ae3b3",
                "normativeManifestDigest": "5265022d17d6a7c6ce962a8130b953fa0ae825b7284d66b2c5845ec7ee1388bc",
            },
        )
        self.assertNotIn("protocolTag", pin)


if __name__ == "__main__":
    unittest.main()
