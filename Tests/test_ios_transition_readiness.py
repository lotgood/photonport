import base64
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("transition", HERE / "scripts/verify-ios-transition-readiness.py")
transition = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transition)
ED25519_SPEC = importlib.util.spec_from_file_location(
    "ed25519_rfc8032", HERE / "scripts" / "evidence" / "ed25519_rfc8032.py"
)
ed25519_rfc8032 = importlib.util.module_from_spec(ED25519_SPEC)
ED25519_SPEC.loader.exec_module(ed25519_rfc8032)



class TransitionReadinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.mac, self.ios, self.protocol = (self.root / n for n in ("mac", "ios", "protocol"))
        (self.mac / "iOS" / "fixtures").mkdir(parents=True)
        self.ios.mkdir()
        self.protocol.mkdir()
        (self.mac / "project.yml").write_text("targets:\n  OpenSidecariOS:\n", encoding="utf-8")
        (self.mac / "iOS/PhoneReceiver.swift").write_text("// preserved\n", encoding="utf-8")
        for name in ("LICENSE", "NOTICE.md", "PROVENANCE.yml", "project.yml"):
            (self.ios / name).write_text("standalone\n", encoding="utf-8")
        for name in ("LICENSE", "COMPATIBILITY.json"):
            (self.protocol / name).write_text("standalone\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=self.mac, check=True)
        subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "add", "."], cwd=self.mac, check=True)
        subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-qm", "preserve"], cwd=self.mac, check=True)
        self.template = self.mac / "iOS" / "fixtures" / "template.json"
        self.template.write_text(json.dumps({"standalone": {"ios": ["LICENSE", "NOTICE.md", "PROVENANCE.yml", "project.yml"], "protocol": ["LICENSE", "COMPATIBILITY.json"]}}), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def write_receipt(self, name, value):
        path = self.mac / "iOS" / "fixtures" / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def args(self, **kwargs):
        base = dict(mac_root=self.mac, ios_root=self.ios, protocol_root=self.protocol,
                    g004_automated=None, g004_physical=None, g006_provenance=None,
                    export_review=None, apple_distribution=None, rollback_build=None,
                    template=self.template, trust_policy=self.root / "trust-policy.json",
                    trust_mode="production", release_attempt_id=None, receipt_set=[],
                    input_root=[])
        base.update(kwargs)
        return type("Args", (), base)()

    def init_git_root(self, root):
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-qm", "snapshot"], cwd=root, check=True)

    def init_m1_roots(self):
        (self.mac / "COMPATIBILITY.json").write_text('{"repo":"mac"}', encoding="utf-8")
        (self.ios / "COMPATIBILITY.json").write_text('{"repo":"ios"}', encoding="utf-8")
        self.init_git_root(self.ios)
        self.init_git_root(self.protocol)
        subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "add", "."], cwd=self.mac, check=True)
        subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-qm", "compat"], cwd=self.mac, check=True)

    def envelope(self, name):
        path = self.write_receipt(name, {"schemaVersion": 2, "kind": "photonport.receipt-envelope.v2", "payloadType": "application/vnd.photonport.receipt.payload.v2+json", "payload": "e30=", "signatures": [{"keyid": "test-ci-hmac-v1", "alg": "HMAC-SHA256-TEST", "sig": "e30="}]})
        if (self.mac / ".git").is_dir():
            subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "add", str(path.relative_to(self.mac))], cwd=self.mac, check=True)
            subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-qm", "receipt"], cwd=self.mac, check=True)
        return path

    def reason_codes(self, result):
        return {gate["reasonCode"] for gate in result["gates"]}

    def fake_digests(self, kind="photonport.gate.g004-automated.v2", policy=None):
        return {
            "scriptSha256": "1" * 64,
            "ed25519ModuleSha256": "2" * 64,
            "schemaSha256": "3" * 64,
            "trustPolicySha256": "4" * 64,
        }

    def production_receipts(self):
        self.init_m1_roots()
        ignored = self.mac / ".gitignore"
        ignored.write_text("iOS/fixtures/production-*.json\n", encoding="utf-8")
        subprocess.run(["git", "add", ".gitignore"], cwd=self.mac, check=True)
        subprocess.run(["git", "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-qm", "ignore production fixtures"], cwd=self.mac, check=True)

        api = transition.load_verify_receipt_api()
        self.assertIsNotNone(api)
        seeds = {
            "prod-ci-ed25519-v1": bytes.fromhex("11" * 32),
            "prod-human-ed25519-v1": bytes.fromhex("22" * 32),
            "prod-provider-ed25519-v1": bytes.fromhex("33" * 32),
        }
        policy = json.loads((HERE / "scripts" / "evidence" / "trust-policy.json").read_text(encoding="utf-8"))
        for keyid, seed in seeds.items():
            policy["productionRoot"]["keys"][keyid]["publicKeyHex"] = ed25519_rfc8032.public_key(seed).hex()
        policy_path = self.mac / "iOS" / "fixtures" / "production-policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")

        roots = {"macRoot": self.mac, "iosRoot": self.ios, "protocolRoot": self.protocol}
        snapshot = transition.snapshot_roots(roots)
        source_tuple = transition.source_tuple_from_snapshot(roots, snapshot)
        source_tuple = {key: value for key, value in source_tuple.items() if key not in {"macRoot", "iosRoot", "protocolRoot"}}
        release_attempt_id = "attempt-production-fixture-0001"
        issuers = {
            "g004_automated": ("prod-ci-ed25519-v1", {"kind": "ci", "identity": "fixture", "role": "automated-ci", "trustDomain": "opendisplay-ci"}),
            "g004_physical": ("prod-human-ed25519-v1", {"kind": "human", "identity": "fixture", "role": "release-engineer", "trustDomain": "human-approval"}),
            "g006_provenance": ("prod-ci-ed25519-v1", {"kind": "ci", "identity": "fixture", "role": "automated-ci", "trustDomain": "opendisplay-ci"}),
            "export_review": ("prod-human-ed25519-v1", {"kind": "human", "identity": "fixture", "role": "export-reviewer", "trustDomain": "human-approval"}),
            "apple_distribution": ("prod-provider-ed25519-v1", {"kind": "provider", "identity": "fixture", "role": "apple-provider", "trustDomain": "external-provider"}),
            "rollback_build": ("prod-ci-ed25519-v1", {"kind": "ci", "identity": "fixture", "role": "automated-ci", "trustDomain": "opendisplay-ci"}),
        }
        receipts = {}
        for label, (gate_id, _, kind) in transition.GATES.items():
            keyid, issuer = issuers[label]
            payload = {
                "schemaVersion": 2,
                "kind": kind,
                "receiptId": f"r-production-{label}",
                "releaseAttemptId": release_attempt_id,
                "gateId": gate_id,
                "status": "passed",
                "sourceTuple": source_tuple,
                "issuer": issuer,
                "verifier": {"commit": snapshot["macRoot"]["commit"], **transition.verifier_digests(kind, policy_path)},
                "invocation": {"tool": "unittest", "argv": ["python3", "-m", "unittest"], "cwd": ".", "toolchain": {"python": "3"}},
                "artifacts": {"inputs": [{"path": "fixtures/evidence.txt", "sha256": "0" * 64, "size": 0}], "outputs": []} if gate_id in {"g004.physical", "export.review", "apple.distribution", "rollback.build"} else {"inputs": [], "outputs": []},
                "children": [],
                "observationTime": "2026-07-14T00:00:00Z",
                **({"deviceOs": {"host": "27", "device": "27"}} if gate_id == "g004.physical" else {}),
            }
            payload_bytes = api.canonical_json(payload)
            signature = ed25519_rfc8032.sign(seeds[keyid], api.dsse_pae(api.PAYLOAD_TYPE, payload_bytes))
            envelope = {
                "schemaVersion": 2,
                "kind": "photonport.receipt-envelope.v2",
                "payloadType": api.PAYLOAD_TYPE,
                "payload": base64.b64encode(payload_bytes).decode("ascii"),
                "signatures": [{"keyid": keyid, "alg": "ED25519-DSSE", "sig": base64.b64encode(signature).decode("ascii")}],
            }
            receipt = self.mac / "iOS" / "fixtures" / f"production-{label}.json"
            receipt.write_text(json.dumps(envelope), encoding="utf-8")
            receipts[label] = receipt
        return receipts, policy_path, release_attempt_id

    def test_forged_result_passed_is_malformed_exit_3(self):
        forged = self.write_receipt("forged.json", {"result": "passed"})
        result = transition.verify(self.args(g004_automated=forged))
        self.assertFalse(result["retirementEligible"])
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("missing_schema_kind", self.reason_codes(result))

    def test_forged_ready_true_is_malformed_exit_3(self):
        forged = self.write_receipt("ready.json", {"ready": True})
        result = transition.verify(self.args(g004_automated=forged))
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("missing_schema_kind", self.reason_codes(result))

    def test_string_synonym_scalar_is_malformed_exit_3(self):
        forged = self.write_receipt("scalar.json", "success")
        result = transition.verify(self.args(g004_automated=forged))
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("top_level_not_object", self.reason_codes(result))

    def test_unknown_schema_or_kind_exit_3(self):
        unknown_schema = self.write_receipt("schema.json", {"schemaVersion": 99, "kind": "photonport.gate.g004-automated.v2"})
        unknown_kind = self.write_receipt("kind.json", {"schemaVersion": 2, "kind": "unknown"})
        self.assertIn("unknown_schema_version", self.reason_codes(transition.verify(self.args(g004_automated=unknown_schema))))
        result = transition.verify(self.args(g004_automated=unknown_kind))
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("unknown_receipt_kind", self.reason_codes(result))

    def test_wrong_gate_kind_exit_3(self):
        wrong = self.write_receipt("wrong.json", {"schemaVersion": 2, "kind": "photonport.gate.g004-physical.v2", "gateId": "g004.physical", "status": "passed"})
        result = transition.verify(self.args(g004_automated=wrong))
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("wrong_gate_kind", self.reason_codes(result))

    def test_duplicate_json_key_exit_3(self):
        path = self.mac / "iOS" / "fixtures" / "dup.json"
        path.write_text('{"schemaVersion":2,"schemaVersion":2,"kind":"photonport.gate.g004-automated.v2"}', encoding="utf-8")
        result = transition.verify(self.args(g004_automated=path))
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("duplicate_json_key", self.reason_codes(result))

    def test_malformed_utf8_exit_3(self):
        path = self.mac / "iOS" / "fixtures" / "bad-utf8.json"
        path.write_bytes(b"\xff")
        result = transition.verify(self.args(g004_automated=path))
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("malformed_utf8", self.reason_codes(result))

    def test_path_traversal_symlink_oversize_exit_3(self):
        outside = self.root / "outside.json"
        outside.write_text(json.dumps({"schemaVersion": 2, "kind": "photonport.gate.g004-automated.v2"}), encoding="utf-8")
        symlink = self.mac / "iOS" / "fixtures" / "link.json"
        symlink.symlink_to(outside)
        oversized = self.mac / "iOS" / "fixtures" / "oversized.json"
        oversized.write_bytes(b"{" + (b" " * 1048576) + b"}")
        result = transition.verify(self.args(g004_automated=outside, g004_physical=symlink, g006_provenance=oversized))
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("path_traversal", self.reason_codes(result))
        self.assertIn("symlink_input", self.reason_codes(result))
        self.assertIn("oversized_input", self.reason_codes(result))

    def test_symlink_directory_below_allowed_root_is_rejected_exit_3(self):
        real_dir = self.mac / "iOS" / "fixtures" / "real"
        real_dir.mkdir()
        receipt = real_dir / "receipt.json"
        receipt.write_text(json.dumps({"schemaVersion": 2, "kind": "photonport.gate.g004-automated.v2"}), encoding="utf-8")
        link_dir = self.mac / "iOS" / "fixtures" / "link-dir"
        link_dir.symlink_to(real_dir, target_is_directory=True)
        result = transition.verify(self.args(g004_automated=link_dir / "receipt.json"))
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("symlink_input", self.reason_codes(result))

    def test_directory_input_configuration_error_is_malformed_exit_3(self):
        directory_input = self.mac / "iOS" / "fixtures"
        result = transition.verify(self.args(g004_automated=directory_input))
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("configuration_error", self.reason_codes(result))

    def test_oserror_input_configuration_error_is_malformed_exit_3(self):
        receipt = self.write_receipt("oserror.json", {"schemaVersion": 2, "kind": "photonport.gate.g004-automated.v2"})
        previous = transition.load_json_strict

        def raise_config(path, allowed_roots):
            if path == receipt:
                raise transition.InputError("configuration_error")
            return previous(path, allowed_roots)

        transition.load_json_strict = raise_config
        try:
            result = transition.verify(self.args(g004_automated=receipt))
        finally:
            transition.load_json_strict = previous
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("configuration_error", self.reason_codes(result))

    def test_missing_optional_gate_is_blocked_exit_2(self):
        result = transition.verify(self.args())
        self.assertEqual(result["exitCode"], 2)
        self.assertIn("missing_gate_evidence", self.reason_codes(result))
        self.assertFalse(result["retirementEligible"])

    def test_current_real_v1_evidence_stays_blocked_exit_2(self):
        auto = self.write_receipt("auto.json", {"schemaVersion": 1, "kind": "legacy", "commands": [{"exitCode": 0}]})
        physical = self.write_receipt("physical.json", {"schemaVersion": 1, "kind": "legacy", "availability": "available", "scenarios": [{"status": "pass"}]})
        result = transition.verify(self.args(g004_automated=auto, g004_physical=physical))
        self.assertEqual(result["exitCode"], 2)
        self.assertIn("legacy_untrusted_v1", self.reason_codes(result))

    def test_synthetic_legacy_evidence_never_eligible(self):
        auto = self.write_receipt("auto.json", {"schemaVersion": 1, "commands": [{"exitCode": 0}]})
        physical = self.write_receipt("physical.json", {"schemaVersion": 1, "availability": "available", "scenarios": [{"status": "pass"}]})
        kwargs = dict(g004_automated=auto, g004_physical=physical,
            g006_provenance=self.write_receipt("g006.json", {"schemaVersion": 2, "kind": "photonport.gate.g006-provenance.v2", "gateId": "g006.provenance", "status": "passed"}),
            export_review=self.write_receipt("export.json", {"schemaVersion": 2, "kind": "photonport.gate.export-review.v2", "gateId": "export.review", "status": "passed"}),
            apple_distribution=self.write_receipt("apple.json", {"schemaVersion": 2, "kind": "photonport.gate.apple-distribution.v2", "gateId": "apple.distribution", "status": "passed"}),
            rollback_build=self.write_receipt("rollback.json", {"schemaVersion": 2, "kind": "photonport.gate.rollback-build.v2", "gateId": "rollback.build", "status": "passed"}))
        result = transition.verify(self.args(**kwargs))
        self.assertEqual(result["exitCode"], 2)
        self.assertFalse(result["retirementEligible"])

    def test_cli_writes_retirement_eligible_and_returns_2_for_current_blocked(self):
        output = self.mac / "iOS" / "fixtures" / "out.json"
        args = self.args(output=output)
        result = transition.verify(args)
        transition.write_atomic(output, result)
        written = json.loads(output.read_text(encoding="utf-8"))
        self.assertIn("retirementEligible", written)
        self.assertNotIn("retirementReady", written)
        self.assertEqual(written["exitCode"], 2)
        self.assertEqual(written["trustMode"], "production")

    def test_missing_release_attempt_id_blocks_typed_transition_exit_2(self):
        self.init_m1_roots()
        receipt = self.envelope("typed.json")
        result = transition.verify(self.args(g004_automated=receipt, trust_mode="test"))
        self.assertEqual(result["exitCode"], 2)
        self.assertIn("missing_release_attempt_id", self.reason_codes(result))
        self.assertFalse(result["retirementEligible"])

    def test_old_source_tuple_from_receipt_verdict_exit_3(self):
        self.init_m1_roots()
        receipt = self.envelope("old-tuple.json")

        class FakeVerifier:
            @staticmethod
            def verify_envelope(receipt_path, *, expected, trust_policy_path, trust_mode, receipt_set_paths, allowed_roots):
                return {"status": "malformed", "trusted": False, "exitCode": 3, "reasonCode": "old_source_tuple", "reason": "old tuple"}

        previous = transition.verify_receipt_api
        previous_digests = transition.verifier_digests
        transition.verify_receipt_api = FakeVerifier
        transition.verifier_digests = self.fake_digests
        try:
            result = transition.verify(self.args(g004_automated=receipt, trust_mode="test", release_attempt_id="attempt-12345678"))
        finally:
            transition.verify_receipt_api = previous
            transition.verifier_digests = previous_digests
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("old_source_tuple", self.reason_codes(result))

    def test_production_input_root_is_configuration_error_exit_3(self):
        self.init_m1_roots()
        receipt = self.envelope("prod-input-root.json")
        result = transition.verify(self.args(g004_automated=receipt, trust_mode="production", release_attempt_id="attempt-12345678", input_root=[self.root]))
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("configuration_error", self.reason_codes(result))

    def test_three_repo_drift_after_receipt_validation_exit_3(self):
        self.init_m1_roots()
        receipt = self.envelope("drift.json")
        mac = self.mac

        class FakeVerifier:
            @staticmethod
            def verify_envelope(receipt_path, *, expected, trust_policy_path, trust_mode, receipt_set_paths, allowed_roots):
                (mac / "drift.txt").write_text("dirty\n", encoding="utf-8")
                return {"status": "passed", "trusted": True, "exitCode": 0, "reasonCode": "passed", "reason": "passed"}

        previous = transition.verify_receipt_api
        previous_digests = transition.verifier_digests
        transition.verify_receipt_api = FakeVerifier
        transition.verifier_digests = self.fake_digests
        try:
            result = transition.verify(self.args(g004_automated=receipt, trust_mode="test", release_attempt_id="attempt-12345678"))
        finally:
            transition.verify_receipt_api = previous
            transition.verifier_digests = previous_digests
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("dirty_worktree", self.reason_codes(result))

    def test_transition_passes_expected_tuple_and_allowed_roots_to_receipt_api(self):
        self.init_m1_roots()
        receipt = self.envelope("valid.json")
        extra_root = self.root / "extra"
        extra_root.mkdir()
        seen = {}

        class FakeVerifier:
            @staticmethod
            def verify_envelope(receipt_path, *, expected, trust_policy_path, trust_mode, receipt_set_paths, allowed_roots):
                seen["expected"] = dict(expected)
                seen["allowed_roots"] = list(allowed_roots)
                seen["receipt_set_paths"] = list(receipt_set_paths)
                return {"status": "passed", "trusted": True, "exitCode": 0, "reasonCode": "passed", "reason": "passed"}

        previous = transition.verify_receipt_api
        previous_digests = transition.verifier_digests
        transition.verify_receipt_api = FakeVerifier
        transition.verifier_digests = self.fake_digests
        try:
            result = transition.verify(self.args(g004_automated=receipt, trust_mode="test", release_attempt_id="attempt-12345678", input_root=[extra_root], receipt_set=[receipt]))
        finally:
            transition.verify_receipt_api = previous
            transition.verifier_digests = previous_digests
        self.assertIn("macCommit", seen["expected"])
        self.assertEqual(seen["expected"]["verifier"], self.fake_digests())
        self.assertIn("protocolPinSha256", seen["expected"])
        self.assertIn(extra_root.resolve(), {root.resolve() for root in seen["allowed_roots"]})
        self.assertEqual(seen["receipt_set_paths"], [receipt])
        self.assertFalse(result["retirementEligible"])

    def test_stale_verifier_schema_trust_policy_digests_fail_through_transition_path(self):
        self.init_m1_roots()
        receipt = self.envelope("stale-digests.json")
        seen = []

        class FakeVerifier:
            @staticmethod
            def verify_envelope(receipt_path, *, expected, trust_policy_path, trust_mode, receipt_set_paths, allowed_roots):
                seen.append(expected["verifier"])
                reason = ("stale_verifier_digest", "stale_schema_digest", "stale_trust_policy_digest")[len(seen) - 1]
                return {"status": "malformed", "trusted": False, "exitCode": 3, "reasonCode": reason, "reason": reason}

        previous = transition.verify_receipt_api
        previous_digests = transition.verifier_digests
        transition.verify_receipt_api = FakeVerifier
        transition.verifier_digests = self.fake_digests
        try:
            kwargs = dict(trust_mode="test", release_attempt_id="attempt-12345678",
                          g004_automated=receipt,
                          g004_physical=self.envelope("stale-schema.json"),
                          g006_provenance=self.envelope("stale-policy.json"))
            result = transition.verify(self.args(**kwargs))
        finally:
            transition.verify_receipt_api = previous
            transition.verifier_digests = previous_digests
        self.assertEqual(result["exitCode"], 3)
        self.assertIn("stale_verifier_digest", self.reason_codes(result))
        self.assertIn("stale_schema_digest", self.reason_codes(result))
        self.assertIn("stale_trust_policy_digest", self.reason_codes(result))
        self.assertEqual(seen[0], self.fake_digests())
        self.assertEqual(result["verifier"]["receiptVerifier"], self.fake_digests())
        self.assertEqual(result["verifier"]["scriptSha256"], self.fake_digests()["scriptSha256"])
        self.assertEqual(result["verifier"]["schemaSha256"], self.fake_digests()["schemaSha256"])
        self.assertEqual(result["verifier"]["trustPolicySha256"], self.fake_digests()["trustPolicySha256"])
        self.assertEqual(result["verifier"]["ed25519ModuleSha256"], self.fake_digests()["ed25519ModuleSha256"])

    def test_test_mode_all_trusted_gate_receipts_stays_ineligible_exit_2(self):
        receipts, policy_path, release_attempt_id = self.production_receipts()
        result = transition.verify(self.args(
            **receipts,
            trust_policy=policy_path,
            trust_mode="test",
            release_attempt_id=release_attempt_id,
        ))
        self.assertEqual(result["trustMode"], "test")
        self.assertEqual(result["exitCode"], 2)
        self.assertFalse(result["retirementEligible"])
        self.assertTrue(all(gate["status"] == "passed" and gate["trusted"] for gate in result["gates"]))

    def test_production_mode_all_trusted_gate_receipts_is_retirement_eligible(self):
        receipts, policy_path, release_attempt_id = self.production_receipts()
        result = transition.verify(self.args(
            **receipts,
            trust_policy=policy_path,
            trust_mode="production",
            release_attempt_id=release_attempt_id,
        ))
        self.assertEqual(result["trustMode"], "production")
        self.assertEqual(result["exitCode"], 0)
        self.assertTrue(result["retirementEligible"])
        self.assertEqual(
            result["verifier"]["ed25519ModuleSha256"],
            transition.sha256_file(HERE / "scripts" / "evidence" / "ed25519_rfc8032.py"),
        )
        self.assertTrue(all(gate["status"] == "passed" and gate["trusted"] for gate in result["gates"]))
if __name__ == "__main__":
    unittest.main()
