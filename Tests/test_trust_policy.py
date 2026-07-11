import base64
import hashlib
import hmac
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_receipt", ROOT / "scripts/evidence/verify_receipt.py")
verify_receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_receipt)

TUPLE = {
    "macCommit": "a" * 40,
    "macTree": "b" * 40,
    "iosCommit": "c" * 40,
    "iosTree": "d" * 40,
    "protocolCommit": "e" * 40,
    "protocolTree": "f" * 40,
    "protocolManifestSha256": "1" * 64,
    "protocolPinSha256": "2" * 64,
}


def payload(**overrides):
    data = {
        "schemaVersion": 2,
        "kind": "photonport.gate.g004-automated.v2",
        "receiptId": "r-g004-automated-0001",
        "releaseAttemptId": "attempt-m0m1-test-0001",
        "gateId": "g004.automated",
        "status": "passed",
        "sourceTuple": TUPLE,
        "issuer": {"kind": "agent", "identity": "fixture", "role": "test", "trustDomain": "test"},
        "verifier": {"commit": "0" * 40, "scriptSha256": "3" * 64, "schemaSha256": "4" * 64, "trustPolicySha256": "5" * 64},
        "invocation": {"tool": "unittest", "argv": ["python3", "-m", "unittest"], "cwd": ".", "toolchain": {"python": "3"}},
        "artifacts": {"inputs": [], "outputs": []},
        "children": [],
        "observationTime": "2026-07-10T00:00:00Z",
    }
    data.update(overrides)
    return data


def envelope_for(payload_value, *, keyid="test-ci-hmac-v1", alg="HMAC-SHA256-TEST"):
    payload_bytes = verify_receipt.canonical_json(payload_value)
    sig = hmac.new(bytes.fromhex("746573742d63692d686d61632d7631"), verify_receipt.dsse_pae(verify_receipt.PAYLOAD_TYPE, payload_bytes), hashlib.sha256).digest()
    return {
        "schemaVersion": 2,
        "kind": "photonport.receipt-envelope.v2",
        "payloadType": verify_receipt.PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_bytes).decode(),
        "signatures": [{"keyid": keyid, "alg": alg, "sig": base64.b64encode(sig).decode()}],
    }


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def expected(**overrides):
    data = {"releaseAttemptId": "attempt-m0m1-test-0001", "gateId": "g004.automated", "kind": "photonport.gate.g004-automated.v2", "sourceTuple": TUPLE, "verifier": {"scriptSha256": "3" * 64, "schemaSha256": "4" * 64, "trustPolicySha256": "5" * 64}}
    data.update(overrides)
    return data


class TrustPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def result_for(self, payload_value, *, keyid="test-ci-hmac-v1", alg="HMAC-SHA256-TEST", trust_mode="test", expected_value=None):
        receipt = self.tmp_path / "receipt.json"
        write_json(receipt, envelope_for(payload_value, keyid=keyid, alg=alg))
        return verify_receipt.verify_envelope(receipt, expected=expected_value or expected(), trust_policy_path=self.tmp_path / "missing-policy.json", trust_mode=trust_mode, allowed_roots=[self.tmp_path])

    def test_test_key_rejected_in_production_mode_exit_3(self):
        result = self.result_for(payload(), trust_mode="production")
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "test_key_in_production")

    def test_production_public_key_signature_unsupported_returns_blocked_exit_2(self):
        prod_payload = payload(issuer={"kind": "ci", "identity": "fixture", "role": "automated-ci", "trustDomain": "opendisplay-ci"})
        result = self.result_for(prod_payload, keyid="prod-ci-ed25519-v1", alg="ED25519-DSSE", trust_mode="production")
        self.assertEqual(result["exitCode"], 2)
        self.assertEqual(result["reasonCode"], "production_signature_verifier_unavailable")
        self.assertIs(result["trusted"], False)

    def test_valid_signature_wrong_role_or_trust_domain_exit_3(self):
        wrong_role = self.result_for(payload(issuer={"kind": "agent", "identity": "fixture", "role": "automated-ci", "trustDomain": "test"}))
        self.assertEqual(wrong_role["exitCode"], 3)
        self.assertEqual(wrong_role["reasonCode"], "wrong_role")
        wrong_domain = self.result_for(payload(issuer={"kind": "agent", "identity": "fixture", "role": "test", "trustDomain": "opendisplay-ci"}))
        self.assertEqual(wrong_domain["exitCode"], 3)
        self.assertEqual(wrong_domain["reasonCode"], "wrong_trust_domain")

    def test_gate_specific_matrix_rejects_agent_test_for_human_provider_gates_before_deferred_block(self):
        physical_payload = payload(gateId="g004.physical", kind="photonport.gate.g004-physical.v2", issuer={"kind": "human", "identity": "fixture", "role": "test", "trustDomain": "human-approval"})
        physical_expected = expected(gateId="g004.physical", kind="photonport.gate.g004-physical.v2")
        physical = self.result_for(physical_payload, keyid="prod-human-ed25519-v1", alg="ED25519-DSSE", trust_mode="production", expected_value=physical_expected)
        self.assertEqual(physical["exitCode"], 3)
        self.assertEqual(physical["reasonCode"], "wrong_role")

        provider_payload = payload(gateId="apple.distribution", kind="photonport.gate.apple-distribution.v2", issuer={"kind": "provider", "identity": "fixture", "role": "test", "trustDomain": "external-provider"})
        provider_expected = expected(gateId="apple.distribution", kind="photonport.gate.apple-distribution.v2")
        provider = self.result_for(provider_payload, keyid="prod-provider-ed25519-v1", alg="ED25519-DSSE", trust_mode="production", expected_value=provider_expected)
        self.assertEqual(provider["exitCode"], 3)
        self.assertEqual(provider["reasonCode"], "wrong_role")

    def test_physical_agent_test_blocked_is_well_formed_but_passed_is_wrong_role(self):
        physical_expected = expected(gateId="g004.physical", kind="photonport.gate.g004-physical.v2")
        blocked_payload = payload(gateId="g004.physical", kind="photonport.gate.g004-physical.v2", status="blocked")
        blocked = self.result_for(blocked_payload, expected_value=physical_expected)
        self.assertEqual(blocked["exitCode"], 2)
        self.assertEqual(blocked["reasonCode"], "payload_status_blocked")

        passed_payload = payload(gateId="g004.physical", kind="photonport.gate.g004-physical.v2", status="passed")
        passed = self.result_for(passed_payload, expected_value=physical_expected)
        self.assertEqual(passed["exitCode"], 3)
        self.assertEqual(passed["reasonCode"], "wrong_role")

    def test_physical_schema_nonpassing_else_issuer_contract_matches_runtime(self):
        schema_path = ROOT / "artifacts/schemas/gate-g004-physical-v2.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        gate_constraints = schema["allOf"][1]
        self.assertIn("else", gate_constraints)

        else_branch = gate_constraints["else"]
        self.assertEqual(else_branch["properties"]["status"]["enum"], ["failed", "blocked", "not_run"])

        issuer_variants = else_branch["properties"]["issuer"]["oneOf"]
        self.assertEqual(len(issuer_variants), 3)
        tuples = {
            (
                variant["properties"]["kind"]["const"],
                variant["properties"]["role"]["const"],
                variant["properties"]["trustDomain"]["const"],
            )
            for variant in issuer_variants
        }
        self.assertEqual(
            tuples,
            {
                ("agent", "test", "test"),
                ("ci", "automated-ci", "opendisplay-ci"),
                ("human", "release-engineer", "human-approval"),
            },
        )
        for variant in issuer_variants:
            self.assertFalse(variant["additionalProperties"])
            self.assertEqual(variant["required"], ["kind", "identity", "role", "trustDomain"])
            self.assertEqual(variant["properties"]["identity"], {"type": "string"})

    def test_missing_release_attempt_id_blocks_transition_exit_2(self):
        bad_payload = payload()
        bad_payload.pop("releaseAttemptId")
        result = self.result_for(bad_payload)
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "missing_release_attempt_id")

    def test_wrong_gate_kind_exit_3(self):
        result = self.result_for(payload(kind="photonport.gate.g004-physical.v2"))
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "wrong_gate_kind")

    def test_old_source_tuple_exit_3(self):
        old_tuple = dict(TUPLE, macCommit="9" * 40)
        result = self.result_for(payload(sourceTuple=old_tuple))
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "old_source_tuple")

    def test_old_release_attempt_exit_3(self):
        result = self.result_for(payload(releaseAttemptId="attempt-oldattempt-0001"))
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "old_release_attempt")

    def test_schema_invalid_issuer_and_status_tuples_exit_3(self):
        ci_test = self.result_for(payload(issuer={"kind": "ci", "identity": "fixture", "role": "test", "trustDomain": "test"}))
        self.assertEqual(ci_test["exitCode"], 3)
        self.assertEqual(ci_test["reasonCode"], "wrong_role")

        g006_passed = payload(gateId="g006.provenance", kind="photonport.gate.g006-provenance.v2", status="passed")
        g006_expected = expected(gateId="g006.provenance", kind="photonport.gate.g006-provenance.v2")
        status_result = self.result_for(g006_passed, expected_value=g006_expected)
        self.assertEqual(status_result["exitCode"], 3)
        self.assertEqual(status_result["reasonCode"], "gate_not_passed")

    def test_stale_verifier_schema_trust_policy_digest_exit_3(self):
        cases = [("scriptSha256", "stale_verifier_digest"), ("schemaSha256", "stale_schema_digest"), ("trustPolicySha256", "stale_trust_policy_digest")]
        for field, reason in cases:
            with self.subTest(reason=reason):
                verifier = {"scriptSha256": "3" * 64, "schemaSha256": "4" * 64, "trustPolicySha256": "5" * 64}
                verifier[field] = "9" * 64
                result = self.result_for(payload(), expected_value=expected(verifier=verifier))
                self.assertEqual(result["exitCode"], 3)
                self.assertEqual(result["reasonCode"], reason)
                self.assertEqual(result["verifier"], verifier)

    def test_expected_verifier_digests_are_mandatory_configuration_error(self):
        exp = expected()
        exp.pop("verifier")
        result = self.result_for(payload(), expected_value=exp)
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "configuration_error")


if __name__ == "__main__":
    unittest.main()
