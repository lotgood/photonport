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


def envelope_for(payload_value, keyid="test-ci-hmac-v1", alg="HMAC-SHA256-TEST"):
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


def expected():
    return {"releaseAttemptId": "attempt-m0m1-test-0001", "gateId": "g004.automated", "kind": "photonport.gate.g004-automated.v2", "sourceTuple": TUPLE, "verifier": {"scriptSha256": "3" * 64, "schemaSha256": "4" * 64, "trustPolicySha256": "5" * 64}}


class ReceiptEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def verify(self, receipt, **kwargs):
        return verify_receipt.verify_envelope(
            receipt,
            expected=kwargs.pop("expected", expected()),
            trust_policy_path=self.tmp_path / "missing-policy.json",
            trust_mode=kwargs.pop("trust_mode", "test"),
            allowed_roots=kwargs.pop("allowed_roots", [self.tmp_path]),
            **kwargs,
        )

    def test_dsse_payload_type_and_pae_bytes_are_exact(self):
        self.assertEqual(verify_receipt.dsse_pae("x", b"abc"), b"DSSEv1 1 x 3 abc")
        self.assertEqual(
            verify_receipt.dsse_pae(verify_receipt.PAYLOAD_TYPE, b"{}"),
            b"DSSEv1 50 application/vnd.photonport.receipt.payload.v2+json 2 {}",
        )

    def test_envelope_rejects_zero_or_multiple_signatures(self):
        cases = [([], "unsigned_envelope"), ([{"keyid": "test-ci-hmac-v1", "alg": "HMAC-SHA256-TEST", "sig": "AAAA="}] * 2, "invalid_signature")]
        for signatures, reason in cases:
            with self.subTest(reason=reason):
                env = envelope_for(payload())
                env["signatures"] = signatures
                receipt = self.tmp_path / f"{reason}.json"
                write_json(receipt, env)
                result = self.verify(receipt)
                self.assertEqual(result["exitCode"], 3)
                self.assertEqual(result["reasonCode"], reason)

    def test_canonical_payload_bytes_are_signed(self):
        env = envelope_for(payload())
        decoded = base64.b64decode(env["payload"])
        env["payload"] = base64.b64encode(json.dumps(json.loads(decoded), indent=2).encode()).decode()
        receipt = self.tmp_path / "receipt.json"
        write_json(receipt, env)
        result = self.verify(receipt)
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "payload_not_canonical")

    def test_valid_schema_invalid_signature_exit_3(self):
        env = envelope_for(payload())
        env["signatures"][0]["sig"] = base64.b64encode(b"bad" * 11).decode()
        receipt = self.tmp_path / "receipt.json"
        write_json(receipt, env)
        result = self.verify(receipt)
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "invalid_signature")

    def test_test_hmac_signature_valid_in_test_mode_only(self):
        receipt = self.tmp_path / "receipt.json"
        write_json(receipt, envelope_for(payload()))
        result = self.verify(receipt)
        self.assertEqual(result["exitCode"], 0)
        self.assertIs(result["trusted"], True)
        self.assertEqual(result["verifier"], expected()["verifier"])

    def test_changed_child_payload_or_envelope_hash_exit_3(self):
        child = payload(receiptId="r-child-receipt-0001", gateId="g006.provenance", kind="photonport.gate.g006-provenance.v2", status="failed")
        child_path = self.tmp_path / "child.json"
        write_json(child_path, envelope_for(child))
        parent = payload(children=[{"receiptId": "r-child-receipt-0001", "gateId": "g006.provenance", "payloadSha256": "0" * 64, "envelopeSha256": "0" * 64}])
        parent_path = self.tmp_path / "parent.json"
        write_json(parent_path, envelope_for(parent))
        result = self.verify(parent_path, receipt_set_paths=[child_path])
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "child_hash_mismatch")

    def test_allowed_roots_input_root_test_mode_only_and_symlink_rejected_exit_3(self):
        receipt = self.tmp_path / "receipt.json"
        write_json(receipt, envelope_for(payload()))
        outside = self.tmp_path.parent / "outside-receipt.json"
        write_json(outside, envelope_for(payload(receiptId="r-outside-receipt-1")))
        self.addCleanup(lambda: outside.exists() and outside.unlink())
        self.assertEqual(self.verify(outside)["reasonCode"], "path_traversal")
        link = self.tmp_path / "link.json"
        link.symlink_to(receipt)
        self.assertEqual(self.verify(link)["reasonCode"], "symlink_input")

    def test_schema_rejects_missing_extra_and_invalid_nested_payload_fields(self):
        cases = []
        missing = payload()
        missing.pop("issuer")
        cases.append((missing, "unknown_receipt_kind"))
        extra = payload(extraField=True)
        cases.append((extra, "unknown_receipt_kind"))
        invalid_nested = payload(artifacts={"inputs": [{"path": "../escape", "sha256": "6" * 64, "size": 1}], "outputs": []})
        cases.append((invalid_nested, "unknown_receipt_kind"))
        invalid_time = payload(observationTime="2026-07-10T00:00:00+00:00")
        cases.append((invalid_time, "unknown_receipt_kind"))
        for index, (payload_value, reason) in enumerate(cases):
            with self.subTest(index=index):
                receipt = self.tmp_path / f"schema-{index}.json"
                write_json(receipt, envelope_for(payload_value))
                result = self.verify(receipt)
                self.assertEqual(result["exitCode"], 3)
                self.assertEqual(result["reasonCode"], reason)

    def test_symlink_directory_below_allowed_root_is_rejected_exit_3(self):
        real_dir = self.tmp_path / "real"
        real_dir.mkdir()
        write_json(real_dir / "receipt.json", envelope_for(payload()))
        link_dir = self.tmp_path / "link-dir"
        link_dir.symlink_to(real_dir, target_is_directory=True)
        result = self.verify(link_dir / "receipt.json")
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "symlink_input")


if __name__ == "__main__":
    unittest.main()
