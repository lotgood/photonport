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


def envelope_for(payload_value):
    payload_bytes = verify_receipt.canonical_json(payload_value)
    sig = hmac.new(bytes.fromhex("746573742d63692d686d61632d7631"), verify_receipt.dsse_pae(verify_receipt.PAYLOAD_TYPE, payload_bytes), hashlib.sha256).digest()
    return {
        "schemaVersion": 2,
        "kind": "photonport.receipt-envelope.v2",
        "payloadType": verify_receipt.PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_bytes).decode(),
        "signatures": [{"keyid": "test-ci-hmac-v1", "alg": "HMAC-SHA256-TEST", "sig": base64.b64encode(sig).decode()}],
    }


def write_receipt(path, payload_value):
    path.write_text(json.dumps(envelope_for(payload_value), sort_keys=True), encoding="utf-8")


def expected():
    return {"releaseAttemptId": "attempt-m0m1-test-0001", "gateId": "g004.automated", "kind": "photonport.gate.g004-automated.v2", "sourceTuple": TUPLE, "verifier": {"scriptSha256": "3" * 64, "schemaSha256": "4" * 64, "trustPolicySha256": "5" * 64}}


class ReceiptReplayDriftTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def verify(self, path, receipt_set_paths=None):
        return verify_receipt.verify_envelope(path, expected=expected(), trust_policy_path=self.tmp_path / "missing-policy.json", trust_mode="test", receipt_set_paths=receipt_set_paths or [], allowed_roots=[self.tmp_path])

    def test_duplicate_receipt_id_in_effective_set_exit_3(self):
        first = self.tmp_path / "first.json"
        second = self.tmp_path / "second.json"
        write_receipt(first, payload(status="failed"))
        write_receipt(second, payload(status="failed"))
        result = self.verify(first, [second])
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "duplicate_receipt_id")

    def test_two_active_receipts_for_one_gate_in_effective_set_exit_3(self):
        first = self.tmp_path / "first.json"
        second = self.tmp_path / "second.json"
        write_receipt(first, payload(receiptId="r-g004-automated-0001"))
        write_receipt(second, payload(receiptId="r-g004-automated-0002"))
        result = self.verify(first, [second])
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "two_active_receipts_for_gate")

    def test_effective_set_dedupes_by_resolved_path_and_rejects_wrong_attempt_or_tuple(self):
        receipt = self.tmp_path / "receipt.json"
        write_receipt(receipt, payload())
        ok = self.verify(receipt, [receipt])
        self.assertEqual(ok["exitCode"], 0)
        self.assertEqual(len(ok["checkedReceiptSet"]), 1)

        wrong_attempt = self.tmp_path / "wrong-attempt.json"
        write_receipt(wrong_attempt, payload(receiptId="r-g004-automated-0002", releaseAttemptId="attempt-oldattempt-0001"))
        result = self.verify(receipt, [wrong_attempt])
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "old_release_attempt")

        wrong_tuple = self.tmp_path / "wrong-tuple.json"
        write_receipt(wrong_tuple, payload(receiptId="r-g004-automated-0003", status="failed", sourceTuple=dict(TUPLE, macTree="9" * 40)))
        result = self.verify(receipt, [wrong_tuple])
        self.assertEqual(result["exitCode"], 3)
        self.assertEqual(result["reasonCode"], "old_source_tuple")

    def test_verify_receipt_compares_supplied_tuple_only_and_performs_no_git_drift(self):
        receipt = self.tmp_path / "receipt.json"
        write_receipt(receipt, payload())
        (self.tmp_path / ".git").mkdir()
        (self.tmp_path / "dirty-untracked-file").write_text("verify_receipt must not inspect git state", encoding="utf-8")
        result = self.verify(receipt)
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(result["reasonCode"], "passed")

    def test_strict_loader_rejects_duplicate_keys_malformed_utf8_oversize_and_bad_base64(self):
        duplicate = self.tmp_path / "duplicate.json"
        duplicate.write_text('{"a":1,"a":2}', encoding="utf-8")
        with self.assertRaises(verify_receipt.ReceiptError) as context:
            verify_receipt.load_json_strict(duplicate, allowed_roots=[self.tmp_path])
        self.assertEqual(context.exception.code, "duplicate_json_key")

        bad_utf8 = self.tmp_path / "bad-utf8.json"
        bad_utf8.write_bytes(b"\xff")
        result = self.verify(bad_utf8)
        self.assertEqual(result["reasonCode"], "malformed_utf8")

        oversized = self.tmp_path / "oversized.json"
        oversized.write_bytes(b" " * (verify_receipt.MAX_BYTES + 1))
        result = self.verify(oversized)
        self.assertEqual(result["reasonCode"], "oversized_input")

        receipt = self.tmp_path / "bad-b64.json"
        env = envelope_for(payload())
        env["payload"] = env["payload"].rstrip("=")
        receipt.write_text(json.dumps(env), encoding="utf-8")
        result = self.verify(receipt)
        self.assertEqual(result["reasonCode"], "bad_payload_base64")


if __name__ == "__main__":
    unittest.main()
