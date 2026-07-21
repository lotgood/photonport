#!/usr/bin/env python3
"""Regression tests: matrix evidence must bind the executed source snapshot.

The cross-repo matrix writer must fail closed before doing any work when a
root checkout is not the exact clean commit named by --expected-*-commit.
This makes post-hoc re-pinning impossible and guarantees a receipt can never
claim that a later evidence-recording commit (one that stores the receipt,
tooling, or docs) was the source that got executed: such a commit cannot be
the clean HEAD of the root at execution time.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "run-cross-repo-matrix.py"
MATRIX_SPEC = importlib.util.spec_from_file_location("run_cross_repo_matrix", SCRIPT)
MATRIX = importlib.util.module_from_spec(MATRIX_SPEC)
MATRIX_SPEC.loader.exec_module(MATRIX)
ZERO64 = "0" * 64


def git(root, *args):
    completed = subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout.decode("utf-8").strip()


def make_repo(root, marker):
    root.mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    (root / "source.txt").write_text(marker + "\n", encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "commit " + marker)
    return git(root, "rev-parse", "HEAD")


def run_matrix(mac, ios, protocol, expected, output):
    argv = [
        sys.executable,
        str(SCRIPT),
        "--mac-root", str(mac),
        "--ios-root", str(ios),
        "--protocol-root", str(protocol),
        "--expected-mac-commit", expected["mac"],
        "--expected-ios-commit", expected["ios"],
        "--expected-protocol-commit", expected["protocol"],
        "--expected-compatibility-digest", ZERO64,
        "--expected-normative-manifest-digest", ZERO64,
        "--output", str(output),
    ]
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


class MatrixReceiptParserTest(unittest.TestCase):
    def setUp(self):
        self.cases = []
        for case_id, platform, stage, reducer in (
            ("mac-case", "mac-client", "session-init-response", "mac-protocol-consumer"),
            ("ios-case", "ios-server", "framing-inbound", "ios-protocol-consumer"),
        ):
            baseline = {"tag": "canonical-json-v1", "value": {"message": case_id, "payload": {"accepted": True}}}
            mutation = {"tag": "canonical-json-v1", "value": {"message": case_id, "payload": {"dimension": "nonce", "value": "mutated"}}}
            ownership = {"consumerPlatform": platform, "direction": "ios-to-mac", "stage": stage}
            context = {"message": case_id, "ownership": ownership}
            self.cases.append({
                "id": case_id, "ownership": ownership, "baseline": baseline, "mutation": mutation,
                "expected": {
                    "baselineSha256": MATRIX.digest(MATRIX.recipe_bytes(baseline)),
                    "inputSha256": MATRIX.digest(MATRIX.recipe_bytes(mutation)),
                    "contextSha256": MATRIX.digest(json.dumps(context, sort_keys=True, separators=(",", ":")).encode()),
                    "context": context,
                },
                "reducer": reducer,
            })

    def receipt(self, **overrides):
        case = self.cases[0]
        fields = {
            "caseId": case["id"], "owner": "mac-client", "reducer": case["reducer"],
            "stage": case["ownership"]["stage"], **MATRIX.derived_case_hashes(case),
            "outcome": "reject_and_fail_closed",
        }
        fields.update(overrides)
        return ("VECTOR_RECEIPT v2 " + " ".join(f"{key}={value}" for key, value in fields.items()) + "\n").encode()

    def test_accepts_exact_metadata_bound_receipt(self):
        receipts = MATRIX.consumer_vector_receipts(self.receipt(), "mac-client", self.cases)
        self.assertEqual(receipts["mac-case"]["inputSha256"], self.cases[0]["expected"]["inputSha256"])
    def test_recipe_tags_are_decoded_before_hashing(self):
        self.assertEqual(MATRIX.recipe_bytes({"tag": "base64-bytes-v1", "value": "AAE="}), b"\x00\x01")
        self.assertEqual(MATRIX.recipe_bytes({"tag": "hex-bytes-v1", "value": "00ff"}), b"\x00\xff")
        with self.assertRaises(ValueError):
            MATRIX.recipe_bytes({"tag": "base64-bytes-v1", "value": "not base64"})

    def test_rejects_protocol_digest_echo_drift(self):
        self.cases[0]["expected"]["inputSha256"] = "0" * 64
        with self.assertRaises(ValueError):
            MATRIX.consumer_vector_receipts(self.receipt(), "mac-client", self.cases)

    def test_rejects_forged_recipe_digests(self):
        for field in ("baselineSha256", "inputSha256", "contextSha256"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    MATRIX.consumer_vector_receipts(self.receipt(**{field: "0" * 64}), "mac-client", self.cases)

    def test_rejects_extra_wrong_platform_duplicate_stage_owner_and_reducer(self):
        for stdout in (
            self.receipt(caseId="ios-case"),
            self.receipt(stage="wrong"),
            self.receipt(owner="ios-server"),
            self.receipt(reducer="generic-parser"),
            self.receipt() + self.receipt(),
            self.receipt()[:-1] + " alias=parser\n".encode(),
            b"VECTOR_RECEIPT v2 owner=mac-client caseId=mac-case reducer=mac-protocol-consumer stage=session-init-response baselineSha256=x inputSha256=x contextSha256=x outcome=reject_and_fail_closed\n",
        ):
            with self.subTest(stdout=stdout):
                with self.assertRaises(ValueError):
                    MATRIX.consumer_vector_receipts(stdout, "mac-client", self.cases)

    def test_rejects_malformed_non_fail_closed_and_protocol_producer_receipts(self):
        for stdout in (
            b"VECTOR_RECEIPT v2 caseId=mac-case\n",
            self.receipt(outcome="rejected"),
            b"VECTOR_RECEIPT producer mac-case\n",
            self.receipt() + b"\xff",
        ):
            with self.subTest(stdout=stdout):
                with self.assertRaises(ValueError):
                    MATRIX.consumer_vector_receipts(stdout, "mac-client", self.cases)

class MatrixSourceBindingTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="matrix-source-binding-")
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.mac = base / "mac"
        self.ios = base / "ios"
        self.protocol = base / "protocol"
        self.output = base / "out" / "automated-matrix.json"
        self.expected = {
            "mac": make_repo(self.mac, "mac"),
            "ios": make_repo(self.ios, "ios"),
            "protocol": make_repo(self.protocol, "protocol"),
        }

    def test_repin_to_unexecuted_commit_fails_closed(self):
        """A receipt can never name a commit other than the executed clean HEAD.

        This covers the evidence-recording-commit case: a commit that stores
        the receipt is created only after the run, so it can never be HEAD at
        execution time, and passing it as --expected-mac-commit must fail.
        """
        (self.mac / "later.txt").write_text("evidence-recording commit\n", encoding="utf-8")
        git(self.mac, "add", "-A")
        git(self.mac, "commit", "-q", "-m", "evidence-recording commit")
        later = git(self.mac, "rev-parse", "HEAD")
        git(self.mac, "checkout", "-q", self.expected["mac"])
        completed = run_matrix(self.mac, self.ios, self.protocol, {**self.expected, "mac": later}, self.output)
        stderr = completed.stderr.decode("utf-8", "replace")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match expected commit", stderr)
        self.assertFalse(self.output.exists(), "no receipt may be written on binding failure")

    def test_dirty_source_tree_fails_closed(self):
        (self.mac / "source.txt").write_text("edited after commit\n", encoding="utf-8")
        completed = run_matrix(self.mac, self.ios, self.protocol, self.expected, self.output)
        stderr = completed.stderr.decode("utf-8", "replace")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not a clean snapshot", stderr)
        self.assertFalse(self.output.exists(), "no receipt may be written on binding failure")

    def test_sibling_root_binding_is_enforced(self):
        (self.ios / "extra.txt").write_text("untracked\n", encoding="utf-8")
        completed = run_matrix(self.mac, self.ios, self.protocol, self.expected, self.output)
        stderr = completed.stderr.decode("utf-8", "replace")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("ios", stderr)
        self.assertIn("not a clean snapshot", stderr)

    def test_clean_matching_checkout_passes_binding_guard(self):
        completed = run_matrix(self.mac, self.ios, self.protocol, self.expected, self.output)
        stderr = completed.stderr.decode("utf-8", "replace")
        self.assertNotIn("does not match expected commit", stderr)
        self.assertNotIn("not a clean snapshot", stderr)
        # The toy repos lack protocol vectors, so the run must still fail,
        # but only after the source-binding guard has passed.
        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
