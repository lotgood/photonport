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
ZERO64 = "0" * 64
MATRIX_SPEC = importlib.util.spec_from_file_location("cross_repo_matrix_source_binding", SCRIPT)
MATRIX = importlib.util.module_from_spec(MATRIX_SPEC)
MATRIX_SPEC.loader.exec_module(MATRIX)


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
    def test_positive_vector_requires_its_own_producer_and_consumer_receipts(self):
        vector_ids = ["session-v3:wifi-psk", "session-v3:usb-seed"]
        self.assertEqual(
            MATRIX.vector_specific_coverage(
                vector_ids,
                {"session-v3:wifi-psk": {"producer", "consumer"}, "session-v3:usb-seed": {"producer"}},
            ),
            ["session-v3:wifi-psk"],
        )
    def test_negative_consumer_receipt_accepts_exact_typed_rejection(self):
        self.assertTrue(
            MATRIX.exact_negative_consumer_receipt(
                b"VECTOR_RECEIPT consumer bad-length-prefix stage=mac-protocol-parser outcome=rejected\n",
                "bad-length-prefix",
            )
        )

    def test_negative_consumer_receipt_rejects_missing_receipt(self):
        self.assertFalse(MATRIX.exact_negative_consumer_receipt(b"production rejected frame\n", "bad-length-prefix"))

    def test_negative_consumer_receipt_rejects_forged_receipt(self):
        self.assertFalse(
            MATRIX.exact_negative_consumer_receipt(
                b"VECTOR_RECEIPT consumer bad-length-prefix stage=mac-protocol-parser outcome=accepted\n",
                "bad-length-prefix",
            )
        )

    def test_negative_consumer_receipt_rejects_duplicate_receipts(self):
        receipt = b"VECTOR_RECEIPT consumer bad-length-prefix stage=mac-protocol-parser outcome=rejected\n"
        self.assertFalse(MATRIX.exact_negative_consumer_receipt(receipt + receipt, "bad-length-prefix"))

    def test_negative_consumer_receipt_rejects_mismatched_id(self):
        self.assertFalse(
            MATRIX.exact_negative_consumer_receipt(
                b"VECTOR_RECEIPT consumer oversize-frame stage=mac-protocol-parser outcome=rejected\n",
                "bad-length-prefix",
            )
        )

    def test_negative_consumer_receipt_rejects_unknown_stage_and_malformed_utf8(self):
        self.assertFalse(
            MATRIX.exact_negative_consumer_receipt(
                b"VECTOR_RECEIPT consumer bad-length-prefix stage=untrusted-helper outcome=rejected\n",
                "bad-length-prefix",
            )
        )
        self.assertFalse(
            MATRIX.exact_negative_consumer_receipt(
                b"VECTOR_RECEIPT consumer bad-length-prefix stage=mac-protocol-parser outcome=rejected\xff\n",
                "bad-length-prefix",
            )
        )



if __name__ == "__main__":
    unittest.main()
