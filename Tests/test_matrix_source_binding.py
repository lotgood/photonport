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
        reducer = "PairingExchangeState.receiveOpening"
        setup = {
            "reducer": reducer, "attemptID": "mac-case:setup", "deviceInstallID": "mac-case:setup",
            "now": 2, "openingVersion": 3, "macPublicKeyBase64": "AAECAwQFBgcICQoLDA0ODw==",
            "macNonceBase64": "AAECAwQFBgcICQoLDA0ODw==",
            "deviceNonceBase64": "AAECAwQFBgcICQoLDA0ODw==", "fixtureID": "mac-case:setup",
        }
        baseline = {**setup, "attemptID": "mac-case:baseline", "deviceInstallID": "mac-case:baseline", "fixtureID": "mac-case:baseline"}
        mutation = {**baseline, "now": 0}
        setup_hash, baseline_hash = MATRIX.digest(MATRIX.canonical_bytes(setup)), MATRIX.digest(MATRIX.canonical_bytes(baseline))
        ownership = {"consumerPlatform": "mac-client", "direction": "ios-to-mac", "stage": "session-init-response"}
        initial = {"reducer": reducer, "state": "fresh:setup", "time": 1, "acceptedInputs": [setup_hash], "effects": [{"type": "accepted-event", "role": "setup", "inputSha256": setup_hash}]}
        baseline_snapshot = {"reducer": reducer, "state": "fresh:setup:baseline", "time": 1, "acceptedInputs": [setup_hash, baseline_hash], "effects": initial["effects"] + [{"type": "accepted-event", "role": "baseline", "inputSha256": baseline_hash}]}
        operations = [
            {"op": "initialize", "state": "fresh", "time": 0},
            {"op": "consume", "role": "setup", "fixture": setup},
            {"op": "advance-time", "to": 1},
            {"op": "clone-checkpoint", "name": "pre-baseline"},
            {"op": "consume", "role": "baseline", "fixture": baseline},
            {"op": "assert-accepted"},
            {"op": "clone-checkpoint", "name": "post-baseline"},
            {"op": "consume", "role": "mutation", "fixture": mutation},
            {"op": "assert-rejected", "checkpoint": "post-baseline"},
        ]
        self.cases = [{
            "id": "mac-case", "ownership": ownership, "reducer": reducer, "message": "session",
            "outcome": "reject_and_fail_closed", "operations": operations,
            "semantic": {"changedField": "now", "mutation": "mac-case"},
            "expected": {
                "transcriptSha256": MATRIX.digest(MATRIX.canonical_bytes(operations)),
                "initialSnapshot": initial, "baselineSnapshot": baseline_snapshot,
                "finalSnapshot": baseline_snapshot, "baselineEffects": baseline_snapshot["effects"][-1:],
            },
        }]

    def receipt(self, **overrides):
        case = self.cases[0]
        fields = {
            "caseId": case["id"], "owner": "mac-client", "reducer": case["reducer"],
            "stage": case["ownership"]["stage"], **MATRIX.derived_case_hashes(case),
            "outcome": "reject_and_fail_closed",
        }
        fields.update(overrides)
        return ("VECTOR_RECEIPT v3 " + " ".join(f"{key}={value}" for key, value in fields.items()) + "\n").encode()

    def test_accepts_independently_derived_transcript_observation(self):
        receipts = MATRIX.consumer_vector_receipts(self.receipt(), "mac-client", self.cases)
        self.assertEqual(receipts["mac-case"]["transcriptSha256"], self.cases[0]["expected"]["transcriptSha256"])

    def test_rejects_setup_omission_reorder_mutation_alias_and_baseline_fixture_drift(self):
        for replacement in (
            self.cases[0]["operations"][1:],
            self.cases[0]["operations"][:1] + [self.cases[0]["operations"][2], self.cases[0]["operations"][1]] + self.cases[0]["operations"][3:],
            self.cases[0]["operations"][:7] + [{"op": "consume", "role": "mutation", "fixture": self.cases[0]["operations"][4]["fixture"]}] + self.cases[0]["operations"][8:],
            self.cases[0]["operations"][:4] + [{"op": "consume", "role": "baseline", "fixture": {**self.cases[0]["operations"][4]["fixture"], "fixtureID": "byte-drift"}}] + self.cases[0]["operations"][5:],
        ):
            case = dict(self.cases[0])
            case["operations"] = replacement
            with self.subTest(operations=replacement):
                with self.assertRaises(ValueError):
                    MATRIX.derived_case_hashes(case)
    def test_rejects_reducer_specific_fixture_shape_corruption(self):
        setup = self.cases[0]["operations"][1]["fixture"]
        for fixture in (
            {key: value for key, value in setup.items() if key != "fixtureID"},
            {**setup, "unexpected": "field"},
            {**setup, "reducer": "RuntimeFrameReducer.reduce"},
        ):
            case = dict(self.cases[0])
            case["operations"] = self.cases[0]["operations"][:1] + [
                {"op": "consume", "role": "setup", "fixture": fixture},
            ] + self.cases[0]["operations"][2:]
            with self.subTest(fixture=fixture):
                with self.assertRaises(ValueError):
                    MATRIX.derived_case_hashes(case)
    def test_rejects_semantic_id_mismatch_extra_changed_field_and_expected_echo(self):
        cases = []
        id_mismatch = dict(self.cases[0])
        id_mismatch["semantic"] = {**id_mismatch["semantic"], "mutation": "other-case"}
        cases.append(id_mismatch)

        wrong_field = dict(self.cases[0])
        wrong_field["semantic"] = {**wrong_field["semantic"], "changedField": "version"}
        cases.append(wrong_field)

        extra_change = dict(self.cases[0])
        mutation = {**extra_change["operations"][7]["fixture"], "openingVersion": 2}
        extra_change["operations"] = extra_change["operations"][:7] + [
            {"op": "consume", "role": "mutation", "fixture": mutation},
        ] + extra_change["operations"][8:]
        cases.append(extra_change)

        expected_echo = dict(self.cases[0])
        expected_echo["expected"] = {
            **expected_echo["expected"],
            "baselineSnapshot": expected_echo["expected"]["initialSnapshot"],
        }
        cases.append(expected_echo)

        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    MATRIX.derived_case_hashes(case)

    def test_rejects_forged_stage_symbol_effect_and_snapshot_hashes(self):
        for field, value in (
            ("stage", "wrong"),
            ("reducer", "generic-parser"),
            ("baselineEffectsSha256", "0" * 64),
            ("initialSnapshotSha256", "0" * 64),
            ("finalSnapshotSha256", "0" * 64),
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    MATRIX.consumer_vector_receipts(self.receipt(**{field: value}), "mac-client", self.cases)

    def test_rejects_accept_bypass_empty_placeholder_and_duplicate_or_aliased_observations(self):
        for stdout in (
            self.receipt(outcome="accepted"),
            self.receipt(initialSnapshotSha256=MATRIX.digest(b"")),
            self.receipt() + self.receipt(),
            self.receipt()[:-1] + " alias=parser\n".encode(),
            b"VECTOR_RECEIPT v3 caseId=mac-case\n",
            self.receipt().replace(b"VECTOR_RECEIPT v3 ", b"VECTOR_RECEIPT v2 "),
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
