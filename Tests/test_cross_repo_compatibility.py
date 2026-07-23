import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-cross-repo-compatibility.py"
MATRIX_SCRIPT = ROOT / "scripts" / "run-cross-repo-matrix.py"
MATRIX_SPEC = importlib.util.spec_from_file_location("cross_repo_matrix", MATRIX_SCRIPT)
MATRIX = importlib.util.module_from_spec(MATRIX_SPEC)
MATRIX_SPEC.loader.exec_module(MATRIX)


class CrossRepoCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.mac = base / "mac"
        self.ios = base / "ios"
        self.protocol = base / "protocol"
        for root in (self.mac, self.ios, self.protocol):
            root.mkdir()
            self.git(root, "init")
            self.git(root, "config", "user.email", "test@example.invalid")
            self.git(root, "config", "user.name", "Test")
        (self.protocol / "COMPATIBILITY.json").write_text('{"protocol":"3.0.0"}\n', encoding="utf-8")
        (self.protocol / "NORMATIVE_MANIFEST.json").write_text('{"normative":true}\n', encoding="utf-8")
        (self.protocol / "schemas").mkdir()
        (self.protocol / "schemas" / "build-pin.schema.json").write_text(
            '{"schemaVersion":1}\n', encoding="utf-8"
        )
        self.compat_digest = self.sha(self.protocol / "COMPATIBILITY.json")
        self.normative_digest = self.sha(self.protocol / "NORMATIVE_MANIFEST.json")
        self.protocol_commit = self.commit_all(self.protocol)
        self.pin = {
            "schemaVersion": 1,
            "protocolCommit": self.protocol_commit,
            "compatibilityDigest": self.compat_digest,
            "normativeManifestDigest": self.normative_digest,
        }
        (self.mac / "ProtocolBuildPin.json").write_text(json.dumps(self.pin, sort_keys=True) + "\n", encoding="utf-8")
        (self.ios / "ProtocolBuildPin.json").write_text(json.dumps(self.pin, sort_keys=True) + "\n", encoding="utf-8")
        self.mac_commit = self.commit_all(self.mac)
        self.ios_commit = self.commit_all(self.ios)

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, root, *args, check=True):
        return subprocess.run(["git", "-C", str(root), *args], check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def commit_all(self, root):
        self.git(root, "add", ".")
        env = {
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
        }
        subprocess.run(
            ["git", "-C", str(root), "commit", "-m", "fixture"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        return self.git(root, "rev-parse", "HEAD").stdout.strip()

    def sha(self, path):
        import hashlib

        return hashlib.sha256(path.read_bytes()).hexdigest()

    def run_verifier(self, output=None, extra=None, mac=None, ios=None, protocol=None):
        output = output or Path(self.tmp.name) / "artifacts" / "receipt.json"
        command = [
            sys.executable,
            str(SCRIPT),
            "--mac-root",
            str(mac or self.mac),
            "--ios-root",
            str(ios or self.ios),
            "--protocol-root",
            str(protocol or self.protocol),
            "--output",
            str(output),
            "--expected-mac-commit",
            self.mac_commit,
            "--expected-ios-commit",
            self.ios_commit,
            "--expected-protocol-commit",
            self.protocol_commit,
            "--expected-compatibility-digest",
            self.compat_digest,
            "--expected-normative-manifest-digest",
            self.normative_digest,
        ]
        if extra:
            command.extend(extra)
        return subprocess.run(command, capture_output=True, text=True), output

    def assert_fail_closed(self, result, needle=None):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL_CLOSED", result.stderr)
        if needle:
            self.assertIn(needle, result.stderr)

    def test_success_receipt_exposes_tuple_and_pins(self):
        result, output = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(receipt["result"], "compatible")
        self.assertEqual(receipt["sourceTuple"]["protocolCommit"], self.protocol_commit)
        self.assertEqual(receipt["sourceTuple"]["compatibilityDigest"], self.compat_digest)
        self.assertEqual(receipt["verifiedConsumerPins"]["mac"]["value"], self.pin)
        self.assertEqual(receipt["verifiedConsumerPins"]["ios"]["path"], "ProtocolBuildPin.json")
        self.assertEqual(
            receipt["protocolContract"]["paths"],
            [
                "COMPATIBILITY.json",
                "NORMATIVE_MANIFEST.json",
                "schemas/build-pin.schema.json",
            ],
        )

    def test_pin_shape_is_strict(self):
        cases = [
            {**self.pin, "extra": True},
            {k: v for k, v in self.pin.items() if k != "schemaVersion"},
            {**self.pin, "protocolCommit": self.protocol_commit.upper()},
            {**self.pin, "protocolCommit": self.protocol_commit[:12]},
            [],
        ]
        valid_head = self.mac_commit
        for value in cases:
            (self.mac / "ProtocolBuildPin.json").write_text(json.dumps(value), encoding="utf-8")
            self.git(self.mac, "add", "ProtocolBuildPin.json")
            self.git(self.mac, "commit", "-m", "invalid pin shape")
            self.mac_commit = self.git(self.mac, "rev-parse", "HEAD").stdout.strip()
            result, _ = self.run_verifier()
            self.assert_fail_closed(result)
            self.git(self.mac, "reset", "--hard", valid_head)
            self.mac_commit = valid_head

    def test_malformed_stale_and_changed_pin_fail_closed(self):
        valid_head = self.mac_commit
        (self.mac / "ProtocolBuildPin.json").write_text("{", encoding="utf-8")
        self.git(self.mac, "add", "ProtocolBuildPin.json")
        self.git(self.mac, "commit", "-m", "malformed pin")
        self.mac_commit = self.git(self.mac, "rev-parse", "HEAD").stdout.strip()
        result, _ = self.run_verifier()
        self.assert_fail_closed(result, "malformed")
        self.git(self.mac, "reset", "--hard", valid_head)
        self.mac_commit = valid_head

        stale = {**self.pin, "compatibilityDigest": "0" * 64}
        (self.mac / "ProtocolBuildPin.json").write_text(json.dumps(stale), encoding="utf-8")
        self.git(self.mac, "add", "ProtocolBuildPin.json")
        self.git(self.mac, "commit", "-m", "stale")
        self.mac_commit = self.git(self.mac, "rev-parse", "HEAD").stdout.strip()
        result, _ = self.run_verifier()
        self.assert_fail_closed(result, "compatibilityDigest mismatch")
        self.git(self.mac, "reset", "--hard", valid_head)
        self.mac_commit = valid_head

        self.git(self.mac, "reset", "--hard", self.mac_commit)
        (self.mac / "ProtocolBuildPin.json").write_text(json.dumps(stale), encoding="utf-8")
        result, _ = self.run_verifier()
        self.assert_fail_closed(result, "unstaged tracked changes")

    def test_protocol_contract_files_must_be_tracked_and_clean(self):
        schema = self.protocol / "schemas" / "build-pin.schema.json"
        schema.write_text('{"schemaVersion":2}\n', encoding="utf-8")
        result, _ = self.run_verifier()
        self.assert_fail_closed(result, "protocol contract has unstaged tracked changes")

        self.git(self.protocol, "checkout", "--", "schemas/build-pin.schema.json")
        self.git(self.protocol, "rm", "--cached", "schemas/build-pin.schema.json")
        result, _ = self.run_verifier()
        self.assert_fail_closed(result, "git ls-files")

    def test_expected_tuple_mismatch_fails_closed(self):
        result, _ = self.run_verifier(extra=["--expected-protocol-commit", "d" * 40])
        self.assert_fail_closed(result, "protocol HEAD mismatch")
        result, _ = self.run_verifier(extra=["--expected-compatibility-digest", "e" * 64])
        self.assert_fail_closed(result, "COMPATIBILITY.json digest mismatch")

    def test_protocol_tag_requires_authorization_local_tag_and_exact_commit(self):
        tagged = {**self.pin, "protocolTag": "protocol/v3"}
        for root in (self.mac, self.ios):
            (root / "ProtocolBuildPin.json").write_text(json.dumps(tagged, sort_keys=True) + "\n", encoding="utf-8")
            self.git(root, "add", "ProtocolBuildPin.json")
            self.git(root, "commit", "-m", "tagged pin")
        self.mac_commit = self.git(self.mac, "rev-parse", "HEAD").stdout.strip()
        self.ios_commit = self.git(self.ios, "rev-parse", "HEAD").stdout.strip()
        result, _ = self.run_verifier()
        self.assert_fail_closed(result, "not explicitly authorized")
        result, _ = self.run_verifier(extra=["--authorize-protocol-tag", "refs/tags/protocol/v3"])
        self.assert_fail_closed(result, "not locally available")
        self.git(self.protocol, "update-ref", "refs/tags/protocol/v3", self.protocol_commit)
        result, _ = self.run_verifier(extra=["--authorize-protocol-tag", "refs/tags/protocol/v3"])
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((Path(self.tmp.name) / "artifacts" / "receipt.json").read_text())
        self.assertEqual(receipt["authorizedProtocolTag"], "protocol/v3")
        self.assertEqual(receipt["authorizedProtocolTagRef"], "refs/tags/protocol/v3")
        self.git(self.protocol, "update-ref", "refs/tags/protocol/wrong", self.protocol_commit)
        result, _ = self.run_verifier(extra=["--authorize-protocol-tag", "refs/tags/protocol/wrong"])
        self.assert_fail_closed(result, "not explicitly authorized")

    def test_fresh_path_receipt_is_semantically_equal(self):
        first, first_output = self.run_verifier()
        self.assertEqual(first.returncode, 0, first.stderr)
        clone_base = Path(self.tmp.name) / "fresh"
        shutil.copytree(self.mac, clone_base / "mac", ignore=shutil.ignore_patterns(".git"))
        shutil.copytree(self.ios, clone_base / "ios", ignore=shutil.ignore_patterns(".git"))
        shutil.copytree(self.protocol, clone_base / "protocol", ignore=shutil.ignore_patterns(".git"))
        for root in (clone_base / "mac", clone_base / "ios", clone_base / "protocol"):
            self.git(root, "init")
            self.git(root, "config", "user.email", "test@example.invalid")
            self.git(root, "config", "user.name", "Test")
        self.assertEqual(self.commit_all(clone_base / "mac"), self.mac_commit)
        self.assertEqual(self.commit_all(clone_base / "ios"), self.ios_commit)
        self.assertEqual(self.commit_all(clone_base / "protocol"), self.protocol_commit)
        second, second_output = self.run_verifier(
            output=clone_base / "receipt.json",
            mac=clone_base / "mac",
            ios=clone_base / "ios",
            protocol=clone_base / "protocol",
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(first_output.read_text()), json.loads(second_output.read_text()))


class CrossRepoMatrixInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        vectors = self.root / "vectors"
        vectors.mkdir()
        # Frozen snapshot of the real protocol schema plus one real sealed
        # case: load_negative_cases validates the full typed-transcript shape,
        # which is not hand-rollable inline.
        fixtures = Path(__file__).resolve().parent / "fixtures"
        schemas = self.root / "schemas"
        schemas.mkdir()
        shutil.copy(fixtures / "negative-vectors.schema.json",
                    schemas / "negative-vectors.schema.json")
        shutil.copy(fixtures / "negative-vectors-single-case.json",
                    vectors / "negative.json")
        (vectors / "session-v3.json").write_text(
            json.dumps({
                "protocol": "session-v3",
                "version": "3.0.0",
                "cases": [{"name": "wifi-psk"}],
                "frames": {"serverHelloWifi": {}},
            }),
            encoding="utf-8",
        )
        (vectors / "pairing-v2.json").write_text(
            json.dumps({
                "protocol": "pairing-v2",
                "version": "2.0.0",
                "outputs": {"sas": "000000"},
            }),
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_matrix_vector_inventory_is_strict_and_complete(self):
        cases = MATRIX.load_negative_cases(self.root)
        self.assertEqual([case["id"] for case in cases], ["commitment-reveal-mismatch"])
        self.assertEqual(
            MATRIX.load_positive_case_ids(self.root),
            [
                "pairing-v2:canonical",
                "session-v3:wifi-psk",
                "session-v3-frame:serverHelloWifi",
            ],
        )

        (self.root / "vectors" / "negative.json").write_text(
            '{"protocol":"negative-vectors","protocol":"negative-vectors","version":"3.0.0","cases":[]}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "FAIL_CLOSED.*duplicate key"):
            MATRIX.load_negative_cases(self.root)

    def test_matrix_rejects_duplicate_ids_non_fail_closed_outcomes_and_malformed_pins(self):
        negative_path = self.root / "vectors" / "negative.json"
        vector = json.loads(negative_path.read_text(encoding="utf-8"))

        duplicated = json.loads(json.dumps(vector))
        duplicated["cases"] = [duplicated["cases"][0], json.loads(json.dumps(duplicated["cases"][0]))]
        negative_path.write_text(json.dumps(duplicated), encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "duplicate or invalid negative vector case id"):
            MATRIX.load_negative_cases(self.root)

        softened = json.loads(json.dumps(vector))
        softened["cases"][0]["outcome"] = "accept"
        negative_path.write_text(json.dumps(softened), encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "negative vector case fields are invalid"):
            MATRIX.load_negative_cases(self.root)

        pin = self.root / "ProtocolBuildPin.json"
        pin.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "FAIL_CLOSED.*duplicate key"):
            MATRIX.read_pin(pin)
    def test_matrix_rejects_built_only_pin_reformat(self):
        pin = {
            "schemaVersion": 1,
            "protocolCommit": "a" * 40,
            "compatibilityDigest": "b" * 64,
            "normativeManifestDigest": "c" * 64,
        }
        source_path = self.root / "Mac" / "ProtocolBuildPin.json"
        source_path.parent.mkdir()
        source_path.write_text(
            json.dumps(pin, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        built_root = self.root / "Build" / "Products"
        built_path = (
            built_root
            / "Debug"
            / "PhotonPort.app"
            / "Contents"
            / "Resources"
            / "ProtocolBuildPin.json"
        )
        built_path.parent.mkdir(parents=True)
        built_path.write_text(json.dumps(pin, sort_keys=True, indent=2) + "\n", encoding="utf-8")

        source_pin, source_sha256 = MATRIX.pin_evidence(source_path)
        built_pin, built_sha256 = MATRIX.single_built_pin(built_root, "Mac")

        self.assertEqual(source_pin, built_pin)
        self.assertNotEqual(source_sha256, built_sha256)
        self.assertFalse(
            MATRIX.built_pins_match(
                pin,
                {"mac": source_pin, "ios": source_pin},
                {"mac": built_pin, "ios": built_pin},
                {"mac": source_sha256, "ios": source_sha256},
                {"mac": built_sha256, "ios": built_sha256},
            )
        )


if __name__ == "__main__":
    unittest.main()
