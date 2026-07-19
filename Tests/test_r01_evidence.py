#!/usr/bin/env python3
"""Adversarial CLI coverage for evidence-only R01 validators and runners."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "scripts" / "evidence"
SCRIPTS = {
    "runtime": "validate-r01-runtime-rollback.py",
    "generation": "validate-r01-generation-classification.py",
    "preservation": "run-r01-preservation-mutations.py",
    "fresh": "verify-r01-fresh-build.py",
}


def dump(path, value):
    path.write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(root, path):
    item = root / path
    return {"path": path, "sha256": digest(item), "size": item.stat().st_size}


def run(name, *args):
    return subprocess.run([sys.executable, str(EVIDENCE / SCRIPTS[name]), *map(str, args)], text=True, capture_output=True)


class R01EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.tuple = {"macCommit": "a" * 40, "iosCommit": "b" * 40, "protocolCommit": "c" * 40,
                      "compatibilityDigest": "d" * 64, "normativeManifestDigest": "e" * 64}

    def tearDown(self):
        self.temp.cleanup()

    def git_root(self, name, commit_key=None):
        root = self.base / name
        root.mkdir()
        subprocess.run(["git", "init", "-q", root], check=True)
        subprocess.run(["git", "-C", root, "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", root, "config", "user.name", "test"], check=True)
        (root / "tracked").write_text(name)
        subprocess.run(["git", "-C", root, "add", "."], check=True)
        subprocess.run(["git", "-C", root, "commit", "-qm", "fixture"], check=True)
        actual = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
        if commit_key:
            self.tuple[commit_key] = actual
        return root

    def test_all_r01_schemas_are_present_and_versioned(self):
        names = ("r01-runtime-rollback-request-v1.schema.json", "r01-runtime-rollback-result-v1.schema.json",
                 "r01-generation-classification-request-v1.schema.json", "r01-generation-classification-result-v1.schema.json",
                 "r01-preservation-closure-manifest-v1.schema.json", "r01-preservation-mutation-result-v1.schema.json",
                 "r01-fresh-build-request-v1.schema.json", "r01-fresh-build-result-v1.schema.json")
        for name in names:
            schema = json.loads((ROOT / "artifacts" / "schemas" / name).read_text())
            self.assertEqual(schema.get("$schema"), "https://json-schema.org/draft/2020-12/schema")
            self.assertIn("required", schema)
            self.assertFalse(schema.get("additionalProperties", True))

    def test_runtime_blocked_and_rejects_malformed_outside_and_tuple_mismatch(self):
        evidence = self.base / "evidence"; logs = evidence / "logs"; logs.mkdir(parents=True)
        for name in ("build", "install", "watchdog", "parser"):
            (logs / name).write_text(name)
        roots = [self.git_root(name, key) for name, key in (("mac", "macCommit"), ("ios", "iosCommit"), ("protocol", "protocolCommit"))]
        request = {"schemaVersion": 1, "kind": "photonport.r01-runtime-rollback-request.v1", "sourceTuple": self.tuple,
                   "host": {"family": "macOS", "majorVersion": 27, "identitySha256": "1" * 64},
                   "device": {"family": "iOS", "majorVersion": 27, "identitySha256": "2" * 64},
                   "build": artifact(evidence, "logs/build"), "install": artifact(evidence, "logs/install"),
                   "observations": [{"transport": "usb", "observer": "test", "recordedAt": "now", "watchdogLog": artifact(evidence, "logs/watchdog"), "strictParserLog": artifact(evidence, "logs/parser"), "ping": {"deviceIdentitySha256": "2" * 64, "result": "id-bearing-ping-passed"}}]}
        path = evidence / "request.json"; output = evidence / "result.json"; dump(path, request)
        args = ("--request", path, "--evidence-root", evidence, "--evidence-dir", logs, "--mac-root", roots[0], "--ios-root", roots[1], "--protocol-root", roots[2], "--output", output)
        result = run("runtime", *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        verdict = json.loads(output.read_text())
        self.assertEqual(verdict["status"], "blocked")
        self.assertFalse(verdict["retirementEligible"]); self.assertFalse(verdict["deletionAuthorized"])
        path.write_bytes(b'{"schemaVersion":1,"schemaVersion":1}\n')
        self.assertNotEqual(run("runtime", *args).returncode, 0)
        request["build"]["path"] = "../outside"; dump(path, request)
        self.assertNotEqual(run("runtime", *args).returncode, 0)
        request["build"] = artifact(evidence, "logs/build"); request["sourceTuple"]["macCommit"] = "f" * 40; dump(path, request)
        self.assertNotEqual(run("runtime", *args).returncode, 0)

    def test_generation_archival_only_is_blocked_and_schema_violation_fails_closed(self):
        request = {"schemaVersion": 1, "kind": "photonport.r01-generation-classification-request.v1", "sourceTuple": self.tuple,
                   "sourceHashes": {"mac": "1" * 64, "ios": "2" * 64, "protocol": "3" * 64}, "classification": "archival_only", "durableEvidence": []}
        path = self.base / "request"; output = self.base / "result"; dump(path, request)
        result = run("generation", "--request", path, "--output", output)
        self.assertEqual(result.returncode, 2)
        verdict = json.loads(output.read_text()); self.assertEqual(verdict["status"], "blocked")
        self.assertNotIn("retirementEligible", verdict); self.assertNotIn("remediationAuthorized", verdict)
        request["durableEvidence"] = [{"id": "illegal", "sha256": "4" * 64}]; dump(path, request)
        self.assertNotEqual(run("generation", "--request", path, "--output", self.base / "bad").returncode, 0)

    def test_preservation_refuses_non_throwaway_and_incomplete_manifest(self):
        clone = self.base / "clone"; clone.mkdir(); member = clone / "keep"; member.write_text("preserve")
        registered_clone = clone.resolve()
        registration = {"canonicalPath": str(registered_clone), "dev": clone.stat().st_dev, "ino": clone.stat().st_ino, "registrationId": "a" * 64, "purpose": "throwaway-clone"}
        manifest = {"schemaVersion": 1, "kind": "photonport.r01-preservation-closure-manifest.v1", "registeredCloneRoot": registration, "members": [{"path": "keep", "sha256": digest(member), "size": member.stat().st_size}]}
        path = self.base / "manifest"; dump(path, manifest)
        result = run("preservation", "--manifest", path, "--clone-root", registered_clone, "--registration-id", "a" * 64, "--output", self.base / "result")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.base / "result").read_text())["result"], "passed")
        manifest["registeredCloneRoot"]["purpose"] = "production"; dump(path, manifest)
        self.assertNotEqual(run("preservation", "--manifest", path, "--clone-root", registered_clone, "--registration-id", "a" * 64, "--output", self.base / "nonthrowaway").returncode, 0)
        manifest["registeredCloneRoot"]["purpose"] = "throwaway-clone"; manifest["members"].append({"path": "missing", "sha256": "b" * 64, "size": 0}); dump(path, manifest)
        self.assertNotEqual(run("preservation", "--manifest", path, "--clone-root", registered_clone, "--registration-id", "a" * 64, "--output", self.base / "incomplete").returncode, 0)

    def test_fresh_build_not_run_and_stale_generated_output_fail_closed(self):
        clone = self.git_root("ios", "iosCommit")
        for name in ("generator", "project", "manifest", "debug", "release"):
            (clone / name).write_text(name)
        subprocess.run(["git", "-C", clone, "add", "."], check=True); subprocess.run(["git", "-C", clone, "commit", "-qm", "inputs"], check=True)
        self.tuple["iosCommit"] = subprocess.run(["git", "-C", clone, "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
        request = {"schemaVersion": 1, "kind": "photonport.r01-fresh-build-request.v1", "sourceTuple": self.tuple,
                   "generator": {"path": "generator", "sha256": digest(clone / "generator")}, "project": {"path": "project", "sha256": digest(clone / "project")}, "sourceManifest": {"path": "manifest", "sha256": digest(clone / "manifest")}, "products": {"Debug": "debug", "Release": "release"}}
        request_path = self.base / "request"; result_path = self.base / "build-result"; output = self.base / "verdict"; dump(request_path, request)
        not_run = {"schemaVersion": 1, "kind": "photonport.r01-fresh-build-result.v1", "status": "not_run", "requestSha256": digest(request_path), "reason": "human build unavailable"}; dump(result_path, not_run)
        result = run("fresh", "--clone-root", clone, "--request", request_path, "--result", result_path, "--output", output)
        self.assertEqual(result.returncode, 0, result.stderr); verdict = json.loads(output.read_text()); self.assertEqual(verdict["status"], "not_run"); self.assertNotIn("retirementEligible", verdict)
        passed = {"schemaVersion": 1, "kind": "photonport.r01-fresh-build-result.v1", "status": "passed", "requestSha256": digest(request_path), "cleanClone": {"gitHead": self.tuple["iosCommit"], "gitStatusPorcelain": "", "projectAbsentBeforeGeneration": True}, "generation": {key: request[key] for key in ("generator", "project", "sourceManifest")}, "products": {name: {"path": request["products"][name], "sha256": digest(clone / request["products"][name])} for name in ("Debug", "Release")}}
        (clone / "debug").write_text("stale replacement"); dump(result_path, passed)
        self.assertNotEqual(run("fresh", "--clone-root", clone, "--request", request_path, "--result", result_path, "--output", self.base / "stale").returncode, 0)

    def test_fresh_build_rejects_symlinked_clone_root(self):
        target = self.base / "target"; target.mkdir(); link = self.base / "link"; link.symlink_to(target, target_is_directory=True)
        request = self.base / "request"; result = self.base / "result"; dump(request, {}); dump(result, {})
        self.assertNotEqual(run("fresh", "--clone-root", link, "--request", request, "--result", result, "--output", self.base / "output").returncode, 0)


if __name__ == "__main__":
    unittest.main()
