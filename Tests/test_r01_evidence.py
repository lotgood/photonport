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
def digest_value(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


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
            if "oneOf" in schema:
                self.assertTrue(schema["oneOf"])
                self.assertTrue(all("$ref" in branch for branch in schema["oneOf"]))
            else:
                self.assertIn("required", schema)
                self.assertFalse(schema.get("additionalProperties", True))

    def test_runtime_requires_typed_proofs_and_durable_bytes(self):
        evidence = self.base / "evidence"; logs = evidence / "logs"; logs.mkdir(parents=True)
        for name in ("build", "install", "watchdog", "parser"):
            (logs / name).write_text(name)
        roots = [self.git_root(name, key) for name, key in (("mac", "macCommit"), ("ios", "iosCommit"), ("protocol", "protocolCommit"))]
        request = {"schemaVersion": 1, "kind": "photonport.r01-runtime-rollback-request.v1", "sourceTuple": self.tuple,
                   "host": {"family": "macOS", "majorVersion": 27, "identitySha256": "1" * 64},
                   "device": {"family": "iOS", "majorVersion": 27, "identitySha256": "2" * 64},
                   "build": artifact(evidence, "logs/build"), "install": artifact(evidence, "logs/install"),
                   "observations": [{"transport": "usb", "observer": "test", "recordedAt": "2026-07-19T12:00:00Z", "watchdogLog": artifact(evidence, "logs/watchdog"), "strictParserLog": artifact(evidence, "logs/parser"), "ping": {"deviceIdentitySha256": "2" * 64, "result": "id-bearing-ping-passed"}}]}
        path = evidence / "request.json"; output = evidence / "result.json"; dump(path, request)
        args = ("--request", path, "--evidence-root", evidence, "--evidence-dir", logs, "--mac-root", roots[0], "--ios-root", roots[1], "--protocol-root", roots[2], "--output", output)

        # Mere words that claim success are not typed watchdog/parser proof.
        self.assertNotEqual(run("runtime", *args).returncode, 0)
        for field in ("watchdogLog", "strictParserLog"):
            request["observations"][0][field] = artifact(evidence, "logs/watchdog" if field == "watchdogLog" else "logs/parser")
        request["observations"][0]["recordedAt"] = "not-a-timestamp"; dump(path, request)
        self.assertNotEqual(run("runtime", *args).returncode, 0)

        request["observations"][0]["recordedAt"] = "2026-07-19T12:00:00Z"
        request["build"]["sha256"] = "0" * 64; dump(path, request)
        self.assertNotEqual(run("runtime", *args).returncode, 0)
        request["build"] = {"path": "logs/missing", "sha256": "0" * 64, "size": 0}; dump(path, request)
        self.assertNotEqual(run("runtime", *args).returncode, 0)
        request["build"] = artifact(evidence, "logs/build"); request["sourceTuple"]["macCommit"] = "f" * 40; dump(path, request)
        self.assertNotEqual(run("runtime", *args).returncode, 0)
        path.write_bytes(b'{"schemaVersion":1,"schemaVersion":1}\n')
        self.assertNotEqual(run("runtime", *args).returncode, 0)

    def test_generation_validates_rooted_proof_chain_and_blocks_archival_only(self):
        artifacts = self.base / "artifacts"; artifacts.mkdir()
        tuple_ = {key: self.tuple[key] for key in ("macCommit", "iosCommit", "protocolCommit")}
        lineage = {"sourceRootSha256": "1" * 64, "sourceManifestSha256": "2" * 64}
        proof = {"schemaVersion": 1, "kind": "r01-durable-generation-proof-v1", "tuple": tuple_,
                 "sourceLineage": lineage, "generation": 1, "previousProofSha256": None}
        proof_path = artifacts / "proof.json"; dump(proof_path, proof)
        request = {"schemaVersion": 1, "kind": "r01-generation-classification-request-v1",
                   "classification": "archival_only", "tuple": tuple_, "sourceLineage": lineage,
                   "durableGenerationProof": proof,
                   "artifacts": {"proofChain": [{"path": "proof.json", "sha256": digest(proof_path)}]}}
        path = self.base / "request"; result = self.base / "result"; dump(path, request)
        completed = run("generation", "--request", path, "--artifact-root", artifacts, "--result", result)
        self.assertEqual(completed.returncode, 2)
        verdict = json.loads(result.read_text())
        self.assertEqual(verdict["status"], "blocked")
        self.assertNotIn("retirementEligible", verdict)
        self.assertNotIn("remediationAuthorized", verdict)

        request["classification"] = "durable_generation"
        request["artifacts"]["proofChain"][0]["sha256"] = "0" * 64
        dump(path, request)
        self.assertNotEqual(run("generation", "--request", path, "--artifact-root", artifacts,
                                "--result", self.base / "bad-hash").returncode, 0)
        request["artifacts"]["proofChain"][0]["sha256"] = digest(proof_path)
        request["durableGenerationProof"]["tuple"]["macCommit"] = "f" * 40
        dump(path, request)
        self.assertNotEqual(run("generation", "--request", path, "--artifact-root", artifacts,
                                "--result", self.base / "bad-tuple").returncode, 0)

    def test_preservation_requires_allocator_registration_and_complete_inventory(self):
        clone = self.git_root("clone")
        member = clone / "keep"; member.write_text("preserve")
        subprocess.run(["git", "-C", clone, "add", "keep"], check=True)
        subprocess.run(["git", "-C", clone, "commit", "-qm", "keep"], check=True)
        root = {"canonicalPath": str(clone.resolve()), "dev": clone.stat().st_dev, "ino": clone.stat().st_ino}
        common = subprocess.run(["git", "-C", clone, "rev-parse", "--path-format=absolute", "--git-common-dir"],
                                text=True, capture_output=True, check=True).stdout.strip()
        common_info = Path(common).stat()
        registry = self.base / "registry"; registry.mkdir()
        lifecycle = self.base / "lifecycle"; lifecycle.mkdir()
        registration = {"schemaVersion": 1, "kind": "disposable-worktree-registration", **root,
                        "registrationId": "a" * 64, "purpose": "throwaway-clone", "lifecycleId": "life",
                        "commonDir": common, "authoritativeInventory": {"members": ["keep"]},
                        "authoritativeInventorySha256": digest_value({"members": ["keep"]})}
        registration_path = registry / "registration.json"; dump(registration_path, registration)
        authority = {"approvedSequence": 1, "root": root, "supervisor": "test", "command": "test",
                     "allocationNonce": "a", "mutexNonce": "b", "lockAPath": "/tmp/a", "lockBPath": "/tmp/b",
                     "registryPath": str(registry.resolve()), "commonGitDir": common}
        allocated = {"schemaVersion": 1, "kind": "photonport.lifecycle-state.v1", "lifecycleId": "life",
                     "rootId": "root", "tuple": self.tuple, "allocation": {}, "authority": authority,
                     "state": "allocated", "predecessorSha256": None}
        allocated_path = lifecycle / "000-allocated.json"; dump(allocated_path, allocated)
        state = {**allocated, "state": "source-active", "predecessorSha256": digest(allocated_path),
                 "allocationReleaseSha256": "b" * 64}
        state_path = lifecycle / "010-source-active.json"; dump(state_path, state)
        registration_sha = digest(registration_path)
        inventory = {"schemaVersion": 1, "kind": "photonport.r01-preservation-target-inventory.v1",
                     "lifecycleId": "life", "rootId": "root", "root": root, "commonGitDir": common,
                     "commonGitDirDev": common_info.st_dev, "commonGitDirIno": common_info.st_ino,
                     "registrationSha256": registration_sha, "registrationId": "a" * 64,
                     "authoritativeInventorySha256": registration["authoritativeInventorySha256"], "members": ["keep"]}
        inventory_path = self.base / "inventory.json"; dump(inventory_path, inventory)
        manifest = {**inventory, "kind": "photonport.r01-preservation-closure-manifest.v1",
                    "inventorySha256": digest_value(inventory)}
        manifest_path = self.base / "manifest.json"; dump(manifest_path, manifest)
        args = ("--registration", registration_path, "--lifecycle-state", state_path,
                "--lifecycle-directory", lifecycle, "--manifest", manifest_path, "--inventory", inventory_path,
                "--root", clone, "--operation", "rename", "--result", self.base / "result.json")
        self.assertEqual(run("preservation", *args).returncode, 0)
        self.assertFalse(member.exists())
        self.assertTrue((clone / "keep.r01-preservation-renamed").exists())

        bad_registration = self.base / "self-authored.json"; dump(bad_registration, registration)
        self.assertNotEqual(run("preservation", "--registration", bad_registration, "--lifecycle-state", state_path,
                                "--lifecycle-directory", lifecycle, "--manifest", manifest_path,
                                "--inventory", inventory_path, "--root", clone, "--operation", "delete",
                                "--result", self.base / "self-authored-result.json").returncode, 0)
        inventory["members"] = ["missing"]; dump(inventory_path, inventory)
        self.assertNotEqual(run("preservation", "--registration", registration_path, "--lifecycle-state", state_path,
                                "--lifecycle-directory", lifecycle, "--manifest", manifest_path,
                                "--inventory", inventory_path, "--root", clone, "--operation", "delete",
                                "--result", self.base / "incomplete-result.json").returncode, 0)

    def test_fresh_build_not_run_requires_clean_tuple_roots_and_no_stale_outputs(self):
        roots = {name: self.git_root(name, name + "Commit") for name in ("mac", "ios", "protocol")}
        evidence = self.base / "evidence"; evidence.mkdir()
        request = {"schemaVersion": 1, "kind": "photonport.r01-fresh-build-request.v1",
                   "sourceTuple": self.tuple, "sourceRoots": {name: str(root) for name, root in roots.items()},
                   "result": "not_run"}
        request_path = evidence / "r01-fresh-build-request.json"; dump(request_path, request)
        completed = run("fresh", "--evidence-root", evidence)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        verdict = json.loads((evidence / "r01-fresh-build-result.json").read_text())
        self.assertEqual(verdict["result"], "not_run")
        self.assertNotIn("retirementEligible", verdict)
        self.assertNotIn("remediationAuthorized", verdict)

        (roots["ios"] / "tracked.xcodeproj").mkdir()
        self.assertNotEqual(run("fresh", "--evidence-root", evidence,
                                "--result", "stale-result.json").returncode, 0)
        (roots["ios"] / "tracked.xcodeproj").rmdir()
        (roots["ios"] / "caller-asserted").write_text("fresh")
        self.assertNotEqual(run("fresh", "--evidence-root", evidence,
                                "--result", "dirty-result.json").returncode, 0)

    def test_r01_result_schemas_never_grant_mutation_authority(self):
        names = ("r01-runtime-rollback-result-v1.schema.json",
                 "r01-generation-classification-result-v1.schema.json",
                 "r01-preservation-mutation-result-v1.schema.json",
                 "r01-fresh-build-result-v1.schema.json")
        forbidden = ("remediation", "retirement", "delete", "deletion")
        for name in names:
            schema = json.loads((ROOT / "artifacts" / "schemas" / name).read_text())
            properties = schema.get("properties", {})
            for key, value in properties.items():
                if any(word in key.lower() for word in forbidden):
                    self.assertEqual(value, {"const": False}, f"{name} must deny {key}")
    def test_fresh_build_rejects_symlinked_evidence_root(self):
        target = self.base / "target"; target.mkdir()
        link = self.base / "link"; link.symlink_to(target, target_is_directory=True)
        self.assertNotEqual(run("fresh", "--evidence-root", link).returncode, 0)


if __name__ == "__main__":
    unittest.main()
