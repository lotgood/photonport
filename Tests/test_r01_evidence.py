#!/usr/bin/env python3
"""R01 validators reject caller assertions and require production DSSE evidence."""
import base64
import hashlib
import hmac
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "scripts" / "evidence"
SEED = bytes.fromhex("11" * 32)
TUPLE = {"macCommit": "a" * 40, "iosCommit": "b" * 40, "protocolCommit": "c" * 40}
ALT_SEED = bytes.fromhex("22" * 32)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def dump(path, value):
    path.write_bytes(canonical(value) + b"\n")


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def descriptor(path, relative):
    raw = (path / relative).read_bytes()
    return {"path": relative, "sha256": digest_bytes(raw)}


class R01EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.tools = self.base / "evidence"
        shutil.copytree(EVIDENCE, self.tools)
        spec = importlib.util.spec_from_file_location("r01_ed25519", self.tools / "ed25519_rfc8032.py")
        self.ed25519 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ed25519)
        self.policy = json.loads((self.tools / "trust-policy.json").read_text())
        self.policy["productionRoot"]["keys"]["prod-ci-ed25519-v1"]["publicKeyHex"] = self.ed25519.public_key(SEED).hex()
        dump(self.tools / "trust-policy.json", self.policy)

    def tearDown(self):
        self.temp.cleanup()

    def run_tool(self, script, *args):
        return subprocess.run([sys.executable, str(self.tools / script), *map(str, args)], text=True, capture_output=True)

    def envelope(self, payload, *, forged=False, seed=SEED, keyid="prod-ci-ed25519-v1", alg="ED25519-DSSE"):
        verifier_spec = importlib.util.spec_from_file_location("r01_receipt", self.tools / "verify_receipt.py")
        verifier = importlib.util.module_from_spec(verifier_spec)
        verifier_spec.loader.exec_module(verifier)
        body = verifier.canonical_json(payload)
        signature = self.ed25519.sign(seed, verifier.dsse_pae(verifier.PAYLOAD_TYPE, body))
        if forged:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return {"schemaVersion": 2, "kind": "photonport.receipt-envelope.v2", "payloadType": verifier.PAYLOAD_TYPE,
                "payload": base64.b64encode(body).decode("ascii"),
                "signatures": [{"keyid": keyid, "alg": alg, "sig": base64.b64encode(signature).decode("ascii")}]}
    def make_test_mode_envelope(self, payload):
        verifier_spec = importlib.util.spec_from_file_location("r01_test_receipt", self.tools / "verify_receipt.py")
        verifier = importlib.util.module_from_spec(verifier_spec)
        verifier_spec.loader.exec_module(verifier)
        body = verifier.canonical_json(payload)
        signature = hmac.new(bytes.fromhex(self.policy["testRoot"]["keys"]["test-ci-hmac-v1"]["keyHex"]),
                             verifier.dsse_pae(verifier.PAYLOAD_TYPE, body), hashlib.sha256).digest()
        return {"schemaVersion": 2, "kind": "photonport.receipt-envelope.v2", "payloadType": verifier.PAYLOAD_TYPE,
                "payload": base64.b64encode(body).decode("ascii"),
                "signatures": [{"keyid": "test-ci-hmac-v1", "alg": "HMAC-SHA256-TEST",
                                "sig": base64.b64encode(signature).decode("ascii")}]}
    def production_signature_valid(self, envelope, public_key):
        verifier_spec = importlib.util.spec_from_file_location("r01_signature_verifier", self.tools / "verify_receipt.py")
        verifier = importlib.util.module_from_spec(verifier_spec)
        verifier_spec.loader.exec_module(verifier)
        return self.ed25519.verify(public_key,
                                   verifier.dsse_pae(envelope["payloadType"], base64.b64decode(envelope["payload"])),
                                   base64.b64decode(envelope["signatures"][0]["sig"]))
    def is_test_mode_signature_valid(self, envelope):
        verifier_spec = importlib.util.spec_from_file_location("r01_test_signature_verifier", self.tools / "verify_receipt.py")
        verifier = importlib.util.module_from_spec(verifier_spec)
        verifier_spec.loader.exec_module(verifier)
        expected = hmac.new(bytes.fromhex(self.policy["testRoot"]["keys"]["test-ci-hmac-v1"]["keyHex"]),
                            verifier.dsse_pae(envelope["payloadType"], base64.b64decode(envelope["payload"])),
                            hashlib.sha256).digest()
        return hmac.compare_digest(expected, base64.b64decode(envelope["signatures"][0]["sig"]))

    def test_generation_rejects_unsigned_and_forged_attestations_but_blocks_archival_only(self):
        artifacts = self.base / "artifacts"
        artifacts.mkdir()
        lineage = {"sourceRootSha256": "1" * 64, "sourceManifestSha256": "2" * 64}
        proof = {"schemaVersion": 1, "kind": "r01-durable-generation-proof-v1", "tuple": TUPLE,
                 "sourceLineage": lineage, "generation": 1, "previousProofSha256": None}
        dump(artifacts / "proof.json", proof)
        proof_hash = digest_bytes((artifacts / "proof.json").read_bytes())
        attestation_payload = {"schemaVersion": 1, "kind": "r01-durable-generation-attestation-v1", "tuple": TUPLE,
                               "sourceLineage": lineage, "proofSha256": proof_hash,
                               "observations": {name: True for name in ("restartContinuity", "interruptedWriteRecovery", "staleCorruptRejection", "uint64MaxIssuanceExhaustion")},
                               "issuer": {"role": "automated-ci", "trustDomain": "opendisplay-ci"}}
        attestation = artifacts / "attestation.json"
        request_path = self.base / "request.json"

        def request_for(attestation_value):
            dump(attestation, attestation_value)
            return {"schemaVersion": 1, "kind": "r01-generation-classification-request-v1", "classification": "archival_only",
                    "tuple": TUPLE, "sourceLineage": lineage, "durableGenerationProof": proof,
                    "artifacts": {"proofChain": [descriptor(artifacts, "proof.json")], "trustedAttestation": descriptor(artifacts, "attestation.json")}}

        # A caller-authored payload is not a receipt, and a syntactically valid receipt with a forged signature is rejected.
        for value in (attestation_payload, self.envelope(attestation_payload, forged=True)):
            dump(request_path, request_for(value))
            self.assertNotEqual(self.run_tool("validate-r01-generation-classification.py", "--request", request_path,
                                         "--artifact-root", artifacts, "--result", self.base / "rejected.json").returncode, 0)
        dump(request_path, request_for(self.envelope(attestation_payload)))
        result = self.base / "archival.json"
        completed = self.run_tool("validate-r01-generation-classification.py", "--request", request_path,
                             "--artifact-root", artifacts, "--result", result)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(json.loads(result.read_text())["status"], "blocked")

    def test_runtime_blocks_unsigned_or_forged_caller_observations(self):
        evidence = self.base / "runtime"
        evidence.mkdir()
        for name in ("command", "watchdog", "parser", "ping"):
            (evidence / name).write_text(name)
        full_tuple = {**TUPLE, "compatibilityDigest": "d" * 64, "normativeManifestDigest": "e" * 64}
        observation = {"schemaVersion": 1, "kind": "photonport.r01-runtime-observation.v1", "sourceTuple": full_tuple,
                       "device": {"id": "device"}, "transport": {"kind": "usb", "id": "usb"}, "hostIdentitySha256": "1" * 64,
                       "observedAt": "2026-07-19T12:00:00Z", "command": {"argv": ["test"], "exitCode": 0, "stdoutSha256": "2" * 64, "stderrSha256": "3" * 64},
                       "watchdog": {"outcome": "stopped", "exitCode": 0}, "strictParser": {"malformedInputSha256": "4" * 64, "outcome": "rejected", "exitCode": 0},
                       "ping": {"requestId": "ping", "responseId": "ping", "deviceId": "device"},
                       "artifactSha256": {name: digest_bytes((evidence / file).read_bytes()) for name, file in (("command", "command"), ("watchdog", "watchdog"), ("strictParser", "parser"), ("ping", "ping"))}}
        request = {"schemaVersion": 1, "kind": "photonport.r01-runtime-rollback-request.v1", "status": "executed", "sourceTuple": full_tuple,
                   "device": {"id": "device"}, "transport": {"kind": "usb", "id": "usb"},
                   "artifacts": [{"artifactType": kind, "path": file, "sha256": digest_bytes((evidence / file).read_bytes()), "size": (evidence / file).stat().st_size} for kind, file in (("command", "command"), ("watchdog", "watchdog"), ("strictParser", "parser"), ("ping", "ping"))],
                   "attestation": {"receiptPath": "receipt.json", "expectedKind": "photonport.r01-runtime-observation.v1"}, "trustPolicy": {"mode": "production"}}
        for receipt in (observation, self.envelope({"schemaVersion": 2, "kind": "photonport.gate.g004-automated.v2"}, forged=True)):
            dump(evidence / "receipt.json", receipt)
            dump(evidence / "request.json", request)
            completed = self.run_tool("validate-r01-runtime-rollback.py", "--request", evidence / "request.json", "--evidence-root", evidence, "--result", evidence / "result.json")
            self.assertNotEqual(completed.returncode, 0)
            if (evidence / "result.json").exists():
                self.assertEqual(json.loads((evidence / "result.json").read_text())["status"], "blocked")
                (evidence / "result.json").unlink()

    def test_preservation_rejects_self_authored_attestations_before_mutation(self):
        clone = self.base / "disposable-clone"
        clone.mkdir()
        for command in (["git", "init", "-q", clone], ["git", "-C", clone, "config", "user.email", "test@example.invalid"],
                        ["git", "-C", clone, "config", "user.name", "test"]):
            subprocess.run(command, check=True)
        (clone / "keep").write_text("preserve")
        subprocess.run(["git", "-C", clone, "add", "."], check=True)
        subprocess.run(["git", "-C", clone, "commit", "-qm", "fixture"], check=True)
        commit = subprocess.run(["git", "-C", clone, "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
        common = subprocess.run(["git", "-C", clone, "rev-parse", "--path-format=absolute", "--git-common-dir"],
                                text=True, capture_output=True, check=True).stdout.strip()
        root = {"canonicalPath": str(clone.resolve()), "dev": clone.stat().st_dev, "ino": clone.stat().st_ino}
        registry, lifecycle = self.base / "registry", self.base / "lifecycle"
        registry.mkdir(); lifecycle.mkdir()
        registration = {"schemaVersion": 1, "kind": "disposable-worktree-registration", **root, "registrationId": "a" * 64,
                        "purpose": "throwaway-clone", "lifecycleId": "life", "commonDir": common,
                        "authoritativeInventory": {"members": ["keep"]}, "authoritativeInventorySha256": digest_bytes(canonical({"members": ["keep"]}))}
        registration_path = registry / "registration.json"; dump(registration_path, registration)
        tuple_value = {**TUPLE, "macCommit": commit, "compatibilityDigest": "d" * 64, "normativeManifestDigest": "e" * 64}
        authority = {"approvedSequence": 1, "root": root, "supervisor": "test", "command": "test", "allocationNonce": "a",
                     "mutexNonce": "b", "lockAPath": "/tmp/a", "lockBPath": "/tmp/b", "registryPath": str(registry.resolve()), "commonGitDir": common}
        allocated = {"schemaVersion": 1, "kind": "photonport.lifecycle-state.v1", "lifecycleId": "life", "rootId": "root",
                     "tuple": tuple_value, "allocation": {}, "authority": authority, "state": "allocated", "predecessorSha256": None}
        allocated_path = lifecycle / "000-allocated.json"; dump(allocated_path, allocated)
        active = {**allocated, "state": "source-active", "predecessorSha256": digest_bytes(allocated_path.read_bytes()), "allocationReleaseSha256": "b" * 64}
        active_path = lifecycle / "010-source-active.json"; dump(active_path, active)
        common_stat = Path(common).stat()
        inventory = {"schemaVersion": 1, "kind": "photonport.r01-preservation-target-inventory.v1", "lifecycleId": "life",
                     "rootId": "root", "root": root, "commonGitDir": common, "commonGitDirDev": common_stat.st_dev,
                     "commonGitDirIno": common_stat.st_ino, "registrationSha256": digest_bytes(registration_path.read_bytes()),
                     "registrationId": "a" * 64, "authoritativeInventorySha256": registration["authoritativeInventorySha256"], "members": ["keep"]}
        inventory_path = self.base / "inventory.json"; dump(inventory_path, inventory)
        allocator, inventory_attestation = self.base / "allocator.json", self.base / "inventory-attestation.json"
        dump(allocator, {"caller": "asserted"}); dump(inventory_attestation, {"caller": "asserted"})
        manifest = {**inventory, "kind": "photonport.r01-preservation-closure-manifest.v1", "inventorySha256": digest_bytes(inventory_path.read_bytes()),
                    "allocatorAttestation": {"path": allocator.name, "sha256": digest_bytes(allocator.read_bytes()), "size": allocator.stat().st_size},
                    "inventoryAttestation": {"path": inventory_attestation.name, "sha256": digest_bytes(inventory_attestation.read_bytes()), "size": inventory_attestation.stat().st_size}}
        manifest_path = self.base / "manifest.json"; dump(manifest_path, manifest)
        args = ["--registration", registration_path, "--lifecycle-state", active_path, "--lifecycle-directory", lifecycle,
                "--manifest", manifest_path, "--inventory", inventory_path, "--root", clone,
                "--allocator-attestation", allocator, "--inventory-attestation", inventory_attestation,
                "--operation", "rename", "--result", self.base / "result.json"]
        completed = self.run_tool("run-r01-preservation-mutations.py", *args,
                                  "--trust-policy", self.tools / "trust-policy.json", "--trust-mode", "production")
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue((clone / "keep").exists(), completed.stderr)
        alternate_policy = self.base / "caller-trust-policy.json"
        alternate = json.loads((self.tools / "trust-policy.json").read_text())
        alternate["productionRoot"]["keys"]["prod-ci-ed25519-v1"]["publicKeyHex"] = self.ed25519.public_key(ALT_SEED).hex()
        dump(alternate_policy, alternate)
        signed = self.envelope({"caller": "asserted"}, seed=ALT_SEED)
        self.assertTrue(self.production_signature_valid(signed, self.ed25519.public_key(ALT_SEED)))
        dump(allocator, signed)
        dump(inventory_attestation, signed)
        alternate_attempt = self.run_tool("run-r01-preservation-mutations.py", *args,
                                          "--trust-policy", alternate_policy, "--trust-mode", "production")
        self.assertNotEqual(alternate_attempt.returncode, 0)
        self.assertIn("caller-selected trust policy is not authorized", alternate_attempt.stderr)
        self.assertTrue((clone / "keep").exists(), alternate_attempt.stderr)
        test_receipt = self.make_test_mode_envelope({"caller": "asserted"})
        self.assertTrue(self.is_test_mode_signature_valid(test_receipt))
        dump(allocator, test_receipt)
        dump(inventory_attestation, test_receipt)
        test_attempt = self.run_tool("run-r01-preservation-mutations.py", *args,
                                     "--trust-mode", "test")
        self.assertNotEqual(test_attempt.returncode, 0)
        self.assertIn("test trust mode is not authorized", test_attempt.stderr)
        self.assertTrue((clone / "keep").exists(), test_attempt.stderr)
    def test_fresh_build_archival_not_run_uses_only_disposable_roots(self):
        roots = {}
        tuple_value = {**TUPLE, "compatibilityDigest": "d" * 64, "normativeManifestDigest": "e" * 64}
        for name in ("mac", "ios", "protocol"):
            root = self.base / name
            root.mkdir()
            subprocess.run(["git", "init", "-q", root], check=True)
            subprocess.run(["git", "-C", root, "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", root, "config", "user.name", "test"], check=True)
            (root / "tracked").write_text(name)
            subprocess.run(["git", "-C", root, "add", "."], check=True)
            subprocess.run(["git", "-C", root, "commit", "-qm", "fixture"], check=True)
            tuple_value[name + "Commit"] = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
            roots[name] = root
        evidence = self.base / "fresh"
        evidence.mkdir()
        dump(evidence / "r01-fresh-build-request.json", {"schemaVersion": 1, "kind": "photonport.r01-fresh-build-request.v1", "sourceTuple": tuple_value, "sourceRoots": {name: str(root) for name, root in roots.items()}, "result": "not_run"})
        completed = self.run_tool("verify-r01-fresh-build.py", "--evidence-root", evidence)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads((evidence / "r01-fresh-build-result.json").read_text())["result"], "not_run")


if __name__ == "__main__":
    unittest.main()
