#!/usr/bin/env python3
"""Validate typed, immutable R01 runtime rollback evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
import importlib.util
from pathlib import Path

MAX_BYTES = 1_048_576
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
ARTIFACT_TYPES = (
    "runtime-rollback-command", "watchdog-observation",
    "strict-parser-observation", "ping-observation",
)
EXPECTED = {
    "runtime-rollback-command": ("command", "runtime-rollback", "completed"),
    "watchdog-observation": ("observation", "watchdog", "stopped"),
    "strict-parser-observation": ("observation", "strict-parser", "rejected"),
    "ping-observation": ("observation", "ping", "received"),
}
RUNTIME_OBSERVATION_KIND = "photonport.r01-runtime-observation.v1"
TRUST_POLICY_PATH = Path(__file__).with_name("trust-policy.json")

class EvidenceError(Exception):
    pass

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError("duplicate JSON key: " + key)
        value[key] = item
    return value

def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise EvidenceError(label + " fields are not exact")

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def parse_json(data, label):
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as exc:
        raise EvidenceError(label + " is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise EvidenceError(label + " must be a JSON object")
    return value

def read_path(path, label):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise EvidenceError(label + " is unavailable: " + str(exc)) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise EvidenceError(label + " must be a bounded regular file")
        data = os.read(fd, info.st_size + 1)
        if len(data) != info.st_size or os.fstat(fd).st_size != info.st_size:
            raise EvidenceError(label + " changed while reading")
        return data
    finally:
        os.close(fd)

def open_root(path):
    root = Path(path)
    try:
        before = root.lstat()
        fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        after = os.fstat(fd)
    except OSError as exc:
        raise EvidenceError("approved evidence root is unavailable: " + str(exc)) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        os.close(fd)
        raise EvidenceError("approved evidence root must be a stable non-symlink directory")
    return fd

def read_rooted(rootfd, relative, label):
    path = Path(relative)
    if (not isinstance(relative, str) or not relative or path.is_absolute() or
            any(part in ("", ".", "..") for part in path.parts)):
        raise EvidenceError(label + " path is not relative to approved evidence root")
    fd = os.dup(rootfd)
    try:
        for component in path.parts[:-1]:
            nextfd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            os.close(fd)
            fd = nextfd
        leaf = os.open(path.parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        try:
            info = os.fstat(leaf)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise EvidenceError(label + " is not a bounded regular evidence file")
            data = os.read(leaf, info.st_size + 1)
            if len(data) != info.st_size or os.fstat(leaf).st_size != info.st_size:
                raise EvidenceError(label + " changed while reading")
            return data
        finally:
            os.close(leaf)
    except OSError as exc:
        raise EvidenceError(label + " is unavailable: " + str(exc)) from exc
    finally:
        os.close(fd)

def validate_tuple(value):
    exact(value, ("macCommit", "iosCommit", "protocolCommit", "compatibilityDigest", "normativeManifestDigest"), "sourceTuple")
    for name in ("macCommit", "iosCommit", "protocolCommit"):
        if not isinstance(value[name], str) or not HEX40.fullmatch(value[name]):
            raise EvidenceError("sourceTuple " + name + " is invalid")
    for name in ("compatibilityDigest", "normativeManifestDigest"):
        if not isinstance(value[name], str) or not HEX64.fullmatch(value[name]):
            raise EvidenceError("sourceTuple " + name + " is invalid")

def validate_binding(value, request):
    if value != request:
        raise EvidenceError("record does not exactly bind the requested runtime tuple, device, and transport")

def validate_timestamp(value):
    if not isinstance(value, str) or not ISO_UTC.fullmatch(value):
        raise EvidenceError("record observedAt is not a UTC ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceError("record observedAt is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise EvidenceError("record observedAt is not UTC")

def validate_request(value):
    exact(value, ("schemaVersion", "kind", "status", "sourceTuple", "device", "transport", "artifacts", "attestation", "trustPolicy"), "request")
    if value["schemaVersion"] != 1 or value["kind"] != "photonport.r01-runtime-rollback-request.v1":
        raise EvidenceError("unsupported request schema")
    if value["status"] not in ("executed", "not_run"):
        raise EvidenceError("request status is invalid")
    validate_tuple(value["sourceTuple"])
    exact(value["device"], ("id",), "device")
    exact(value["transport"], ("kind", "id"), "transport")
    if not isinstance(value["device"]["id"], str) or not IDENT.fullmatch(value["device"]["id"]):
        raise EvidenceError("device id is invalid")
    if value["transport"]["kind"] not in ("usb", "wifi") or not isinstance(value["transport"]["id"], str) or not IDENT.fullmatch(value["transport"]["id"]):
        raise EvidenceError("transport is invalid")
    exact(value["trustPolicy"], ("mode",), "trustPolicy")
    if value["trustPolicy"]["mode"] != "production":
        raise EvidenceError("only the canonical production trust policy is permitted")
    exact(value["attestation"], ("receiptPath", "expectedKind"), "attestation")
    if (not isinstance(value["attestation"]["receiptPath"], str) or
            value["attestation"]["expectedKind"] != RUNTIME_OBSERVATION_KIND):
        raise EvidenceError("attestation is malformed")
    artifacts = value["artifacts"]
    if value["status"] == "not_run":
        if artifacts != []:
            raise EvidenceError("not_run request must not claim executable proof artifacts")
        return {}
    if not isinstance(artifacts, list) or len(artifacts) != len(ARTIFACT_TYPES):
        raise EvidenceError("executed request must provide exactly four typed artifacts")
    indexed = {}
    for artifact in artifacts:
        exact(artifact, ("artifactType", "path", "sha256", "size"), "artifact descriptor")
        kind = artifact["artifactType"]
        if kind not in ARTIFACT_TYPES or kind in indexed:
            raise EvidenceError("artifact types must be unique and complete")
        if (not isinstance(artifact["path"], str) or not artifact["path"] or
                not isinstance(artifact["sha256"], str) or not HEX64.fullmatch(artifact["sha256"]) or
                not isinstance(artifact["size"], int) or isinstance(artifact["size"], bool) or artifact["size"] < 0):
            raise EvidenceError("artifact descriptor is malformed")
        indexed[kind] = artifact
    if set(indexed) != set(ARTIFACT_TYPES):
        raise EvidenceError("request is missing a required artifact type")
    return indexed

def receipt_module():
    module_path = Path(__file__).with_name("verify_receipt.py")
    spec = importlib.util.spec_from_file_location("photonport_r01_receipt", module_path)
    if spec is None or spec.loader is None:
        raise EvidenceError("receipt verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def signed_observation(request, root: Path):
    receipt = root / request["attestation"]["receiptPath"]
    verifier = receipt_module()
    try:
        _, unsigned_payload, _, _, _ = verifier._decode_envelope(receipt.resolve(), [root, TRUST_POLICY_PATH.parent])
    except Exception as exc:
        raise EvidenceError("attestation receipt cannot be decoded") from exc
    expected_verifier = unsigned_payload.get("verifier") if isinstance(unsigned_payload, dict) else None
    if not isinstance(expected_verifier, dict):
        raise EvidenceError("attestation receipt lacks verifier digests")
    verified = verifier.verify_envelope(
        receipt, expected={"verifier": expected_verifier}, trust_policy_path=TRUST_POLICY_PATH,
        trust_mode=request["trustPolicy"]["mode"], allowed_roots=[root, TRUST_POLICY_PATH.parent])
    if verified.get("exitCode") != 0 or not verified.get("trusted"):
        raise EvidenceError("attestation receipt is not a valid trusted DSSE/Ed25519 signature")
    _, payload, _, _, _ = verifier._decode_envelope(receipt.resolve(), [root, TRUST_POLICY_PATH.parent])
    invocation = payload.get("invocation")
    if not isinstance(invocation, dict) or invocation.get("tool") != request["attestation"]["expectedKind"]:
        raise EvidenceError("signed receipt does not carry the required runtime observation kind")
    argv = invocation.get("argv")
    if not isinstance(argv, list) or len(argv) != 1 or not isinstance(argv[0], str):
        raise EvidenceError("signed runtime observation argv is malformed")
    raw = argv[0].encode("utf-8")
    observation = parse_json(raw, "signed runtime observation")
    if raw != verifier.canonical_json(observation):
        raise EvidenceError("signed runtime observation is not canonical JSON")
    exact(observation, ("schemaVersion", "kind", "sourceTuple", "device", "transport", "hostIdentitySha256", "observedAt", "command", "watchdog", "strictParser", "ping", "artifactSha256"), "signed runtime observation")
    if observation["schemaVersion"] != 1 or observation["kind"] != request["attestation"]["expectedKind"]:
        raise EvidenceError("signed runtime observation schema is invalid")
    validate_tuple(observation["sourceTuple"])
    validate_binding(observation["sourceTuple"], request["sourceTuple"])
    validate_binding(observation["device"], request["device"])
    validate_binding(observation["transport"], request["transport"])
    if not isinstance(observation["hostIdentitySha256"], str) or not HEX64.fullmatch(observation["hostIdentitySha256"]):
        raise EvidenceError("signed runtime observation host identity is invalid")
    validate_timestamp(observation["observedAt"])
    exact(observation["command"], ("argv", "exitCode", "stdoutSha256", "stderrSha256"), "signed command")
    command = observation["command"]
    if (not isinstance(command["argv"], list) or not command["argv"] or not all(isinstance(arg, str) for arg in command["argv"]) or
            command["exitCode"] != 0 or any(not isinstance(command[key], str) or not HEX64.fullmatch(command[key]) for key in ("stdoutSha256", "stderrSha256"))):
        raise EvidenceError("signed command execution is invalid")
    exact(observation["watchdog"], ("outcome", "exitCode"), "signed watchdog")
    if observation["watchdog"] != {"outcome": "stopped", "exitCode": 0}:
        raise EvidenceError("signed watchdog was not stopped")
    exact(observation["strictParser"], ("malformedInputSha256", "outcome", "exitCode"), "signed strict parser")
    strict = observation["strictParser"]
    if strict["outcome"] != "rejected" or strict["exitCode"] != 0 or not isinstance(strict["malformedInputSha256"], str) or not HEX64.fullmatch(strict["malformedInputSha256"]):
        raise EvidenceError("signed strict parser did not reject malformed input")
    exact(observation["ping"], ("requestId", "responseId", "deviceId"), "signed ping")
    ping = observation["ping"]
    if (any(not isinstance(ping[key], str) or not IDENT.fullmatch(ping[key]) for key in ping) or
            ping["requestId"] != ping["responseId"] or ping["deviceId"] != request["device"]["id"]):
        raise EvidenceError("signed ping is not id-bearing for the requested device")
    exact(observation["artifactSha256"], ARTIFACT_TYPES, "signed artifact hashes")
    if any(not isinstance(observation["artifactSha256"][key], str) or not HEX64.fullmatch(observation["artifactSha256"][key]) for key in ARTIFACT_TYPES):
        raise EvidenceError("signed artifact hashes are invalid")
    return observation
def validate_record(raw, descriptor, request, observation):
    if sha256(raw) != descriptor["sha256"] or sha256(raw) != observation["artifactSha256"][descriptor["artifactType"]]:
        raise EvidenceError(descriptor["artifactType"] + " hash is not bound by the signed observation")

def result(request, status, artifacts, failures):
    return {"schemaVersion": 1, "kind": "photonport.r01-runtime-rollback-result.v1", "status": status,
            "sourceTuple": request["sourceTuple"], "device": request["device"], "transport": request["transport"],
            "attestation": request["attestation"], "trustPolicy": request["trustPolicy"],
            "artifacts": artifacts, "failures": sorted(set(failures))}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--evidence-dir")
    parser.add_argument("--mac-root")
    parser.add_argument("--ios-root")
    parser.add_argument("--protocol-root")
    parser.add_argument("--result", "--output", dest="result", required=True)
    args = parser.parse_args()
    try:
        request = parse_json(read_path(args.request, "request"), "request")
        descriptors = validate_request(request)
    except EvidenceError as exc:
        raise SystemExit("FAIL_CLOSED: " + str(exc))
    if request["status"] == "not_run":
        output = result(request, "blocked", [], ["runtime observation explicitly not_run"])
        encoded = json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n"
        Path(args.result).write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0
    artifacts, failures = [], []
    try:
        rootfd = open_root(args.evidence_root)
    except EvidenceError as exc:
        rootfd = None
        failures.append(str(exc))
    if rootfd is not None:
        try:
            try:
                observation = signed_observation(request, Path(args.evidence_root).resolve())
            except EvidenceError as exc:
                observation = None
                failures.append(str(exc))
            if observation is not None:
                for artifact_type in ARTIFACT_TYPES:
                    descriptor = descriptors[artifact_type]
                    try:
                        raw = read_rooted(rootfd, descriptor["path"], artifact_type)
                        if len(raw) != descriptor["size"]:
                            raise EvidenceError(artifact_type + " durable bytes do not match descriptor size")
                        validate_record(raw, descriptor, request, observation)
                        artifacts.append(dict(descriptor))
                    except EvidenceError as exc:
                        failures.append(str(exc))
        finally:
            os.close(rootfd)
    output = result(request, "passed" if not failures else "blocked", artifacts, failures)
    encoded = json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n"
    Path(args.result).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if not failures else 1

if __name__ == "__main__":
    sys.exit(main())
