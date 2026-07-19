#!/usr/bin/env python3
"""Validate R01-06 runtime rollback evidence; this never performs device actions."""
from __future__ import annotations
import argparse, hashlib, json, os, stat, subprocess, sys, tempfile
from pathlib import Path

HEX = set("0123456789abcdef")
TUPLE_FIELDS = ("macCommit", "iosCommit", "protocolCommit", "compatibilityDigest", "normativeManifestDigest")
ARTIFACT_FIELDS = ("path", "sha256", "size")
STATUS = {"passed", "failed", "blocked", "not_run"}

class EvidenceError(Exception): pass

def digest(data): return hashlib.sha256(data).hexdigest()
def exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields): raise EvidenceError(label + " fields are not exact")
def sha256(value): return isinstance(value, str) and len(value) == 64 and set(value) <= HEX
def commit(value): return isinstance(value, str) and len(value) == 40 and set(value) <= HEX
def safe_relative(value):
    return isinstance(value, str) and value and not Path(value).is_absolute() and all(part not in ("", ".", "..") for part in Path(value).parts)
def parse_json(data, label):
    def unique(items):
        out = {}
        for key, value in items:
            if key in out: raise ValueError("duplicate key " + key)
            out[key] = value
        return out
    try: return json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, ValueError) as exc: raise EvidenceError(label + " is malformed: " + str(exc))
def open_directory(path, label):
    try:
        before = Path(path).lstat()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        after = os.fstat(fd)
    except OSError as exc: raise EvidenceError(label + " is unavailable: " + str(exc))
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        os.close(fd); raise EvidenceError(label + " is unstable")
    return fd
def read_at(rootfd, relative, label):
    if not safe_relative(relative): raise EvidenceError(label + " path is invalid")
    fd = os.dup(rootfd)
    try:
        for part in Path(relative).parts[:-1]:
            child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            os.close(fd); fd = child
        leaf = os.open(Path(relative).name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        try:
            info = os.fstat(leaf)
            if not stat.S_ISREG(info.st_mode): raise EvidenceError(label + " is not a regular file")
            data = os.read(leaf, info.st_size + 1)
            if len(data) != info.st_size or os.fstat(leaf).st_size != info.st_size: raise EvidenceError(label + " changed while reading")
            return data
        finally: os.close(leaf)
    except OSError as exc: raise EvidenceError(label + " is unavailable: " + str(exc))
    finally: os.close(fd)
def relative_to(root, path, label):
    try: return Path(path).resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()
    except (OSError, ValueError): raise EvidenceError(label + " is outside evidence root")
def artifact(value, rootfd, label):
    exact(value, ARTIFACT_FIELDS, label)
    if not safe_relative(value["path"]) or not sha256(value["sha256"]) or not isinstance(value["size"], int) or isinstance(value["size"], bool) or value["size"] < 0: raise EvidenceError(label + " is invalid")
    data = read_at(rootfd, value["path"], label)
    if len(data) != value["size"] or digest(data) != value["sha256"]: raise EvidenceError(label + " hash mismatch")
def validate_tuple(value):
    exact(value, TUPLE_FIELDS, "source tuple")
    if not all(commit(value[key]) for key in TUPLE_FIELDS[:3]) or not all(sha256(value[key]) for key in TUPLE_FIELDS[3:]): raise EvidenceError("source tuple is invalid")
def git_value(root, args, label):
    try: return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc: raise EvidenceError(label + " is unavailable: " + str(exc))
def validate_source_root(path, expected, label):
    fd = open_directory(path, label)
    os.close(fd)
    root = Path(path).resolve(strict=True)
    if git_value(root, ["rev-parse", "HEAD"], label + " head") != expected: raise EvidenceError(label + " commit does not match tuple")
    if git_value(root, ["status", "--porcelain"], label + " status"): raise EvidenceError(label + " is dirty")
def validate_request(request, rootfd, evidence_dir):
    exact(request, ("schemaVersion", "kind", "sourceTuple", "host", "device", "build", "install", "observations"), "request")
    if request["schemaVersion"] != 1 or request["kind"] != "photonport.r01-runtime-rollback-request.v1": raise EvidenceError("request version or kind is invalid")
    validate_tuple(request["sourceTuple"])
    for name, family in (("host", "macOS"), ("device", "iOS")):
        value = request[name]; exact(value, ("family", "majorVersion", "identitySha256"), name)
        if value["family"] != family or value["majorVersion"] != 27 or not sha256(value["identitySha256"]): raise EvidenceError(name + " is not an OS27 provenance record")
    for name in ("build", "install"):
        artifact(request[name], rootfd, name)
        if Path(request[name]["path"]).parts[:len(Path(evidence_dir).parts)] != Path(evidence_dir).parts: raise EvidenceError(name + " is outside evidence directory")
    observations = request["observations"]
    if not isinstance(observations, list): raise EvidenceError("observations are invalid")
    seen = set(); validated = []
    for observation in observations:
        exact(observation, ("transport", "observer", "recordedAt", "watchdogLog", "strictParserLog", "ping"), "observation")
        transport = observation["transport"]
        if transport not in {"usb", "wifi"} or transport in seen or not isinstance(observation["observer"], str) or not observation["observer"] or not isinstance(observation["recordedAt"], str) or not observation["recordedAt"]: raise EvidenceError("observation provenance is invalid")
        exact(observation["ping"], ("deviceIdentitySha256", "result"), "ping")
        if observation["ping"]["deviceIdentitySha256"] != request["device"]["identitySha256"] or observation["ping"]["result"] != "id-bearing-ping-passed": raise EvidenceError("ping does not bind the declared device identity")
        for field, label in (("watchdogLog", "watchdog log"), ("strictParserLog", "strict parser log")):
            artifact(observation[field], rootfd, transport + " " + label)
            if Path(observation[field]["path"]).parts[:len(Path(evidence_dir).parts)] != Path(evidence_dir).parts: raise EvidenceError(transport + " " + label + " is outside evidence directory")
        seen.add(transport); validated.append(observation)
    return validated
def atomic_write(root, output, value):
    output_path = Path(output)
    if not output_path.name or output_path.name in (".", ".."): raise EvidenceError("output path is invalid")
    try:
        parent = output_path.parent.resolve(strict=True)
        parent.relative_to(root.resolve(strict=True))
    except (OSError, ValueError): raise EvidenceError("output is outside evidence root")
    pfd = open_directory(parent, "output directory")
    try:
        name = output_path.name
        try:
            info = os.stat(name, dir_fd=pfd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode): raise EvidenceError("output is a symlink")
        except FileNotFoundError: pass
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        tmp = ".r01-runtime-rollback-" + next(tempfile._get_candidate_names())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=pfd)
        try:
            os.write(fd, raw); os.fsync(fd)
        finally: os.close(fd)
        os.replace(tmp, name, src_dir_fd=pfd, dst_dir_fd=pfd); os.fsync(pfd)
    finally: os.close(pfd)
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True); parser.add_argument("--evidence-root", required=True); parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--mac-root", required=True); parser.add_argument("--ios-root", required=True); parser.add_argument("--protocol-root", required=True); parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        root = Path(args.evidence_root).resolve(strict=True); rootfd = open_directory(root, "evidence root")
        try:
            request_path = relative_to(root, args.request, "request")
            evidence_dir = relative_to(root, args.evidence_dir, "evidence directory")
            if not safe_relative(evidence_dir): raise EvidenceError("evidence directory path is invalid")
            request_raw = read_at(rootfd, request_path, "request")
            request = parse_json(request_raw, "request")
            observations = validate_request(request, rootfd, evidence_dir)
            validate_source_root(args.mac_root, request["sourceTuple"]["macCommit"], "mac root")
            validate_source_root(args.ios_root, request["sourceTuple"]["iosCommit"], "ios root")
            validate_source_root(args.protocol_root, request["sourceTuple"]["protocolCommit"], "protocol root")
            # A valid request may intentionally omit external human observations; CI does not infer them.
            supplied = {item["transport"] for item in observations}
            status = "passed" if supplied == {"usb", "wifi"} else "blocked"
            result_observations = [{"transport": item["transport"], "status": "passed", "watchdogLog": item["watchdogLog"], "strictParserLog": item["strictParserLog"], "ping": item["ping"]} for item in observations]
            result = {"schemaVersion": 1, "kind": "photonport.r01-runtime-rollback-result.v1", "status": status, "sourceTuple": request["sourceTuple"], "request": {"path": request_path, "sha256": digest(request_raw), "size": len(request_raw)}, "observations": result_observations, "retirementEligible": False, "deletionAuthorized": False}
        finally: os.close(rootfd)
        atomic_write(root, args.output, result)
        print(json.dumps({"status": result["status"], "retirementEligible": False, "deletionAuthorized": False}, sort_keys=True)); return 0
    except EvidenceError as exc:
        print("validate-r01-runtime-rollback.py: FAIL_CLOSED: " + str(exc), file=sys.stderr); return 2
if __name__ == "__main__": sys.exit(main())
