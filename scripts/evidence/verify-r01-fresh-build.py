#!/usr/bin/env python3
"""Fail-closed verifier for R01 fresh iOS build evidence; it grants no release authority."""
from __future__ import annotations
import argparse, hashlib, json, os, stat, subprocess, sys, tempfile
from pathlib import Path

HEX = set("0123456789abcdef")
STATUSES = {"passed", "failed", "blocked", "not_run"}
TUPLE_KEYS = ("macCommit", "iosCommit", "protocolCommit", "compatibilityDigest", "normativeManifestDigest")

class EvidenceError(Exception): pass

def digest(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def canonical(value: object) -> bytes: return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
def exact(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields: raise EvidenceError(f"{label} fields are not exact")
    return value
def hex_value(value: object, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length or set(value) - HEX: raise EvidenceError(f"{label} is invalid")
    return value
def relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value: raise EvidenceError(f"{label} path is invalid")
    parts = Path(value).parts
    if Path(value).is_absolute() or any(p in ("", ".", "..") for p in parts): raise EvidenceError(f"{label} path escapes clone root")
    return value
def parse(raw: bytes, label: str) -> dict:
    def reject(pairs):
        out = {}
        for key, value in pairs:
            if key in out: raise EvidenceError(f"{label} has duplicate key {key}")
            out[key] = value
        return out
    try: value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise EvidenceError(f"{label} is malformed JSON") from exc
    if not isinstance(value, dict): raise EvidenceError(f"{label} must be an object")
    return value
def regular_at(rootfd: int, path: str, label: str) -> bytes:
    path = relative(path, label); fd = os.dup(rootfd)
    try:
        for part in Path(path).parts[:-1]:
            nextfd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            os.close(fd); fd = nextfd
        leaf = os.open(Path(path).parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        try:
            info = os.fstat(leaf)
            if not stat.S_ISREG(info.st_mode): raise EvidenceError(f"{label} is not a regular file")
            data = os.read(leaf, info.st_size + 1)
            if len(data) != info.st_size or os.fstat(leaf).st_size != info.st_size: raise EvidenceError(f"{label} changed while reading")
            return data
        finally: os.close(leaf)
    except OSError as exc: raise EvidenceError(f"{label} is unavailable") from exc
    finally: os.close(fd)
def validate_tuple(value: object) -> dict:
    value = exact(value, set(TUPLE_KEYS), "source tuple")
    for key in TUPLE_KEYS: hex_value(value[key], 40 if key.endswith("Commit") else 64, key)
    return value
def validate_digest_file(value: object, label: str) -> dict:
    value = exact(value, {"path", "sha256"}, label); relative(value["path"], label); hex_value(value["sha256"], 64, label + " digest"); return value
def validate_request(request: dict) -> None:
    exact(request, {"schemaVersion", "kind", "sourceTuple", "generator", "project", "sourceManifest", "products"}, "request")
    if request["schemaVersion"] != 1 or request["kind"] != "photonport.r01-fresh-build-request.v1": raise EvidenceError("request identity is invalid")
    validate_tuple(request["sourceTuple"])
    for key in ("generator", "project", "sourceManifest"): validate_digest_file(request[key], "request " + key)
    products = exact(request["products"], {"Debug", "Release"}, "request products")
    for name in products: relative(products[name], "request product " + name)
def validate_result(result: dict, request: dict, request_raw: bytes, rootfd: int, root: Path) -> None:
    allowed = {"schemaVersion", "kind", "status", "requestSha256", "reason", "cleanClone", "generation", "products"}
    if set(result) - allowed or not {"schemaVersion", "kind", "status", "requestSha256"} <= set(result): raise EvidenceError("result fields are invalid")
    if result["schemaVersion"] != 1 or result["kind"] != "photonport.r01-fresh-build-result.v1" or result["status"] not in STATUSES: raise EvidenceError("result identity is invalid")
    if result["requestSha256"] != digest(request_raw): raise EvidenceError("result does not bind exact request bytes")
    passed = result["status"] == "passed"
    evidence = {"cleanClone", "generation", "products"}
    if passed and not evidence <= set(result): raise EvidenceError("passing result lacks fresh build evidence")
    if not passed:
        if set(result) & evidence or not isinstance(result.get("reason"), str) or not result["reason"]: raise EvidenceError("non-passing result has invalid evidence")
        return
    if "reason" in result: raise EvidenceError("passing result must not contain a reason")
    clean = exact(result["cleanClone"], {"gitHead", "gitStatusPorcelain", "projectAbsentBeforeGeneration"}, "clean clone")
    if clean["gitHead"] != request["sourceTuple"]["iosCommit"] or clean["gitStatusPorcelain"] != "" or clean["projectAbsentBeforeGeneration"] is not True: raise EvidenceError("clean clone evidence is invalid")
    try:
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
        status = subprocess.run(["git", "-C", str(root), "status", "--porcelain=v1", "--ignored"], check=True, text=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc: raise EvidenceError("clone root is not a readable git clone") from exc
    if head != clean["gitHead"] or status != "": raise EvidenceError("clone root is not clean or contains ignored stale project evidence")
    generation = exact(result["generation"], {"generator", "project", "sourceManifest"}, "generation")
    for key in generation:
        actual = validate_digest_file(generation[key], "generation " + key)
        expected = request[key]
        if actual != expected or digest(regular_at(rootfd, actual["path"], "generation " + key)) != actual["sha256"]: raise EvidenceError("generation digest does not bind requested fresh input")
    products = exact(result["products"], {"Debug", "Release"}, "products")
    for name in products:
        item = validate_digest_file(products[name], "product " + name)
        if item["path"] != request["products"][name] or digest(regular_at(rootfd, item["path"], "product " + name)) != item["sha256"]: raise EvidenceError("product digest does not bind requested product")
def read_input(path: Path, label: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode): raise EvidenceError(f"{label} is not a regular file")
            data = os.read(fd, info.st_size + 1)
            if len(data) != info.st_size or os.fstat(fd).st_size != info.st_size: raise EvidenceError(f"{label} changed while reading")
            return data
        finally: os.close(fd)
    except OSError as exc: raise EvidenceError(f"{label} is unavailable") from exc
def atomic_write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".verify-r01-fresh-build.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(canonical(value) + b"\n"); file.flush(); os.fsync(file.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(directory); os.close(directory)
    except Exception:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise
def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--clone-root", required=True, type=Path); parser.add_argument("--request", required=True, type=Path); parser.add_argument("--result", required=True, type=Path); parser.add_argument("--output", required=True, type=Path); args = parser.parse_args()
    try:
        original_root = args.clone_root
        root_info = original_root.lstat()
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode): raise EvidenceError("clone root is not a real directory")
        root = original_root.resolve(strict=True)
        rootfd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            request_raw = read_input(args.request, "request"); result_raw = read_input(args.result, "result")
            request = parse(request_raw, "request"); result = parse(result_raw, "result"); validate_request(request); validate_result(result, request, request_raw, rootfd, root)
        finally: os.close(rootfd)
        atomic_write(args.output, {"kind":"photonport.r01-fresh-build-verdict.v1", "requestSha256":digest(request_raw), "resultSha256":digest(result_raw), "status":result["status"], "verification":"passed"})
        print(json.dumps({"status":result["status"], "verification":"passed"}, sort_keys=True)); return 0
    except Exception as exc:
        print("verify-r01-fresh-build.py: FAIL_CLOSED: " + str(exc), file=sys.stderr); return 2
if __name__ == "__main__": sys.exit(main())
