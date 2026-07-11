#!/usr/bin/env python3
"""Verify Phase M3 cross-repository protocol pins deterministically."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

PIN_REQUIRED_KEYS = ("schemaVersion", "protocolCommit", "compatibilityDigest", "normativeManifestDigest")
PIN_OPTIONAL_KEYS = ("protocolTag",)
PIN_ALLOWED_KEYS = set(PIN_REQUIRED_KEYS + PIN_OPTIONAL_KEYS)
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
TAG_RE = re.compile(r"^refs/tags/[^\000-\037\177 ~^:?*\[]+$")
PROTOCOL_CONTRACT_PATHS = (
    "COMPATIBILITY.json",
    "NORMATIVE_MANIFEST.json",
    "schemas/build-pin.schema.json",
)


class Failure(Exception):
    pass


def fail(message):
    raise Failure(message)


def git(root, *args, allow_failure=False):
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=not allow_failure,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        fail(f"git {' '.join(args)} failed in {root}: {detail.strip()}")
    return result


def require_hex(value, label, length):
    pattern = HEX40_RE if length == 40 else HEX64_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(f"{label} must be a lowercase full {length}-hex value")
    return value


def require_repo_head(root, expected, label):
    expected = require_hex(expected, f"expected {label} commit", 40)
    inside = git(root, "rev-parse", "--is-inside-work-tree").stdout.strip()
    if inside != "true":
        fail(f"{label} root is not a git work tree: {root}")
    head = git(root, "rev-parse", "HEAD").stdout.strip()
    require_hex(head, f"{label} HEAD", 40)
    if head != expected:
        fail(f"{label} HEAD mismatch: expected {expected}, got {head}")
    return head


def file_sha256(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError as exc:
        fail(f"missing or unreadable required protocol file {path}: {exc}")


def strict_json_object(path):
    def pairs_hook(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                fail(f"duplicate JSON key {key!r} in {path}")
            obj[key] = value
        return obj

    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=pairs_hook)
    except UnicodeError as exc:
        fail(f"pin is not UTF-8 JSON: {path}: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"malformed JSON pin {path}: {exc}")
    except OSError as exc:
        fail(f"missing pin {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"pin must be a JSON object: {path}")
    return value


def canonical_pin_bytes(pin):
    return json.dumps(pin, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def relative_pin_path(root, explicit):
    root = Path(root)
    if explicit:
        path = Path(explicit)
        if path.is_absolute():
            try:
                return path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                fail(f"pin path must be inside repo {root}: {path}")
        return path.as_posix()
    candidates = ("ProtocolBuildPin.json", "Mac/ProtocolBuildPin.json")
    existing = [name for name in candidates if (root / name).is_file()]
    if len(existing) != 1:
        fail(f"expected exactly one tracked protocol pin in {root}: {', '.join(candidates)}")
    return existing[0]


def require_tracked_clean(root, relpath, label):
    git(root, "ls-files", "--error-unmatch", "--", relpath)
    if git(root, "diff", "--quiet", "--", relpath, allow_failure=True).returncode != 0:
        fail(f"{label} has unstaged tracked changes: {relpath}")
    if git(root, "diff", "--cached", "--quiet", "--", relpath, allow_failure=True).returncode != 0:
        fail(f"{label} has staged tracked changes: {relpath}")


def verify_tag(protocol_root, tag_name, expected_commit):
    if not tag_name:
        return None
    if not TAG_RE.fullmatch(tag_name):
        fail("authorized protocol tag must be a fully qualified refs/tags/... name")
    result = git(protocol_root, "rev-parse", "--verify", f"{tag_name}^{{commit}}", allow_failure=True)
    if result.returncode != 0:
        fail(f"authorized protocol tag is not locally available: {tag_name}")
    peeled = result.stdout.strip()
    require_hex(peeled, f"peeled {tag_name}", 40)
    if peeled != expected_commit:
        fail(f"authorized protocol tag {tag_name} resolves to {peeled}, expected {expected_commit}")
    return tag_name.removeprefix("refs/tags/")


def verify_pin(root, relpath, label, protocol_commit, compatibility_digest, normative_digest, authorized_tag):
    tracked_label = f"{label} pin"
    require_tracked_clean(root, relpath, tracked_label)
    path = Path(root) / relpath
    pin = strict_json_object(path)
    keys = set(pin)
    if not set(PIN_REQUIRED_KEYS).issubset(keys):
        missing = sorted(set(PIN_REQUIRED_KEYS) - keys)
        fail(f"{label} pin missing required fields: {', '.join(missing)}")
    extra = keys - PIN_ALLOWED_KEYS
    if extra:
        fail(f"{label} pin has unauthorized fields: {', '.join(sorted(extra))}")
    if pin.get("schemaVersion") != 1:
        fail(f"{label} pin schemaVersion must be integer 1")
    require_hex(pin.get("protocolCommit"), f"{label} pin protocolCommit", 40)
    require_hex(pin.get("compatibilityDigest"), f"{label} pin compatibilityDigest", 64)
    require_hex(pin.get("normativeManifestDigest"), f"{label} pin normativeManifestDigest", 64)
    if pin["protocolCommit"] != protocol_commit:
        fail(f"{label} pin protocolCommit mismatch: expected protocol HEAD {protocol_commit}, got {pin['protocolCommit']}")
    if pin["compatibilityDigest"] != compatibility_digest:
        fail(f"{label} pin compatibilityDigest mismatch: expected {compatibility_digest}, got {pin['compatibilityDigest']}")
    if pin["normativeManifestDigest"] != normative_digest:
        fail(f"{label} pin normativeManifestDigest mismatch: expected {normative_digest}, got {pin['normativeManifestDigest']}")
    if "protocolTag" in pin:
        if pin["protocolTag"] != authorized_tag:
            fail(f"{label} pin protocolTag is not explicitly authorized: {pin['protocolTag']!r}")
    elif authorized_tag:
        fail(f"{label} pin is missing authorized protocolTag {authorized_tag!r}")
    return {
        "path": relpath,
        "sha256": hashlib.sha256(canonical_pin_bytes(pin)).hexdigest(),
        "value": pin,
    }


def write_receipt(output, receipt):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".compatibility-", dir=str(output.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(receipt, handle, sort_keys=True, indent=2, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, output)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def run(args):
    mac_head = require_repo_head(args.mac_root, args.expected_mac_commit, "mac")
    ios_head = require_repo_head(args.ios_root, args.expected_ios_commit, "ios")
    protocol_head = require_repo_head(args.protocol_root, args.expected_protocol_commit, "protocol")
    for relpath in PROTOCOL_CONTRACT_PATHS:
        require_tracked_clean(args.protocol_root, relpath, "protocol contract")
    compatibility_digest = file_sha256(Path(args.protocol_root) / "COMPATIBILITY.json")
    normative_digest = file_sha256(Path(args.protocol_root) / "NORMATIVE_MANIFEST.json")
    expected_compat = require_hex(args.expected_compatibility_digest, "expected compatibility digest", 64)
    expected_normative = require_hex(args.expected_normative_manifest_digest, "expected normative manifest digest", 64)
    if compatibility_digest != expected_compat:
        fail(f"protocol COMPATIBILITY.json digest mismatch: expected {expected_compat}, got {compatibility_digest}")
    if normative_digest != expected_normative:
        fail(f"protocol NORMATIVE_MANIFEST.json digest mismatch: expected {expected_normative}, got {normative_digest}")
    authorized_tag = verify_tag(args.protocol_root, args.authorize_protocol_tag, protocol_head)
    mac_pin = verify_pin(args.mac_root, relative_pin_path(args.mac_root, args.mac_pin), "mac", protocol_head, compatibility_digest, normative_digest, authorized_tag)
    ios_pin = verify_pin(args.ios_root, relative_pin_path(args.ios_root, args.ios_pin), "ios", protocol_head, compatibility_digest, normative_digest, authorized_tag)
    receipt = {
        "schemaVersion": 1,
        "result": "compatible",
        "sourceTuple": {
            "macCommit": mac_head,
            "iosCommit": ios_head,
            "protocolCommit": protocol_head,
            "compatibilityDigest": compatibility_digest,
            "normativeManifestDigest": normative_digest,
        },
        "authorizedProtocolTag": authorized_tag,
        "authorizedProtocolTagRef": args.authorize_protocol_tag,
        "protocolContract": {
            "paths": list(PROTOCOL_CONTRACT_PATHS),
            "commit": protocol_head,
            "compatibilityDigest": compatibility_digest,
            "normativeManifestDigest": normative_digest,
        },
        "verifiedConsumerPins": {"mac": mac_pin, "ios": ios_pin},
    }
    write_receipt(args.output, receipt)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mac-root", required=True)
    parser.add_argument("--ios-root", required=True)
    parser.add_argument("--protocol-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-mac-commit", required=True)
    parser.add_argument("--expected-ios-commit", required=True)
    parser.add_argument("--expected-protocol-commit", required=True)
    parser.add_argument("--expected-compatibility-digest", required=True)
    parser.add_argument("--expected-normative-manifest-digest", required=True)
    parser.add_argument("--mac-pin")
    parser.add_argument("--ios-pin")
    parser.add_argument("--authorize-protocol-tag")
    args = parser.parse_args()
    try:
        run(args)
    except Failure as exc:
        print("FAIL_CLOSED: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
