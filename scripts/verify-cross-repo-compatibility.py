#!/usr/bin/env python3
"""Produce deterministic, secret-free cross-repository compatibility evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SCHEMA = {"protocol", "pairing", "mac", "ios", "mismatch"}
EXPECTED = {"protocol": "3.0.0", "pairing": "2.0.0", "mac": {"minimum": "0.1.0"}, "ios": {"minimum": "1.0.0"}, "mismatch": "fail_closed_with_upgrade_message"}

class Failure(Exception):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def manifest(root):
    path = Path(root) / "COMPATIBILITY.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Failure("malformed or missing compatibility manifest: " + str(path)) from exc
    if not isinstance(value, dict) or set(value) != SCHEMA:
        raise Failure("manifest fields must be exactly protocol,pairing,mac,ios,mismatch: " + str(path))
    if value != EXPECTED:
        raise Failure("compatibility manifest drift: " + str(path))
    return value, canonical(value)

def git(root, *args):
    try:
        return subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError):
        return None

def shipped_files(root):
    root = Path(root)
    provenance = root / "PROVENANCE.yml"
    if provenance.is_file():
        try:
            value = json.loads(provenance.read_text(encoding="utf-8"))
            names = value["shipped_paths"]
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise Failure("invalid PROVENANCE.yml shipped_paths in " + str(root)) from exc
        if not isinstance(names, list) or not all(isinstance(name, str) and name for name in names):
            raise Failure("invalid PROVENANCE.yml shipped_paths in " + str(root))
        names = names + [
            name for name in (
                "COMPATIBILITY.json", "LICENSE", "NOTICE.md", "PROVENANCE.yml",
                "TRADEMARKS.md",
            ) if (root / name).is_file()
        ]
        return sorted(set(names))

    listed = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if listed is not None:
        names = [x.decode("utf-8") for x in listed.split(b"\0") if x]
    else:
        names = []
        for path in root.rglob("*"):
            if path.is_file() and ".git" not in path.parts:
                names.append(path.relative_to(root).as_posix())
    excluded = (".gjc/", "artifacts/", "DerivedData/", "build/", "dist/")
    return sorted({
        name for name in names
        if not name.startswith(excluded) and "/DerivedData/" not in name
    })

def content_digest(root, names=None):
    root = Path(root)
    names = shipped_files(root) if names is None else sorted(names)
    h = hashlib.sha256()
    for name in names:
        path = root / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        name_bytes = name.encode("utf-8")
        h.update(len(name_bytes).to_bytes(4, "big")); h.update(name_bytes)
        h.update(len(data).to_bytes(8, "big")); h.update(data)
    return h.hexdigest()

def snapshot(root):
    root = Path(root)
    inside = git(root, "rev-parse", "--is-inside-work-tree") == b"true\n"
    head = git(root, "rev-parse", "HEAD") if inside else None
    status = git(root, "status", "--porcelain") if inside else None
    if not inside:
        identity = "not_git"
    elif head:
        identity = "committed_tree" if not status else "committed_with_uncommitted_changes"
    else:
        identity = "unborn_repository"
    return {"git_repository": inside, "head": head.decode().strip() if head else None,
            "identity": identity, "uncommitted": bool(status),
            "content_sha256": content_digest(root)}

def source_check(root, platform):
    root = Path(root)
    names = shipped_files(root)
    texts = []
    for name in names:
        if name.endswith((".swift", ".yml", ".yaml", ".plist", ".json")):
            try: texts.append((name, (root / name).read_text(encoding="utf-8")))
            except (OSError, UnicodeError): pass
    all_text = "\n".join(text for _, text in texts)
    if platform == "mac":
        checks = (("mac marketing version", "MARKETING_VERSION: \"0.1.0\""),
                  ("protocol version constant", "static let version = 3"),
                  ("protocol v3 label", "PhotonPort-primary-v3"),
                  ("pairing version constant", "static let version = 2"),
                  ("pairing v2 label", "PhotonPort-pair-v2"))
    else:
        checks = (("ios marketing version", "MARKETING_VERSION: \"1.0.0\""),
                  ("protocol version constant", "static let version = 3"),
                  ("protocol v3 label", "PhotonPort-primary-v3"),
                  ("pairing version constant", "static let version = 2"),
                  ("pairing v2 label", "PhotonPort-pair-v2"))
    for label, token in checks:
        if token not in all_text:
            raise Failure(label + " missing or mismatched in " + str(root))

def protocol_digest(root):
    names = [n for n in shipped_files(root) if n.startswith(("spec/", "vectors/", "schemas/")) or n == "COMPATIBILITY.json"]
    if not names:
        raise Failure("protocol specs/vectors are missing")
    # Canonical protocol files must carry the versions they claim.
    for name in names:
        if name.endswith(".json"):
            try: value = json.loads((Path(root) / name).read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc: raise Failure("malformed protocol JSON: " + name) from exc
            if name.endswith("COMPATIBILITY.json") and value != EXPECTED: raise Failure("protocol compatibility drift")
            if name.endswith("pairing-v2.json") and value.get("version") != EXPECTED["pairing"]: raise Failure("pairing vector version drift")
            if name.endswith("session-v3.json") and value.get("version") != EXPECTED["protocol"]: raise Failure("session vector version drift")
    return content_digest(root, names)

def run(args):
    manifests = []
    normalized = []
    for root in (args.mac_root, args.ios_root, args.protocol_root):
        value, raw = manifest(root); manifests.append(value); normalized.append(raw)
    if len(set(normalized)) != 1: raise Failure("normalized manifests are not byte-equivalent")
    source_check(args.mac_root, "mac")
    source_check(args.ios_root, "ios")
    pdigest = protocol_digest(args.protocol_root)
    receipt = {"schema_version": 1, "result": "compatible", "compatibility": EXPECTED,
               "normalized_manifest_sha256": hashlib.sha256(normalized[0]).hexdigest(),
               "protocol_content_sha256": pdigest,
               "snapshots": {"mac": snapshot(args.mac_root), "ios": snapshot(args.ios_root), "protocol": snapshot(args.protocol_root)}}
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".compatibility-", dir=str(output.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(receipt, handle, sort_keys=True, indent=2, ensure_ascii=True); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp, output)
    finally:
        if os.path.exists(temp): os.unlink(temp)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mac-root", required=True); parser.add_argument("--ios-root", required=True); parser.add_argument("--protocol-root", required=True); parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try: run(args)
    except Failure as exc:
        print("FAIL_CLOSED: " + str(exc), file=sys.stderr); return 1
    return 0

if __name__ == "__main__": sys.exit(main())
