#!/usr/bin/env python3
"""Exercise an R01 preservation closure only inside a registered throwaway clone."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath

NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
HEX = set("0123456789abcdef")


def fail(message):
    raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def reject_duplicates(items):
    result = {}
    for key, value in items:
        if key in result:
            fail("duplicate JSON key")
        result[key] = value
    return result


def read_regular(path, label):
    named = path.lstat()
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
        fail(f"{label} is not a regular non-symlink file")
    fd = os.open(path, os.O_RDONLY | NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            fail(f"{label} changed while opening")
        chunks = []
        remaining = opened.st_size + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != opened.st_size or os.fstat(fd).st_size != opened.st_size:
            fail(f"{label} changed while reading")
        return data
    finally:
        os.close(fd)


def open_directory(path, label):
    named = path.lstat()
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
        fail(f"{label} is not a non-symlink directory")
    fd = os.open(path, os.O_RDONLY | DIRECTORY | NOFOLLOW)
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        os.close(fd)
        fail(f"{label} changed while opening")
    return fd, opened


def check_directory(fd, identity, label):
    current = os.fstat(fd)
    if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
        fail(f"{label} changed")


def member_parts(path):
    if not isinstance(path, str) or not path or "\x00" in path:
        fail("member path is invalid")
    candidate = PurePosixPath(path)
    if candidate.is_absolute() or any(part in ("", ".", "..") for part in candidate.parts):
        fail("member path escapes the registered clone")
    return candidate.parts


def open_member_parent(root_fd, root_identity, parts):
    current_fd = os.dup(root_fd)
    current_identity = os.fstat(current_fd)
    try:
        for part in parts[:-1]:
            check_directory(current_fd, current_identity, "member parent")
            named = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
                fail("member parent is unsafe")
            child_fd = os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=current_fd)
            opened = os.fstat(child_fd)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                os.close(child_fd)
                fail("member parent changed while opening")
            os.close(current_fd)
            current_fd, current_identity = child_fd, opened
        check_directory(root_fd, root_identity, "registered clone root")
        check_directory(current_fd, current_identity, "member parent")
        return current_fd, current_identity, parts[-1]
    except Exception:
        os.close(current_fd)
        raise


def member_data(root_fd, root_identity, member, require_present=True):
    parts = member_parts(member["path"])
    parent_fd, parent_identity, name = open_member_parent(root_fd, root_identity, parts)
    try:
        try:
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if require_present:
                fail(f"manifest member is absent: {member['path']}")
            return None
        if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
            fail(f"manifest member is unsafe: {member['path']}")
        fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                fail("manifest member changed while opening")
            data = b""
            while len(data) <= opened.st_size:
                chunk = os.read(fd, opened.st_size + 1 - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) != opened.st_size or os.fstat(fd).st_size != opened.st_size:
                fail("manifest member changed while reading")
        finally:
            os.close(fd)
        check_directory(parent_fd, parent_identity, "member parent")
        check_directory(root_fd, root_identity, "registered clone root")
        if len(data) != member["size"] or sha256(data) != member["sha256"]:
            fail(f"manifest member does not match its digest: {member['path']}")
        return data, stat.S_IMODE(opened.st_mode)
    finally:
        os.close(parent_fd)


def closure_status(root_fd, root_identity, members):
    """Return failed for a missing member; unsafe or changed inputs remain fatal."""
    for member in members:
        data = member_data(root_fd, root_identity, member, require_present=False)
        if data is None:
            return "failed"
    return "passed"


def restore(parent_fd, parent_identity, name, data, mode):
    check_directory(parent_fd, parent_identity, "member parent")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode, dir_fd=parent_fd)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    check_directory(parent_fd, parent_identity, "member parent")


def validate_manifest(value):
    required = {"schemaVersion", "kind", "registeredCloneRoot", "members"}
    if not isinstance(value, dict) or set(value) != required:
        fail("manifest has missing or unexpected keys")
    if value["schemaVersion"] != 1 or value["kind"] != "photonport.r01-preservation-closure-manifest.v1":
        fail("unsupported preservation manifest")
    root = value["registeredCloneRoot"]
    root_keys = {"canonicalPath", "dev", "ino", "registrationId", "purpose"}
    if not isinstance(root, dict) or set(root) != root_keys:
        fail("registered clone root is malformed")
    if (not isinstance(root["canonicalPath"], str) or not root["canonicalPath"].startswith("/")
            or "\x00" in root["canonicalPath"] or root["purpose"] != "throwaway-clone"):
        fail("registered clone root is invalid")
    if any(not isinstance(root[key], int) or isinstance(root[key], bool) or root[key] < 0 for key in ("dev", "ino")):
        fail("registered clone root identity is invalid")
    if (not isinstance(root["registrationId"], str) or len(root["registrationId"]) != 64
            or any(ch not in HEX for ch in root["registrationId"])):
        fail("registered clone registration is invalid")
    members = value["members"]
    if not isinstance(members, list) or not members:
        fail("manifest has no members")
    seen = set()
    for member in members:
        if not isinstance(member, dict) or set(member) != {"path", "sha256", "size"}:
            fail("manifest member is malformed")
        parts = member_parts(member["path"])
        normalized = "/".join(parts)
        if member["path"] != normalized or normalized in seen:
            fail("manifest member path is non-canonical or duplicated")
        seen.add(normalized)
        if (not isinstance(member["sha256"], str) or len(member["sha256"]) != 64
                or any(ch not in HEX for ch in member["sha256"])):
            fail("manifest member digest is invalid")
        if not isinstance(member["size"], int) or isinstance(member["size"], bool) or member["size"] < 0:
            fail("manifest member size is invalid")
    return root, members


def atomic_output(path, data):
    if not path.is_absolute():
        fail("output path must be absolute")
    parent_fd, parent_identity = open_directory(path.parent, "output parent")
    try:
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            fail("output already exists")
        except FileNotFoundError:
            pass
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        check_directory(parent_fd, parent_identity, "output parent")
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--clone-root", required=True)
    parser.add_argument("--registration-id", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        manifest_path = Path(args.manifest)
        manifest_raw = read_regular(manifest_path, "manifest")
        manifest = json.loads(manifest_raw, object_pairs_hook=reject_duplicates)
        if manifest_raw != canonical(manifest) + b"\n":
            fail("manifest is not canonical JSON")
        registered, members = validate_manifest(manifest)
        clone_path = Path(args.clone_root)
        if not clone_path.is_absolute() or str(clone_path) != registered["canonicalPath"]:
            fail("clone root does not exactly match the registered throwaway clone")
        if args.registration_id != registered["registrationId"]:
            fail("registration id does not match the registered throwaway clone")
        root_fd, root_identity = open_directory(clone_path, "registered clone root")
        try:
            if (root_identity.st_dev, root_identity.st_ino) != (registered["dev"], registered["ino"]):
                fail("clone root identity does not match registration")
            if os.path.realpath(clone_path) != registered["canonicalPath"]:
                fail("clone root canonical path is uncertain")
            if closure_status(root_fd, root_identity, members) != "passed":
                fail("incomplete preservation manifest closure")
            results = []
            for member in members:
                data, mode = member_data(root_fd, root_identity, member)
                parts = member_parts(member["path"])
                parent_fd, parent_identity, name = open_member_parent(root_fd, root_identity, parts)
                try:
                    os.unlink(name, dir_fd=parent_fd)
                    if closure_status(root_fd, root_identity, members) != "failed":
                        fail("delete mutation did not fail closure")
                    restore(parent_fd, parent_identity, name, data, mode)
                    if closure_status(root_fd, root_identity, members) != "passed":
                        fail("delete mutation restoration did not restore closure")
                    results.append({"operation": "delete", "path": member["path"], "closure": "failed", "restored": True})
                    renamed = "." + name + ".r01-preservation-mutation"
                    try:
                        os.stat(renamed, dir_fd=parent_fd, follow_symlinks=False)
                        fail("rename mutation destination already exists")
                    except FileNotFoundError:
                        pass
                    os.rename(name, renamed, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    if closure_status(root_fd, root_identity, members) != "failed":
                        fail("rename mutation did not fail closure")
                    os.rename(renamed, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    if closure_status(root_fd, root_identity, members) != "passed":
                        fail("rename mutation restoration did not restore closure")
                    results.append({"operation": "rename", "path": member["path"], "closure": "failed", "restored": True})
                finally:
                    os.close(parent_fd)
        finally:
            os.close(root_fd)
        result = {"schemaVersion": 1, "kind": "photonport.r01-preservation-mutation-result.v1", "result": "passed", "manifestSha256": sha256(manifest_raw), "registeredCloneRoot": registered, "baselineClosure": "passed", "mutations": results}
        atomic_output(Path(args.output), canonical(result) + b"\n")
        return 0
    except Exception as exc:
        print(f"run-r01-preservation-mutations.py: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
