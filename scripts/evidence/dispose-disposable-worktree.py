#!/usr/bin/env python3
"""Claim and dispose only the registered, released disposable worktree."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

CORE = Path(__file__).with_name("transition-lifecycle-state.py")
VERIFY = Path(__file__).with_name("verify-lifecycle-state.py")
CORE_MODULE = None


def transition_module():
    global CORE_MODULE
    if CORE_MODULE is None:
        spec = importlib.util.spec_from_file_location("photonport_transition_lifecycle", CORE)
        if spec is None or spec.loader is None:
            fail("cannot load lifecycle transition authority")
        CORE_MODULE = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(CORE_MODULE)
        if not hasattr(CORE_MODULE, "transition_authorized") or not hasattr(CORE_MODULE, "_WRAPPER_CAPABILITY"):
            fail("lifecycle transition internal authority is unavailable")
    return CORE_MODULE
CLEANUP_KEYS = {
    "schemaVersion", "kind", "lifecycleId", "rootId", "allocation", "destination",
    "rootDev", "rootIno", "generatedOutputsAbsent",
}
AUTHORITY_KEYS = {
    "approvedSequence", "root", "supervisor", "command", "allocationNonce", "mutexNonce",
    "lockAPath", "lockBPath", "registryPath", "commonGitDir",
}


def fail(message):
    raise RuntimeError(message)


def canonical_path(path):
    return Path(os.path.realpath(path))


def raw(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"not a regular file: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            fail(f"file changed while opening: {path}")
        chunks = []
        remaining = opened.st_size + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if os.fstat(fd).st_size != opened.st_size:
            fail(f"file changed while reading: {path}")
        return data
    finally:
        os.close(fd)


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("duplicate JSON key")
        value[key] = item
    return value


def obj(path):
    try:
        value = json.loads(raw(path), object_pairs_hook=reject_duplicates)
    except Exception as exc:
        raise RuntimeError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        fail("record is not an object")
    return value
def raw_relative(path, label):
    parent_fd, parent_info = open_stable_directory(path.parent, f"{label} parent")
    try:
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode):
            fail(f"{label} is not a regular file")
        fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                fail(f"{label} changed while opening")
            data = os.read(fd, opened.st_size + 1)
            if len(data) > opened.st_size or os.fstat(fd).st_size != opened.st_size:
                fail(f"{label} changed while reading")
            if os.fstat(parent_fd).st_dev != parent_info.st_dev or os.fstat(parent_fd).st_ino != parent_info.st_ino:
                fail(f"{label} parent changed while reading")
            return data
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
def raw_at(directory_fd, name, label):
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            fail(f"{label} is not a regular file")
        data = os.read(fd, info.st_size + 1)
        if len(data) > info.st_size or os.fstat(fd).st_size != info.st_size:
            fail(f"{label} changed while reading")
        return data
    finally:
        os.close(fd)


def parse_object(data, label):
    try:
        value = json.loads(data, object_pairs_hook=reject_duplicates)
    except Exception as exc:
        raise RuntimeError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    return value


def revalidate_directory(fd, identity, path, label):
    current = os.fstat(fd)
    named = path.lstat()
    if ((current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
            or (named.st_dev, named.st_ino) != (identity.st_dev, identity.st_ino)
            or stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode)):
        fail(f"{label} identity changed")
def authority_binding(authority):
    if not isinstance(authority, dict) or set(authority) != AUTHORITY_KEYS:
        fail("lifecycle authority has missing or unexpected keys")
    if authority["approvedSequence"] != ["allocated", "source-active", "source-closing", "source-released", "disposing", "disposed"]:
        fail("lifecycle authority sequence is not canonical")
    root = authority["root"]
    if not isinstance(root, dict) or set(root) != {"canonicalPath", "dev", "ino"}:
        fail("lifecycle authority root binding is invalid")
    if not isinstance(root["canonicalPath"], str) or canonical_path(root["canonicalPath"]) != Path(root["canonicalPath"]):
        fail("lifecycle authority root path is invalid")
    if not isinstance(root["dev"], int) or not isinstance(root["ino"], int):
        fail("lifecycle authority root identity is invalid")
    for key in ("supervisor", "command"):
        if not isinstance(authority[key], str) or not authority[key]:
            fail(f"lifecycle authority {key} is invalid")
    for key in ("allocationNonce", "mutexNonce"):
        if not isinstance(authority[key], str) or len(authority[key]) != 64 or any(c not in "0123456789abcdef" for c in authority[key]):
            fail(f"lifecycle authority {key} is invalid")
    for key in ("lockAPath", "lockBPath", "registryPath", "commonGitDir"):
        if not isinstance(authority[key], str) or canonical_path(authority[key]) != Path(authority[key]):
            fail(f"lifecycle authority {key} is invalid")
    return authority
def require_absent(path, label):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    fail(f"{label} is still present")
def sha256_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
def open_stable_directory(path, label):
    try:
        named = path.lstat()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        fail(f"{label} is unavailable or unsafe: {exc}")
    opened = os.fstat(fd)
    if (stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)):
        os.close(fd)
        fail(f"{label} changed while opening")
    return fd, opened


def child_identity(parent_fd, name, label):
    try:
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        fail(f"{label} is absent")
    if stat.S_ISLNK(entry.st_mode):
        fail(f"{label} is a symlink")
    return entry


def require_child_absent(parent_fd, name, label):
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    fail(f"{label} is still present")




def validate_cleanup(cleanup, destination):
    if set(cleanup) != CLEANUP_KEYS:
        fail("cleanup record has missing or unexpected keys")
    if cleanup["schemaVersion"] != 1 or cleanup["kind"] != "photonport.disposable-worktree-cleanup.v1":
        fail("unsupported cleanup record")
    if cleanup["destination"] != str(destination):
        fail("cleanup destination does not match allocated destination")
    if not isinstance(cleanup["rootDev"], int) or not isinstance(cleanup["rootIno"], int):
        fail("cleanup root identity is invalid")
    if cleanup["generatedOutputsAbsent"] is not True:
        fail("cleanup does not attest generated outputs are absent")
    if not isinstance(cleanup["allocation"], dict) or set(cleanup["allocation"]) != {"id", "sha256"}:
        fail("cleanup allocation is malformed")
def common_git_dir(git, cwd):
    result = subprocess.run([git, "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        fail(result.stderr.strip() or "cannot determine common Git directory")
    common = Path(result.stdout.strip())
    if not common.is_absolute():
        fail("common Git directory is not absolute")
    try:
        before = common.lstat()
        fd = os.open(common, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        fail(f"common Git directory is unavailable or unsafe: {exc}")
    try:
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        fail("common Git directory changed or is not a stable non-symlink directory")
    return canonical_path(common)


def registered_worktrees(git, common):
    argv = [str(git), f"--git-dir={common}", "worktree", "list", "--porcelain"]
    listed = subprocess.run(argv, capture_output=True)
    if listed.returncode:
        fail(listed.stderr.decode(errors="replace").strip() or "git worktree list failed")
    return ({Path(line[9:]).resolve() for line in listed.stdout.decode().splitlines()
             if line.startswith("worktree ")},
            hashlib.sha256(listed.stdout).hexdigest(), argv)


def disposal_context_path(registry_mutex):
    return registry_mutex.with_name(registry_mutex.name + ".dispose-context.json")


def write_disposal_context(path, destination, cleanup, common, pre_list_sha256, remove_argv):
    command = {"argv": remove_argv}
    context = {
        "schemaVersion": 1,
        "kind": "photonport.disposable-worktree-context.v1",
        "destination": str(destination),
        "rootDev": cleanup["rootDev"],
        "rootIno": cleanup["rootIno"],
        "allocationSha256": cleanup["allocation"]["sha256"],
        "commonGitDir": str(common),
        "preWorktreeListSha256": pre_list_sha256,
        "removeArgv": remove_argv,
        "removeCommandRecordSha256": sha256_json(command),
        "removeArgvSha256": sha256_json(remove_argv),
        "rootIdentitySha256": sha256_json({"canonicalPath": str(destination), "dev": cleanup["rootDev"], "ino": cleanup["rootIno"]}),
        "registryReleaseSha256": sha256_json({"commonGitDir": str(common), "destination": str(destination), "preWorktreeListSha256": pre_list_sha256}),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, json.dumps(context, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_parent(path)


def fsync_parent(path):
    fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def acquire_registry_lock(path):
    """Acquire the persistent Lock-A inode; flock releases it if this process dies."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        opened = os.fstat(fd)
        named = path.lstat()
        if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(named.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
            fail("registry mutex is unavailable or unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except Exception:
        os.close(fd)
        raise


def disposal_context(path, destination, cleanup):
    context = obj(path)
    expected = {
        "schemaVersion": 1,
        "kind": "photonport.disposable-worktree-context.v1",
        "destination": str(destination),
        "rootDev": cleanup["rootDev"],
        "rootIno": cleanup["rootIno"],
        "allocationSha256": cleanup["allocation"]["sha256"],
    }
    required = set(expected) | {
        "commonGitDir", "preWorktreeListSha256", "removeArgv", "removeCommandRecordSha256",
        "removeArgvSha256", "rootIdentitySha256", "registryReleaseSha256",
    }
    if any(context.get(key) != value for key, value in expected.items()) or set(context) != required:
        fail("disposal context does not match immutable cleanup binding")
    if (not isinstance(context["preWorktreeListSha256"], str)
            or len(context["preWorktreeListSha256"]) != 64
            or not isinstance(context["removeArgv"], list)
            or not all(isinstance(item, str) for item in context["removeArgv"])
            or not isinstance(context["removeCommandRecordSha256"], str)
            or context["removeCommandRecordSha256"] != sha256_json({"argv": context["removeArgv"]})
            or context["removeArgvSha256"] != sha256_json(context["removeArgv"])
            or context["rootIdentitySha256"] != sha256_json({"canonicalPath": str(destination), "dev": cleanup["rootDev"], "ino": cleanup["rootIno"]})
            or context["registryReleaseSha256"] != sha256_json({"commonGitDir": context["commonGitDir"], "destination": str(destination), "preWorktreeListSha256": context["preWorktreeListSha256"]})):
        fail("disposal context command provenance is invalid")
    common = Path(context["commonGitDir"])
    if not common.is_absolute() or not common.is_dir() or common.is_symlink():
        fail("disposal context common Git directory is unavailable or unsafe")
    return common.resolve()


def state(directory_fd, predecessor_raw, predecessor, target, proofs):
    transition = {
        "schemaVersion": 1, "kind": "photonport.lifecycle-transition.v1",
        "lifecycleId": predecessor["lifecycleId"], "rootId": predecessor["rootId"], "tuple": predecessor["tuple"],
        "allocation": predecessor["allocation"], "authority": predecessor["authority"], "fromState": predecessor["state"], "toState": target,
        "predecessorSha256": hashlib.sha256(predecessor_raw).hexdigest(),
        **proofs,
    }
    fd, name = tempfile.mkstemp(prefix="lifecycle-transition-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(transition, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
        module = transition_module()
        return module.transition_authorized(
            directory=None, directory_fd=directory_fd, transition=Path(name), expected_state=target,
            _capability=module._WRAPPER_CAPABILITY)
    except Exception as exc:
        fail(f"internal lifecycle transition failed: {exc}")
    finally:
        os.unlink(name)


def verify_release_lineage(directory):
    result = subprocess.run([sys.executable, str(VERIFY), "--directory", str(directory)], text=True, capture_output=True)
    if result.returncode:
        fail(result.stderr.strip() or "lifecycle verification failed")
    verified = json.loads(result.stdout)
    if verified["state"] not in ("source-released", "disposing"):
        fail("lifecycle is not eligible for disposal")
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--mutex", type=Path, required=True)
    parser.add_argument("--registry-mutex", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--cleanup", type=Path, required=True)
    parser.add_argument("--allocation-record", type=Path, required=True, help="raw immutable allocation record bound by allocation.sha256")
    parser.add_argument("--git", default="git")
    args = parser.parse_args()
    lifecycle_fd = None
    try:
        lifecycle_fd, lifecycle_identity = open_stable_directory(args.directory, "lifecycle directory")
        closing_raw = raw_at(lifecycle_fd, "020-source-closing.json", "source-closing")
        released_raw = raw_at(lifecycle_fd, "030-source-released.json", "source-released")
        close = parse_object(closing_raw, "source-closing")
        release = parse_object(released_raw, "source-released")
        if close.get("state") != "source-closing" or release.get("state") != "source-released":
            fail("complete source release lineage is required")
        context_path = disposal_context_path(args.registry_mutex)
        disposing = args.directory / "040-dispose-claim.json"
        if release.get("predecessorSha256") != hashlib.sha256(closing_raw).hexdigest():
            fail("release raw predecessor binding mismatch")
        if any(release[key] != close[key] for key in ("lifecycleId", "rootId", "tuple", "allocation", "authority")):
            fail("release lineage mismatch")
        authority = authority_binding(release["authority"])
        if (canonical_path(args.registry_mutex) != Path(authority["lockAPath"])
                or canonical_path(args.mutex) != Path(authority["lockBPath"])
                or canonical_path(args.registry_mutex.parent) != Path(authority["registryPath"])):
            fail("caller-selected lock namespace does not match lifecycle authority")
        if canonical_path(args.root) != Path(authority["root"]["canonicalPath"]) or canonical_path(args.destination) != Path(authority["root"]["canonicalPath"]):
            fail("caller-selected root does not match lifecycle authority")
        destination = Path(authority["root"]["canonicalPath"])
        cleanup_raw = raw(args.cleanup)
        cleanup_sha256 = hashlib.sha256(cleanup_raw).hexdigest()
        cleanup = json.loads(cleanup_raw, object_pairs_hook=reject_duplicates)
        if not isinstance(cleanup, dict):
            fail("cleanup record is not an object")
        validate_cleanup(cleanup, destination)
        if close.get("cleanupSha256") != cleanup_sha256:
            fail("raw cleanup bytes do not match source-closing cleanupSha256")
        if any(cleanup.get(key) != release[key] for key in ("lifecycleId", "rootId", "allocation")):
            fail("cleanup lineage mismatch")
        root_fd = parent_fd = None
        fd = acquire_registry_lock(args.registry_mutex)
        try:
            # Lock A serializes every mutable root, allocation, registry, and Lock-B observation.
            if (args.directory / "050-disposed.json").exists():
                fail("disposal is already terminal")
            if disposing.exists():
                fail("DISPOSAL_RECOVERY_UNCERTAIN: existing disposing claim requires inspection; no retry or synthesis is permitted")
            if context_path.exists():
                fail("DISPOSAL_RECOVERY_UNCERTAIN: unclaimed disposal context requires inspection")
            require_absent(args.mutex, "source mutex")
            revalidate_directory(lifecycle_fd, lifecycle_identity, args.directory, "lifecycle directory")

            root_info = args.root.lstat()
            if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
                fail("authority root is unavailable or unsafe")
            parent_fd, parent_info = open_stable_directory(destination.parent, "destination parent")
            root_entry = child_identity(parent_fd, destination.name, "destination")
            root_fd = os.open(destination.name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            opened_root = os.fstat(root_fd)
            if ((root_info.st_dev, root_info.st_ino) != (opened_root.st_dev, opened_root.st_ino)
                    or (root_entry.st_dev, root_entry.st_ino) != (opened_root.st_dev, opened_root.st_ino)
                    or (root_info.st_dev, root_info.st_ino) != (authority["root"]["dev"], authority["root"]["ino"])
                    or (cleanup["rootDev"], cleanup["rootIno"]) != (opened_root.st_dev, opened_root.st_ino)):
                fail("root identity validation failed under Lock-A")

            allocation_raw = raw_relative(args.allocation_record, "allocation record")
            try:
                allocation_record = json.loads(allocation_raw, object_pairs_hook=reject_duplicates)
            except Exception as exc:
                raise RuntimeError("invalid JSON: allocation record") from exc
            if not isinstance(allocation_record, dict):
                fail("allocation record is not an object")
            if (set(allocation_record) != {"schemaVersion", "kind", "id", "destination"}
                    or allocation_record["schemaVersion"] != 1
                    or allocation_record["kind"] != "allocation-record.v1"
                    or not isinstance(allocation_record["id"], str)
                    or not allocation_record["id"]
                    or not isinstance(allocation_record["destination"], str)):
                fail("allocation record has missing or unexpected fields")
            if hashlib.sha256(allocation_raw).hexdigest() != release["allocation"]["sha256"]:
                fail("allocation.sha256 does not bind the raw allocation record")
            if allocation_record["id"] != release["allocation"]["id"] or allocation_record["destination"] != str(destination):
                fail("allocation record does not bind the released destination")

            common = common_git_dir(args.git, args.root)
            if canonical_path(common) != Path(authority["commonGitDir"]):
                fail("common Git directory does not match lifecycle authority")
            worktrees, pre_list_sha256, _ = registered_worktrees(args.git, common)
            if destination not in worktrees:
                fail("allocated destination is not registered")
            remove_argv = [str(args.git), f"--git-dir={common}", "worktree", "remove", "--force", str(destination)]
            write_disposal_context(context_path, destination, cleanup, common, pre_list_sha256, remove_argv)
            state(lifecycle_fd, released_raw, release, "disposing", {
                "cleanupSha256": cleanup_sha256,
                "preWorktreeListSha256": pre_list_sha256,
                "removeArgvSha256": sha256_json(remove_argv),
                "removeCommandSha256": sha256_json({"argv": remove_argv}),
                "rootIdentitySha256": sha256_json({"canonicalPath": str(destination), "dev": opened_root.st_dev, "ino": opened_root.st_ino}),
                "registryReleaseSha256": sha256_json({"commonGitDir": str(common), "destination": str(destination), "preWorktreeListSha256": pre_list_sha256}),
            })
            revalidate_directory(lifecycle_fd, lifecycle_identity, args.directory, "lifecycle directory")

            if os.fstat(root_fd).st_dev != opened_root.st_dev or os.fstat(root_fd).st_ino != opened_root.st_ino:
                fail("retained root descriptor changed before removal")
            current_parent = destination.parent.lstat()
            if (current_parent.st_dev, current_parent.st_ino) != (parent_info.st_dev, parent_info.st_ino):
                fail("destination parent path rebound before removal")
            if os.fstat(parent_fd).st_dev != parent_info.st_dev or os.fstat(parent_fd).st_ino != parent_info.st_ino:
                fail("destination parent changed before removal")
            removed = subprocess.run(remove_argv, capture_output=True)
            if removed.returncode:
                fail(removed.stderr.decode(errors="replace").strip() or "worktree removal failed")
            worktrees, post_list_sha256, _ = registered_worktrees(args.git, common)
            if destination in worktrees:
                fail("worktree remains registered")
            current_parent = destination.parent.lstat()
            if (current_parent.st_dev, current_parent.st_ino) != (parent_info.st_dev, parent_info.st_ino):
                fail("destination parent path rebound after removal")
            if os.fstat(parent_fd).st_dev != parent_info.st_dev or os.fstat(parent_fd).st_ino != parent_info.st_ino:
                fail("destination parent changed after removal")
            if os.fstat(root_fd).st_dev != opened_root.st_dev or os.fstat(root_fd).st_ino != opened_root.st_ino:
                fail("retained root descriptor changed after removal")
            require_child_absent(parent_fd, destination.name, "worktree destination")
            # A crash after claim/removal remains forensic uncertainty; never resume it.
            revalidate_directory(lifecycle_fd, lifecycle_identity, args.directory, "lifecycle directory")
            disposing_raw = raw_at(lifecycle_fd, "040-dispose-claim.json", "disposing claim")
            disposing_record = parse_object(disposing_raw, "disposing claim")
            disposed = state(lifecycle_fd, disposing_raw, disposing_record, "disposed", {
                "cleanupSha256": cleanup_sha256,
                "preWorktreeListSha256": pre_list_sha256,
                "postWorktreeListSha256": post_list_sha256,
                "removeArgvSha256": sha256_json(remove_argv),
                "removeCommandSha256": sha256_json({"argv": remove_argv}),
                "rootIdentitySha256": sha256_json({"canonicalPath": str(destination), "dev": opened_root.st_dev, "ino": opened_root.st_ino}),
                "registryReleaseSha256": sha256_json({"commonGitDir": str(common), "destination": str(destination), "preWorktreeListSha256": pre_list_sha256}),
            })
            revalidate_directory(lifecycle_fd, lifecycle_identity, args.directory, "lifecycle directory")
            os.replace(context_path, context_path.with_name(context_path.name + ".terminal"))
            fsync_parent(context_path)
            print(json.dumps({"disposed": disposed, "preWorktreeListSha256": pre_list_sha256,
                              "postWorktreeListSha256": post_list_sha256,
                              "removeArgv": remove_argv}, sort_keys=True))
            os.close(lifecycle_fd)
            lifecycle_fd = None
            return 0
        finally:
            if root_fd is not None:
                os.close(root_fd)
            if parent_fd is not None:
                os.close(parent_fd)
            os.close(fd)
    except Exception as exc:
        if lifecycle_fd is not None:
            os.close(lifecycle_fd)
        print(f"dispose-disposable-worktree.py: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
