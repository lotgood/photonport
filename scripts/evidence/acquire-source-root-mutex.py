#!/usr/bin/env python3
"""Admit a source root and bind it to a supervisor-held Lock-B capability."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

CORE = Path(__file__).with_name("transition-lifecycle-state.py")
STATES = ("allocated", "source-active", "source-closing", "source-released", "disposing", "disposed")


def fail(message: str) -> None:
    raise RuntimeError(message)


def raw(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            fail(f"not a regular file: {path}")
        data = os.read(fd, info.st_size + 1)
        if len(data) != info.st_size:
            fail(f"changed while reading: {path}")
        return data
    finally:
        os.close(fd)


def obj(path: Path) -> dict:
    try:
        value = json.loads(raw(path))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        fail(f"not an object: {path}")
    return value


def fsync_parent(path: Path) -> None:
    fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_at(dfd: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dfd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            fail("lifecycle entry is not a regular file")
        return os.read(fd, info.st_size + 1)
    finally:
        os.close(fd)


def admit(directory: Path, allocation_released: Path) -> tuple[int, dict, bytes, bytes]:
    """Pin the lifecycle directory before reading its durable history."""
    info = directory.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("lifecycle directory must be a non-symlink directory")
    dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        pinned = os.fstat(dfd)
        if (pinned.st_dev, pinned.st_ino) != (info.st_dev, info.st_ino):
            fail("lifecycle directory changed while opening")
        entries = set(os.listdir(dfd))
        if entries != {"000-allocated.json"}:
            fail("source acquisition requires the sole durable state to be allocated")
        allocated_raw = _read_at(dfd, "000-allocated.json")
        allocated = json.loads(allocated_raw)
        if not isinstance(allocated, dict) or allocated.get("state") != "allocated":
            fail("allocated state missing")
        release_raw = raw(allocation_released)
        try:
            release = json.loads(release_raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("invalid allocation release JSON") from exc
        if not isinstance(release, dict):
            fail("allocation release is not an object")
        if (release.get("lifecycleId") != allocated.get("lifecycleId")
                or release.get("rootId") != allocated.get("rootId")
                or release.get("allocation") != allocated.get("allocation")
                or release.get("allocationNonce") != allocated.get("authority", {}).get("allocationNonce")
                or release.get("allocatedSha256") != hashlib.sha256(allocated_raw).hexdigest()):
            fail("allocation release lineage mismatch")
        return dfd, allocated, allocated_raw, release_raw
    except Exception:
        os.close(dfd)
        raise


def require_independently_held(mutex: Path) -> None:
    """A child has a different open-file description from inherited Lock-B."""
    probe = subprocess.run([sys.executable, "-c", "import fcntl,os,sys; fd=os.open(sys.argv[1],os.O_RDWR|getattr(os,'O_NOFOLLOW',0));\ntry: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); sys.exit(1)\nexcept BlockingIOError: sys.exit(0)", str(mutex)])
    if probe.returncode != 0:
        fail("supervisor mutex capability does not hold Lock-B")

def require_visible_identity(directory: Path, mutex: Path, directory_fd: int, supervisor_fd: int) -> None:
    visible_directory = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    visible_mutex = os.open(mutex, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if (os.fstat(visible_directory).st_dev, os.fstat(visible_directory).st_ino) != (os.fstat(directory_fd).st_dev, os.fstat(directory_fd).st_ino):
            fail("caller-visible lifecycle directory replacement detected")
        if (os.fstat(visible_mutex).st_dev, os.fstat(visible_mutex).st_ino) != (os.fstat(supervisor_fd).st_dev, os.fstat(supervisor_fd).st_ino):
            fail("caller-visible Lock-B replacement detected")
    finally:
        os.close(visible_mutex)
        os.close(visible_directory)
def supervisor_mutex(fd: int, mutex: Path) -> None:
    """Validate the inherited, pre-created fd that the supervisor will retain."""
    try:
        held = os.fstat(fd)
        named = mutex.stat()
    except OSError as exc:
        raise RuntimeError("supervisor mutex capability is unavailable") from exc
    if not stat.S_ISREG(held.st_mode) or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
        fail("supervisor mutex capability does not name the canonical mutex")
    # First prove a distinct open-file description observes Lock-B as held.
    require_independently_held(mutex)
    # Then prove this inherited descriptor is that holder.  This succeeds for
    # the same open-file description, but an unlocked descriptor contending
    # with a different holder fails without changing ownership.
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise RuntimeError("inherited supervisor capability is not the Lock-B holder") from exc
def authority_binding(allocated: dict, root: Path, mutex: Path) -> tuple[dict, os.stat_result]:
    authority = allocated.get("authority")
    if not isinstance(authority, dict):
        fail("allocated state has no authority")
    root_info = root.lstat()
    canonical_root = Path(os.path.realpath(root))
    canonical_mutex = Path(os.path.realpath(mutex))
    expected_root = authority.get("root", {})
    if (stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode)
            or canonical_root != Path(expected_root.get("canonicalPath", ""))
            or (root_info.st_dev, root_info.st_ino) != (expected_root.get("dev"), expected_root.get("ino"))):
        fail("caller-selected root does not match lifecycle authority")
    if canonical_mutex != Path(authority.get("lockBPath", "")):
        fail("caller-selected Lock-B path does not match lifecycle authority")
    return authority, root_info



def transition(directory_fd: int, allocated: dict, target: str, predecessor_raw: bytes, allocation_release_raw: bytes) -> dict:
    record = {"schemaVersion": 1, "kind": "photonport.lifecycle-transition.v1", "lifecycleId": allocated["lifecycleId"], "rootId": allocated["rootId"], "tuple": allocated["tuple"], "allocation": allocated["allocation"], "authority": allocated["authority"], "fromState": allocated["state"], "toState": target, "predecessorSha256": hashlib.sha256(predecessor_raw).hexdigest(), "allocationReleaseSha256": hashlib.sha256(allocation_release_raw).hexdigest()}
    fd, name = tempfile.mkstemp(prefix="lifecycle-transition-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(record, out, sort_keys=True, separators=(",", ":"))
            out.write("\n")
        spec = importlib.util.spec_from_file_location("lifecycle_transition", CORE)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module.transition_authorized(directory=None, directory_fd=directory_fd, transition=Path(name), expected_state="source-active", _capability=module._WRAPPER_CAPABILITY)
    finally:
        os.unlink(name)


def supervisor_close_secret(fd: int) -> bytes:
    try:
        value = os.pread(fd, 33, 0)
    except OSError as exc:
        raise RuntimeError("supervisor close capability is unavailable") from exc
    if len(value) != 32:
        fail("supervisor close capability must be exactly 32 bytes")
    return value
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--allocation-released", type=Path, required=True)
    parser.add_argument("--mutex", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--supervisor-fd", type=int, required=True,
                        help="inherited Lock-B fd retained and closed by the supervisor only after release")
    parser.add_argument("--supervisor-close-secret-fd", type=int, required=True,
                        help="inherited private supervisor close-authentication capability")
    args = parser.parse_args()
    try:
        directory_fd, allocated, allocated_raw, release_raw = admit(args.directory, args.allocation_released)
        try:
            authority, root_stat = authority_binding(allocated, args.root, args.mutex)
            supervisor_mutex(args.supervisor_fd, args.mutex)
            secret = supervisor_close_secret(args.supervisor_close_secret_fd)
            held = os.fstat(args.supervisor_fd)
            payload = {"lifecycleId": allocated["lifecycleId"], "rootId": allocated["rootId"], "allocation": allocated["allocation"], "authority": authority, "allocationNonce": authority["allocationNonce"], "mutexNonce": authority["mutexNonce"], "supervisor": authority["supervisor"], "rootDev": root_stat.st_dev, "rootIno": root_stat.st_ino, "mutexDev": held.st_dev, "mutexIno": held.st_ino, "supervisorFdDev": held.st_dev, "supervisorFdIno": held.st_ino, "closeSecretSha256": hashlib.sha256(secret).hexdigest()}
            unsigned = dict(payload)
            payload["acquisitionTag"] = hmac.new(secret, json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
            os.lseek(args.supervisor_fd, 0, os.SEEK_SET)
            os.ftruncate(args.supervisor_fd, 0)
            os.write(args.supervisor_fd, (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode())
            os.fsync(args.supervisor_fd)
            fsync_parent(args.mutex)
            require_visible_identity(args.directory, args.mutex, directory_fd, args.supervisor_fd)
            result = transition(directory_fd, allocated, "source-active", allocated_raw, release_raw)
            require_visible_identity(args.directory, args.mutex, directory_fd, args.supervisor_fd)
            print(json.dumps({"mutex": str(args.mutex), "mutexSha256": hashlib.sha256(raw(args.mutex)).hexdigest(), "supervisorFd": args.supervisor_fd, **result}, sort_keys=True))
            return 0
        finally:
            os.close(directory_fd)
        return 0
    except Exception as exc:
        print(f"acquire-source-root-mutex.py: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
