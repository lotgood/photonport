#!/usr/bin/env python3
"""Release Lock-B only through a durable, authority-bound source-release handoff."""
from __future__ import annotations

import argparse
import hmac
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
CONTEXT_NAME = "source-release-context.json"


def fail(message: str) -> None:
    raise RuntimeError(message)
def validate_release_command(path: Path, authority: dict, mutex: Path) -> bytes:
    data = raw(path)
    try:
        evidence = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError("invalid unlink-and-close command evidence") from exc
    expected = {"schemaVersion", "kind", "authoritySha256", "operation", "mutexPath", "argv"}
    if (not isinstance(evidence, dict) or set(evidence) != expected
            or evidence["schemaVersion"] != 1
            or evidence["kind"] != "photonport.unlink-and-close-command.v1"
            or evidence["operation"] != "unlink-and-close"
            or evidence["mutexPath"] != str(mutex)
            or evidence["argv"] != ["unlink", str(mutex)]
            or evidence["authoritySha256"] != hashlib.sha256(json.dumps(authority, sort_keys=True, separators=(",", ":")).encode()).hexdigest()):
        fail("unlink-and-close command evidence does not bind authority and mutex operation")
    return data


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
def raw_at(dfd: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dfd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            fail(f"not a regular lifecycle entry: {name}")
        data = os.read(fd, info.st_size + 1)
        if len(data) != info.st_size:
            fail(f"lifecycle entry changed while reading: {name}")
        return data
    finally:
        os.close(fd)
def object_bytes(data: bytes, label: str) -> dict:
    try: value=json.loads(data)
    except (ValueError,UnicodeDecodeError) as exc: raise RuntimeError(f"invalid JSON: {label}") from exc
    if not isinstance(value,dict): fail(f"record is not object: {label}")
    return value
def require_visible_lifecycle(directory: Path, dfd: int) -> None:
    visible = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if (os.fstat(visible).st_dev, os.fstat(visible).st_ino) != (os.fstat(dfd).st_dev, os.fstat(dfd).st_ino):
            fail("caller-visible lifecycle directory replacement detected")
    finally:
        os.close(visible)


def obj(path: Path) -> dict:
    try:
        value = json.loads(raw(path))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        fail("record is not object")
    return value


def fsync_parent(path: Path) -> None:
    fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def require_independently_held(mutex: Path) -> None:
    """A child has a different open-file description from inherited Lock-B."""
    probe = subprocess.run([sys.executable, "-c", "import fcntl,os,sys; fd=os.open(sys.argv[1],os.O_RDWR|getattr(os,'O_NOFOLLOW',0));\ntry: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); sys.exit(1)\nexcept BlockingIOError: sys.exit(0)", str(mutex)])
    if probe.returncode != 0:
        fail("supervisor mutex capability does not hold Lock-B")

def supervisor_mutex(fd: int, mutex: Path) -> os.stat_result:
    try:
        held = os.fstat(fd)
        named = mutex.stat()
    except OSError as exc:
        raise RuntimeError("supervisor mutex capability is unavailable") from exc
    if not stat.S_ISREG(held.st_mode) or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
        fail("supervisor mutex capability does not name the canonical mutex")
    # A distinct open-file description must observe Lock-B held first.
    require_independently_held(mutex)
    # flock succeeds only for the owning open-file description; an unlocked
    # inherited descriptor contending with an unrelated holder raises.
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise RuntimeError("inherited supervisor capability is not the Lock-B holder") from exc
    return held


def transition_for(record: dict, closing_raw: bytes, command_bytes: bytes) -> dict:
    closing_sha256 = hashlib.sha256(closing_raw).hexdigest()
    return {"schemaVersion": 1, "kind": "photonport.lifecycle-transition.v1", "lifecycleId": record["lifecycleId"], "rootId": record["rootId"], "tuple": record["tuple"], "allocation": record["allocation"], "authority": record["authority"], "fromState": "source-closing", "toState": "source-released", "predecessorSha256": closing_sha256, "closingSha256": closing_sha256, "releasedByUnlinkAndClose": True, "releaseCommandSha256": hashlib.sha256(command_bytes).hexdigest()}


def lifecycle(directory_fd: int, transition: dict, *, validate_only: bool = False) -> dict:
    fd, name = tempfile.mkstemp(prefix="lifecycle-transition-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(transition, out, sort_keys=True, separators=(",", ":"))
            out.write("\n"); out.flush(); os.fsync(out.fileno())
        spec = importlib.util.spec_from_file_location("lifecycle_transition", CORE)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module.transition_authorized(directory=None, directory_fd=directory_fd, transition=Path(name), expected_state="source-released", _capability=module._WRAPPER_CAPABILITY, validate_only=validate_only)
    finally:
        os.unlink(name)


def validate_binding(args: argparse.Namespace, closing_record: dict) -> tuple[Path, dict]:
    authority = closing_record.get("authority")
    if not isinstance(authority, dict):
        fail("source-closing state has no authority")
    root_info = args.root.lstat()
    if (stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode)
            or Path(os.path.realpath(args.root)) != Path(authority.get("root", {}).get("canonicalPath", ""))
            or (root_info.st_dev, root_info.st_ino) != (authority.get("root", {}).get("dev"), authority.get("root", {}).get("ino"))):
        fail("caller-selected root does not match lifecycle authority")
    mutex = Path(authority.get("lockBPath", ""))
    if Path(os.path.realpath(args.mutex)) != mutex:
        fail("caller-selected Lock-B path does not match lifecycle authority")
    return mutex, authority


def write_context(dfd: int, closing_raw: bytes, transition: dict, mutex: Path, held: os.stat_result, secret_sha256: str, lifecycle_stat: os.stat_result, command_bytes: bytes) -> None:
    context = {"schemaVersion": 1, "kind": "photonport.source-release-context.v1", "closingSha256": hashlib.sha256(closing_raw).hexdigest(), "commandSha256": hashlib.sha256(command_bytes).hexdigest(), "lifecycleDev": lifecycle_stat.st_dev, "lifecycleIno": lifecycle_stat.st_ino, "transition": transition, "authority": transition["authority"], "mutexPath": str(mutex), "mutexDev": held.st_dev, "mutexIno": held.st_ino, "supervisorFdDev": held.st_dev, "supervisorFdIno": held.st_ino, "closeSecretSha256": secret_sha256}
    fd = os.open(CONTEXT_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dfd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(context, out, sort_keys=True, separators=(",", ":")); out.write("\n"); out.flush(); os.fsync(out.fileno())
        os.fsync(dfd)
    except Exception:
        try: os.unlink(CONTEXT_NAME, dir_fd=dfd); os.fsync(dfd)
        except OSError: pass
        raise


def valid_context(context_raw: bytes, context_obj: dict, closing_raw: bytes, mutex: Path, command_bytes: bytes, lifecycle_stat: os.stat_result) -> dict:
    context = context_obj
    required = {"schemaVersion", "kind", "closingSha256", "commandSha256", "lifecycleDev", "lifecycleIno", "transition", "authority", "mutexPath", "mutexDev", "mutexIno", "supervisorFdDev", "supervisorFdIno", "closeSecretSha256"}
    if set(context) != required or context["schemaVersion"] != 1 or context["kind"] != "photonport.source-release-context.v1":
        fail("invalid source-release context")
    transition = context["transition"]
    if (not isinstance(transition, dict) or context["closingSha256"] != hashlib.sha256(closing_raw).hexdigest() or context["commandSha256"] != hashlib.sha256(command_bytes).hexdigest() or (context["lifecycleDev"],context["lifecycleIno"]) != (lifecycle_stat.st_dev,lifecycle_stat.st_ino) or transition.get("authority") != context["authority"] or transition.get("fromState") != "source-closing" or transition.get("toState") != "source-released" or context["mutexPath"] != str(mutex) or context["mutexDev"] != context["supervisorFdDev"] or context["mutexIno"] != context["supervisorFdIno"]):
        fail("source-release context does not bind lifecycle authority and evidence")
    return transition



def finish(dfd: int, transition: dict) -> dict:
    result = lifecycle(dfd, transition)
    os.unlink(CONTEXT_NAME, dir_fd=dfd)
    os.fsync(dfd)
    return result


def close_secret(fd: int) -> bytes:
    try:
        value = os.pread(fd, 33, 0)
    except OSError as exc:
        raise RuntimeError("supervisor close capability is unavailable") from exc
    if len(value) != 32:
        fail("supervisor close capability must be exactly 32 bytes")
    return value


def valid_close_ack(ack_raw: bytes, context_raw: bytes, context_obj: dict, closing_raw: bytes, authority: dict, secret_fd: int) -> None:
    ack = object_bytes(ack_raw, "supervisor close acknowledgment")
    expected = {"schemaVersion", "kind", "contextSha256", "closingSha256", "authoritySha256", "tag"}
    if set(ack) != expected or ack["schemaVersion"] != 1 or ack["kind"] != "photonport.supervisor-close-ack.v1": fail("invalid supervisor-close acknowledgment")
    authority_raw = json.dumps(authority, sort_keys=True, separators=(",", ":")).encode()
    if ack["contextSha256"] != hashlib.sha256(context_raw).hexdigest() or ack["closingSha256"] != hashlib.sha256(closing_raw).hexdigest() or ack["authoritySha256"] != hashlib.sha256(authority_raw).hexdigest(): fail("supervisor-close acknowledgment lineage mismatch")
    body = {key: ack[key] for key in ("schemaVersion", "kind", "contextSha256", "closingSha256", "authoritySha256")}
    secret = close_secret(secret_fd)
    if hashlib.sha256(secret).hexdigest() != context_obj["closeSecretSha256"]: fail("supervisor close capability substitution detected")
    expected_tag = hmac.new(secret, json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    if not isinstance(ack["tag"], str) or not hmac.compare_digest(ack["tag"], expected_tag): fail("supervisor-close acknowledgment authentication failed")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--mutex", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--supervisor-fd", type=int, help="only for --prepare-close; owned by supervisor")
    parser.add_argument("--supervisor-close-secret-fd", type=int, help="inherited supervisor-only close-authentication capability")
    parser.add_argument("--supervisor-close-ack", type=Path, help="authenticated acknowledgment written after supervisor closes Lock-B")
    parser.add_argument("--unlink-and-close-command", type=Path, required=True,
                        help="immutable command evidence for this unlink-and-close release")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--prepare-close", action="store_true", help="durably attest release preflight before the supervisor closes Lock-B")
    action.add_argument("--finalize", action="store_true", help="complete release only after the supervisor capability is closed")
    args = parser.parse_args()
    try:
        dfd = os.open(args.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        lifecycle_stat = os.fstat(dfd)
        closing_bytes = raw_at(dfd, "020-source-closing.json")
        closing_record = object_bytes(closing_bytes, "source-closing")
        closing = args.directory / "020-source-closing.json"; active = args.directory / "010-source-active.json"; released = args.directory / "030-source-released.json"; context = args.directory / CONTEXT_NAME
        if "010-source-active.json" not in os.listdir(dfd):
            fail("source-closing barrier and active state are required")
        mutex, authority = validate_binding(args, closing_record)
        command_bytes = validate_release_command(args.unlink_and_close_command, authority, mutex)
        if released.exists():
            fail("source already released")
        if not mutex.exists():
            fail("absent Lock-B mutex is unrecoverable without live authority observation")
        mutex_record = obj(mutex)
        authority = closing_record["authority"]
        if (closing_record.get("lifecycleId") != mutex_record.get("lifecycleId") or closing_record.get("rootId") != mutex_record.get("rootId") or closing_record.get("allocation") != mutex_record.get("allocation") or mutex_record.get("allocationNonce") != authority.get("allocationNonce") or mutex_record.get("mutexNonce") != authority.get("mutexNonce") or mutex_record.get("supervisor") != authority.get("supervisor")):
            fail("mutex lineage or authority capability mismatch")
        root_info = args.root.stat()
        if mutex_record.get("rootDev") != root_info.st_dev or mutex_record.get("rootIno") != root_info.st_ino:
            fail("root identity mismatch")
        transition = transition_for(closing_record, closing_bytes, command_bytes)
        lifecycle(dfd, transition, validate_only=True)
        if args.prepare_close:
            if args.supervisor_fd is None:
                fail("--prepare-close requires an inherited supervisor capability")
            held = supervisor_mutex(args.supervisor_fd, mutex)
            if args.supervisor_close_secret_fd is None:
                fail("--prepare-close requires the supervisor close capability")
            close_secret(args.supervisor_close_secret_fd)
            try: raw_at(dfd, CONTEXT_NAME); fail("release intent already exists")
            except FileNotFoundError: pass
            write_context(dfd, closing_bytes, transition, mutex, held, hashlib.sha256(close_secret(args.supervisor_close_secret_fd)).hexdigest(), lifecycle_stat, command_bytes)
            print(json.dumps({"readyToClose": True, "supervisorMustClose": True, "context": str(context)}, sort_keys=True))
            return 0
        if args.supervisor_fd is not None:
            fail("--finalize must not receive a supervisor capability")
        if args.supervisor_fd is not None or args.supervisor_close_ack is None or args.supervisor_close_secret_fd is None:
            fail("finalization requires release intent, authenticated close acknowledgment, and supervisor close capability")
        context_raw = raw_at(dfd, CONTEXT_NAME)
        context_obj = object_bytes(context_raw, "source-release context")
        transition = valid_context(context_raw, context_obj, closing_bytes, mutex, command_bytes, lifecycle_stat)
        ack_raw = raw(args.supervisor_close_ack)
        valid_close_ack(ack_raw, context_raw, context_obj, closing_bytes, transition["authority"], args.supervisor_close_secret_fd)
        require_visible_lifecycle(args.directory, dfd)
        # A successful nonblocking flock on a fresh open proves the supervisor's
        # original Lock-B open description is no longer holding the advisory lock.
        parent_fd = os.open(mutex.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        probe = os.open(mutex.name, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            probe_stat = os.fstat(probe)
            context_record = context_obj
            if (probe_stat.st_dev, probe_stat.st_ino) != (context_record["mutexDev"], context_record["mutexIno"]):
                raise RuntimeError("Lock-B replacement detected; refusing source release")
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.unlink(mutex.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError as exc:
            raise RuntimeError("supervisor capability remains open or Lock-B unlink failed; refusing source release") from exc
        finally:
            os.close(probe)
            os.close(parent_fd)
        require_visible_lifecycle(args.directory, dfd)
        if os.fstat(dfd).st_dev != lifecycle_stat.st_dev or os.fstat(dfd).st_ino != lifecycle_stat.st_ino:
            fail("lifecycle directory authority changed")
        result = finish(dfd, transition)
        require_visible_lifecycle(args.directory, dfd)
        print(json.dumps({"releasedByFinalize": True, "supervisorCapabilityClosed": True, **result}, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"release-source-root-mutex.py: error: {exc}", file=sys.stderr)
        return 2
    finally:
        if "dfd" in locals():
            os.close(dfd)


if __name__ == "__main__":
    sys.exit(main())
