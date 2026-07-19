#!/usr/bin/env python3
"""Classify R01 generation evidence without accessing or changing source roots."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import secrets
from pathlib import Path

MAX_BYTES = 1_048_576
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REQUEST_KEYS = {"schemaVersion", "kind", "sourceTuple", "sourceHashes", "classification", "durableEvidence"}


def fail(message: str) -> None:
    raise ValueError(message)


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_regular(path: Path) -> bytes:
    try:
        before = path.lstat()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        fail(f"request is unavailable: {exc}")
    try:
        info = os.fstat(fd)
        if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(info.st_mode)
                or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)
                or info.st_size > MAX_BYTES):
            fail("request must be a bounded stable regular non-symlink file")
        data = os.read(fd, info.st_size + 1)
        if len(data) != info.st_size or os.fstat(fd).st_size != info.st_size:
            fail("request changed while reading")
        return data
    finally:
        os.close(fd)


def parse_request(data: bytes) -> dict:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        fail(f"request is not valid UTF-8 JSON: {exc}")
    if not isinstance(value, dict) or set(value) != REQUEST_KEYS:
        fail("request fields are not exact")
    if (type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["kind"] != "photonport.r01-generation-classification-request.v1"):
        fail("unsupported request schema or kind")
    validate_tuple(value["sourceTuple"])
    validate_source_hashes(value["sourceHashes"])
    classification = value["classification"]
    if classification not in ("archival_only", "durable_proof"):
        fail("classification must be archival_only or durable_proof")
    evidence = value["durableEvidence"]
    if not isinstance(evidence, list):
        fail("durableEvidence must be an array")
    ids = set()
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"id", "sha256"}:
            fail("durable evidence fields are not exact")
        if not isinstance(item["id"], str) or not EVIDENCE_ID.fullmatch(item["id"]):
            fail("durable evidence id is invalid")
        if item["id"] in ids:
            fail("durable evidence ids must be unique")
        ids.add(item["id"])
        if not isinstance(item["sha256"], str) or not HEX64.fullmatch(item["sha256"]):
            fail("durable evidence sha256 is invalid")
    if classification == "archival_only" and evidence:
        fail("archival_only must not claim durable evidence")
    if classification == "durable_proof" and not evidence:
        fail("durable_proof requires durable evidence")
    return value


def validate_tuple(value) -> None:
    keys = {"macCommit", "iosCommit", "protocolCommit", "compatibilityDigest", "normativeManifestDigest"}
    if not isinstance(value, dict) or set(value) != keys:
        fail("sourceTuple fields are not exact")
    for key in ("macCommit", "iosCommit", "protocolCommit"):
        if not isinstance(value[key], str) or not HEX40.fullmatch(value[key]):
            fail(f"sourceTuple.{key} is invalid")
    for key in ("compatibilityDigest", "normativeManifestDigest"):
        if not isinstance(value[key], str) or not HEX64.fullmatch(value[key]):
            fail(f"sourceTuple.{key} is invalid")


def validate_source_hashes(value) -> None:
    if not isinstance(value, dict) or set(value) != {"mac", "ios", "protocol"}:
        fail("sourceHashes fields are not exact")
    if any(not isinstance(item, str) or not HEX64.fullmatch(item) for item in value.values()):
        fail("sourceHashes values are invalid")


def write_atomically(path: Path, data: bytes) -> None:
    parent = path.parent
    try:
        before = parent.lstat()
        dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        fail(f"output directory is unavailable: {exc}")
    temporary = None
    try:
        info = os.fstat(dfd)
        if (stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(info.st_mode)
                or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)):
            fail("output directory must be a stable non-symlink directory")
        try:
            existing = os.stat(path.name, dir_fd=dfd, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode):
                fail("output must replace only a regular file")
        except FileNotFoundError:
            pass
        for _ in range(16):
            temporary = f".{path.name}.{secrets.token_hex(16)}.tmp"
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dfd)
                break
            except FileExistsError:
                temporary = None
        else:
            fail("cannot allocate atomic output")
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path.name, src_dir_fd=dfd, dst_dir_fd=dfd)
        temporary = None
        os.fsync(dfd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=dfd)
            except FileNotFoundError:
                pass
        os.close(dfd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        request_bytes = read_regular(args.request)
        request = parse_request(request_bytes)
        try:
            request_identity = args.request.resolve().stat()
            output_identity = args.output.resolve().stat()
            if (request_identity.st_dev, request_identity.st_ino) == (output_identity.st_dev, output_identity.st_ino):
                fail("output must not replace the request")
        except FileNotFoundError:
            pass
        result = {
            "schemaVersion": 1,
            "kind": "photonport.r01-generation-classification-result.v1",
            "requestSha256": hashlib.sha256(request_bytes).hexdigest(),
            "sourceTuple": request["sourceTuple"],
            "sourceHashes": request["sourceHashes"],
            "classification": request["classification"],
            "durableEvidence": request["durableEvidence"],
            "status": "passed" if request["classification"] == "durable_proof" else "blocked",
        }
        output = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        write_atomically(args.output, output)
        print(json.dumps({"classification": result["classification"], "status": result["status"], "resultSha256": hashlib.sha256(output).hexdigest()}, sort_keys=True))
        return 0 if result["status"] == "passed" else 2
    except Exception as exc:
        print(f"validate-r01-generation-classification.py: FAIL_CLOSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
