#!/usr/bin/env python3
"""Independently validate R01 durable-generation proof artifacts."""
from __future__ import annotations
import argparse, hashlib, json, os, stat, sys
from pathlib import PurePosixPath

HEX = set("0123456789abcdef")
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def fail(message):
    raise ValueError(message)


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse_json(raw, label):
    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    fail(f"duplicate key in {label}")
                result[key] = value
            return result
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON {label}") from error
    if not isinstance(value, dict) or raw != canon(value):
        fail(f"{label} is not canonical JSON")
    return value


def read_regular_at(directory_fd, name):
    fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            fail("artifact is not an unlinked regular file")
        data = os.read(fd, info.st_size + 1)
        if len(data) != info.st_size or os.fstat(fd).st_size != info.st_size:
            fail("artifact changed while reading")
        return data
    finally:
        os.close(fd)


def safe_relative(path):
    pure = PurePosixPath(path)
    return (isinstance(path, str) and bool(path) and not pure.is_absolute() and
            all(part not in ("", ".", "..") for part in pure.parts))


def rooted_bytes(root_fd, path):
    if not safe_relative(path):
        fail("artifact descriptor path is not rooted relative path")
    parts = PurePosixPath(path).parts
    directory_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=directory_fd)
            try:
                info = os.fstat(child)
                if not stat.S_ISDIR(info.st_mode):
                    fail("artifact path component is not directory")
            except Exception:
                os.close(child)
                raise
            os.close(directory_fd)
            directory_fd = child
        return read_regular_at(directory_fd, parts[-1])
    finally:
        os.close(directory_fd)


def is_hash(value):
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX


def is_commit(value):
    return isinstance(value, str) and len(value) == 40 and set(value) <= HEX


def valid_tuple(value):
    return (isinstance(value, dict) and set(value) == {"macCommit", "iosCommit", "protocolCommit"}
            and all(is_commit(value[key]) for key in value))


def valid_lineage(value):
    return (isinstance(value, dict) and set(value) == {"sourceRootSha256", "sourceManifestSha256"}
            and all(is_hash(value[key]) for key in value))


def validate_proof(proof):
    required = {"schemaVersion", "kind", "tuple", "sourceLineage", "generation", "previousProofSha256"}
    if not isinstance(proof, dict) or set(proof) != required:
        fail("durable proof has an invalid shape")
    if proof["schemaVersion"] != 1 or proof["kind"] != "r01-durable-generation-proof-v1":
        fail("durable proof has an invalid type")
    if not valid_tuple(proof["tuple"]) or not valid_lineage(proof["sourceLineage"]):
        fail("durable proof has invalid tuple or source lineage")
    if type(proof["generation"]) is not int or proof["generation"] < 1:
        fail("durable proof has invalid generation")
    if proof["previousProofSha256"] is not None and not is_hash(proof["previousProofSha256"]):
        fail("durable proof has invalid predecessor hash")


def validate_request(request):
    required = {"schemaVersion", "kind", "classification", "tuple", "sourceLineage", "durableGenerationProof", "artifacts"}
    if not isinstance(request, dict) or set(request) != required:
        fail("request has an invalid shape")
    if request["schemaVersion"] != 1 or request["kind"] != "r01-generation-classification-request-v1":
        fail("request has an invalid type")
    if request["classification"] not in ("durable_generation", "archival_only"):
        fail("request has invalid classification")
    if not valid_tuple(request["tuple"]) or not valid_lineage(request["sourceLineage"]):
        fail("request has invalid tuple or source lineage")
    validate_proof(request["durableGenerationProof"])
    artifacts = request["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {"proofChain"} or not isinstance(artifacts["proofChain"], list) or not artifacts["proofChain"]:
        fail("request requires a proofChain")
    for descriptor in artifacts["proofChain"]:
        if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256"} or not safe_relative(descriptor["path"]) or not is_hash(descriptor["sha256"]):
            fail("invalid rooted artifact descriptor")


def verify(request, root_fd):
    descriptors = request["artifacts"]["proofChain"]
    seen_paths, seen_hashes, proofs = set(), set(), []
    for descriptor in descriptors:
        if descriptor["path"] in seen_paths or descriptor["sha256"] in seen_hashes:
            fail("proofChain contains duplicate descriptor")
        seen_paths.add(descriptor["path"])
        raw = rooted_bytes(root_fd, descriptor["path"])
        actual_hash = sha256(raw)
        if actual_hash != descriptor["sha256"]:
            fail("artifact descriptor hash does not match actual bytes")
        proof = parse_json(raw, "durable proof")
        validate_proof(proof)
        proofs.append((proof, actual_hash))
    expected_tuple, expected_lineage = request["tuple"], request["sourceLineage"]
    for index, (proof, proof_hash) in enumerate(proofs):
        if proof["tuple"] != expected_tuple or proof["sourceLineage"] != expected_lineage:
            fail("durable proof is not bound to request tuple and source lineage")
        if proof["generation"] != index + 1:
            fail("durable proof generation is not continuous from genesis")
        expected_previous = None if index == 0 else proofs[index - 1][1]
        if proof["previousProofSha256"] != expected_previous:
            fail("durable proof predecessor hash is not continuous")
    current, current_hash = proofs[-1]
    if request["durableGenerationProof"] != current:
        fail("request embedded durable proof does not match rooted proof artifact")
    return current, current_hash


def write_result(path, value):
    parent, name = os.path.split(path)
    directory_fd = os.open(parent or ".", os.O_RDONLY | DIRECTORY | NOFOLLOW)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=directory_fd)
        try:
            data = canon(value)
            if os.write(fd, data) != len(data):
                fail("short result write")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    try:
        request_parent, request_name = os.path.split(args.request)
        request_fd = os.open(request_parent or ".", os.O_RDONLY | DIRECTORY | NOFOLLOW)
        try:
            request_raw = read_regular_at(request_fd, request_name)
        finally:
            os.close(request_fd)
        request = parse_json(request_raw, "request")
        validate_request(request)
        root_fd = os.open(args.artifact_root, os.O_RDONLY | DIRECTORY | NOFOLLOW)
        try:
            root_info = os.fstat(root_fd)
            if not stat.S_ISDIR(root_info.st_mode):
                fail("artifact root is not a directory")
            proof, proof_hash = verify(request, root_fd)
        finally:
            os.close(root_fd)
        status = "passed" if request["classification"] == "durable_generation" else "blocked"
        reason = "independently validated durable generation proof" if status == "passed" else "archival_only classification is not remediation authority"
        result = {"schemaVersion": 1, "kind": "r01-generation-classification-result-v1", "status": status, "classification": request["classification"], "requestSha256": sha256(request_raw), "tuple": request["tuple"], "sourceLineage": request["sourceLineage"], "proofSha256": proof_hash, "generation": proof["generation"], "reason": reason}
        write_result(args.result, result)
        return 0 if status == "passed" else 2
    except Exception as error:
        print(f"validate-r01-generation-classification.py: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
