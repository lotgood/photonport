#!/usr/bin/env python3
"""Archive deterministic, license-gated evidence from a git commit range."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


class ArchiveError(ValueError):
    """Raised when the requested evidence cannot be established completely."""


def _git(repo: Path, *args: str, input_bytes=None) -> bytes:
    try:
        result = subprocess.run(
            ["git", *args], cwd=repo, input=input_bytes, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", b"").decode("utf-8", "replace").strip()
        command = "git " + " ".join(args)
        raise ArchiveError(f"{command} failed{': ' + detail if detail else ''}") from error
    return result.stdout


def _resolve(repo: Path, name: str) -> str:
    value = _git(repo, "rev-parse", "--verify", f"{name}^{{commit}}").decode().strip()
    if len(value) != 40:
        raise ArchiveError(f"ref {name!r} did not resolve to a SHA-1 commit")
    return value


def _ensure_objects(repo: Path, refs: tuple[str, str]) -> None:
    missing = []
    for ref in refs:
        try:
            _resolve(repo, ref)
        except ArchiveError:
            missing.append(ref)
    if missing:
        try:
            _git(repo, "fetch", "--no-tags", "origin", *missing)
        except ArchiveError as error:
            raise ArchiveError(
                "required pinned git objects are unavailable; fetch failed: " + str(error)
            ) from error


def _mit_license(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    folded = " ".join(text.split()).casefold()
    required = (
        "mit license",
        "permission is hereby granted, free of charge, to any person obtaining a copy",
        "the software is provided \"as is\", without warranty of any kind",
        "in no event shall the authors or copyright holders be liable",
    )
    return all(fragment in folded for fragment in required)


def _root_license(repo: Path, commit: str) -> tuple[str, bytes]:
    listing = _git(repo, "ls-tree", "-z", commit, "--", "LICENSE")
    entries = listing.split(b"\0")
    if len(entries) != 2 or not entries[0]:
        raise ArchiveError(f"commit {commit} has no exact root LICENSE blob")
    entry = entries[0]
    try:
        metadata, name = entry.split(b"\t", 1)
        mode, kind, blob = metadata.decode("ascii").split()
    except (ValueError, UnicodeDecodeError) as error:
        raise ArchiveError(f"commit {commit} has an invalid root LICENSE tree entry") from error
    if name != b"LICENSE" or kind != "blob" or mode not in {"100644", "100755"}:
        raise ArchiveError(f"commit {commit} root LICENSE is not a regular blob")
    if len(blob) != 40:
        raise ArchiveError(f"commit {commit} root LICENSE has an invalid SHA-1")
    data = _git(repo, "cat-file", "blob", blob)
    if not _mit_license(data):
        raise ArchiveError(f"commit {commit} root LICENSE is not byte-verified MIT")
    return blob, data


def archive(repo_input: str, anchor: str, through: str, output: Path) -> dict:
    temporary = None
    source = Path(repo_input).expanduser()
    if not source.exists():
        temporary = tempfile.TemporaryDirectory(prefix="archive-baselines-")
        destination = Path(temporary.name) / "repo"
        try:
            subprocess.run(
                ["git", "clone", "--no-checkout", "--no-tags", "--no-single-branch",
                 repo_input, str(destination)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            detail = getattr(error, "stderr", b"").decode("utf-8", "replace").strip()
            raise ArchiveError(f"git clone failed: {detail}") from error
        source = destination
    try:
        _ensure_objects(source, (anchor, through))
        anchor_sha = _resolve(source, anchor)
        through_sha = _resolve(source, through)
        try:
            subprocess.run(["git", "merge-base", "--is-ancestor", anchor_sha, through_sha],
                           cwd=source, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError) as error:
            raise ArchiveError("anchor is not an ancestor of through commit") from error
        commits = _git(
            source,
            "rev-list",
            "--reverse",
            "--topo-order",
            through_sha,
            "--not",
            f"{anchor_sha}^@",
        ).decode().splitlines()
        commits = [item for item in commits if item]
        if not commits or commits[0] != anchor_sha or commits[-1] != through_sha:
            raise ArchiveError("requested commit range produced incomplete evidence")
        records = []
        for commit in commits:
            commit_bytes = _git(source, "cat-file", "commit", commit)
            tree_sha = _git(source, "show", "-s", "--format=%T", commit).decode().strip()
            tree_bytes = _git(source, "cat-file", "tree", tree_sha)
            license_sha, license_bytes = _root_license(source, commit)
            metadata = _git(
                source,
                "show",
                "-s",
                "--format=%an%x00%ae%x00%aI%x00%cI%x00%P",
                commit,
            ).decode("utf-8", "strict").rstrip("\n").split("\0")
            if len(metadata) != 5:
                raise ArchiveError(f"incomplete commit metadata for {commit}")
            records.append({
                "commit_sha1": commit,
                "commit_sha256": hashlib.sha256(commit_bytes).hexdigest(),
                "tree_sha1": tree_sha,
                "tree_sha256": hashlib.sha256(tree_bytes).hexdigest(),
                "license_sha1": license_sha,
                "license_sha256": hashlib.sha256(license_bytes).hexdigest(),
                "license_classification": "MIT_EXACT",
                "author_name": metadata[0],
                "author_email": metadata[1],
                "author_date": metadata[2],
                "committer_date": metadata[3],
                "parent_sha1": metadata[4].split(),
            })
        report = {"schema_version": 1, "repository": repo_input, "anchor": anchor_sha,
                  "through": through_sha, "commits": records}
        payload = (json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
        output.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_output = tempfile.mkstemp(prefix=output.name + ".", dir=output.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_output, output)
        finally:
            if os.path.exists(temporary_output):
                os.unlink(temporary_output)
        return report
    finally:
        if temporary is not None:
            temporary.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--anchor", required=True)
    parser.add_argument("--through", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        archive(args.repo, args.anchor, args.through, args.output)
    except (ArchiveError, OSError) as error:
        print(f"baseline archive failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
