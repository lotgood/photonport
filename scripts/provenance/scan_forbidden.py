#!/usr/bin/env python3
"""Fail-closed scan for forbidden upstream blobs and normalized diff hunks."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Iterable


class ScanError(ValueError):
    pass


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_TOKEN = re.compile(r"[A-Za-z0-9_]+")
_SHINGLE_SIZE = 2
_DEFAULT_EXCLUDES = (".git", ".cache", "build", "dist", "DerivedData", "generated")


def _git(cache: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *args], cwd=cache, check=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"").decode("utf-8", "replace").strip()
        raise ScanError("git operation failed" + (f": {detail}" if detail else "")) from exc
    return result.stdout


def _validate_range(cache: Path, revision_range: str) -> None:
    if not revision_range or any(c in revision_range for c in "\x00\n\r"):
        raise ScanError("invalid git revision range")
    try:
        _git(cache, "rev-list", "--max-count=1", revision_range)
    except ScanError as exc:
        raise ScanError("invalid git revision range") from exc


def _changed_blobs(cache: Path, revision_range: str) -> dict[str, bytes]:
    raw = _git(cache, "diff", "--raw", "--no-abbrev", "--no-renames", revision_range, "--")
    entries = raw.splitlines()
    blobs: dict[str, bytes] = {}
    for entry in entries:
        if not entry:
            continue
        try:
            header, path_bytes = entry.split(b"\t", 1)
            fields = header.decode("ascii").split()
            old_hash, new_hash = fields[-3], fields[-2]
        except (ValueError, UnicodeDecodeError, IndexError) as exc:
            raise ScanError("could not parse git blob inventory") from exc
        for blob_hash in (old_hash, new_hash):
            if blob_hash == "0" * 40:
                continue
            try:
                blobs[blob_hash] = _git(cache, "cat-file", "blob", blob_hash)
            except ScanError as exc:
                raise ScanError("could not read upstream blob") from exc
    return blobs


def _normalized(lines: Iterable[str]) -> tuple[str, ...]:
    return tuple(line.strip() for line in lines if line.strip())


def _changed_hunks(cache: Path, revision_range: str) -> list[tuple[str, tuple[str, ...], int]]:
    data = _git(cache, "diff", "--no-ext-diff", "--unified=0", "--no-renames", revision_range, "--")
    text = data.decode("utf-8", "replace")
    hunks: list[tuple[str, tuple[str, ...], int]] = []
    current = ""
    lines: list[str] = []
    start = 0
    for line in text.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
        match = _HUNK.match(line)
        if match:
            if lines and current:
                hunks.append((current, _normalized(lines), start))
            lines = []
            start = int(match.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    if lines and current:
        hunks.append((current, _normalized(lines), start))
    return [
        hunk
        for hunk in hunks
        if hunk[1] and len(_TOKEN.findall(" ".join(hunk[1]))) >= 2
    ]


def _files(root: Path, outputs: set[Path]) -> list[tuple[Path, str, bytes]]:
    found: list[tuple[Path, str, bytes]] = []

    def add(path: Path, relative: str) -> None:
        if path.resolve() in outputs or path.is_symlink():
            return
        try:
            data = path.read_bytes()
            if b"\0" in data:
                return
            text = data.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise ScanError(f"cannot read shipped file {relative}") from exc
        found.append((path, relative, text.encode("utf-8")))

    manifest_path = root / "PROVENANCE.yml"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            shipped = manifest["shipped_paths"]
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ScanError("cannot read PROVENANCE.yml shipped_paths") from exc
        if not isinstance(shipped, list) or not all(isinstance(p, str) for p in shipped):
            raise ScanError("invalid PROVENANCE.yml shipped_paths")
        for relative in sorted(shipped):
            path = (root / relative).resolve()
            if os.path.commonpath([str(root), str(path)]) != str(root):
                raise ScanError(f"shipped path escapes root: {relative}")
            add(path, relative)
        return found

    for directory, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _DEFAULT_EXCLUDES)
        for name in sorted(names):
            path = Path(directory) / name
            add(path, path.relative_to(root).as_posix())
    return found


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tokens(data: bytes) -> tuple[str, ...]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ()
    return tuple(x.lower() for x in _TOKEN.findall(text))


def _shingles(tokens: tuple[str, ...]) -> set[tuple[str, ...]]:
    if len(tokens) < _SHINGLE_SIZE:
        return {tokens} if tokens else set()
    return {tokens[i:i + _SHINGLE_SIZE] for i in range(len(tokens) - _SHINGLE_SIZE + 1)}


def scan(root: Path, cache: Path, revision_range: str, exact_output: Path, review_output: Path) -> tuple[dict, dict]:
    root = root.resolve()
    cache = cache.resolve()
    _validate_range(cache, revision_range)
    blobs = _changed_blobs(cache, revision_range)
    hunks = _changed_hunks(cache, revision_range)
    outputs = {p.resolve() for p in (exact_output, review_output)}
    files = _files(root, outputs)
    blob_by_digest = {_digest(data): data for data in blobs.values()}
    exact: list[dict] = []
    reviews: list[dict] = []
    for _, path, data in files:
        digest = _digest(data)
        if digest in blob_by_digest:
            exact.append({"path": path, "kind": "blob", "sha256": digest})
        normalized_file = _normalized(data.decode("utf-8").splitlines())
        for hunk_path, hunk_lines, start in hunks:
            width = len(hunk_lines)
            for offset in range(max(0, len(normalized_file) - width + 1)):
                if normalized_file[offset:offset + width] == hunk_lines:
                    exact.append({"path": path, "kind": "hunk", "upstream_path": hunk_path, "line": offset + 1, "sha256": _digest("\n".join(hunk_lines).encode())})
                    break
        source_shingles = _shingles(_tokens(data))
        if not source_shingles:
            continue
        for blob_digest, blob_data in sorted(((_digest(v), v) for v in blobs.values())):
            common = source_shingles & _shingles(_tokens(blob_data))
            if common:
                score = len(common) / len(source_shingles | _shingles(_tokens(blob_data)))
                reviews.append({"path": path, "upstream_sha256": blob_digest, "score": round(score, 8), "shingles": len(common)})
    exact.sort(key=lambda x: (x["path"], x["kind"], x.get("upstream_path", ""), x.get("line", 0), x["sha256"]))
    reviews.sort(key=lambda x: (x["path"], -x["score"], x["upstream_sha256"]))
    return {"version": 1, "forbidden": exact}, {"version": 1, "manual_review": reviews}


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--upstream-cache", required=True, type=Path)
    parser.add_argument("--forbidden-range", required=True)
    parser.add_argument("--exact-output", required=True, type=Path)
    parser.add_argument("--review-output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        exact, review = scan(args.root, args.upstream_cache, args.forbidden_range, args.exact_output, args.review_output)
        _atomic_json(args.exact_output, exact)
        _atomic_json(args.review_output, review)
    except (OSError, ScanError) as error:
        print(f"forbidden scan failed: {error}", file=sys.stderr)
        return 1
    return 2 if exact["forbidden"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
