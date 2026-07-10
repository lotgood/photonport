#!/usr/bin/env python3
"""Build a deterministic, fail-closed provenance triage inventory from git."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

APPROVAL = "TRIAGE_ONLY_REQUIRES_INDEPENDENT_REVIEW"
CLASSIFICATIONS = ("MIT_EXACT", "PHOTONPORT_OWNED", "UPSTREAM_GPL", "AMBIGUOUS")


class InventoryError(ValueError):
    pass


def git(repo: Path, *args: str, check: bool = True) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args], text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        raise InventoryError("git " + " ".join(args) + ": " + p.stderr.strip())
    return p.stdout


def commit_class(repo: Path, commit: str, mit: str, transition: str,
                  authors: set[str]) -> str:
    p = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, mit],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode == 0:
        return "MIT_EXACT"
    if p.returncode not in (1,):
        raise InventoryError("cannot inspect MIT ancestry: " + p.stderr.decode(errors="replace").strip())
    ident = git(repo, "show", "-s", "--format=%an\n%ae", commit).splitlines()
    if len(ident) >= 2 and (ident[0].strip() in authors or ident[1].strip() in authors):
        return "PHOTONPORT_OWNED"
    p = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", transition, commit],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode == 0:
        return "UPSTREAM_GPL"
    if p.returncode not in (1,):
        raise InventoryError("cannot inspect GPL ancestry: " + p.stderr.decode(errors="replace").strip())
    return "AMBIGUOUS"


def blob(repo: Path, commit: str, path: str) -> str:
    out = git(repo, "rev-parse", f"{commit}:{path}").strip()
    if len(out) != 40:
        raise InventoryError(f"missing blob for {path}")
    return out


def author_evidence(repo: Path, commit: str) -> dict[str, str]:
    vals = git(repo, "show", "-s", "--format=%an\n%ae", commit).splitlines()
    if len(vals) < 2:
        raise InventoryError(f"missing author evidence for {commit}")
    return {"name": vals[0], "email": vals[1]}


def base_region(repo: Path, commit: str, path: str, source_start: int,
                source_end: int, output_start: int, output_end: int,
                classification: str) -> dict:
    return {
        "output_lines": [output_start, output_end],
        "source_commit": commit,
        "source_blob": blob(repo, commit, path),
        "source_path": path,
        "source_lines": [source_start, source_end],
        "author_evidence": author_evidence(repo, commit),
        "classification": classification,
    }


def text_entry(repo: Path, rev: str, path: str, data: bytes, mit: str,
               transition: str, authors: set[str]) -> dict:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return binary_entry(repo, rev, path, data, mit, transition, authors)
    regions: list[dict] = []
    raw = git(repo, "blame", "--line-porcelain", rev, "--", path).splitlines()
    i = 0
    output_no = 0
    commit_metadata: dict[str, dict[str, str]] = {}
    while i < len(raw):
        bits = raw[i].split()
        if (
            len(bits) not in (3, 4)
            or len(bits[0]) != 40
            or any(c not in "0123456789abcdef" for c in bits[0].lower())
        ):
            raise InventoryError(f"malformed blame header for {path}")
        commit, orig_s, final_s = bits[:3]
        try:
            orig, final = int(orig_s), int(final_s)
        except ValueError:
            raise InventoryError(f"malformed blame numbers for {path}")
        meta = dict(commit_metadata.get(commit, {}))
        i += 1
        while i < len(raw) and not raw[i].startswith("\t"):
            if " " in raw[i]:
                key, value = raw[i].split(" ", 1)
            else:
                key, value = raw[i], ""
            meta[key] = value
            i += 1
        if i >= len(raw):
            raise InventoryError(f"malformed blame source line for {path}")
        commit_metadata[commit] = meta
        output_no += 1
        if final != output_no:
            raise InventoryError(f"malformed blame continuity for {path}")
        source_path = meta.get("filename", path)
        cls = commit_class(repo, commit, mit, transition, authors)
        region_key = (cls, commit, source_path, orig - output_no)
        if (
            regions
            and regions[-1]["_key"] == region_key
            and regions[-1]["source_lines"][1] + 1 == orig
            and regions[-1]["output_lines"][1] + 1 == output_no
        ):
            regions[-1]["source_lines"][1] = orig
            regions[-1]["output_lines"][1] = output_no
        else:
            region = base_region(
                repo, commit, source_path, orig, orig, output_no, output_no, cls
            )
            region["_key"] = region_key
            regions.append(region)
        i += 1
    for region in regions:
        region.pop("_key", None)
    if not regions:
        raise InventoryError(f"empty blame for {path}")
    return {"path": path, "binary": False, "whole_file": False,
            "output_blob_sha256": hashlib.sha256(data).hexdigest(), "regions": regions}


def binary_entry(repo: Path, rev: str, path: str, data: bytes, mit: str,
                  transition: str, authors: set[str]) -> dict:
    log = git(repo, "log", "-1", "--format=%H", rev, "--", path).strip()
    if not log:
        raise InventoryError(f"missing binary history for {path}")
    cls = commit_class(repo, log, mit, transition, authors)
    return {"path": path, "binary": True, "whole_file": True,
            "output_blob_sha256": hashlib.sha256(data).hexdigest(),
            "source_commit": log, "source_blob": blob(repo, log, path),
            "source_path": path, "source_lines": [1, 1],
            "author_evidence": author_evidence(repo, log), "classification": cls}


def build(args) -> dict:
    repo = args.repo.resolve()
    if git(repo, "rev-parse", "--is-inside-work-tree").strip() != "true":
        raise InventoryError("not a git work tree")
    if git(repo, "rev-parse", "--is-shallow-repository").strip() == "true":
        raise InventoryError("shallow repository is not supported")
    if git(repo, "status", "--porcelain", "--untracked-files=all").strip():
        raise InventoryError("repository is dirty")
    mit = git(repo, "rev-parse", "--verify", f"{args.mit_through}^{{commit}}").strip()
    transition = git(repo, "rev-parse", "--verify", f"{args.gpl_transition}^{{commit}}").strip()
    root = PurePosixPath(args.root)
    if root.is_absolute() or ".." in root.parts:
        raise InventoryError("root escapes repository")
    root_s = "." if str(root) in ("", ".") else str(root)
    files = git(repo, "ls-files", "-z", "--", root_s).split("\0")
    files = sorted(x for x in files if x)
    if not files:
        raise InventoryError("empty inventory")
    authors = {x.strip() for x in args.photonport_author if x.strip()}
    entries = []
    for path in files:
        if path == "." or path.startswith("../") or "/../" in path:
            raise InventoryError("tracked path escapes root")
        raw = subprocess.run(["git", "-C", str(repo), "show", f"HEAD:{path}"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        check = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"HEAD:{path}"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check.returncode:
            raise InventoryError(f"missing object for {path}")
        entries.append(text_entry(repo, "HEAD", path, raw, mit, transition, authors))
    entries.sort(key=lambda x: x["path"])
    region_counts = {
        classification: sum(
            1
            for entry in entries
            for region in (entry.get("regions") or [entry])
            if region.get("classification") == classification
        )
        for classification in CLASSIFICATIONS
    }
    line_counts = {
        classification: sum(
            region["output_lines"][1] - region["output_lines"][0] + 1
            for entry in entries
            for region in entry.get("regions", [])
            if region.get("classification") == classification
        )
        for classification in CLASSIFICATIONS
    }
    binary_counts = {
        classification: sum(
            1
            for entry in entries
            if entry.get("binary")
            and entry.get("classification") == classification
        )
        for classification in CLASSIFICATIONS
    }
    return {
        "schema_version": 1,
        "approval_status": APPROVAL,
        "root": root_s,
        "entries": entries,
        "summary": {
            "files": len(entries),
            "text_files": sum(not entry.get("binary") for entry in entries),
            "binary_files": sum(bool(entry.get("binary")) for entry in entries),
            "regions": sum(region_counts.values()),
            "classifications": line_counts,
            "region_counts": region_counts,
            "binary_files_by_classification": binary_counts,
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--root", required=True)
    ap.add_argument("--mit-through", required=True)
    ap.add_argument("--gpl-transition", required=True)
    ap.add_argument("--photonport-author", action="append", default=[])
    ap.add_argument("--output", required=True, type=Path)
    try:
        args = ap.parse_args(argv)
        result = build(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".build-inventory.", dir=str(args.output.parent)); os.close(fd)
        try:
            Path(tmp).write_text(
                json.dumps(result, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            os.replace(tmp, args.output)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
        return 0
    except (InventoryError, OSError, subprocess.SubprocessError) as e:
        print(f"build_inventory: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
