#!/usr/bin/env python3
"""Fail-closed deterministic audit of a provenance manifest."""
from __future__ import annotations
import argparse, hashlib, json, os, sys, tempfile
from pathlib import Path
from datetime import datetime

ALLOWED = {"MIT_EXACT", "PHOTONPORT_OWNED", "INDEPENDENT_REIMPLEMENTATION", "GENERATED_PLATFORM_FACT", "FRESH_ASSET"}
BLOCKED = {"UPSTREAM_GPL", "AMBIGUOUS"}
HEX64 = set("0123456789abcdef")

class AuditError(ValueError): pass

def load_json_yaml(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        raise AuditError(f"cannot read manifest: {e}")
    except json.JSONDecodeError as e:
        raise AuditError(f"unsupported YAML syntax; provide JSON-compatible YAML: {e}")

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()

def _records(obj):
    """Yield dicts from common archive-baseline report shapes."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values(): yield from _records(v)
    elif isinstance(obj, list):
        for v in obj: yield from _records(v)

def _baseline_match(report, region):
    commit, tree, blob = region.get("source_commit"), region.get("source_tree"), region.get("source_blob")
    for r in _records(report):
        if not isinstance(r, dict): continue
        if commit and r.get("commit") != commit and r.get("source_commit") != commit: continue
        if tree and r.get("tree") != tree and r.get("source_tree") != tree: continue
        if blob and r.get("blob") != blob and r.get("source_blob") != blob: continue
        if commit or tree or blob: return r
    return None

def _required(region, errors):
    for key in ("reviewer", "reviewed_at", "author_evidence"):
        if not region.get(key): errors.append(f"missing required {key}")
    if region.get("reviewed_at"):
        try: datetime.fromisoformat(str(region["reviewed_at"]).replace("Z", "+00:00"))
        except ValueError: errors.append("reviewed_at is not ISO-8601")

def _has_license_evidence(record):
    if isinstance(record, dict):
        if record.get("license_sha256") or record.get("license_sha256_digest"):
            return True
        return any(_has_license_evidence(v) for v in record.values())
    if isinstance(record, list):
        return any(_has_license_evidence(v) for v in record)
    return False
def audit(manifest, root: Path, baseline):
    errors=[]
    if not isinstance(manifest, dict): raise AuditError("manifest root must be an object")
    if manifest.get("schema_version") != 1: errors.append("schema_version must be 1")
    shipped=manifest.get("shipped_paths")
    if not isinstance(shipped,list) or not shipped or not all(isinstance(p,str) and p for p in shipped):
        errors.append("shipped_paths must be a non-empty string list"); shipped=[]
    elif len(set(shipped)) != len(shipped):
        errors.append("shipped_paths contains duplicates")
    entries = manifest.get("entries")
    if not isinstance(entries, list): errors.append("entries must be a list"); entries=[]
    seen=set()
    for entry in entries:
        if not isinstance(entry, dict): errors.append("entry must be an object"); continue
        path_s=entry.get("path")
        if not isinstance(path_s,str) or not path_s or path_s in seen: errors.append(f"duplicate or missing path: {path_s!r}"); continue
        seen.add(path_s)
        p=Path(path_s)
        if p.is_absolute() or ".." in p.parts: errors.append(f"manifest path escapes root: {path_s}"); continue
        target=(root/p)
        try: resolved=target.resolve(strict=True); root_res=root.resolve(strict=True)
        except OSError as e: errors.append(f"missing shipped file {path_s}: {e}"); continue
        if os.path.commonpath([str(root_res),str(resolved)]) != str(root_res): errors.append(f"manifest path escapes root: {path_s}")
        if target.is_symlink(): errors.append(f"symlink shipped file is not allowed: {path_s}")
        out_hash=entry.get("output_blob_sha256")
        if not isinstance(out_hash,str) or len(out_hash)!=64 or any(c not in HEX64 for c in out_hash.lower()): errors.append(f"invalid output_blob_sha256 for {path_s}")
        elif digest(resolved) != out_hash.lower(): errors.append(f"output SHA-256 mismatch for {path_s}")
        whole=entry.get("whole_file") is True
        regions=entry.get("regions")
        if whole and regions: errors.append(f"whole-file entry has regions: {path_s}"); continue
        binary=entry.get("binary") is True or entry.get("generated") is True or Path(path_s).suffix.lower() in {".png",".jpg",".jpeg",".gif",".icns",".pdf",".zip",".xcassets"}
        if binary and not whole: errors.append(f"binary/generated file requires whole_file: {path_s}")
        rs=[]
        if whole:
            rs=[entry]
        else:
            if not isinstance(regions,list) or not regions: errors.append(f"missing regions for {path_s}"); continue
            try: total=len(resolved.read_text(encoding="utf-8").splitlines())
            except (OSError,UnicodeDecodeError): errors.append(f"non-text file requires whole_file: {path_s}"); continue
            for r in regions:
                if not isinstance(r,dict): errors.append(f"invalid region in {path_s}"); continue
                line=r.get("output_lines")
                if not isinstance(line,list) or len(line)!=2 or not all(isinstance(x,int) for x in line) or line[0]<1 or line[1]<line[0]: errors.append(f"invalid output_lines in {path_s}"); continue
                rs.append(r)
            rs.sort(key=lambda r:r["output_lines"][0] if isinstance(r.get("output_lines"),list) else 0)
            pos=1
            for r in rs:
                a,b=r["output_lines"]
                if a!=pos: errors.append(f"uncovered or overlapping lines in {path_s}")
                pos=b+1
            if pos!=total+1: errors.append(f"uncovered lines in {path_s}")
        for r in rs:
            c=r.get("classification")
            if c in BLOCKED: errors.append(f"blocked classification {c} in {path_s}")
            elif c not in ALLOWED: errors.append(f"invalid classification in {path_s}")
            _required(r,errors)
            if c=="MIT_EXACT":
                if not all(r.get(k) for k in ("source_repository","source_commit","source_blob","license_spdx")): errors.append(f"MIT_EXACT lacks source evidence: {path_s}")
                elif r.get("license_spdx") != "MIT": errors.append(f"MIT_EXACT requires MIT license: {path_s}")
                else:
                    match=_baseline_match(baseline,r)
                    if not match: errors.append(f"MIT_EXACT source not in baseline: {path_s}")
                    elif not _has_license_evidence(match): errors.append(f"MIT_EXACT license evidence missing: {path_s}")
            if c=="INDEPENDENT_REIMPLEMENTATION" and not r.get("protocol_refs"): errors.append(f"independent reimplementation lacks protocol references: {path_s}")
            if c=="INDEPENDENT_REIMPLEMENTATION" and not r.get("replacement_method"): errors.append(f"independent reimplementation lacks replacement evidence: {path_s}")
            if c=="PHOTONPORT_OWNED" and not r.get("replacement_method"): errors.append(f"PHOTONPORT_OWNED lacks ownership evidence: {path_s}")
            if c=="FRESH_ASSET" and not (r.get("design_receipt") and r.get("license_scope")): errors.append(f"FRESH_ASSET lacks design/license evidence: {path_s}")
    missing=set(shipped)-seen
    unexpected=seen-set(shipped)
    if missing: errors.append("missing manifest entries: "+", ".join(sorted(missing)))
    if unexpected: errors.append("entries not declared shipped: "+", ".join(sorted(unexpected)))
    report={"schema_version":1,"ok":not errors,"errors":sorted(set(errors)),"entries_checked":len(entries)}
    return report

def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument("--manifest",required=True,type=Path); ap.add_argument("--root",required=True,type=Path)
    ap.add_argument("--baseline-report",required=True,type=Path); ap.add_argument("--output",required=True,type=Path)
    args=ap.parse_args(argv)
    try:
        m=load_json_yaml(args.manifest)
        b=load_json_yaml(args.baseline_report); result=audit(m,args.root,b)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        fd,tmp=tempfile.mkstemp(prefix=".manifest-audit.",dir=str(args.output.parent)); os.close(fd)
        try:
            Path(tmp).write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8"); os.replace(tmp,args.output)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
        if result["errors"]:
            for e in result["errors"]: print("audit_manifest: "+e,file=sys.stderr)
            return 1
        return 0
    except (AuditError,OSError) as e:
        print(f"audit_manifest: {e}",file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
