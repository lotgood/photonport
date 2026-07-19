#!/usr/bin/env python3
"""Create immutable lifecycle records using descriptor-relative no-follow CAS."""
from __future__ import annotations
import argparse, hashlib, json, os, re, stat, sys
from pathlib import Path

STATES=("allocated","source-active","source-closing","source-released","disposing","disposed")
STATE_FILES=dict(zip(STATES,("000-allocated.json","010-source-active.json","020-source-closing.json","030-source-released.json","040-dispose-claim.json","050-disposed.json")))
ID_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"); HEX40_RE=re.compile(r"^[0-9a-f]{40}$"); HEX64_RE=re.compile(r"^[0-9a-f]{64}$"); MAX_BYTES=1_048_576
BASE={"schemaVersion","kind","lifecycleId","rootId","tuple","allocation","authority","predecessorSha256"}
PROOFS={
 "allocated":set(), "source-active":{"allocationReleaseSha256"},
 "source-closing":{"cleanupSha256","postConsumerSha256","matrixBindingSha256","b1PreflightSha256"},
 "source-released":{"closingSha256","releasedByUnlinkAndClose","releaseCommandSha256"},
 "disposing":{"cleanupSha256","preWorktreeListSha256","removeArgvSha256","removeCommandSha256","rootIdentitySha256","registryReleaseSha256"},
 "disposed":{"cleanupSha256","preWorktreeListSha256","postWorktreeListSha256","removeArgvSha256","removeCommandSha256","rootIdentitySha256","registryReleaseSha256"},
}
class LifecycleError(Exception): pass
def reject_duplicates(pairs):
 out={}
 for k,v in pairs:
  if k in out: raise LifecycleError(f"duplicate JSON key: {k}")
  out[k]=v
 return out
def exact(v,keys,label):
 if not isinstance(v,dict) or set(v)!=set(keys): raise LifecycleError(f"{label} has missing or unexpected keys")
def _open_dir(directory):
 try:
  before=directory.lstat(); fd=os.open(directory,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)); after=os.fstat(fd)
 except OSError as e: raise LifecycleError(f"cannot open lifecycle directory: {e}") from e
 if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino): os.close(fd); raise LifecycleError("lifecycle directory must be a stable non-symlink directory")
 return fd
def read_regular_bytes(path):
 try: fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 except OSError as e: raise LifecycleError(f"cannot read {path}: {e}") from e
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_BYTES: raise LifecycleError("input must be a bounded regular file")
  data=os.read(fd,info.st_size+1)
  if len(data)>MAX_BYTES or os.fstat(fd).st_size!=info.st_size: raise LifecycleError("input changed while reading")
  return data
 finally: os.close(fd)
def parse_json_bytes(data):
 try: value=json.loads(data.decode(),object_pairs_hook=reject_duplicates)
 except (UnicodeDecodeError,json.JSONDecodeError) as e: raise LifecycleError("input is not valid UTF-8 JSON") from e
 if not isinstance(value,dict): raise LifecycleError("input top level must be an object")
 return value
def read_json(path): return parse_json_bytes(read_regular_bytes(path))
AUTHORITY_KEYS={"approvedSequence","root","supervisor","command","allocationNonce","mutexNonce","lockAPath","lockBPath","registryPath","commonGitDir"}
def validate_authority(a):
 exact(a,AUTHORITY_KEYS,"authority")
 if a["approvedSequence"]!=list(STATES): raise LifecycleError("authority approvedSequence must be canonical")
 exact(a["root"],{"canonicalPath","dev","ino"},"authority.root")
 if not isinstance(a["root"]["canonicalPath"],str) or not Path(a["root"]["canonicalPath"]).is_absolute() or not isinstance(a["root"]["dev"],int) or not isinstance(a["root"]["ino"],int): raise LifecycleError("invalid authority root")
 for k in ("supervisor","command"):
  if not isinstance(a[k],str) or not a[k]: raise LifecycleError(f"invalid authority {k}")
 for k in ("allocationNonce","mutexNonce"):
  if not isinstance(a[k],str) or not HEX64_RE.fullmatch(a[k]): raise LifecycleError(f"invalid authority {k}")
 for k in ("lockAPath","lockBPath","registryPath","commonGitDir"):
  if not isinstance(a[k],str) or not Path(a[k]).is_absolute(): raise LifecycleError(f"invalid authority {k}")
def validate_lineage(v,*,transition):
 state=v["toState"] if transition else v["state"]
 if state not in STATES: raise LifecycleError("invalid lifecycle state")
 keys=BASE|({"fromState","toState"} if transition else {"state"})|PROOFS[state]
 exact(v,keys,"record")
 if v["schemaVersion"]!=1 or v["kind"]!=("photonport.lifecycle-transition.v1" if transition else "photonport.lifecycle-state.v1"): raise LifecycleError("unsupported schemaVersion or kind")
 if any(not isinstance(v[k],str) or not ID_RE.fullmatch(v[k]) for k in ("lifecycleId","rootId")): raise LifecycleError("invalid lifecycle identity")
 exact(v["tuple"],{"macCommit","iosCommit","protocolCommit"},"tuple")
 if any(not isinstance(x,str) or not HEX40_RE.fullmatch(x) for x in v["tuple"].values()): raise LifecycleError("invalid tuple")
 exact(v["allocation"],{"id","sha256"},"allocation")
 if not isinstance(v["allocation"]["id"],str) or not ID_RE.fullmatch(v["allocation"]["id"]) or not isinstance(v["allocation"]["sha256"],str) or not HEX64_RE.fullmatch(v["allocation"]["sha256"]): raise LifecycleError("invalid allocation")
 validate_authority(v["authority"])
 if v["predecessorSha256"] is not None and (not isinstance(v["predecessorSha256"],str) or not HEX64_RE.fullmatch(v["predecessorSha256"])): raise LifecycleError("invalid predecessorSha256")
 if transition and v["fromState"] is not None and v["fromState"] not in STATES: raise LifecycleError("invalid lifecycle state")
 for key in PROOFS[state]-{"releasedByUnlinkAndClose"}:
  if not isinstance(v[key],str) or not HEX64_RE.fullmatch(v[key]): raise LifecycleError(f"invalid {key}")
 if state=="source-released" and v["releasedByUnlinkAndClose"] is not True: raise LifecycleError("source release must attest unlink-and-close")
def _read_at(dfd,name):
 fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=dfd)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_BYTES: raise LifecycleError("state entry must be a bounded regular file")
  data=os.read(fd,info.st_size+1)
  if len(data)>MAX_BYTES or os.fstat(fd).st_size!=info.st_size: raise LifecycleError("state entry changed while reading")
  return data
 finally: os.close(fd)
def directory_entries_fd(dfd):
 names=os.listdir(dfd); allowed=set(STATE_FILES.values())|{"source-release-context.json"}; out=set()
 for name in names:
  if name not in allowed: raise LifecycleError(f"unexpected lifecycle directory entry: {name}")
  info=os.stat(name,dir_fd=dfd,follow_symlinks=False)
  if not stat.S_ISREG(info.st_mode): raise LifecycleError(f"state entry must be a regular non-symlink file: {name}")
  if name in STATE_FILES.values(): out.add(name)
 return out
def _proof_paths(values):
 out={}
 for value in values:
  key,sep,path=value.partition("=")
  if not sep or key in out or key not in PROOFS["source-closing"]: raise LifecycleError("invalid source-closing proof argument")
  out[key]=Path(path)
 return out
def validate_closing_evidence(transition, values):
 paths=_proof_paths(values)
 if transition["toState"]=="source-closing":
  if set(paths)!=PROOFS["source-closing"]: raise LifecycleError("source-closing requires exact raw proof evidence")
  authority_sha=hashlib.sha256(json.dumps(transition["authority"],sort_keys=True,separators=(",",":")).encode()).hexdigest()
  tuple_sha=hashlib.sha256(json.dumps(transition["tuple"],sort_keys=True,separators=(",",":")).encode()).hexdigest()
  contracts={
   "cleanupSha256":("photonport.lifecycle-cleanup-proof.v1","cleanupRecordSha256","photonport.disposable-worktree-cleanup.v1"),
   "postConsumerSha256":("photonport.lifecycle-post-consumer-proof.v1","consumerManifestSha256","photonport.post-consumer-inventory.v1"),
   "matrixBindingSha256":("photonport.lifecycle-matrix-binding-proof.v1","matrixReportSha256","photonport.matrix-binding.v1"),
   "b1PreflightSha256":("photonport.lifecycle-b1-preflight-proof.v1","preflightManifestSha256","photonport.b1-preflight.v1"),
  }
  for key,path in paths.items():
   data=read_regular_bytes(path); proof=parse_json_bytes(data); kind,detail,artifact_kind=contracts[key]
   expected={"schemaVersion","kind","lifecycleId","rootId","authoritySha256","tupleSha256","predecessorSha256",detail,"artifactPath"}
   if key=="matrixBindingSha256": expected|={"allocatedSha256","sourceActiveSha256","sealSha256","mutexSha256"}
   exact(proof,expected,key)
   artifact_path=Path(proof["artifactPath"])
   artifact_raw=read_regular_bytes(artifact_path); artifact=parse_json_bytes(artifact_raw)
   if (proof["schemaVersion"]!=1 or proof["kind"]!=kind or proof["lifecycleId"]!=transition["lifecycleId"] or proof["rootId"]!=transition["rootId"] or proof["authoritySha256"]!=authority_sha or proof["tupleSha256"]!=tuple_sha or proof["predecessorSha256"]!=transition["predecessorSha256"] or proof[detail]!=hashlib.sha256(artifact_raw).hexdigest() or not isinstance(artifact.get("kind"),str) or artifact["kind"]!=artifact_kind): raise LifecycleError(f"invalid {key} evidence")
   if key=="cleanupSha256" and (artifact.get("lifecycleId")!=transition["lifecycleId"] or artifact.get("rootId")!=transition["rootId"] or artifact.get("generatedOutputsAbsent") is not True): raise LifecycleError("invalid cleanup artifact")
   if key=="postConsumerSha256" and (artifact.get("tupleSha256")!=tuple_sha or artifact.get("rootId")!=transition["rootId"] or artifact.get("beforeInventorySha256")!=artifact.get("afterInventorySha256")): raise LifecycleError("invalid post-consumer artifact")
   if key=="matrixBindingSha256":
    maps={"allocatedSha256":"allocatedSha256ByRoot","sourceActiveSha256":"sourceActiveSha256ByRoot","sealSha256":"sealSha256ByRoot","mutexSha256":"mutexSha256ByRoot"}
    if (artifact.get("lifecycleTupleSha256")!=tuple_sha or not HEX64_RE.fullmatch(artifact.get("tupleSha256","")) or not HEX64_RE.fullmatch(artifact.get("reportSha256","")) or any(not isinstance(artifact.get(map_name),dict) or artifact[map_name].get(transition["rootId"])!=proof[field] for field,map_name in maps.items())): raise LifecycleError("invalid matrix-binding root mapping")
   if key=="b1PreflightSha256" and (artifact.get("tupleSha256")!=tuple_sha or artifact.get("lifecycleId")!=transition["lifecycleId"] or artifact.get("readiness")!="ready"): raise LifecycleError("invalid B1 preflight artifact")
   expected_hash=hashlib.sha256(artifact_raw).hexdigest() if key=="cleanupSha256" else hashlib.sha256(data).hexdigest()
   if expected_hash!=transition[key]: raise LifecycleError(f"{key} raw evidence hash mismatch")
 elif paths: raise LifecycleError("proof evidence is only valid for source-closing")
_WRAPPER_CAPABILITY=object()
def transition_authorized(*,directory,transition,expected_state,proofs=(),directory_fd=None,validate_only=False,_capability=None):
 if _capability is not _WRAPPER_CAPABILITY: raise LifecycleError("internal lifecycle authority required")
 return _run(argparse.Namespace(directory=directory,directory_fd=directory_fd,transition=transition,proof=list(proofs),validate_only=validate_only),expected_state)
def _run(a,expected_state=None):
 if (a.directory is None)==(a.directory_fd is None): raise LifecycleError("exactly one lifecycle directory authority is required")
 transition=read_json(a.transition); validate_lineage(transition,transition=True); validate_closing_evidence(transition,a.proof)
 target=transition["toState"]
 if expected_state!=target: raise LifecycleError("lifecycle mutation requires internal state-specific authority")
 if target=="source-active" and a.directory_fd is None: raise LifecycleError("source-active requires inherited lifecycle directory authority")
 if target=="source-closing" and not a.proof: raise LifecycleError("source-closing requires proof authority")
 if a.directory_fd is None: dfd=_open_dir(a.directory); directory=a.directory
 else:
  dfd=os.dup(a.directory_fd); info=os.fstat(dfd)
  if not stat.S_ISDIR(info.st_mode): os.close(dfd); raise LifecycleError("lifecycle directory fd is not a directory")
  directory=Path(f"/dev/fd/{a.directory_fd}")
 try:
  entries=directory_entries_fd(dfd); index=STATES.index(target); prior=STATES[index-1] if index else None
  if transition["fromState"]!=prior: raise LifecycleError(f"invalid transition: {target} must follow {prior}")
  if index==0:
   if entries or transition["predecessorSha256"] is not None: raise LifecycleError("allocated is create-once")
  else:
   predecessor=STATE_FILES[prior]
   if predecessor not in entries: raise LifecycleError("missing predecessor state")
   previous_raw=_read_at(dfd,predecessor); previous=parse_json_bytes(previous_raw); validate_lineage(previous,transition=False); predecessor_sha=hashlib.sha256(previous_raw).hexdigest()
   if previous["state"]!=prior or transition["predecessorSha256"]!=predecessor_sha: raise LifecycleError("predecessor CAS mismatch")
   if any(previous[k]!=transition[k] for k in ("lifecycleId","rootId","tuple","allocation","authority")): raise LifecycleError("lineage mismatch")
   if target=="source-released" and transition["closingSha256"]!=predecessor_sha: raise LifecycleError("source release closing proof mismatch")
   if target=="disposed" and any(previous[k]!=transition[k] for k in PROOFS["disposing"]): raise LifecycleError("disposal proof lineage mismatch")
   if entries!={STATE_FILES[s] for s in STATES[:index]}: raise LifecycleError("lifecycle history is incomplete or conflicting")
  record={k:transition[k] for k in BASE-{"kind"}}; record.update(kind="photonport.lifecycle-state.v1",state=target); record.update({k:transition[k] for k in PROOFS[target]}); validate_lineage(record,transition=False)
  encoded=json.dumps(record,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()+b"\n"
  if a.validate_only: return {"state":target,"validated":True}
  name=STATE_FILES[target]; fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=dfd)
  try:
   with os.fdopen(fd,"wb") as h: h.write(encoded); h.flush(); os.fsync(h.fileno())
  except Exception:
   try: os.unlink(name,dir_fd=dfd); os.fsync(dfd)
   except OSError: pass
   raise
  os.fsync(dfd); return {"state":target,"path":str(directory/STATE_FILES[target]),"sha256":hashlib.sha256(encoded).hexdigest()}
 finally: os.close(dfd)
def main():
 p=argparse.ArgumentParser(); p.add_argument("--directory",type=Path); p.add_argument("--directory-fd",type=int); p.add_argument("--transition",type=Path,required=True); p.add_argument("--proof",action="append",default=[]); p.add_argument("--validate-only",action="store_true"); a=p.parse_args()
 try: print(json.dumps(_run(a),sort_keys=True)); return 0
 except (LifecycleError,OSError) as e: print(f"transition-lifecycle-state.py: error: {e}",file=sys.stderr); return 2
if __name__=="__main__": sys.exit(main())
