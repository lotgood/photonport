#!/usr/bin/env python3
"""Close an active lifecycle using an inherited lifecycle-directory descriptor."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, stat, sys, tempfile
from pathlib import Path
CORE=Path(__file__).with_name("transition-lifecycle-state.py")
def fail(m): raise RuntimeError(m)
def pairs(items):
 out={}
 for k,v in items:
  if k in out: fail("duplicate JSON key")
  out[k]=v
 return out
def raw(path):
 fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_size>1_048_576: fail("evidence must be a bounded regular non-symlink file")
  data=os.read(fd,s.st_size+1)
  if len(data)!=s.st_size or os.fstat(fd).st_size!=s.st_size: fail("evidence changed while reading")
  return data
 finally: os.close(fd)
def load():
 spec=importlib.util.spec_from_file_location("lifecycle_transition",CORE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--directory-fd",type=int,required=True);p.add_argument("--source-active",type=Path,required=True)
 for option,name in (("--cleanup-proof","cleanupSha256"),("--post-consumer-proof","postConsumerSha256"),("--matrix-binding-proof","matrixBindingSha256"),("--b1-preflight-proof","b1PreflightSha256")): p.add_argument(option,dest=name,type=Path,required=True)
 a=p.parse_args()
 try:
  dfd=os.dup(a.directory_fd)
  try:
   info=os.fstat(dfd)
   if not stat.S_ISDIR(info.st_mode): fail("lifecycle directory fd is not a directory")
   active_fd=os.open("010-source-active.json",os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=dfd)
   try:
    active_info=os.fstat(active_fd)
    if not stat.S_ISREG(active_info.st_mode): fail("active state is not a regular file")
    active_raw=os.read(active_fd,active_info.st_size+1)
   finally: os.close(active_fd)
   supplied=raw(a.source_active)
   if supplied!=active_raw: fail("source-active bytes are not the pinned lifecycle bytes")
   active=json.loads(active_raw,object_pairs_hook=pairs); core=load(); core.validate_lineage(active,transition=False)
   if active["state"]!="source-active": fail("source-active state required")
   proofs=[]; hashes={}
   for key in ("cleanupSha256","postConsumerSha256","matrixBindingSha256","b1PreflightSha256"):
    path=getattr(a,key); data=raw(path); proofs.append(key+"="+str(path))
    if key=="cleanupSha256":
     envelope=json.loads(data,object_pairs_hook=pairs)
     if not isinstance(envelope,dict) or set(envelope)!={"schemaVersion","kind","lifecycleId","rootId","authoritySha256","tupleSha256","predecessorSha256","cleanupRecordSha256","artifactPath"}: fail("invalid cleanup proof envelope")
     hashes[key]=hashlib.sha256(raw(Path(envelope["artifactPath"]))).hexdigest()
    else: hashes[key]=hashlib.sha256(data).hexdigest()
   transition={"schemaVersion":1,"kind":"photonport.lifecycle-transition.v1","lifecycleId":active["lifecycleId"],"rootId":active["rootId"],"tuple":active["tuple"],"allocation":active["allocation"],"authority":active["authority"],"fromState":"source-active","toState":"source-closing","predecessorSha256":hashlib.sha256(active_raw).hexdigest(),**hashes}
   fd,name=tempfile.mkstemp(prefix="close-source-lifecycle-",suffix=".json")
   try:
    encoded=json.dumps(transition,sort_keys=True,separators=(",",":")).encode()+b"\n"
    with os.fdopen(fd,"wb") as out: out.write(encoded);out.flush();os.fsync(out.fileno())
    result=core.transition_authorized(directory=None,directory_fd=dfd,transition=Path(name),expected_state="source-closing",proofs=proofs,_capability=core._WRAPPER_CAPABILITY)
   finally: os.unlink(name)
  finally: os.close(dfd)
  print(json.dumps(result,sort_keys=True));return 0
 except Exception as exc: print(f"close-source-lifecycle.py: error: {exc}",file=sys.stderr);return 2
if __name__=="__main__": sys.exit(main())
