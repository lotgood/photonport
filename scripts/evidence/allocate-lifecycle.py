#!/usr/bin/env python3
"""Allocate an empty lifecycle directory from exact, no-follow evidence."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, stat, sys, tempfile
from pathlib import Path

CORE = Path(__file__).with_name("transition-lifecycle-state.py")

def fail(message): raise RuntimeError(message)
def raw(path):
 fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_size>1_048_576: fail("input must be a bounded regular non-symlink file")
  value=os.read(fd,info.st_size+1)
  if len(value)!=info.st_size or os.fstat(fd).st_size!=info.st_size: fail("input changed while reading")
  return value
 finally: os.close(fd)
def obj(path, keys, kind):
 try: value=json.loads(raw(path),object_pairs_hook=lambda pairs: _pairs(pairs))
 except (ValueError,UnicodeDecodeError) as exc: raise RuntimeError("invalid JSON evidence") from exc
 if not isinstance(value,dict) or set(value)!=set(keys) or value.get("schemaVersion")!=1 or value.get("kind")!=kind: fail("invalid evidence schema")
 return value
def _pairs(pairs):
 value={}
 for key,item in pairs:
  if key in value: fail("duplicate JSON key")
  value[key]=item
 return value
def canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":")).encode()
def load_core():
 spec=importlib.util.spec_from_file_location("lifecycle_transition",CORE); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--directory",type=Path,required=True);p.add_argument("--registration",type=Path,required=True);p.add_argument("--tuple",dest="tuple_path",type=Path,required=True);p.add_argument("--root",type=Path,required=True);p.add_argument("--authority",type=Path,required=True);p.add_argument("--lifecycle-id",required=True);p.add_argument("--root-id",required=True)
 a=p.parse_args()
 try:
  registration_raw=raw(a.registration); registration=json.loads(registration_raw,object_pairs_hook=lambda pairs:_pairs(pairs))
  if not isinstance(registration,dict) or set(registration)!={"schemaVersion","kind","id","destination"} or registration.get("schemaVersion")!=1 or registration.get("kind")!="allocation-record.v1": fail("invalid allocator registration")
  tuple_raw=raw(a.tuple_path); tuple_value=json.loads(tuple_raw,object_pairs_hook=lambda pairs:_pairs(pairs))
  if not isinstance(tuple_value,dict) or set(tuple_value)!={"macCommit","iosCommit","protocolCommit"}: fail("invalid tuple evidence")
  root_evidence=obj(a.root,{"schemaVersion","kind","canonicalPath","dev","ino"},"photonport.lifecycle-root.v1")
  root_value={key:root_evidence[key] for key in ("canonicalPath","dev","ino")}
  authority=json.loads(raw(a.authority),object_pairs_hook=lambda pairs:_pairs(pairs))
  core=load_core(); core.validate_authority(authority)
  if root_value!=authority["root"] or Path(registration["destination"])!=Path(root_value["canonicalPath"]): fail("root evidence lineage mismatch")
  info=os.stat(root_value["canonicalPath"],follow_symlinks=False)
  if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or (info.st_dev,info.st_ino)!=(root_value["dev"],root_value["ino"]): fail("managed disposable root identity mismatch")
  before=a.directory.lstat()
  if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode): fail("lifecycle directory must be a non-symlink directory")
  dfd=os.open(a.directory,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
  after=os.fstat(dfd)
  if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino) or os.listdir(dfd): os.close(dfd);fail("lifecycle state must be absent")
  transition={"schemaVersion":1,"kind":"photonport.lifecycle-transition.v1","lifecycleId":a.lifecycle_id,"rootId":a.root_id,"tuple":tuple_value,"allocation":{"id":registration["id"],"sha256":hashlib.sha256(registration_raw).hexdigest()},"authority":authority,"fromState":None,"toState":"allocated","predecessorSha256":None}
  fd,name=tempfile.mkstemp(prefix="allocate-lifecycle-",suffix=".json")
  try:
   with os.fdopen(fd,"wb") as out: out.write(canonical(transition)+b"\n");out.flush();os.fsync(out.fileno())
   result=core.transition_authorized(directory=None,directory_fd=dfd,transition=Path(name),expected_state="allocated",_capability=core._WRAPPER_CAPABILITY)
  finally:
   os.unlink(name)
  visible=a.directory.lstat()
  visible_fd=os.open(a.directory,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
  try:
   opened=os.fstat(visible_fd); pinned=os.fstat(dfd)
   if (visible.st_dev,visible.st_ino)!=(pinned.st_dev,pinned.st_ino) or (opened.st_dev,opened.st_ino)!=(pinned.st_dev,pinned.st_ino): fail("caller-visible lifecycle directory replaced after allocated CAS")
  finally:
   os.close(visible_fd)
   os.close(dfd)
  print(json.dumps(result,sort_keys=True)); return 0
 except Exception as exc: print(f"allocate-lifecycle.py: error: {exc}",file=sys.stderr);return 2
if __name__=="__main__": sys.exit(main())
