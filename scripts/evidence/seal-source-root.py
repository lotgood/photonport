#!/usr/bin/env python3
"""Create test/integrity seal evidence from a live, Lock-B-protected source root."""
import argparse, fcntl, hashlib, json, os, stat, subprocess, sys
from pathlib import PurePosixPath

HEX=set("0123456789abcdef")
def fail(s): raise RuntimeError(s)
def canon(v): return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def digest(b): return hashlib.sha256(b).hexdigest()
def regular_at(dfd,name):
 fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=dfd)
 try:
  i=os.fstat(fd)
  if not stat.S_ISREG(i.st_mode): fail("not a regular file")
  b=os.read(fd,i.st_size+1)
  if len(b)!=i.st_size or os.fstat(fd).st_size!=i.st_size: fail("file changed while reading")
  return b
 finally: os.close(fd)
def load_bytes(b,label):
 try:
  def pairs(x):
   d={}
   for k,v in x:
    if k in d: raise ValueError("duplicate key")
    d[k]=v
   return d
  x=json.loads(b.decode(),object_pairs_hook=pairs)
 except Exception as e: raise RuntimeError("invalid "+label) from e
 if not isinstance(x,dict): fail("invalid "+label)
 return x
def read_path(p):
 p=os.fspath(p); parent,name=os.path.split(p); d=os.open(parent or ".",os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
 try:return regular_at(d,name)
 finally:os.close(d)
def write_exclusive(p,b):
 parent,name=os.path.split(os.fspath(p)); d=os.open(parent or ".",os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
 try:
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=d)
  try: os.write(fd,b);os.fsync(fd)
  finally: os.close(fd)
  os.fsync(d)
 finally: os.close(d)
def safe_relative(path):
 p=PurePosixPath(path)
 return bool(path) and not p.is_absolute() and all(x not in ("",".","..") for x in p.parts)
def root_file(rootfd,path):
 if not safe_relative(path): fail("unsafe inventory path")
 fd=os.dup(rootfd)
 try:
  for part in PurePosixPath(path).parts[:-1]:
   n=os.open(part,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=fd);os.close(fd);fd=n
  return regular_at(fd,PurePosixPath(path).name)
 finally:os.close(fd)
def inventory(rootfd,path,label):
 v=load_bytes(read_path(path),label)
 entries=v.get("entries",v.get("files"))
 if not isinstance(entries,list): fail(label+" requires entries")
 seen=set()
 for e in entries:
  if not isinstance(e,dict) or set(e)!={"path","sha256"} or not isinstance(e["path"],str) or not isinstance(e["sha256"],str) or len(e["sha256"])!=64 or set(e["sha256"])>HEX or e["path"] in seen: fail("invalid "+label+" entry")
  seen.add(e["path"]); data=root_file(rootfd,e["path"])
  if digest(data)!=e["sha256"]: fail(label+" hash mismatch")
  if e["path"].endswith("Package.resolved"):
   lock=load_bytes(data,"Package.resolved")
   if not isinstance(lock.get("pins"),list) or not isinstance(lock.get("version"),int): fail("invalid Package.resolved semantics")
def root_inventory(fd):
 out={}
 def walk(dfd,prefix,dev):
  for name in os.listdir(dfd):
   info=os.stat(name,dir_fd=dfd,follow_symlinks=False); path=prefix+name
   if stat.S_ISLNK(info.st_mode) or info.st_dev!=dev: fail("source inventory rejects symlink or rebind: "+path)
   if stat.S_ISDIR(info.st_mode):
    child=os.open(name,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=dfd)
    try:
     opened=os.fstat(child)
     if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino): fail("source directory changed")
     walk(child,path+"/",dev)
    finally: os.close(child)
   elif stat.S_ISREG(info.st_mode):
    if info.st_nlink!=1: fail("source inventory rejects hardlink: "+path)
    data=regular_at(dfd,name); out[path]=digest(data)
   else: fail("source inventory rejects unsupported entry: "+path)
 root=os.fstat(fd); walk(fd,"",root.st_dev); return out,(root.st_dev,root.st_ino)
def inventories(rootfd, paths):
 declared={}; all_entries={}; counts={}; categories={}
 for key,label,path in paths:
  v=load_bytes(read_path(path),label); entries=v.get("entries",v.get("files"))
  if not isinstance(entries,list): fail(label+" requires entries")
  category=[]
  for e in entries:
   if not isinstance(e,dict) or set(e)!={"path","sha256"} or not isinstance(e["path"],str) or not isinstance(e["sha256"],str) or len(e["sha256"])!=64 or set(e["sha256"])>HEX or e["path"] in all_entries: fail("invalid or duplicate inventory entry")
   data=root_file(rootfd,e["path"]); fd=os.dup(rootfd)
   try:
    for part in PurePosixPath(e["path"]).parts[:-1]: nextfd=os.open(part,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=fd);os.close(fd);fd=nextfd
    leaf=os.open(PurePosixPath(e["path"]).name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=fd)
    try: info=os.fstat(leaf)
    finally: os.close(leaf)
   finally: os.close(fd)
   if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or digest(data)!=e["sha256"]: fail(label+" hash mismatch")
   item={"path":e["path"],"sha256":e["sha256"],"size":info.st_size,"dev":info.st_dev,"ino":info.st_ino};all_entries[e["path"]]=e["sha256"];category.append(item)
  category.sort(key=lambda item:item["path"]);categories[key]=category;declared[key]=digest(canon(category));counts[key]=len(category)
 actual,identity=root_inventory(rootfd)
 if actual!=all_entries: fail("inventories do not exactly cover source root")
 return declared,digest(canon(categories)),counts,categories,identity
def held(fd,mutex):
 named=os.stat(mutex,follow_symlinks=False); got=os.fstat(fd)
 if not stat.S_ISREG(got.st_mode) or (got.st_dev,got.st_ino)!=(named.st_dev,named.st_ino): fail("supervisor fd is not canonical Lock-B")
 probe=os.open(mutex,os.O_RDWR|getattr(os,"O_NOFOLLOW",0))
 try:
  try: fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError: pass
  else: fail("Lock-B is not held")
 finally: os.close(probe)
 try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError as e: raise RuntimeError("supervisor fd does not hold Lock-B") from e
def main():
 p=argparse.ArgumentParser();p.add_argument("--lifecycle-directory-fd","--directory-fd",dest="dfd",type=int,required=True);p.add_argument("--source-active",required=True);p.add_argument("--root-fd",type=int,required=True);p.add_argument("--mutex",required=True);p.add_argument("--supervisor-fd",type=int,required=True);p.add_argument("--id",required=True);p.add_argument("--commit",required=True)
 for n in ("logical","generated","package","cache"): p.add_argument("--"+n+"-inventory",required=True)
 p.add_argument("--seal-manifest","--seal-output",dest="seal",required=True);p.add_argument("--live-attestation","--live-output",dest="live",required=True);a=p.parse_args()
 try:
  names=set(os.listdir(a.dfd))
  if names!={"000-allocated.json","010-source-active.json"}: fail("lifecycle must be allocated and source-active only")
  allocated=load_bytes(regular_at(a.dfd,"000-allocated.json"),"allocated")
  active_raw=regular_at(a.dfd,"010-source-active.json"); active=load_bytes(active_raw,"source-active")
  if read_path(a.source_active)!=active_raw or active.get("state")!="source-active" or active.get("predecessorSha256")!=digest(regular_at(a.dfd,"000-allocated.json")): fail("source-active substitution")
  if any(active.get(k)!=allocated.get(k) for k in ("lifecycleId","rootId","tuple","allocation","authority")): fail("lifecycle lineage mismatch")
  if active.get("rootId")!=a.id or active.get("tuple",{}).get(a.id+"Commit")!=a.commit or len(a.commit)!=40 or set(a.commit)>HEX: fail("tuple identity mismatch")
  root=os.fstat(a.root_fd); auth=active.get("authority",{}); expected=auth.get("root",{})
  if not stat.S_ISDIR(root.st_mode) or (root.st_dev,root.st_ino)!=(expected.get("dev"),expected.get("ino")): fail("root fd identity mismatch")
  if os.path.realpath(a.mutex)!=auth.get("lockBPath"): fail("mutex authority mismatch")
  held(a.supervisor_fd,a.mutex)
  inventory_hashes,full_inventory_hash,entry_counts,inventory_entries,identity=inventories(a.root_fd,[(n,n+" inventory",getattr(a,n+"_inventory")) for n in ("logical","generated","package","cache")])
  actual,after_identity=root_inventory(a.root_fd)
  if after_identity!=identity or digest(canon(actual))!=digest(canon({item["path"]:item["sha256"] for category in inventory_entries.values() for item in category})): fail("source root changed before seal emission")
  bindings={"inventorySha256":inventory_hashes,"fullInventorySha256":full_inventory_hash,"inventoryEntryCounts":entry_counts,"inventoryEntries":inventory_entries}
  seal={"schemaVersion":1,"kind":"seal-manifest-v1","id":a.id,"commit":a.commit,"sourceActiveSha256":digest(active_raw),**bindings}; seal_raw=canon(seal)+b"\n"
  live={"schemaVersion":1,"kind":"live-attestation-v1","id":a.id,"commit":a.commit,"sealManifestSha256":digest(seal_raw),**bindings}
  write_exclusive(a.seal,seal_raw);write_exclusive(a.live,canon(live)+b"\n");return 0
 except Exception as e: print("seal-source-root.py: error: "+str(e),file=sys.stderr);return 2
if __name__=="__main__":sys.exit(main())
