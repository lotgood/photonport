#!/usr/bin/env python3
"""Verify the descriptor-relative immutable lifecycle CAS chain."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, sys
from pathlib import Path
spec=importlib.util.spec_from_file_location("lifecycle",Path(__file__).with_name("transition-lifecycle-state.py")); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
LifecycleError=module.LifecycleError; STATES=module.STATES; STATE_FILES=module.STATE_FILES
def main():
 p=argparse.ArgumentParser(); p.add_argument("--directory",type=Path,required=True); p.add_argument("--lifecycle-id"); p.add_argument("--require-terminal",action="store_true"); a=p.parse_args()
 try:
  dfd=module._open_dir(a.directory)
  try:
   entries=module.directory_entries_fd(dfd); present=[s for s in STATES if STATE_FILES[s] in entries]
   if not present or present!=list(STATES[:len(present)]) or entries!={STATE_FILES[s] for s in present}: raise LifecycleError("lifecycle states are non-contiguous or conflicting")
   records=[]
   for state in present:
    raw=module._read_at(dfd,STATE_FILES[state]); record=module.parse_json_bytes(raw); module.validate_lineage(record,transition=False)
    if record["state"]!=state: raise LifecycleError("filename/state mismatch")
    records.append((record,raw))
  finally: os.close(dfd)
  first=records[0][0]
  if first["predecessorSha256"] is not None: raise LifecycleError("allocated state has a predecessor")
  if a.lifecycle_id and first["lifecycleId"]!=a.lifecycle_id: raise LifecycleError("lifecycleId does not match")
  for index,(record,_) in enumerate(records[1:],1):
   predecessor,raw=records[index-1]
   if record["predecessorSha256"]!=hashlib.sha256(raw).hexdigest() or any(record[k]!=first[k] for k in ("lifecycleId","rootId","tuple","allocation","authority")): raise LifecycleError("predecessor CAS or lineage mismatch")
  current=present[-1]
  if a.require_terminal and current!="disposed": raise LifecycleError("lifecycle is not terminal")
  print(json.dumps({"lifecycleId":first["lifecycleId"],"state":current,"terminal":current=="disposed","sha256":hashlib.sha256(records[-1][1]).hexdigest(),"approvedSequence":first["authority"]["approvedSequence"],"root":first["authority"]["root"],"supervisor":first["authority"]["supervisor"],"command":first["authority"]["command"],"allocationNonce":first["authority"]["allocationNonce"],"mutexNonce":first["authority"]["mutexNonce"]},sort_keys=True)); return 0
 except Exception as e: print(f"verify-lifecycle-state.py: error: {e}",file=sys.stderr); return 2
if __name__=="__main__": sys.exit(main())
