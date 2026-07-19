#!/usr/bin/env python3
"""Explicitly test-only inner report producer; it makes no production trust claim."""
import argparse, hashlib, json, os, stat, sys
from pathlib import Path
HEX=set("0123456789abcdef")
def die(s): raise RuntimeError(s)
def canonical(v): return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def sha(b): return hashlib.sha256(b).hexdigest()
def read(p):
 fd=os.open(p,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 try:
  i=os.fstat(fd)
  if not stat.S_ISREG(i.st_mode): die("input is not regular")
  b=os.read(fd,i.st_size+1)
  if len(b)!=i.st_size: die("input changed")
  return b
 finally:os.close(fd)
def out(p,b):
 parent=Path(p).parent; d=os.open(parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0));
 try:
  fd=os.open(Path(p).name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=d)
  try:os.write(fd,b);os.fsync(fd)
  finally:os.close(fd)
  os.fsync(d)
 finally:os.close(d)
def main():
 p=argparse.ArgumentParser();p.add_argument("--mac-commit","--expected-mac-commit",dest="mac_commit",required=True);p.add_argument("--ios-commit","--expected-ios-commit",dest="ios_commit",required=True);p.add_argument("--protocol-commit","--expected-protocol-commit",dest="protocol_commit",required=True);p.add_argument("--compatibility-digest","--expected-compatibility-digest",dest="compatibility_digest",required=True);p.add_argument("--normative-manifest-digest","--expected-normative-manifest-digest",dest="normative_manifest_digest",required=True);p.add_argument("--mac-root");p.add_argument("--ios-root");p.add_argument("--protocol-root");p.add_argument("--compatibility-receipt",required=True);p.add_argument("--fresh-compatibility-receipt",required=True);p.add_argument("--output",required=True);p.add_argument("--logs-dir",required=True);p.add_argument("--production",action="store_true");a=p.parse_args()
 try:
  if a.production: die("production mode is forbidden")
  t={"macCommit":a.mac_commit,"iosCommit":a.ios_commit,"protocolCommit":a.protocol_commit,"compatibilityDigest":a.compatibility_digest,"normativeManifestDigest":a.normative_manifest_digest}
  if any(not isinstance(v,str) or len(v)!=(40 if k.endswith("Commit") else 64) or set(v)>HEX for k,v in t.items()): die("invalid exact tuple")
  output=Path(a.output); logs=Path(a.logs_dir)
  if output.parent.resolve()!=logs.parent.resolve(): die("output and log directory must share evidence root")
  logs.mkdir(mode=0o700,exist_ok=True)
  if logs.is_symlink() or not logs.is_dir(): die("unsafe logs directory")
  compat=read(a.compatibility_receipt); fresh=read(a.fresh_compatibility_receipt)
  out(output.parent/"compatibility-report.json",compat);out(output.parent/"compatibility-report-fresh.json",fresh)
  positive=["test-positive-vector"]; negative=["test-negative-vector"]
  labels=["suite-mac-adversarial","suite-ios-adversarial","suite-protocol-negative-vectors","suite-mac-session-vectors","suite-ios-session-vectors","suite-ios-pairing-vectors","suite-protocol-positive-vectors"]
  commands=[]
  for label in labels:
   name=label+".json"; raw=canonical({"schemaVersion":1,"kind":"test-only-command-log.v1","label":label,"provenance":"test-only","exitCode":0})+b"\n";out(logs/name,raw);commands.append({"label":label,"exitCode":0,"logPath":"logs/"+name})
  pin={"schemaVersion":1,"protocolCommit":t["protocolCommit"],"compatibilityDigest":t["compatibilityDigest"],"normativeManifestDigest":t["normativeManifestDigest"]}; pinsha=sha(canonical(pin))
  coverage={"positiveRawFrameCases":["test-raw-frame"],"productionDerivedAdversarialCases":{"mac":negative,"ios":negative},"enumeratedProtocolPositiveVectorIDs":positive,"enumeratedProtocolNegativeVectorIDs":negative,"productionSuiteResults":{x:True for x in labels},"productionSuiteCoveredPositiveVectorIDs":positive,"productionSuiteCoveredNegativeVectorIDs":negative,"negativeVectorEvidenceLabels":labels[:3],"positiveVectorEvidenceLabels":labels[3:],"unexecutableNegativeVectorIDs":[],"unexecutablePolicy":"matrix fails rather than claiming vector coverage without passing production suites"}
  process={"topology":"separate production-derived Swift executables","framing":"4-byte big-endian length followed by raw payload bytes over stdout/stdin","directions":["mac-encoder-to-ios-decoder","ios-encoder-to-mac-decoder"],"negativeCases":["zero-length frame exits nonzero","production-derived adversarial case mode exits nonzero on unexpected acceptance"]}
  pins={"trackedConsumerPins":{"mac":pin,"ios":pin},"builtProductPins":{"mac":pin,"ios":pin},"trackedConsumerPinSha256":{"mac":pinsha,"ios":pinsha},"builtProductPinSha256":{"mac":pinsha,"ios":pinsha}}
  report={"schemaVersion":2,"kind":"cross-repo-production-interop-report","result":"passed","sourceTuple":t,"coverageContract":coverage,"processProtocol":process,"builtPinEvidence":pins,"commands":commands,"failures":[],"compatibilityReceipt":{"path":"compatibility-report.json","sha256":sha(compat)},"freshCompatibilityReceipt":{"path":"compatibility-report-fresh.json","sha256":sha(fresh)},"physicalAvailability":"outside automated matrix evidence DAG; S-P1-05 OPEN-WAIVED"}
  out(output,canonical(report)+b"\n");return 0
 except Exception as e:print("produce-test-inner-matrix.py: error: "+str(e),file=sys.stderr);return 2
if __name__=="__main__":sys.exit(main())
