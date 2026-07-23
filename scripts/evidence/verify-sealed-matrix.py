#!/usr/bin/env python3
"""Verify sealed matrix evidence without accepting or accessing source roots."""
import argparse, hashlib, json, os, re, stat, sys
from pathlib import Path

IDS = ("mac", "ios", "protocol"); HEX = set("0123456789abcdef")
def die(m): raise SystemExit("FAIL_CLOSED: " + m)
def sha(b): return hashlib.sha256(b).hexdigest()
def hexv(v, n): return isinstance(v, str) and len(v) == n and set(v) <= HEX
INNER_FIELDS={"schemaVersion","kind","result","sourceTuple","coverageContract","processProtocol","builtPinEvidence","commands","failures","compatibilityReceipt","freshCompatibilityReceipt","physicalAvailability"}
COVERAGE_FIELDS={"positiveRawFrameCases","productionDerivedAdversarialCases","enumeratedProtocolPositiveVectorIDs","enumeratedProtocolNegativeVectorIDs","productionSuiteResults","productionSuiteCoveredPositiveVectorIDs","productionSuiteCoveredNegativeVectorIDs","negativeVectorEvidenceLabels","positiveVectorEvidenceLabels","unexecutableNegativeVectorIDs","unexecutablePolicy"}
NEGATIVE_LABELS={"suite-mac-adversarial","suite-ios-adversarial","suite-protocol-negative-vectors"}
POSITIVE_LABELS={"suite-mac-session-vectors","suite-ios-session-vectors","suite-ios-pairing-vectors","suite-protocol-positive-vectors"}
PROCESS={"topology":"separate production-derived Swift executables","framing":"4-byte big-endian length followed by raw payload bytes over stdout/stdin","directions":["mac-encoder-to-ios-decoder","ios-encoder-to-mac-decoder"],"negativeCases":["zero-length frame exits nonzero","production-derived adversarial case mode exits nonzero on unexpected acceptance"]}
AVAILABILITY="outside automated matrix evidence DAG; S-P1-05 OPEN-WAIVED"
PUBLIC_INVENTORY_KEYS={"logical","generated","package","cache"}
def public_inventory(value,label):
 if (not isinstance(value,dict) or set(value)!={"inventorySha256","fullInventorySha256","inventoryEntryCounts","inventoryEntries"} or not isinstance(value["inventorySha256"],dict) or set(value["inventorySha256"])!=PUBLIC_INVENTORY_KEYS or any(not hexv(item,64) for item in value["inventorySha256"].values()) or not hexv(value["fullInventorySha256"],64) or not isinstance(value["inventoryEntryCounts"],dict) or set(value["inventoryEntryCounts"])!=PUBLIC_INVENTORY_KEYS or any(not isinstance(item,int) or isinstance(item,bool) or item<0 for item in value["inventoryEntryCounts"].values()) or not isinstance(value["inventoryEntries"],dict) or set(value["inventoryEntries"])!=PUBLIC_INVENTORY_KEYS): die(label+" public inventory fields are invalid")
 seen=set()
 for category in PUBLIC_INVENTORY_KEYS:
  entries=value["inventoryEntries"][category]
  if not isinstance(entries,list) or value["inventoryEntryCounts"][category]!=len(entries) or entries!=sorted(entries,key=lambda entry:entry.get("path") if isinstance(entry,dict) else ""): die(label+" inventory entries are not sorted")
  for entry in entries:
   if (not isinstance(entry,dict) or set(entry)!={"path","sha256","size","dev","ino"} or not isinstance(entry["path"],str) or not entry["path"] or Path(entry["path"]).is_absolute() or any(part in ("",".","..") for part in Path(entry["path"]).parts) or entry["path"] in seen or not hexv(entry["sha256"],64) or any(not isinstance(entry[key],int) or isinstance(entry[key],bool) or entry[key]<0 for key in ("size","dev","ino"))): die(label+" inventory entry is invalid")
   seen.add(entry["path"])
  if value["inventorySha256"][category]!=sha(json.dumps(entries,sort_keys=True,separators=(",",":")).encode()): die(label+" inventory category digest mismatch")
 if value["fullInventorySha256"]!=sha(json.dumps(value["inventoryEntries"],sort_keys=True,separators=(",",":")).encode()): die(label+" full inventory digest mismatch")
def nonempty_unique(values, label):
 if not isinstance(values,list) or not values or any(not isinstance(v,str) or not v for v in values) or len(set(values))!=len(values): die(label+" must be a nonempty unique string list")
def validate_inner(value, tuple_):
 exact(value,INNER_FIELDS,"inner matrix")
 if value.get("schemaVersion")!=2 or value.get("kind")!="cross-repo-production-interop-report" or value.get("result")!="passed" or value.get("sourceTuple")!=tuple_ or value.get("failures")!=[]: die("inner matrix semantic contract is invalid")
 coverage=value["coverageContract"]; exact(coverage,COVERAGE_FIELDS,"inner coverage contract")
 for key in ("positiveRawFrameCases","enumeratedProtocolPositiveVectorIDs","enumeratedProtocolNegativeVectorIDs","productionSuiteCoveredPositiveVectorIDs","productionSuiteCoveredNegativeVectorIDs","negativeVectorEvidenceLabels","positiveVectorEvidenceLabels"): nonempty_unique(coverage[key],"inner "+key)
 if coverage["productionSuiteCoveredPositiveVectorIDs"]!=coverage["enumeratedProtocolPositiveVectorIDs"] or coverage["productionSuiteCoveredNegativeVectorIDs"]!=coverage["enumeratedProtocolNegativeVectorIDs"] or coverage["unexecutableNegativeVectorIDs"]!=[] or set(coverage["negativeVectorEvidenceLabels"])!=NEGATIVE_LABELS or set(coverage["positiveVectorEvidenceLabels"])!=POSITIVE_LABELS or coverage["unexecutablePolicy"]!="matrix fails rather than claiming vector coverage without passing production suites": die("inner coverage semantics are incomplete")
 adversarial=coverage["productionDerivedAdversarialCases"]
 if not isinstance(adversarial,dict) or set(adversarial)!={"mac","ios"} or any(not isinstance(adversarial[i],list) or set(adversarial[i])!=set(coverage["enumeratedProtocolNegativeVectorIDs"]) for i in adversarial): die("inner adversarial coverage is incomplete")
 suites=coverage["productionSuiteResults"]
 if not isinstance(suites,dict) or set(suites)!=NEGATIVE_LABELS|POSITIVE_LABELS or any(item is not True for item in suites.values()): die("inner production suite evidence is incomplete")
 exact(value["processProtocol"],set(PROCESS),"inner process protocol")
 if value["processProtocol"]!=PROCESS: die("inner process protocol is invalid")
 pins=value["builtPinEvidence"]; exact(pins,{"trackedConsumerPins","builtProductPins","trackedConsumerPinSha256","builtProductPinSha256"},"inner pin evidence")
 for key in ("trackedConsumerPins","builtProductPins"):
  if not isinstance(pins[key],dict) or set(pins[key])!={"mac","ios"}: die("inner pin evidence is invalid")
  for pin in pins[key].values():
   exact(pin,{"schemaVersion","protocolCommit","compatibilityDigest","normativeManifestDigest"},"inner build pin")
   if pin!={"schemaVersion":1,"protocolCommit":tuple_["protocolCommit"],"compatibilityDigest":tuple_["compatibilityDigest"],"normativeManifestDigest":tuple_["normativeManifestDigest"]}: die("inner pin evidence is invalid")
 for key in ("trackedConsumerPinSha256","builtProductPinSha256"):
  if not isinstance(pins[key],dict) or set(pins[key])!={"mac","ios"} or any(not hexv(v,64) for v in pins[key].values()): die("inner pin hash references are invalid")
 if pins["trackedConsumerPins"]!=pins["builtProductPins"] or pins["trackedConsumerPinSha256"]!=pins["builtProductPinSha256"]: die("inner built pin evidence does not bind tracked pins")
 commands=value["commands"]
 if not isinstance(commands,list) or not commands: die("inner command contract is invalid")
 paths=set()
 for command in commands:
  exact(command,{"label","exitCode","logPath"},"inner command")
  if not isinstance(command["label"],str) or not command["label"] or command["exitCode"]!=0 or not isinstance(command["logPath"],str) or not command["logPath"].startswith("logs/") or "/" in command["logPath"][5:]: die("inner command contract is invalid")
  paths.add(command["logPath"])
 if len(paths)!=len(commands): die("inner command contract is invalid")
 for key,path in (("compatibilityReceipt","compatibility-report.json"),("freshCompatibilityReceipt","compatibility-report-fresh.json")):
  exact(value[key],{"path","sha256"},"inner "+key)
  if value[key]["path"]!=path or not hexv(value[key]["sha256"],64): die("inner receipt contract is invalid")
 if value["physicalAvailability"]!=AVAILABILITY: die("inner physical availability contract is invalid")
 return paths
def validate_containment_profile(raw, containment, root):
 if containment["mode"]=="test-only":
  if raw or containment["allowedWritePaths"]!=[]: die("test-only containment profile is not empty")
  return
 try: lines=raw.decode("utf-8").splitlines()
 except UnicodeDecodeError: die("containment profile is not UTF-8")
 grants=[]
 for line in lines:
  match=re.fullmatch(r'\(allow file-write\* \((subpath|literal) "([^"\\\n]+)"\)\)',line)
  if match: grants.append((match.group(1),match.group(2)))
 expected_sandbox_prefix=str(root / "sandboxes") + "/TX-"
 allowed=containment["allowedWritePaths"]
 if (not isinstance(allowed,list) or len(allowed)!=6 or len(set(allowed))!=6 or allowed[0].startswith(expected_sandbox_prefix) is False or not re.fullmatch(re.escape(expected_sandbox_prefix)+r"[0-9a-f]{64}",allowed[0]) or allowed[1:]!=[str(root/"inner-matrix.json"),str(root/"receipts"),str(root/"logs"),str(root/"compatibility-report.json"),str(root/"compatibility-report-fresh.json")]):
  die("containment allowed write paths are not exact")
 expected_lines=["(version 1)","(deny default)","(allow process*)","(allow file-read*)",
  '(allow file-write* (subpath "'+allowed[0]+'"))',
  '(allow file-write* (literal "'+allowed[1]+'"))',
  '(allow file-write* (subpath "'+allowed[2]+'"))',
  '(allow file-write* (subpath "'+allowed[3]+'"))',
  '(allow file-write* (literal "'+allowed[4]+'"))',
  '(allow file-write* (literal "'+allowed[5]+'"))']
 if lines!=expected_lines or grants!=[("subpath",allowed[0]),("literal",allowed[1]),("subpath",allowed[2]),("subpath",allowed[3]),("literal",allowed[4]),("literal",allowed[5])]:
  die("containment profile grants are not exact")
def validate_transcript(raw, containment):
 try: header, _ = raw.split(b"\n",1); value=json.loads(header.decode("utf-8"))
 except (ValueError,UnicodeDecodeError): die("containment transcript is malformed")
 if value!={"profileSha256":containment["profileSha256"],"argvSha256":containment["argvSha256"],"environmentSha256":containment["environmentSha256"]}: die("containment transcript does not bind profile, argv, and environment")
def exact(v, fields, label):
 if not isinstance(v, dict) or set(v) != set(fields): die(label + " fields are not exact")
def report_hash(records, role): return next(record["sha256"] for record in records if record["role"] == role)
def open_evidence_root(path):
 try:
  before=Path(path).lstat(); fd=__import__("os").open(path,__import__("os").O_RDONLY|getattr(__import__("os"),"O_DIRECTORY",0)|getattr(__import__("os"),"O_NOFOLLOW",0)); info=__import__("os").fstat(fd)
 except OSError as exc: die("evidence root is unavailable: " + str(exc))
 if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or (before.st_dev,before.st_ino)!=(info.st_dev,info.st_ino): __import__("os").close(fd); die("evidence root is unstable")
 return fd
def read_evidence(rootfd, relative, label):
 import os
 parts=Path(relative).parts
 if not parts or any(part in ("", ".", "..") for part in parts): die(label + " has invalid path")
 fd=os.dup(rootfd)
 try:
  for part in parts[:-1]:
   nextfd=os.open(part,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=fd); os.close(fd); fd=nextfd
  leaf=os.open(parts[-1],os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=fd)
  try:
   info=os.fstat(leaf)
   if not stat.S_ISREG(info.st_mode): die(label + " is not a regular evidence file")
   data=os.read(leaf,info.st_size+1)
   if len(data)!=info.st_size or os.fstat(leaf).st_size!=info.st_size: die(label + " changed while reading")
   return data
  finally: os.close(leaf)
 except OSError as exc: die(label + " is unavailable: " + str(exc))
 finally: os.close(fd)

def main():
 p = argparse.ArgumentParser(); p.add_argument("--evidence-root", required=True); p.add_argument("--matrix", default="sealed-matrix.json"); p.add_argument("--matrix-binding", default="matrix-binding.json"); p.add_argument("--require-production-trust", action="store_true"); a = p.parse_args(); root = Path(a.evidence_root).resolve(); rootfd = open_evidence_root(root)
 raw = read_evidence(rootfd, a.matrix, "sealed report")
 try:
  def duplicate_rejecting_pairs(items):
   value = {}
   for key, item in items:
    if key in value: raise ValueError("duplicate key " + key)
    value[key] = item
   return value
  report = json.loads(raw.decode("utf-8"), object_pairs_hook=duplicate_rejecting_pairs)
 except Exception as exc: die("malformed immutable evidence sealed report: " + str(exc))
 exact(report, ("schemaVersion", "kind", "result", "sourceTuple", "provenance", "containment", "inventories", "publicInventories", "records", "mutexBindings", "innerMatrix", "logs"), "sealed report")
 if report["schemaVersion"] != 1 or report["kind"] not in ("photonport.sealed-cross-repo-matrix.v1","photonport.sealed-cross-repo-matrix.test-only.v1") or report["result"] != "passed": die("report is not a passing sealed matrix")
 provenance = report["provenance"]; exact(provenance, ("mode", "runnerPath", "runnerSha256"), "provenance")
 if provenance["mode"] not in ("production", "test-only") or not hexv(provenance["runnerSha256"],64) or (provenance["mode"]=="test-only") != report["kind"].endswith(".test-only.v1"): die("invalid provenance")
 containment=report["containment"]
 if (not isinstance(containment,dict) or set(containment)!={"profileFormat","mode","result","profile","profileSha256","allowedWritePaths","argvSha256","environmentSha256","processTranscript","processTranscriptSha256"} or containment["profileFormat"]!="seatbelt-v1" or any(not hexv(containment[k],64) for k in ("profileSha256","argvSha256","environmentSha256","processTranscriptSha256")) or (provenance["mode"]=="production" and (containment["mode"]!="source-read-only" or containment["result"]!="enforced")) or (provenance["mode"]=="test-only" and (containment["mode"]!="test-only" or containment["result"]!="not-production"))):
  die("invalid containment binding")
 artifacts={}
 for name, expected_path, expected_sha in (("profile", "containment/seatbelt.sb", "profileSha256"), ("processTranscript", "containment/process-transcript.log", "processTranscriptSha256")):
  artifact=containment[name]
  if not isinstance(artifact,dict) or set(artifact)!={"path","sha256","size"} or artifact["path"]!=expected_path or not hexv(artifact["sha256"],64) or not isinstance(artifact["size"],int) or artifact["size"]<0:
   die("invalid containment artifact")
  artifact_raw=read_evidence(rootfd,artifact["path"],"containment "+name)
  if len(artifact_raw)!=artifact["size"] or sha(artifact_raw)!=artifact["sha256"] or artifact["sha256"]!=containment[expected_sha]:
   die("containment artifact hash mismatch")
  artifacts[name]=artifact_raw
 validate_containment_profile(artifacts["profile"],containment,root)
 validate_transcript(artifacts["processTranscript"],containment)
 tuple_ = report["sourceTuple"]; exact(tuple_, ("macCommit", "iosCommit", "protocolCommit", "compatibilityDigest", "normativeManifestDigest"), "tuple")
 if not all(hexv(v, 40 if k.endswith("Commit") else 64) for k, v in tuple_.items()): die("invalid tuple")
 binding_raw=read_evidence(rootfd,a.matrix_binding,"matrix binding")
 try: matrix_binding=json.loads(binding_raw.decode("utf-8"))
 except Exception as exc: die("malformed matrix binding: " + str(exc))
 if (set(matrix_binding) != {"schemaVersion","kind","reportSha256","reportSize","tupleSha256","lifecycleTupleSha256","inventorySha256ByRoot","fullInventorySha256ByRoot","inventoryEntryCountsByRoot","inventoryEntriesSha256ByRoot","allocatedSha256ByRoot","sourceActiveSha256ByRoot","sealSha256ByRoot","mutexSha256ByRoot","containmentSha256","innerMatrixSha256","logsSha256"}
     or matrix_binding.get("schemaVersion") != 1
     or matrix_binding.get("kind") != "photonport.matrix-binding.v1"
     or matrix_binding.get("reportSha256") != sha(raw)
     or matrix_binding.get("reportSize") != len(raw)
     or matrix_binding.get("tupleSha256") != sha(json.dumps(tuple_,sort_keys=True,separators=(",",":")).encode())
     or matrix_binding.get("lifecycleTupleSha256") != sha(json.dumps({key:tuple_[key] for key in ("macCommit","iosCommit","protocolCommit")},sort_keys=True,separators=(",",":")).encode())
     or matrix_binding.get("containmentSha256") != sha(json.dumps(containment,sort_keys=True,separators=(",",":")).encode())):
  die("matrix binding does not bind exact report bytes")
 records = report["records"]
 if not isinstance(records, list) or len(records) != 23: die("record count mismatch")
 if not isinstance(report["mutexBindings"], list) or len(report["mutexBindings"]) != 3: die("mutex bindings malformed")
 expected = {role + ":" + ident for role in ("source-active", "inventory", "lifecycle-allocated", "lifecycle-admission", "seal-manifest", "live-attestation", "source-mutex") for ident in IDS} | {"compatibility-receipt", "fresh-compatibility-receipt"}; indexed = {}; record_hashes = {}; record_bytes = {}
 expected_paths = {
  **{role + ":" + ident: "inputs/" + role + "-" + ident + ".json" for role in ("source-active", "inventory", "lifecycle-allocated", "lifecycle-admission", "seal-manifest", "live-attestation", "source-mutex") for ident in IDS},
  "compatibility-receipt": "receipts/compatibility-report.json",
  "fresh-compatibility-receipt": "receipts/compatibility-report-fresh.json",
 }
 for rec in records:
  exact(rec, ("role", "path", "sha256"), "record")
  if rec["role"] not in expected or rec["role"] in indexed or rec["path"] != expected_paths[rec["role"]] or not hexv(rec["sha256"], 64): die("duplicate or malformed record")
  data = read_evidence(rootfd, rec["path"], "record")
  if sha(data) != rec["sha256"]: die("record hash mismatch")
  record_bytes[rec["role"]] = data
  record_hashes[rec["role"]] = rec["sha256"]
  if rec["role"] in {"compatibility-receipt", "fresh-compatibility-receipt"}: indexed[rec["role"]] = None
  else:
   try: indexed[rec["role"]] = json.loads(data.decode("utf-8"))
   except (UnicodeDecodeError, json.JSONDecodeError) as exc: die("malformed immutable evidence record: " + str(exc))
 if set(indexed) != expected: die("missing record")
 inventories=report["inventories"]
 if not isinstance(inventories,dict) or set(inventories)!=set(IDS) or any(inventories[i] != record_hashes["inventory:"+i] for i in IDS): die("inventory binding mismatch")
 public_inventories=report["publicInventories"]
 if not isinstance(public_inventories,dict) or set(public_inventories)!=set(IDS): die("public inventory report binding is malformed")
 for ident in IDS: public_inventory(public_inventories[ident],"public inventory report")
 for field,key in (("inventorySha256ByRoot","inventorySha256"),("fullInventorySha256ByRoot","fullInventorySha256"),("inventoryEntryCountsByRoot","inventoryEntryCounts")):
  digest_map=matrix_binding[field]
  if not isinstance(digest_map,dict) or set(digest_map)!=set(IDS) or any(digest_map[i] != public_inventories[i][key] for i in IDS): die("matrix binding public inventory map mismatch")
 digest_map=matrix_binding["inventoryEntriesSha256ByRoot"]
 if not isinstance(digest_map,dict) or set(digest_map)!=set(IDS) or any(digest_map[i] != sha(json.dumps(public_inventories[i]["inventoryEntries"],sort_keys=True,separators=(",",":")).encode()) for i in IDS): die("matrix binding inventory entries map mismatch")
 for field in ("allocatedSha256ByRoot","sourceActiveSha256ByRoot","sealSha256ByRoot","mutexSha256ByRoot"):
  digest_map=matrix_binding[field]
  if not isinstance(digest_map,dict) or set(digest_map)!=set(IDS) or any(not hexv(digest_map[i],64) for i in IDS): die("matrix binding digest map is malformed")
 if (any(matrix_binding["allocatedSha256ByRoot"][i] != record_hashes["lifecycle-allocated:"+i] for i in IDS)
     or any(matrix_binding["sourceActiveSha256ByRoot"][i] != record_hashes["source-active:"+i] for i in IDS)
     or any(matrix_binding["sealSha256ByRoot"][i] != record_hashes["seal-manifest:"+i] for i in IDS)
     or any(matrix_binding["mutexSha256ByRoot"][i] != record_hashes["source-mutex:"+i] for i in IDS)):
  die("matrix binding digest map mismatch")
 for ident in IDS:
  active = indexed["source-active:" + ident]; seal = indexed["seal-manifest:" + ident]; att = indexed["live-attestation:" + ident]
  allocated = indexed["lifecycle-allocated:" + ident]; admission = indexed["lifecycle-admission:" + ident]
  active = json.loads(record_bytes["source-active:" + ident].decode())
  allocated = json.loads(record_bytes["lifecycle-allocated:" + ident].decode())
  if active.get("state") != "source-active" or allocated.get("state") != "allocated" or not hexv(active.get("allocationReleaseSha256"),64): die("invalid lifecycle state")
  if (not isinstance(admission, dict)
      or set(admission) != {"entries", "dev", "ino"}
      or admission["entries"] != ["000-allocated.json", "010-source-active.json"]
      or not isinstance(admission["dev"], int)
      or not isinstance(admission["ino"], int)
      or active["predecessorSha256"] != report_hash(records, "lifecycle-allocated:" + ident)
      or any(active[k] != allocated[k] for k in ("lifecycleId", "rootId", "tuple", "allocation", "authority"))
      or active["rootId"] != ident
      or active["tuple"] != {k: tuple_[k] for k in ("macCommit", "iosCommit", "protocolCommit")}):
   die("lifecycle admission or CAS chain mismatch")
  exact(seal, ("schemaVersion", "kind", "id", "commit", "sourceActiveSha256", "inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries"), "seal manifest"); exact(att, ("schemaVersion", "kind", "id", "commit", "sealManifestSha256", "inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries"), "live attestation")
  public_inventory({key:seal[key] for key in ("inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries")},"seal manifest")
  if seal["inventorySha256"] != att["inventorySha256"] or seal["fullInventorySha256"] != att["fullInventorySha256"] or seal["inventoryEntryCounts"] != att["inventoryEntryCounts"] or seal["inventoryEntries"] != att["inventoryEntries"] or public_inventories[ident] != {key:seal[key] for key in ("inventorySha256", "fullInventorySha256", "inventoryEntryCounts", "inventoryEntries")}: die("public inventory evidence mismatch")
  if seal.get("schemaVersion") != 1 or att.get("schemaVersion") != 1 or seal.get("kind") != "seal-manifest-v1" or att.get("kind") != "live-attestation-v1" or any(v.get("id") != ident for v in (seal, att)): die("state/seal identity mismatch")
  if any(not hexv(v.get("commit"), 40) for v in (seal, att)) or seal["commit"] != tuple_[ident + "Commit"] or att["commit"] != tuple_[ident + "Commit"]: die("tuple/state mismatch")
  if seal.get("sourceActiveSha256") != report_hash(records, "source-active:" + ident) or att.get("sealManifestSha256") != report_hash(records, "seal-manifest:" + ident): die("seal chain mismatch")
  mutex = indexed["source-mutex:" + ident]
  if mutex.get("rootId") != ident or mutex.get("authority") != active.get("authority"): die("invalid source mutex")
  binding = next((value for value in report["mutexBindings"] if isinstance(value, dict) and value.get("id") == ident), None)
  exact(binding, ("id", "canonicalPath", "sourceActiveSha256", "sealManifestSha256", "mutexSha256", "lifecycleId", "rootId", "allocation", "authority", "allocationNonce", "mutexNonce", "supervisor", "rootDev", "rootIno", "mutexDev", "mutexIno", "supervisorFdDev", "supervisorFdIno", "closeSecretSha256", "acquisitionTag"), "mutex binding")
  if (len({value.get("id") for value in report["mutexBindings"] if isinstance(value, dict)}) != 3
      or binding["canonicalPath"] != "source-root.mutex"
      or binding["sourceActiveSha256"] != report_hash(records, "source-active:" + ident)
      or binding["sealManifestSha256"] != report_hash(records, "seal-manifest:" + ident)
      or binding["mutexSha256"] != report_hash(records, "source-mutex:" + ident)
      or any(binding[field] != active[field] for field in ("lifecycleId", "allocation"))
      or binding["rootDev"] != active["authority"]["root"]["dev"] or binding["rootIno"] != active["authority"]["root"]["ino"]
      or any(mutex[field] != binding[field] for field in ("lifecycleId", "rootId", "allocation", "authority", "allocationNonce", "mutexNonce", "supervisor", "rootDev", "rootIno", "mutexDev", "mutexIno", "supervisorFdDev", "supervisorFdIno", "closeSecretSha256", "acquisitionTag"))):
   die("mutex binding mismatch")
 inner = report["innerMatrix"]; exact(inner, ("path", "sha256"), "inner output")
 if inner["path"] != "inner-matrix.json" or not hexv(inner["sha256"], 64): die("inner output malformed")
 data = read_evidence(rootfd, inner["path"], "inner matrix report")
 try: value = json.loads(data.decode("utf-8"))
 except Exception as exc: die("malformed immutable evidence inner matrix report: " + str(exc))
 if sha(data) != inner["sha256"] or matrix_binding["innerMatrixSha256"] != sha(data): die("inner output hash mismatch")
 command_paths=validate_inner(value,tuple_)
 for key, role in (("compatibilityReceipt", "compatibility-receipt"), ("freshCompatibilityReceipt", "fresh-compatibility-receipt")):
  if value[key]["sha256"] != record_hashes[role]: die("inner " + key + " does not bind sealed receipt")
 if not isinstance(report["logs"], list): die("logs malformed")
 seen = set()
 for log in report["logs"]:
  exact(log, ("path", "sha256"), "log")
  if not isinstance(log["path"], str) or not log["path"].startswith("logs/") or "/" in log["path"][5:] or log["path"] in seen or not hexv(log["sha256"], 64): die("duplicate or malformed log")
  seen.add(log["path"]); data = read_evidence(rootfd, log["path"], "log")
  if sha(data) != log["sha256"]: die("log mismatch")
 if matrix_binding["logsSha256"] != sha(json.dumps(report["logs"],sort_keys=True,separators=(",",":")).encode()) or command_paths != seen: die("inner command evidence does not exactly bind sealed logs")
 if a.require_production_trust: die("production trust requires a later verified G004 DSSE envelope")
 print(json.dumps({"evidenceKind":report["kind"],"integrity":"verified","productionTrust":"unavailable-without-g004-dsse"},sort_keys=True))
 return 0
if __name__ == "__main__": sys.exit(main())
