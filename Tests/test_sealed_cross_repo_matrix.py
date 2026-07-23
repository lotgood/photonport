#!/usr/bin/env python3
"""Self-contained trust-boundary tests; no project build is invoked."""
import hashlib, importlib.util, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; SUPERVISOR_FDS=[]; WRAPPER=ROOT/"scripts/evidence/run-sealed-cross-repo-matrix.py"; VERIFY=ROOT/"scripts/evidence/verify-sealed-matrix.py"
PRODUCER_SPEC=importlib.util.spec_from_file_location("sealed_matrix_fixture_contract",WRAPPER); PRODUCER=importlib.util.module_from_spec(PRODUCER_SPEC); PRODUCER_SPEC.loader.exec_module(PRODUCER)
VERIFIER_SPEC=importlib.util.spec_from_file_location("sealed_matrix_verifier_contract",VERIFY); VERIFIER=importlib.util.module_from_spec(VERIFIER_SPEC); VERIFIER_SPEC.loader.exec_module(VERIFIER)
def digest(data): return hashlib.sha256(data).hexdigest()
def run(args, **kwargs):
 fds=[]
 for flag in ("--supervisor-fd","--supervisor-close-secret-fd"):
  if flag in args:
   start=args.index(flag)+1
   fds.extend(int(value) for value in args[start:start+3])
 if fds: kwargs.setdefault("pass_fds",tuple(fds))
 return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
class SealedMatrixTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.base=Path(self.tmp.name); self.commits={}; self.mutexes=[]; self.supervisor_fds=[]; self.secret_fds=[]
  for ident in ("mac","ios","protocol"):
   root=self.base/ident; root.mkdir(); run(["git","init",str(root)]).check_returncode(); run(["git","-C",str(root),"config","user.email","test@example.invalid"]).check_returncode(); run(["git","-C",str(root),"config","user.name","Test"]).check_returncode(); (root/"file").write_text(ident); run(["git","-C",str(root),"add","file"]).check_returncode(); run(["git","-C",str(root),"commit","-m","fixture"]).check_returncode(); self.commits[ident]=run(["git","-C",str(root),"rev-parse","HEAD"]).stdout.strip(); st=root.stat(); lifecycle=self.base/("lifecycle-"+ident); lifecycle.mkdir(); mutex=self.base/("source-root-"+ident+".mutex"); secret_path=self.base/("secret-"+ident); secret_path.write_bytes((ident*32).encode()[:32]); secret_fd=os.open(secret_path,os.O_RDONLY); fd=os.open(mutex,os.O_RDWR|os.O_CREAT); import fcntl; fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); authority={"approvedSequence":["allocated","source-active","source-closing","source-released","disposing","disposed"],"root":{"canonicalPath":str(root.resolve()),"dev":st.st_dev,"ino":st.st_ino},"supervisor":"fixture-supervisor","command":"fixture","allocationNonce":"a"*64,"mutexNonce":"d"*64,"lockAPath":str((self.base/"lock-a").resolve()),"lockBPath":str(mutex.resolve()),"registryPath":str(self.base.resolve()),"commonGitDir":str(self.base.resolve())}; payload={"lifecycleId":"fixture","rootId":ident,"allocation":{"id":"fixture","sha256":"c"*64},"authority":authority,"allocationNonce":"a"*64,"mutexNonce":"d"*64,"supervisor":"fixture-supervisor","rootDev":st.st_dev,"rootIno":st.st_ino,"mutexDev":os.fstat(fd).st_dev,"mutexIno":os.fstat(fd).st_ino,"supervisorFdDev":os.fstat(fd).st_dev,"supervisorFdIno":os.fstat(fd).st_ino,"closeSecretSha256":digest((ident*32).encode()[:32])}; payload["acquisitionTag"]=__import__('hmac').new((ident*32).encode()[:32],json.dumps(payload,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest(); mutex.write_text(json.dumps(payload)); self.secret_fds.append(secret_fd); self.supervisor_fds.append(fd); self.mutexes.append(mutex)
  self.records=[]
  for ident in ("mac","ios","protocol"):
   st=(self.base/ident).stat(); mutex=self.mutexes[("mac","ios","protocol").index(ident)]; lifecycle=self.base/("lifecycle-"+ident); authority=json.loads(mutex.read_text())["authority"]; tuple_={"macCommit":self.commits["mac"],"iosCommit":self.commits["ios"],"protocolCommit":self.commits["protocol"]}; allocated={"schemaVersion":1,"kind":"photonport.lifecycle-state.v1","lifecycleId":"fixture","rootId":ident,"tuple":tuple_,"allocation":{"id":"fixture","sha256":"c"*64},"authority":authority,"state":"allocated","predecessorSha256":None}; araw=json.dumps(allocated,sort_keys=True,separators=(",",":")).encode(); ap=lifecycle/"000-allocated.json"; ap.write_bytes(araw); active={**allocated,"state":"source-active","predecessorSha256":digest(araw),"allocationReleaseSha256":"e"*64}; ap=lifecycle/"010-source-active.json"; raw=json.dumps(active,sort_keys=True,separators=(",",":")).encode(); ap.write_bytes(raw)
   handles=PRODUCER.open_source_roots({ident:self.base/ident})
   try:
    entries=PRODUCER.source_manifest(handles)[ident]; logical=[{"path":path,"sha256":value[-1],"size":value[3],"dev":value[1],"ino":value[2]} for path,value in entries.items() if value[0]=="file"]; logical.sort(key=lambda entry:entry["path"]); categories={"logical":logical,"generated":[],"package":[],"cache":[]}; public={"inventoryEntries":categories,"inventorySha256":{key:digest(json.dumps(categories[key],sort_keys=True,separators=(",",":")).encode()) for key in categories},"fullInventorySha256":digest(json.dumps(categories,sort_keys=True,separators=(",",":")).encode()),"inventoryEntryCounts":{key:len(categories[key]) for key in categories}}
   finally:
    for handle,_ in handles.values(): os.close(handle)
   seal={"schemaVersion":1,"kind":"seal-manifest-v1","id":ident,"commit":self.commits[ident],"sourceActiveSha256":digest(raw),**public}; sp=self.base/("seal-"+ident+".json"); sraw=json.dumps(seal).encode(); sp.write_bytes(sraw)
   att={"schemaVersion":1,"kind":"live-attestation-v1","id":ident,"commit":self.commits[ident],"sealManifestSha256":digest(sraw),**public}; tp=self.base/("att-"+ident+".json"); tp.write_bytes(json.dumps(att).encode()); self.records.extend([ap,sp,tp])
  self.inner=self.base/"inner.py"; self.inner.write_text('''import argparse,fcntl,hashlib,json,os
p=argparse.ArgumentParser(); [p.add_argument(x,required=True) for x in ["--mac-root","--ios-root","--protocol-root","--expected-mac-commit","--expected-ios-commit","--expected-protocol-commit","--expected-compatibility-digest","--expected-normative-manifest-digest","--output"]]; p.add_argument("--mode",default="good"); a=p.parse_args()
t={"macCommit":a.expected_mac_commit,"iosCommit":a.expected_ios_commit,"protocolCommit":a.expected_protocol_commit,"compatibilityDigest":a.expected_compatibility_digest,"normativeManifestDigest":a.expected_normative_manifest_digest}
if a.mode=="mutate": open(os.path.join(a.mac_root,"file"),"w").write("changed")
if a.mode=="mutate-restore":
 for name in ("source-root-mac.mutex","source-root-ios.mutex","source-root-protocol.mutex"):
  fd=os.open(os.path.join(os.path.dirname(a.mac_root),name),os.O_RDWR)
  try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); raise SystemExit("mutex was not held")
  except BlockingIOError: pass
  finally: os.close(fd)
 original=open(os.path.join(a.mac_root,"file")).read(); open(os.path.join(a.mac_root,"file"),"w").write("changed"); open(os.path.join(a.mac_root,"file"),"w").write(original)
if a.mode=="ignored": open(os.path.join(a.mac_root,"ignored-generated"),"w").write("ignored")
if a.mode=="untracked": open(os.path.join(a.mac_root,"untracked"),"w").write("untracked")
if a.mode=="git-mutation": open(os.path.join(a.mac_root,".git","fixture-mutation"),"w").write("mutation")
if a.mode=="symlink": os.symlink(os.path.join(a.mac_root,"file"),a.output); raise SystemExit()
pin={"schemaVersion":1,"protocolCommit":a.expected_protocol_commit,"compatibilityDigest":a.expected_compatibility_digest,"normativeManifestDigest":a.expected_normative_manifest_digest}; neg=["n1"]; pos=["p1"]; neglabels=["suite-mac-adversarial","suite-ios-adversarial","suite-protocol-negative-vectors"]; poslabels=["suite-mac-session-vectors","suite-ios-session-vectors","suite-ios-pairing-vectors","suite-protocol-positive-vectors"]; logs=os.path.join(os.path.dirname(a.output),"logs"); os.mkdir(logs); commands=[]
for n in ("one","two"):
 path="logs/"+n+".json"; json.dump({"label":n},open(os.path.join(os.path.dirname(a.output),path),"w")); commands.append({"label":n,"exitCode":0,"logPath":path})
receipt1=b'{"receipt":"compatibility"}\\n'; receipt2=b'{"receipt":"fresh"}\\n'; open(os.path.join(os.path.dirname(a.output),"compatibility-report.json"),"wb").write(receipt1); open(os.path.join(os.path.dirname(a.output),"compatibility-report-fresh.json"),"wb").write(receipt2); receipt1hash=hashlib.sha256(receipt1).hexdigest(); receipt2hash=hashlib.sha256(receipt2).hexdigest()
r={"schemaVersion":2,"kind":"cross-repo-production-interop-report","result":"passed","sourceTuple":t,"coverageContract":{"positiveRawFrameCases":["frame"],"productionDerivedAdversarialCases":{"mac":neg,"ios":neg},"enumeratedProtocolPositiveVectorIDs":pos,"enumeratedProtocolNegativeVectorIDs":neg,"productionSuiteResults":{x:True for x in neglabels+poslabels},"productionSuiteCoveredPositiveVectorIDs":pos,"productionSuiteCoveredNegativeVectorIDs":neg,"negativeVectorEvidenceLabels":neglabels,"positiveVectorEvidenceLabels":poslabels,"unexecutableNegativeVectorIDs":[],"unexecutablePolicy":"matrix fails rather than claiming vector coverage without passing production suites"},"processProtocol":{"topology":"separate production-derived Swift executables","framing":"4-byte big-endian length followed by raw payload bytes over stdout/stdin","directions":["mac-encoder-to-ios-decoder","ios-encoder-to-mac-decoder"],"negativeCases":["zero-length frame exits nonzero","production-derived adversarial case mode exits nonzero on unexpected acceptance"]},"builtPinEvidence":{"trackedConsumerPins":{"mac":pin,"ios":pin},"builtProductPins":{"mac":pin,"ios":pin},"trackedConsumerPinSha256":{"mac":"a"*64,"ios":"b"*64},"builtProductPinSha256":{"mac":"a"*64,"ios":"b"*64}},"commands":commands,"failures":[],"compatibilityReceipt":{"path":"compatibility-report.json","sha256":receipt1hash},"freshCompatibilityReceipt":{"path":"compatibility-report-fresh.json","sha256":receipt2hash},"physicalAvailability":"outside automated matrix evidence DAG; S-P1-05 OPEN-WAIVED"}
if a.mode=="malformed": r["result"]="failed"
if a.mode=="placeholder": r["commands"]=[]
json.dump(r,open(a.output,"w"))
if a.mode=="inner-symlink": os.unlink(a.output); os.symlink(os.path.join(os.path.dirname(a.output),"compatibility-report.json"),a.output)
if a.mode=="receipt-symlink": os.unlink(os.path.join(os.path.dirname(a.output),"compatibility-report.json")); os.symlink(os.path.join(os.path.dirname(a.output),"compatibility-report-fresh.json"),os.path.join(os.path.dirname(a.output),"compatibility-report.json"))
if a.mode=="log-symlink": os.unlink(os.path.join(logs,"one.json")); os.symlink(os.path.join(logs,"two.json"),os.path.join(logs,"one.json"))
if a.mode=="post-closing": open(os.path.join(os.path.dirname(a.mac_root),"lifecycle-mac","020-source-closing.json"),"w").write("{}")
''')
 def tearDown(self):
  for fd in self.supervisor_fds + self.secret_fds: os.close(fd)
  self.tmp.cleanup()
 def command(self, mode="good"):
  return [sys.executable,str(WRAPPER),"--mac-root",str(self.base/'mac'),"--ios-root",str(self.base/'ios'),"--protocol-root",str(self.base/'protocol'),"--expected-mac-commit",self.commits['mac'],"--expected-ios-commit",self.commits['ios'],"--expected-protocol-commit",self.commits['protocol'],"--expected-compatibility-digest","a"*64,"--expected-normative-manifest-digest","b"*64,"--lifecycle-directory",*[str(x.parent) for x in self.records[0::3]],"--seal-manifest",*[str(x) for x in self.records[1::3]],"--live-attestation",*[str(x) for x in self.records[2::3]],"--source-mutex",*[str(x) for x in self.mutexes],"--supervisor-fd",*[str(x) for x in self.supervisor_fds],"--supervisor-close-secret-fd",*[str(x) for x in self.secret_fds],"--evidence-root",str(self.base/'evidence'),"--test-only-inner-command",sys.executable,str(self.inner),"--mode",mode]
 def verify_command(self): return [sys.executable,str(VERIFY),"--evidence-root",str(self.base/"evidence")]
 def verified_evidence(self):
  initial=run(self.command()); self.assertEqual(initial.returncode,0,initial.stderr)
  verified=run(self.verify_command()); self.assertEqual(verified.returncode,0,verified.stderr)
  for ident in ("mac","ios","protocol"):
   for entry in (self.base/("lifecycle-"+ident)).iterdir(): entry.unlink()
   (self.base/("lifecycle-"+ident)).rmdir()
  self.assertEqual(run(self.verify_command()).returncode,0)
 def test_sealed_receipt_tampering_is_rejected(self):
  self.verified_evidence(); (self.base/"evidence/receipts/compatibility-report.json").write_bytes(b"tampered")
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0); self.assertIn("record hash mismatch",result.stderr)
 def test_sealed_lifecycle_record_replacement_is_rejected(self):
  self.verified_evidence(); path=self.base/"evidence/inputs/lifecycle-allocated-mac.json"; path.unlink(); path.write_bytes(b"{}")
  self.assertNotEqual(run(self.verify_command()).returncode,0)
 def test_sealed_evidence_symlink_is_rejected(self):
  self.verified_evidence(); path=self.base/"evidence/inputs/lifecycle-allocated-mac.json"; original=self.base/"replacement"; original.write_bytes(path.read_bytes()); path.unlink(); path.symlink_to(original)
  self.assertNotEqual(run(self.verify_command()).returncode,0)
 def test_missing_sealed_receipt_is_rejected(self):
  self.verified_evidence(); (self.base/"evidence/receipts/compatibility-report-fresh.json").unlink()
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0); self.assertIn("record is unavailable",result.stderr)
 def test_test_only_override_cannot_emit_verifiable_production_evidence(self):
  self.assertEqual(run(self.command()).returncode,0)
  report=self.base/"evidence/sealed-matrix.json"; value=json.loads(report.read_text()); value["kind"]="photonport.sealed-cross-repo-matrix.v1"; report.write_text(json.dumps(value))
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0); self.assertIn("invalid provenance",result.stderr)
 def test_relabel_recompute_cannot_produce_trusted_verdict(self):
  self.assertEqual(run(self.command()).returncode,0)
  report=self.base/"evidence/sealed-matrix.json"; value=json.loads(report.read_text()); value.update(kind="photonport.sealed-cross-repo-matrix.v1",provenance={"mode":"production","runnerPath":"scripts/run-cross-repo-matrix.py","runnerSha256":"a"*64},containment={**value["containment"],"mode":"source-read-only","result":"enforced","allowedWritePaths":[str(self.base/"sandbox"),str(self.base/"evidence"/"inner-matrix.json"),str(self.base/"evidence"/"receipts"),str(self.base/"evidence"/"logs")]}); raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode(); report.write_bytes(raw)
  binding=self.base/"evidence/matrix-binding.json"; b=json.loads(binding.read_text()); b.update(reportSha256=digest(raw),reportSize=len(raw),containmentSha256=digest(json.dumps(value["containment"],sort_keys=True,separators=(",",":")).encode())); binding.write_text(json.dumps(b,sort_keys=True,separators=(",",":"))+"\n")
  result=run([*self.verify_command(),"--require-production-trust"]); self.assertNotEqual(result.returncode,0); self.assertIn("containment allowed write paths",result.stderr)
 def test_authenticated_manifest_tampering_is_rejected(self):
  self.verified_evidence(); report=self.base/"evidence/sealed-matrix.json"; value=json.loads(report.read_text()); value["records"][0]["sha256"]="0"*64; report.write_text(json.dumps(value))
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0); self.assertIn("matrix binding does not bind exact report bytes",result.stderr)
 def test_authenticated_mutex_binding_tampering_is_rejected(self):
  self.verified_evidence(); report=self.base/"evidence/sealed-matrix.json"; value=json.loads(report.read_text()); value["mutexBindings"][0]["supervisor"]="tampered"; report.write_text(json.dumps(value))
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0)
 def test_authenticated_log_manifest_tampering_is_rejected(self):
  self.verified_evidence(); report=self.base/"evidence/sealed-matrix.json"; value=json.loads(report.read_text()); value["logs"][0]["sha256"]="0"*64; report.write_text(json.dumps(value))
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0)
 def test_containment_artifact_tampering_is_rejected(self):
  self.verified_evidence(); artifact=self.base/"evidence/containment/seatbelt.sb"; artifact.write_bytes(b"tampered")
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0); self.assertIn("containment artifact hash mismatch",result.stderr)
 def test_containment_transcript_tampering_is_rejected(self):
  self.verified_evidence(); artifact=self.base/"evidence/containment/process-transcript.log"; artifact.write_bytes(b"{}\\n")
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0); self.assertIn("containment artifact hash mismatch",result.stderr)
 def test_profile_grant_parser_rejects_broad_omitted_extra_reordered_and_duplicate_grants(self):
  root=self.base/"sealed"; sandbox=root/"sandboxes"/("TX-"+"a"*64); allowed=[str(sandbox),str(root/"inner-matrix.json"),str(root/"receipts"),str(root/"logs")]
  containment={"mode":"source-read-only","allowedWritePaths":allowed}
  allowed.extend([str(root/"compatibility-report.json"),str(root/"compatibility-report-fresh.json")])
  containment={"mode":"source-read-only","allowedWritePaths":allowed}
  lines=["(version 1)","(deny default)","(allow process*)","(allow file-read*)",f'(allow file-write* (subpath "{allowed[0]}"))',f'(allow file-write* (literal "{allowed[1]}"))',f'(allow file-write* (subpath "{allowed[2]}"))',f'(allow file-write* (subpath "{allowed[3]}"))',f'(allow file-write* (literal "{allowed[4]}"))',f'(allow file-write* (literal "{allowed[5]}"))']
  VERIFIER.validate_containment_profile(("\n".join(lines)+"\n").encode(),containment,root)
  variants=[lines[:4]+[f'(allow file-write* (subpath "{root}"))'],lines[:4]+lines[4:7],lines+['(allow file-write* (subpath "/tmp"))'],lines[:4]+[lines[5],lines[4],lines[6],lines[7]],lines+[lines[7]]]
  for variant in variants:
   with self.assertRaises(SystemExit): VERIFIER.validate_containment_profile(("\n".join(variant)+"\n").encode(),containment,root)
  for paths in (allowed[:3],allowed+["/tmp"],[allowed[0],allowed[2],allowed[1],allowed[3]],allowed+[allowed[3]]):
   with self.assertRaises(SystemExit): VERIFIER.validate_containment_profile(("\n".join(lines)+"\n").encode(),{"mode":"source-read-only","allowedWritePaths":paths},root)
 def test_inventory_descriptor_traversal_rejects_symlink_and_hardlink_races(self):
  roots={"mac":self.base/"mac","ios":self.base/"ios","protocol":self.base/"protocol"}; handles=PRODUCER.open_source_roots(roots)
  try:
   PRODUCER.source_manifest(handles)
   target=roots["mac"]/"file"; (roots["mac"]/"escape").symlink_to(target)
   with self.assertRaises(SystemExit): PRODUCER.source_manifest(handles)
   (roots["mac"]/"escape").unlink(); os.link(target,roots["mac"]/"hardlink")
   with self.assertRaises(SystemExit): PRODUCER.source_manifest(handles)
  finally:
   for fd,_ in handles.values(): os.close(fd)
 def test_production_profile_has_exact_compatibility_output_grants(self):
  evidence=self.base/"profile-evidence"; evidence.mkdir(); roots={"mac":self.base/"mac","ios":self.base/"ios","protocol":self.base/"protocol"}
  sandbox,profile,raw,env,grants=PRODUCER.seatbelt_profile(evidence,roots,["runner"])
  self.assertEqual(grants[4:],[str(evidence/"compatibility-report.json"),str(evidence/"compatibility-report-fresh.json")])
  VERIFIER.validate_containment_profile(raw,{"mode":"source-read-only","allowedWritePaths":grants},evidence)
 def test_rebound_inner_semantic_tampering_is_rejected(self):
  self.verified_evidence(); inner=self.base/"evidence/inner-matrix.json"; value=json.loads(inner.read_text()); value["processProtocol"]["directions"]=[]
  inner_raw=json.dumps(value,sort_keys=True,separators=(",",":")).encode(); inner.write_bytes(inner_raw)
  report=self.base/"evidence/sealed-matrix.json"; sealed=json.loads(report.read_text()); sealed["innerMatrix"]["sha256"]=digest(inner_raw)
  report_raw=(json.dumps(sealed,sort_keys=True,separators=(",",":"))+"\n").encode(); report.write_bytes(report_raw)
  binding=self.base/"evidence/matrix-binding.json"; bound=json.loads(binding.read_text()); bound.update(reportSha256=digest(report_raw),reportSize=len(report_raw),innerMatrixSha256=digest(inner_raw)); binding.write_text(json.dumps(bound,sort_keys=True,separators=(",",":"))+"\n")
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0); self.assertIn("inner process protocol is invalid",result.stderr)
 def test_lifecycle_tuple_binding_is_exact_three_commit_subset(self):
  self.verified_evidence(); binding=self.base/"evidence/matrix-binding.json"; value=json.loads(binding.read_text())
  subset={"macCommit":self.commits["mac"],"iosCommit":self.commits["ios"],"protocolCommit":self.commits["protocol"]}
  self.assertEqual(value["lifecycleTupleSha256"],digest(json.dumps(subset,sort_keys=True,separators=(",",":")).encode()))
  self.assertNotEqual(value["lifecycleTupleSha256"],value["tupleSha256"])
  value["lifecycleTupleSha256"]="0"*64; binding.write_text(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0); self.assertIn("matrix binding does not bind exact report bytes",result.stderr)
 def test_public_inventory_seal_and_live_contract_is_exact(self):
  seal=self.records[1]; value=json.loads(seal.read_text()); del value["inventorySha256"]; seal.write_text(json.dumps(value))
  result=run(self.command()); self.assertNotEqual(result.returncode,0); self.assertIn("seal-manifest-v1 fields are not exact",result.stderr)
 def test_public_inventory_seal_live_mismatch_is_rejected(self):
  att=self.records[2]; value=json.loads(att.read_text()); value["inventoryEntryCounts"]["cache"]=1; att.write_text(json.dumps(value))
  result=run(self.command()); self.assertNotEqual(result.returncode,0); self.assertIn("inventory entries are not sorted",result.stderr)
 def test_nonempty_category_entries_are_strictly_validated(self):
  seal=json.loads(self.records[1].read_text()); entry=seal["inventoryEntries"]["logical"].pop(0); seal["inventoryEntries"]["generated"].append(entry)
  for category in seal["inventoryEntries"]:
   seal["inventoryEntries"][category].sort(key=lambda item:item["path"]); seal["inventoryEntryCounts"][category]=len(seal["inventoryEntries"][category]); seal["inventorySha256"][category]=digest(json.dumps(seal["inventoryEntries"][category],sort_keys=True,separators=(",",":")).encode())
  seal["fullInventorySha256"]=digest(json.dumps(seal["inventoryEntries"],sort_keys=True,separators=(",",":")).encode()); PRODUCER.public_inventory({key:seal[key] for key in ("inventorySha256","fullInventorySha256","inventoryEntryCounts","inventoryEntries")},"test")
  seal["inventoryEntries"]["cache"].append(dict(entry))
  with self.assertRaises(SystemExit): PRODUCER.public_inventory({key:seal[key] for key in ("inventorySha256","fullInventorySha256","inventoryEntryCounts","inventoryEntries")},"test")
 def test_public_inventory_report_binding_tampering_is_rejected(self):
  self.verified_evidence(); report=self.base/"evidence/sealed-matrix.json"; value=json.loads(report.read_text()); value["publicInventories"]["mac"]["fullInventorySha256"]="0"*64; report.write_text(json.dumps(value))
  result=run(self.verify_command()); self.assertNotEqual(result.returncode,0); self.assertIn("matrix binding does not bind exact report bytes",result.stderr)
 def test_rejects_post_seal_tracked_source_mutation_at_admission(self):
  (self.base/"mac"/"file").write_text("post-seal")
  result=run(self.command()); self.assertNotEqual(result.returncode,0); self.assertIn("not the exact clean tuple",result.stderr)
 def test_rejects_post_seal_ignored_generated_mutation_at_admission(self):
  (self.base/"mac"/"ignored-generated").write_text("post-seal")
  result=run(self.command()); self.assertNotEqual(result.returncode,0); self.assertIn("not the exact clean tuple",result.stderr)
 def test_rejects_malformed_inner_result(self): self.assertNotEqual(run(self.command("malformed")).returncode,0)
 def test_rejects_source_mutation_after_execution(self): self.assertNotEqual(run(self.command("mutate")).returncode,0)
 def test_rejects_mutate_restore_without_mutex_access(self): self.assertNotEqual(run(self.command("mutate-restore")).returncode,0)
 def test_rejects_ignored_generated_source_mutation(self): self.assertNotEqual(run(self.command("ignored")).returncode,0)
 def test_rejects_untracked_source_mutation(self): self.assertNotEqual(run(self.command("untracked")).returncode,0)
 def test_rejects_git_metadata_mutation(self): self.assertNotEqual(run(self.command("git-mutation")).returncode,0)
 def test_rejects_lifecycle_closing_barrier_added_during_execution(self): self.assertNotEqual(run(self.command("post-closing")).returncode,0)
 def test_rejects_evidence_output_inside_source_root(self):
  command=self.command(); command[command.index("--evidence-root")+1]=str(self.base/"mac"/"evidence")
  self.assertNotEqual(run(command).returncode,0)
 def test_rejects_placeholder_inner_evidence(self): self.assertNotEqual(run(self.command("placeholder")).returncode,0)
 def test_rejects_inner_symlink_escape(self): self.assertNotEqual(run(self.command("symlink")).returncode,0)
 def test_rejects_inner_output_symlink_replacement(self): self.assertNotEqual(run(self.command("inner-symlink")).returncode,0)
 def test_rejects_receipt_symlink_replacement(self): self.assertNotEqual(run(self.command("receipt-symlink")).returncode,0)
 def test_rejects_log_symlink_replacement(self): self.assertNotEqual(run(self.command("log-symlink")).returncode,0)
 def test_rejects_fake_mutex_substitute(self):
  fake=self.base/"fake-mutex"; fake.write_bytes(self.mutexes[0].read_bytes()); command=self.command(); command[command.index("--source-mutex")+1]=str(fake)
  result=run(command); self.assertNotEqual(result.returncode,0); self.assertIn("authority-bound canonical Lock-B path",result.stderr); self.assertNotIn("Traceback",result.stderr)
 def test_rejects_missing_seal_key_fail_closed(self):
  seal=self.records[1]; value=json.loads(seal.read_text()); del value["sourceActiveSha256"]; seal.write_text(json.dumps(value))
  result=run(self.command()); self.assertNotEqual(result.returncode,0); self.assertIn("seal-manifest-v1 fields are not exact",result.stderr); self.assertNotIn("Traceback",result.stderr)
if __name__=='__main__': unittest.main()
