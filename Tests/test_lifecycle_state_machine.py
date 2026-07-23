#!/usr/bin/env python3
"""Adversarial lifecycle wrapper tests; every fixture is an isolated temporary repo."""
import ast, fcntl, hashlib, hmac, importlib.util, json, os, signal, subprocess, sys, tempfile, time, types, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; E=ROOT/'scripts/evidence'
COMMITS={'macCommit':'a'*40,'iosCommit':'b'*40,'protocolCommit':'c'*40}
STATE_FILES={'allocated':'000-allocated.json','source-active':'010-source-active.json','source-closing':'020-source-closing.json','source-released':'030-source-released.json','disposing':'040-dispose-claim.json','disposed':'050-disposed.json'}
def run(script,*args,pass_fds=()):
 if script=='transition-lifecycle-state.py' and '--transition' in args:
  transition=Path(args[args.index('--transition')+1]); value=json.loads(transition.read_text())
  if value.get('toState')=='allocated':
   directory=Path(args[args.index('--directory')+1]); spec=importlib.util.spec_from_file_location('lifecycle_transition',E/script);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
   try: result=module.transition_authorized(directory=directory,transition=transition,expected_state='allocated',_capability=module._WRAPPER_CAPABILITY);return types.SimpleNamespace(returncode=0,stdout=json.dumps(result),stderr='')
   except Exception as exc: return types.SimpleNamespace(returncode=2,stdout='',stderr=str(exc))
 return subprocess.run([sys.executable,str(E/script),*map(str,args)],text=True,capture_output=True,pass_fds=pass_fds)
def dump(path,value): path.write_text(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
class LifecycleWrappers(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name);self.root=self.base/'root';self.root.mkdir();self.d=self.base/'lifecycle';self.d.mkdir();self.destination=Path(os.path.realpath(self.root));self.mutex=self.base/'mutex';self.registry_mutex=self.base/'registry-mutex';self.close_secret_path=self.base/'close-secret';self.close_secret_path.write_bytes(b's'*32);self.close_secret_fd=os.open(self.close_secret_path,os.O_RDONLY);self.release_command=self.base/'unlink-and-close-command.json';self.cleanup_path=self.base/'cleanup.json';self.allocation_record_path=self.base/'allocation-record.json';allocation_record={'schemaVersion':1,'kind':'allocation-record.v1','id':'alloc1','destination':str(self.destination)};dump(self.allocation_record_path,allocation_record);allocation={'id':'alloc1','sha256':hashlib.sha256(self.allocation_record_path.read_bytes()).hexdigest()};self.cleanup={'schemaVersion':1,'kind':'photonport.disposable-worktree-cleanup.v1','lifecycleId':'tx1','rootId':'mac','allocation':allocation,'destination':str(self.destination),'rootDev':self.root.stat().st_dev,'rootIno':self.root.stat().st_ino,'generatedOutputsAbsent':True};dump(self.cleanup_path,self.cleanup);self.authority={'approvedSequence':['allocated','source-active','source-closing','source-released','disposing','disposed'],'root':{'canonicalPath':str(self.destination),'dev':self.root.stat().st_dev,'ino':self.root.stat().st_ino},'supervisor':'test-supervisor','command':str((E/'dispose-disposable-worktree.py').resolve()),'allocationNonce':'1'*64,'mutexNonce':'2'*64,'lockAPath':str(Path(os.path.realpath(self.registry_mutex))),'lockBPath':str(Path(os.path.realpath(self.mutex))),'registryPath':str(Path(os.path.realpath(self.registry_mutex.parent))),'commonGitDir':str(Path(os.path.realpath(self.base)))};dump(self.release_command,{'schemaVersion':1,'kind':'photonport.unlink-and-close-command.v1','authoritySha256':hashlib.sha256(json.dumps(self.authority,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'operation':'unlink-and-close','mutexPath':self.authority['lockBPath'],'argv':['unlink',self.authority['lockBPath']]});self.alloc={'schemaVersion':1,'kind':'photonport.lifecycle-transition.v1','lifecycleId':'tx1','rootId':'mac','tuple':COMMITS,'allocation':allocation,'authority':self.authority,'fromState':None,'toState':'allocated','predecessorSha256':None};self.t=self.base/'transition.json';dump(self.t,self.alloc);self.assertEqual(run('transition-lifecycle-state.py','--directory',self.d,'--transition',self.t).returncode,0)
  a=self.d/'000-allocated.json';self.release=self.base/'allocation-released.json';dump(self.release,{'lifecycleId':'tx1','rootId':'mac','allocation':self.alloc['allocation'],'allocationNonce':self.authority['allocationNonce'],'allocatedSha256':hashlib.sha256(a.read_bytes()).hexdigest()})
 def tearDown(self):
  if getattr(self,'supervisor_fd',None) is not None: os.close(self.supervisor_fd)
  if getattr(self,'supervisor_process',None) is not None and self.supervisor_process.poll() is None: self.supervisor_process.terminate();self.supervisor_process.wait()
  os.close(self.close_secret_fd)
  self.tmp.cleanup()
 def acquire(self):
  if getattr(self,'supervisor_fd',None) is None:
   self.supervisor_fd=os.open(self.mutex,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
   fcntl.flock(self.supervisor_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  return run('acquire-source-root-mutex.py','--directory',self.d,'--allocation-released',self.release,'--mutex',self.mutex,'--root',self.root,'--supervisor-fd',self.supervisor_fd,'--supervisor-close-secret-fd',self.close_secret_fd,pass_fds=(self.supervisor_fd,self.close_secret_fd))
 def close_ack(self):
  context=self.d/'source-release-context.json';closing=self.d/'020-source-closing.json';body={'schemaVersion':1,'kind':'photonport.supervisor-close-ack.v1','contextSha256':hashlib.sha256(context.read_bytes()).hexdigest(),'closingSha256':hashlib.sha256(closing.read_bytes()).hexdigest(),'authoritySha256':hashlib.sha256(json.dumps(self.authority,sort_keys=True,separators=(',',':')).encode()).hexdigest()};body['tag']=hmac.new(b's'*32,json.dumps(body,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest();ack=self.base/'close-ack.json';dump(ack,body);return ack
 def release_mutex(self):
  self.supervisor_process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])
  result=run('release-source-root-mutex.py','--directory',self.d,'--mutex',self.mutex,'--root',self.root,'--supervisor-fd',self.supervisor_fd,'--supervisor-close-secret-fd',self.close_secret_fd,'--unlink-and-close-command',self.release_command,'--prepare-close',pass_fds=(self.supervisor_fd,self.close_secret_fd))
  if result.returncode: return result
  os.close(self.supervisor_fd);self.supervisor_fd=None;self.supervisor_process.terminate();self.supervisor_process.wait();ack=self.close_ack()
  return run('release-source-root-mutex.py','--directory',self.d,'--mutex',self.mutex,'--root',self.root,'--supervisor-close-ack',ack,'--supervisor-close-secret-fd',self.close_secret_fd,'--unlink-and-close-command',self.release_command,'--finalize',pass_fds=(self.close_secret_fd,))
 def advance(self,from_state,to_state):
  if from_state=='allocated' and to_state=='source-active':
   self.assertEqual(self.acquire().returncode,0)
   return
  predecessor=self.d/STATE_FILES[from_state]
  proof=lambda key:hashlib.sha256(key.encode()).hexdigest()
  proofs={'source-active':{'allocationReleaseSha256':proof('allocation-release')},'source-closing':{'cleanupSha256':proof('cleanup'),'postConsumerSha256':proof('consumer'),'matrixBindingSha256':proof('matrix'),'b1PreflightSha256':proof('b1')},'source-released':{'closingSha256':hashlib.sha256(predecessor.read_bytes()).hexdigest(),'releasedByUnlinkAndClose':True,'releaseCommandSha256':hashlib.sha256(self.release_command.read_bytes()).hexdigest()}}
  extra=[];closing_proofs={}
  authority_sha=hashlib.sha256(json.dumps(self.authority,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  tuple_sha=hashlib.sha256(json.dumps(self.alloc['tuple'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
  if to_state=='source-closing':
   for key in proofs[to_state]:
    path=self.base/(key+'.json')
    detail={'cleanupSha256':'cleanupRecordSha256','postConsumerSha256':'consumerManifestSha256','matrixBindingSha256':'matrixReportSha256','b1PreflightSha256':'preflightManifestSha256'}[key]
    kind={'cleanupSha256':'photonport.lifecycle-cleanup-proof.v1','postConsumerSha256':'photonport.lifecycle-post-consumer-proof.v1','matrixBindingSha256':'photonport.lifecycle-matrix-binding-proof.v1','b1PreflightSha256':'photonport.lifecycle-b1-preflight-proof.v1'}[key]
    artifact_kind={'cleanupSha256':'photonport.disposable-worktree-cleanup.v1','postConsumerSha256':'photonport.post-consumer-inventory.v1','matrixBindingSha256':'photonport.matrix-binding.v1','b1PreflightSha256':'photonport.b1-preflight.v1'}[key]
    artifact=self.cleanup_path if key=='cleanupSha256' else self.base/(key+'.artifact.json')
    fields={'kind':artifact_kind,'lifecycleId':'tx1','rootId':'mac','tupleSha256':tuple_sha}
    if key=='cleanupSha256': fields['generatedOutputsAbsent']=True
    if key=='postConsumerSha256': fields.update(beforeInventorySha256=proof('inventory'),afterInventorySha256=proof('inventory'))
    if key=='matrixBindingSha256': fields={'kind':artifact_kind,'tupleSha256':proof('full-matrix-tuple'),'lifecycleTupleSha256':tuple_sha,'reportSha256':proof('report'),'allocatedSha256ByRoot':{'mac':proof('allocated')},'sourceActiveSha256ByRoot':{'mac':proof('active')},'sealSha256ByRoot':{'mac':proof('seal')},'mutexSha256ByRoot':{'mac':proof('mutex')}}
    if key=='b1PreflightSha256': fields['readiness']='ready'
    if key!='cleanupSha256': dump(artifact,fields)
    envelope={'schemaVersion':1,'kind':kind,'lifecycleId':'tx1','rootId':'mac','authoritySha256':authority_sha,'tupleSha256':tuple_sha,'predecessorSha256':hashlib.sha256(predecessor.read_bytes()).hexdigest(),detail:hashlib.sha256(artifact.read_bytes()).hexdigest(),'artifactPath':str(artifact)}
    if key=='matrixBindingSha256': envelope.update(allocatedSha256=proof('allocated'),sourceActiveSha256=proof('active'),sealSha256=proof('seal'),mutexSha256=proof('mutex'))
    dump(path,envelope)
    closing_proofs[key]=hashlib.sha256(artifact.read_bytes()).hexdigest() if key=='cleanupSha256' else hashlib.sha256(path.read_bytes()).hexdigest()
    extra.extend(['--proof',key+'='+str(path)])
  dump(self.t,dict(self.alloc,fromState=from_state,toState=to_state,predecessorSha256=hashlib.sha256(predecessor.read_bytes()).hexdigest(),**(closing_proofs if closing_proofs else proofs.get(to_state,{}))))
  if to_state=='source-closing':
   spec=importlib.util.spec_from_file_location('lifecycle_transition',E/'transition-lifecycle-state.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);self.assertIsInstance(module.transition_authorized(directory=self.d,transition=self.t,expected_state=to_state,proofs=[extra[i+1] for i in range(0,len(extra),2)],_capability=module._WRAPPER_CAPABILITY),dict)
  else: self.assertEqual(run('transition-lifecycle-state.py','--directory',self.d,'--transition',self.t).returncode,0)
 def released_lifecycle(self):
  self.advance('allocated','source-active');self.advance('source-active','source-closing');self.assertEqual(self.release_mutex().returncode,0)
 def fake_git(self,post_list_error=False):
  marker=self.base/'removed';script=self.base/'git';script.write_text('#!'+sys.executable+'\nimport os,sys\nmarker='+repr(str(marker))+'\ndestination='+repr(str(self.destination))+'\nif sys.argv[1:]==[\"rev-parse\",\"--path-format=absolute\",\"--git-common-dir\"]:\n print('+repr(str(self.base))+');sys.exit(0)\nif \"worktree\" in sys.argv and \"list\" in sys.argv:\n if os.path.exists(marker):\n  '+('sys.exit(1)' if post_list_error else 'sys.exit(0)')+'\n print(\"worktree \"+destination)\n sys.exit(0)\nif \"worktree\" in sys.argv and \"remove\" in sys.argv:\n open(marker,\"w\").close();os.rmdir(destination);sys.exit(0)\nsys.exit(1)\n');os.chmod(script,0o700);return script
 def dispose(self,git):
  return run('dispose-disposable-worktree.py','--directory',self.d,'--mutex',self.mutex,'--registry-mutex',self.registry_mutex,'--root',self.root,'--destination',self.destination,'--cleanup',self.cleanup_path,'--allocation-record',self.allocation_record_path,'--git',git)
 def test_duplicate_acquisition_loses_without_mutating_source(self):
  self.assertEqual(self.acquire().returncode,0); self.assertNotEqual(self.acquire().returncode,0);self.assertEqual((self.d/'010-source-active.json').exists(),True)
 def test_durability_barriers_precede_lifecycle_claims(self):
  acquire=(E/'acquire-source-root-mutex.py').read_text()
  release=(E/'release-source-root-mutex.py').read_text()
  dispose=(E/'dispose-disposable-worktree.py').read_text()
  def function_calls(source,name):
   tree=ast.parse(source)
   function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==name)
   return [node for node in ast.walk(function) if isinstance(node,ast.Call)]
  def call_line(calls,name,*constants):
   for node in calls:
    callee=node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else None
    if callee==name and all(any(isinstance(argument,ast.Constant) and argument.value==constant for argument in node.args) for constant in constants):
     return node.lineno
   self.fail(f'missing {name} call with constants {constants}')
  acquire_calls=function_calls(acquire,'main')
  release_calls=function_calls(release,'main')
  write_calls=function_calls(dispose,'write_disposal_context')
  dispose_calls=function_calls(dispose,'main')
  self.assertLess(call_line(acquire_calls,'fsync_parent'),call_line(acquire_calls,'transition','source-active'))
  self.assertLess(release.index('write_context(dfd'),release.index('os.unlink(mutex.name, dir_fd=parent_fd)'))
  self.assertIn('supervisor capability remains open',release)
  self.assertIn('--prepare-close',release)
  self.assertIn('--finalize',release)
  self.assertLess(call_line(write_calls,'fsync'),call_line(write_calls,'fsync_parent'))
  self.assertLess(call_line(dispose_calls,'write_disposal_context'),call_line(dispose_calls,'state','disposing'))
  def assert_unlink_is_parent_fsynced(source,variable,expected):
   unlinks=0
   for parent in ast.walk(ast.parse(source)):
    for body in (getattr(parent,'body',None),getattr(parent,'orelse',None),getattr(parent,'finalbody',None)):
     if not isinstance(body,list): continue
     for index,statement in enumerate(body[:-1]):
      call=statement.value if isinstance(statement,ast.Expr) and isinstance(statement.value,ast.Call) else None
      if not (isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name) and call.func.value.id=='os' and call.func.attr=='unlink' and len(call.args)==1 and ast.unparse(call.args[0])==variable): continue
      unlinks+=1
      following=body[index+1].value if isinstance(body[index+1],ast.Expr) and isinstance(body[index+1].value,ast.Call) else None
      self.assertIsNotNone(following)
      self.assertIsInstance(following.func,ast.Name)
      self.assertEqual(following.func.id,'fsync_parent')
      self.assertEqual(len(following.args),1)
      self.assertEqual(ast.unparse(following.args[0]),variable)
   self.assertEqual(unlinks,expected)
  assert_unlink_is_parent_fsynced(acquire,'args.mutex',0)
  assert_unlink_is_parent_fsynced(dispose,'context_path',0)
  core=(E/'transition-lifecycle-state.py').read_text()
  self.assertIn('name=STATE_FILES[target]; fd=os.open(name,',core)
  self.assertIn('dir_fd=dfd',core)
 def test_replayed_release_evidence_is_rejected_before_mutex_namespace_access(self):
  x=json.loads(self.release.read_text());x['allocatedSha256']='0'*64;dump(self.release,x)
  fd=os.open(os.devnull,os.O_RDONLY)
  try:
   self.assertNotEqual(run('acquire-source-root-mutex.py','--directory',self.d,'--allocation-released',self.release,'--mutex',self.mutex,'--root',self.root,'--supervisor-fd',fd,'--supervisor-close-secret-fd',self.close_secret_fd,pass_fds=(fd,self.close_secret_fd)).returncode,0)
  finally: os.close(fd)
  self.assertFalse(self.mutex.exists())
 def test_release_cannot_skip_closing_barrier(self):
  self.assertEqual(self.acquire().returncode,0);self.assertNotEqual(self.release_mutex().returncode,0);self.assertTrue(self.mutex.exists())
 def test_closing_permanently_blocks_contender_without_mutex_create_or_unlink(self):
  self.advance('allocated','source-active');self.advance('source-active','source-closing')
  fd=os.open(os.devnull,os.O_RDONLY)
  try:
   self.assertNotEqual(run('acquire-source-root-mutex.py','--directory',self.d,'--allocation-released',self.release,'--mutex',self.mutex,'--root',self.root,'--supervisor-fd',fd,'--supervisor-close-secret-fd',self.close_secret_fd,pass_fds=(fd,self.close_secret_fd)).returncode,0)
  finally: os.close(fd)
  self.assertTrue(self.mutex.exists())
 def test_release_recovers_only_from_matching_durable_context(self):
  self.assertEqual(self.acquire().returncode,0);self.advance('source-active','source-closing')
  self.supervisor_process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])
  closing=self.d/'020-source-closing.json';closing_sha256=hashlib.sha256(closing.read_bytes()).hexdigest();command_sha256=hashlib.sha256(self.release_command.read_bytes()).hexdigest();transition={'schemaVersion':1,'kind':'photonport.lifecycle-transition.v1','lifecycleId':'tx1','rootId':'mac','tuple':COMMITS,'allocation':self.alloc['allocation'],'authority':self.authority,'fromState':'source-closing','toState':'source-released','predecessorSha256':closing_sha256,'closingSha256':closing_sha256,'releasedByUnlinkAndClose':True,'releaseCommandSha256':command_sha256};held=os.fstat(self.supervisor_fd);context={'schemaVersion':1,'kind':'photonport.source-release-context.v1','closingSha256':closing_sha256,'transition':transition,'authority':self.authority,'mutexPath':self.authority['lockBPath'],'mutexDev':held.st_dev,'mutexIno':held.st_ino,'supervisorFdDev':held.st_dev,'supervisorFdIno':held.st_ino,'closeSecretSha256':hashlib.sha256(b's'*32).hexdigest()};dump(self.d/'source-release-context.json',context);os.close(self.supervisor_fd);self.supervisor_fd=None;self.supervisor_process.terminate();self.supervisor_process.wait();self.mutex.unlink()
  self.assertNotEqual(run('release-source-root-mutex.py','--directory',self.d,'--mutex',self.mutex,'--root',self.root,'--supervisor-close-ack',self.close_ack(),'--supervisor-close-secret-fd',self.close_secret_fd,'--unlink-and-close-command',self.release_command,'--finalize',pass_fds=(self.close_secret_fd,)).returncode,0);self.assertFalse((self.d/'030-source-released.json').exists());self.assertTrue((self.d/'source-release-context.json').exists())
 def test_supervisor_capability_holds_lock_until_release(self):
  self.assertEqual(self.acquire().returncode,0)
  contender=os.open(self.mutex,os.O_RDWR)
  try:
   with self.assertRaises(BlockingIOError): fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
  finally: os.close(contender)
  self.advance('source-active','source-closing')
  self.assertEqual(self.release_mutex().returncode,0);self.assertFalse(self.mutex.exists())
 def test_finalize_rejects_a_supervisor_that_retains_lock_b(self):
  self.assertEqual(self.acquire().returncode,0);self.advance('source-active','source-closing')
  self.supervisor_process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);prepared=run('release-source-root-mutex.py','--directory',self.d,'--mutex',self.mutex,'--root',self.root,'--supervisor-fd',self.supervisor_fd,'--supervisor-close-secret-fd',self.close_secret_fd,'--unlink-and-close-command',self.release_command,'--prepare-close',pass_fds=(self.supervisor_fd,self.close_secret_fd))
  self.assertEqual(prepared.returncode,0)
  self.supervisor_process.terminate();self.supervisor_process.wait();ack=self.close_ack();self.assertNotEqual(run('release-source-root-mutex.py','--directory',self.d,'--mutex',self.mutex,'--root',self.root,'--supervisor-close-ack',ack,'--supervisor-close-secret-fd',self.close_secret_fd,'--unlink-and-close-command',self.release_command,'--finalize',pass_fds=(self.close_secret_fd,)).returncode,0)
  self.assertFalse((self.d/'030-source-released.json').exists())
 def test_release_prepare_rejects_unrelated_lock_b_holder(self):
  self.assertEqual(self.acquire().returncode,0);self.advance('source-active','source-closing')
  os.close(self.supervisor_fd);self.supervisor_fd=None
  inherited=os.open(self.mutex,os.O_RDWR)
  holder=os.open(self.mutex,os.O_RDWR)
  try:
   fcntl.flock(holder,fcntl.LOCK_EX|fcntl.LOCK_NB)
   self.assertNotEqual(run('release-source-root-mutex.py','--directory',self.d,'--mutex',self.mutex,'--root',self.root,'--supervisor-fd',inherited,'--supervisor-close-secret-fd',self.close_secret_fd,'--prepare-close',pass_fds=(inherited,self.close_secret_fd)).returncode,0)
  finally:
   os.close(inherited);os.close(holder)
 def test_release_refuses_replaced_root(self):
  self.assertEqual(self.acquire().returncode,0);self.advance('source-active','source-closing');old=self.root;old.rename(self.base/'old');self.root.mkdir();self.assertNotEqual(self.release_mutex().returncode,0)
 def test_closing_proof_cross_kind_and_arbitrary_hash_are_rejected(self):
  self.assertEqual(self.acquire().returncode,0);active=self.d/'010-source-active.json';proof=lambda key:hashlib.sha256(key.encode()).hexdigest();record=dict(self.alloc,fromState='source-active',toState='source-closing',predecessorSha256=hashlib.sha256(active.read_bytes()).hexdigest(),cleanupSha256=proof('x'),postConsumerSha256=proof('y'),matrixBindingSha256=proof('z'),b1PreflightSha256=proof('q'));dump(self.t,record);self.assertNotEqual(run('transition-lifecycle-state.py','--directory',self.d,'--transition',self.t).returncode,0)
 def test_lifecycle_schemas_parse_and_share_authority_definition(self):
  state=json.loads((ROOT/'artifacts/schemas/lifecycle-state-v1.schema.json').read_text());transition=json.loads((ROOT/'artifacts/schemas/lifecycle-transition-v1.schema.json').read_text())
  self.assertEqual(state['properties']['authority'],transition['properties']['authority'])
  self.assertIn('authority',transition['required'])
 def test_public_transition_cli_rejects_every_state_mutation(self):
  for state in STATE_FILES:
   record=dict(self.alloc,toState=state,fromState=None,predecessorSha256=None)
   dump(self.t,record)
   result=subprocess.run([sys.executable,str(E/'transition-lifecycle-state.py'),'--directory',str(self.d),'--transition',str(self.t)],text=True,capture_output=True)
   self.assertNotEqual(result.returncode,0,state)
 def test_release_finalize_rejects_replaced_lifecycle_before_unlink(self):
  self.assertEqual(self.acquire().returncode,0);self.advance('source-active','source-closing')
  prepared=run('release-source-root-mutex.py','--directory',self.d,'--mutex',self.mutex,'--root',self.root,'--supervisor-fd',self.supervisor_fd,'--supervisor-close-secret-fd',self.close_secret_fd,'--unlink-and-close-command',self.release_command,'--prepare-close',pass_fds=(self.supervisor_fd,self.close_secret_fd));self.assertEqual(prepared.returncode,0)
  os.close(self.supervisor_fd);self.supervisor_fd=None;ack=self.close_ack();old=self.d;old.rename(self.base/'old-lifecycle');self.d.mkdir()
  result=run('release-source-root-mutex.py','--directory',self.d,'--mutex',self.mutex,'--root',self.root,'--supervisor-close-ack',ack,'--supervisor-close-secret-fd',self.close_secret_fd,'--unlink-and-close-command',self.release_command,'--finalize',pass_fds=(self.close_secret_fd,))
  self.assertNotEqual(result.returncode,0);self.assertTrue(self.mutex.exists());self.assertFalse((old/'030-source-released.json').exists())
 def test_acquire_rejects_alternate_root_and_lock_b(self):
  other=self.base/'other';other.mkdir();fd=os.open(self.mutex,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
  try:
   self.assertNotEqual(run('acquire-source-root-mutex.py','--directory',self.d,'--allocation-released',self.release,'--mutex',self.mutex,'--root',other,'--supervisor-fd',fd,'--supervisor-close-secret-fd',self.close_secret_fd,pass_fds=(fd,self.close_secret_fd)).returncode,0)
  finally: os.close(fd);self.mutex.unlink()
  alternate=self.base/'alternate-mutex';fd=os.open(alternate,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
  try:
   self.assertNotEqual(run('acquire-source-root-mutex.py','--directory',self.d,'--allocation-released',self.release,'--mutex',alternate,'--root',self.root,'--supervisor-fd',fd,'--supervisor-close-secret-fd',self.close_secret_fd,pass_fds=(fd,self.close_secret_fd)).returncode,0)
  finally: os.close(fd);alternate.unlink()
 def test_release_rejects_alternate_mutex_nonce(self):
  self.assertEqual(self.acquire().returncode,0);payload=json.loads(self.mutex.read_text());payload['mutexNonce']='0'*64;dump(self.mutex,payload);self.advance('source-active','source-closing')
  self.assertNotEqual(self.release_mutex().returncode,0);self.assertTrue(self.mutex.exists())
 def test_disposal_requires_cleanup_bound_to_allocation(self):
  self.released_lifecycle();forged=dict(self.cleanup);forged['destination']=str(self.base/'other');dump(self.cleanup_path,forged);self.assertNotEqual(self.dispose(self.fake_git()).returncode,0);self.assertFalse((self.d/'040-dispose-claim.json').exists())
 def test_disposal_records_terminal_state_after_exact_absence(self):
  self.released_lifecycle();self.assertEqual(self.dispose(self.fake_git()).returncode,0);self.assertTrue((self.d/'050-disposed.json').exists());terminal=self.registry_mutex.with_name(self.registry_mutex.name+'.dispose-context.json.terminal');self.assertTrue(terminal.exists());record=json.loads((self.d/'050-disposed.json').read_text());self.assertIn('postWorktreeListSha256',record);self.assertEqual(record['preWorktreeListSha256'],json.loads((self.d/'040-dispose-claim.json').read_text())['preWorktreeListSha256'])
 def test_disposal_refuses_terminal_state_when_post_removal_query_fails(self):
  self.released_lifecycle();self.assertNotEqual(self.dispose(self.fake_git(post_list_error=True)).returncode,0);self.assertFalse((self.d/'050-disposed.json').exists())
 def test_disposal_crash_after_claim_is_terminal_recovery_uncertain(self):
  self.released_lifecycle();git=self.fake_git();started=self.base/'removal-started';permit=self.base/'removal-permit'
  git.write_text(git.read_text().replace('open(marker,"w").close();os.rmdir(destination);sys.exit(0)','open('+repr(str(started))+',"w").close()\n while not os.path.exists('+repr(str(permit))+'): pass\n open(marker,\"w\").close();os.rmdir(destination);sys.exit(0)'))
  command=[sys.executable,str(E/'dispose-disposable-worktree.py'),'--directory',str(self.d),'--mutex',str(self.mutex),'--registry-mutex',str(self.registry_mutex),'--root',str(self.root),'--destination',str(self.destination),'--cleanup',str(self.cleanup_path),'--allocation-record',str(self.allocation_record_path),'--git',str(git)]
  owner=subprocess.Popen(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  deadline=time.monotonic()+5
  while not started.exists() and time.monotonic()<deadline: time.sleep(.01)
  self.assertTrue(started.exists());os.killpg(owner.pid,signal.SIGKILL);owner.wait(timeout=5)
  self.assertTrue((self.d/'040-dispose-claim.json').exists());self.assertTrue(self.registry_mutex.exists())
  retry=self.dispose(self.fake_git())
  self.assertNotEqual(retry.returncode,0);self.assertIn('DISPOSAL_RECOVERY_UNCERTAIN',retry.stderr)
  self.assertFalse((self.d/'050-disposed.json').exists());self.assertTrue(self.root.exists())
 def test_disposal_lock_a_admits_only_one_concurrent_winner(self):
  self.released_lifecycle();lock=os.open(self.registry_mutex,os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try:
   self.assertNotEqual(self.dispose(self.fake_git()).returncode,0);self.assertFalse((self.d/'040-dispose-claim.json').exists())
  finally: os.close(lock)
  self.assertEqual(self.dispose(self.fake_git()).returncode,0);self.assertTrue((self.d/'050-disposed.json').exists())
 def test_disposal_uses_surviving_common_git_directory_for_linked_worktree(self):
  for state in self.d.glob('*.json'): state.unlink()
  self.root.rmdir()
  main=self.base/'main';main.mkdir()
  for command in (['git','init'],['git','config','user.email','test@example.invalid'],['git','config','user.name','Test'],['git','commit','--allow-empty','-m','initial'],['git','worktree','add','-b','disposable',str(self.root)]):
   subprocess.run(command,cwd=main,check=True,capture_output=True,text=True)
  self.destination=Path(os.path.realpath(self.root))
  self.cleanup.update(destination=str(self.destination),rootDev=self.root.stat().st_dev,rootIno=self.root.stat().st_ino);allocation_record={'schemaVersion':1,'kind':'allocation-record.v1','id':'alloc1','destination':str(self.destination)};dump(self.allocation_record_path,allocation_record);allocation={'id':'alloc1','sha256':hashlib.sha256(self.allocation_record_path.read_bytes()).hexdigest()};self.cleanup['allocation']=allocation;dump(self.cleanup_path,self.cleanup);self.authority.update(root={'canonicalPath':str(self.destination),'dev':self.root.stat().st_dev,'ino':self.root.stat().st_ino},commonGitDir=str(Path(os.path.realpath(main/'.git'))));dump(self.release_command,{'schemaVersion':1,'kind':'photonport.unlink-and-close-command.v1','authoritySha256':hashlib.sha256(json.dumps(self.authority,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'operation':'unlink-and-close','mutexPath':self.authority['lockBPath'],'argv':['unlink',self.authority['lockBPath']]});self.alloc['allocation']=allocation;dump(self.t,self.alloc)
  self.assertEqual(run('transition-lifecycle-state.py','--directory',self.d,'--transition',self.t).returncode,0);dump(self.release,{'lifecycleId':'tx1','rootId':'mac','allocation':allocation,'allocationNonce':self.authority['allocationNonce'],'allocatedSha256':hashlib.sha256((self.d/'000-allocated.json').read_bytes()).hexdigest()})
  self.released_lifecycle()
  self.assertEqual(self.dispose('git').returncode,0)
  listed=subprocess.run(['git','worktree','list','--porcelain'],cwd=main,check=True,capture_output=True,text=True).stdout
  self.assertNotIn('worktree '+str(self.destination),listed)
  self.assertTrue((self.d/'050-disposed.json').exists())
if __name__=='__main__':unittest.main()
