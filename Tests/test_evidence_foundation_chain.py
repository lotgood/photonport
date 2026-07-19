#!/usr/bin/env python3
"""Public, same-fixture lifecycle foundation chain coverage."""
import fcntl, hashlib, hmac, json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; E=ROOT/'scripts/evidence'; COMMITS={'macCommit':'a'*40,'iosCommit':'b'*40,'protocolCommit':'c'*40}
def dump(p,v): p.write_bytes(json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n')
def run(script,*args,pass_fds=()): return subprocess.run([sys.executable,str(E/script),*map(str,args)],text=True,capture_output=True,pass_fds=pass_fds)
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def inventories(root, base, prefix):
 entries=[]
 for path in root.rglob('*'):
  if path.is_file() and not path.is_symlink(): entries.append({'path':str(path.relative_to(root)),'sha256':sha(path)})
 categories=[[],[],[],[]]
 for index,entry in enumerate(entries): categories[index%4].append(entry)
 paths=[]
 for index,name in enumerate(('logical','generated','package','cache')):
  path=base/(prefix+'-'+name);dump(path,{'entries':categories[index]});paths.append(path)
 return paths
class EvidenceFoundationChainTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.base=Path(self.tmp.name);self.root=self.base/'root';self.root.mkdir();self.directory=self.base/'lifecycle';self.directory.mkdir();self.dest=Path(os.path.realpath(self.root));self.mutex=self.base/'mutex';self.locka=self.base/'locka';self.secret=self.base/'secret';self.secret.write_bytes(b'x'*32);self.secretfd=os.open(self.secret,os.O_RDONLY)
  self.authority={'approvedSequence':['allocated','source-active','source-closing','source-released','disposing','disposed'],'root':{'canonicalPath':str(self.dest),'dev':self.root.stat().st_dev,'ino':self.root.stat().st_ino},'supervisor':'test','command':str(E/'dispose-disposable-worktree.py'),'allocationNonce':'1'*64,'mutexNonce':'2'*64,'lockAPath':str(self.locka.resolve()),'lockBPath':str(self.mutex.resolve()),'registryPath':str(self.base.resolve()),'commonGitDir':str(self.base.resolve())}
  dump(self.base/'registration',{'schemaVersion':1,'kind':'allocation-record.v1','id':'alloc1','destination':str(self.dest)});dump(self.base/'tuple',COMMITS);dump(self.base/'root-evidence',{'schemaVersion':1,'kind':'photonport.lifecycle-root.v1',**self.authority['root']});dump(self.base/'authority',self.authority)
 def tearDown(self): os.close(self.secretfd);self.tmp.cleanup()
 def allocate(self): return run('allocate-lifecycle.py','--directory',self.directory,'--registration',self.base/'registration','--tuple',self.base/'tuple','--root',self.base/'root-evidence','--authority',self.base/'authority','--lifecycle-id','tx1','--root-id','mac')
 def test_public_same_fixture_allocate_acquire_and_close(self):
  self.assertEqual(self.allocate().returncode,0)
  allocated=self.directory/'000-allocated.json'; release=self.base/'release';dump(release,{'lifecycleId':'tx1','rootId':'mac','allocation':json.loads(allocated.read_text())['allocation'],'allocationNonce':self.authority['allocationNonce'],'allocatedSha256':sha(allocated)})
  mfd=os.open(self.mutex,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600);fcntl.flock(mfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try: self.assertEqual(run('acquire-source-root-mutex.py','--directory',self.directory,'--allocation-released',release,'--mutex',self.mutex,'--root',self.root,'--supervisor-fd',mfd,'--supervisor-close-secret-fd',self.secretfd,pass_fds=(mfd,self.secretfd)).returncode,0)
  finally: os.close(mfd)
  active=self.directory/'010-source-active.json'; predecessor=sha(active);authority_sha=hashlib.sha256(json.dumps(self.authority,sort_keys=True,separators=(',',':')).encode()).hexdigest();tuple_sha=hashlib.sha256(json.dumps(COMMITS,sort_keys=True,separators=(',',':')).encode()).hexdigest(); paths=[]
  specs=(('cleanupSha256','photonport.lifecycle-cleanup-proof.v1','cleanupRecordSha256','photonport.disposable-worktree-cleanup.v1',{'lifecycleId':'tx1','rootId':'mac','generatedOutputsAbsent':True}),('postConsumerSha256','photonport.lifecycle-post-consumer-proof.v1','consumerManifestSha256','photonport.post-consumer-inventory.v1',{'rootId':'mac','beforeInventorySha256':'a'*64,'afterInventorySha256':'a'*64}),('matrixBindingSha256','photonport.lifecycle-matrix-binding-proof.v1','matrixReportSha256','photonport.matrix-binding.v1',{'reportSha256':'b'*64,'tupleSha256':'c'*64,'lifecycleTupleSha256':tuple_sha,'allocatedSha256ByRoot':{'mac':'c'*64},'sourceActiveSha256ByRoot':{'mac':'d'*64},'sealSha256ByRoot':{'mac':'e'*64},'mutexSha256ByRoot':{'mac':'f'*64}}),('b1PreflightSha256','photonport.lifecycle-b1-preflight-proof.v1','preflightManifestSha256','photonport.b1-preflight.v1',{'lifecycleId':'tx1','readiness':'ready'}))
  for key,kind,detail,artifact_kind,extra in specs:
   artifact=self.base/(key+'-artifact');dump(artifact,{'kind':artifact_kind,'tupleSha256':tuple_sha,**extra}); proof=self.base/(key+'-proof');envelope={'schemaVersion':1,'kind':kind,'lifecycleId':'tx1','rootId':'mac','authoritySha256':authority_sha,'tupleSha256':tuple_sha,'predecessorSha256':predecessor,detail:sha(artifact),'artifactPath':str(artifact)}
   if key=='matrixBindingSha256': envelope.update(allocatedSha256='c'*64,sourceActiveSha256='d'*64,sealSha256='e'*64,mutexSha256='f'*64)
   dump(proof,envelope);paths.append(proof)
  dfd=os.open(self.directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
  try: result=run('close-source-lifecycle.py','--directory-fd',dfd,'--source-active',active,'--cleanup-proof',paths[0],'--post-consumer-proof',paths[1],'--matrix-binding-proof',paths[2],'--b1-preflight-proof',paths[3],pass_fds=(dfd,))
  finally: os.close(dfd)
  self.assertEqual(result.returncode,0,result.stderr);self.assertTrue((self.directory/'020-source-closing.json').exists())
 def test_public_seal_producer_uses_live_capabilities(self):
  self.assertEqual(self.allocate().returncode,0)
  allocated=self.directory/'000-allocated.json'; release=self.base/'release';dump(release,{'lifecycleId':'tx1','rootId':'mac','allocation':json.loads(allocated.read_text())['allocation'],'allocationNonce':self.authority['allocationNonce'],'allocatedSha256':sha(allocated)})
  mfd=os.open(self.mutex,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600);fcntl.flock(mfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try:
   self.assertEqual(run('acquire-source-root-mutex.py','--directory',self.directory,'--allocation-released',release,'--mutex',self.mutex,'--root',self.root,'--supervisor-fd',mfd,'--supervisor-close-secret-fd',self.secretfd,pass_fds=(mfd,self.secretfd)).returncode,0)
   inventories=[]
   for name in ('logical','generated','package','cache'):
    path=self.base/(name+'-inventory');dump(path,{'entries':[]});inventories.append(path)
   dfd=os.open(self.directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));rfd=os.open(self.root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
   try:
    result=run('seal-source-root.py','--directory-fd',dfd,'--source-active',self.directory/'010-source-active.json','--root-fd',rfd,'--mutex',self.mutex,'--supervisor-fd',mfd,'--id','mac','--commit',COMMITS['macCommit'],'--logical-inventory',inventories[0],'--generated-inventory',inventories[1],'--package-inventory',inventories[2],'--cache-inventory',inventories[3],'--seal-manifest',self.base/'seal','--live-attestation',self.base/'live',pass_fds=(dfd,rfd,mfd))
   finally: os.close(dfd);os.close(rfd)
   self.assertEqual(result.returncode,0,result.stderr)
   seal=json.loads((self.base/'seal').read_text());live=json.loads((self.base/'live').read_text())
   self.assertEqual(seal['kind'],'seal-manifest-v1');self.assertEqual(live['sealManifestSha256'],sha(self.base/'seal'))
  finally: os.close(mfd)
 def test_public_three_root_sealed_matrix_and_source_free_verification(self):
  roots={}; dirs={}; mutexes={}; secrets={}; mfds=[]; sfds=[]; seals=[]; lives=[]; tuple_={'compatibilityDigest':'d'*64,'normativeManifestDigest':'e'*64}
  try:
   for ident in ('mac','ios','protocol'):
    root=self.base/ident;root.mkdir();subprocess.run(['git','init','-q',root],check=True);subprocess.run(['git','-C',root,'config','user.email','test@example.invalid'],check=True);subprocess.run(['git','-C',root,'config','user.name','test'],check=True);(root/'source.txt').write_text(ident);subprocess.run(['git','-C',root,'add','.'],check=True);subprocess.run(['git','-C',root,'commit','-qm','fixture'],check=True)
    tuple_[ident+'Commit']=subprocess.run(['git','-C',root,'rev-parse','HEAD'],text=True,capture_output=True,check=True).stdout.strip();roots[ident]=root
   for ident in ('mac','ios','protocol'):
    root=roots[ident];commit=tuple_[ident+'Commit'];dirs[ident]=self.base/(ident+'-lifecycle');dirs[ident].mkdir();mutexes[ident]=self.base/(ident+'-mutex');secrets[ident]=self.base/(ident+'-secret');secrets[ident].write_bytes((ident*32).encode()[:32]);sfd=os.open(secrets[ident],os.O_RDONLY);sfds.append(sfd)
    authority={'approvedSequence':['allocated','source-active','source-closing','source-released','disposing','disposed'],'root':{'canonicalPath':str(root.resolve()),'dev':root.stat().st_dev,'ino':root.stat().st_ino},'supervisor':'test','command':str(E/'dispose-disposable-worktree.py'),'allocationNonce':str(('mac','ios','protocol').index(ident)+1)*64,'mutexNonce':str(('mac','ios','protocol').index(ident)+4)*64,'lockAPath':str((self.base/(ident+'-locka')).resolve()),'lockBPath':str(mutexes[ident].resolve()),'registryPath':str(self.base.resolve()),'commonGitDir':str((root/'.git').resolve())}
    for name,value in (('registration',{'schemaVersion':1,'kind':'allocation-record.v1','id':'alloc-'+ident,'destination':str(root.resolve())}),('tuple',{k:tuple_[k] for k in ('macCommit','iosCommit','protocolCommit')}),('root',{'schemaVersion':1,'kind':'photonport.lifecycle-root.v1',**authority['root']}),('authority',authority)): dump(self.base/(ident+'-'+name),value)
    result=run('allocate-lifecycle.py','--directory',dirs[ident],'--registration',self.base/(ident+'-registration'),'--tuple',self.base/(ident+'-tuple'),'--root',self.base/(ident+'-root'),'--authority',self.base/(ident+'-authority'),'--lifecycle-id','tx-'+ident,'--root-id',ident);self.assertEqual(result.returncode,0,result.stderr)
    allocated=dirs[ident]/'000-allocated.json'; release=self.base/(ident+'-release');dump(release,{'lifecycleId':'tx-'+ident,'rootId':ident,'allocation':json.loads(allocated.read_text())['allocation'],'allocationNonce':authority['allocationNonce'],'allocatedSha256':sha(allocated)})
    mfd=os.open(mutexes[ident],os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600);fcntl.flock(mfd,fcntl.LOCK_EX|fcntl.LOCK_NB);mfds.append(mfd)
    self.assertEqual(run('acquire-source-root-mutex.py','--directory',dirs[ident],'--allocation-released',release,'--mutex',mutexes[ident],'--root',root,'--supervisor-fd',mfd,'--supervisor-close-secret-fd',sfd,pass_fds=(mfd,sfd)).returncode,0)
    inv=inventories(root,self.base,ident)
    dfd=os.open(dirs[ident],os.O_RDONLY|getattr(os,'O_DIRECTORY',0));rfd=os.open(root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try:
     seal=self.base/(ident+'-seal');live=self.base/(ident+'-live');result=run('seal-source-root.py','--directory-fd',dfd,'--source-active',dirs[ident]/'010-source-active.json','--root-fd',rfd,'--mutex',mutexes[ident],'--supervisor-fd',mfd,'--id',ident,'--commit',commit,'--logical-inventory',inv[0],'--generated-inventory',inv[1],'--package-inventory',inv[2],'--cache-inventory',inv[3],'--seal-manifest',seal,'--live-attestation',live,pass_fds=(dfd,rfd,mfd));self.assertEqual(result.returncode,0,result.stderr);seals.append(seal);lives.append(live)
    finally: os.close(dfd);os.close(rfd)
   receipt=self.base/'receipt';fresh=self.base/'fresh';dump(receipt,{'test':'receipt'});dump(fresh,{'test':'fresh'});evidence=self.base/'evidence';evidence.mkdir()
   inner=[sys.executable,str(E/'produce-test-inner-matrix.py'),'--compatibility-receipt',str(receipt),'--fresh-compatibility-receipt',str(fresh),'--logs-dir',str(evidence/'logs')]
   args=['--mac-root',roots['mac'],'--ios-root',roots['ios'],'--protocol-root',roots['protocol'],'--expected-mac-commit',tuple_['macCommit'],'--expected-ios-commit',tuple_['iosCommit'],'--expected-protocol-commit',tuple_['protocolCommit'],'--expected-compatibility-digest',tuple_['compatibilityDigest'],'--expected-normative-manifest-digest',tuple_['normativeManifestDigest'],'--supervisor-close-secret-fd',*sfds,'--lifecycle-directory',dirs['mac'],dirs['ios'],dirs['protocol'],'--seal-manifest',*seals,'--live-attestation',*lives,'--source-mutex',mutexes['mac'],mutexes['ios'],mutexes['protocol'],'--supervisor-fd',*mfds,'--evidence-root',evidence,'--test-only-inner-command',*inner]
   result=run('run-sealed-cross-repo-matrix.py',*args,pass_fds=tuple(mfds+sfds));self.assertEqual(result.returncode,0,result.stderr)
   binding=evidence/'matrix-binding.json'
   for ident in ('mac','ios','protocol'):
    active=dirs[ident]/'010-source-active.json';pre=sha(active);authority=json.loads((dirs[ident]/'000-allocated.json').read_text())['authority'];authority_sha=hashlib.sha256(json.dumps(authority,sort_keys=True,separators=(',',':')).encode()).hexdigest();tuple_sha=hashlib.sha256(json.dumps({k:tuple_[k] for k in ('macCommit','iosCommit','protocolCommit')},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    proof_paths=[]
    specs=(('cleanupSha256','photonport.lifecycle-cleanup-proof.v1','cleanupRecordSha256','photonport.disposable-worktree-cleanup.v1',{'lifecycleId':'tx-'+ident,'rootId':ident,'generatedOutputsAbsent':True}),('postConsumerSha256','photonport.lifecycle-post-consumer-proof.v1','consumerManifestSha256','photonport.post-consumer-inventory.v1',{'rootId':ident,'beforeInventorySha256':'a'*64,'afterInventorySha256':'a'*64}),('b1PreflightSha256','photonport.lifecycle-b1-preflight-proof.v1','preflightManifestSha256','photonport.b1-preflight.v1',{'lifecycleId':'tx-'+ident,'readiness':'ready'}))
    for key,kind,detail,artifact_kind,extra in specs:
     artifact=self.base/(ident+'-'+key+'-artifact')
     if key=='cleanupSha256': extra={'lifecycleId':'tx-'+ident,'rootId':ident,'allocation':json.loads((dirs[ident]/'000-allocated.json').read_text())['allocation'],'destination':str(roots[ident].resolve()),'rootDev':roots[ident].stat().st_dev,'rootIno':roots[ident].stat().st_ino,'generatedOutputsAbsent':True}
     dump(artifact,({'schemaVersion':1,'kind':artifact_kind,**extra} if key=='cleanupSha256' else {'schemaVersion':1,'kind':artifact_kind,'tupleSha256':tuple_sha,**extra}));proof=self.base/(ident+'-'+key+'-proof');dump(proof,{'schemaVersion':1,'kind':kind,'lifecycleId':'tx-'+ident,'rootId':ident,'authoritySha256':authority_sha,'tupleSha256':tuple_sha,'predecessorSha256':pre,detail:sha(artifact),'artifactPath':str(artifact)});proof_paths.append(proof)
    matrix=json.loads(binding.read_text());proof=self.base/(ident+'-matrix-proof');dump(proof,{'schemaVersion':1,'kind':'photonport.lifecycle-matrix-binding-proof.v1','lifecycleId':'tx-'+ident,'rootId':ident,'authoritySha256':authority_sha,'tupleSha256':tuple_sha,'predecessorSha256':pre,'matrixReportSha256':sha(binding),'artifactPath':str(binding),'allocatedSha256':matrix['allocatedSha256ByRoot'][ident],'sourceActiveSha256':matrix['sourceActiveSha256ByRoot'][ident],'sealSha256':matrix['sealSha256ByRoot'][ident],'mutexSha256':matrix['mutexSha256ByRoot'][ident]})
    dfd=os.open(dirs[ident],os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try: result=run('close-source-lifecycle.py','--directory-fd',dfd,'--source-active',active,'--cleanup-proof',proof_paths[0],'--post-consumer-proof',proof_paths[1],'--matrix-binding-proof',proof,'--b1-preflight-proof',proof_paths[2],pass_fds=(dfd,))
    finally: os.close(dfd)
    self.assertEqual(result.returncode,0,result.stderr)
   for index,ident in enumerate(('mac','ios','protocol')):
    authority=json.loads((dirs[ident]/'020-source-closing.json').read_text())['authority'];mutex=Path(authority['lockBPath']);command=self.base/(ident+'-unlink-command');dump(command,{'schemaVersion':1,'kind':'photonport.unlink-and-close-command.v1','authoritySha256':hashlib.sha256(json.dumps(authority,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'operation':'unlink-and-close','mutexPath':str(mutex),'argv':['unlink',str(mutex)]})
    result=run('release-source-root-mutex.py','--directory',dirs[ident],'--mutex',mutex,'--root',roots[ident],'--supervisor-fd',mfds[index],'--supervisor-close-secret-fd',sfds[index],'--unlink-and-close-command',command,'--prepare-close',pass_fds=(mfds[index],sfds[index]));self.assertEqual(result.returncode,0,result.stderr)
    context=(dirs[ident]/'source-release-context.json').read_bytes();closing=(dirs[ident]/'020-source-closing.json').read_bytes();secret=secrets[ident].read_bytes();body={'schemaVersion':1,'kind':'photonport.supervisor-close-ack.v1','contextSha256':hashlib.sha256(context).hexdigest(),'closingSha256':hashlib.sha256(closing).hexdigest(),'authoritySha256':hashlib.sha256(json.dumps(authority,sort_keys=True,separators=(',',':')).encode()).hexdigest()};body['tag']=hmac.new(secret,json.dumps(body,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest();ack=self.base/(ident+'-ack');dump(ack,body);os.close(mfds[index]);mfds[index]=-1
    result=run('release-source-root-mutex.py','--directory',dirs[ident],'--mutex',mutex,'--root',roots[ident],'--supervisor-close-secret-fd',sfds[index],'--supervisor-close-ack',ack,'--unlink-and-close-command',command,'--finalize',pass_fds=(sfds[index],));self.assertEqual(result.returncode,0,result.stderr)
   mac='mac'; common=roots[mac]/'.git'; registry=Path(json.loads((dirs[mac]/'020-source-closing.json').read_text())['authority']['lockAPath']);fake_git=self.base/'fake-git.py';state_file=self.base/'fake-git-state';fake_git.write_text("#!/usr/bin/env python3\nimport os,shutil,sys\nroot="+repr(str(roots[mac]))+"\ncommon="+repr(str(common))+"\nstate="+repr(str(state_file))+"\na=sys.argv[1:]\nif a[:3]==['rev-parse','--path-format=absolute','--git-common-dir']: print(common)\nelif a[-3:]==['worktree','list','--porcelain']: print(('' if os.path.exists(state) else 'worktree '+root+'\\n'))\nelif len(a)>=5 and a[-4:-1]==['worktree','remove','--force']: shutil.rmtree(root);open(state,'w').close()\nelse: sys.exit(2)\n");os.chmod(fake_git,0o700)
   cleanup=self.base/'mac-cleanupSha256-artifact';bad=self.base/'bad-allocation';dump(bad,{'schemaVersion':1,'kind':'allocation-record.v1','id':'bad','destination':str(roots[mac])})
   result=run('dispose-disposable-worktree.py','--directory',dirs[mac],'--mutex',mutexes[mac],'--registry-mutex',registry,'--root',roots[mac],'--destination',roots[mac],'--cleanup',cleanup,'--allocation-record',bad,'--git',fake_git);self.assertNotEqual(result.returncode,0)
   result=run('dispose-disposable-worktree.py','--directory',dirs[mac],'--mutex',mutexes[mac],'--registry-mutex',registry,'--root',roots[mac],'--destination',roots[mac],'--cleanup',cleanup,'--allocation-record',self.base/'mac-registration','--git',fake_git);self.assertEqual(result.returncode,0,result.stderr);self.assertTrue((dirs[mac]/'040-dispose-claim.json').exists());self.assertTrue((dirs[mac]/'050-disposed.json').exists());self.assertFalse(roots[mac].exists())
   for ident in ('ios','protocol'): os.rename(roots[ident],self.base/(ident+'-unavailable'))
   for ident in ('mac','ios','protocol'): os.rename(dirs[ident],self.base/(ident+'-lifecycle-unavailable'))
   self.assertEqual(run('verify-sealed-matrix.py','--evidence-root',evidence).returncode,0)
   self.assertNotEqual(run('verify-sealed-matrix.py','--evidence-root',evidence,'--require-production-trust').returncode,0)
  finally:
   for fd in mfds+sfds:
    try:
     if fd >= 0: os.close(fd)
    except OSError: pass
 def test_allocation_rejects_root_substitution(self):
  other=self.base/'other';other.mkdir(); evidence=json.loads((self.base/'root-evidence').read_text());evidence['ino']=other.stat().st_ino;dump(self.base/'root-evidence',evidence);self.assertNotEqual(self.allocate().returncode,0);self.assertFalse(any(self.directory.iterdir()))
 def test_close_rejects_source_active_substitution(self):
  self.assertEqual(self.allocate().returncode,0); fake=self.base/'active';fake.write_bytes(b'{}\n');fd=os.open(self.directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
  try: result=run('close-source-lifecycle.py','--directory-fd',fd,'--source-active',fake,'--cleanup-proof',fake,'--post-consumer-proof',fake,'--matrix-binding-proof',fake,'--b1-preflight-proof',fake,pass_fds=(fd,))
  finally: os.close(fd)
  self.assertNotEqual(result.returncode,0);self.assertFalse((self.directory/'020-source-closing.json').exists())
if __name__=='__main__': unittest.main()
