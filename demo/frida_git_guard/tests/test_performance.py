"""Real pwsh command latency and historical scanner comparison; isolated fixtures."""
from pathlib import Path
import hashlib,json,os,queue,signal,statistics,subprocess,sys,tempfile,threading,time,zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));import guard
from test_backend import remove_fixture


def main():
 w=Path(tempfile.mkdtemp(prefix='.tmp-perf-',dir=ROOT/'tests')).resolve()
 records,metrics,backends=[],{},[];client=None
 binary=guard.git_executable();original_hash=hashlib.sha256(Path(binary).read_bytes()).hexdigest()
 def run(argv,cwd=None):
  r=subprocess.run([str(x) for x in argv],cwd=cwd,capture_output=True,timeout=60)
  records.append({'argv':[str(x) for x in argv],'cwd':str(cwd or ROOT),'exit_code':r.returncode,'stdout':r.stdout.decode('utf-8','replace'),'stderr':r.stderr.decode('utf-8','replace')})
  assert r.returncode==0,records[-1];return r
 def g(*args):return run([binary,'-C',repo,*args])
 def launch(source):
  p=w/f'backend-{len(backends)}.log';f=p.open('w',encoding='utf-8')
  b=subprocess.Popen([sys.executable,'-B',source/'backend.py','--pid',str(client.pid),'--config',config],stdout=f,stderr=f,creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
  backends.append((b,f,p));deadline=time.monotonic()+30
  while '"event": "READY"' not in p.read_text():
   assert b.poll() is None,p.read_text();assert time.monotonic()<deadline,p.read_text();time.sleep(.05)
  return b
 def stop(b):
  b.send_signal(signal.CTRL_BREAK_EVENT);assert b.wait(15)==0
 def command(args):
  req={'args':args,'repo':str(repo)};started=time.perf_counter()
  client.stdin.write(json.dumps(req)+'\n');client.stdin.flush()
  q=queue.Queue();threading.Thread(target=lambda:q.put(client.stdout.readline()),daemon=True).start()
  result=json.loads(q.get(timeout=60));elapsed=(time.perf_counter()-started)*1000
  records.append({'argv':args,'cwd':str(repo),**result,'wall_ms':elapsed});assert result['exit_code']==0,result
  return elapsed
 def measure(name):
  tests={'git-add':['git','add','--','file-0.txt'],'git-status':['git','status','--porcelain'],'git-rev-parse':['git','rev-parse','--short','HEAD'],'python-version':[sys.executable,'--version']}
  metrics[name]={}
  for test,args in tests.items():
   command(args);values=[command(args) for _ in range(7)]
   metrics[name][test]={'median_ms':statistics.median(values),'max_ms':max(values),'samples_ms':values}
   print(f'[{name}] {test}: median {statistics.median(values):.1f} ms',flush=True)
 try:
  baseline=w/'baseline';baseline.mkdir()
  with zipfile.ZipFile(ROOT/'tests'/'perf-baseline.zip') as z:
   for name in ['backend.py','guard.py','watch_agent.js']:(baseline/name).write_bytes(z.read(name))
  repo=w/'repo';repo.mkdir();g('init','-b','main');g('config','user.name','Fixture');g('config','user.email','fixture@example.invalid');g('config','commit.gpgsign','false')
  for i in range(24):(repo/f'file-{i}.txt').write_text(f'ordinary benchmark data item {i}\n')
  g('add','.');g('commit','-m','initial')
  for i in range(3):
   (repo/f'file-{i}.txt').write_text(f'changed ordinary benchmark data {i}\n');g('add','.');g('commit','-m',f'change {i}')
  config=w/'policy.json';config.write_text(json.dumps({'sensitive_directories':[],'sensitive_files':['flag'],'scan_content':True}))
  config_hash=hashlib.sha256((repo/'.git'/'config').read_bytes()).hexdigest()
  ps='''[Console]::WriteLine("READY");while($line=[Console]::ReadLine()) {$r=ConvertFrom-Json $line;Set-Location -LiteralPath $r.repo;$a=@($r.args);$exe=$a[0];$a=@($a|Select-Object -Skip 1);$ErrorActionPreference='Stop';try{$o=(& $exe @a 2>&1|Out-String);$code=$LASTEXITCODE;$failed=$false}catch{$o=$_.ToString();$code=$null;$failed=$true};[Console]::WriteLine((@{exit_code=$code;output=$o;launch_error=$failed}|ConvertTo-Json -Compress))}'''
  client=subprocess.Popen([r'C:\Program Files\PowerShell\7\pwsh.exe','-NoProfile','-Command',ps],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  assert client.stdout.readline().strip()=='READY'
  measure('off')
  b=launch(baseline);measure('baseline');stop(b)
  b=launch(ROOT);measure('modified');stop(b)
  measure('after-stop')
  scan_code='''from pathlib import Path
import sys,time,json,subprocess
sys.path.insert(0,sys.argv[1]);import guard
original=subprocess.run;calls=[]
def trace(*args,**kw):
 r=original(*args,**kw)
 calls.append({'argv':[str(x) for x in r.args],'exit_code':r.returncode,'stdout':r.stdout.decode('utf-8','replace'),'stderr':r.stderr.decode('utf-8','replace')})
 return r
subprocess.run=trace
p=guard.Policy([],['flag'],True);started=time.perf_counter();result=guard.scan_history(Path(sys.argv[2]),'HEAD',p);elapsed=(time.perf_counter()-started)*1000
print(json.dumps({'wall_ms':elapsed,'result':result,'git_subprocess_count':len(calls),'commands':calls}))
'''
  for name,source in [('baseline',baseline),('modified',ROOT)]:
   r=run([sys.executable,'-B','-c',scan_code,source,repo]);result=json.loads(r.stdout);assert not result['result']['deny']
   metrics[name]['history-scan']=result
   print(f'[{name}] history scan: {result["wall_ms"]:.1f} ms, {result["git_subprocess_count"]} Git subprocesses',flush=True)
  assert hashlib.sha256((repo/'.git'/'config').read_bytes()).hexdigest()==config_hash
  assert hashlib.sha256(Path(binary).read_bytes()).hexdigest()==original_hash
  for test in ['git-add','git-status','git-rev-parse','history-scan']:
   key='wall_ms' if test=='history-scan' else 'median_ms'
   assert metrics['modified'][test][key]<metrics['baseline'][test][key],(test,metrics)
  report={'passed':True,'metrics':metrics,'records':records,'backend_logs':[p.read_text() for b,f,p in backends],
          'repo_config_sha256_unchanged':config_hash,'git_binary_sha256_unchanged':original_hash,
          'source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ['backend.py','guard.py','watch_agent.js','launcher_agent.js']}}
  (ROOT/'tests'/'performance-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
  print('[VERIFIED] ordinary Git commands and history scan improved; stop restores normal commands.',flush=True)
 finally:
  for b,f,p in backends:
   if b.poll() is None:b.kill();b.wait(15)
   f.close()
  if client:
   client.stdin.close()
   try:client.wait(10)
   except subprocess.TimeoutExpired:client.kill();client.wait()
  remove_fixture(w)


if __name__=='__main__':main()
