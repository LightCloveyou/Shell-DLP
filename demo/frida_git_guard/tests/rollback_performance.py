"""Restore the working version before performance changes, inside this demo only."""
import argparse,hashlib,json,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--target',type=Path,required=True)
 target=parser.parse_args().target.resolve(strict=True)
 if target!=ROOT and not target.is_relative_to(ROOT):raise ValueError('Target must stay inside demo')
 with zipfile.ZipFile(Path(__file__).with_name('perf-baseline.zip')) as z:
  if z.testzip() is not None:raise ValueError('Baseline CRC mismatch')
  manifest=json.loads(z.read('manifest.json'))
  for name,expected in manifest.items():
   dest=(target/name).resolve()
   if not dest.is_relative_to(target):raise ValueError('Baseline leaves target')
   data=z.read(name)
   if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Baseline hash mismatch')
   dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
   if hashlib.sha256(dest.read_bytes()).hexdigest()!=expected:raise ValueError('Restored hash mismatch')
 for name in ['launcher_agent.js','tests/test_performance.py','tests/test_shutdown.py']:
  dest=(target/name).resolve()
  if not dest.is_relative_to(target):raise ValueError('Added file leaves target')
  if dest.exists():dest.unlink()
 print('Pre-performance source hashes restored; Git/system configuration unchanged.')

if __name__=='__main__':main()
