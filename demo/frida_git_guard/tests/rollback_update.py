"""Restore sources saved before the absolute-path fix; no Git/system changes."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    target = parser.parse_args().target.resolve(strict=True)
    if target != ROOT and not target.is_relative_to(ROOT):
        raise ValueError('Target must stay inside this demo directory')
    with zipfile.ZipFile(Path(__file__).with_name('baseline.zip')) as archive:
        if archive.testzip() is not None:
            raise ValueError('Baseline archive CRC mismatch')
        manifest = json.loads(archive.read('manifest.json'))
        for name, expected in manifest.items():
            destination = (target / name).resolve()
            if not destination.is_relative_to(target):
                raise ValueError('Baseline path leaves target')
            content = archive.read(name)
            if hashlib.sha256(content).hexdigest() != expected:
                raise ValueError(f'Baseline hash mismatch: {name}')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            if hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
                raise ValueError(f'Restored hash mismatch: {name}')
    added = (target / 'tests' / 'test_push_paths.py').resolve()
    if not added.is_relative_to(target):
        raise ValueError('Added file leaves target')
    if added.exists():
        added.unlink()
    print('Original source hashes restored; no Git/system configuration changed.')


if __name__ == '__main__':
    main()
