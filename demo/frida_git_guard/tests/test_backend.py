"""Config and real ordinary-push checks; temporary repositories are cleaned up."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import guard


def remove_fixture(path):
    target = Path(path).resolve()
    assert target.is_relative_to((ROOT / 'tests').resolve()) and target.name.startswith('.tmp-')

    def writable(func, name, error):
        item = Path(name).resolve()
        assert item.is_relative_to(target) or item == target
        if not isinstance(error[1], PermissionError):
            raise error[1]
        os.chmod(item, stat.S_IREAD | stat.S_IWRITE)
        func(name)

    shutil.rmtree(target, onerror=writable)


def main():
    work = Path(tempfile.mkdtemp(prefix='.tmp-', dir=ROOT / 'tests')).resolve()
    assert work.is_relative_to((ROOT / 'tests').resolve())
    records, cases, backends = [], [], []
    client = None
    binary = guard.git_executable()
    original_binary = hashlib.sha256(Path(binary).read_bytes()).hexdigest()

    def run(argv, expected=0, cwd=None):
        result = subprocess.run([str(x) for x in argv], cwd=cwd, capture_output=True, timeout=60)
        record = {'argv': [str(x) for x in argv], 'cwd': str(cwd or ROOT), 'exit_code': result.returncode,
                  'stdout': result.stdout.decode('utf-8', 'replace'), 'stderr': result.stderr.decode('utf-8', 'replace')}
        records.append(record)
        if expected is not None:
            assert result.returncode == expected, record
        return result

    def g(repo, *args, expected=0):
        return run([binary, '-C', repo, *args], expected)

    def save_config(name, directories, files=(), content=False):
        path = work / name
        path.write_text(json.dumps({'sensitive_directories': [str(x) for x in directories],
                                    'sensitive_files': list(files), 'scan_content': content}), encoding='utf-8')
        return path

    def commit(repo, message):
        g(repo, 'add', '-A')
        g(repo, 'commit', '-m', message)
        return g(repo, 'rev-parse', 'HEAD').stdout.decode().strip()

    def start_backend(config):
        path = work / (config.stem + '-backend.log')
        log = path.open('w', encoding='utf-8')
        backend = subprocess.Popen([sys.executable, '-B', ROOT / 'backend.py', '--pid', str(client.pid), '--config', config],
                                   stdout=log, stderr=log, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        backends.append((backend, log))
        deadline = time.monotonic() + 30
        while '"event": "READY"' not in path.read_text(encoding='utf-8'):
            assert backend.poll() is None, path.read_text()
            assert time.monotonic() < deadline
            time.sleep(0.1)
        return backend, path

    def stop_backend(backend):
        backend.send_signal(signal.CTRL_BREAK_EVENT)
        assert backend.wait(15) == 0

    def push(name, repo, remote, expect_success, log=None):
        before = g(remote, 'rev-parse', '--verify', 'refs/heads/main', expected=None).stdout
        argv = [binary, '-C', str(repo), 'push', 'origin', 'main']
        offset = len(log.read_text()) if log else 0
        client.stdin.write(json.dumps(argv) + '\n')
        client.stdin.flush()
        response = json.loads(client.stdout.readline())
        records.append({'argv': argv, **response})
        after = g(remote, 'rev-parse', '--verify', 'refs/heads/main', expected=None).stdout
        if expect_success:
            assert response['exit_code'] == 0, response
        else:
            assert response['exit_code'] != 0 and before == after, response
            native = log.read_text()[offset:]
            assert '"event": "DENY"' in native and '"event": "NATIVE_BLOCK"' in native, native
            source = g(repo, 'rev-parse', 'HEAD').stdout.decode().strip()
            assert g(remote, 'cat-file', '-e', source, expected=None).returncode != 0
        cases.append({'name': name, 'passed': True, 'exit_code': response['exit_code'],
                      'before_tip': before.decode().strip(), 'after_tip': after.decode().strip(),
                      'backend_log': log.read_text()[offset:] if log else ''})
        print(f'[PASS] {name}: exit={response["exit_code"]}', flush=True)

    try:
        relative_config = save_config('relative.json', ['vault'])
        relative = guard.load_policy(relative_config)
        assert guard.sensitive_path('vault/nested/data.txt', relative)
        assert not guard.sensitive_path('vault2/data.txt', relative)
        assert not guard.sensitive_path('.env', relative)
        assert not guard.content_findings(b'DEMO_SECRET_DISABLED_0123456789', relative)
        default = guard.Policy(['secrets', 'private'], ['.env', '*.pem'], True)
        assert guard.sensitive_path('.env', default)
        assert guard.sensitive_path('private/ordinary.txt', default)
        cases.append({'name': 'policy-relative-prefix-and-switches', 'passed': True})

        repo, remote, protected = work / 'source', work / 'receiver.git', work / 'protected'
        for path in (repo, remote, protected):
            path.mkdir()
        g(repo, 'init', '-b', 'main')
        g(remote, 'init', '--bare')
        for key, value in [('user.name', 'Fixture'), ('user.email', 'fixture@example.invalid'), ('commit.gpgSign', 'false')]:
            g(repo, 'config', key, value)
        g(repo, 'remote', 'add', 'origin', str(remote))
        config_hash = hashlib.sha256((repo / '.git' / 'config').read_bytes()).hexdigest()
        (repo / '.env').write_text('DEMO_SECRET_DISABLED_0123456789\n')
        commit(repo, 'custom policy permits outside files')
        client_file = work / 'client.py'
        client_file.write_text('''import json,subprocess,sys
print("READY",flush=True)
for line in sys.stdin:
 try:
  p=subprocess.run(json.loads(line),capture_output=True)
  response={"exit_code":p.returncode,"stdout":p.stdout.decode("utf-8","replace"),"stderr":p.stderr.decode("utf-8","replace")}
 except OSError as e:
  response={"exit_code":None,"stdout":"","stderr":str(e),"launch_error":True}
 print(json.dumps(response),flush=True)
''')
        client = subprocess.Popen([sys.executable, '-B', client_file], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert client.stdout.readline().strip() == 'READY'
        backend, log = start_backend(relative_config)
        push('outside-configured-directory-allow', repo, remote, True, log)
        (repo / 'vault').mkdir()
        (repo / 'vault' / 'data.txt').write_text('ordinary contents in a configured sensitive directory\n')
        commit(repo, 'relative directory fixture')
        push('configured-relative-directory-block', repo, remote, False, log)
        stop_backend(backend)
        push('stop-restores-normal-push', repo, remote, True)

        source = protected / 'source.dat'
        source.write_bytes(b'absolute-protected-file-fixture-0123456789\x00')
        absolute_config = save_config('absolute.json', [protected])
        policy = guard.load_policy(absolute_config)
        assert guard.content_findings(source.read_bytes(), policy) == ['protected-directory-content']
        source.write_bytes(b'new-protected-file-content-0123456789')
        policy.refresh()
        assert 'protected-directory-content' in guard.content_findings(source.read_bytes(), policy)
        assert 'protected-directory-content' in guard.content_findings(b'absolute-protected-file-fixture-0123456789\x00', policy)
        cases.append({'name': 'absolute-index-refresh-and-memory-history', 'passed': True})
        backend, log = start_backend(absolute_config)
        push('other-configured-policy-applies', repo, remote, True, log)
        (repo / 'renamed-upload.bin').write_bytes(source.read_bytes())
        commit(repo, 'copy external protected file under an unrelated name')
        push('configured-absolute-copy-rename-block', repo, remote, False, log)
        assert 'protected-directory-content' in log.read_text()
        stop_backend(backend)
        push('absolute-policy-stop-restores-push', repo, remote, True)
        invalid = work / 'invalid.json'
        invalid.write_text('{"sensitive_directories": "wrong"}')
        run([sys.executable, '-B', ROOT / 'backend.py', '--config', invalid], expected=2)
        cases.append({'name': 'invalid-config-fails-before-attach', 'passed': True})
        assert hashlib.sha256((repo / '.git' / 'config').read_bytes()).hexdigest() == config_hash
        assert hashlib.sha256(Path(binary).read_bytes()).hexdigest() == original_binary
        report = {'passed': True, 'cases': cases, 'records': records,
                  'git_binary_sha256_unchanged': original_binary, 'repo_config_sha256_unchanged': config_hash,
                  'source_sha256': {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in ROOT.iterdir() if path.is_file()}}
        (ROOT / 'tests' / 'verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'[VERIFIED] {len(cases)} config/lifecycle checks passed', flush=True)
    finally:
        for backend, log in backends:
            if backend.poll() is None:
                backend.send_signal(signal.CTRL_BREAK_EVENT)
                try:
                    backend.wait(10)
                except subprocess.TimeoutExpired:
                    backend.kill()
                    backend.wait()
            log.close()
        if client:
            client.stdin.close()
            try:
                client.wait(10)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait()
        remove_fixture(work)


if __name__ == '__main__':
    main()
