"""Reproduce old path leak and verify real pwsh/PATH Git pushes over TLS."""
from pathlib import Path
import hashlib
import http.server
import json
import os
import queue
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import guard
from test_backend import remove_fixture
import tempfile


def main():
    work = Path(tempfile.mkdtemp(prefix='.tmp-paths-', dir=ROOT / 'tests')).resolve()
    records, cases, backends, clients = [], [], [], []
    requests = []
    server = None
    binary = guard.git_executable()
    binary_hash = hashlib.sha256(Path(binary).read_bytes()).hexdigest()

    def run(argv, cwd=None, expected=0, input=None, flags=0):
        result = subprocess.run([str(x) for x in argv], cwd=cwd, input=input, capture_output=True,
                                timeout=60, creationflags=flags)
        records.append({'argv': [str(x) for x in argv], 'cwd': str(cwd or ROOT),
                        'exit_code': result.returncode, 'stdout': result.stdout.decode('utf-8', 'replace'),
                        'stderr': result.stderr.decode('utf-8', 'replace')})
        if expected is not None:
            assert result.returncode == expected, records[-1]
        return result

    def g(repo, *args, expected=0):
        return run([binary, '-C', repo, *args], expected=expected)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.serve_git()

        def do_POST(self):
            self.serve_git()

        def serve_git(self):
            requests.append({'method': self.command, 'path': self.path})
            parsed = urllib.parse.urlsplit(self.path)
            env = dict(os.environ, GIT_PROJECT_ROOT=str(work), GIT_HTTP_EXPORT_ALL='1',
                       PATH_INFO=parsed.path, QUERY_STRING=parsed.query, REQUEST_METHOD=self.command,
                       CONTENT_TYPE=self.headers.get('Content-Type', ''),
                       CONTENT_LENGTH=self.headers.get('Content-Length', '0'), REMOTE_USER='fixture')
            payload = self.rfile.read(int(env['CONTENT_LENGTH']))
            proc = subprocess.run([binary, 'http-backend'], env=env, input=payload,
                                  capture_output=True, timeout=30)
            head, body = proc.stdout.split(b'\r\n\r\n', 1)
            headers = [line.split(b':', 1) for line in head.split(b'\r\n')]
            status = next((int(value.strip().split()[0]) for key, value in headers if key.lower() == b'status'), 200)
            self.send_response(status)
            for key, value in headers:
                if key.lower() != b'status':
                    self.send_header(key.decode(), value.strip().decode())
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def start_client(repo):
        script = '''[Console]::WriteLine("CLIENT_READY");
while ($line=[Console]::ReadLine()) {
 $r=ConvertFrom-Json $line; Set-Location -LiteralPath $r.repo;
 $a=@($r.args); $ErrorActionPreference='Stop';$launchError=$false;
 try {$o=(& git @a 2>&1 | Out-String);$code=$LASTEXITCODE}
 catch {$o=$_.ToString();$code=$null;$launchError=$true}
 [Console]::WriteLine((@{exit_code=$code;output=$o;launch_error=$launchError} | ConvertTo-Json -Compress));
}'''
        client = subprocess.Popen([r'C:\Program Files\PowerShell\7\pwsh.exe', '-NoProfile', '-Command', script],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        clients.append(client)
        assert client.stdout.readline().strip() == 'CLIENT_READY'
        return client

    def start_backend(source, config, client):
        logpath = work / f'backend-{len(backends)}.log'
        log = logpath.open('w', encoding='utf-8')
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = subprocess.SW_HIDE
        proc = subprocess.Popen([sys.executable, '-B', source / 'backend.py', '--pid', str(client.pid), '--config', config],
                                stdout=log, stderr=log, creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup)
        backends.append((proc, log))
        deadline = time.monotonic() + 30
        while '"event": "READY"' not in logpath.read_text(encoding='utf-8'):
            assert proc.poll() is None, logpath.read_text()
            assert time.monotonic() < deadline, logpath.read_text()
            time.sleep(.1)
        return proc, logpath

    def stop_backend(proc, logpath, name):
        # Send actual CTRL_C_EVENT only to the backend's isolated hidden console.
        helper = '''import ctypes,sys,time
k=ctypes.WinDLL('kernel32',use_last_error=True)
k.FreeConsole()
assert k.AttachConsole(int(sys.argv[1])),ctypes.get_last_error()
assert k.SetConsoleCtrlHandler(None,True),ctypes.get_last_error()
assert k.GenerateConsoleCtrlEvent(0,0),ctypes.get_last_error()
time.sleep(.2)
k.FreeConsole()
print('CTRL_C_EVENT delivered to isolated backend console')
'''
        started = time.monotonic()
        run([sys.executable, '-B', '-c', helper, str(proc.pid)], flags=subprocess.CREATE_NO_WINDOW)
        assert proc.wait(10) == 0
        elapsed = time.monotonic() - started
        assert '"event": "STOPPED"' in logpath.read_text(), logpath.read_text()
        cases.append({'name': name, 'passed': True, 'exit_code': proc.returncode, 'seconds': elapsed})
        print(f'[PASS] {name}: exit=0, {elapsed:.2f}s', flush=True)

    def push(name, client, repo, receiver, allow, logpath=None, baseline=False):
        before = g(receiver, 'rev-parse', '--verify', 'refs/heads/main', expected=None).stdout
        offset = len(logpath.read_text()) if logpath else 0
        count = len(requests)
        args = ['push', '-u', 'origin', 'main']
        client.stdin.write(json.dumps({'repo': str(repo), 'args': args}) + '\n'); client.stdin.flush()
        response_queue = queue.Queue()
        threading.Thread(target=lambda: response_queue.put(client.stdout.readline()), daemon=True).start()
        response = json.loads(response_queue.get(timeout=60))
        records.append({'argv': ['git', *args], 'cwd': str(repo), **response})
        after = g(receiver, 'rev-parse', '--verify', 'refs/heads/main', expected=None).stdout
        native = logpath.read_text()[offset:] if logpath else ''
        if allow:
            assert response['exit_code'] == 0 and len(requests) > count, response
        else:
            assert response['exit_code'] != 0 and before == after and len(requests) == count, (response, native)
            assert '"event": "GIT_PUSH"' in native and '"event": "DENY"' in native and '"event": "NATIVE_BLOCK"' in native, native
            assert 'sensitive-path' in native, native
            oid = g(repo, 'rev-parse', 'HEAD').stdout.decode().strip()
            assert g(receiver, 'cat-file', '-e', oid, expected=None).returncode != 0
        cases.append({'name': name, 'passed': True, 'exit_code': response['exit_code'],
                      'before_tip': before.decode().strip(), 'after_tip': after.decode().strip(),
                      'https_requests': len(requests) - count, 'backend_log': native,
                      'baseline_leak': baseline})
        print(f'[PASS] {name}: exit={response["exit_code"]}, HTTPS requests={len(requests)-count}', flush=True)

    try:
        baseline = work / 'baseline'; baseline.mkdir()
        with zipfile.ZipFile(ROOT / 'tests' / 'baseline.zip') as archive:
            for name in ['backend.py', 'guard.py', 'watch_agent.js']:
                (baseline / name).write_bytes(archive.read(name))
        cert, key = work / 'cert.pem', work / 'key.pem'
        run([r'E:\Git\usr\bin\openssl.exe', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
             '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost',
             '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'])
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        for version, source in [('baseline', baseline), ('modified', ROOT)]:
            repo, receiver = work / f'{version}-repo', work / f'{version}.git'
            repo.mkdir(); receiver.mkdir()
            g(repo, 'init', '-b', 'main'); g(receiver, 'init', '--bare')
            g(receiver, 'config', 'http.receivepack', 'true')
            for name, value in [('user.name', 'Fixture'), ('user.email', 'fixture@example.invalid'),
                                ('commit.gpgsign', 'false'), ('http.sslCAInfo', str(cert)), ('http.sslVerify', 'true'), ('http.schannelUseSSLCAInfo', 'true')]:
                g(repo, 'config', name, value)
            g(repo, 'remote', 'add', 'origin', f'https://localhost:{server.server_port}/{receiver.name}')
            flag = repo / 'demo' / 'frida_git_guard' / 'flag'; flag.parent.mkdir(parents=True)
            (repo / 'ordinary.txt').write_text('clean fixture\n'); g(repo, 'add', '.'); g(repo, 'commit', '-m', 'clean')
            config = work / f'{version}.json'
            config.write_text(json.dumps({'sensitive_directories': [], 'sensitive_files': [str(flag)], 'scan_content': False}))
            def local_settings():
                data = g(repo, 'config', '--local', '--null', '--list').stdout
                return dict(item.split(b'\n', 1) for item in data.split(b'\0') if item)
            initial_settings = local_settings()
            client = start_client(repo)
            backend, logpath = start_backend(source, config, client)
            push(f'{version}-normal-pwsh-https-clean-allow', client, repo, receiver, True, logpath)
            expected_settings = dict(initial_settings, **{})
            expected_settings.update({b'branch.main.remote': b'origin', b'branch.main.merge': b'refs/heads/main'})
            assert local_settings() == expected_settings, local_settings()
            config_hash = hashlib.sha256((repo / '.git' / 'config').read_bytes()).hexdigest()
            flag.write_text('ordinary content that must be protected by its exact configured path\n')
            g(repo, 'add', '.'); g(repo, 'commit', '-m', 'sensitive file')
            secret_commit = g(repo, 'rev-parse', 'HEAD').stdout.decode().strip()
            if version == 'modified':
                push('absolute-path-existing-file-block', client, repo, receiver, False, logpath)
                stop_backend(backend, logpath, 'ctrl-c-stop-existing-file-backend')
            g(repo, 'rm', '-f', 'demo/frida_git_guard/flag'); g(repo, 'commit', '-m', 'delete sensitive file')
            if version == 'modified':
                assert not flag.exists()
                backend, logpath = start_backend(source, config, client)
                push('absolute-path-deleted-history-after-restart-block', client, repo, receiver, False, logpath)
                stop_backend(backend, logpath, 'ctrl-c-stop-deleted-file-backend')
                push('backend-exit-restores-normal-https-push', client, repo, receiver, True)
            else:
                push('baseline-absolute-path-deleted-history-leak-reproduced', client, repo, receiver, True, logpath, baseline=True)
                assert g(receiver, 'cat-file', '-e', secret_commit, expected=None).returncode == 0
                stop_backend(backend, logpath, 'baseline-stop')
            assert hashlib.sha256((repo / '.git' / 'config').read_bytes()).hexdigest() == config_hash
        policy = guard.Policy([], ['demo/frida_git_guard/flag'], False)
        assert guard.sensitive_path('demo/frida_git_guard/flag', policy)
        assert not guard.sensitive_path('other/flag', policy)
        user_policy = guard.load_policy(ROOT / 'config.json')
        assert guard.sensitive_path('demo/frida_git_guard/flag', user_policy, ROOT.parents[1])
        cases.append({'name': 'relative-specific-path-and-current-user-config', 'passed': True})
        assert hashlib.sha256(Path(binary).read_bytes()).hexdigest() == binary_hash
        report = {'passed': True, 'cases': cases, 'records': records, 'https_requests': requests,
                  'tls_verification': True, 'git_binary_sha256_unchanged': binary_hash,
                  'source_sha256': {str(ROOT / name): hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                    for name in ['backend.py', 'guard.py', 'watch_agent.js', 'launcher_agent.js', 'config.json', 'README.md']}}
        (ROOT / 'tests' / 'push-path-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'[VERIFIED] {len(cases)} baseline/path/TLS/console checks passed', flush=True)
    finally:
        for proc, log in backends:
            if proc.poll() is None:
                proc.kill(); proc.wait(15)
            log.close()
        for client in clients:
            client.stdin.close()
            try: client.wait(10)
            except subprocess.TimeoutExpired: client.kill(); client.wait()
        if server:
            server.shutdown(); server.server_close()
        remove_fixture(work)


if __name__ == '__main__':
    main()
