"""Verify an ordinary PowerShell ``git push`` against the configured remote."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
REPORT = Path(__file__).with_name('live-terminal-verification.jsonl')
POWERSHELL = Path(r'C:\Program Files\PowerShell\7\pwsh.exe')


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)


def remote_tip() -> tuple[int, str, str]:
    result = run('git', 'ls-remote', 'origin', 'refs/heads/main')
    tip = result.stdout.split()[0] if result.returncode == 0 and result.stdout.split() else ''
    return result.returncode, tip, result.stderr


def main() -> None:
    command = 'git push origin main'
    local = run('git', 'rev-parse', 'HEAD')
    assert local.returncode == 0, local.stderr
    local_tip = local.stdout.strip()
    before_code, before_tip, before_error = remote_tip()
    assert before_code == 0, before_error

    policy_fd, policy_name = tempfile.mkstemp(prefix='git-guard-live-', suffix='.json', dir=APP_ROOT / 'tests')
    os.close(policy_fd)
    policy = Path(policy_name)
    log = policy.with_suffix('.log')
    policy.write_text(json.dumps({
        'sensitive_directories': [],
        'sensitive_files': ['__live_remote_nonmatching_fixture__'],
        'scan_content': False,
    }), encoding='utf-8')

    script = r'''[Console]::WriteLine("CLIENT_READY")
$line = [Console]::ReadLine()
Set-Location -LiteralPath $env:LIVE_REPO
$ErrorActionPreference = 'Continue'
$output = (Invoke-Expression $line 2>&1 | Out-String)
$code = $LASTEXITCODE
[Console]::WriteLine((@{exit_code=$code;output=$output} | ConvertTo-Json -Compress))
'''
    env = os.environ.copy()
    env['LIVE_REPO'] = str(REPO_ROOT)
    client = subprocess.Popen(
        [POWERSHELL, '-NoLogo', '-NoProfile', '-Command', script],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    backend = None
    log_stream = None
    try:
        assert client.stdout.readline().strip() == 'CLIENT_READY'
        log_stream = log.open('w', encoding='utf-8')
        backend = subprocess.Popen(
            [sys.executable, '-B', APP_ROOT / 'backend.py', '--pid', str(client.pid), '--config', policy],
            stdout=log_stream, stderr=log_stream,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        deadline = time.monotonic() + 30
        while '"event": "READY"' not in log.read_text(encoding='utf-8'):
            assert backend.poll() is None, log.read_text(encoding='utf-8')
            assert time.monotonic() < deadline, log.read_text(encoding='utf-8')
            time.sleep(0.1)

        client.stdin.write(command + '\n')
        client.stdin.flush()
        result = json.loads(client.stdout.readline())
        client.stdin.close()
        client_stderr = client.stderr.read()
        assert client.wait(30) == 0, client_stderr

        deadline = time.monotonic() + 10
        while '"event": "ALLOW"' not in log.read_text(encoding='utf-8'):
            assert backend.poll() is None, log.read_text(encoding='utf-8')
            assert time.monotonic() < deadline, log.read_text(encoding='utf-8')
            time.sleep(0.1)
        backend.send_signal(signal.CTRL_BREAK_EVENT)
        assert backend.wait(15) == 0
        log_stream.close()
        log_stream = None

        backend_lines = [json.loads(line) for line in log.read_text(encoding='utf-8').splitlines() if line]
        events = [item.get('event') for item in backend_lines]
        after_code, after_tip, after_error = remote_tip()
        assert result['exit_code'] == 0, result
        assert {'MONITOR', 'GIT_PUSH', 'ALLOW', 'STOPPED'} <= set(events), events
        assert after_code == 0, after_error
        assert after_tip == local_tip, (after_tip, local_tip)

        records = [
            {'type': 'metadata', 'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
             'repo': str(REPO_ROOT), 'local_head': local_tip, 'remote_before': before_tip,
             'terminal_pid': client.pid, 'backend_pid': backend.pid},
            {'type': 'command', 'shell': str(POWERSHELL), 'cwd': str(REPO_ROOT),
             'argv_text': command, 'exit_code': result['exit_code'], 'literal_output': result['output'],
             'stderr': client_stderr},
            *({'type': 'backend', **item} for item in backend_lines),
            {'type': 'verification', 'remote_after': after_tip, 'expected': local_tip,
             'exit_code': after_code, 'passed': True},
        ]
        REPORT.write_text(''.join(json.dumps(item, ensure_ascii=False) + '\n' for item in records), encoding='utf-8')
        print(f'[VERIFIED] monitored terminal ordinary push reached origin/main at {after_tip}')
    finally:
        if backend is not None and backend.poll() is None:
            backend.send_signal(signal.CTRL_BREAK_EVENT)
            try:
                backend.wait(10)
            except subprocess.TimeoutExpired:
                backend.kill()
                backend.wait()
        if client.poll() is None:
            client.kill()
            client.wait()
        if log_stream is not None:
            log_stream.close()
        policy.unlink(missing_ok=True)
        log.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
