"""Verify Ctrl+Break/Ctrl+C shutdown with many monitored terminals."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
REPORT = Path(__file__).with_name('shutdown-verification.json')
POWERSHELL = Path(r'C:\Program Files\PowerShell\7\pwsh.exe')


def main():
    work = Path(tempfile.mkdtemp(prefix='.tmp-shutdown-', dir=ROOT / 'tests'))
    clients = []
    backend = None
    log_stream = None
    try:
        config = work / 'config.json'
        config.write_text(json.dumps({
            'sensitive_directories': [],
            'sensitive_files': ['__shutdown_fixture__'],
            'scan_content': False,
        }), encoding='utf-8')
        client_script = '[Console]::WriteLine("READY");[Console]::ReadLine() | Out-Null'
        for _ in range(12):
            client = subprocess.Popen(
                [POWERSHELL, '-NoLogo', '-NoProfile', '-Command', client_script],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            assert client.stdout.readline().strip() == 'READY'
            clients.append(client)

        log_path = work / 'backend.jsonl'
        log_stream = log_path.open('w', encoding='utf-8')
        argv = [sys.executable, '-B', ROOT / 'backend.py', '--config', config]
        for client in clients:
            argv.extend(['--pid', str(client.pid)])
        backend = subprocess.Popen(
            [str(item) for item in argv], stdout=log_stream, stderr=log_stream,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        deadline = time.monotonic() + 45
        while '"event": "READY"' not in log_path.read_text(encoding='utf-8'):
            assert backend.poll() is None, log_path.read_text(encoding='utf-8')
            assert time.monotonic() < deadline, log_path.read_text(encoding='utf-8')
            time.sleep(0.1)

        started = time.perf_counter()
        backend.send_signal(signal.CTRL_BREAK_EVENT)
        exit_code = backend.wait(8)
        elapsed_ms = (time.perf_counter() - started) * 1000
        log_stream.close()
        log_stream = None
        lines = [json.loads(line) for line in log_path.read_text(encoding='utf-8').splitlines() if line]
        events = [line.get('event') for line in lines]
        assert exit_code == 0, (exit_code, lines)
        assert elapsed_ms < 6000, elapsed_ms
        assert 'STOP_REQUESTED' in events, events
        assert 'STOPPED' in events or 'FORCE_STOP' in events, events
        report = {
            'passed': True,
            'command': [str(item) for item in argv],
            'signal': 'CTRL_BREAK_EVENT (same Win32 console path as Ctrl+C handler)',
            'monitors': len(clients),
            'exit_code': exit_code,
            'elapsed_ms': elapsed_ms,
            'events': lines,
        }
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'[VERIFIED] {len(clients)} sessions stopped in {elapsed_ms:.1f} ms, exit={exit_code}')
    finally:
        if backend is not None and backend.poll() is None:
            backend.kill()
            backend.wait()
        if log_stream is not None:
            log_stream.close()
        for client in clients:
            if client.poll() is None:
                try:
                    client.stdin.write('EXIT\n')
                    client.stdin.flush()
                    client.wait(5)
                except Exception:
                    client.kill()
                    client.wait()
        for path in sorted(work.rglob('*'), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        work.rmdir()


if __name__ == '__main__':
    main()
