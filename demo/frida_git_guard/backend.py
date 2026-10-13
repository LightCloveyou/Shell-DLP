"""Temporary Frida backend. Ordinary Git pushes from monitored terminals are gated."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import threading
import time
from functools import lru_cache

import frida
import guard

ROOT = Path(__file__).resolve().parent
TERMINAL_PROCESSES = {'powershell.exe', 'pwsh.exe', 'cmd.exe', 'bash.exe', 'sh.exe'}
DEFAULT_PROCESSES = {'powershell.exe', 'pwsh.exe', 'cmd.exe', 'bash.exe', 'sh.exe',
                     'windowsterminal.exe', 'explorer.exe', 'code.exe', 'devenv.exe',
                     'idea64.exe', 'sourcetree.exe', 'tortoisegitproc.exe'}


INFO_AGENT = r"""
const k = Process.getModuleByName('kernel32.dll');
const shell = Module.load('shell32.dll');
const command = new NativeFunction(k.getExportByName('GetCommandLineW'), 'pointer', []);
const parse = new NativeFunction(shell.getExportByName('CommandLineToArgvW'), 'pointer', ['pointer', 'pointer']);
const free = new NativeFunction(k.getExportByName('LocalFree'), 'pointer', ['pointer']);
rpc.exports = {info() {
 const count = Memory.alloc(4), p = parse(command(), count), argv = [];
 for (let i=0; i<count.readS32(); i++) argv.push(p.add(i*Process.pointerSize).readPointer().readUtf16String());
 free(p); return {pid:Process.id,cwd:Process.getCurrentDir(),argv};
}};
"""


@lru_cache(maxsize=1)
def git_builtins():
    result = subprocess.run([guard.git_executable(), '--list-cmds=builtins'],
                            capture_output=True, check=True, timeout=15)
    return frozenset(result.stdout.decode().splitlines())


@dataclass
class Watched:
    session: object
    script: object | None
    info: dict | None
    prefix: list[str]
    push_args: list[str] | None


def git_command(info: dict) -> tuple[list[str], list[str] | None]:
    """Keep original global options, including -C, --git-dir and -c aliases."""
    args = info['argv'][1:]
    prefix, index = [], 0
    takes_value = {'-C', '-c', '--git-dir', '--work-tree', '--namespace', '--config-env', '--super-prefix'}
    while index < len(args) and args[index].startswith('-'):
        token = args[index]
        if token == '--':
            index += 1
            break
        prefix.append(token)
        index += 1
        if token in takes_value:
            if index == len(args):
                return prefix, None
            prefix.append(args[index])
            index += 1
    if index == len(args):
        return prefix, None
    command, rest = args[index], args[index + 1:]
    for _ in range(10):
        if command == 'push':
            return prefix, rest
        if command in git_builtins():
            return prefix, None
        alias = subprocess.run([guard.git_executable(), *prefix, 'config', '--get', f'alias.{command}'],
                               cwd=info['cwd'], capture_output=True, timeout=15)
        if alias.returncode != 0:
            return prefix, None
        value = alias.stdout.decode().strip()
        if value.startswith('!'):
            return prefix, None  # child gating catches the shell's actual git push.
        import shlex
        expanded = shlex.split(value)
        if not expanded:
            return prefix, None
        command, rest = expanded[0], expanded[1:] + rest
    raise ValueError('Git alias expansion limit')


def scan_push(info: dict, prefix: list[str], push_args: list[str], policy: guard.Policy) -> dict:
    """Conservative policy covers all refs/tags/mirror and detached HEAD/source OIDs.

    No network probes or config writes. Git performs its actual original push,
    unmodified, after the decision. Noncommit tag targets are examined as well.
    """
    def query(*args, check=True):
        proc = subprocess.run([guard.git_executable(), *prefix, *args], cwd=info['cwd'],
                              capture_output=True, timeout=30)
        if check and proc.returncode:
            raise RuntimeError(proc.stderr.decode('utf-8', 'replace'))
        return proc

    repo = Path(query('rev-parse', '--absolute-git-dir').stdout.decode().strip())
    worktree_result = query('rev-parse', '--show-toplevel', check=False)
    repo_root = (Path(worktree_result.stdout.decode().strip()) if worktree_result.returncode == 0
                 else guard.repository_worktree(repo))
    sources = query('for-each-ref', '--format=%(objectname)').stdout.decode().splitlines()
    head = query('rev-parse', '--verify', 'HEAD', check=False)
    if head.returncode == 0:
        sources.append(head.stdout.decode().strip())
    for arg in push_args:
        if arg.startswith('-') or '*' in arg:
            continue
        source = arg.lstrip('+').split(':', 1)[0]
        if not source:
            continue
        resolved = query('rev-parse', '--verify', '--end-of-options', source, check=False)
        if resolved.returncode == 0:
            sources.append(resolved.stdout.decode().strip())
    findings, objects, commit_roots = [], set(), []
    for oid in dict.fromkeys(sources):
        resolved = guard.git(repo, 'rev-parse', '--verify', oid + '^{}').stdout.decode().strip()
        if resolved in objects:
            continue
        objects.add(resolved)
        kind = guard.git(repo, 'cat-file', '-t', resolved).stdout.strip()
        if kind == b'commit':
            commit_roots.append(resolved)
        elif kind == b'tree':
            tree = guard.git(repo, 'ls-tree', '-r', '-z', resolved).stdout
            for entry in tree.split(b'\0'):
                if not entry:
                    continue
                meta, path = entry.split(b'\t', 1)
                mode, objtype, blob = meta.split()
                label = path.decode('utf-8', 'replace')
                if guard.sensitive_path(label, policy, repo_root):
                    findings.append({'path': label, 'rule': 'sensitive-path'})
                if objtype == b'blob':
                    findings.extend(scan_blob(repo, blob.decode(), label, policy))
        elif kind == b'blob':
            findings.extend(scan_blob(repo, resolved, '(tag/ref blob)', policy))
    if commit_roots and not findings:
        findings.extend(guard.scan_history(repo, commit_roots, policy, repo_root)['findings'])
    return {'deny': bool(findings), 'repo': str(repo), 'findings': findings,
            'policy_scope': 'all local refs + HEAD + explicit push sources (conservative)'}


def scan_blob(repo, oid, label, policy):
    size = int(guard.git(repo, 'cat-file', '-s', oid).stdout)
    if size > guard.MAX_BLOB_BYTES:
        return [{'path': label, 'rule': 'blob-scan-limit'}]
    data = guard.git(repo, 'cat-file', 'blob', oid).stdout
    return [{'path': label, 'rule': name} for name in guard.content_findings(data, policy)]


class Backend:
    def __init__(self, pids=(), process_names=(), config_path=ROOT / 'config.json'):
        self.config_path = Path(config_path)
        self.policy = guard.load_policy(self.config_path)
        self.device = frida.get_local_device()
        self.pids = set(pids)
        self.names = set(process_names) or DEFAULT_PROCESSES
        self.events = queue.Queue()
        self.sessions: dict[int, Watched] = {}
        self.pending = set()
        self.stopping = threading.Event()
        self.excluded = {os.getpid()}
        self.failed = {}
        self.active_cancels = set()
        self.cancellation_lock = threading.Lock()
        self.attach_locks = {}
        self.fast_resumes = queue.Queue()
        self.workers = []
        git_builtins()  # Resolve Git installation/builtins once, before gating launches.
        self.device.on('child-added', self.child_added)

    def log(self, kind, **fields):
        print(json.dumps({'event': kind, **fields}, ensure_ascii=False), flush=True)

    def child_added(self, child):
        self.pending.add(child.pid)
        name = Path(child.path or child.identifier or '').name.lower()
        if name == 'git.exe' or name in self.names:
            self.events.put(('child', child))
        else:
            self.fast_resumes.put(child.pid)

    def request_stop(self):
        self.stopping.set()
        with self.cancellation_lock:
            cancels = list(self.active_cancels)
        for cancel in cancels:
            cancel.cancel()

    def attach(self, pid, name):
        lock = self.attach_locks.setdefault(pid, threading.Lock())
        with lock:
            if pid in self.sessions or pid in self.excluded or self.stopping.is_set():
                return
            if name.lower() != 'git.exe' and time.monotonic() < self.failed.get(pid, 0):
                return
            cancel = frida.Cancellable()
            with self.cancellation_lock:
                self.active_cancels.add(cancel)
            deadline = threading.Timer(5, cancel.cancel)
            deadline.daemon = True
            deadline.start()
            try:
                with cancel:
                    self._attach(pid, name)
            finally:
                deadline.cancel()
                with self.cancellation_lock:
                    self.active_cancels.discard(cancel)

    def _attach(self, pid, name):
        if pid in self.sessions or pid in self.excluded:
            return
        session = None
        try:
            session = self.device.attach(pid)
            session.on('detached', lambda *args: self.events.put(('detached', pid)))
            script, info, prefix, push_args = None, None, [], None
            if name.lower() == 'git.exe':
                probe = session.create_script(INFO_AGENT)
                probe.load()
                try:
                    info = probe.exports_sync.info()
                finally:
                    probe.unload()
                prefix, push_args = git_command(info)
                if push_args is not None:
                    script = session.create_script((ROOT / 'watch_agent.js').read_text(encoding='utf-8'))
                    script.on('message', lambda message, data: self.events.put(('message', (pid, message))))
                    script.load()
                    script.exports_sync.configure(True)
            else:
                script = session.create_script((ROOT / 'launcher_agent.js').read_text(encoding='utf-8'))
                script.on('message', lambda message, data: self.events.put(('message', (pid, message))))
                script.load()
            session.enable_child_gating()
            self.sessions[pid] = Watched(session, script, info, prefix, push_args)
            self.failed.pop(pid, None)
            self.log('MONITOR', pid=pid, process=name)
            if push_args is not None:
                self.log('GIT_PUSH', pid=pid, cwd=info['cwd'], argv=info['argv'])
        except frida.ProcessNotFoundError:
            if session:
                session.detach()
        except Exception as exc:
            if session:
                try:
                    with frida.Cancellable():
                        session.detach()
                except (frida.InvalidOperationError, frida.ProcessNotFoundError):
                    pass
            first_failure = pid not in self.failed
            retry = 10 if name.lower() in TERMINAL_PROCESSES else 300
            self.failed[pid] = time.monotonic() + retry
            if first_failure and not self.stopping.is_set():
                self.log('ATTACH_ERROR', pid=pid, process=name, error=str(exc), retry_seconds=retry)
                if name.lower() in TERMINAL_PROCESSES:
                    self.log('UNPROTECTED_TERMINAL', pid=pid, process=name)
            raise

    def discover(self, desktop=False):
        for proc in self.device.enumerate_processes():
            if self.stopping.is_set():
                break
            eligible = ((self.pids and proc.pid in self.pids)
                        or (not self.pids and proc.name.lower() in self.names
                            and ((proc.name.lower() not in TERMINAL_PROCESSES) == desktop)))
            if eligible:
                try:
                    self.attach(proc.pid, proc.name)
                except Exception:
                    pass

    def resume_child(self, pid):
        try:
            self.device.resume(pid)
        except (frida.ProcessNotFoundError, frida.InvalidOperationError):
            pass
        finally:
            self.pending.discard(pid)

    def resume_worker(self):
        while not self.stopping.is_set():
            try:
                pid = self.fast_resumes.get(timeout=0.1)
            except queue.Empty:
                continue
            self.resume_child(pid)

    def discover_worker(self, desktop):
        while not self.stopping.is_set():
            try:
                self.discover(desktop)
            except Exception as exc:
                if not self.stopping.is_set():
                    self.log('DISCOVERY_ERROR', error=str(exc))
            self.stopping.wait(2 if desktop else 1)

    def handle_child(self, child):
        name = Path(child.path or child.identifier or '').name.lower()
        try:
            if name == 'git.exe' or name in self.names:
                self.attach(child.pid, name)
        except Exception as exc:
            # Fail closed for a Git child intercepted before it starts running.
            if name == 'git.exe':
                self.device.kill(child.pid)
                self.log('BLOCKED_ATTACH_FAILURE', pid=child.pid, error=str(exc))
        finally:
            self.resume_child(child.pid)

    def handle_message(self, pid, message):
        watched = self.sessions.get(pid)
        if not watched or not watched.script:
            return
        if message['type'] != 'send':
            self.log('AGENT_ERROR', pid=pid, error=message.get('description', message['type']))
            return
        data = message['payload']
        if data['type'] in {'check', 'launch-check'}:
            started = time.perf_counter()
            try:
                self.policy.refresh()
                if data['type'] == 'launch-check':
                    info = data['info']
                    prefix, push_args = git_command(info)
                    if push_args is None:
                        raise ValueError('Launcher push arguments changed')
                    self.log('GIT_PUSH', pid=pid, cwd=info['cwd'], argv=info['argv'], stage='launcher-before-create')
                    policy = scan_push(info, prefix, push_args, self.policy)
                else:
                    policy = scan_push(watched.info, watched.prefix, watched.push_args, self.policy)
            except Exception as exc:
                policy = {'deny': True, 'findings': [{'rule': 'scan-error'}], 'error': str(exc)}
            response_type = 'decision-' + data['id'] if data['type'] == 'launch-check' else 'decision'
            watched.script.post({'type': response_type, 'payload': {'deny': policy['deny']}})
            self.log('DENY' if policy['deny'] else 'ALLOW', pid=pid, scan_ms=round((time.perf_counter()-started)*1000,1), **policy)
        elif data['type'] == 'launcher-error':
            self.log('AGENT_ERROR', **data)
        elif data['type'] == 'blocked':
            self.log('NATIVE_BLOCK', **data)

    def run(self):
        try:
            resumer = threading.Thread(target=self.resume_worker, daemon=True, name='fast-resume')
            self.workers.append(resumer)
            resumer.start()
            self.discover()
            if self.stopping.is_set():
                return
            if not self.sessions:
                raise RuntimeError('No terminal attached; run at the same/elevated privilege as the terminal')
            self.log('READY', monitors=len(self.sessions), config=str(self.config_path.absolute()),
                     coverage='monitored terminals and descendants only', unprotected_pids=list(self.failed))
            if not self.pids:
                for desktop in (False, True):
                    worker = threading.Thread(target=self.discover_worker, args=(desktop,), daemon=True)
                    self.workers.append(worker)
                    worker.start()
            while not self.stopping.is_set():
                try:
                    kind, item = self.events.get(timeout=0.2)
                except queue.Empty:
                    kind = None
                if kind == 'child':
                    self.handle_child(item)
                elif kind == 'message':
                    self.handle_message(*item)
                elif kind == 'detached':
                    self.sessions.pop(item, None)

        finally:
            self.stop()

    def stop(self):
        self.request_stop()
        for worker in self.workers:
            worker.join(timeout=6)
        for pid, watched in list(self.sessions.items()):
            try:
                if watched.script:
                    # Release an in-flight decision before unloading its script.
                    watched.script.post({'type': 'decision', 'payload': {'deny': True}})
                watched.session.disable_child_gating()
                if watched.script:
                    watched.script.unload()
                watched.session.detach()
            except (frida.ProcessNotFoundError, frida.InvalidOperationError):
                pass
        self.sessions.clear()
        for pid in list(self.pending):
            try:
                self.device.resume(pid)
            except (frida.ProcessNotFoundError, frida.InvalidOperationError):
                pass
        self.pending.clear()
        self.device.off('child-added', self.child_added)
        self.log('STOPPED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, action='append', default=[], help='monitor a specific launcher PID (repeatable)')
    parser.add_argument('--process', action='append', default=[], help='extra launcher process name')
    parser.add_argument('--config', type=Path, default=ROOT / 'config.json', help='sensitive path policy JSON')
    args = parser.parse_args()
    try:
        backend = Backend(args.pid, DEFAULT_PROCESSES | {name.lower() for name in args.process}, args.config)
    except Exception as exc:
        print(f'[CONFIG_ERROR] {exc}', flush=True)
        return 2
    signal.signal(signal.SIGINT, lambda *args: backend.request_stop())
    signal.signal(signal.SIGTERM, lambda *args: backend.request_stop())
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, lambda *args: backend.request_stop())
    # Win32 console callbacks run on a separate thread: cancel a blocked native
    # attach immediately instead of waiting for Python's main-thread SIGINT.
    console_handler = None
    if os.name == 'nt':
        import ctypes
        callback_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint32)
        def on_console_event(event):
            if event in (0, 1):
                backend.request_stop()
                return 1
            return 0
        console_handler = callback_type(on_console_event)
        console_api = ctypes.WinDLL('kernel32', use_last_error=True).SetConsoleCtrlHandler
        console_api.argtypes = [callback_type, ctypes.c_int]
        console_api.restype = ctypes.c_int
        if not console_api(console_handler, 1):
            raise ctypes.WinError(ctypes.get_last_error())
    try:
        backend.run()
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f'[ERROR] {exc}', flush=True)
        return 2
    finally:
        if console_handler is not None:
            console_api(console_handler, 0)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
