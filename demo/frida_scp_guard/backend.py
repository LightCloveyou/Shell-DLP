"""Frida launch gate for one demo target (SCP or Python)."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import signal
import threading
import time

import frida
import guard

ROOT = Path(__file__).resolve().parent
DEFAULT_PROCESSES = {"powershell.exe", "pwsh.exe", "cmd.exe", "bash.exe", "sh.exe"}


class Backend:
    def __init__(self, pids=(), process_names=(), config_path=ROOT / "config.json"):
        self.device = frida.get_local_device()
        self.config_path = Path(config_path)
        self.policy = guard.load_policy(self.config_path)
        self.pids = set(pids)
        self.names = {name.casefold() for name in process_names} or DEFAULT_PROCESSES
        self.sessions = {}
        self.events = queue.Queue()
        self.stopping = threading.Event()
        self.pending = {}
        self.lock = threading.Lock()
        self.device.on("child-added", self.child_added)

    @staticmethod
    def log(event, **fields):
        print(json.dumps({"event": event, **fields}, ensure_ascii=False), flush=True)

    def request_stop(self):
        if self.stopping.is_set():
            return
        self.stopping.set()
        self.log("STOP_REQUESTED", detail="正在释放等待中的命令并退出")
        with self.lock:
            waiting = list(self.pending.items())
            self.pending.clear()
        for (_, response_type), script in waiting:
            try:
                script.post({"type": response_type, "payload": {"deny": True}})
            except Exception:
                pass

    def on_message(self, pid, script, message):
        if message.get("type") != "send":
            self.log("AGENT_ERROR", pid=pid, detail=message)
            return
        payload = message.get("payload", {})
        kind = payload.get("type")
        if kind == "launch-check":
            response_type = "decision-" + str(payload.get("id"))
            key = (pid, response_type)
            with self.lock:
                self.pending[key] = script
            try:
                decision = {"deny": True, "findings": [{"rule": "backend-stopping"}]} if self.stopping.is_set() else guard.scan_launch(payload.get("info", {}), self.policy)
            except Exception as error:
                decision = {"deny": True, "findings": [{"rule": "scan-error", "detail": str(error)}]}
            try:
                script.post({"type": response_type, "payload": decision})
            finally:
                with self.lock:
                    self.pending.pop(key, None)
            self.log("BLOCKED" if decision["deny"] else "ALLOWED", pid=pid,
                     argv=payload.get("info", {}).get("argv", []), findings=decision.get("findings", []))
        elif kind == "blocked":
            self.log("NATIVE_BLOCK", pid=pid, win32_error=payload.get("win32_error", 5))
        elif kind == "launcher-error":
            self.log("LAUNCHER_ERROR", pid=pid, error=payload.get("error"))

    def child_added(self, child):
        name = Path(child.path or child.identifier or "").name
        try:
            if name.casefold() in self.names and not self.stopping.is_set():
                self.attach(child.pid, name)
        finally:
            try:
                self.device.resume(child.pid)
            except Exception:
                pass

    def attach(self, pid, name):
        if pid == os.getpid() or pid in self.sessions or self.stopping.is_set():
            return
        session = None
        try:
            session = self.device.attach(pid)
            session.enable_child_gating()
            script = session.create_script((ROOT / "launcher_agent.js").read_text(encoding="utf-8"))
            script.on("message", lambda message, data, p=pid, s=script: self.on_message(p, s, message))
            script.load()
            self.sessions[pid] = (session, script)
            session.on("detached", lambda *_, p=pid: self.sessions.pop(p, None))
            self.log("MONITOR", pid=pid, process=name)
        except (frida.ProcessNotFoundError, frida.InvalidOperationError, frida.TransportError) as error:
            if session:
                try:
                    session.detach()
                except Exception:
                    pass
            self.log("ATTACH_ERROR", pid=pid, process=name, error=str(error))

    def discover(self):
        for process in self.device.enumerate_processes():
            if process.pid in self.pids or process.name.casefold() in self.names:
                self.attach(process.pid, process.name)

    def run(self):
        self.discover()
        self.log("READY", monitors=len(self.sessions), config=str(self.config_path),
                 coverage="monitored terminal CreateProcess calls")
        while not self.stopping.wait(0.5):
            self.discover()
        self.log("STOPPING", monitors=len(self.sessions))
        for pid, (session, script) in list(self.sessions.items()):
            try:
                script.exports_sync.stop()
            except Exception:
                pass
            try:
                session.detach()
            except Exception:
                pass
        self.sessions.clear()
        self.log("STOPPED", monitors=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", action="append", type=int, default=[])
    parser.add_argument("--process", action="append", default=[])
    parser.add_argument("--config", type=Path, default=ROOT / "config.json")
    args = parser.parse_args()
    backend = Backend(args.pid, args.process, args.config)
    signal.signal(signal.SIGINT, lambda *_: backend.request_stop())
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, lambda *_: backend.request_stop())
    backend.run()


if __name__ == "__main__":
    main()
