"""Policy checks for Python entry points launched from a monitored Windows terminal."""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
MAX_FILE_BYTES = 16 * 1024 * 1024
CONTENT_RULES = (
    ("demo-secret-marker", re.compile(rb"DEMO_SECRET_[A-Z0-9_]{8,}")),
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("credential-assignment", re.compile(
        rb"(?im)\b(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*[\x22\x27]?[A-Za-z0-9_./+\-]{12,}")),
)


class Policy:
    def __init__(self, directories: list[str], files: list[str], scan_content: bool):
        self.directories = [Path(value).resolve() for value in directories]
        self.files = files
        self.scan_content = scan_content
        for directory in self.directories:
            if not directory.is_dir():
                raise ValueError(f"Sensitive directory does not exist: {directory}")


def load_policy(path: Path = ROOT / "config.json") -> Policy:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    expected = {"sensitive_directories", "sensitive_files", "scan_content"}
    if not isinstance(data, dict) or set(data) != expected:
        raise ValueError("Policy keys: sensitive_directories, sensitive_files, scan_content")
    if type(data["scan_content"]) is not bool:
        raise ValueError("scan_content must be true or false")
    for key in ("sensitive_directories", "sensitive_files"):
        if not isinstance(data[key], list) or not all(isinstance(v, str) and v.strip() for v in data[key]):
            raise ValueError(f"{key} must be an array of nonempty strings")
    return Policy(data["sensitive_directories"], data["sensitive_files"], data["scan_content"])


def _sensitive_path(path: Path, policy: Policy) -> bool:
    resolved = path.resolve()
    folded = str(resolved).replace("\\", "/").casefold()
    if any(resolved == root or root in resolved.parents for root in policy.directories):
        return True
    return any(fnmatch.fnmatchcase(resolved.name.casefold(), p.casefold()) or
               fnmatch.fnmatchcase(folded, p.replace("\\", "/").casefold())
               for p in policy.files)


def scan_launch(info: dict, policy: Policy) -> dict:
    argv = info.get("argv") or []
    args = argv[1:]
    if not args:
        return {"deny": False, "reason": "interactive", "findings": []}
    index = 0
    takes_value = {"-W", "-X", "--check-hash-based-pycs"}
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if token in {"-c", "-m"}:
            break
        if not token.startswith("-") or token == "-":
            break
        if token in takes_value:
            index += 2
        else:
            index += 1
    if index >= len(args) or args[index] == "-":
        return {"deny": False, "reason": "interactive-or-stdin", "findings": []}
    if args[index] == "-c":
        data = (args[index + 1] if len(args) > index + 1 else "").encode("utf-8", "replace")
        findings = [{"path": "<python -c>", "rule": name} for name, regex in CONTENT_RULES
                    if policy.scan_content and regex.search(data)]
        return {"deny": bool(findings), "reason": "inline-code", "findings": findings}
    if args[index] == "-m" or args[index] in {"--version", "-V", "-h", "--help"}:
        return {"deny": False, "reason": "non-file-entry", "findings": []}
    cwd = Path(info.get("cwd") or ".")
    path = Path(args[index])
    path = path if path.is_absolute() else cwd / path
    findings = []
    if _sensitive_path(path, policy):
        findings.append({"path": str(path), "rule": "sensitive-path"})
    elif not path.is_file():
        findings.append({"path": str(path), "rule": "script-not-found"})
    elif path.stat().st_size > MAX_FILE_BYTES:
        findings.append({"path": str(path), "rule": "file-scan-limit"})
    elif policy.scan_content:
        data = path.read_bytes()
        findings.extend({"path": str(path), "rule": name} for name, regex in CONTENT_RULES if regex.search(data))
    return {"deny": bool(findings), "reason": "script", "findings": findings}
