"""Policy checks for SCP uploads launched from a monitored Windows terminal."""
from __future__ import annotations

import fnmatch
import hashlib
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


def _is_remote(value: str) -> bool:
    if re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith("\\\\"):
        return False
    if value.lower().startswith("scp://"):
        return True
    # Do not confuse C:\path with host:path.
    return bool(re.match(r"^(?:[^\\/:]+@)?[^\\/:]+:.+", value))


def _operands(argv: list[str]) -> list[str]:
    takes_value = {"-B", "-b", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"}
    result, index = [], 1
    while index < len(argv):
        token = argv[index]
        if token == "--":
            result.extend(argv[index + 1:])
            break
        if token in takes_value:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        result.append(token)
        index += 1
    return result


def _sensitive_path(path: Path, policy: Policy) -> bool:
    resolved = path.resolve()
    folded = str(resolved).replace("\\", "/").casefold()
    if any(resolved == root or root in resolved.parents for root in policy.directories):
        return True
    return any(fnmatch.fnmatchcase(resolved.name.casefold(), p.casefold()) or
               fnmatch.fnmatchcase(folded, p.replace("\\", "/").casefold())
               for p in policy.files)


def _scan_file(path: Path, policy: Policy) -> list[dict]:
    if _sensitive_path(path, policy):
        return [{"path": str(path), "rule": "sensitive-path"}]
    if not path.exists():
        return [{"path": str(path), "rule": "source-not-found"}]
    paths = [p for p in path.rglob("*") if p.is_file()] if path.is_dir() else [path]
    findings = []
    for item in paths:
        if _sensitive_path(item, policy):
            findings.append({"path": str(item), "rule": "sensitive-path"})
            continue
        if item.stat().st_size > MAX_FILE_BYTES:
            findings.append({"path": str(item), "rule": "file-scan-limit"})
            continue
        if policy.scan_content:
            data = item.read_bytes()
            findings.extend({"path": str(item), "rule": name} for name, regex in CONTENT_RULES if regex.search(data))
    return findings


def scan_launch(info: dict, policy: Policy) -> dict:
    argv = info.get("argv") or []
    operands = _operands(argv)
    if len(operands) < 2 or not _is_remote(operands[-1]):
        return {"deny": False, "reason": "not-an-upload", "findings": []}
    cwd = Path(info.get("cwd") or ".")
    findings = []
    for value in operands[:-1]:
        if _is_remote(value):
            continue
        source = Path(value)
        findings.extend(_scan_file(source if source.is_absolute() else cwd / source, policy))
    return {"deny": bool(findings), "reason": "scp-upload", "findings": findings}
