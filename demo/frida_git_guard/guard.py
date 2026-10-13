"""Git object scanning and JSON policy for the temporary Frida backend."""
from __future__ import annotations

import json
import posixpath
import fnmatch
import hashlib
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
MAX_COMMITS = 1000
MAX_BLOB_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_TREE_ENTRIES = 50000
CONTENT_RULES = [
    ('demo-secret-marker', re.compile(rb'DEMO_SECRET_[A-Z0-9_]{8,}')),
    ('private-key', re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('credential-assignment', re.compile(
        rb'(?im)\b(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*[\x22\x27]?[A-Za-z0-9_./+\-]{12,}')),
]


class Policy:
    def __init__(self, directories, files, scan_content):
        self.relative_directories = []
        self.absolute_directories = []
        self.file_patterns = []
        self.relative_file_patterns = []
        self.absolute_file_patterns = []
        self.absolute_files = []
        for value in files:
            normalized = value.replace('\\', '/').casefold()
            if Path(value).is_absolute():
                normalized = posixpath.normpath(normalized)
                self.absolute_file_patterns.append(normalized)
                if not any(char in value for char in '*?['):
                    self.absolute_files.append(Path(value))
            elif '/' in normalized:
                normalized = posixpath.normpath(normalized)
                if normalized == '..' or normalized.startswith('../'):
                    raise ValueError(f'Sensitive file must stay inside the repository: {value}')
                self.relative_file_patterns.append(normalized)
            else:
                self.file_patterns.append(normalized)
        self.scan_content = scan_content
        self.protected_hashes = set()
        for value in directories:
            path = Path(value)
            if path.is_absolute():
                if not path.is_dir():
                    raise ValueError(f'Sensitive directory does not exist: {value}')
                self.absolute_directories.append(path)
            else:
                normalized = value.replace('\\', '/').strip('/').casefold()
                if not normalized or any(part in {'', '..'} for part in normalized.split('/')):
                    raise ValueError(f'Invalid relative sensitive directory: {value}')
                self.relative_directories.append(normalized)
        self.refresh()

    def refresh(self):
        # In-memory fingerprints detect copies/renames of absolute-directory files.
        # Keep fingerprints already observed until this backend instance exits.
        total = count = 0
        for directory in self.absolute_directories:
            if not directory.is_dir():
                raise ValueError(f'Sensitive directory disappeared: {directory}')
            for path in directory.rglob('*'):
                if path.is_symlink():
                    raise ValueError(f'Symlink in sensitive directory: {path}')
                if not path.is_file():
                    continue
                size = path.stat().st_size
                total += size
                count += 1
                if size > MAX_BLOB_BYTES or total > MAX_TOTAL_BYTES or count > MAX_TREE_ENTRIES:
                    raise ValueError('Sensitive directory exceeds indexing limits')
                self.protected_hashes.add(hashlib.sha256(path.read_bytes()).digest())

        # Missing absolute files still match historical Git paths. Existing ones
        # additionally protect exact-content copies under a different filename.
        for path in self.absolute_files:
            if path.is_symlink():
                raise ValueError(f'Symlink sensitive file: {path}')
            if not path.exists():
                continue
            if not path.is_file():
                raise ValueError(f'Sensitive file is not a regular file: {path}')
            size = path.stat().st_size
            total += size
            count += 1
            if size > MAX_BLOB_BYTES or total > MAX_TOTAL_BYTES or count > MAX_TREE_ENTRIES:
                raise ValueError('Sensitive files exceed indexing limits')
            self.protected_hashes.add(hashlib.sha256(path.read_bytes()).digest())


def load_policy(path: Path = ROOT / 'config.json') -> Policy:
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(config, dict):
        raise ValueError('Policy must be a JSON object')
    expected = {'sensitive_directories', 'sensitive_files', 'scan_content'}
    if set(config) != expected:
        raise ValueError('Policy keys: sensitive_directories, sensitive_files, scan_content')
    directories, files = config['sensitive_directories'], config['sensitive_files']
    for label, values in [('sensitive_directories', directories), ('sensitive_files', files)]:
        if not isinstance(values, list) or not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError(f'{label} must be an array of nonempty strings')
    if type(config['scan_content']) is not bool:
        raise ValueError('scan_content must be true or false')
    return Policy(directories, files, config['scan_content'])


def content_findings(data: bytes, policy: Policy) -> list[str]:
    rules = [name for name, regex in CONTENT_RULES if regex.search(data)] if policy.scan_content else []
    if policy.protected_hashes and hashlib.sha256(data).digest() in policy.protected_hashes:
        rules.append('protected-directory-content')
    return rules


def git_executable() -> str:
    """Avoid the small cmd/git.exe trampoline; instrument the actual Git binary."""
    found = shutil.which('git')
    if not found:
        raise RuntimeError('git.exe is required on PATH')
    result = subprocess.run([found, '--exec-path'], capture_output=True, check=True)
    exec_dir = Path(result.stdout.decode().strip())
    candidates = [exec_dir.parent.parent / 'bin' / 'git.exe', Path(found)]
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_size > 100000:
            return str(candidate.resolve())
    raise RuntimeError('Specify a Git for Windows installation with its full git.exe')


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [git_executable(), '-C', str(repo), *args], capture_output=True, timeout=30)
    if check and result.returncode:
        raise RuntimeError(f'Git command failed ({result.returncode}): '
                           + result.stderr.decode('utf-8', 'replace'))
    return result


def sensitive_path(path: str, policy: Policy, repo_root: Path | None = None) -> bool:
    normalized = posixpath.normpath(path.replace('\\', '/').strip('/')).casefold()
    name = normalized.rsplit('/', 1)[-1]
    if (any(directory == '.' or normalized == directory or normalized.startswith(directory + '/')
            for directory in policy.relative_directories)
            or any(fnmatch.fnmatchcase(name, pattern) for pattern in policy.file_patterns)
            or any(fnmatch.fnmatchcase(normalized, pattern) for pattern in policy.relative_file_patterns)):
        return True
    if repo_root is None:
        return False
    absolute = posixpath.normpath(str(repo_root).replace('\\', '/') + '/' + normalized).casefold()
    return (any(fnmatch.fnmatchcase(absolute, pattern) for pattern in policy.absolute_file_patterns)
            or any(absolute == str(directory).replace('\\', '/').rstrip('/').casefold()
                   or absolute.startswith(str(directory).replace('\\', '/').rstrip('/').casefold() + '/')
                   for directory in policy.absolute_directories))


def repository_worktree(repo: Path) -> Path | None:
    result = git(repo, 'rev-parse', '--show-toplevel', check=False)
    if result.returncode == 0:
        return Path(result.stdout.decode('utf-8', 'replace').strip())
    if git(repo, 'rev-parse', '--is-bare-repository', check=False).stdout.strip() == b'true':
        return None
    # Scanning commonly uses -C <repo>/.git, where --show-toplevel is unavailable.
    gitdir = Path(git(repo, 'rev-parse', '--absolute-git-dir').stdout.decode().strip())
    configured = git(repo, 'config', '--get', 'core.worktree', check=False)
    if configured.returncode == 0:
        worktree = Path(configured.stdout.decode().strip())
        return worktree if worktree.is_absolute() else gitdir / worktree
    return gitdir.parent if gitdir.name.casefold() == '.git' else None


def scan_history(repo: Path, commit: str, policy: Policy, repo_root: Path | None = None) -> dict:
    """Conservative: examine all ancestry of the exact commit, not just the worktree.

    Enumerate every tree, so renames and deleted secrets remain visible. Cache
    content results by blob OID but check path rules for each path separately.
    No secret values enter the report. Resource limits result in a deny decision.
    """
    repo_root = repo_root or repository_worktree(repo)
    findings = []
    seen_findings = set()
    cache: dict[str, list[str]] = {}
    total_bytes = entries = 0
    # Replacement objects/grafts could otherwise hide the real outgoing ancestry.
    if git(repo, 'replace', '-l').stdout.strip():
        return {'deny': True, 'findings': [{'rule': 'replacement-objects-present'}]}
    graft_file = Path(git(repo, 'rev-parse', '--git-path', 'info/grafts').stdout.decode().strip())
    if not graft_file.is_absolute():
        graft_file = repo / graft_file
    if graft_file.is_file() and graft_file.stat().st_size:
        return {'deny': True, 'findings': [{'rule': 'legacy-grafts-present'}]}
    if git(repo, 'rev-parse', '--is-shallow-repository').stdout.strip() == b'true':
        return {'deny': True, 'findings': [{'rule': 'shallow-history'}]}
    commits = git(repo, 'rev-list', '--max-count', str(MAX_COMMITS + 1), commit).stdout.decode().splitlines()
    if len(commits) > MAX_COMMITS:
        return {'deny': True, 'findings': [{'rule': 'commit-limit'}]}

    def record(path: str, oid: str, rule: str, tree_commit: str):
        key = (path, oid, rule)
        if key not in seen_findings:
            seen_findings.add(key)
            findings.append({'path': path, 'blob': oid, 'rule': rule, 'commit': tree_commit})

    for tree_commit in commits:
        tree = git(repo, 'ls-tree', '-r', '-z', tree_commit).stdout
        for entry in tree.split(b'\0'):
            if not entry:
                continue
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                record('', '', 'tree-entry-limit', tree_commit)
                return {'deny': True, 'findings': findings}
            meta, path_bytes = entry.split(b'\t', 1)
            mode, objtype, oid_bytes = meta.split()
            oid = oid_bytes.decode('ascii')
            path = path_bytes.decode('utf-8', 'replace')
            if objtype != b'blob':
                continue  # gitlinks contain commit IDs, not embedded submodule files.
            if sensitive_path(path, policy, repo_root):
                record(path, oid, 'sensitive-path', tree_commit)
            if oid not in cache:
                size = int(git(repo, 'cat-file', '-s', oid).stdout)
                total_bytes += size
                if size > MAX_BLOB_BYTES or total_bytes > MAX_TOTAL_BYTES:
                    record(path, oid, 'blob-scan-limit', tree_commit)
                    return {'deny': True, 'findings': findings}
                content = git(repo, 'cat-file', 'blob', oid).stdout
                cache[oid] = content_findings(content, policy)
            for rule in cache[oid]:
                record(path, oid, rule, tree_commit)
    return {'deny': bool(findings), 'findings': findings,
            'commits_scanned': len(commits), 'blobs_scanned': len(cache),
            'bytes_scanned': total_bytes, 'tree_entries': entries}

