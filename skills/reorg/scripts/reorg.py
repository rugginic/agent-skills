#!/usr/bin/env python3
"""reorg: deterministic local and Google Drive file organization CLI.

Subcommands:
  audit     Metadata-only tree/size/extension/empty/nesting/duplicate snapshot.
  extract   Bounded content prep (PDF/Office/text, vision flags, credential guard).
  plan      Build and preview a validated, fingerprinted source->target plan.
  validate  Re-validate a plan against path safety, rules, drift, and conflicts.
  apply     Execute an approved plan (in-place move default; --copy for additive).
  undo      Deterministically reverse an applied in-place move journal.

Pure mechanics only (stdlib + PyYAML). Zero LLM calls. Zero file deletion.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import csv
import datetime
import errno
import fnmatch
import hashlib
import io
import json
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from typing import Any

import yaml

SCHEMA_VERSION = 3
DEFAULT_STATE_DIR = os.path.expanduser('~/.local/state/reorg')

# Default ignored directory / file name patterns
DEFAULT_IGNORES = (
    '.git',
    '.Trash*',
    'node_modules',
    'ObsidianVault',
)

# Forbidden local roots (exact resolved paths)
FORBIDDEN_LOCAL_ROOTS = {
    '/',
    '/bin',
    '/boot',
    '/dev',
    '/etc',
    '/lib',
    '/lib64',
    '/proc',
    '/root',
    '/sbin',
    '/sys',
    '/usr',
    '/var',
}

# Google Drive MIME constants
DRIVE_FOLDER_MIME = 'application/vnd.google-apps.folder'
DRIVE_SHORTCUT_MIME = 'application/vnd.google-apps.shortcut'
DRIVE_DANGLING_MIME = 'application/vnd.google-apps.shortcut.dangling'
DRIVE_NATIVE_PREFIX = 'application/vnd.google-apps.'
DRIVE_META_FIELDS = (
    'id,name,mimeType,parents,size,md5Checksum,modifiedTime,'
    'version,headRevisionId,shortcutDetails,trashed'
)

# Copyable Google Workspace native types -> (display export ext, export text mime)
COPYABLE_NATIVE_MIMES: dict[str, tuple[str, str, str | None]] = {
    'application/vnd.google-apps.document': (
        '.docx',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain',
    ),
    'application/vnd.google-apps.spreadsheet': (
        '.xlsx',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/csv',
    ),
    'application/vnd.google-apps.presentation': (
        '.pptx',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'text/plain',
    ),
    'application/vnd.google-apps.drawing': (
        '.svg',
        'image/svg+xml',
        None,
    ),
}

UNSUPPORTED_NATIVE_LABELS: dict[str, str] = {
    'application/vnd.google-apps.map': 'Google My Maps',
    'application/vnd.google-apps.form': 'Google Form',
    'application/vnd.google-apps.site': 'Google Site',
    'application/vnd.google-apps.script': 'Apps Script',
    'application/vnd.google-apps.jam': 'Google Jamboard',
    'application/vnd.google-apps.fusiontable': 'Google Fusion Table',
    'application/vnd.google-apps.drive-sdk': 'Third-party Drive app object',
}

# File type classification for extract
ARCHIVE_COMPOUND_EXTS = (
    '.tar.gz',
    '.tar.bz2',
    '.tar.xz',
    '.tar.zst',
    '.tar.lz',
    '.tar.lz4',
)
ARCHIVE_EXTS = {
    '.zip', '.7z', '.rar', '.tar', '.tgz', '.tbz2', '.txz', '.tzst',
    '.gz', '.bz2', '.xz', '.zst', '.iso', '.dmg', '.cab', '.ar', '.cpio',
}
IMAGE_EXTS = {
    '.png', '.jpg', '.jpeg', '.webp', '.gif', '.bmp', '.tif', '.tiff',
    '.heic', '.heif', '.avif', '.ico',
}
TEXT_EXTS = {
    '.txt', '.md', '.markdown', '.rst', '.csv', '.tsv', '.json', '.jsonl',
    '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.xml', '.html',
    '.htm', '.css', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py',
    '.sh', '.bash', '.zsh', '.fish', '.rb', '.go', '.rs', '.java', '.kt',
    '.c', '.h', '.cpp', '.hpp', '.cs', '.php', '.sql', '.r', '.tex',
    '.log', '.eml', '.ics', '.vcf', '.svg', '.org', '.adoc', '.rtf',
}

# Credential detection patterns (applied BEFORE text ever leaves extract)
CREDENTIAL_DIR_SEGMENTS = {'.aws', '.ssh', '.gnupg', '.kube'}
CREDENTIAL_NAME_PATTERNS = (
    '.env',
    '.env.*',
    'id_rsa',
    'id_rsa.*',
    'id_ed25519',
    'id_ed25519.*',
    'id_ecdsa',
    'id_ecdsa.*',
    'id_dsa',
    'id_dsa.*',
    '*.pem',
    '*.key',
    '*.p12',
    '*.pfx',
    '*.jks',
    '*.kdbx',
    '.netrc',
    '.npmrc',
    '.pypirc',
    '.pgpass',
    '.htpasswd',
    'kubeconfig',
    'credentials',
    'credentials.*',
    '*credentials*.json',
    '*credentials*.yaml',
    '*credentials*.yml',
    '*secret*.json',
    '*secret*.yaml',
    '*secret*.yml',
    '*secret*.env',
    'service-account*.json',
    'service_account*.json',
    'token.json',
    'client_secret*.json',
)
CREDENTIAL_CONTENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ('private_key_block', re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----')),
    ('aws_access_key', re.compile(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b')),
    ('github_token', re.compile(r'\b(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b')),
    ('gitlab_token', re.compile(r'\bglpat-[A-Za-z0-9_\-]{16,}\b')),
    ('slack_token', re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]{10,}\b')),
    ('api_key_token', re.compile(r'\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}\b')),
    ('db_uri_password', re.compile(r'\b(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://[^/\s:@]{1,64}:[^/\s@]{3,}@')),
    (
        'password_assignment',
        re.compile(
            r'(?im)^\s*(?:export\s+)?'
            r'[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|CLIENT_SECRET)\s*'
            r'[:=]\s*["\']?(?!(?:<|\$\{|change.?me|your_|example|placeholder|xxx+|none|null|false|true|""|\'\'))\S{6,}'
        ),
    ),
]

MAX_ZIP_XML_BYTES = 4 * 1024 * 1024  # 4 MiB decompression guard for Office XML
MIN_PDF_TEXT_CHARS = 20
YEAR_RE = re.compile(r'(?<!\d)((?:19|20)\d{2})(?!\d)')
DRIVE_REMOTE_RE = re.compile(r'^([A-Za-z0-9_.-]+):(.*)$')
DRIVE_ID_PART_RE = re.compile(r'[\w-]+', re.ASCII)


# ---------------------------------------------------------------------------
# General helpers & safety primitives
# ---------------------------------------------------------------------------

def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def utc_stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def format_bytes(num: int) -> str:
    if num < 0:
        return 'native'
    value = float(num)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if abs(value) < 1024.0 or unit == 'TiB':
            return f'{int(value)} {unit}' if unit == 'B' else f'{value:.1f} {unit}'
        value /= 1024.0
    return f'{num} B'


def is_drive_target(target: str) -> bool:
    if not target or target.startswith(('/', '.', '~')):
        return False
    return bool(DRIVE_REMOTE_RE.match(target))


def parse_drive_target(target: str) -> tuple[str, str]:
    m = DRIVE_REMOTE_RE.match(target)
    require(bool(m), f'Invalid Drive target: {target}')
    remote = m.group(1)
    subpath = m.group(2).strip('/')
    if subpath:
        require(safe_rel_path(subpath), f'Unsafe Drive subpath: {subpath}')
    return remote, subpath


def safe_rel_path(path: str) -> bool:
    if not isinstance(path, str) or not path or '\0' in path:
        return False
    if path.startswith('/') or path.endswith('/') or '\\' in path:
        return False
    parts = path.split('/')
    return all(p not in ('', '.', '..') for p in parts)


def parent_chain(rel_path: str) -> list[str]:
    parts = rel_path.split('/')
    return ['/'.join(parts[:i]) for i in range(1, len(parts))]


def validate_root_safety(target: str, *, allow_home: bool = False) -> str:
    """Validate and normalize a local or Drive root. Refuses `/` and `$HOME`."""
    if is_drive_target(target):
        remote, subpath = parse_drive_target(target)
        return f'{remote}:{subpath}'
    expanded = os.path.expanduser(target)
    real = os.path.realpath(expanded)
    home = os.path.realpath(os.path.expanduser('~'))
    require(real not in FORBIDDEN_LOCAL_ROOTS, f'Refusing forbidden root path: {real}')
    if not allow_home:
        require(real != home, f'Refusing $HOME root path: {real}')
    return real


def safe_join_local(root_real: str, rel_path: str) -> str:
    require(safe_rel_path(rel_path), f'Unsafe relative path: {rel_path}')
    candidate = os.path.normpath(os.path.join(root_real, rel_path))
    require(os.path.commonpath([root_real, candidate]) == root_real and candidate != root_real,
            f'Path escapes root: {rel_path}')
    return candidate


def check_no_symlink_escape(root_real: str, path_abs: str) -> None:
    real = os.path.realpath(path_abs)
    require(os.path.commonpath([root_real, real]) == root_real,
            f'Symlink escapes root: {path_abs}')


def raw_id(ident: str) -> str:
    """Resolve Drive ID; rclone composite shortcut IDs are target-ID<TAB>shortcut-ID."""
    require(isinstance(ident, str) and bool(ident), 'Missing Drive ID')
    parts = ident.split('\t')
    require(len(parts) <= 2 and all(DRIVE_ID_PART_RE.fullmatch(p) for p in parts),
            f'Invalid Drive ID: {ident!r}')
    return parts[0]


def shortcut_id(ident: str) -> str | None:
    parts = ident.split('\t')
    require(len(parts) <= 2 and all(DRIVE_ID_PART_RE.fullmatch(p) for p in parts),
            f'Invalid Drive ID: {ident!r}')
    return parts[1] if len(parts) == 2 else None


def escape_drive_display_name(raw_name: str) -> str:
    """Escape raw Drive filename characters that cannot live inside a POSIX path segment."""
    out = raw_name.replace('/', '／')
    chars = []
    for ch in out:
        code = ord(ch)
        if 0 <= code <= 0x20 and ch != ' ':
            chars.append(chr(0x2400 + code))
        else:
            chars.append(ch)
    return ''.join(chars)


def has_escaped_name(name: str) -> bool:
    return any(c in '／‛' or '\u2400' <= c <= '\u2421' for c in name)


def split_name_ext(name: str, *, native: bool = False) -> tuple[str, str]:
    if native:
        return name, ''
    lower = name.lower()
    for cext in ARCHIVE_COMPOUND_EXTS:
        if lower.endswith(cext) and len(name) > len(cext):
            return name[:-len(cext)], name[-len(cext):]
    return os.path.splitext(name)


def restore_original_drive_name(display: str, target_name: str, original: str, *, native: bool = False) -> str:
    """Apply any deterministic collision suffix (_2, _3, ...) from target_name back onto original raw Drive name."""
    if display == target_name:
        return original
    stem, ext = split_name_ext(display, native=native)
    suffix_end = len(target_name) - len(ext) if ext else len(target_name)
    if target_name.startswith(stem) and (not ext or target_name.endswith(ext)):
        suffix = target_name[len(stem):suffix_end]
        if re.fullmatch(r'_[2-9]\d*|_1\d+', suffix):
            raw_stem, raw_ext = split_name_ext(original, native=native)
            return raw_stem + suffix + raw_ext
    # Explicit rename by user/agent (not just a collision suffix)
    return target_name


def is_ignored(rel_path: str, ignore_patterns: tuple[str, ...]) -> bool:
    parts = rel_path.split('/')
    for pat in ignore_patterns:
        if '/' in pat:
            if fnmatch.fnmatchcase(rel_path, pat) or fnmatch.fnmatchcase(rel_path, pat.rstrip('/') + '/*'):
                return True
        else:
            if any(fnmatch.fnmatchcase(seg, pat) for seg in parts):
                return True
    return False


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def ensure_state_dir(state_dir: str | None = None) -> str:
    target = os.path.expanduser(state_dir or DEFAULT_STATE_DIR)
    os.makedirs(target, exist_ok=True)
    return target


# ---------------------------------------------------------------------------
# Optional external rules (--rules <path>)
# ---------------------------------------------------------------------------

def load_rules(rules_path: str | None) -> dict[str, Any] | None:
    if not rules_path:
        return None
    abs_path = os.path.realpath(os.path.expanduser(rules_path))
    with open(abs_path, 'rb') as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    data = yaml.safe_load(raw.decode('utf-8')) or {}
    require(isinstance(data, dict), f'Rules file must be a YAML mapping: {rules_path}')

    ignore = data.get('ignore') or []
    require(isinstance(ignore, list) and all(isinstance(x, str) for x in ignore),
            'rules.ignore must be a list of glob strings')

    allowed_roots = data.get('allowed_roots')
    if allowed_roots is None and isinstance(data.get('areas'), list):
        allowed_roots = [str(a) for a in data['areas']]
    if allowed_roots is not None:
        require(isinstance(allowed_roots, list) and all(isinstance(x, str) and safe_rel_path(x) for x in allowed_roots),
                'rules.allowed_roots must be a list of safe folder names')

    max_depth = data.get('max_depth')
    if max_depth is None and isinstance(data.get('naming'), dict):
        max_depth = data['naming'].get('max_depth')
    if max_depth is not None:
        require(isinstance(max_depth, int) and max_depth >= 1, 'rules.max_depth must be an integer >= 1')

    rule_entries = data.get('rules') or []
    require(isinstance(rule_entries, list), 'rules.rules must be a list')
    normalized_rules = []
    for idx, entry in enumerate(rule_entries):
        require(isinstance(entry, dict) and isinstance(entry.get('match'), str) and entry['match'],
                f'rules[{idx}] must define a non-empty string "match"')
        action = entry.get('action', 'move')
        require(action in ('move', 'copy', 'skip'), f'rules[{idx}] invalid action: {action}')
        target = entry.get('target', '')
        if action != 'skip':
            require(isinstance(target, str) and bool(target), f'rules[{idx}] must define "target"')
        normalized_rules.append({
            'match': entry['match'],
            'action': action,
            'target': target,
            'reason': str(entry.get('reason', f'rule:{entry["match"]}')),
        })

    return {
        'path': abs_path,
        'sha256': digest,
        'ignore': tuple(ignore),
        'allowed_roots': list(allowed_roots) if allowed_roots is not None else None,
        'max_depth': max_depth,
        'rules': normalized_rules,
    }


def extract_year_hint(rel_path: str, mtime_iso: str | None = None) -> str:
    years = YEAR_RE.findall(rel_path)
    if len(set(years)) == 1:
        return years[0]
    if years:
        return years[-1]
    if mtime_iso and len(mtime_iso) >= 4 and mtime_iso[:4].isdigit():
        return mtime_iso[:4]
    return 'unknown'


def match_rule(rules_cfg: dict[str, Any], rel_path: str, mtime_iso: str | None = None) -> dict[str, str] | None:
    """Return best matching rule (deepest pattern, then longest) with expanded target."""
    hits = []
    for entry in rules_cfg.get('rules', []):
        pat = entry['match']
        if fnmatch.fnmatchcase(rel_path, pat) or fnmatch.fnmatchcase(rel_path, pat.rstrip('/') + '/*'):
            hits.append(entry)
    if not hits:
        return None
    best = max(hits, key=lambda e: (e['match'].count('/'), len(e['match'])))
    if best['action'] == 'skip':
        return {'action': 'skip', 'target': '', 'reason': best['reason']}
    name = os.path.basename(rel_path)
    stem, ext = split_name_ext(name)
    parent = os.path.dirname(rel_path)
    # Compute relative tail below matched prefix if pattern has static prefix
    pat_prefix = best['match'].split('*')[0].rstrip('/')
    if pat_prefix and rel_path.startswith(pat_prefix + '/'):
        rel_tail = rel_path[len(pat_prefix) + 1:]
    else:
        rel_tail = name
    year = extract_year_hint(rel_path, mtime_iso)
    rendered = best['target'].format(
        name=name,
        stem=stem,
        ext=ext,
        rel=rel_tail,
        parent=parent,
        year=year,
    )
    rendered = '/'.join(seg for seg in rendered.split('/') if seg)
    return {'action': best['action'], 'target': rendered, 'reason': best['reason']}


# ---------------------------------------------------------------------------
# Google Drive API client (using configured rclone credentials, zero logging)
# ---------------------------------------------------------------------------

def run_rclone(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(['rclone', *args], capture_output=True, text=True)


class DriveClient:
    """Direct Google Drive v3 API client using configured rclone OAuth tokens.

    Safety invariants:
    - Never logs OAuth tokens or secrets.
    - Thread-safe proactive token refresh + safe 401 retry before mutation.
    - Never retries non-GET writes (POST/PATCH) on 5xx or network errors.
    - Never exposes DELETE or trashing methods.
    """

    def __init__(self, remote: str):
        self.remote = remote.rstrip(':')
        self.auth_lock = threading.Lock()
        self.token = ''
        self.expires = 0.0
        self.root = 'root'
        self.refresh()

    def refresh(self) -> None:
        about = run_rclone('about', f'{self.remote}:', '--json')
        require(about.returncode == 0, f'rclone authentication failed for {self.remote}:')
        dumped = run_rclone('config', 'dump')
        require(dumped.returncode == 0, 'Cannot read rclone configuration')
        all_cfg = json.loads(dumped.stdout)
        require(self.remote in all_cfg, f'Unknown rclone remote: {self.remote}')
        cfg = all_cfg[self.remote]
        require(cfg.get('type') == 'drive', f'Remote {self.remote}: is not a Google Drive remote')
        require(not cfg.get('shared_with_me'), f'Unsupported shared_with_me config on {self.remote}:')
        token_data = json.loads(cfg['token'])
        self.token = token_data['access_token']
        self.expires = datetime.datetime.fromisoformat(
            token_data['expiry'].replace('Z', '+00:00')
        ).timestamp()
        self.root = cfg.get('root_folder_id') or cfg.get('team_drive') or 'root'

    def _raw_request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        *,
        expect_json: bool = True,
        max_bytes: int | None = None,
    ) -> Any:
        require(method in ('GET', 'POST', 'PATCH'), f'Disallowed Drive HTTP method: {method}')
        query_params = {'supportsAllDrives': 'true', **(params or {})}
        url = 'https://www.googleapis.com/drive/v3/' + path + '?' + urllib.parse.urlencode(query_params)
        payload = None if body is None else json.dumps(body).encode('utf-8')
        for attempt in range(4):
            if time.time() >= self.expires - 5:
                with self.auth_lock:
                    if time.time() >= self.expires - 5:
                        self.refresh()
            headers = {'Authorization': 'Bearer ' + self.token}
            if payload is not None:
                headers['Content-Type'] = 'application/json'
            req = urllib.request.Request(url, method=method, data=payload, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=90) as resp:
                    if expect_json:
                        return json.load(resp)
                    return resp.read(max_bytes) if max_bytes is not None else resp.read()
            except urllib.error.HTTPError as err:
                code = err.code
                # A 401 means auth was rejected before any mutation; safe to refresh and retry.
                if code == 401 and attempt < 3:
                    with self.auth_lock:
                        self.refresh()
                    continue
                if method != 'GET' or attempt == 3 or code not in (429, 500, 502, 503, 504):
                    raise RuntimeError(f'Drive {method} failed (HTTP {code}); no credentials logged') from None
            except (TimeoutError, OSError):
                if method != 'GET' or attempt == 3:
                    raise RuntimeError(
                        f'Drive {method} network failure; inspect destination before any retry'
                    ) from None
            time.sleep(2 ** attempt)
        raise RuntimeError(f'Drive {method} failed after retries')

    def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._raw_request(method, path, params=params, body=body, expect_json=True)

    def metadata(self, ident: str) -> dict[str, Any]:
        return self.request(
            'GET',
            'files/' + urllib.parse.quote(raw_id(ident), safe=''),
            {'fields': DRIVE_META_FIELDS},
        )

    def children(self, parent_id: str, name: str | None = None) -> list[dict[str, Any]]:
        esc = lambda s: s.replace('\\', '\\\\').replace("'", "\\'")
        query = f"'{esc(parent_id)}' in parents and trashed = false"
        if name is not None:
            query += f" and name = '{esc(name)}'"
        params: dict[str, Any] = {
            'q': query,
            'fields': f'nextPageToken,files({DRIVE_META_FIELDS})',
            'pageSize': 1000,
            'includeItemsFromAllDrives': 'true',
        }
        items: list[dict[str, Any]] = []
        while True:
            resp = self.request('GET', 'files', params)
            items.extend(resp.get('files', []))
            token = resp.get('nextPageToken')
            if not token:
                return items
            params['pageToken'] = token

    def resolve_folder(self, subpath: str, *, create: bool = False) -> str:
        """Resolve a slash-separated folder subpath starting at drive.root."""
        current = self.root
        if not subpath:
            return current
        for seg in subpath.split('/'):
            matches = [c for c in self.children(current, seg) if c.get('mimeType') == DRIVE_FOLDER_MIME]
            if len(matches) > 1:
                raise ValueError(f'Ambiguous Drive folder "{seg}" inside {subpath}')
            if not matches:
                if create:
                    current = self.mkdir(seg, current)
                    continue
                raise FileNotFoundError(f'Drive folder not found: {subpath}')
            current = matches[0]['id']
        return current

    def mkdir(self, name: str, parent_id: str) -> str:
        resp = self.request(
            'POST',
            'files',
            {'fields': DRIVE_META_FIELDS},
            {'name': name, 'mimeType': DRIVE_FOLDER_MIME, 'parents': [parent_id]},
        )
        return resp['id']

    def copy(self, ident: str, name: str, parent_id: str, modified: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {'name': name, 'parents': [parent_id]}
        if modified:
            body['modifiedTime'] = modified
        return self.request(
            'POST',
            'files/' + urllib.parse.quote(raw_id(ident), safe='') + '/copy',
            {'fields': DRIVE_META_FIELDS},
            body,
        )

    def move(
        self,
        ident: str,
        name: str,
        add_parent: str | None = None,
        remove_parents: list[str] | None = None,
    ) -> dict[str, Any]:
        """Server-side move/rename via Drive PATCH files/{id}."""
        if remove_parents:
            require(bool(add_parent), 'Refusing to detach Drive parents without a destination parent')
        params: dict[str, Any] = {'fields': DRIVE_META_FIELDS}
        if add_parent:
            params['addParents'] = add_parent
        if remove_parents:
            params['removeParents'] = ','.join(remove_parents)
        return self.request(
            'PATCH',
            'files/' + urllib.parse.quote(raw_id(ident), safe=''),
            params,
            {'name': name},
        )

    def download_bytes(self, ident: str, max_bytes: int) -> bytes:
        return self._raw_request(
            'GET',
            'files/' + urllib.parse.quote(raw_id(ident), safe=''),
            {'alt': 'media'},
            expect_json=False,
            max_bytes=max_bytes,
        )

    def export_bytes(self, ident: str, mime_type: str, max_bytes: int) -> bytes:
        return self._raw_request(
            'GET',
            'files/' + urllib.parse.quote(raw_id(ident), safe='') + '/export',
            {'mimeType': mime_type},
            expect_json=False,
            max_bytes=max_bytes,
        )


# ---------------------------------------------------------------------------
# Unified inventory walking (Local + Google Drive API)
# ---------------------------------------------------------------------------

def walk_local_inventory(
    root_real: str,
    *,
    ignore_patterns: tuple[str, ...] = DEFAULT_IGNORES,
    max_depth: int | None = None,
) -> dict[str, Any]:
    require(os.path.isdir(root_real), f'Directory not found: {root_real}')
    files: list[dict[str, Any]] = []
    folders: list[dict[str, Any]] = []

    for dirpath, dirnames, filenames in os.walk(root_real, topdown=True, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root_real)
        rel_dir = '' if rel_dir == '.' else rel_dir.replace(os.sep, '/')
        depth = 0 if not rel_dir else rel_dir.count('/') + 1

        # Filter ignored subdirectories in-place so os.walk prunes them
        kept_dirs = []
        for d in sorted(dirnames):
            child_rel = f'{rel_dir}/{d}' if rel_dir else d
            if is_ignored(child_rel, ignore_patterns):
                continue
            full_d = os.path.join(dirpath, d)
            if os.path.islink(full_d):
                continue
            folders.append({'path': child_rel, 'depth': depth + 1})
            if max_depth is None or depth + 1 < max_depth:
                kept_dirs.append(d)
        dirnames[:] = kept_dirs

        if max_depth is not None and depth >= max_depth:
            continue

        for fname in sorted(filenames):
            rel_file = f'{rel_dir}/{fname}' if rel_dir else fname
            if is_ignored(rel_file, ignore_patterns):
                continue
            full_f = os.path.join(dirpath, fname)
            try:
                st = os.lstat(full_f)
            except OSError:
                continue
            if os.path.islink(full_f):
                continue
            mtime_iso = datetime.datetime.fromtimestamp(
                st.st_mtime, tz=datetime.timezone.utc
            ).strftime('%Y-%m-%dT%H:%M:%SZ')
            files.append({
                'path': rel_file,
                'name': fname,
                'size': st.st_size,
                'mtime_ns': st.st_mtime_ns,
                'mtime': mtime_iso,
                'depth': depth + 1,
                'mime': mimetypes.guess_type(fname)[0] or 'application/octet-stream',
                'is_native': False,
                'unsupported_native': False,
            })

    return {'backend': 'local', 'root': root_real, 'files': files, 'folders': folders}


def walk_drive_inventory(
    drive: DriveClient,
    subpath: str,
    *,
    ignore_patterns: tuple[str, ...] = DEFAULT_IGNORES,
    max_depth: int | None = None,
) -> dict[str, Any]:
    """Walk Google Drive directly via Drive API so unsupported native objects are surfaced."""
    root_id = drive.resolve_folder(subpath)
    files: list[dict[str, Any]] = []
    folders: list[dict[str, Any]] = []
    unsupported_native: list[dict[str, Any]] = []
    shortcuts: list[dict[str, Any]] = []

    queue: collections.deque[tuple[str, str, int]] = collections.deque([(root_id, '', 0)])
    visited_folders = {root_id}

    while queue:
        folder_id, rel_dir, depth = queue.popleft()
        children = sorted(
            drive.children(folder_id),
            key=lambda c: (c.get('name', ''), c.get('id', '')),
        )
        # Track duplicate display names in the same folder deterministically
        seen_names: collections.Counter[str] = collections.Counter()
        for item in children:
            raw_name = item.get('name', '')
            display_name = escape_drive_display_name(raw_name)
            seen_names[display_name] += 1
            rel_path = f'{rel_dir}/{display_name}' if rel_dir else display_name
            if is_ignored(rel_path, ignore_patterns):
                continue
            mime = item.get('mimeType', 'application/octet-stream')
            item_id = item['id']

            if mime == DRIVE_FOLDER_MIME:
                folders.append({'path': rel_path, 'id': item_id, 'raw_name': raw_name, 'depth': depth + 1})
                if (max_depth is None or depth + 1 < max_depth) and item_id not in visited_folders:
                    visited_folders.add(item_id)
                    queue.append((item_id, rel_path, depth + 1))
                continue

            if max_depth is not None and depth >= max_depth:
                continue

            is_native = mime.startswith(DRIVE_NATIVE_PREFIX) and mime != DRIVE_SHORTCUT_MIME
            is_shortcut = mime == DRIVE_SHORTCUT_MIME
            is_copyable_native = mime in COPYABLE_NATIVE_MIMES
            is_unsupported_native = is_native and not is_copyable_native

            size_val = -1 if is_native else int(item.get('size', 0) or 0)
            entry: dict[str, Any] = {
                'path': rel_path,
                'name': display_name,
                'raw_name': raw_name,
                'id': item_id,
                'raw_id': item_id,
                'parents': list(item.get('parents') or [folder_id]),
                'size': size_val,
                'md5': item.get('md5Checksum', ''),
                'mtime': item.get('modifiedTime', ''),
                'version': str(item.get('version', '')),
                'head_revision_id': item.get('headRevisionId', ''),
                'mime': mime,
                'depth': depth + 1,
                'is_native': is_native,
                'copyable_native': is_copyable_native,
                'unsupported_native': is_unsupported_native,
                'is_shortcut': is_shortcut,
            }

            if is_shortcut:
                details = item.get('shortcutDetails') or {}
                target_id = details.get('targetId', '')
                target_mime = details.get('targetMimeType', '')
                entry['shortcut_target_id'] = target_id
                entry['shortcut_target_mime'] = target_mime
                if target_id:
                    entry['id'] = f'{target_id}\t{item_id}'
                    entry['raw_id'] = target_id
                else:
                    entry['mime'] = DRIVE_DANGLING_MIME
                shortcuts.append(entry)

            if is_unsupported_native:
                entry['unsupported_label'] = UNSUPPORTED_NATIVE_LABELS.get(mime, mime)
                unsupported_native.append(entry)

            files.append(entry)

    return {
        'backend': 'drive',
        'root': f'{drive.remote}:{subpath}',
        'root_id': root_id,
        'files': files,
        'folders': folders,
        'unsupported_native': unsupported_native,
        'shortcuts': shortcuts,
    }


# ---------------------------------------------------------------------------
# Subcommand: audit
# ---------------------------------------------------------------------------

def build_compact_tree(
    files: list[dict[str, Any]],
    folders: list[dict[str, Any]],
    max_depth: int = 3,
) -> list[str]:
    node_files: collections.Counter[str] = collections.Counter()
    node_bytes: collections.Counter[str] = collections.Counter()
    all_dirs: set[str] = {d['path'] for d in folders}

    for f in files:
        size = max(0, int(f.get('size', 0)))
        for p in parent_chain(f['path']):
            all_dirs.add(p)
            node_files[p] += 1
            node_bytes[p] += size

    children_map: dict[str, list[str]] = collections.defaultdict(list)
    for d in sorted(all_dirs):
        parent = os.path.dirname(d)
        children_map[parent].append(d)

    lines: list[str] = []

    def render(parent: str, depth: int) -> None:
        if depth >= max_depth:
            return
        for d in sorted(children_map.get(parent, [])):
            name = os.path.basename(d)
            count = node_files[d]
            size = node_bytes[d]
            indent = '  ' * depth
            lines.append(f'{indent}{name}/  [{count} files, {format_bytes(size)}]')
            render(d, depth + 1)

    render('', 0)
    return lines


def compute_audit(
    target: str,
    *,
    do_hash: bool = False,
    depth: int = 3,
    top: int = 10,
    deep_threshold: int = 5,
    extra_excludes: list[str] | None = None,
    include_ignored: bool = False,
    rules_path: str | None = None,
    drive: DriveClient | None = None,
) -> dict[str, Any]:
    rules_cfg = load_rules(rules_path)
    ignores = () if include_ignored else DEFAULT_IGNORES
    if rules_cfg:
        ignores = ignores + rules_cfg['ignore']
    if extra_excludes:
        ignores = ignores + tuple(extra_excludes)

    if is_drive_target(target):
        remote, subpath = parse_drive_target(target)
        client = drive or DriveClient(remote)
        inv = walk_drive_inventory(client, subpath, ignore_patterns=ignores)
    else:
        root_real = os.path.realpath(os.path.expanduser(target))
        inv = walk_local_inventory(root_real, ignore_patterns=ignores)

    files = inv['files']
    folders = inv['folders']
    total_size = sum(max(0, int(f['size'])) for f in files)

    # Folder recursive totals
    folder_size: collections.Counter[str] = collections.Counter()
    folder_count: collections.Counter[str] = collections.Counter()
    all_folder_paths = {d['path'] for d in folders}
    for f in files:
        sz = max(0, int(f['size']))
        for p in parent_chain(f['path']):
            all_folder_paths.add(p)
            folder_size[p] += sz
            folder_count[p] += 1

    largest_folders = [
        {'path': p, 'size': folder_size[p], 'files': folder_count[p]}
        for p, _ in sorted(folder_size.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
    ]
    largest_files = [
        {'path': f['path'], 'size': f['size']}
        for f in sorted(files, key=lambda x: (-max(0, int(x['size'])), x['path']))[:top]
    ]

    # Extension breakdown
    ext_counts: collections.Counter[str] = collections.Counter()
    ext_bytes: collections.Counter[str] = collections.Counter()
    for f in files:
        if f.get('is_native'):
            ext = f"native:{f['mime'].removeprefix(DRIVE_NATIVE_PREFIX)}"
        else:
            _, raw_ext = split_name_ext(f['name'])
            ext = raw_ext.lower() if raw_ext else '(no ext)'
        ext_counts[ext] += 1
        ext_bytes[ext] += max(0, int(f['size']))

    extensions = [
        {'ext': ext, 'count': ext_counts[ext], 'size': ext_bytes[ext]}
        for ext in sorted(ext_counts, key=lambda k: (-ext_counts[k], -ext_bytes[k], k))
    ]

    # Empty folders (folders with zero files anywhere beneath them)
    empty_folders = sorted(p for p in all_folder_paths if folder_count[p] == 0)

    # Deep-nesting hotspots
    hotspots = []
    for f in files:
        d = f['path'].count('/') + 1
        if d >= deep_threshold:
            hotspots.append({'path': f['path'], 'depth': d, 'kind': 'file'})
    for folder in folders:
        d = folder['path'].count('/') + 1
        if d >= deep_threshold:
            hotspots.append({'path': folder['path'], 'depth': d, 'kind': 'folder'})
    hotspots.sort(key=lambda h: (-h['depth'], h['path']))
    hotspots = hotspots[:top]

    # Optional exact duplicate report
    duplicates: list[dict[str, Any]] = []
    wasted_bytes = 0
    if do_hash:
        by_size: dict[int, list[dict[str, Any]]] = collections.defaultdict(list)
        for f in files:
            if int(f['size']) > 0 and not f.get('is_native'):
                by_size[int(f['size'])].append(f)
        by_hash: dict[tuple[int, str], list[dict[str, Any]]] = collections.defaultdict(list)
        for sz, group in by_size.items():
            if len(group) < 2:
                continue
            for f in group:
                if inv['backend'] == 'local':
                    digest = sha256_file(os.path.join(inv['root'], f['path']))
                else:
                    digest = f.get('md5', '')
                if digest:
                    by_hash[(sz, digest)].append(f)
        for (sz, digest), group in sorted(by_hash.items(), key=lambda kv: (-kv[0][0] * (len(kv[1]) - 1), kv[0][1])):
            if len(group) >= 2:
                wasted = sz * (len(group) - 1)
                wasted_bytes += wasted
                duplicates.append({
                    'hash': digest,
                    'size': sz,
                    'wasted_bytes': wasted,
                    'paths': sorted(f['path'] for f in group),
                })

    # Optional rules coverage
    rules_coverage = None
    if rules_cfg:
        matched = 0
        skipped = 0
        unmatched = 0
        for f in files:
            m = match_rule(rules_cfg, f['path'], f.get('mtime'))
            if m is None:
                unmatched += 1
            elif m['action'] == 'skip':
                skipped += 1
            else:
                matched += 1
        rules_coverage = {'matched': matched, 'skipped': skipped, 'unmatched': unmatched}

    report: dict[str, Any] = {
        'backend': inv['backend'],
        'root': inv['root'],
        'total_files': len(files),
        'total_folders': len(folders),
        'total_size': total_size,
        'largest_folders': largest_folders,
        'largest_files': largest_files,
        'extensions': extensions,
        'empty_folders': empty_folders,
        'deep_nesting_hotspots': hotspots,
        'duplicates': duplicates if do_hash else None,
        'duplicate_wasted_bytes': wasted_bytes if do_hash else None,
        'unsupported_native': [
            {'path': u['path'], 'id': u['id'], 'mime': u['mime'], 'label': u.get('unsupported_label', u['mime'])}
            for u in inv.get('unsupported_native', [])
        ],
        'shortcuts': [
            {
                'path': s['path'],
                'id': s['id'],
                'target_id': s.get('shortcut_target_id', ''),
                'target_mime': s.get('shortcut_target_mime', ''),
                'dangling': s['mime'] == DRIVE_DANGLING_MIME,
            }
            for s in inv.get('shortcuts', [])
        ],
        'rules_coverage': rules_coverage,
        'tree': build_compact_tree(files, folders, max_depth=depth),
    }
    return report


def format_audit_text(report: dict[str, Any]) -> str:
    lines = [
        f"Audit: {report['root']} ({report['backend']})",
        f"Summary: {report['total_files']} files, {report['total_folders']} folders, {format_bytes(report['total_size'])}",
    ]
    if report.get('rules_coverage'):
        rc = report['rules_coverage']
        lines.append(f"Rules coverage: {rc['matched']} matched, {rc['skipped']} skipped, {rc['unmatched']} unmatched")

    if report['tree']:
        lines.append('\nCompact tree:')
        lines.extend('  ' + line for line in report['tree'])

    if report['largest_folders']:
        lines.append('\nLargest folders:')
        for f in report['largest_folders']:
            lines.append(f"  {format_bytes(f['size']):>10}  ({f['files']} files)  {f['path']}/")

    if report['largest_files']:
        lines.append('\nLargest files:')
        for f in report['largest_files']:
            lines.append(f"  {format_bytes(f['size']):>10}  {f['path']}")

    if report['extensions']:
        lines.append('\nExtensions:')
        for e in report['extensions'][:15]:
            lines.append(f"  {e['ext']:<24} {e['count']:>6} files  {format_bytes(e['size']):>10}")

    if report['empty_folders']:
        lines.append(f"\nEmpty folders ({len(report['empty_folders'])}):")
        for p in report['empty_folders'][:20]:
            lines.append(f'  {p}/')

    if report['deep_nesting_hotspots']:
        lines.append('\nDeep-nesting hotspots:')
        for h in report['deep_nesting_hotspots']:
            lines.append(f"  depth={h['depth']}  ({h['kind']})  {h['path']}")

    if report['unsupported_native']:
        lines.append(f"\nUnsupported Drive native objects ({len(report['unsupported_native'])}):")
        for u in report['unsupported_native']:
            lines.append(f"  {u['path']}  [{u['label']}]  ({u['mime']})")

    if report['shortcuts']:
        lines.append(f"\nDrive shortcuts ({len(report['shortcuts'])}):")
        for s in report['shortcuts']:
            flag = ' [DANGLING]' if s['dangling'] else ''
            lines.append(f"  {s['path']}{flag} -> {s['target_id'] or 'missing'}")

    if report['duplicates'] is not None:
        lines.append(
            f"\nExact duplicates: {len(report['duplicates'])} groups "
            f"({format_bytes(report['duplicate_wasted_bytes'] or 0)} reclaimable)"
        )
        for g in report['duplicates'][:20]:
            lines.append(f"  [{format_bytes(g['size'])}] {g['hash'][:12]}:")
            for p in g['paths']:
                lines.append(f'    - {p}')

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Subcommand: extract (scoped content prep + credential guard)
# ---------------------------------------------------------------------------

def detect_credential_path(rel_path: str) -> str | None:
    parts = rel_path.split('/')
    lower_parts = [p.lower() for p in parts]
    for seg in lower_parts[:-1]:
        if seg in CREDENTIAL_DIR_SEGMENTS:
            return f'credential_dir:{seg}'
    name = parts[-1]
    lower_name = name.lower()
    for pat in CREDENTIAL_NAME_PATTERNS:
        if fnmatch.fnmatchcase(lower_name, pat):
            return f'credential_filename:{pat}'
    return None


def detect_credential_text(text: str) -> str | None:
    for label, pattern in CREDENTIAL_CONTENT_PATTERNS:
        if pattern.search(text):
            return f'credential_content:{label}'
    return None


def is_archive_name(name: str) -> bool:
    lower = name.lower()
    if any(lower.endswith(cext) for cext in ARCHIVE_COMPOUND_EXTS):
        return True
    _, ext = os.path.splitext(lower)
    return ext in ARCHIVE_EXTS


def is_image_name(name: str) -> bool:
    _, ext = os.path.splitext(name.lower())
    return ext in IMAGE_EXTS


def _safe_zip_read(zf: zipfile.ZipFile, member: str, max_bytes: int = MAX_ZIP_XML_BYTES) -> bytes:
    info = zf.getinfo(member)
    require(info.file_size <= max_bytes, f'Office XML entry exceeds safety limit: {member}')
    with zf.open(info, 'r') as fh:
        data = fh.read(max_bytes + 1)
    require(len(data) <= max_bytes, f'Office XML stream exceeds safety limit: {member}')
    return data


def extract_docx_text(source: str | bytes, max_chars: int) -> str:
    stream: Any = io.BytesIO(source) if isinstance(source, bytes) else source
    with zipfile.ZipFile(stream, 'r') as zf:
        names = set(zf.namelist())
        if 'word/document.xml' not in names:
            return ''
        xml_bytes = _safe_zip_read(zf, 'word/document.xml')
    root = ET.fromstring(xml_bytes)
    paragraphs: list[str] = []
    for elem in root.iter():
        if elem.tag.endswith('}p'):
            runs = [t.text for t in elem.iter() if t.tag.endswith('}t') and t.text]
            if runs:
                paragraphs.append(''.join(runs))
                if sum(len(p) + 1 for p in paragraphs) >= max_chars:
                    break
    return '\n'.join(paragraphs)[:max_chars]


def extract_xlsx_text(source: str | bytes, max_chars: int) -> str:
    stream: Any = io.BytesIO(source) if isinstance(source, bytes) else source
    with zipfile.ZipFile(stream, 'r') as zf:
        names = set(zf.namelist())
        shared: list[str] = []
        if 'xl/sharedStrings.xml' in names:
            s_root = ET.fromstring(_safe_zip_read(zf, 'xl/sharedStrings.xml'))
            for si in s_root.iter():
                if si.tag.endswith('}si'):
                    parts = [t.text for t in si.iter() if t.tag.endswith('}t') and t.text]
                    shared.append(''.join(parts))

        sheet_names: list[str] = []
        if 'xl/workbook.xml' in names:
            wb_root = ET.fromstring(_safe_zip_read(zf, 'xl/workbook.xml'))
            for sh in wb_root.iter():
                if sh.tag.endswith('}sheet') and sh.attrib.get('name'):
                    sheet_names.append(sh.attrib['name'])

        sheet_files = sorted(
            n for n in names if n.startswith('xl/worksheets/sheet') and n.endswith('.xml')
        )[:4]

        lines: list[str] = []
        for idx, sfile in enumerate(sheet_files):
            title = sheet_names[idx] if idx < len(sheet_names) else os.path.basename(sfile)
            lines.append(f'## Sheet: {title}')
            sh_root = ET.fromstring(_safe_zip_read(zf, sfile))
            row_count = 0
            for row in sh_root.iter():
                if not row.tag.endswith('}row'):
                    continue
                vals: list[str] = []
                for cell in row:
                    if not cell.tag.endswith('}c'):
                        continue
                    ctype = cell.attrib.get('t', '')
                    val = ''
                    if ctype == 's':
                        v = next((c.text for c in cell if c.tag.endswith('}v') and c.text), None)
                        if v is not None and v.isdigit() and int(v) < len(shared):
                            val = shared[int(v)]
                    elif ctype == 'inlineStr':
                        val = ''.join(t.text for t in cell.iter() if t.tag.endswith('}t') and t.text)
                    else:
                        val = next((c.text for c in cell if c.tag.endswith('}v') and c.text), '')
                    if val != '':
                        vals.append(val.strip())
                if vals:
                    lines.append(' | '.join(vals))
                    row_count += 1
                if row_count >= 30 or sum(len(x) + 1 for x in lines) >= max_chars:
                    break
            if sum(len(x) + 1 for x in lines) >= max_chars:
                break
    return '\n'.join(lines)[:max_chars]


def extract_pptx_text(source: str | bytes, max_chars: int) -> str:
    stream: Any = io.BytesIO(source) if isinstance(source, bytes) else source
    with zipfile.ZipFile(stream, 'r') as zf:
        slides = sorted(
            n for n in zf.namelist() if re.fullmatch(r'ppt/slides/slide\d+\.xml', n)
        )[:10]
        chunks: list[str] = []
        for sfile in slides:
            root = ET.fromstring(_safe_zip_read(zf, sfile))
            texts = [t.text.strip() for t in root.iter() if t.tag.endswith('}t') and t.text and t.text.strip()]
            if texts:
                chunks.append(' '.join(texts))
            if sum(len(c) + 1 for c in chunks) >= max_chars:
                break
    return '\n'.join(chunks)[:max_chars]


def extract_pdf_text(source: str | bytes, max_chars: int) -> tuple[str | None, str | None]:
    """Run pdftotext on first 5 pages. Returns (text, error_reason)."""
    pdftotext_bin = shutil.which('pdftotext')
    if not pdftotext_bin:
        return None, 'pdftotext not installed'
    cmd = [pdftotext_bin, '-f', '1', '-l', '5', '-layout', '-' if isinstance(source, bytes) else source, '-']
    try:
        proc = subprocess.run(
            cmd,
            input=source if isinstance(source, bytes) else None,
            capture_output=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        return None, 'pdftotext timeout'
    except OSError as err:
        return None, f'pdftotext failed: {err}'
    if proc.returncode != 0:
        return None, 'pdftotext non-zero exit'
    text = proc.stdout.decode('utf-8', errors='replace')
    cleaned = re.sub(r'\n{3,}', '\n\n', text).strip()
    return cleaned[:max_chars], None


def extract_plain_text_bytes(raw: bytes, max_chars: int) -> str | None:
    if b'\x00' in raw[:8192]:
        return None
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = raw.decode('latin-1', errors='replace')
    return text.strip()[:max_chars]


def _finalize_extracted_text(base: dict[str, Any], text: str | None) -> dict[str, Any]:
    if not text:
        return {**base, 'status': 'empty_text', 'text': None}
    cred = detect_credential_text(text)
    if cred:
        return {**base, 'status': 'credential_skipped', 'reason': cred, 'text': None}
    return {**base, 'status': 'extracted', 'text': text}


def extract_scope(
    target: str,
    *,
    max_depth: int = 3,
    max_files: int = 100,
    max_chars: int = 4000,
    max_bytes: int = 25 * 1024 * 1024,
    extra_excludes: list[str] | None = None,
    include_ignored: bool = False,
    rules_path: str | None = None,
    drive: DriveClient | None = None,
) -> dict[str, Any]:
    rules_cfg = load_rules(rules_path)
    ignores = () if include_ignored else DEFAULT_IGNORES
    if rules_cfg:
        ignores = ignores + rules_cfg['ignore']
    if extra_excludes:
        ignores = ignores + tuple(extra_excludes)

    client: DriveClient | None = None
    if is_drive_target(target):
        remote, subpath = parse_drive_target(target)
        client = drive or DriveClient(remote)
        inv = walk_drive_inventory(client, subpath, ignore_patterns=ignores, max_depth=max_depth)
    else:
        root_real = os.path.realpath(os.path.expanduser(target))
        inv = walk_local_inventory(root_real, ignore_patterns=ignores, max_depth=max_depth)

    all_files = inv['files']
    total_discovered = len(all_files)
    truncated = False
    if max_files > 0 and total_discovered > max_files:
        selected = all_files[:max_files]
        truncated = True
    else:
        selected = all_files

    items: list[dict[str, Any]] = []
    for f in selected:
        rel_path = f['path']
        name = f['name']
        base = {
            'path': rel_path,
            'name': name,
            'size': f['size'],
            'mtime': f.get('mtime', ''),
            'mime': f.get('mime', ''),
        }
        if inv['backend'] == 'drive':
            base['id'] = f['id']

        # 1. Credential path check BEFORE reading any bytes
        cred_path = detect_credential_path(rel_path)
        if cred_path:
            items.append({**base, 'status': 'credential_skipped', 'reason': cred_path, 'text': None})
            continue

        # 2. Unsupported native Drive objects / shortcuts
        if f.get('unsupported_native'):
            items.append({
                **base,
                'status': 'unsupported_native',
                'reason': f.get('unsupported_label', f['mime']),
                'text': None,
            })
            continue
        if f.get('is_shortcut'):
            items.append({
                **base,
                'status': 'shortcut_metadata_only',
                'reason': 'dangling shortcut' if f['mime'] == DRIVE_DANGLING_MIME else 'drive shortcut',
                'text': None,
            })
            continue

        # 3. Archives (never unpack)
        if is_archive_name(name):
            items.append({**base, 'status': 'archive_skipped', 'reason': 'archive not unpacked', 'text': None})
            continue

        # 4. Images (flag for vision)
        if is_image_name(name) or str(f.get('mime', '')).startswith('image/'):
            items.append({**base, 'status': 'vision_required', 'reason': 'image file', 'text': None})
            continue

        # 5. Size guard for binary reads
        if not f.get('is_native') and int(f['size']) > max_bytes:
            items.append({
                **base,
                'status': 'skipped_too_large',
                'reason': f'exceeds max_bytes ({max_bytes})',
                'text': None,
            })
            continue

        # 6. Google Drive native Workspace export
        if inv['backend'] == 'drive' and f.get('is_native'):
            assert client is not None
            _, _, export_mime = COPYABLE_NATIVE_MIMES[f['mime']]
            if not export_mime:
                items.append({**base, 'status': 'vision_required', 'reason': 'Google Drawing', 'text': None})
                continue
            try:
                raw = client.export_bytes(f['id'], export_mime, max_bytes=max_chars * 4)
                text = extract_plain_text_bytes(raw, max_chars)
                items.append(_finalize_extracted_text(base, text))
            except Exception as err:
                items.append({**base, 'status': 'extraction_error', 'reason': str(err), 'text': None})
            continue

        # 7. Content extraction (local path or bounded Drive download in memory)
        _, ext = os.path.splitext(name.lower())
        local_path = os.path.join(inv['root'], rel_path) if inv['backend'] == 'local' else None

        def load_source(byte_limit: int | None = None) -> str | bytes:
            if local_path is not None:
                if byte_limit is not None:
                    with open(local_path, 'rb') as fh:
                        return fh.read(byte_limit)
                return local_path
            assert client is not None
            return client.download_bytes(f['id'], byte_limit or max_bytes)

        try:
            if ext == '.pdf':
                src = load_source()
                text, err = extract_pdf_text(src, max_chars)
                if err:
                    items.append({**base, 'status': 'extraction_unavailable', 'reason': err, 'text': None})
                elif not text or len(re.sub(r'\s+', '', text)) < MIN_PDF_TEXT_CHARS:
                    items.append({
                        **base,
                        'status': 'vision_required',
                        'reason': 'scanned PDF / no extractable text',
                        'text': None,
                    })
                else:
                    items.append(_finalize_extracted_text(base, text))
            elif ext == '.docx':
                text = extract_docx_text(load_source(), max_chars)
                items.append(_finalize_extracted_text(base, text))
            elif ext == '.xlsx':
                text = extract_xlsx_text(load_source(), max_chars)
                items.append(_finalize_extracted_text(base, text))
            elif ext == '.pptx':
                text = extract_pptx_text(load_source(), max_chars)
                items.append(_finalize_extracted_text(base, text))
            elif ext in TEXT_EXTS or str(f.get('mime', '')).startswith('text/'):
                raw = load_source(byte_limit=max_chars * 4)
                assert isinstance(raw, bytes)
                text = extract_plain_text_bytes(raw, max_chars)
                if text is None:
                    items.append({**base, 'status': 'binary_metadata_only', 'reason': 'binary content', 'text': None})
                else:
                    items.append(_finalize_extracted_text(base, text))
            else:
                items.append({**base, 'status': 'binary_metadata_only', 'reason': 'non-text binary', 'text': None})
        except (OSError, zipfile.BadZipFile, ET.ParseError, ValueError, RuntimeError) as err:
            items.append({**base, 'status': 'extraction_error', 'reason': str(err), 'text': None})

    counts = dict(collections.Counter(i['status'] for i in items))
    return {
        'backend': inv['backend'],
        'root': inv['root'],
        'max_depth': max_depth,
        'max_files': max_files,
        'total_discovered': total_discovered,
        'processed': len(items),
        'truncated': truncated,
        'skipped_cap_count': max(0, total_discovered - len(items)),
        'counts': counts,
        'items': items,
    }


def format_extract_markdown(data: dict[str, Any]) -> str:
    lines = [
        f"# Extract: {data['root']} ({data['backend']})",
        f"Processed {data['processed']}/{data['total_discovered']} files "
        f"(max_depth={data['max_depth']}, max_files={data['max_files']}, truncated={data['truncated']})",
        'Counts: ' + ', '.join(f'{k}={v}' for k, v in sorted(data['counts'].items())),
        '',
    ]
    for item in data['items']:
        reason = f" — {item['reason']}" if item.get('reason') else ''
        lines.append(f"## {item['path']} [{item['status']}{reason}] ({format_bytes(item['size'])})")
        if item.get('text'):
            lines.append('```text')
            lines.append(item['text'])
            lines.append('```')
        lines.append('')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Subcommands: plan & validate
# ---------------------------------------------------------------------------

def load_proposals(path: str) -> list[dict[str, Any]]:
    abs_path = os.path.realpath(os.path.expanduser(path))
    lower = abs_path.lower()
    entries: list[dict[str, Any]] = []
    if lower.endswith('.tsv') or lower.endswith('.csv'):
        delim = '\t' if lower.endswith('.tsv') else ','
        with open(abs_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=delim, strict=True)
            require(bool(reader.fieldnames) and 'source' in reader.fieldnames and 'target' in reader.fieldnames,
                    'Proposal TSV/CSV must have "source" and "target" columns')
            for row in reader:
                if not row or not any(row.values()):
                    continue
                if str(row.get('source', '')).startswith('#'):
                    continue
                entries.append({
                    'source': row['source'].strip(),
                    'target': (row.get('target') or '').strip(),
                    'action': (row.get('action') or 'apply').strip().lower(),
                    'reason': (row.get('reason') or '').strip(),
                    'confidence': (row.get('confidence') or '').strip(),
                })
    else:
        with open(abs_path, encoding='utf-8') as f:
            raw = json.load(f) if lower.endswith('.json') else yaml.safe_load(f)
        if isinstance(raw, dict):
            raw = raw.get('operations') or raw.get('proposals') or []
        require(isinstance(raw, list), 'Proposal file must contain a list of {source, target} objects')
        for idx, item in enumerate(raw):
            require(isinstance(item, dict) and 'source' in item, f'Proposal[{idx}] missing "source"')
            entries.append({
                'source': str(item['source']).strip(),
                'target': str(item.get('target', '')).strip(),
                'action': str(item.get('action', 'apply')).strip().lower(),
                'reason': str(item.get('reason', '')).strip(),
                'confidence': str(item.get('confidence', '')).strip(),
            })
    return entries


def _fingerprint_local(root_real: str, file_info: dict[str, Any]) -> dict[str, Any]:
    full = safe_join_local(root_real, file_info['path'])
    check_no_symlink_escape(root_real, full)
    st = os.lstat(full)
    return {
        'size': st.st_size,
        'mtime_ns': st.st_mtime_ns,
        'sha256': sha256_file(full),
    }


def _fingerprint_drive(file_info: dict[str, Any]) -> dict[str, Any]:
    return {
        'id': file_info['id'],
        'raw_id': file_info['raw_id'],
        'raw_name': file_info['raw_name'],
        'mime': file_info['mime'],
        'parents': list(file_info['parents']),
        'size': file_info['size'],
        'md5': file_info.get('md5', ''),
        'mtime': file_info.get('mtime', ''),
        'version': file_info.get('version', ''),
        'head_revision_id': file_info.get('head_revision_id', ''),
        'is_native': bool(file_info.get('is_native')),
        'copyable_native': bool(file_info.get('copyable_native')),
        'unsupported_native': bool(file_info.get('unsupported_native')),
        'is_shortcut': bool(file_info.get('is_shortcut')),
    }


def _dedupe_proposals(inv: dict[str, Any]) -> list[dict[str, Any]]:
    """Build exact-duplicate quarantine proposals routing extras to _Duplicates/<source>."""
    by_size: dict[int, list[dict[str, Any]]] = collections.defaultdict(list)
    for f in inv['files']:
        if int(f['size']) > 0 and not f.get('is_native'):
            by_size[int(f['size'])].append(f)
    by_hash: dict[tuple[int, str], list[dict[str, Any]]] = collections.defaultdict(list)
    for sz, group in by_size.items():
        if len(group) < 2:
            continue
        for f in group:
            if inv['backend'] == 'local':
                digest = sha256_file(os.path.join(inv['root'], f['path']))
            else:
                digest = f.get('md5', '')
            if digest:
                by_hash[(sz, digest)].append(f)

    proposals: list[dict[str, Any]] = []
    for (sz, digest), group in sorted(by_hash.items()):
        if len(group) < 2:
            continue
        # Deterministic canonical survivor: shallowest path, shortest name, oldest mtime, lexicographic
        ordered = sorted(
            group,
            key=lambda x: (x['path'].count('/'), len(x['path']), x.get('mtime', ''), x['path']),
        )
        survivor = ordered[0]['path']
        for dup in ordered[1:]:
            proposals.append({
                'source': dup['path'],
                'target': f"_Duplicates/{dup['path']}",
                'action': 'apply',
                'reason': f'duplicate of {survivor} ({digest[:12]})',
                'confidence': 'high',
            })
    return proposals


def build_plan(
    source_target: str,
    *,
    proposals_path: str | None = None,
    proposals_list: list[dict[str, Any]] | None = None,
    into_target: str | None = None,
    dedupe: bool = False,
    rules_path: str | None = None,
    mode: str = 'move',
    extra_excludes: list[str] | None = None,
    drive: DriveClient | None = None,
) -> dict[str, Any]:
    require(mode in ('move', 'copy'), f'Invalid mode: {mode}')
    src_root = validate_root_safety(source_target)
    dst_root = validate_root_safety(into_target) if into_target else src_root

    src_is_drive = is_drive_target(src_root)
    dst_is_drive = is_drive_target(dst_root)
    require(src_is_drive == dst_is_drive, 'Source and --into destination must use the same backend (both local or both Drive)')

    rules_cfg = load_rules(rules_path)
    ignores = DEFAULT_IGNORES + (rules_cfg['ignore'] if rules_cfg else ()) + tuple(extra_excludes or ())

    client: DriveClient | None = None
    if src_is_drive:
        src_remote, src_sub = parse_drive_target(src_root)
        dst_remote, dst_sub = parse_drive_target(dst_root)
        require(src_remote == dst_remote, 'Cross-remote Drive operations are not supported')
        client = drive or DriveClient(src_remote)
        src_inv = walk_drive_inventory(client, src_sub, ignore_patterns=ignores)
        if dst_root == src_root:
            dst_inv = src_inv
        else:
            try:
                dst_inv = walk_drive_inventory(client, dst_sub, ignore_patterns=ignores)
            except FileNotFoundError:
                dst_inv = {'backend': 'drive', 'root': dst_root, 'files': [], 'folders': []}
    else:
        src_inv = walk_local_inventory(src_root, ignore_patterns=ignores)
        if dst_root == src_root:
            dst_inv = src_inv
        elif os.path.isdir(dst_root):
            dst_inv = walk_local_inventory(dst_root, ignore_patterns=ignores)
        else:
            dst_inv = {'backend': 'local', 'root': dst_root, 'files': [], 'folders': []}

    src_by_path: dict[str, dict[str, Any]] = {}
    ambiguous_src_paths: set[str] = set()
    for f in src_inv['files']:
        if f['path'] in src_by_path:
            ambiguous_src_paths.add(f['path'])
        else:
            src_by_path[f['path']] = f

    raw_proposals: list[dict[str, Any]] = []
    if dedupe:
        raw_proposals.extend(_dedupe_proposals(src_inv))
    if rules_cfg:
        for f in src_inv['files']:
            m = match_rule(rules_cfg, f['path'], f.get('mtime'))
            if m:
                raw_proposals.append({
                    'source': f['path'],
                    'target': m['target'],
                    'action': 'skip' if m['action'] == 'skip' else 'apply',
                    'reason': m['reason'],
                    'confidence': 'high',
                })
    if proposals_path:
        raw_proposals.extend(load_proposals(proposals_path))
    if proposals_list:
        raw_proposals.extend(proposals_list)

    require(bool(raw_proposals), 'No proposals generated (provide --proposals, --rules, or --dedupe)')

    # Deduplicate by source: explicit proposals override rules/dedupe if listed later,
    # unless same source is repeated inside explicit proposals_path/proposals_list.
    explicit_sources: set[str] = set()
    if proposals_path or proposals_list:
        explicit_items = (load_proposals(proposals_path) if proposals_path else []) + list(proposals_list or [])
        for item in explicit_items:
            s = item['source']
            require(s not in explicit_sources, f'Duplicate source in proposals: {s}')
            explicit_sources.add(s)

    by_source: dict[str, dict[str, Any]] = {}
    for p in raw_proposals:
        by_source[p['source']] = p

    # First pass: validate sources & targets, collect active moves
    prelim: list[dict[str, Any]] = []
    for src_path in sorted(by_source):
        p = by_source[src_path]
        require(safe_rel_path(src_path), f'Unsafe source path: {src_path}')
        require(src_path not in ambiguous_src_paths, f'Ambiguous duplicate Drive source path: {src_path}')
        require(src_path in src_by_path, f'Source file not found in inventory: {src_path}')
        f = src_by_path[src_path]
        action = p.get('action', 'apply')
        require(action in ('apply', 'move', 'copy', 'skip'), f'Invalid proposal action for {src_path}: {action}')

        fp = _fingerprint_local(src_root, f) if not src_is_drive else _fingerprint_drive(f)
        target_path = p.get('target', '')

        if action == 'skip':
            prelim.append({
                'source': src_path,
                'target': '',
                'requested_target': '',
                'status': 'skip',
                'reason': p.get('reason', 'skipped'),
                'confidence': p.get('confidence', ''),
                'fingerprint': fp,
            })
            continue

        require(safe_rel_path(target_path), f'Unsafe target path for {src_path}: {target_path!r}')
        if not dst_is_drive:
            safe_join_local(dst_root, target_path)

        # Rules constraints check
        if rules_cfg:
            if rules_cfg['allowed_roots'] is not None:
                top_seg = target_path.split('/')[0]
                if not dedupe or top_seg != '_Duplicates':
                    require(
                        top_seg in rules_cfg['allowed_roots'],
                        f'Target root "{top_seg}" not in rules.allowed_roots for {target_path}',
                    )
            if rules_cfg['max_depth'] is not None:
                t_depth = target_path.count('/') + 1
                require(
                    t_depth <= rules_cfg['max_depth'],
                    f'Target depth {t_depth} exceeds rules.max_depth ({rules_cfg["max_depth"]}): {target_path}',
                )

        # Handle Drive dangling shortcuts & unsupported native types explicitly
        if src_is_drive:
            if f['mime'] == DRIVE_DANGLING_MIME:
                prelim.append({
                    'source': src_path,
                    'target': target_path,
                    'requested_target': target_path,
                    'status': 'unavailable',
                    'reason': 'dangling Drive shortcut',
                    'confidence': p.get('confidence', ''),
                    'fingerprint': fp,
                })
                continue
            if f.get('unsupported_native') and mode == 'copy':
                prelim.append({
                    'source': src_path,
                    'target': target_path,
                    'requested_target': target_path,
                    'status': 'unsupported',
                    'reason': f"unsupported native Drive type for copy: {f.get('unsupported_label', f['mime'])}",
                    'confidence': p.get('confidence', ''),
                    'fingerprint': fp,
                })
                continue

        if src_root == dst_root and src_path == target_path and mode == 'move':
            prelim.append({
                'source': src_path,
                'target': target_path,
                'requested_target': target_path,
                'status': 'noop',
                'reason': p.get('reason', 'already at target'),
                'confidence': p.get('confidence', ''),
                'fingerprint': fp,
            })
            continue

        prelim.append({
            'source': src_path,
            'target': target_path,
            'requested_target': target_path,
            'status': 'planned',
            'reason': p.get('reason', ''),
            'confidence': p.get('confidence', ''),
            'fingerprint': fp,
        })

    # Second pass: deterministic no-overwrite collision suffixing (_2, _3, ...)
    vacating_sources = {
        op['source'] for op in prelim
        if op['status'] == 'planned' and mode == 'move' and src_root == dst_root
    }
    untouched_dest_files = {
        f['path'] for f in dst_inv['files']
        if f['path'] not in vacating_sources
    }
    existing_dest_dirs = {d['path'] for d in dst_inv['folders']}
    literal_targets = {op['target'] for op in prelim if op['status'] == 'planned'}
    reserved = literal_targets | untouched_dest_files
    taken = set(untouched_dest_files)

    for op in prelim:
        if op['status'] != 'planned':
            continue
        base = op['target']
        target = base
        n = 2
        while target in taken or target in existing_dest_dirs:
            parent = os.path.dirname(base)
            fname = os.path.basename(base)
            is_native = bool(op['fingerprint'].get('is_native'))
            stem, ext = split_name_ext(fname, native=is_native)
            cand_name = f'{stem}_{n}{ext}'
            target = f'{parent}/{cand_name}' if parent else cand_name
            n += 1
            while target in reserved or target in existing_dest_dirs:
                cand_name = f'{stem}_{n}{ext}'
                target = f'{parent}/{cand_name}' if parent else cand_name
                n += 1
        op['target'] = target
        op['collision_suffixed'] = target != base
        taken.add(target)

        # Compute exact raw Drive destination name (preserving escaped raw names if unchanged/suffixed)
        if src_is_drive:
            fp = op['fingerprint']
            src_display = os.path.basename(op['source'])
            tgt_display = os.path.basename(target)
            if has_escaped_name(src_display) or fp['raw_name'] != src_display:
                op['drive_target_name'] = restore_original_drive_name(
                    src_display, tgt_display, fp['raw_name'], native=bool(fp.get('is_native'))
                )
            else:
                op['drive_target_name'] = tgt_display

    # File/folder conflict check across final targets and untouched destination files
    final_targets = {op['target'] for op in prelim if op['status'] == 'planned'}
    all_target_ancestors = {anc for t in final_targets for anc in parent_chain(t)}
    conflict = (final_targets & all_target_ancestors) | (untouched_dest_files & all_target_ancestors)
    require(not conflict, f'File/folder path conflict: {sorted(conflict)[:5]}')

    # Check Drive real-name uniqueness per target folder
    if src_is_drive:
        real_pairs: set[tuple[str, str]] = set()
        for op in prelim:
            if op['status'] != 'planned':
                continue
            pair = (os.path.dirname(op['target']), op['drive_target_name'])
            require(bool(pair[1]) and '\0' not in pair[1], f'Invalid Drive target name for {op["source"]}')
            require(pair not in real_pairs, f'Actual Drive filename collision: {pair}')
            real_pairs.add(pair)

    counts = dict(collections.Counter(op['status'] for op in prelim))
    suffixed = sum(1 for op in prelim if op.get('collision_suffixed'))
    return {
        'schema': SCHEMA_VERSION,
        'created_at': utc_now_iso(),
        'backend': src_inv['backend'],
        'mode_hint': mode,
        'source_root': src_root,
        'dest_root': dst_root,
        'rules': {'path': rules_cfg['path'], 'sha256': rules_cfg['sha256']} if rules_cfg else None,
        'summary': {
            'total': len(prelim),
            'counts': counts,
            'collision_suffixed': suffixed,
        },
        'operations': prelim,
    }


def validate_plan(
    plan: dict[str, Any],
    *,
    mode: str | None = None,
    rules_path: str | None = None,
    check_live: bool = True,
    drive: DriveClient | None = None,
) -> list[str]:
    """Validate plan schema, path safety, rules, source drift, and destination conflicts."""
    errors: list[str] = []
    if not isinstance(plan, dict) or plan.get('schema') != SCHEMA_VERSION:
        return [f'Unsupported or missing plan schema (expected {SCHEMA_VERSION})']

    effective_mode = mode or plan.get('mode_hint', 'move')
    if effective_mode not in ('move', 'copy'):
        errors.append(f'Invalid mode: {effective_mode}')

    backend = plan.get('backend')
    if backend not in ('local', 'drive'):
        return [f'Invalid backend: {backend}']

    try:
        src_root = validate_root_safety(plan['source_root'])
        dst_root = validate_root_safety(plan['dest_root'])
    except (KeyError, ValueError) as err:
        return [str(err)]

    ops = plan.get('operations')
    if not isinstance(ops, list) or not ops:
        return ['Plan has no operations']

    rules_cfg = None
    if rules_path:
        try:
            rules_cfg = load_rules(rules_path)
        except (OSError, ValueError) as err:
            errors.append(f'Rules load failed: {err}')
    elif plan.get('rules'):
        rp = plan['rules'].get('path')
        if rp and os.path.exists(rp):
            try:
                rules_cfg = load_rules(rp)
                if rules_cfg['sha256'] != plan['rules'].get('sha256'):
                    errors.append('Rules file changed since plan was created; regenerate plan')
            except (OSError, ValueError) as err:
                errors.append(f'Rules check failed: {err}')

    seen_sources: set[str] = set()
    planned_targets: set[str] = set()
    planned_ops: list[dict[str, Any]] = []

    for idx, op in enumerate(ops):
        if not isinstance(op, dict):
            errors.append(f'operations[{idx}] is not an object')
            continue
        src = op.get('source', '')
        tgt = op.get('target', '')
        st = op.get('status', '')
        if not safe_rel_path(src):
            errors.append(f'Unsafe source path: {src!r}')
            continue
        if src in seen_sources:
            errors.append(f'Duplicate source in plan: {src}')
        seen_sources.add(src)
        if st not in ('planned', 'skip', 'noop', 'unavailable', 'unsupported'):
            errors.append(f'Invalid operation status for {src}: {st!r}')
            continue
        if st != 'planned':
            continue
        if not safe_rel_path(tgt):
            errors.append(f'Unsafe target path for {src}: {tgt!r}')
            continue
        if backend == 'local':
            try:
                safe_join_local(src_root, src)
                safe_join_local(dst_root, tgt)
            except ValueError as err:
                errors.append(str(err))
                continue
        if tgt in planned_targets:
            errors.append(f'Duplicate target collision in plan: {tgt}')
        planned_targets.add(tgt)
        if rules_cfg:
            if rules_cfg['allowed_roots'] is not None:
                top_seg = tgt.split('/')[0]
                if top_seg != '_Duplicates' and top_seg not in rules_cfg['allowed_roots']:
                    errors.append(f'Target root "{top_seg}" not allowed by rules: {tgt}')
            if rules_cfg['max_depth'] is not None and (tgt.count('/') + 1) > rules_cfg['max_depth']:
                errors.append(f'Target exceeds rules.max_depth: {tgt}')
        if backend == 'drive' and effective_mode == 'copy':
            fp = op.get('fingerprint') or {}
            if fp.get('unsupported_native') or (fp.get('is_native') and fp.get('mime') not in COPYABLE_NATIVE_MIMES):
                errors.append(f'Unsupported native Drive type for --copy: {src} ({fp.get("mime")})')
        planned_ops.append(op)

    ancestors = {anc for t in planned_targets for anc in parent_chain(t)}
    conflicts = planned_targets & ancestors
    if conflicts:
        errors.append(f'File/folder conflict in targets: {sorted(conflicts)[:5]}')

    if not check_live or errors:
        return errors

    # Live source drift & destination collision check
    vacating = {
        op['source'] for op in planned_ops
        if effective_mode == 'move' and src_root == dst_root
    }

    if backend == 'local':
        for op in planned_ops:
            src_abs = safe_join_local(src_root, op['source'])
            fp = op.get('fingerprint') or {}
            if not os.path.lexists(src_abs) or os.path.islink(src_abs) or not os.path.isfile(src_abs):
                errors.append(f'Source missing or invalid: {op["source"]}')
                continue
            try:
                check_no_symlink_escape(src_root, src_abs)
            except ValueError as err:
                errors.append(str(err))
                continue
            st = os.lstat(src_abs)
            if st.st_size != fp.get('size'):
                errors.append(f'Source size drifted: {op["source"]}')
                continue
            if sha256_file(src_abs) != fp.get('sha256'):
                errors.append(f'Source content hash drifted: {op["source"]}')
                continue

            dst_abs = safe_join_local(dst_root, op['target'])
            if os.path.lexists(dst_abs) and op['target'] not in vacating:
                errors.append(f'Destination already exists: {op["target"]}')
            # Also ensure no ancestor of dst_abs is an existing regular file
            for anc in parent_chain(op['target']):
                anc_abs = safe_join_local(dst_root, anc)
                if os.path.lexists(anc_abs) and not os.path.isdir(anc_abs):
                    errors.append(f'Destination parent is a file, not a directory: {anc}')
    else:
        src_remote, _ = parse_drive_target(src_root)
        client = drive or DriveClient(src_remote)
        for op in planned_ops:
            fp = op.get('fingerprint') or {}
            file_id = fp.get('id', '')
            if not file_id:
                errors.append(f'Missing Drive ID fingerprint for {op["source"]}')
                continue
            # Check metadata of the Drive item (for shortcuts, verify shortcut itself + target)
            if fp.get('is_shortcut'):
                sc_id = shortcut_id(file_id) or raw_id(file_id)
                try:
                    sc_meta = client.metadata(sc_id)
                except Exception as err:
                    errors.append(f'Drive shortcut metadata check failed for {op["source"]}: {err}')
                    continue
                if sc_meta.get('trashed'):
                    errors.append(f'Drive shortcut is trashed: {op["source"]}')
                    continue
                if sc_meta.get('name') != fp.get('raw_name'):
                    errors.append(f'Drive shortcut name drifted: {op["source"]}')
                if effective_mode == 'copy':
                    try:
                        tgt_meta = client.metadata(raw_id(file_id))
                        if tgt_meta.get('trashed'):
                            errors.append(f'Drive shortcut target is trashed: {op["source"]}')
                        tgt_mime = tgt_meta.get('mimeType', '')
                        if tgt_mime.startswith(DRIVE_NATIVE_PREFIX) and tgt_mime not in COPYABLE_NATIVE_MIMES:
                            errors.append(f'Unsupported native Drive shortcut target for --copy: {op["source"]} ({tgt_mime})')
                    except Exception as err:
                        errors.append(f'Drive shortcut target check failed for {op["source"]}: {err}')
                continue

            try:
                meta = client.metadata(raw_id(file_id))
            except Exception as err:
                errors.append(f'Drive metadata check failed for {op["source"]}: {err}')
                continue
            if meta.get('trashed'):
                errors.append(f'Drive source is trashed: {op["source"]}')
                continue
            if meta.get('name') != fp.get('raw_name'):
                errors.append(f'Drive source name drifted: {op["source"]}')
            if meta.get('mimeType') != fp.get('mime'):
                errors.append(f'Drive source MIME drifted: {op["source"]}')
            if fp.get('is_native'):
                if str(meta.get('version', '')) != str(fp.get('version', '')) or meta.get('modifiedTime') != fp.get('mtime'):
                    errors.append(f'Drive native version/mtime drifted: {op["source"]}')
            else:
                if fp.get('md5') and meta.get('md5Checksum') != fp.get('md5'):
                    errors.append(f'Drive source MD5 drifted: {op["source"]}')
                if int(meta.get('size', 0) or 0) != int(fp.get('size', 0)):
                    errors.append(f'Drive source size drifted: {op["source"]}')

    return errors


def format_plan_review(plan: dict[str, Any], tree_depth: int = 4) -> str:
    ops = plan['operations']
    lines = [
        f"Plan ({plan['backend']}, mode_hint={plan['mode_hint']})",
        f"Source: {plan['source_root']}",
        f"Dest:   {plan['dest_root']}",
        'Counts: ' + ', '.join(f'{k}={v}' for k, v in sorted(plan['summary']['counts'].items()))
        + f" (collision_suffixed={plan['summary']['collision_suffixed']})",
        '',
        'Review table:',
        f"{'STATUS':<12} {'SOURCE':<40} -> {'TARGET':<40} NOTE",
        '-' * 110,
    ]
    for op in ops:
        note_parts = []
        if op.get('collision_suffixed'):
            note_parts.append('collision-suffixed')
        if op.get('confidence'):
            note_parts.append(f"conf={op['confidence']}")
        if op.get('reason'):
            note_parts.append(op['reason'])
        note = '; '.join(note_parts)
        tgt = op['target'] or '-'
        lines.append(f"{op['status']:<12} {op['source']:<40} -> {tgt:<40} {note}")

    planned_files = [
        {'path': op['target'], 'size': max(0, int((op.get('fingerprint') or {}).get('size', 0)))}
        for op in ops if op['status'] == 'planned'
    ]
    tree_lines = build_compact_tree(planned_files, [], max_depth=tree_depth)
    if tree_lines:
        lines.append('\nResulting tree preview:')
        lines.extend('  ' + line for line in tree_lines)
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Subcommand: apply (in-place move default; --copy opt-in)
# ---------------------------------------------------------------------------

def _atomic_copy_no_overwrite(src_abs: str, dst_abs: str) -> None:
    """Copy src_abs to dst_abs atomically without ever overwriting an existing file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(dst_abs, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out_f, open(src_abs, 'rb') as in_f:
            shutil.copyfileobj(in_f, out_f, length=1024 * 1024)
    except Exception:
        raise
    shutil.copystat(src_abs, dst_abs)


def _execute_local_moves(
    moves: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Execute local renames safely, breaking chains/cycles via unique sibling staging names."""
    # Each item: {'op': op, 'current': src_abs, 'target': dst_abs, 'staged': False}
    pending = [
        {'op': m['op'], 'current': m['src_abs'], 'target': m['dst_abs'], 'staged': False}
        for m in moves
    ]
    completed: list[dict[str, Any]] = []
    stage_counter = 0

    while pending:
        occupied = {item['current'] for item in pending}
        progressed = False
        next_pending: list[dict[str, Any]] = []
        for item in pending:
            if item['target'] not in occupied and not os.path.lexists(item['target']):
                try:
                    os.rename(item['current'], item['target'])
                except OSError as err:
                    if err.errno == errno.EXDEV:
                        raise RuntimeError(
                            f'Cross-filesystem move requires copy+delete ({item["op"]["source"]}); '
                            f're-run with --copy instead'
                        ) from None
                    raise
                completed.append(item)
                occupied.discard(item['current'])
                progressed = True
            else:
                next_pending.append(item)
        pending = next_pending

        if pending and not progressed:
            # Break cycle by staging the first remaining item in its own directory
            victim = pending[0]
            stage_counter += 1
            parent = os.path.dirname(victim['current'])
            token = hashlib.sha256(f"{victim['current']}:{time.time_ns()}:{stage_counter}".encode()).hexdigest()[:12]
            stage_path = os.path.join(parent, f'.reorg_stage_{stage_counter}_{token}')
            while os.path.lexists(stage_path):
                stage_counter += 1
                stage_path = os.path.join(parent, f'.reorg_stage_{stage_counter}_{token}')
            os.rename(victim['current'], stage_path)
            victim['current'] = stage_path
            victim['staged'] = True

    return completed


def apply_plan(
    plan: dict[str, Any],
    *,
    copy_mode: bool = False,
    journal_path: str | None = None,
    plan_path: str | None = None,
    rules_path: str | None = None,
    state_dir: str | None = None,
    drive: DriveClient | None = None,
) -> dict[str, Any]:
    mode = 'copy' if copy_mode else 'move'
    errors = validate_plan(plan, mode=mode, rules_path=rules_path, check_live=True, drive=drive)
    if errors:
        raise ValueError('Preflight validation failed (zero writes performed):\n  ' + '\n  '.join(errors))

    backend = plan['backend']
    src_root = validate_root_safety(plan['source_root'])
    dst_root = validate_root_safety(plan['dest_root'])

    if not journal_path:
        sdir = ensure_state_dir(state_dir)
        journal_path = os.path.join(sdir, f'journal-{mode}-{utc_stamp()}.jsonl')
    else:
        os.makedirs(os.path.dirname(os.path.realpath(os.path.expanduser(journal_path))) or '.', exist_ok=True)

    planned_ops = [op for op in plan['operations'] if op['status'] == 'planned']
    non_planned = [op for op in plan['operations'] if op['status'] != 'planned']
    require(bool(planned_ops), 'Plan has no planned operations to apply')

    verify_errors: list[str] = []
    applied_count = 0

    with open(journal_path, 'x', encoding='utf-8') as log:
        def record(entry: dict[str, Any]) -> None:
            log.write(json.dumps(entry, sort_keys=True) + '\n')
            log.flush()

        record({
            'type': 'header',
            'schema': SCHEMA_VERSION,
            'mode': mode,
            'backend': backend,
            'source_root': src_root,
            'dest_root': dst_root,
            'plan_path': plan_path or '',
            'started_at': utc_now_iso(),
        })

        for op in non_planned:
            record({
                'type': 'op',
                'status': op['status'],
                'source': op['source'],
                'target': op.get('target', ''),
                'reason': op.get('reason', ''),
            })

        # Create required destination directories sequentially first
        req_dirs = sorted(
            {anc for op in planned_ops for anc in parent_chain(op['target'])},
            key=lambda p: (p.count('/'), p),
        )

        if backend == 'local':
            os.makedirs(dst_root, exist_ok=True)
            for d in req_dirs:
                d_abs = safe_join_local(dst_root, d)
                existed = os.path.isdir(d_abs)
                if not existed:
                    os.makedirs(d_abs, exist_ok=False)
                record({'type': 'mkdir', 'path': d, 'existed': existed})

            if mode == 'move':
                move_specs = [
                    {
                        'op': op,
                        'src_abs': safe_join_local(src_root, op['source']),
                        'dst_abs': safe_join_local(dst_root, op['target']),
                    }
                    for op in planned_ops
                ]
                done_items = _execute_local_moves(move_specs)
                moved_targets = {op['target'] for op in planned_ops}
                for item in done_items:
                    op = item['op']
                    dst_abs = item['target']
                    src_abs = safe_join_local(src_root, op['source'])
                    fp = op['fingerprint']
                    actual_size = os.lstat(dst_abs).st_size if os.path.isfile(dst_abs) else -1
                    actual_hash = sha256_file(dst_abs) if os.path.isfile(dst_abs) else ''
                    ok = actual_size == fp['size'] and actual_hash == fp['sha256']
                    if src_root == dst_root and op['source'] not in moved_targets and os.path.lexists(src_abs):
                        ok = False
                    if not ok:
                        verify_errors.append(f'Post-move verification failed: {op["source"]} -> {op["target"]}')
                    else:
                        applied_count += 1
                    record({
                        'type': 'op',
                        'mode': 'move',
                        'status': 'applied' if ok else 'failed',
                        'source': op['source'],
                        'target': op['target'],
                        'size': actual_size,
                        'sha256': actual_hash,
                        'mtime_ns': os.lstat(dst_abs).st_mtime_ns if os.path.isfile(dst_abs) else 0,
                    })
            else:
                # Additive copy mode
                for op in planned_ops:
                    src_abs = safe_join_local(src_root, op['source'])
                    dst_abs = safe_join_local(dst_root, op['target'])
                    fp = op['fingerprint']
                    try:
                        _atomic_copy_no_overwrite(src_abs, dst_abs)
                        dst_size = os.lstat(dst_abs).st_size
                        dst_hash = sha256_file(dst_abs)
                        src_hash = sha256_file(src_abs)
                        ok = (dst_size == fp['size'] and dst_hash == fp['sha256'] and src_hash == fp['sha256'])
                        if not ok:
                            verify_errors.append(f'Post-copy verification failed: {op["target"]}')
                        else:
                            applied_count += 1
                        record({
                            'type': 'op',
                            'mode': 'copy',
                            'status': 'applied' if ok else 'failed',
                            'source': op['source'],
                            'target': op['target'],
                            'size': dst_size,
                            'sha256': dst_hash,
                        })
                    except Exception as err:
                        verify_errors.append(f'Copy failed for {op["source"]}: {err}')
                        record({
                            'type': 'op',
                            'mode': 'copy',
                            'status': 'failed',
                            'source': op['source'],
                            'target': op['target'],
                            'error': str(err),
                        })
        else:
            # Google Drive backend
            dst_remote, dst_sub = parse_drive_target(dst_root)
            client = drive or DriveClient(dst_remote)
            dst_root_id = client.resolve_folder(dst_sub, create=True)
            folder_ids: dict[str, str] = {'': dst_root_id}

            # Create folders sequentially (Drive allows duplicate folder names!)
            for d in req_dirs:
                parent_rel = os.path.dirname(d)
                fname = os.path.basename(d)
                parent_id = folder_ids[parent_rel]
                existing = [c for c in client.children(parent_id, fname) if c.get('mimeType') == DRIVE_FOLDER_MIME]
                require(len(existing) <= 1, f'Ambiguous duplicate Drive folder at destination: {d}')
                if existing:
                    folder_ids[d] = existing[0]['id']
                    record({'type': 'mkdir', 'path': d, 'existed': True, 'dir_id': existing[0]['id']})
                else:
                    new_dir_id = client.mkdir(fname, parent_id)
                    folder_ids[d] = new_dir_id
                    record({'type': 'mkdir', 'path': d, 'existed': False, 'dir_id': new_dir_id})

            new_copy_ids: list[str] = []
            source_raw_ids = {raw_id(op['fingerprint']['id']) for op in planned_ops}

            for op in planned_ops:
                fp = op['fingerprint']
                tgt_parent_id = folder_ids[os.path.dirname(op['target'])]
                tgt_name = op.get('drive_target_name') or os.path.basename(op['target'])

                if mode == 'move':
                    # Move the shortcut itself if shortcut, otherwise the file
                    move_ident = (shortcut_id(fp['id']) or raw_id(fp['id'])) if fp.get('is_shortcut') else raw_id(fp['id'])
                    old_parents = list(fp.get('parents') or [])
                    add_p = None if tgt_parent_id in old_parents else tgt_parent_id
                    rem_p = [p for p in old_parents if p != tgt_parent_id]
                    try:
                        resp = client.move(move_ident, tgt_name, add_parent=add_p, remove_parents=rem_p or None)
                        verified = client.metadata(resp['id'])
                        ok = (
                            verified.get('id') == move_ident
                            and verified.get('name') == tgt_name
                            and tgt_parent_id in (verified.get('parents') or [])
                            and (fp.get('is_native') or fp.get('is_shortcut') or not fp.get('md5')
                                 or verified.get('md5Checksum') == fp.get('md5'))
                        )
                        if not ok:
                            verify_errors.append(f'Post-move Drive verification failed: {op["target"]}')
                        else:
                            applied_count += 1
                        record({
                            'type': 'op',
                            'mode': 'move',
                            'status': 'applied' if ok else 'failed',
                            'source': op['source'],
                            'target': op['target'],
                            'file_id': move_ident,
                            'old_name': fp['raw_name'],
                            'new_name': tgt_name,
                            'old_parents': old_parents,
                            'new_parent': tgt_parent_id,
                            'mime': verified.get('mimeType', fp['mime']),
                            'md5': verified.get('md5Checksum', ''),
                            'version': str(verified.get('version', '')),
                            'is_native': bool(fp.get('is_native')),
                        })
                    except Exception as err:
                        verify_errors.append(f'Drive move failed for {op["source"]}: {err}')
                        record({
                            'type': 'op',
                            'mode': 'move',
                            'status': 'failed',
                            'source': op['source'],
                            'target': op['target'],
                            'file_id': move_ident,
                            'error': str(err),
                        })
                else:
                    # Additive server-side copy by resolved raw_id
                    try:
                        resp = client.copy(fp['id'], tgt_name, tgt_parent_id, fp.get('mtime') or None)
                        new_id = resp.get('id', '')
                        verified = client.metadata(new_id) if new_id else {}
                        ok = (
                            bool(new_id)
                            and new_id not in source_raw_ids
                            and new_id not in new_copy_ids
                            and verified.get('name') == tgt_name
                            and tgt_parent_id in (verified.get('parents') or [])
                            and (fp.get('is_native') or fp.get('is_shortcut') or (
                                (not fp.get('md5') or verified.get('md5Checksum') == fp.get('md5'))
                                and str(verified.get('size', '')) == str(fp.get('size', ''))
                            ))
                        )
                        if new_id:
                            new_copy_ids.append(new_id)
                        if not ok:
                            verify_errors.append(f'Post-copy Drive verification failed: {op["target"]}')
                        else:
                            applied_count += 1
                        record({
                            'type': 'op',
                            'mode': 'copy',
                            'status': 'applied' if ok else 'failed',
                            'source': op['source'],
                            'target': op['target'],
                            'source_id': raw_id(fp['id']),
                            'new_id': new_id,
                            'new_name': tgt_name,
                            'new_parent': tgt_parent_id,
                            'mime': verified.get('mimeType', fp['mime']),
                            'md5': verified.get('md5Checksum', ''),
                        })
                    except Exception as err:
                        verify_errors.append(f'Drive copy failed for {op["source"]}: {err}')
                        record({
                            'type': 'op',
                            'mode': 'copy',
                            'status': 'failed',
                            'source': op['source'],
                            'target': op['target'],
                            'source_id': raw_id(fp['id']),
                            'error': str(err),
                        })

        summary_status = 'FAILED' if verify_errors else 'VERIFIED'
        record({
            'type': 'summary',
            'status': summary_status,
            'finished_at': utc_now_iso(),
            'planned': len(planned_ops),
            'applied': applied_count,
            'errors': verify_errors,
        })

    result = {
        'status': 'FAILED' if verify_errors else 'VERIFIED',
        'mode': mode,
        'backend': backend,
        'planned': len(planned_ops),
        'applied': applied_count,
        'errors': verify_errors,
        'journal': journal_path,
    }
    if verify_errors:
        raise RuntimeError(
            f'Apply finished with {len(verify_errors)} error(s); journal: {journal_path}\n  '
            + '\n  '.join(verify_errors)
        )
    return result


# ---------------------------------------------------------------------------
# Subcommand: undo (deterministic reversal of an applied in-place move journal)
# ---------------------------------------------------------------------------

def undo_journal(
    journal_path: str,
    *,
    undo_journal_path: str | None = None,
    state_dir: str | None = None,
    drive: DriveClient | None = None,
) -> dict[str, Any]:
    abs_journal = os.path.realpath(os.path.expanduser(journal_path))
    with open(abs_journal, encoding='utf-8') as f:
        entries = [json.loads(line) for line in f if line.strip()]

    require(bool(entries) and entries[0].get('type') == 'header', 'Invalid or empty journal file')
    header = entries[0]
    require(header.get('mode') == 'move',
            'Cannot undo a --copy journal (undo never deletes files; originals are already untouched)')

    backend = header['backend']
    src_root = validate_root_safety(header['source_root'])
    dst_root = validate_root_safety(header['dest_root'])

    applied_ops = [e for e in entries if e.get('type') == 'op' and e.get('status') == 'applied' and e.get('mode') == 'move']
    require(bool(applied_ops), 'Journal contains no applied move operations to undo')

    # Reverse order for deterministic reversal
    reversed_ops = list(reversed(applied_ops))
    created_dirs = [e['path'] for e in entries if e.get('type') == 'mkdir' and not e.get('existed')]

    # Preflight integrity & conflict checks BEFORE moving anything back
    errors: list[str] = []
    if backend == 'local':
        vacating_targets = {op['target'] for op in reversed_ops}
        for op in reversed_ops:
            dst_abs = safe_join_local(dst_root, op['target'])
            src_abs = safe_join_local(src_root, op['source'])
            if not os.path.lexists(dst_abs) or os.path.islink(dst_abs) or not os.path.isfile(dst_abs):
                errors.append(f'Applied file missing at destination: {op["target"]}')
                continue
            actual_size = os.lstat(dst_abs).st_size
            actual_hash = sha256_file(dst_abs)
            if actual_size != op.get('size') or actual_hash != op.get('sha256'):
                errors.append(f'Destination file was modified since apply (refusing undo): {op["target"]}')
                continue
            if os.path.lexists(src_abs) and not (src_root == dst_root and op['source'] in vacating_targets):
                errors.append(f'Original source path is now occupied (refusing to overwrite): {op["source"]}')
    else:
        src_remote, _ = parse_drive_target(src_root)
        client = drive or DriveClient(src_remote)
        vacating_ids = {op['file_id'] for op in reversed_ops}
        for op in reversed_ops:
            fid = op['file_id']
            try:
                meta = client.metadata(fid)
            except Exception as err:
                errors.append(f'Cannot read Drive file {fid} ({op["target"]}): {err}')
                continue
            if meta.get('trashed'):
                errors.append(f'Drive file is trashed (refusing undo): {op["target"]}')
                continue
            if meta.get('name') != op.get('new_name') or op.get('new_parent') not in (meta.get('parents') or []):
                errors.append(f'Drive file moved or renamed since apply: {op["target"]}')
                continue
            if not op.get('is_native') and op.get('md5') and meta.get('md5Checksum') != op.get('md5'):
                errors.append(f'Drive file content modified since apply: {op["target"]}')
                continue
            if op.get('is_native') and op.get('version') and str(meta.get('version', '')) != str(op.get('version')):
                errors.append(f'Drive native file version modified since apply: {op["target"]}')
                continue
            for old_p in op.get('old_parents') or []:
                conflicts = [
                    c for c in client.children(old_p, op['old_name'])
                    if c.get('id') not in vacating_ids
                ]
                if conflicts:
                    errors.append(f'Original Drive location occupied by another file: {op["source"]}')

    if errors:
        raise ValueError('Undo preflight failed (zero changes performed):\n  ' + '\n  '.join(errors))

    if not undo_journal_path:
        sdir = ensure_state_dir(state_dir)
        undo_journal_path = os.path.join(sdir, f'undo-{utc_stamp()}.jsonl')

    restored = 0
    post_errors: list[str] = []

    with open(undo_journal_path, 'x', encoding='utf-8') as log:
        def record(entry: dict[str, Any]) -> None:
            log.write(json.dumps(entry, sort_keys=True) + '\n')
            log.flush()

        record({
            'type': 'undo_header',
            'schema': SCHEMA_VERSION,
            'backend': backend,
            'original_journal': abs_journal,
            'started_at': utc_now_iso(),
        })

        if backend == 'local':
            for op in reversed_ops:
                src_parent = os.path.dirname(safe_join_local(src_root, op['source']))
                os.makedirs(src_parent, exist_ok=True)
            move_specs = [
                {
                    'op': {'source': op['target'], 'target': op['source'], 'orig': op},
                    'src_abs': safe_join_local(dst_root, op['target']),
                    'dst_abs': safe_join_local(src_root, op['source']),
                }
                for op in reversed_ops
            ]
            done_items = _execute_local_moves(move_specs)
            for item in done_items:
                orig = item['op']['orig']
                dst_abs = item['target']
                actual_hash = sha256_file(dst_abs) if os.path.isfile(dst_abs) else ''
                ok = actual_hash == orig['sha256']
                if ok:
                    restored += 1
                else:
                    post_errors.append(f'Post-undo verification failed: {orig["source"]}')
                record({
                    'type': 'undo_op',
                    'status': 'restored' if ok else 'failed',
                    'from_target': orig['target'],
                    'to_source': orig['source'],
                    'sha256': actual_hash,
                })
        else:
            src_remote, _ = parse_drive_target(src_root)
            client = drive or DriveClient(src_remote)
            for op in reversed_ops:
                fid = op['file_id']
                old_parents = list(op.get('old_parents') or [])
                new_parent = op['new_parent']
                add_p = ','.join(p for p in old_parents if p != new_parent) or None
                rem_p = [new_parent] if new_parent not in old_parents else None
                try:
                    client.move(fid, op['old_name'], add_parent=add_p, remove_parents=rem_p)
                    verified = client.metadata(fid)
                    ok = (
                        verified.get('name') == op['old_name']
                        and all(p in (verified.get('parents') or []) for p in old_parents)
                    )
                    if ok:
                        restored += 1
                    else:
                        post_errors.append(f'Post-undo Drive verification failed: {op["source"]}')
                    record({
                        'type': 'undo_op',
                        'status': 'restored' if ok else 'failed',
                        'file_id': fid,
                        'from_target': op['target'],
                        'to_source': op['source'],
                    })
                except Exception as err:
                    post_errors.append(f'Drive undo failed for {op["source"]}: {err}')
                    record({
                        'type': 'undo_op',
                        'status': 'failed',
                        'file_id': fid,
                        'error': str(err),
                    })

        record({
            'type': 'undo_summary',
            'status': 'FAILED' if post_errors else 'VERIFIED',
            'restored': restored,
            'empty_dirs_retained': created_dirs,
            'errors': post_errors,
            'finished_at': utc_now_iso(),
        })

    if post_errors:
        raise RuntimeError('Undo completed with errors:\n  ' + '\n  '.join(post_errors))

    return {
        'status': 'VERIFIED',
        'restored': restored,
        'empty_dirs_retained': created_dirs,
        'undo_journal': undo_journal_path,
    }


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='reorg.py',
        description='Deterministic local and Google Drive file organization CLI (zero LLM calls, zero deletion).',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # audit
    p_audit = sub.add_parser('audit', help='Metadata-only structural snapshot of a local path or Drive remote.')
    p_audit.add_argument('path', help='Local directory path or Drive remote (e.g., ~/Downloads or gdrive:Inbox)')
    p_audit.add_argument('--hash', action='store_true', dest='do_hash', help='Detect exact duplicates by hash')
    p_audit.add_argument('--depth', type=int, default=3, help='Compact tree max depth (default: 3)')
    p_audit.add_argument('--top', type=int, default=10, help='Top N largest files/folders/hotspots (default: 10)')
    p_audit.add_argument('--deep-threshold', type=int, default=5, help='Depth threshold for nesting hotspots (default: 5)')
    p_audit.add_argument('--exclude', action='append', default=[], help='Extra ignore glob pattern (repeatable)')
    p_audit.add_argument('--include-ignored', action='store_true', help='Disable default ignore list')
    p_audit.add_argument('--rules', help='Optional external YAML rules/taxonomy file')
    p_audit.add_argument('--json', action='store_true', dest='as_json', help='Emit JSON instead of text report')
    p_audit.add_argument('--output', help='Write output to file path')

    # extract
    p_ext = sub.add_parser('extract', help='Bounded content extraction with credential guard and vision flags.')
    p_ext.add_argument('path', help='Local directory path or Drive remote')
    p_ext.add_argument('--max-depth', type=int, default=3, help='Max folder depth (default: 3)')
    p_ext.add_argument('--max-files', type=int, default=100, help='Soft file cap, 0 for unlimited (default: 100)')
    p_ext.add_argument('--max-chars', type=int, default=4000, help='Max extracted chars per file (default: 4000)')
    p_ext.add_argument('--max-bytes', type=int, default=25 * 1024 * 1024, help='Max file size in bytes to read')
    p_ext.add_argument('--exclude', action='append', default=[], help='Extra ignore glob pattern (repeatable)')
    p_ext.add_argument('--include-ignored', action='store_true', help='Disable default ignore list')
    p_ext.add_argument('--rules', help='Optional external YAML rules/taxonomy file')
    p_ext.add_argument('--format', choices=('json', 'markdown'), default='json', help='Output format (default: json)')
    p_ext.add_argument('--output', help='Write output to file path')

    # plan
    p_plan = sub.add_parser('plan', help='Build and preview a validated, fingerprinted execution plan.')
    p_plan.add_argument('path', help='Source local directory or Drive remote')
    p_plan.add_argument('--proposals', help='Proposed mappings file (JSON, YAML, or TSV with source & target)')
    p_plan.add_argument('--into', dest='into_target', help='Optional destination root for inbox filing')
    p_plan.add_argument('--dedupe', action='store_true', help='Quarantine exact duplicates into _Duplicates/')
    p_plan.add_argument('--rules', help='Optional external YAML rules/taxonomy file')
    p_plan.add_argument('--mode', choices=('move', 'copy'), default='move', help='Plan mode hint (default: move)')
    p_plan.add_argument('--exclude', action='append', default=[], help='Extra ignore glob pattern (repeatable)')
    p_plan.add_argument('--depth', type=int, default=4, help='Resulting tree preview depth (default: 4)')
    p_plan.add_argument('--output', help='Plan JSON output path (default: ~/.local/state/reorg/plan-<ts>.json)')
    p_plan.add_argument('--state-dir', help='Override state directory')
    p_plan.add_argument('--json', action='store_true', dest='as_json', help='Print plan JSON to stdout')

    # validate
    p_val = sub.add_parser('validate', help='Re-validate an existing plan against safety, rules, drift, and conflicts.')
    p_val.add_argument('plan', help='Path to plan JSON file')
    p_val.add_argument('--copy', action='store_true', dest='copy_mode', help='Validate for additive --copy mode')
    p_val.add_argument('--rules', help='Optional external YAML rules/taxonomy file')
    p_val.add_argument('--offline', action='store_true', help='Skip live source drift / destination checks')
    p_val.add_argument('--tree', action='store_true', help='Also print review table and tree preview')
    p_val.add_argument('--depth', type=int, default=4, help='Tree depth when --tree is set')

    # apply
    p_app = sub.add_parser('apply', help='Execute an approved plan (in-place move by default; --copy for additive).')
    p_app.add_argument('plan', help='Path to approved plan JSON file')
    p_app.add_argument('--copy', action='store_true', dest='copy_mode', help='Additive copy mode (leave sources untouched)')
    p_app.add_argument('--rules', help='Optional external YAML rules/taxonomy file')
    p_app.add_argument('--journal', help='Explicit JSONL journal output path')
    p_app.add_argument('--state-dir', help='Override state directory')

    # undo
    p_undo = sub.add_parser('undo', help='Deterministically reverse an applied in-place move journal.')
    p_undo.add_argument('journal', help='Path to JSONL journal from a move apply run')
    p_undo.add_argument('--output', help='Explicit undo journal path')
    p_undo.add_argument('--state-dir', help='Override state directory')

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == 'audit':
            report = compute_audit(
                args.path,
                do_hash=args.do_hash,
                depth=args.depth,
                top=args.top,
                deep_threshold=args.deep_threshold,
                extra_excludes=args.exclude,
                include_ignored=args.include_ignored,
                rules_path=args.rules,
            )
            rendered = json.dumps(report, indent=2) if args.as_json else format_audit_text(report)
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(rendered + '\n')
                print(f'Audit written to {args.output}')
            else:
                print(rendered)
            return 0

        if args.command == 'extract':
            data = extract_scope(
                args.path,
                max_depth=args.max_depth,
                max_files=args.max_files,
                max_chars=args.max_chars,
                max_bytes=args.max_bytes,
                extra_excludes=args.exclude,
                include_ignored=args.include_ignored,
                rules_path=args.rules,
            )
            rendered = json.dumps(data, indent=2) if args.format == 'json' else format_extract_markdown(data)
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(rendered + '\n')
                print(f"Extract written to {args.output} ({data['processed']}/{data['total_discovered']} files)")
            else:
                print(rendered)
            return 0

        if args.command == 'plan':
            plan = build_plan(
                args.path,
                proposals_path=args.proposals,
                into_target=args.into_target,
                dedupe=args.dedupe,
                rules_path=args.rules,
                mode=args.mode,
                extra_excludes=args.exclude,
            )
            out_path = args.output
            if not out_path:
                sdir = ensure_state_dir(args.state_dir)
                out_path = os.path.join(sdir, f'plan-{utc_stamp()}.json')
            else:
                os.makedirs(os.path.dirname(os.path.realpath(os.path.expanduser(out_path))) or '.', exist_ok=True)
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(plan, f, indent=2)
            if args.as_json:
                print(json.dumps(plan, indent=2))
            else:
                print(format_plan_review(plan, tree_depth=args.depth))
                print(f'\nPlan saved to {out_path}')
            return 0

        if args.command == 'validate':
            with open(os.path.expanduser(args.plan), encoding='utf-8') as f:
                plan = json.load(f)
            mode = 'copy' if args.copy_mode else plan.get('mode_hint', 'move')
            errors = validate_plan(plan, mode=mode, rules_path=args.rules, check_live=not args.offline)
            if args.tree:
                print(format_plan_review(plan, tree_depth=args.depth))
                print('')
            if errors:
                print(f'VALIDATION FAILED ({len(errors)} error(s)):', file=sys.stderr)
                for err in errors:
                    print(f'  - {err}', file=sys.stderr)
                return 1
            print(f"VALIDATION PASSED ({plan['summary']['counts'].get('planned', 0)} planned operations, mode={mode})")
            return 0

        if args.command == 'apply':
            with open(os.path.expanduser(args.plan), encoding='utf-8') as f:
                plan = json.load(f)
            res = apply_plan(
                plan,
                copy_mode=args.copy_mode,
                journal_path=args.journal,
                plan_path=os.path.realpath(os.path.expanduser(args.plan)),
                rules_path=args.rules,
                state_dir=args.state_dir,
            )
            print(
                f"APPLY {res['status']} ({res['mode']}, {res['backend']}): "
                f"{res['applied']}/{res['planned']} verified. Journal: {res['journal']}"
            )
            return 0

        if args.command == 'undo':
            res = undo_journal(
                args.journal,
                undo_journal_path=args.output,
                state_dir=args.state_dir,
            )
            print(
                f"UNDO {res['status']}: {res['restored']} files restored. "
                f"Undo journal: {res['undo_journal']}"
            )
            if res['empty_dirs_retained']:
                print(
                    f"Retained {len(res['empty_dirs_retained'])} created director(y/ies) "
                    f"(reorg never deletes): {', '.join(res['empty_dirs_retained'][:10])}"
                )
            return 0

    except (ValueError, RuntimeError, OSError, KeyError, csv.Error, yaml.YAMLError, json.JSONDecodeError) as err:
        print(f'error: {err}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
