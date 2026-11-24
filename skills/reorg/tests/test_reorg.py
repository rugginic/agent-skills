#!/usr/bin/env python3
"""Self-contained tests for reorg v3 (local + mocked Google Drive API).

Zero dependency on personal vault files, real Drive credentials, or network.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import os
import re
import tempfile
import threading
import time
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

SKILL_DIR = Path(__file__).resolve().parent.parent
TOOL_PATH = SKILL_DIR / 'scripts' / 'reorg.py'
SKILL_MD_PATH = SKILL_DIR / 'SKILL.md'
SPEC = importlib.util.spec_from_file_location('reorg_v3', TOOL_PATH)
assert SPEC and SPEC.loader
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


# ---------------------------------------------------------------------------
# Test fixtures & in-memory mock Google Drive
# ---------------------------------------------------------------------------

def make_minimal_pdf(text: str = '') -> bytes:
    """Create a tiny valid 1-page PDF with optional literal text."""
    stream = f'BT /F1 12 Tf 72 720 Td ({text}) Tj ET'.encode('ascii') if text else b''
    objs = [
        b'1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n',
        b'2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n',
        b'3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n',
        f'4 0 obj << /Length {len(stream)} >> stream\n'.encode('ascii') + stream + b'\nendstream endobj\n',
        b'5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n',
    ]
    out = bytearray(b'%PDF-1.4\n')
    offsets = []
    for obj in objs:
        offsets.append(len(out))
        out.extend(obj)
    xref_pos = len(out)
    out.extend(f'xref\n0 {len(objs) + 1}\n0000000000 65535 f \n'.encode('ascii'))
    for off in offsets:
        out.extend(f'{off:010d} 00000 n \n'.encode('ascii'))
    out.extend(f'trailer << /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n'.encode('ascii'))
    return bytes(out)


def make_docx(path: Path, paragraphs: list[str]) -> None:
    body = ''.join(f'<w:p><w:r><w:t>{p}</w:t></w:r></w:p>' for p in paragraphs)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:body>{body}</w:body></w:document>'
    )
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr('word/document.xml', xml)


def make_xlsx(path: Path, sheet_name: str, rows: list[list[str]]) -> None:
    shared: list[str] = []
    row_xml = []
    for r_idx, row in enumerate(rows, 1):
        cells = []
        for c_idx, val in enumerate(row):
            shared.append(val)
            s_idx = len(shared) - 1
            col = chr(ord('A') + c_idx)
            cells.append(f'<c r="{col}{r_idx}" t="s"><v>{s_idx}</v></c>')
        row_xml.append(f'<row r="{r_idx}">{"".join(cells)}</row>')
    ss_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        + ''.join(f'<si><t>{s}</t></si>' for s in shared)
        + '</sst>'
    )
    wb_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheets><sheet name="{sheet_name}" sheetId="1"/></sheets></workbook>'
    )
    sh_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(row_xml)}</sheetData></worksheet>'
    )
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr('xl/workbook.xml', wb_xml)
        zf.writestr('xl/sharedStrings.xml', ss_xml)
        zf.writestr('xl/worksheets/sheet1.xml', sh_xml)


class FakeDrive:
    """In-memory Google Drive API fake implementing DriveClient's interface."""

    def __init__(self, remote: str = 'gdrive'):
        self.remote = remote
        self.root = 'root'
        self._seq = 0
        self.items: dict[str, dict] = {
            'root': {
                'id': 'root',
                'name': 'My Drive',
                'mimeType': r.DRIVE_FOLDER_MIME,
                'parents': [],
                'trashed': False,
            }
        }
        self.contents: dict[str, bytes] = {}
        self.exports: dict[str, bytes] = {}
        self.calls: list[tuple] = []

    def add_folder(self, ident: str, name: str, parent: str = 'root') -> str:
        self.items[ident] = {
            'id': ident,
            'name': name,
            'mimeType': r.DRIVE_FOLDER_MIME,
            'parents': [parent],
            'trashed': False,
        }
        return ident

    def add_file(
        self,
        ident: str,
        name: str,
        parent: str = 'root',
        *,
        mime: str = 'application/pdf',
        size: int = 100,
        md5: str = 'aa11',
        mtime: str = '2026-01-01T00:00:00Z',
        version: str = '1',
        shortcut_target: tuple[str, str] | None = None,
        content: bytes = b'',
        export_bytes: bytes = b'',
    ) -> str:
        entry: dict = {
            'id': ident,
            'name': name,
            'mimeType': mime,
            'parents': [parent],
            'modifiedTime': mtime,
            'version': version,
            'headRevisionId': f'rev-{version}',
            'trashed': False,
        }
        if not mime.startswith(r.DRIVE_NATIVE_PREFIX):
            entry['size'] = str(size)
            entry['md5Checksum'] = md5
        if shortcut_target is not None:
            entry['shortcutDetails'] = {
                'targetId': shortcut_target[0],
                'targetMimeType': shortcut_target[1],
            }
        self.items[ident] = entry
        if content:
            self.contents[ident] = content
        if export_bytes:
            self.exports[ident] = export_bytes
        return ident

    def metadata(self, ident: str) -> dict:
        key = r.raw_id(ident)
        self.calls.append(('metadata', key))
        if key not in self.items:
            raise RuntimeError(f'Drive GET failed (HTTP 404): {key}')
        return dict(self.items[key])

    def children(self, parent_id: str, name: str | None = None) -> list[dict]:
        self.calls.append(('children', parent_id, name))
        out = []
        for item in self.items.values():
            if item.get('trashed'):
                continue
            if parent_id in (item.get('parents') or []):
                if name is None or item['name'] == name:
                    out.append(dict(item))
        return out

    def resolve_folder(self, subpath: str, *, create: bool = False) -> str:
        current = self.root
        if not subpath:
            return current
        for seg in subpath.split('/'):
            matches = [c for c in self.children(current, seg) if c['mimeType'] == r.DRIVE_FOLDER_MIME]
            if len(matches) > 1:
                raise ValueError(f'Ambiguous Drive folder "{seg}"')
            if not matches:
                if create:
                    current = self.mkdir(seg, current)
                    continue
                raise FileNotFoundError(f'Drive folder not found: {subpath}')
            current = matches[0]['id']
        return current

    def mkdir(self, name: str, parent_id: str) -> str:
        self._seq += 1
        ident = f'dir-{self._seq}-{name}'
        self.calls.append(('mkdir', name, parent_id))
        return self.add_folder(ident, name, parent_id)

    def copy(self, ident: str, name: str, parent_id: str, modified: str | None = None) -> dict:
        key = r.raw_id(ident)
        self.calls.append(('copy', key, name, parent_id))
        src = self.items[key]
        if src['mimeType'].startswith(r.DRIVE_NATIVE_PREFIX) and src['mimeType'] not in r.COPYABLE_NATIVE_MIMES:
            raise RuntimeError('Drive POST failed (HTTP 403): unsupported native copy')
        self._seq += 1
        new_id = f'copy-{self._seq}-{key}'
        copied = dict(src)
        copied['id'] = new_id
        copied['name'] = name
        copied['parents'] = [parent_id]
        if modified:
            copied['modifiedTime'] = modified
        self.items[new_id] = copied
        return dict(copied)

    def move(
        self,
        ident: str,
        name: str,
        add_parent: str | None = None,
        remove_parents: list[str] | None = None,
    ) -> dict:
        key = r.raw_id(ident)
        if remove_parents:
            r.require(bool(add_parent), 'Refusing to detach Drive parents without a destination parent')
        self.calls.append(('move', key, name, add_parent, tuple(remove_parents or ())))
        item = self.items[key]
        parents = list(item.get('parents') or [])
        if remove_parents:
            parents = [p for p in parents if p not in remove_parents]
        if add_parent:
            for ap in add_parent.split(','):
                if ap and ap not in parents:
                    parents.append(ap)
        item['parents'] = parents
        item['name'] = name
        return dict(item)

    def download_bytes(self, ident: str, max_bytes: int) -> bytes:
        return self.contents.get(r.raw_id(ident), b'')[:max_bytes]

    def export_bytes(self, ident: str, mime_type: str, max_bytes: int) -> bytes:
        return self.exports.get(r.raw_id(ident), b'')[:max_bytes]


# ---------------------------------------------------------------------------
# 1. Audit tests (local + Drive unsupported native objects)
# ---------------------------------------------------------------------------

class TestAudit(unittest.TestCase):
    def test_local_audit_metrics_ignores_and_hash_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'Docs').mkdir()
            (root / 'Docs' / 'a.pdf').write_bytes(b'hello-pdf-1')
            (root / 'Docs' / 'b.pdf').write_bytes(b'hello-pdf-1')  # exact dup
            (root / 'Docs' / 'big.bin').write_bytes(b'X' * 5000)
            (root / 'EmptyDir' / 'NestedEmpty').mkdir(parents=True)
            (root / 'a' / 'b' / 'c' / 'd' / 'e').mkdir(parents=True)
            (root / 'a' / 'b' / 'c' / 'd' / 'e' / 'deep.txt').write_text('deep')
            # Ignored directories must be excluded
            for ignored in ('.git', '.Trash-1000', 'node_modules', 'ObsidianVault'):
                (root / ignored).mkdir()
                (root / ignored / 'secret.txt').write_text('ignore me')

            rep = r.compute_audit(str(root), do_hash=True, deep_threshold=5)
            self.assertEqual(rep['backend'], 'local')
            self.assertEqual(rep['total_files'], 4)
            self.assertIn('EmptyDir/NestedEmpty', rep['empty_folders'])
            self.assertIn('EmptyDir', rep['empty_folders'])
            self.assertEqual(rep['largest_files'][0]['path'], 'Docs/big.bin')
            self.assertTrue(any(h['path'] == 'a/b/c/d/e/deep.txt' for h in rep['deep_nesting_hotspots']))
            self.assertEqual(len(rep['duplicates']), 1)
            self.assertEqual(rep['duplicates'][0]['paths'], ['Docs/a.pdf', 'Docs/b.pdf'])
            self.assertEqual(rep['duplicate_wasted_bytes'], len(b'hello-pdf-1'))
            # Ignored dirs never leak into report
            rendered = r.format_audit_text(rep)
            for ignored in ('.git', '.Trash-1000', 'node_modules', 'ObsidianVault'):
                self.assertNotIn(ignored, rendered)

    def test_drive_audit_surfaces_unsupported_native_objects_and_shortcuts(self):
        drive = FakeDrive()
        inbox = drive.add_folder('f-inbox', 'Inbox')
        drive.add_file('f-doc', 'Plan', inbox, mime='application/vnd.google-apps.document')
        drive.add_file('f-map', 'Italy Trip Map', inbox, mime='application/vnd.google-apps.map')
        drive.add_file('f-form', 'Survey 2026', inbox, mime='application/vnd.google-apps.form')
        drive.add_file('f-bin1', 'dup1.pdf', inbox, size=50, md5='deadbeef')
        drive.add_file('f-bin2', 'dup2.pdf', inbox, size=50, md5='deadbeef')
        drive.add_file('f-sc', 'BrokenLink', inbox, mime=r.DRIVE_SHORTCUT_MIME, shortcut_target=('', ''))

        rep = r.compute_audit('gdrive:Inbox', do_hash=True, drive=drive)
        self.assertEqual(rep['backend'], 'drive')
        self.assertEqual(rep['total_files'], 6)
        unsupported_mimes = {u['mime'] for u in rep['unsupported_native']}
        self.assertEqual(
            unsupported_mimes,
            {'application/vnd.google-apps.map', 'application/vnd.google-apps.form'},
        )
        self.assertEqual(len(rep['shortcuts']), 1)
        self.assertTrue(rep['shortcuts'][0]['dangling'])
        self.assertEqual(len(rep['duplicates']), 1)
        self.assertEqual(rep['duplicates'][0]['paths'], ['dup1.pdf', 'dup2.pdf'])


# ---------------------------------------------------------------------------
# 2. Extract tests (PDF, Office, credentials, archives, vision, scope cap)
# ---------------------------------------------------------------------------

class TestExtract(unittest.TestCase):
    def test_extract_pdf_office_text_vision_archives_credentials_and_ignores(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Plain text
            (root / 'note.txt').write_text('Invoice from Acme Corp for January 2026 consulting.')
            # PDF with text
            (root / 'invoice.pdf').write_bytes(make_minimal_pdf('Acme Invoice 2026 Total 450 EUR'))
            # Scanned/empty-text PDF -> vision_required
            (root / 'scan.pdf').write_bytes(make_minimal_pdf(''))
            # Office docx & xlsx
            make_docx(root / 'contract.docx', ['Lease Agreement 2026', 'Tenant: Sample User'])
            make_xlsx(root / 'budget.xlsx', 'Q1', [['Category', 'Amount'], ['Rent', '1200']])
            # Image -> vision_required
            (root / 'receipt.png').write_bytes(b'\x89PNG\r\n\x1a\nfake')
            # Archives -> archive_skipped (never unpacked)
            with zipfile.ZipFile(root / 'bundle.zip', 'w') as zf:
                zf.writestr('inner.txt', 'SHOULD_NEVER_BE_EXTRACTED')
            (root / 'backup.tar.gz').write_bytes(b'fake-tarball')
            # Credentials by filename/dir -> credential_skipped (text NEVER emitted)
            (root / '.env').write_text('DATABASE_URL=postgres://admin:supersecret@db/app')
            (root / '.aws').mkdir()
            (root / '.aws' / 'config').write_text('aws_secret_access_key = VERYSECRET')
            (root / 'id_ed25519').write_text('-----BEGIN OPENSSH PRIVATE KEY-----\nabc')
            # Credential by content inside innocent filename -> credential_skipped
            (root / 'notes_export.txt').write_text('My notes:\nAPI_KEY=sk-ant-1234567890abcdef1234567890\n')
            # Ignored directories
            for ig in ('.git', '.Trash-1000', 'node_modules', 'ObsidianVault'):
                (root / ig).mkdir()
                (root / ig / 'file.txt').write_text('ignored')

            out = r.extract_scope(str(root), max_depth=3, max_files=100)
            by_path = {item['path']: item for item in out['items']}

            # Ignored dirs absent
            for ig in ('.git', '.Trash-1000', 'node_modules', 'ObsidianVault'):
                self.assertFalse(any(p.startswith(ig) for p in by_path))

            # Text extracted
            self.assertEqual(by_path['note.txt']['status'], 'extracted')
            self.assertIn('Acme Corp', by_path['note.txt']['text'])

            # PDF extracted (when pdftotext present) and scanned PDF flagged for vision
            if r.shutil.which('pdftotext'):
                self.assertEqual(by_path['invoice.pdf']['status'], 'extracted')
                self.assertIn('Acme Invoice 2026', by_path['invoice.pdf']['text'])
                self.assertEqual(by_path['scan.pdf']['status'], 'vision_required')

            # Office docs extracted
            self.assertEqual(by_path['contract.docx']['status'], 'extracted')
            self.assertIn('Lease Agreement 2026', by_path['contract.docx']['text'])
            self.assertEqual(by_path['budget.xlsx']['status'], 'extracted')
            self.assertIn('Rent | 1200', by_path['budget.xlsx']['text'])

            # Images flagged for vision
            self.assertEqual(by_path['receipt.png']['status'], 'vision_required')

            # Archives never unpacked
            self.assertEqual(by_path['bundle.zip']['status'], 'archive_skipped')
            self.assertEqual(by_path['backup.tar.gz']['status'], 'archive_skipped')
            self.assertNotIn('SHOULD_NEVER_BE_EXTRACTED', json.dumps(out))

            # Credentials skipped and NEVER leaked into output JSON
            for cred_file in ('.env', '.aws/config', 'id_ed25519', 'notes_export.txt'):
                self.assertEqual(by_path[cred_file]['status'], 'credential_skipped')
                self.assertIsNone(by_path[cred_file]['text'])
            dumped = json.dumps(out)
            self.assertNotIn('supersecret', dumped)
            self.assertNotIn('VERYSECRET', dumped)
            self.assertNotIn('sk-ant-1234567890', dumped)

    def test_extract_depth_and_file_count_caps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Depth 1, 2, 3 included; depth 4 excluded with max_depth=3
            (root / 'd1.txt').write_text('depth 1')
            (root / 'a').mkdir()
            (root / 'a' / 'd2.txt').write_text('depth 2')
            (root / 'a' / 'b').mkdir()
            (root / 'a' / 'b' / 'd3.txt').write_text('depth 3')
            (root / 'a' / 'b' / 'c').mkdir()
            (root / 'a' / 'b' / 'c' / 'd4.txt').write_text('depth 4')

            depth_out = r.extract_scope(str(root), max_depth=3, max_files=100)
            paths = {i['path'] for i in depth_out['items']}
            self.assertEqual(paths, {'d1.txt', 'a/d2.txt', 'a/b/d3.txt'})
            self.assertFalse(depth_out['truncated'])

            cap_out = r.extract_scope(str(root), max_depth=3, max_files=2)
            self.assertTrue(cap_out['truncated'])
            self.assertEqual(cap_out['processed'], 2)
            self.assertEqual(cap_out['skipped_cap_count'], 1)


# ---------------------------------------------------------------------------
# 3. Plan & Validate tests (collisions, traversal, roots, rules, dedupe, drift)
# ---------------------------------------------------------------------------

class TestPlanAndValidate(unittest.TestCase):
    def test_refuses_root_and_home(self):
        with self.assertRaisesRegex(ValueError, 'forbidden root'):
            r.validate_root_safety('/')
        with tempfile.TemporaryDirectory() as fake_home:
            with patch.dict(os.environ, {'HOME': fake_home}):
                with self.assertRaisesRegex(ValueError, r'\$HOME'):
                    r.validate_root_safety(fake_home)

    def test_rejects_path_traversal_and_file_folder_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a.txt').write_text('one')
            (root / 'b.txt').write_text('two')
            with self.assertRaisesRegex(ValueError, 'Unsafe target'):
                r.build_plan(str(root), proposals_list=[{'source': 'a.txt', 'target': '../escape.txt'}])
            with self.assertRaisesRegex(ValueError, 'Unsafe target'):
                r.build_plan(str(root), proposals_list=[{'source': 'a.txt', 'target': '/etc/passwd'}])
            with self.assertRaisesRegex(ValueError, 'File/folder path conflict'):
                r.build_plan(str(root), proposals_list=[
                    {'source': 'a.txt', 'target': 'Dir'},
                    {'source': 'b.txt', 'target': 'Dir/file.txt'},
                ])

    def test_rejects_cosmetic_prefix_renames(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for n in ('IMG_8117.jpeg', 'IMG_8118.jpeg', 'Preventivo-37.pdf', 'scan.pdf'):
                (root / n).write_text(n)
            stamped = [
                {'source': 'IMG_8117.jpeg', 'target': 'Foto/Foto_IMG_8117.jpeg'},
                {'source': 'IMG_8118.jpeg', 'target': 'Foto/Foto_IMG_8118.jpeg'},
                {'source': 'scan.pdf', 'target': 'Foto/Foto_scan.pdf'},
            ]
            with self.assertRaisesRegex(ValueError, r'Cosmetic renames rejected[\s\S]*"foto" added to 3'):
                r.build_plan(str(root), proposals_list=stamped)
            self.assertEqual(len(r.build_plan(str(root), proposals_list=stamped, allow_cosmetic=True)['operations']), 3)
            # Real renames (dates/refs), plain moves, and a lone counterparty addition pass.
            plan = r.build_plan(str(root), proposals_list=[
                {'source': 'IMG_8117.jpeg', 'target': 'Foto/2026-06-14_Cucina_Demolizione_01.jpeg'},
                {'source': 'IMG_8118.jpeg', 'target': 'Foto/IMG_8118.jpeg'},
                {'source': 'Preventivo-37.pdf', 'target': 'Preventivi/Preventivo-37_Termoclima.pdf'},
                {'source': 'scan.pdf', 'target': 'Docs/2026-05-05_scan.pdf'},
            ])
            self.assertEqual(len(plan['operations']), 4)
            self.assertEqual(r.cosmetic_addition('Preventivo-37.pdf', 'Preventivo_Preventivo-37.pdf'), 'preventivo')

    def test_collision_suffixing_reserves_literals_and_untouched_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'existing.pdf').write_text('untouched')
            (root / 's1.pdf').write_text('one')
            (root / 's2.pdf').write_text('two')
            (root / 's3.pdf').write_text('three')
            plan = r.build_plan(str(root), proposals_list=[
                {'source': 's1.pdf', 'target': 'existing.pdf'},
                {'source': 's2.pdf', 'target': 'existing.pdf'},
                {'source': 's3.pdf', 'target': 'existing_2.pdf'},
            ])
            by_src = {op['source']: op['target'] for op in plan['operations']}
            # existing.pdf untouched, existing_2.pdf reserved by s3 -> s1 gets _3, s2 gets _4
            self.assertEqual(by_src['s3.pdf'], 'existing_2.pdf')
            self.assertEqual(by_src['s1.pdf'], 'existing_3.pdf')
            self.assertEqual(by_src['s2.pdf'], 'existing_4.pdf')
            self.assertEqual(r.validate_plan(plan), [])

    def test_dedupe_quarantine_and_external_rules_and_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'keep.txt').write_text('same-content')
            (root / 'sub').mkdir()
            (root / 'sub' / 'dup.txt').write_text('same-content')
            (root / 'inv_2025.pdf').write_text('pdf-bytes')

            # Dedupe mode routes deeper duplicate to _Duplicates/
            dedupe_plan = r.build_plan(str(root), dedupe=True)
            self.assertEqual(len(dedupe_plan['operations']), 1)
            self.assertEqual(dedupe_plan['operations'][0]['source'], 'sub/dup.txt')
            self.assertEqual(dedupe_plan['operations'][0]['target'], '_Duplicates/sub/dup.txt')

            # External rules YAML
            rules_file = root / 'rules.yaml'
            rules_file.write_text(yaml.safe_dump({
                'allowed_roots': ['Finance'],
                'max_depth': 4,
                'rules': [
                    {'match': 'inv_*.pdf', 'target': 'Finance/{year}/{name}'},
                ],
            }))
            rules_plan = r.build_plan(str(root), rules_path=str(rules_file))
            self.assertEqual(rules_plan['operations'][0]['target'], 'Finance/2025/inv_2025.pdf')
            self.assertEqual(r.validate_plan(rules_plan), [])

            # Source drift detected by validate_plan
            (root / 'inv_2025.pdf').write_text('modified-after-plan')
            errs = r.validate_plan(rules_plan)
            self.assertTrue(any('drifted' in e for e in errs))


# ---------------------------------------------------------------------------
# 4. Apply (in-place move default, chains/swaps, --copy, --into) & Undo
# ---------------------------------------------------------------------------

class TestApplyAndUndo(unittest.TestCase):
    def test_apply_default_inplace_move_chain_swap_and_undo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'workspace'
            state = Path(tmp) / 'state'
            root.mkdir()
            (root / 'a.txt').write_text('alpha')
            (root / 'b.txt').write_text('beta')
            (root / 'loose.pdf').write_text('invoice')

            plan = r.build_plan(str(root), proposals_list=[
                {'source': 'a.txt', 'target': 'b.txt'},       # swap cycle
                {'source': 'b.txt', 'target': 'a.txt'},       # swap cycle
                {'source': 'loose.pdf', 'target': 'Finance/2026/invoice.pdf'},
            ])
            res = r.apply_plan(plan, copy_mode=False, state_dir=str(state))
            self.assertEqual(res['status'], 'VERIFIED')
            self.assertEqual(res['mode'], 'move')
            self.assertEqual((root / 'a.txt').read_text(), 'beta')
            self.assertEqual((root / 'b.txt').read_text(), 'alpha')
            self.assertFalse((root / 'loose.pdf').exists())
            self.assertEqual((root / 'Finance' / '2026' / 'invoice.pdf').read_text(), 'invoice')

            # Verify JSONL journal structure
            j_lines = [json.loads(x) for x in Path(res['journal']).read_text().splitlines()]
            self.assertEqual(j_lines[0]['type'], 'header')
            self.assertEqual(j_lines[-1]['type'], 'summary')
            self.assertEqual(j_lines[-1]['status'], 'VERIFIED')

            # Undo deterministically restores original state (including swap!)
            undo_res = r.undo_journal(res['journal'], state_dir=str(state))
            self.assertEqual(undo_res['status'], 'VERIFIED')
            self.assertEqual(undo_res['restored'], 3)
            self.assertEqual((root / 'a.txt').read_text(), 'alpha')
            self.assertEqual((root / 'b.txt').read_text(), 'beta')
            self.assertEqual((root / 'loose.pdf').read_text(), 'invoice')
            self.assertFalse((root / 'Finance' / '2026' / 'invoice.pdf').exists())

    def test_apply_copy_mode_preserves_sources_and_undo_refuses_copy_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'inbox'
            dst = Path(tmp) / 'archive'
            state = Path(tmp) / 'state'
            src.mkdir()
            (src / 'doc.txt').write_text('immutable-source')

            plan = r.build_plan(
                str(src),
                into_target=str(dst),
                mode='copy',
                proposals_list=[{'source': 'doc.txt', 'target': '2026/doc.txt'}],
            )
            res = r.apply_plan(plan, copy_mode=True, state_dir=str(state))
            self.assertEqual(res['mode'], 'copy')
            self.assertEqual((src / 'doc.txt').read_text(), 'immutable-source')
            self.assertEqual((dst / '2026' / 'doc.txt').read_text(), 'immutable-source')

            # Undo must refuse a --copy journal (zero deletion guarantee)
            with self.assertRaisesRegex(ValueError, 'Cannot undo a --copy'):
                r.undo_journal(res['journal'], state_dir=str(state))

    def test_apply_aborts_before_any_write_on_source_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'work'
            state = Path(tmp) / 'state'
            root.mkdir()
            (root / 'a.txt').write_text('v1')
            (root / 'b.txt').write_text('v1')
            plan = r.build_plan(str(root), proposals_list=[
                {'source': 'a.txt', 'target': 'Sub/a.txt'},
                {'source': 'b.txt', 'target': 'Sub/b.txt'},
            ])
            (root / 'b.txt').write_text('tampered')
            with self.assertRaisesRegex(ValueError, 'Preflight validation failed'):
                r.apply_plan(plan, state_dir=str(state))
            # Zero writes occurred (Sub dir was never even created)
            self.assertFalse((root / 'Sub').exists())
            self.assertTrue((root / 'a.txt').exists())

    def test_undo_refuses_modified_or_conflicting_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'work'
            state = Path(tmp) / 'state'
            root.mkdir()
            (root / 'orig.txt').write_text('clean')
            plan = r.build_plan(str(root), proposals_list=[{'source': 'orig.txt', 'target': 'Moved/orig.txt'}])
            res = r.apply_plan(plan, state_dir=str(state))

            # Case 1: destination modified post-apply
            (root / 'Moved' / 'orig.txt').write_text('edited-by-user')
            with self.assertRaisesRegex(ValueError, 'modified since apply'):
                r.undo_journal(res['journal'], state_dir=str(state))
            self.assertFalse((root / 'orig.txt').exists())

            # Restore destination content, then create conflict at original source path
            (root / 'Moved' / 'orig.txt').write_text('clean')
            (root / 'orig.txt').write_text('new-unrelated-file')
            with self.assertRaisesRegex(ValueError, 'now occupied'):
                r.undo_journal(res['journal'], state_dir=str(state))
            self.assertEqual((root / 'orig.txt').read_text(), 'new-unrelated-file')


# ---------------------------------------------------------------------------
# 5. Google Drive API safety tests
# ---------------------------------------------------------------------------

class TestDriveSafety(unittest.TestCase):
    def test_composite_shortcut_ids_and_escaped_names(self):
        self.assertEqual(r.raw_id('target-123\tshortcut-456'), 'target-123')
        self.assertEqual(r.shortcut_id('target-123\tshortcut-456'), 'shortcut-456')
        with self.assertRaises(ValueError):
            r.raw_id('a\tb\tc')
        with self.assertRaises(ValueError):
            r.raw_id('../bad')

        display = r.escape_drive_display_name('https://example.com/report.txt')
        self.assertIn('／', display)
        self.assertTrue(r.has_escaped_name(display))
        self.assertEqual(
            r.restore_original_drive_name(display, display, 'https://example.com/report.txt'),
            'https://example.com/report.txt',
        )
        suffixed = display.replace('.txt', '_2.txt')
        self.assertEqual(
            r.restore_original_drive_name(display, suffixed, 'https://example.com/report.txt'),
            'https://example.com/report_2.txt',
        )

    def test_drive_auth_401_refresh_and_non_retried_5xx_writes(self):
        # Proactive refresh when expired + safe 401 retry before mutation
        for expired in (True, False):
            with self.subTest(expired=expired):
                drive = object.__new__(r.DriveClient)
                drive.remote = 'gdrive'
                drive.token = 'dummy'
                drive.expires = 0.0 if expired else time.time() + 3600
                drive.auth_lock = threading.Lock()

                def refreshed():
                    drive.expires = time.time() + 3600

                drive.refresh = Mock(side_effect=refreshed)
                responses = (
                    [io.BytesIO(b'{"id": "new-1"}')]
                    if expired
                    else [
                        urllib.error.HTTPError('https://example.invalid', 401, 'Unauthorized', {}, None),
                        io.BytesIO(b'{"id": "new-1"}'),
                    ]
                )
                with patch.object(r.urllib.request, 'urlopen', side_effect=responses):
                    self.assertEqual(drive.copy('target\tshortcut', 'name.pdf', 'parent'), {'id': 'new-1'})
                drive.refresh.assert_called_once()

        # Non-GET writes (POST copy, PATCH move) are NEVER retried on 503
        for method_call in (
            lambda d: d.copy('target\tshortcut', 'alias.pdf', 'parent'),
            lambda d: d.move('file-1', 'new.pdf', add_parent='p2', remove_parents=['p1']),
        ):
            drive = object.__new__(r.DriveClient)
            drive.remote = 'gdrive'
            drive.token = 'dummy'
            drive.expires = time.time() + 3600
            drive.auth_lock = threading.Lock()
            err_503 = urllib.error.HTTPError('https://example.invalid', 503, 'Unavailable', {}, None)
            with patch.object(r.urllib.request, 'urlopen', side_effect=err_503) as call:
                with self.assertRaisesRegex(RuntimeError, 'HTTP 503'):
                    method_call(drive)
                self.assertEqual(call.call_count, 1)

    def test_drive_copy_and_move_preserve_escaped_names_native_and_flag_unsupported(self):
        drive = FakeDrive()
        inbox = drive.add_folder('f-inbox', 'Inbox')
        drive.add_file('f-esc', 'Q1/Q2 Report.pdf', inbox, size=20, md5='md5esc')
        drive.add_file('f-sheet', 'Budget', inbox, mime='application/vnd.google-apps.spreadsheet', version='3')
        drive.add_file('f-map', 'Roadtrip', inbox, mime='application/vnd.google-apps.map', version='1')
        # Shortcut pointing to a real file
        drive.add_file('f-real', 'RealTarget.pdf', 'root', size=40, md5='md5real')
        drive.add_file(
            'f-sc',
            'Alias.pdf',
            inbox,
            mime=r.DRIVE_SHORTCUT_MIME,
            shortcut_target=('f-real', 'application/pdf'),
        )

        esc_disp = r.escape_drive_display_name('Q1/Q2 Report.pdf')
        proposals = [
            {'source': esc_disp, 'target': f'Reports/{esc_disp}'},
            {'source': 'Budget', 'target': 'Finance/Budget'},
            {'source': 'Roadtrip', 'target': 'Trips/Roadtrip'},
            {'source': 'Alias.pdf', 'target': 'Links/Alias.pdf'},
        ]

        # 1. Copy mode flags unsupported Google My Maps instead of crashing, copies others by raw_id
        with tempfile.TemporaryDirectory() as state:
            copy_plan = r.build_plan('gdrive:Inbox', into_target='gdrive:Archive', mode='copy',
                                     proposals_list=proposals, drive=drive)
            by_src = {op['source']: op for op in copy_plan['operations']}
            self.assertEqual(by_src['Roadtrip']['status'], 'unsupported')
            self.assertEqual(by_src[esc_disp]['drive_target_name'], 'Q1/Q2 Report.pdf')

            res = r.apply_plan(copy_plan, copy_mode=True, state_dir=state, drive=drive)
            self.assertEqual(res['applied'], 3)
            # Shortcut copied by target raw_id ('f-real'), not composite id
            copy_calls = [c for c in drive.calls if c[0] == 'copy']
            self.assertTrue(any(c[1] == 'f-real' and c[2] == 'Alias.pdf' and c[3].endswith('-Links') for c in copy_calls))
            # Escaped raw filename preserved on Drive
            self.assertTrue(any(c[1] == 'f-esc' and c[2] == 'Q1/Q2 Report.pdf' and c[3].endswith('-Reports') for c in copy_calls))
            # Native Google Sheet preserved
            self.assertTrue(any(c[1] == 'f-sheet' and c[2] == 'Budget' and c[3].endswith('-Finance') for c in copy_calls))

        # 2. Move mode moves & undoes cleanly on Drive
        with tempfile.TemporaryDirectory() as state:
            move_plan = r.build_plan('gdrive:Inbox', mode='move', proposals_list=[
                {'source': esc_disp, 'target': f'Sorted/{esc_disp}'},
                {'source': 'Budget', 'target': 'Sorted/Budget Renamed'},
            ], drive=drive)
            m_res = r.apply_plan(move_plan, copy_mode=False, state_dir=state, drive=drive)
            self.assertEqual(m_res['applied'], 2)
            self.assertEqual(drive.items['f-esc']['name'], 'Q1/Q2 Report.pdf')
            self.assertEqual(drive.items['f-sheet']['name'], 'Budget Renamed')
            self.assertNotEqual(drive.items['f-sheet']['parents'], [inbox])

            # Undo restores exact original Drive parents and names
            u_res = r.undo_journal(m_res['journal'], state_dir=state, drive=drive)
            self.assertEqual(u_res['restored'], 2)
            self.assertEqual(drive.items['f-esc']['parents'], [inbox])
            self.assertEqual(drive.items['f-sheet']['parents'], [inbox])
            self.assertEqual(drive.items['f-sheet']['name'], 'Budget')


# ---------------------------------------------------------------------------
# 6. Static no-delete guard
# ---------------------------------------------------------------------------

class TestStaticNoDeleteGuard(unittest.TestCase):
    def test_reorg_contains_zero_deletion_primitives(self):
        source = TOOL_PATH.read_text(encoding='utf-8')
        tree = ast.parse(source, filename=str(TOOL_PATH))

        forbidden_attrs = {'remove', 'unlink', 'rmdir', 'removedirs', 'rmtree'}
        forbidden_subproc_args = {'rm', 'delete', 'deletefile', 'purge'}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check attribute calls like os.remove, os.unlink, Path.unlink, shutil.rmtree
                if isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_attrs:
                    self.fail(f'Forbidden deletion call .{node.func.attr}() at line {node.lineno}')
                # Check direct imported names like unlink(...)
                if isinstance(node.func, ast.Name) and node.func.id in forbidden_attrs:
                    self.fail(f'Forbidden deletion function {node.func.id}() at line {node.lineno}')
                # Check HTTP DELETE literal passed to request helpers
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if arg.value.upper() == 'DELETE':
                            self.fail(f'Forbidden HTTP DELETE method at line {node.lineno}')
                        if isinstance(node.func, ast.Name) and node.func.id == 'run_rclone':
                            if arg.value.lower() in forbidden_subproc_args:
                                self.fail(f'Forbidden rclone delete/purge arg {arg.value!r} at line {node.lineno}')

            # Ensure no dict sets {'trashed': True}
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if (
                        isinstance(k, ast.Constant) and k.value == 'trashed'
                        and isinstance(v, ast.Constant) and v.value is True
                    ):
                        self.fail(f'Forbidden trashed=True payload at line {node.lineno}')

        # Also verify no hardcoded personal vault paths remain in reorg.py or SKILL.md
        skill_text = SKILL_MD_PATH.read_text(encoding='utf-8')
        for forbidden in ('DriveReorg', 'Drive-Reorg', 'mapping.tsv', 'decisions.tsv', '.claude/skills'):
            self.assertNotIn(forbidden, source, f'Hardcoded personal reference in reorg.py: {forbidden}')
            self.assertNotIn(forbidden, skill_text, f'Hardcoded personal reference in SKILL.md: {forbidden}')


if __name__ == '__main__':
    unittest.main()
