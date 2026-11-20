"""TraceDesk MCP 业务编排层：复用 forensic.core 与 forensic.engines，不依赖 Qt。"""
from contextlib import contextmanager
import json
import math
from pathlib import Path
from typing import Any

from ..core.case import Case
from ..core.content_search import SearchControl, search as run_content_search
from ..core.coverage import SOURCE_FIELDS, coverage_text, source_status
from ..core.file_tools import examine as examine_entry, record_note
from ..core.findings import (
    ACTION_TITLES,
    OPERATIONS,
    audit_origin,
    audit_origin_label,
    export_findings as do_export_findings,
    group_findings,
)
from ..core.formatting import display_time
from ..core.preview import PAGE_BYTES, PREVIEW_ENCODINGS, PreviewReader, preview_rows, preview_text
from ..core.review import build_bundle
from ..core.timeline import FIELDS as TIMELINE_FIELDS, TimelineEvents
from ..engines.tsk import can_export, deleted_source_note, entry_name, entry_status
from ..paths import CASES_DIR


EVENT_ALIASES = {
    'M': 'M 内容修改',
    'A': 'A 访问',
    'C': 'C 元数据变更',
    'B': 'B 创建',
}
VALID_EVENT_LABELS = {label for _, label in TIMELINE_FIELDS}


def _normalize_entry_path(path: str) -> str:
    return path.replace('\\', '/').strip().lstrip('/')


def _format_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        'path': entry['path'],
        'name': entry_name(entry),
        'partition_offset': entry['offset'],
        'inode': str(entry['inode']),
        'directory': bool(entry.get('directory', False)),
        'mode': entry.get('mode', ''),
        'size': int(entry.get('size', 0)),
        'deleted': bool(entry.get('deleted', False)),
        'reallocated': bool(entry.get('reallocated', False)),
        'start_cluster_allocated': bool(entry.get('start_cluster_allocated', False)),
        'status': entry_status(entry),
        'exportable': can_export(entry),
        'filesystem': entry.get('filesystem', ''),
        'mtime': display_time(entry.get('mtime', 0)),
        'atime': display_time(entry.get('atime', 0)),
        'ctime': display_time(entry.get('ctime', 0)),
        'crtime': display_time(entry.get('crtime', 0)),
        'source_note': deleted_source_note(entry),
    }


def _paginate(items: list[Any], *, limit: int, offset: int) -> dict[str, Any]:
    total = len(items)
    sliced = items[offset:offset + limit]
    has_more = offset + len(sliced) < total
    return {
        'total': total,
        'count': len(sliced),
        'offset': offset,
        'limit': limit,
        'has_more': has_more,
        'next_offset': offset + len(sliced) if has_more else None,
        'items': sliced,
    }


class CaseService:
    """面向 MCP 工具的案件与证据服务，按单次调用安全加锁并及时释放 case.lock。"""

    def __init__(self, cases_root: Path | str | None = None, default_actor: str | None = None):
        self.cases_root = Path(cases_root).resolve() if cases_root else CASES_DIR.resolve()
        self.default_actor = (default_actor or '').strip() or None

    def resolve_case_dir(self, case_dir: str) -> Path:
        raw = Path(case_dir.strip())
        candidates = [raw] if raw.is_absolute() else [self.cases_root / raw, raw]
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved.is_file() and resolved.name.casefold() == 'case.json':
                resolved = resolved.parent
            if (resolved / 'case.json').is_file():
                return resolved
        raise FileNotFoundError(
            f'未找到有效案件目录（缺少 case.json）：{case_dir}。'
            '请先调用 tracedesk_list_cases 查看已有案件，或调用 tracedesk_create_case 新建案件。'
        )

    @contextmanager
    def open_case(self, case_dir: str, *, actor: str | None = None):
        folder = self.resolve_case_dir(case_dir)
        explicit_actor = (actor or self.default_actor or '').strip() or None
        try:
            case = Case(folder, actor=explicit_actor, origin='mcp')
        except RuntimeError as error:
            message = str(error)
            if '占用' in message or '加锁' in message:
                raise RuntimeError(
                    f'案件目录 {folder} 当前已被 TraceDesk 桌面端或其他进程锁定。'
                    '请先在桌面端关闭该案件或切换至其他案件后再重试。'
                ) from error
            raise
        try:
            yield case
        finally:
            case.close()

    def _ensure_large_image_session(self, case: Case, *, verify_if_needed: bool = False) -> None:
        evidence = case.data.get('evidence')
        if not evidence or not evidence.get('large_image'):
            return
        if evidence.get('sha256') and not case._session_verified:
            if verify_if_needed:
                case.verify()
            else:
                raise ValueError(
                    '该案件为 1 GiB 以上大容量镜像，重新打开后尚未完成本次会话校验。'
                    '请将 verify_large_image 设为 true，或先在工作台执行完整性校验。'
                )

    @staticmethod
    def _find_entry(
        case: Case,
        path: str,
        *,
        partition_offset: int | None = None,
        inode: str | None = None,
        deleted: bool | None = None,
        dir_inode: str | None = None,
        dir_path: str = '',
    ) -> dict[str, Any]:
        target_path = _normalize_entry_path(path)
        if not target_path:
            raise ValueError('文件路径 path 不能为空。')

        if case.browsing_directories:
            if partition_offset is None:
                raise ValueError(
                    '当前为大容量镜像快速浏览模式（尚未建立完整文件索引）。'
                    '请先调用 tracedesk_scan_partitions 建立完整文件索引，或同时提供 partition_offset 与所在目录参数。'
                )
            parent = dir_path.strip() or (target_path.rsplit('/', 1)[0] if '/' in target_path else '')
            case.browse_directory(partition_offset, dir_inode or None, parent)

        entries = case.displayed_entries()
        matches = []
        for entry in entries:
            if _normalize_entry_path(entry['path']).casefold() != target_path.casefold():
                continue
            if partition_offset is not None and entry['offset'] != partition_offset:
                continue
            if inode is not None and str(entry['inode']) != str(inode):
                continue
            if deleted is not None and bool(entry.get('deleted', False)) != bool(deleted):
                continue
            matches.append(entry)

        if not matches:
            raise ValueError(
                f'未在当前案件清单中找到文件：{path}。'
                '请先调用 tracedesk_list_files 确认准确的 path、partition_offset 和 inode。'
            )
        if len(matches) > 1:
            candidates = [
                f"(partition_offset={e['offset']}, inode={e['inode']}, deleted={bool(e.get('deleted', False))}, size={e['size']})"
                for e in matches[:10]
            ]
            raise ValueError(
                f'路径 {path} 匹配到 {len(matches)} 条记录，存在同名或跨分区歧义：'
                + '；'.join(candidates)
                + '。请补充 partition_offset、inode 或 deleted 参数以唯一定位目标文件。'
            )
        return matches[0]

    def list_cases(
        self,
        *,
        cases_root: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        root = Path(cases_root).resolve() if cases_root else self.cases_root
        if not root.exists():
            return {'cases_root': str(root), **_paginate([], limit=limit, offset=offset)}
        if not root.is_dir():
            raise ValueError(f'案件库路径不是有效目录：{root}')

        rows = []
        for child in sorted(root.iterdir(), key=lambda p: p.name.casefold()):
            metadata_file = child / 'case.json'
            if not child.is_dir() or not metadata_file.is_file():
                continue
            try:
                data = json.loads(metadata_file.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                rows.append({
                    'folder': str(child.resolve()),
                    'name': child.name,
                    'status': 'invalid_metadata',
                })
                continue
            evidence = data.get('evidence') or {}
            inventory_count = data.get('inventory_count', len(data.get('inventory', [])))
            rows.append({
                'folder': str(child.resolve()),
                'name': child.name,
                'id': data.get('id', ''),
                'number': data.get('number', ''),
                'examiner': data.get('examiner', ''),
                'target': data.get('target', ''),
                'created': display_time(data.get('created', '')),
                'has_evidence': bool(data.get('evidence')),
                'image_name': Path(evidence['path']).name if evidence.get('path') else '',
                'image_path': evidence.get('path', ''),
                'image_format': evidence.get('format', 'RAW') if evidence else '',
                'image_size': evidence.get('size', 0) if evidence else 0,
                'sha256_fixed': bool(evidence.get('sha256')),
                'inventory_count': inventory_count,
                'exports_count': len(data.get('exports', [])),
                'status': 'ok',
            })
        rows.sort(key=lambda item: item.get('created', ''), reverse=True)
        return {'cases_root': str(root), **_paginate(rows, limit=limit, offset=offset)}

    def create_case(
        self,
        *,
        number: str,
        examiner: str,
        target: str,
        cases_root: str | None = None,
        folder_name: str | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        root = Path(cases_root).resolve() if cases_root else self.cases_root
        explicit_actor = (actor or self.default_actor or '').strip() or None
        case = Case.create(
            root,
            number,
            examiner,
            target,
            folder_name=folder_name,
            actor=explicit_actor,
            origin='mcp',
        )
        try:
            return {
                'case_dir': str(case.folder),
                'id': case.data['id'],
                'number': case.data['number'],
                'examiner': case.data['examiner'],
                'target': case.data['target'],
                'origin': 'mcp',
                'origin_label': 'MCP',
                'created': display_time(case.data['created']),
            }
        finally:
            case.close()

    def get_case_summary(self, *, case_dir: str, actor: str | None = None) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            records = case.check_audit()
            data = case.data
            evidence = data.get('evidence')
            findings_groups = group_findings(records)
            mcp_count = sum(1 for r in records if audit_origin(r) == 'mcp')
            summary: dict[str, Any] = {
                'case_dir': str(case.folder),
                'id': data['id'],
                'number': data['number'],
                'examiner': data['examiner'],
                'target': data['target'],
                'created': display_time(data['created']),
                'browsing_directories': case.browsing_directories,
                'needs_partition_scan': case.needs_partition_scan(),
                'inventory_count': len(data.get('inventory', [])),
                'exports_count': len(data.get('exports', [])),
                'findings_file_count': len(findings_groups),
                'findings_record_count': sum(len(items) for items in findings_groups.values()),
                'audit_count': len(records),
                'audit_origin_counts': {'manual': len(records) - mcp_count, 'mcp': mcp_count},
                'audit_head': records[-1]['hash'] if records else '',
                'audit_chain_valid': True,
                'evidence': None,
                'partition_scans': data.get('partition_scans', []),
                'verification': data.get('verification'),
            }
            if evidence:
                summary['evidence'] = {
                    'path': evidence['path'],
                    'format': evidence.get('format', 'RAW'),
                    'size': evidence['size'],
                    'large_image': bool(evidence.get('large_image', False)),
                    'sha256': evidence.get('sha256'),
                    'fixed_at': display_time(evidence['fixed_at']) if evidence.get('fixed_at') else '',
                    'partitions': evidence.get('partitions', []),
                    'provenance': evidence.get('provenance', {}),
                    'source_comparison': source_status(evidence),
                    'coverage': evidence.get('coverage'),
                    'coverage_text': coverage_text(evidence.get('coverage')),
                    'segments_count': len(evidence.get('segments', [])),
                }
            return summary

    def load_image(
        self,
        *,
        case_dir: str,
        image_path: str,
        scan_all: bool = True,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            case.load(image_path)
            evidence = case.data['evidence']
            scanned = False
            inventory_count = len(case.data['inventory'])
            if scan_all and not evidence.get('large_image'):
                entries = case.scan_all()
                scanned = True
                inventory_count = len(entries)
            return {
                'case_dir': str(case.folder),
                'image_path': evidence['path'],
                'format': evidence.get('format', 'RAW'),
                'size': evidence['size'],
                'large_image': bool(evidence.get('large_image', False)),
                'sha256': evidence.get('sha256'),
                'fixed_at': display_time(evidence['fixed_at']) if evidence.get('fixed_at') else '',
                'partitions': evidence.get('partitions', []),
                'coverage_text': coverage_text(evidence.get('coverage')),
                'scanned_all_partitions': scanned,
                'partition_scans': case.data.get('partition_scans', []),
                'inventory_count': inventory_count,
                'note': (
                    '镜像容量达到 1 GiB，已按快速浏览模式载入。'
                    '如需全案索引请调用 tracedesk_scan_partitions，如需建立 SHA-256 基线请调用 tracedesk_verify_integrity。'
                    if evidence.get('large_image') else ''
                ),
            }

    def verify_integrity(self, *, case_dir: str, actor: str | None = None) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            ok = case.verify()
            evidence = case.data['evidence']
            verification = case.data.get('verification', {})
            return {
                'case_dir': str(case.folder),
                'image_path': evidence['path'],
                'ok': bool(ok),
                'sha256': evidence.get('sha256'),
                'actual': verification.get('actual'),
                'method': verification.get('method', ''),
                'verified_at': display_time(verification.get('time', '')),
                'source_comparison': source_status(evidence),
                'coverage_text': coverage_text(evidence.get('coverage')),
            }

    def register_source(
        self,
        *,
        case_dir: str,
        evidence_id: str = '',
        source: str = '',
        acquired: str = '',
        tool: str = '',
        expected_sha256: str = '',
        actor: str | None = None,
    ) -> dict[str, Any]:
        values = {
            'evidence_id': evidence_id,
            'source': source,
            'acquired': acquired,
            'tool': tool,
            'expected_sha256': expected_sha256,
        }
        with self.open_case(case_dir, actor=actor) as case:
            case.register_source(values)
            evidence = case.data['evidence']
            return {
                'case_dir': str(case.folder),
                'image_path': evidence['path'],
                'provenance': evidence.get('provenance', {}),
                'source_fields': SOURCE_FIELDS,
                'source_comparison': source_status(evidence),
            }

    def scan_partitions(
        self,
        *,
        case_dir: str,
        partition_offset: int | None = None,
        verify_large_image: bool = False,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            self._ensure_large_image_session(case, verify_if_needed=verify_large_image)
            if partition_offset is not None:
                entries = case.scan(partition_offset)
            else:
                entries = case.scan_all()
            return {
                'case_dir': str(case.folder),
                'partition_offset': partition_offset,
                'inventory_count': len(entries),
                'partition_scans': case.data.get('partition_scans', []),
            }

    def list_files(
        self,
        *,
        case_dir: str,
        partition_offset: int | None = None,
        path_prefix: str = '',
        suffix: str = '',
        keyword: str = '',
        status: str = 'all',
        files_only: bool = False,
        dir_inode: str | None = None,
        dir_path: str = '',
        limit: int = 50,
        offset: int = 0,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            if not case.data.get('evidence'):
                raise ValueError('当前案件尚未加载镜像，请先调用 tracedesk_load_image。')
            if case.browsing_directories:
                target_offset = partition_offset
                if target_offset is None:
                    partitions = case.data['evidence'].get('partitions', [])
                    if not partitions:
                        raise ValueError('当前镜像未识别到分区。')
                    target_offset = partitions[0]['offset']
                entries = case.browse_directory(target_offset, dir_inode or None, _normalize_entry_path(dir_path))
                mode = 'directory_browse'
            else:
                entries = case.data['inventory']
                mode = 'full_inventory'

            norm_prefix = _normalize_entry_path(path_prefix).rstrip('/').casefold()
            norm_suffix = suffix.strip().lower()
            if norm_suffix and not norm_suffix.startswith('.'):
                norm_suffix = '.' + norm_suffix
            norm_keyword = keyword.strip().casefold()

            matched = []
            for entry in entries:
                if partition_offset is not None and entry['offset'] != partition_offset:
                    continue
                if files_only and (entry.get('directory') or entry.get('mode', '').startswith('V/')):
                    continue
                if status == 'active' and entry_status(entry) != '现存':
                    continue
                if status == 'deleted' and not entry.get('deleted', False):
                    continue
                if status == 'system' and not entry.get('mode', '').startswith(('v/', 'V/')):
                    continue
                entry_path_cf = _normalize_entry_path(entry['path']).casefold()
                if norm_prefix and not (entry_path_cf == norm_prefix or entry_path_cf.startswith(norm_prefix + '/')):
                    continue
                if norm_suffix and not entry['path'].lower().endswith(norm_suffix):
                    continue
                if norm_keyword and norm_keyword not in entry_path_cf and norm_keyword not in entry_name(entry).casefold():
                    continue
                matched.append(_format_entry(entry))

            return {
                'case_dir': str(case.folder),
                'browse_mode': mode,
                **_paginate(matched, limit=limit, offset=offset),
            }

    def preview_file(
        self,
        *,
        case_dir: str,
        path: str,
        partition_offset: int | None = None,
        inode: str | None = None,
        deleted: bool | None = None,
        dir_inode: str | None = None,
        dir_path: str = '',
        page: int = 0,
        page_bytes: int = PAGE_BYTES,
        encoding: str = 'UTF-8',
        mode: str = 'both',
        actor: str | None = None,
    ) -> dict[str, Any]:
        if encoding not in PREVIEW_ENCODINGS:
            raise ValueError(f'不支持的编码 {encoding}；可选编码：{", ".join(PREVIEW_ENCODINGS)}')

        with self.open_case(case_dir, actor=actor) as case:
            entry = self._find_entry(
                case,
                path,
                partition_offset=partition_offset,
                inode=inode,
                deleted=deleted,
                dir_inode=dir_inode,
                dir_path=dir_path,
            )
            if entry.get('directory') or entry.get('mode', '').startswith('V/'):
                raise ValueError(f'{entry["path"]} 是目录，无法按文件内容预览。')

            validate = case.check_source if case.data['evidence'].get('large_image') else None
            reader = PreviewReader(case.image(), entry, page_bytes=page_bytes, encoding=encoding, validate=validate)
            try:
                res_page, window, size, note = reader.results.get(timeout=30)
                if res_page is None:
                    raise RuntimeError(note or '无法读取文件内容')
                if page > 0:
                    reader.pages.put(page)
                    res_page, window, size, note = reader.results.get(timeout=30)
                    if res_page is None:
                        raise RuntimeError(note or '无法读取指定页')
            finally:
                reader.close()

            start = res_page * page_bytes
            total_pages = max(1, math.ceil(size / page_bytes)) if size else 1
            result: dict[str, Any] = {
                'case_dir': str(case.folder),
                'entry': _format_entry(entry),
                'encoding': encoding,
                'page': res_page,
                'total_pages': total_pages,
                'page_bytes': page_bytes,
                'byte_start': start,
                'byte_end': min(size, start + page_bytes),
                'readable_size': size,
                'recorded_size': entry['size'],
                'read_note': note,
                'source_note': deleted_source_note(entry),
            }
            if mode in ('text', 'both'):
                result['text'] = preview_text(window, start, size, encoding, page_bytes)
            if mode in ('hex', 'both'):
                rows = list(preview_rows(window, start, size, encoding, page_bytes))
                result['hex_lines'] = [f'{addr}  {hex_bytes:<47}  {chars}' for addr, hex_bytes, chars in rows]
            return result

    def search_content(
        self,
        *,
        case_dir: str,
        query: str,
        encoding: str = 'UTF-8',
        path: str | None = None,
        partition_offset: int | None = None,
        inode: str | None = None,
        deleted: bool | None = None,
        dir_inode: str | None = None,
        dir_path: str = '',
        max_hits: int = 200,
        limit: int = 50,
        offset: int = 0,
        verify_large_image: bool = False,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            self._ensure_large_image_session(case, verify_if_needed=verify_large_image)
            selected = None
            if path:
                selected = self._find_entry(
                    case,
                    path,
                    partition_offset=partition_offset,
                    inode=inode,
                    deleted=deleted,
                    dir_inode=dir_inode,
                    dir_path=dir_path,
                )
            control = SearchControl()
            record, _, report_name = run_content_search(
                case,
                query,
                encoding,
                control,
                lambda stage, done, total: None,
                limit=max_hits,
                selected=selected,
            )
            page_data = _paginate(record['hits'], limit=limit, offset=offset)
            return {
                'case_dir': str(case.folder),
                'report_file': str(case.folder / 'reports' / report_name),
                'query': record['query'],
                'encoding': record['encoding'],
                'needle_hex': record['needle'],
                'scope': record['scope'],
                'status': record['status'],
                'verification': record['verification'],
                'visited': record['visited'],
                'eligible': record['eligible'],
                'errors_count': len(record['errors']),
                'errors': record['errors'][:20],
                **page_data,
            }

    def examine_file(
        self,
        *,
        case_dir: str,
        path: str,
        partition_offset: int | None = None,
        inode: str | None = None,
        deleted: bool | None = None,
        dir_inode: str | None = None,
        dir_path: str = '',
        comparison_path: str | None = None,
        verify_large_image: bool = False,
        actor: str | None = None,
    ) -> dict[str, Any]:
        comparison = None
        if comparison_path:
            comparison = Path(comparison_path).resolve()
            if not comparison.is_file():
                raise FileNotFoundError(f'对照文件不存在：{comparison}')
        with self.open_case(case_dir, actor=actor) as case:
            self._ensure_large_image_session(case, verify_if_needed=verify_large_image)
            entry = self._find_entry(
                case,
                path,
                partition_offset=partition_offset,
                inode=inode,
                deleted=deleted,
                dir_inode=dir_inode,
                dir_path=dir_path,
            )
            result, details = examine_entry(case, entry, comparison=comparison)
            return {
                'case_dir': str(case.folder),
                'operation': 'FILE_COMPARE' if comparison is not None else 'FILE_HASH',
                'path': entry['path'],
                'partition_offset': entry['offset'],
                'inode': str(entry['inode']),
                'deleted': bool(entry.get('deleted', False)),
                'result': result,
                'details': details,
            }

    def record_finding(
        self,
        *,
        case_dir: str,
        path: str,
        note: str,
        partition_offset: int | None = None,
        inode: str | None = None,
        deleted: bool | None = None,
        dir_inode: str | None = None,
        dir_path: str = '',
        verify_large_image: bool = False,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            self._ensure_large_image_session(case, verify_if_needed=verify_large_image)
            entry = self._find_entry(
                case,
                path,
                partition_offset=partition_offset,
                inode=inode,
                deleted=deleted,
                dir_inode=dir_inode,
                dir_path=dir_path,
            )
            record_note(case, entry, note)
            latest = case.check_audit()[-1]
            return {
                'case_dir': str(case.folder),
                'seq': latest['seq'],
                'timestamp': display_time(latest['timestamp']),
                'origin': audit_origin(latest),
                'origin_label': audit_origin_label(latest),
                'actor': latest['actor'],
                'path': entry['path'],
                'partition_offset': entry['offset'],
                'inode': str(entry['inode']),
                'deleted': bool(entry.get('deleted', False)),
                'note': latest['details'].get('note', ''),
                'audit_hash': latest['hash'],
            }

    def _filtered_finding_groups(
        self,
        records: list[dict[str, Any]],
        *,
        status: str = 'all',
        partition_offset: int | None = None,
        keyword: str = '',
    ) -> list[list[dict[str, Any]]]:
        groups = list(group_findings(records).values())
        needle = keyword.strip().casefold()
        matched = []
        for items in groups:
            first = items[0]
            details = first['details']
            deleted = bool(details.get('deleted', False))
            if status == 'active' and deleted:
                continue
            if status == 'deleted' and not deleted:
                continue
            if partition_offset is not None and details.get('offset') != partition_offset:
                continue
            if needle:
                haystack = ' '.join(
                    [
                        first['subject'],
                        str(details.get('inode', '')),
                        *(str(item['details'].get('note', '')) for item in items),
                        *(str(item['details'].get('sha256', '')) for item in items),
                    ]
                ).casefold()
                if needle not in haystack:
                    continue
            matched.append(items)
        return matched

    def list_findings(
        self,
        *,
        case_dir: str,
        status: str = 'all',
        partition_offset: int | None = None,
        keyword: str = '',
        limit: int = 50,
        offset: int = 0,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            records = case.check_audit()
            groups = self._filtered_finding_groups(
                records, status=status, partition_offset=partition_offset, keyword=keyword
            )
            formatted = []
            for items in groups:
                first = items[0]
                d = first['details']
                formatted.append({
                    'path': first['subject'],
                    'partition_offset': d['offset'],
                    'inode': str(d['inode']),
                    'deleted': bool(d['deleted']),
                    'status': '已删除' if d['deleted'] else '现存',
                    'image_sha256': d.get('image_sha256') or '',
                    'records': [
                        {
                            'seq': r['seq'],
                            'timestamp': display_time(r['timestamp']),
                            'origin': audit_origin(r),
                            'origin_label': audit_origin_label(r),
                            'actor': r['actor'],
                            'action': r['action'],
                            'operation': OPERATIONS.get(r['action'], r['action']),
                            'result': r['result'],
                            'details': r['details'],
                        }
                        for r in items
                    ],
                })
            return {'case_dir': str(case.folder), **_paginate(formatted, limit=limit, offset=offset)}

    def query_timeline(
        self,
        *,
        case_dir: str,
        event: str | None = None,
        status: str | None = None,
        partition_offset: int | None = None,
        query: str = '',
        sort_order: str = 'asc',
        limit: int = 50,
        offset: int = 0,
        actor: str | None = None,
    ) -> dict[str, Any]:
        normalized_event = None
        if event:
            key = event.strip()
            normalized_event = EVENT_ALIASES.get(key.upper(), key)
            if normalized_event not in VALID_EVENT_LABELS:
                raise ValueError(
                    f'无效的时间线事件筛选：{event}。可选：M / A / C / B 或 {", ".join(sorted(VALID_EVENT_LABELS))}'
                )
        with self.open_case(case_dir, actor=actor) as case:
            if not case.data.get('evidence'):
                raise ValueError('当前案件尚未加载镜像。')
            if case.browsing_directories:
                raise ValueError('大容量镜像尚未建立完整文件索引，请先调用 tracedesk_scan_partitions。')
            timeline = TimelineEvents(case.data['inventory'])
            filters: dict[int, Any] = {}
            if normalized_event is not None:
                filters[2] = normalized_event
            if status:
                filters[3] = status.strip()
            if partition_offset is not None:
                filters[4] = str(partition_offset)
            indices = timeline.matching(query=query, filters=filters)
            total = len(indices)
            if sort_order == 'desc':
                selected_indices = [indices[total - 1 - i] for i in range(offset, min(total, offset + limit))]
            else:
                selected_indices = [indices[i] for i in range(offset, min(total, offset + limit))]
            items = [timeline[idx] for idx in selected_indices]
            has_more = offset + len(items) < total
            events_opt, statuses_opt, offsets_opt = timeline.filter_options()
            return {
                'case_dir': str(case.folder),
                'total': total,
                'count': len(items),
                'offset': offset,
                'limit': limit,
                'has_more': has_more,
                'next_offset': offset + len(items) if has_more else None,
                'sort_order': sort_order,
                'available_filters': {
                    'events': events_opt,
                    'statuses': statuses_opt,
                    'partition_offsets': offsets_opt,
                },
                'items': items,
            }

    def query_audit_log(
        self,
        *,
        case_dir: str,
        origin: str = 'all',
        action: str | None = None,
        actor_filter: str | None = None,
        result: str | None = None,
        query: str = '',
        sort_order: str = 'desc',
        limit: int = 50,
        offset: int = 0,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            records = case.check_audit()
            audit_head = records[-1]['hash'] if records else ''
            mcp_total = sum(1 for r in records if audit_origin(r) == 'mcp')
            origin_counts = {'manual': len(records) - mcp_total, 'mcp': mcp_total}
            origin_filter = origin.strip().lower() if origin else 'all'
            action_cf = action.strip().casefold() if action else None
            actor_cf = actor_filter.strip().casefold() if actor_filter else None
            result_cf = result.strip().casefold() if result else None
            query_cf = query.strip().casefold()

            matched = []
            for r in records:
                rec_origin = audit_origin(r)
                rec_origin_label = audit_origin_label(r)
                if origin_filter in ('manual', 'mcp') and rec_origin != origin_filter:
                    continue
                title = ACTION_TITLES.get(r['action'], r['action'])
                if action_cf and r['action'].casefold() != action_cf and title.casefold() != action_cf:
                    continue
                if actor_cf and actor_cf not in r['actor'].casefold():
                    continue
                if result_cf and r['result'].casefold() != result_cf:
                    continue
                formatted_time = display_time(r['timestamp'])
                if query_cf:
                    blob = json.dumps(
                        [r['seq'], formatted_time, rec_origin, rec_origin_label, r['actor'], r['action'], title, r['subject'], r['result'], r['details']],
                        ensure_ascii=False,
                    ).casefold()
                    if query_cf not in blob:
                        continue
                matched.append({
                    'seq': r['seq'],
                    'timestamp': formatted_time,
                    'origin': rec_origin,
                    'origin_label': rec_origin_label,
                    'actor': r['actor'],
                    'action': r['action'],
                    'action_title': title,
                    'subject': r['subject'],
                    'result': r['result'],
                    'details': r['details'],
                    'previous': r['previous'],
                    'hash': r['hash'],
                })

            if sort_order == 'desc':
                matched.reverse()

            return {
                'case_dir': str(case.folder),
                'audit_chain_valid': True,
                'audit_head': audit_head,
                'origin_counts': origin_counts,
                'sort_order': sort_order,
                **_paginate(matched, limit=limit, offset=offset),
            }

    def export_file(
        self,
        *,
        case_dir: str,
        path: str,
        partition_offset: int | None = None,
        inode: str | None = None,
        deleted: bool | None = None,
        dir_inode: str | None = None,
        dir_path: str = '',
        verify_large_image: bool = False,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            self._ensure_large_image_session(case, verify_if_needed=verify_large_image)
            entry = self._find_entry(
                case,
                path,
                partition_offset=partition_offset,
                inode=inode,
                deleted=deleted,
                dir_inode=dir_inode,
                dir_path=dir_path,
            )
            destination = case.export(entry)
            record = case.data['exports'][-1]
            return {
                'case_dir': str(case.folder),
                'exported_path': str(destination),
                'record': record,
            }

    def export_findings(
        self,
        *,
        case_dir: str,
        status: str = 'all',
        partition_offset: int | None = None,
        keyword: str = '',
        verify_large_image: bool = False,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            self._ensure_large_image_session(case, verify_if_needed=verify_large_image)
            records = case.check_audit()
            groups = self._filtered_finding_groups(
                records, status=status, partition_offset=partition_offset, keyword=keyword
            )
            summary_path, exported_count, failed = do_export_findings(case, groups)
            return {
                'case_dir': str(case.folder),
                'summary_path': str(summary_path),
                'total_groups': len(groups),
                'exported_count': exported_count,
                'failed_count': len(failed),
                'failed': [{'path': item[0], 'reason': item[1]} for item in failed],
            }

    def generate_report(
        self,
        *,
        case_dir: str,
        verify_large_image: bool = False,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            self._ensure_large_image_session(case, verify_if_needed=verify_large_image)
            report_path = case.report()
            latest = case.check_audit()[-1]
            return {
                'case_dir': str(case.folder),
                'report_path': str(report_path),
                'sha256': latest['details'].get('sha256', ''),
                'verification': case.data.get('verification'),
            }

    def build_review_bundle(
        self,
        *,
        case_dir: str,
        verify_large_image: bool = False,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.open_case(case_dir, actor=actor) as case:
            self._ensure_large_image_session(case, verify_if_needed=verify_large_image)
            bundle_path = build_bundle(case)
            sha_file = bundle_path.with_suffix('.zip.sha256')
            latest = case.check_audit()[-1]
            return {
                'case_dir': str(case.folder),
                'bundle_path': str(bundle_path),
                'sha256_file': str(sha_file),
                'sha256': latest['details'].get('sha256', ''),
            }
