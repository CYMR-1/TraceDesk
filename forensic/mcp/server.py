"""TraceDesk FastMCP 服务端：提供标准 MCP 工具与资源，支持 stdio 和本地 Streamable HTTP。"""
from enum import Enum
import json
from pathlib import Path
from typing import Any, Callable, Optional

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from ..core.preview import PAGE_BYTES, PREVIEW_ENCODINGS
from .service import CaseService


DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 8765
DEFAULT_HTTP_PATH = '/mcp'

SERVER_INSTRUCTIONS = (
    'TraceDesk 是本地电子数据取证工作台 MCP 服务。'
    '所有源镜像（RAW / 分段 EWF .E01）均以只读方式打开，绝不修改原始证据；'
    '所有受控写操作（新建案件、载入镜像、校验、登记来源、搜索、记录发现、导出、生成报告与复核包）'
    '都会写入案件目录并追加到可核验 SHA-256 审计哈希链。'
    '同名或跨分区文件请通过 partition_offset、inode 和 deleted 参数唯一定位。'
    '界面与返回时间统一采用东八区（UTC+8）。'
)


TOOL_CATALOG: tuple[dict[str, Any], ...] = (
    {'name': 'tracedesk_list_cases', 'title': '列出案件', 'category': '案件管理', 'read_only': True,
     'summary': '列出案件库目录中的已有取证案件及其摘要状态'},
    {'name': 'tracedesk_create_case', 'title': '新建案件', 'category': '案件管理', 'read_only': False,
     'summary': '创建隔离的取证案件目录、元数据与审计链起点'},
    {'name': 'tracedesk_get_case_summary', 'title': '案件总览', 'category': '案件管理', 'read_only': True,
     'summary': '查看案件元数据、镜像哈希、覆盖范围、分区扫描与审计链状态'},
    {'name': 'tracedesk_load_image', 'title': '加载镜像', 'category': '证据镜像', 'read_only': False,
     'summary': '以只读方式加载 RAW 或 .E01 首段镜像，固定 SHA-256 并识别分区'},
    {'name': 'tracedesk_verify_integrity', 'title': '校验完整性', 'category': '证据镜像', 'read_only': False,
     'summary': '复算镜像 SHA-256 并与初始固定基线比对，更新校验记录'},
    {'name': 'tracedesk_register_source', 'title': '登记证据来源', 'category': '证据镜像', 'read_only': False,
     'summary': '登记证据编号、交付方、采集时间/工具和交付方 SHA-256'},
    {'name': 'tracedesk_scan_partitions', 'title': '扫描分区清单', 'category': '证据镜像', 'read_only': False,
     'summary': '扫描全部分区或指定偏移分区，建立/刷新完整文件清单'},
    {'name': 'tracedesk_list_files', 'title': '浏览与筛选文件', 'category': '文件分析', 'read_only': True,
     'summary': '按分区、路径前缀、后缀、关键词和状态分页查询镜像内文件'},
    {'name': 'tracedesk_preview_file', 'title': '预览文件内容', 'category': '文件分析', 'read_only': True,
     'summary': '按页读取文件或系统区域的文本（多编码）与十六进制转储'},
    {'name': 'tracedesk_search_content', 'title': '搜索文件内容', 'category': '文件分析', 'read_only': False,
     'summary': '按 UTF-8 / UTF-16LE / GBK / HEX 精确搜索全案或单文件字节'},
    {'name': 'tracedesk_examine_file', 'title': '计算文件哈希/比对', 'category': '文件分析', 'read_only': False,
     'summary': '直接从只读镜像计算文件 SHA-256，或与本地副本核验一致性'},
    {'name': 'tracedesk_record_finding', 'title': '记录取证发现', 'category': '取证发现', 'read_only': False,
     'summary': '绑定镜像摘要、分区偏移、路径与 inode 写入结构化取证笔记'},
    {'name': 'tracedesk_list_findings', 'title': '查询取证发现', 'category': '取证发现', 'read_only': True,
     'summary': '按文件归组查看取证笔记、哈希计算与副本比对记录'},
    {'name': 'tracedesk_query_timeline', 'title': '查询 MACB 时间线', 'category': '时间线与审计', 'read_only': True,
     'summary': '按事件类型、状态、分区偏移与关键词分页查询 MACB 时间线'},
    {'name': 'tracedesk_query_audit_log', 'title': '核验并查询审计日志', 'category': '时间线与审计', 'read_only': True,
     'summary': '核验审计哈希链完整性，并按操作/人员/结果分页检索日志'},
    {'name': 'tracedesk_export_file', 'title': '导出单个文件', 'category': '导出与报告', 'read_only': False,
     'summary': '导出镜像中现存或已删除文件到案件 exports 目录并记录副本哈希'},
    {'name': 'tracedesk_export_findings', 'title': '一键导出取证发现', 'category': '导出与报告', 'read_only': False,
     'summary': '批量导出取证发现涉及的文件副本及 Markdown 汇总清单'},
    {'name': 'tracedesk_generate_report', 'title': '生成 Markdown 报告', 'category': '导出与报告', 'read_only': False,
     'summary': '执行完整性校验并生成分节 Markdown 取证报告'},
    {'name': 'tracedesk_build_review_bundle', 'title': '构建复核包 ZIP', 'category': '导出与报告', 'read_only': False,
     'summary': '生成含报告、副本、搜索记录、审计链与 SHA256SUMS 的复核包'},
)


class ResponseFormat(str, Enum):
    MARKDOWN = 'markdown'
    JSON = 'json'


class FileStatusFilter(str, Enum):
    ALL = 'all'
    ACTIVE = 'active'
    DELETED = 'deleted'
    SYSTEM = 'system'


class FindingStatusFilter(str, Enum):
    ALL = 'all'
    ACTIVE = 'active'
    DELETED = 'deleted'


class PreviewMode(str, Enum):
    TEXT = 'text'
    HEX = 'hex'
    BOTH = 'both'


class SearchEncoding(str, Enum):
    UTF8 = 'UTF-8'
    UTF16LE = 'UTF-16LE'
    GBK = 'GBK'
    HEX = 'HEX'


class SortOrder(str, Enum):
    ASC = 'asc'
    DESC = 'desc'


class AuditOriginFilter(str, Enum):
    ALL = 'all'
    MANUAL = 'manual'
    MCP = 'mcp'


class _BaseInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra='forbid')


class _CaseBaseInput(_BaseInput):
    case_dir: str = Field(..., min_length=1, description='案件目录路径（绝对路径、相对案件库文件夹名，或 case.json 路径）')
    actor: Optional[str] = Field(default=None, max_length=80, description='可选操作人员标识，写入审计日志；无论是否指定，MCP 调用均在审计链中固定标记为 MCP 来源')
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description='输出格式：markdown 或 json')


class _EntryLocatorInput(_CaseBaseInput):
    path: str = Field(..., min_length=1, description='镜像内文件路径，例如 DOCS/CASE.TXT 或 README.TXT')
    partition_offset: Optional[int] = Field(default=None, ge=0, description='可选分区起始扇区偏移，用于区分跨分区同名文件')
    inode: Optional[str] = Field(default=None, max_length=64, description='可选 inode 标识，用于区分同路径多条记录')
    deleted: Optional[bool] = Field(default=None, description='可选删除标记（true=已删除，false=现存）')
    dir_inode: Optional[str] = Field(default=None, max_length=64, description='仅大容量镜像快速浏览模式需要：所在目录 inode')
    dir_path: str = Field(default='', description='仅大容量镜像快速浏览模式需要：所在目录路径')


class ListCasesInput(_BaseInput):
    cases_root: Optional[str] = Field(default=None, description='可选案件库目录路径，省略时使用默认 cases 目录')
    limit: int = Field(default=20, ge=1, le=200, description='每页最多返回案件数（1-200）')
    offset: int = Field(default=0, ge=0, description='分页偏移量')
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description='输出格式：markdown 或 json')


class CreateCaseInput(_BaseInput):
    number: str = Field(..., min_length=1, max_length=120, description='案件编号，例如 CASE-2026-01')
    examiner: str = Field(..., min_length=1, max_length=80, description='取证人员姓名或工号')
    target: str = Field(..., min_length=1, max_length=200, description='取证对象说明，例如 FAT16 演示镜像')
    cases_root: Optional[str] = Field(default=None, description='可选案件库根目录，省略时使用项目默认 cases 目录')
    folder_name: Optional[str] = Field(default=None, max_length=180, description='可选自定义案件目录名，省略时自动按“编号-人员-对象”生成')
    actor: Optional[str] = Field(default=None, max_length=80, description='可选操作人员标识（默认使用取证人员，审计来源固定标记为 MCP）')
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description='输出格式：markdown 或 json')


class CaseSummaryInput(_CaseBaseInput):
    pass


class LoadImageInput(_CaseBaseInput):
    image_path: str = Field(..., min_length=1, description='源镜像路径（RAW 镜像或分段 EWF 的 .E01 首段），必须位于案件库目录之外')
    scan_all: bool = Field(default=True, description='小于 1 GiB 的镜像是否在载入后自动扫描全部分区文件树（默认 true）')


class VerifyIntegrityInput(_CaseBaseInput):
    pass


class RegisterSourceInput(_CaseBaseInput):
    evidence_id: str = Field(default='', max_length=120, description='证据编号')
    source: str = Field(default='', max_length=200, description='来源 / 交付方')
    acquired: str = Field(default='', max_length=120, description='采集时间与时区')
    tool: str = Field(default='', max_length=160, description='采集工具与版本')
    expected_sha256: str = Field(default='', max_length=64, description='交付方提供的 64 位十六进制 SHA-256（可选）')


class ScanPartitionsInput(_CaseBaseInput):
    partition_offset: Optional[int] = Field(default=None, ge=0, description='指定要扫描的单个分区扇区偏移；省略时扫描全部已识别分区')
    verify_large_image: bool = Field(default=False, description='大容量镜像（>=1 GiB）已固定基线时，是否在扫描前先执行整镜像复算校验')


class ListFilesInput(_CaseBaseInput):
    partition_offset: Optional[int] = Field(default=None, ge=0, description='按分区起始扇区偏移筛选')
    path_prefix: str = Field(default='', description='按路径前缀筛选，例如 DOCS')
    suffix: str = Field(default='', max_length=32, description='按扩展名筛选，例如 .txt 或 txt')
    keyword: str = Field(default='', max_length=120, description='按路径或文件名关键词筛选（不区分大小写）')
    status: FileStatusFilter = Field(default=FileStatusFilter.ALL, description='状态筛选：all / active / deleted / system')
    files_only: bool = Field(default=False, description='仅返回文件，排除目录项')
    dir_inode: Optional[str] = Field(default=None, max_length=64, description='仅大容量镜像快速浏览模式有效：要浏览的目录 inode')
    dir_path: str = Field(default='', description='仅大容量镜像快速浏览模式有效：要浏览的目录路径')
    limit: int = Field(default=50, ge=1, le=200, description='每页返回条目数（1-200）')
    offset: int = Field(default=0, ge=0, description='分页偏移量')


class PreviewFileInput(_EntryLocatorInput):
    page: int = Field(default=0, ge=0, description='页码（从 0 开始）')
    page_bytes: int = Field(default=PAGE_BYTES, ge=64, le=16384, description='每页读取字节数（64-16384，默认 4096）')
    encoding: str = Field(
        default='UTF-8',
        description='文本解码编码，可选：' + ', '.join(PREVIEW_ENCODINGS),
    )
    mode: PreviewMode = Field(default=PreviewMode.BOTH, description='返回内容模式：text / hex / both')


class SearchContentInput(_CaseBaseInput):
    query: str = Field(..., min_length=1, max_length=4096, description='要检索的文本或 HEX 字节串（如 "6E 6F 74 65"）')
    encoding: SearchEncoding = Field(default=SearchEncoding.UTF8, description='检索编码：UTF-8 / UTF-16LE / GBK / HEX')
    path: Optional[str] = Field(default=None, description='可选单文件路径；指定时仅搜索该文件，省略时搜索全部可读取清单')
    partition_offset: Optional[int] = Field(default=None, ge=0, description='配合 path 使用：指定分区起始扇区偏移')
    inode: Optional[str] = Field(default=None, max_length=64, description='配合 path 使用：指定 inode')
    deleted: Optional[bool] = Field(default=None, description='配合 path 使用：指定删除标记')
    dir_inode: Optional[str] = Field(default=None, max_length=64, description='仅大容量镜像单文件搜索需要：所在目录 inode')
    dir_path: str = Field(default='', description='仅大容量镜像单文件搜索需要：所在目录路径')
    max_hits: int = Field(default=200, ge=1, le=5000, description='单次搜索最多收集命中条数（1-5000）')
    limit: int = Field(default=50, ge=1, le=200, description='本次响应最多返回命中条数（1-200）')
    offset: int = Field(default=0, ge=0, description='命中列表分页偏移量')
    verify_large_image: bool = Field(default=False, description='大容量镜像已固定基线时，是否在搜索前执行整镜像校验')


class ExamineFileInput(_EntryLocatorInput):
    comparison_path: Optional[str] = Field(default=None, description='可选本地对照文件路径；省略时仅计算镜像文件 SHA-256，提供时进行一致性比对')
    verify_large_image: bool = Field(default=False, description='大容量镜像已固定基线时，是否在操作前执行整镜像校验')


class RecordFindingInput(_EntryLocatorInput):
    note: str = Field(..., min_length=1, max_length=4000, description='取证发现说明与依据，将写入案件审计链并纳入报告')
    verify_large_image: bool = Field(default=False, description='大容量镜像已固定基线时，是否在操作前执行整镜像校验')


class ListFindingsInput(_CaseBaseInput):
    status: FindingStatusFilter = Field(default=FindingStatusFilter.ALL, description='状态筛选：all / active / deleted')
    partition_offset: Optional[int] = Field(default=None, ge=0, description='按分区起始扇区偏移筛选')
    keyword: str = Field(default='', max_length=120, description='按路径、inode、笔记或哈希关键词筛选')
    limit: int = Field(default=50, ge=1, le=200, description='每页返回归组文件数（1-200）')
    offset: int = Field(default=0, ge=0, description='分页偏移量')


class QueryTimelineInput(_CaseBaseInput):
    event: Optional[str] = Field(default=None, description='事件类型筛选：M / A / C / B，或完整中文名（如 "M 内容修改"）')
    status: Optional[str] = Field(default=None, description='文件状态筛选，例如 现存 / 已删除 / 系统区域')
    partition_offset: Optional[int] = Field(default=None, ge=0, description='按分区起始扇区偏移筛选')
    query: str = Field(default='', max_length=120, description='按路径、时间、inode 或状态关键词筛选')
    sort_order: SortOrder = Field(default=SortOrder.ASC, description='时间排序方向：asc（正序）或 desc（倒序）')
    limit: int = Field(default=50, ge=1, le=200, description='每页返回事件数（1-200）')
    offset: int = Field(default=0, ge=0, description='分页偏移量')


class QueryAuditLogInput(_CaseBaseInput):
    origin: AuditOriginFilter = Field(default=AuditOriginFilter.ALL, description='按操作来源筛选：all（全部）/ manual（人工）/ mcp（MCP）')
    action: Optional[str] = Field(default=None, description='按操作代码或中文名称筛选，例如 FILE_EXPORT 或 导出文件')
    actor_filter: Optional[str] = Field(default=None, description='按操作人员关键词筛选')
    result: Optional[str] = Field(default=None, description='按结果筛选，例如 成功 / 失败 / 通过')
    query: str = Field(default='', max_length=120, description='按对象、详情或哈希关键词筛选')
    sort_order: SortOrder = Field(default=SortOrder.DESC, description='排序方向：desc（最新在前）或 asc（最早在前）')
    limit: int = Field(default=50, ge=1, le=200, description='每页返回日志条数（1-200）')
    offset: int = Field(default=0, ge=0, description='分页偏移量')


class ExportFileInput(_EntryLocatorInput):
    verify_large_image: bool = Field(default=False, description='大容量镜像已固定基线时，是否在导出前执行整镜像校验')


class ExportFindingsInput(_CaseBaseInput):
    status: FindingStatusFilter = Field(default=FindingStatusFilter.ALL, description='仅导出指定状态的发现：all / active / deleted')
    partition_offset: Optional[int] = Field(default=None, ge=0, description='仅导出指定分区偏移的发现')
    keyword: str = Field(default='', max_length=120, description='仅导出匹配关键词的发现')
    verify_large_image: bool = Field(default=False, description='大容量镜像已固定基线时，是否在导出前执行整镜像校验')


class ReportActionInput(_CaseBaseInput):
    verify_large_image: bool = Field(default=False, description='大容量镜像在生成正式报告或复核包前需要本次会话校验，设为 true 可自动复算')


class ReviewBundleInput(ReportActionInput):
    selected_export_indices: Optional[list[int]] = Field(
        default=None,
        description='可选要纳入复核包的导出记录序号列表（从 1 开始）；省略时默认纳入全部历史导出',
    )
    skip_missing_exports: bool = Field(
        default=False,
        description='本地 exports 目录中存在缺失副本时，是否自动跳过缺失项并在 manifest.json 的 omitted_exports 中标注（默认 false）',
    )


def _to_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _format_error(error: Exception) -> str:
    return f'Error ({type(error).__name__}): {error}'


def _render_cases_md(data: dict[str, Any]) -> str:
    lines = [
        '# TraceDesk 案件列表',
        f'- 案件库目录：`{data["cases_root"]}`',
        f'- 共 {data["total"]} 个案件，当前显示 {data["count"]} 个（offset={data["offset"]}）',
        '',
    ]
    if not data['items']:
        lines.append('当前案件库为空，可调用 `tracedesk_create_case` 新建案件。')
        return '\n'.join(lines)
    for item in data['items']:
        if item.get('status') != 'ok':
            lines.append(f'- **{item["name"]}**（元数据损坏）· `{item["folder"]}`')
            continue
        ev = f'{item["image_name"]}（{"已固定 SHA-256" if item["sha256_fixed"] else "待固定"}）' if item['has_evidence'] else '尚未加载镜像'
        lines.append(
            f'- **{item["number"]}** · {item["examiner"]} · {item["target"]}  \n'
            f'  目录：`{item["folder"]}` · 创建：{item["created"]} · 镜像：{ev} · 清单：{item["inventory_count"]} 项 · 导出：{item["exports_count"]} 项'
        )
    if data['has_more']:
        lines.append(f'\n> 还有更多案件，请使用 `offset={data["next_offset"]}` 继续翻页。')
    return '\n'.join(lines)


def _render_summary_md(data: dict[str, Any]) -> str:
    lines = [
        f'# 案件总览 · {data["number"]}',
        f'- **案件目录**：`{data["case_dir"]}`',
        f'- **取证人员**：{data["examiner"]} · **取证对象**：{data["target"]}',
        f'- **创建时间（UTC+8）**：{data["created"]}',
        f'- **清单条目**：{data["inventory_count"]} · **已导出**：{data["exports_count"]} · **取证发现**：{data["findings_file_count"]} 个文件（{data["findings_record_count"]} 条记录）',
        f'- **审计链**：校验通过（共 {data["audit_count"]} 条：人工 {data["audit_origin_counts"]["manual"]} · MCP {data["audit_origin_counts"]["mcp"]}，尾部锚点 `{data["audit_head"][:16]}…`）' if data['audit_head'] else '- **审计链**：暂无记录',
    ]
    ev = data.get('evidence')
    if not ev:
        lines.append('\n## 证据镜像\n尚未加载镜像，可调用 `tracedesk_load_image` 载入 RAW 或 .E01 镜像。')
        return '\n'.join(lines)
    lines.extend([
        '',
        '## 证据镜像',
        f'- **路径**：`{ev["path"]}`',
        f'- **格式 / 大小**：{ev["format"]} · {ev["size"]:,} 字节{"（大容量快速浏览模式）" if ev["large_image"] else ""}',
        f'- **SHA-256**：`{ev["sha256"] or "待固定"}`（固定时间：{ev["fixed_at"] or "未固定"}）',
        f'- **交付方摘要比对**：{ev["source_comparison"]}',
        f'- **声明范围评估**：{ev["coverage_text"]}',
        f'- **识别分区**：{len(ev["partitions"])} 个',
    ])
    for part in ev['partitions']:
        lines.append(f'  - 偏移 `{part["offset"]}` 扇区 · {part.get("description", "")}（长度 {part.get("length", 0)} 扇区）')
    if data.get('partition_scans'):
        lines.append('- **分区扫描状态**：')
        for scan in data['partition_scans']:
            extra = f'，错误：{scan["error"]}' if scan.get('error') else ''
            lines.append(f'  - 偏移 `{scan["offset"]}`：{scan["status"]}（{scan["count"]} 项{extra}）')
    return '\n'.join(lines)


def _render_files_md(data: dict[str, Any]) -> str:
    lines = [
        f'# 文件列表（{data["browse_mode"]}）',
        f'- 匹配总数：{data["total"]} · 当前返回：{data["count"]}（offset={data["offset"]}）',
        '',
    ]
    if not data['items']:
        lines.append('未匹配到任何条目。')
        return '\n'.join(lines)
    lines.append('| 路径 | 状态 | 分区偏移 | inode | 大小(字节) | 修改时间(UTC+8) |')
    lines.append('| --- | --- | ---: | --- | ---: | --- |')
    for item in data['items']:
        kind = '[目录] ' if item['directory'] else ''
        safe_path = (kind + item['path']).replace('|', '\\|')
        lines.append(
            f'| `{safe_path}` | {item["status"]} | {item["partition_offset"]} | `{item["inode"]}` | {item["size"]} | {item["mtime"] or "-"} |'
        )
    if data['has_more']:
        lines.append(f'\n> 还有更多条目，请使用 `offset={data["next_offset"]}` 继续翻页。')
    return '\n'.join(lines)


def _render_preview_md(data: dict[str, Any]) -> str:
    entry = data['entry']
    lines = [
        f'# 文件预览 · `{entry["path"]}`',
        f'- 分区偏移：`{entry["partition_offset"]}` · inode：`{entry["inode"]}` · 状态：{entry["status"]} · 编码：{data["encoding"]}',
        f'- 页码：{data["page"] + 1} / {data["total_pages"]} · 字节范围：{data["byte_start"]}..{data["byte_end"]} / 可读 {data["readable_size"]} 字节（目录记录 {data["recorded_size"]} 字节）',
    ]
    if data.get('source_note'):
        lines.append(f'- **删除提示**：{data["source_note"]}')
    if data.get('read_note'):
        lines.append(f'- **读取说明**：{data["read_note"]}')
    if 'text' in data:
        lines.extend(['', '## 文本内容', '```text', data['text'], '```'])
    if 'hex_lines' in data:
        lines.extend(['', '## 十六进制', '```text', '\n'.join(data['hex_lines']), '```'])
    return '\n'.join(lines)


def _render_search_md(data: dict[str, Any]) -> str:
    lines = [
        f'# 内容搜索结果 · `{data["query"]}` ({data["encoding"]})',
        f'- 状态：{data["status"]} · 范围：{data["scope"]} · 十六进制模式：`{data["needle_hex"]}`',
        f'- 校验方式：{data["verification"]}',
        f'- 扫描文件：{data["visited"]} / {data["eligible"]} · 命中总数：{data["total"]}（当前显示 {data["count"]}，offset={data["offset"]}） · 读取失败：{data["errors_count"]}',
        f'- 完整搜索记录：`{data["report_file"]}`',
        '',
    ]
    if not data['items']:
        lines.append('未命中任何内容。')
    else:
        for idx, hit in enumerate(data['items'], data['offset'] + 1):
            status = '已删除' if hit['deleted'] else '现存'
            lines.append(
                f'{idx}. `{hit["path"]}`（偏移 `{hit["offset"]}` / inode `{hit["inode"]}` / {status}）· '
                f'文件内字节偏移 **{hit["file_byte"]}** · 上下文 `{hit["before"]} | {data["needle_hex"]} | {hit["after"]}`'
            )
    if data['has_more']:
        lines.append(f'\n> 还有更多命中，请使用 `offset={data["next_offset"]}` 继续翻页。')
    return '\n'.join(lines)


def _render_findings_md(data: dict[str, Any]) -> str:
    lines = [
        '# 取证发现',
        f'- 归组文件数：{data["total"]} · 当前返回：{data["count"]}（offset={data["offset"]}）',
        '',
    ]
    if not data['items']:
        lines.append('当前尚无符合条件的取证发现。')
        return '\n'.join(lines)
    for group in data['items']:
        lines.append(f'## `{group["path"]}`（偏移 `{group["partition_offset"]}` · inode `{group["inode"]}` · {group["status"]}）')
        lines.append(f'- 来源镜像 SHA-256：`{group["image_sha256"] or "记录时待固定"}`')
        for r in group['records']:
            d = r['details']
            note = f' · 笔记：{d["note"]}' if d.get('note') else ''
            digest = f' · SHA-256：`{d["sha256"]}`' if d.get('sha256') else ''
            lines.append(f'  - `#{r["seq"]}` {r["timestamp"]} · [{r["origin_label"]}] · {r["actor"]} · {r["operation"]} · **{r["result"]}**{note}{digest}')
        lines.append('')
    if data['has_more']:
        lines.append(f'> 还有更多发现，请使用 `offset={data["next_offset"]}` 继续翻页。')
    return '\n'.join(lines)


def _render_timeline_md(data: dict[str, Any]) -> str:
    lines = [
        '# MACB 时间线（UTC+8）',
        f'- 匹配事件总数：{data["total"]} · 当前返回：{data["count"]}（offset={data["offset"]}，排序：{data["sort_order"]}）',
        '',
    ]
    if not data['items']:
        lines.append('未匹配到时间线事件。')
        return '\n'.join(lines)
    lines.append('| 时间（UTC+8） | 事件 | 路径 | 状态 | 分区偏移 | inode |')
    lines.append('| --- | --- | --- | --- | ---: | --- |')
    for item in data['items']:
        safe_path = item['path'].replace('|', '\\|')
        lines.append(
            f'| {item["time"]} | {item["event"]} | `{safe_path}` | {item["status"]} | {item["offset"]} | `{item["inode"]}` |'
        )
    if data['has_more']:
        lines.append(f'\n> 还有更多事件，请使用 `offset={data["next_offset"]}` 继续翻页。')
    return '\n'.join(lines)


def _render_audit_md(data: dict[str, Any]) -> str:
    counts = data.get('origin_counts', {})
    lines = [
        '# 审计日志（哈希链核验通过）',
        f'- 尾部锚点：`{data["audit_head"] or "无"}`',
        f'- 来源统计：人工 {counts.get("manual", 0)} 条 · MCP {counts.get("mcp", 0)} 条',
        f'- 匹配总数：{data["total"]} · 当前返回：{data["count"]}（offset={data["offset"]}，排序：{data["sort_order"]}）',
        '',
    ]
    if not data['items']:
        lines.append('未匹配到审计记录。')
        return '\n'.join(lines)
    for r in data['items']:
        lines.append(
            f'- `#{r["seq"]}` {r["timestamp"]} · **[{r["origin_label"]}]** · **{r["action_title"]}** (`{r["action"]}`) · {r["actor"]} · {r["result"]} · 对象：`{r["subject"]}`'
        )
    if data['has_more']:
        lines.append(f'\n> 还有更多日志，请使用 `offset={data["next_offset"]}` 继续翻页。')
    return '\n'.join(lines)


def _render_simple_kv_md(title: str, data: dict[str, Any]) -> str:
    lines = [f'# {title}']
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            lines.append(f'- **{key}**：\n```json\n{_to_json(value)}\n```')
        else:
            lines.append(f'- **{key}**：`{value}`' if value != '' else f'- **{key}**：（空）')
    return '\n'.join(lines)


def _format_output(data: dict[str, Any], fmt: ResponseFormat, md_renderer: Callable[[dict[str, Any]], str]) -> str:
    if fmt == ResponseFormat.JSON:
        return _to_json(data)
    return md_renderer(data)


async def _run_sync(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return await anyio.to_thread.run_sync(lambda: func(*args, **kwargs))


def create_server(
    *,
    cases_root: Path | str | None = None,
    default_actor: str | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    streamable_http_path: str = DEFAULT_HTTP_PATH,
    stateless_http: bool = True,
    json_response: bool = True,
) -> FastMCP:
    """构建并返回一个绑定 TraceDesk 取证业务的 FastMCP 实例。"""
    service = CaseService(cases_root=cases_root, default_actor=default_actor)
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[f'{host}:{port}', f'localhost:{port}', host, 'localhost'],
        allowed_origins=[f'http://{host}:{port}', f'http://localhost:{port}'],
    )
    mcp = FastMCP(
        name='tracedesk_mcp',
        instructions=SERVER_INSTRUCTIONS,
        host=host,
        port=port,
        streamable_http_path=streamable_http_path,
        stateless_http=stateless_http,
        json_response=json_response,
        transport_security=security,
    )

    @mcp.resource('tracedesk://cases', name='cases_list', description='默认案件库中的 TraceDesk 案件清单（JSON）')
    async def resource_cases() -> str:
        data = await _run_sync(service.list_cases, limit=200, offset=0)
        return _to_json(data)

    @mcp.resource('tracedesk://guide/workflow', name='forensic_workflow', description='TraceDesk 标准电子数据取证流程与证据边界说明')
    async def resource_workflow() -> str:
        return (
            '# TraceDesk MCP 标准取证流程\n\n'
            '1. 使用 `tracedesk_list_cases` 查看现有案件，或用 `tracedesk_create_case` 新建隔离案件。\n'
            '2. 使用 `tracedesk_load_image` 只读载入 RAW 或 `.E01` 首段镜像（镜像必须位于案件库目录之外）。\n'
            '3. 使用 `tracedesk_get_case_summary` 查看 SHA-256、卷声明范围和分区扫描状态。\n'
            '4. 使用 `tracedesk_list_files`、`tracedesk_preview_file`、`tracedesk_search_content`、`tracedesk_query_timeline` 开展分析。\n'
            '5. 使用 `tracedesk_examine_file` 校验文件哈希，用 `tracedesk_record_finding` 记录取证发现。\n'
            '6. 使用 `tracedesk_export_file` / `tracedesk_export_findings` 导出副本，并用 `tracedesk_generate_report` 或 `tracedesk_build_review_bundle` 输出正式报告和可核验复核包。\n\n'
            '注意：同名文件可能存在于不同分区或包含已删除记录，定位文件时请优先提供 `partition_offset`、`inode` 与 `deleted` 参数。'
        )

    @mcp.tool(
        name='tracedesk_list_cases',
        annotations=ToolAnnotations(
            title='列出 TraceDesk 案件',
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_list_cases(params: ListCasesInput) -> str:
        """列出案件库目录中的所有 TraceDesk 案件及其摘要状态（只读，不加锁）。"""
        try:
            data = await _run_sync(
                service.list_cases,
                cases_root=params.cases_root,
                limit=params.limit,
                offset=params.offset,
            )
            return _format_output(data, params.response_format, _render_cases_md)
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_create_case',
        annotations=ToolAnnotations(
            title='新建取证案件',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    async def tracedesk_create_case(params: CreateCaseInput) -> str:
        """创建新的隔离取证案件目录、元数据文件与初始审计链。"""
        try:
            data = await _run_sync(
                service.create_case,
                number=params.number,
                examiner=params.examiner,
                target=params.target,
                cases_root=params.cases_root,
                folder_name=params.folder_name,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('已创建新案件', d))
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_get_case_summary',
        annotations=ToolAnnotations(
            title='获取案件总览',
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_get_case_summary(params: CaseSummaryInput) -> str:
        """读取案件元数据、镜像哈希与覆盖范围、分区扫描状态以及审计链完整性结论。"""
        try:
            data = await _run_sync(service.get_case_summary, case_dir=params.case_dir, actor=params.actor)
            return _format_output(data, params.response_format, _render_summary_md)
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_load_image',
        annotations=ToolAnnotations(
            title='加载取证镜像',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    async def tracedesk_load_image(params: LoadImageInput) -> str:
        """以只读模式载入 RAW 或分段 EWF（.E01 首段）镜像，识别分区并固定 SHA-256。"""
        try:
            data = await _run_sync(
                service.load_image,
                case_dir=params.case_dir,
                image_path=params.image_path,
                scan_all=params.scan_all,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('镜像已载入', d))
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_verify_integrity',
        annotations=ToolAnnotations(
            title='校验镜像完整性',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_verify_integrity(params: VerifyIntegrityInput) -> str:
        """重新计算源镜像（或全部 EWF 分段）的 SHA-256，与初始固定基线比对并记录审计日志。"""
        try:
            data = await _run_sync(service.verify_integrity, case_dir=params.case_dir, actor=params.actor)
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('完整性校验结果', d))
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_register_source',
        annotations=ToolAnnotations(
            title='登记证据来源',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_register_source(params: RegisterSourceInput) -> str:
        """登记证据编号、来源、采集时间、采集工具和交付方 SHA-256，并与本机固定值比对。"""
        try:
            data = await _run_sync(
                service.register_source,
                case_dir=params.case_dir,
                evidence_id=params.evidence_id,
                source=params.source,
                acquired=params.acquired,
                tool=params.tool,
                expected_sha256=params.expected_sha256,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('证据来源已登记', d))
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_scan_partitions',
        annotations=ToolAnnotations(
            title='扫描分区文件清单',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_scan_partitions(params: ScanPartitionsInput) -> str:
        """扫描全部分区或单个指定扇区偏移的分区，建立或更新完整文件清单。"""
        try:
            data = await _run_sync(
                service.scan_partitions,
                case_dir=params.case_dir,
                partition_offset=params.partition_offset,
                verify_large_image=params.verify_large_image,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('分区扫描完成', d))
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_list_files',
        annotations=ToolAnnotations(
            title='浏览与筛选文件清单',
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_list_files(params: ListFilesInput) -> str:
        """分页浏览和筛选案件中的镜像文件清单，支持按分区偏移、路径前缀、后缀、关键词和状态过滤。"""
        try:
            data = await _run_sync(
                service.list_files,
                case_dir=params.case_dir,
                partition_offset=params.partition_offset,
                path_prefix=params.path_prefix,
                suffix=params.suffix,
                keyword=params.keyword,
                status=params.status.value,
                files_only=params.files_only,
                dir_inode=params.dir_inode,
                dir_path=params.dir_path,
                limit=params.limit,
                offset=params.offset,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, _render_files_md)
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_preview_file',
        annotations=ToolAnnotations(
            title='预览文件内容',
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_preview_file(params: PreviewFileInput) -> str:
        """按页读取镜像内文件（现存、已删除或 FAT 系统区域）的文本解码和/或十六进制转储。"""
        try:
            data = await _run_sync(
                service.preview_file,
                case_dir=params.case_dir,
                path=params.path,
                partition_offset=params.partition_offset,
                inode=params.inode,
                deleted=params.deleted,
                dir_inode=params.dir_inode,
                dir_path=params.dir_path,
                page=params.page,
                page_bytes=params.page_bytes,
                encoding=params.encoding,
                mode=params.mode.value,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, _render_preview_md)
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_search_content',
        annotations=ToolAnnotations(
            title='搜索文件内容',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_search_content(params: SearchContentInput) -> str:
        """按精确字节（UTF-8 / UTF-16LE / GBK / HEX）搜索全案可读文件或单个文件，并生成 search_*.json 审计记录。"""
        try:
            data = await _run_sync(
                service.search_content,
                case_dir=params.case_dir,
                query=params.query,
                encoding=params.encoding.value,
                path=params.path,
                partition_offset=params.partition_offset,
                inode=params.inode,
                deleted=params.deleted,
                dir_inode=params.dir_inode,
                dir_path=params.dir_path,
                max_hits=params.max_hits,
                limit=params.limit,
                offset=params.offset,
                verify_large_image=params.verify_large_image,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, _render_search_md)
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_examine_file',
        annotations=ToolAnnotations(
            title='计算文件哈希或比对副本',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_examine_file(params: ExamineFileInput) -> str:
        """从只读镜像计算指定文件的 SHA-256，或与本地对照文件核验一致性并记入取证发现与审计链。"""
        try:
            data = await _run_sync(
                service.examine_file,
                case_dir=params.case_dir,
                path=params.path,
                partition_offset=params.partition_offset,
                inode=params.inode,
                deleted=params.deleted,
                dir_inode=params.dir_inode,
                dir_path=params.dir_path,
                comparison_path=params.comparison_path,
                verify_large_image=params.verify_large_image,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('文件核验结果', d))
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_record_finding',
        annotations=ToolAnnotations(
            title='记录取证发现',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    async def tracedesk_record_finding(params: RecordFindingInput) -> str:
        """为镜像内指定文件记录结构化取证发现笔记，绑定来源镜像 SHA-256、分区偏移与 inode。"""
        try:
            data = await _run_sync(
                service.record_finding,
                case_dir=params.case_dir,
                path=params.path,
                note=params.note,
                partition_offset=params.partition_offset,
                inode=params.inode,
                deleted=params.deleted,
                dir_inode=params.dir_inode,
                dir_path=params.dir_path,
                verify_large_image=params.verify_large_image,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('已记录取证发现', d))
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_list_findings',
        annotations=ToolAnnotations(
            title='查询取证发现',
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_list_findings(params: ListFindingsInput) -> str:
        """按文件归组列出案件中的取证笔记、文件哈希计算与副本比对记录。"""
        try:
            data = await _run_sync(
                service.list_findings,
                case_dir=params.case_dir,
                status=params.status.value,
                partition_offset=params.partition_offset,
                keyword=params.keyword,
                limit=params.limit,
                offset=params.offset,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, _render_findings_md)
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_query_timeline',
        annotations=ToolAnnotations(
            title='查询 MACB 时间线',
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_query_timeline(params: QueryTimelineInput) -> str:
        """分页查询案件的 MACB 时间线（UTC+8），支持按事件类型、状态、分区偏移和关键词筛选。"""
        try:
            data = await _run_sync(
                service.query_timeline,
                case_dir=params.case_dir,
                event=params.event,
                status=params.status,
                partition_offset=params.partition_offset,
                query=params.query,
                sort_order=params.sort_order.value,
                limit=params.limit,
                offset=params.offset,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, _render_timeline_md)
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_query_audit_log',
        annotations=ToolAnnotations(
            title='核验并查询审计日志',
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def tracedesk_query_audit_log(params: QueryAuditLogInput) -> str:
        """核验审计哈希链及尾部锚点，并按来源（人工/MCP）、操作、操作人员、结果和关键词分页检索审计日志。"""
        try:
            data = await _run_sync(
                service.query_audit_log,
                case_dir=params.case_dir,
                origin=params.origin.value,
                action=params.action,
                actor_filter=params.actor_filter,
                result=params.result,
                query=params.query,
                sort_order=params.sort_order.value,
                limit=params.limit,
                offset=params.offset,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, _render_audit_md)
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_export_file',
        annotations=ToolAnnotations(
            title='导出镜像文件副本',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    async def tracedesk_export_file(params: ExportFileInput) -> str:
        """导出镜像内现存或已删除文件到案件 exports 目录，前后校验原镜像并记录副本 SHA-256。"""
        try:
            data = await _run_sync(
                service.export_file,
                case_dir=params.case_dir,
                path=params.path,
                partition_offset=params.partition_offset,
                inode=params.inode,
                deleted=params.deleted,
                dir_inode=params.dir_inode,
                dir_path=params.dir_path,
                verify_large_image=params.verify_large_image,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('文件已导出', d))
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_export_findings',
        annotations=ToolAnnotations(
            title='一键导出取证发现',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    async def tracedesk_export_findings(params: ExportFindingsInput) -> str:
        """批量导出取证发现涉及的镜像文件副本，并在 exports 目录生成 Markdown 汇总清单。"""
        try:
            data = await _run_sync(
                service.export_findings,
                case_dir=params.case_dir,
                status=params.status.value,
                partition_offset=params.partition_offset,
                keyword=params.keyword,
                verify_large_image=params.verify_large_image,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('取证发现导出完成', d))
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_generate_report',
        annotations=ToolAnnotations(
            title='生成 Markdown 取证报告',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    async def tracedesk_generate_report(params: ReportActionInput) -> str:
        """执行完整性校验并在案件 reports 目录生成分节 Markdown 取证报告。"""
        try:
            data = await _run_sync(
                service.generate_report,
                case_dir=params.case_dir,
                verify_large_image=params.verify_large_image,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('Markdown 报告已生成', d))
        except Exception as error:
            return _format_error(error)

    @mcp.tool(
        name='tracedesk_build_review_bundle',
        annotations=ToolAnnotations(
            title='构建可核验复核包',
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    async def tracedesk_build_review_bundle(params: ReviewBundleInput) -> str:
        """构建包含报告、导出副本、搜索记录、审计链、SHA256SUMS 与核验脚本的复核包 ZIP；支持按序号选择副本或跳过缺失项。"""
        try:
            data = await _run_sync(
                service.build_review_bundle,
                case_dir=params.case_dir,
                selected_export_indices=params.selected_export_indices,
                skip_missing_exports=params.skip_missing_exports,
                verify_large_image=params.verify_large_image,
                actor=params.actor,
            )
            return _format_output(data, params.response_format, lambda d: _render_simple_kv_md('复核包已构建', d))
        except Exception as error:
            return _format_error(error)

    return mcp
