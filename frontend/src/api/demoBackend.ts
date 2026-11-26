/**
 * 非 Tauri 浏览器独立预览模式的只读演示降级引擎。
 * 在真实 Tauri 2 桌面端运行时（window.__TAURI_INTERNALS__ 存在）不会被调用。
 */

import type {
  AppPaths,
  AuditRecordDto,
  BuildTimelineResponse,
  BundleMaterialsResponse,
  CaseSnapshot,
  EntryView,
  ExamineFileResponse,
  ExportFileResponse,
  ExportFindingsResponse,
  FindingGroupDto,
  GenerateHtmlReportResponse,
  HashFinishedEvent,
  HashProgressEvent,
  HexRowDto,
  InspectEntryMagicResponse,
  ListAuditLogResponse,
  ListFindingsResponse,
  ListMcpActivitiesParams,
  LocateFileResponse,
  McpActivityRecord,
  McpActivitySnapshot,
  McpCaseUpdatedEvent,
  McpStatus,
  PreviewEncoding,
  PreviewImageResponse,
  PreviewPageResponse,
  QueryFilesPageResponse,
  QueryTimelinePageResponse,
  RebindImagePathResponse,
  RecentCaseDto,
  ScanMagicMismatchesResponse,
  SearchEncoding,
  SearchFinishedEvent,
  SearchHitDto,
  SearchHitsEvent,
  SearchProgressEvent,
  SearchRecordSummaryDto,
  StartContentSearchResponse,
  SuggestCaseDirResponse,
  TaskProgressEvent,
  TimelineRowDto,
  ToolCatalogItem,
  TreeChildrenResponse,
  TreeNodeDto,
  VerifyReviewBundleResponse,
} from '../types/ipc';
import { computeMcpActivityStats, stripTrailingVersion } from '../utils/mcpActivity';

type EventName =
  | 'task:progress'
  | 'hash:progress'
  | 'hash:finished'
  | 'search:hits'
  | 'search:progress'
  | 'search:finished'
  | 'mcp:activity'
  | 'mcp:case-updated';

type EventPayloadMap = {
  'task:progress': TaskProgressEvent;
  'hash:progress': HashProgressEvent;
  'hash:finished': HashFinishedEvent;
  'search:hits': SearchHitsEvent;
  'search:progress': SearchProgressEvent;
  'search:finished': SearchFinishedEvent;
  'mcp:activity': McpActivityRecord;
  'mcp:case-updated': McpCaseUpdatedEvent;
};

type Listener<K extends EventName> = (payload: EventPayloadMap[K]) => void;

const listeners: { [K in EventName]: Set<Listener<K>> } = {
  'task:progress': new Set(),
  'hash:progress': new Set(),
  'hash:finished': new Set(),
  'search:hits': new Set(),
  'search:progress': new Set(),
  'search:finished': new Set(),
  'mcp:activity': new Set(),
  'mcp:case-updated': new Set(),
};

export function demoListen<K extends EventName>(event: K, handler: Listener<K>): () => void {
  listeners[event].add(handler);
  return () => {
    listeners[event].delete(handler);
  };
}

function emit<K extends EventName>(event: K, payload: EventPayloadMap[K]): void {
  for (const handler of listeners[event]) {
    handler(payload);
  }
}

const DEMO_SHA256 = '6a8f2c904e5d1b7c3f8a02e941d6c53b7f48e2910a3b5c7d9e1f2a3b4c5d6e7f';
const DEMO_CASE_TXT_CONTENT = 'Case note inside a nested directory.\nTraceDesk FAT16 演示取证材料（浏览器演示预览模式）。\n';
const DEMO_DELETED_CONTENT = 'Deleted evidence draft: transfer_id=TD-2026-0091; note=confidential review record.\n';
const DEMO_PNG_DATA_URL =
  'data:image/svg+xml;utf8,' +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" width="420" height="240" viewBox="0 0 420 240">' +
      '<rect width="420" height="240" fill="#ECF5FF"/>' +
      '<rect x="16" y="16" width="388" height="208" rx="8" fill="#FFFFFF" stroke="#BDD9F7" stroke-width="2"/>' +
      '<text x="210" y="106" text-anchor="middle" font-family="Segoe UI, Microsoft YaHei UI, sans-serif" font-size="18" font-weight="700" fill="#1B5A9D">TraceDesk 演示证据图片预览</text>' +
      '<text x="210" y="138" text-anchor="middle" font-family="Consolas, monospace" font-size="13" fill="#45586E">EVIDENCE/SAMPLE.PNG · 420 × 240</text>' +
    '</svg>'
  );

const DEMO_TOOLS: ToolCatalogItem[] = [
  { name: 'tracedesk_list_cases', title: '列出案件', category: '案件管理', readOnly: true, summary: '列出案件库目录中的已有取证案件及其摘要状态' },
  { name: 'tracedesk_create_case', title: '新建案件', category: '案件管理', readOnly: false, summary: '创建隔离的取证案件目录、元数据与审计链起点' },
  { name: 'tracedesk_get_case_summary', title: '案件总览', category: '案件管理', readOnly: true, summary: '查看案件元数据、镜像哈希、覆盖范围、分区扫描与审计链状态' },
  { name: 'tracedesk_load_image', title: '加载镜像', category: '证据镜像', readOnly: false, summary: '以只读方式加载 RAW 或 .E01 首段镜像，固定 SHA-256 并识别分区' },
  { name: 'tracedesk_verify_integrity', title: '校验完整性', category: '证据镜像', readOnly: false, summary: '复算镜像 SHA-256 并与初始固定基线比对，更新校验记录' },
  { name: 'tracedesk_register_source', title: '登记证据来源', category: '证据镜像', readOnly: false, summary: '登记证据编号、交付方、采集时间/工具和交付方 SHA-256' },
  { name: 'tracedesk_scan_partitions', title: '扫描分区清单', category: '证据镜像', readOnly: false, summary: '扫描全部分区或指定偏移分区，建立/刷新完整文件清单' },
  { name: 'tracedesk_list_files', title: '浏览与筛选文件', category: '文件分析', readOnly: true, summary: '按分区、路径前缀、后缀、关键词和状态分页查询镜像内文件' },
  { name: 'tracedesk_preview_file', title: '预览文件内容', category: '文件分析', readOnly: true, summary: '按页读取文件或系统区域的文本（多编码）与十六进制转储' },
  { name: 'tracedesk_search_content', title: '搜索文件内容', category: '文件分析', readOnly: false, summary: '按 UTF-8 / UTF-16LE / GBK / HEX 精确搜索全案或单文件字节' },
  { name: 'tracedesk_examine_file', title: '计算文件哈希/比对', category: '文件分析', readOnly: false, summary: '直接从只读镜像计算文件 SHA-256，或与本地副本核验一致性' },
  { name: 'tracedesk_record_finding', title: '记录取证发现', category: '取证发现', readOnly: false, summary: '绑定镜像摘要、分区偏移、路径与 inode 写入结构化取证笔记' },
  { name: 'tracedesk_list_findings', title: '查询取证发现', category: '取证发现', readOnly: true, summary: '按文件归组查看取证笔记、哈希计算与副本比对记录' },
  { name: 'tracedesk_query_timeline', title: '查询 MACB 时间线', category: '时间线与审计', readOnly: true, summary: '按事件类型、状态、分区偏移与关键词分页查询 MACB 时间线' },
  { name: 'tracedesk_query_audit_log', title: '核验并查询审计日志', category: '时间线与审计', readOnly: true, summary: '核验审计哈希链完整性，并按操作/人员/结果分页检索日志' },
  { name: 'tracedesk_export_file', title: '导出单个文件', category: '导出与报告', readOnly: false, summary: '导出镜像中现存或已删除文件到案件 exports 目录并记录副本哈希' },
  { name: 'tracedesk_export_findings', title: '一键导出取证发现', category: '导出与报告', readOnly: false, summary: '批量导出取证发现涉及的文件副本及 Markdown 汇总清单' },
  { name: 'tracedesk_generate_report', title: '生成 Markdown 报告', category: '导出与报告', readOnly: false, summary: '执行完整性校验并生成分节 Markdown 取证报告' },
  { name: 'tracedesk_build_review_bundle', title: '构建复核包 ZIP', category: '导出与报告', readOnly: false, summary: '生成含报告、副本、搜索记录、审计链与 SHA256SUMS 的复核包' },
];

const DEMO_ENTRIES: EntryView[] = [
  {
    entryId: '2048:3:0',
    name: 'DOCS',
    path: 'DOCS',
    status: '现存',
    size: 2048,
    inode: '3',
    mtime: '2026-03-10 09:15:00',
    atime: '2026-03-10 09:15:00',
    ctime: '不支持（FAT16）',
    crtime: '2026-03-10 09:12:00',
    offset: 2048,
    directory: true,
    deleted: false,
    mode: 'd/drwxrwxrwx',
    filesystem: 'FAT16',
    canExport: false,
    iconKind: 'folder',
  },
  {
    entryId: '2048:5:0',
    name: 'CASE.TXT',
    path: 'DOCS/CASE.TXT',
    status: '现存',
    size: new TextEncoder().encode(DEMO_CASE_TXT_CONTENT).length,
    inode: '5',
    mtime: '2026-03-10 09:16:22',
    atime: '2026-03-10 10:00:00',
    ctime: '不支持（FAT16）',
    crtime: '2026-03-10 09:15:10',
    offset: 2048,
    directory: false,
    deleted: false,
    mode: 'r/rrwxrwxrwx',
    filesystem: 'FAT16',
    canExport: true,
    iconKind: 'file',
  },
  {
    entryId: '2048:7:1',
    name: 'DRAFT_DEL.TXT',
    path: 'DOCS/DRAFT_DEL.TXT',
    status: '已删除',
    size: new TextEncoder().encode(DEMO_DELETED_CONTENT).length,
    inode: '7',
    mtime: '2026-03-10 09:20:04',
    atime: '2026-03-10 09:22:00',
    ctime: '不支持（FAT16）',
    crtime: '2026-03-10 09:18:30',
    offset: 2048,
    directory: false,
    deleted: true,
    mode: 'r/rrwxrwxrwx',
    filesystem: 'FAT16',
    canExport: true,
    iconKind: 'file',
  },
  {
    entryId: '2048:9:0',
    name: 'SAMPLE.PNG',
    path: 'EVIDENCE/SAMPLE.PNG',
    status: '现存',
    size: 468,
    inode: '9',
    mtime: '2026-03-10 09:25:14',
    atime: '2026-03-10 09:25:14',
    ctime: '不支持（FAT16）',
    crtime: '2026-03-10 09:25:12',
    offset: 2048,
    directory: false,
    deleted: false,
    mode: 'r/rrwxrwxrwx',
    filesystem: 'FAT16',
    canExport: true,
    iconKind: 'image',
  },
  {
    entryId: '2048:8:0',
    name: 'EVIDENCE',
    path: 'EVIDENCE',
    status: '现存',
    size: 2048,
    inode: '8',
    mtime: '2026-03-10 09:25:00',
    atime: '2026-03-10 09:25:00',
    ctime: '不支持（FAT16）',
    crtime: '2026-03-10 09:25:00',
    offset: 2048,
    directory: true,
    deleted: false,
    mode: 'd/drwxrwxrwx',
    filesystem: 'FAT16',
    canExport: false,
    iconKind: 'folder',
  },
  {
    entryId: '2048:11:0',
    name: 'LEDGER.CSV',
    path: 'LEDGER.CSV',
    status: '现存',
    size: 164,
    inode: '11',
    mtime: '2026-03-10 09:30:40',
    atime: '2026-03-10 09:30:40',
    ctime: '不支持（FAT16）',
    crtime: '2026-03-10 09:30:02',
    offset: 2048,
    directory: false,
    deleted: false,
    mode: 'r/rrwxrwxrwx',
    filesystem: 'FAT16',
    canExport: true,
    iconKind: 'table',
  },
  {
    entryId: '2048:0:0',
    name: '$MBR',
    path: '$MBR',
    status: '系统区域',
    size: 512,
    inode: '0',
    mtime: '—',
    atime: '—',
    ctime: '—',
    crtime: '—',
    offset: 2048,
    directory: false,
    deleted: false,
    mode: 'v/vrwxrwxrwx',
    filesystem: 'FAT16',
    canExport: false,
    iconKind: 'system',
  },
];

const DEMO_FILE_TEXTS: Record<string, string> = {
  '2048:5:0': DEMO_CASE_TXT_CONTENT,
  '2048:7:1': DEMO_DELETED_CONTENT,
  '2048:11:0': 'seq,time_utc8,account,amount,remark\n1,2026-03-10 09:12:00,ACC-001,12800.00,demo transfer\n2,2026-03-10 09:28:15,ACC-002,4560.50,review note\n',
  '2048:9:0': '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\xa4\x00\x00\x00\xf0\x08\x06\x00\x00\x00',
};

function buildInitialCase(): CaseSnapshot {
  return {
    caseDir: 'C:\\TraceDesk\\cases\\DEMO-01-演示人员-FAT16演示镜像',
    id: 'demo-case-001',
    number: 'DEMO-01',
    examiner: '演示人员',
    target: 'FAT16 演示镜像',
    created: '2026-03-10 09:00:00',
    custodyState: 'verified',
    summaryLine1: '案件 DEMO-01  ·  取证人员：演示人员  ·  对象：FAT16 演示镜像  ·  只读演示预览模式',
    summaryLine2: `镜像：evidence/demo.dd（33,554,432 字节） · SHA-256：${DEMO_SHA256.slice(0, 16)}… · 校验通过 · 1 个分区 · 7 项`,
    sourceNote: '本机整镜像 SHA-256 已固定且校验通过',
    browsingDirectories: false,
    needsPartitionScan: false,
    inventoryCount: DEMO_ENTRIES.length,
    exportsCount: 2,
    evidence: {
      path: 'C:\\TraceDesk\\evidence\\demo.dd',
      size: 33554432,
      sha256: DEMO_SHA256,
      fixedAt: '2026-03-10 09:05:12',
      format: 'RAW',
      largeImage: false,
      layout: [
        'DOS Partition Table',
        'Offset Sector: 0',
        'Units are in 512-byte sectors',
        '',
        '      Slot      Start        End          Length       Description',
        '000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)',
        '001:  -------   0000000001   0000002047   0000002047   Unallocated',
        '002:  000:000   0000002048   0000065535   0000063488   DOS FAT16 (0x06)',
      ].join('\n'),
      partitions: [{ offset: 2048, length: 63488, description: 'DOS FAT16 (0x06)', slot: '000:000' }],
      coverage: {
        bytes: 33554432,
        volumes: [
          {
            offset: 2048,
            filesystem: 'FAT',
            partitionEnd: 33554432,
            volumeEnd: 33554432,
            missingBytes: 0,
            status: '声明范围已覆盖',
          },
        ],
      },
      coverageText:
        '偏移 2048 扇区：声明范围已覆盖（FAT，声明结束字节位置 33554432，镜像 33554432 字节）。仅判断可识别的声明范围，不能证明原盘无坏扇区或已完整采集。',
      provenance: {
        evidenceId: 'EVID-DEMO-01',
        source: 'TraceDesk 内置演示检材库',
        acquired: '2026-03-10 08:50 UTC+8',
        tool: 'TraceDesk Demo Builder',
        expectedSha256: DEMO_SHA256,
      },
      sourceStatus: '交付方摘要与本机固定值一致',
    },
    partitionScans: [{ offset: 2048, status: 'ready', count: DEMO_ENTRIES.length }],
    verification: { ok: true, checkedAt: '2026-03-10 09:05:14', method: 'SHA-256' },
    fsstat: [
      '=== 分区偏移 2048 扇区 ===',
      'FILE SYSTEM INFORMATION',
      '--------------------------------------------',
      'File System Type: FAT16',
      'OEM Name: MKFS.FAT',
      'Volume ID: 0x20260310',
      'Volume Label (Boot Sector): TRACEDESK',
      'Sector Size: 512',
      'Cluster Size: 2048',
      'Total Cluster Range: 2 - 15855',
    ].join('\n'),
    quickLocation: null,
    searchRecords: [
      {
        reportName: 'search_demo_1.json',
        query: '6E 6F 74 65',
        encoding: 'HEX',
        hits: 1,
        failed: 0,
        visited: 5,
        eligible: 5,
        status: '完成',
        time: '2026-03-10 09:40:00',
      },
    ],
    evidenceMissing: false,
  };
}

let currentCase: CaseSnapshot | null = buildInitialCase();
let mcpRunning = false;
let mcpPort = 8765;
let searchCounter = 0;
const activeSearchTimers = new Map<string, number>();
const searchHitsStore = new Map<string, SearchHitDto[]>();
/** 演示模式：记录已被移出最近列表的案件目录，用于模拟 remove_recent_case */
const removedDemoRecentFolders = new Set<string>();
/** 演示模式：按案件目录缓存魔数伪装检测结果，用于模拟 load_cached_magic_scan */
const demoMagicScanCache = new Map<string, ScanMagicMismatchesResponse>();

const INITIAL_DEMO_FINDINGS: FindingGroupDto[] = [
  {
    groupKey: 'DOCS/CASE.TXT|2048|5|false',
    seq: 1,
    subject: 'DOCS/CASE.TXT',
    status: '现存',
    deleted: false,
    offset: 2048,
    inode: '5',
    imageSha256: DEMO_SHA256,
    count: 2,
    latestTime: '2026-03-10 09:42:18',
    records: [
      {
        seq: 6,
        timestamp: '2026-03-10 09:38:05',
        action: 'FILE_NOTE',
        actionTitle: '取证笔记',
        origin: 'manual',
        originLabel: '人工',
        actor: '演示人员',
        result: '成功',
        details: {
          offset: 2048,
          inode: '5',
          deleted: false,
          image_sha256: DEMO_SHA256,
          note: '关键演示文档：包含 nested directory 备注内容，已核对十六进制首行 43 61 73 65。',
          source_verification: '通过（与初始固定值一致）',
        },
      },
      {
        seq: 7,
        timestamp: '2026-03-10 09:42:18',
        action: 'FILE_HASH',
        actionTitle: '计算摘要',
        origin: 'mcp',
        originLabel: 'MCP · Cursor',
        mcpUser: 'Cursor',
        actor: '演示人员',
        result: '成功',
        details: {
          offset: 2048,
          inode: '5',
          deleted: false,
          image_sha256: DEMO_SHA256,
          size: 112,
          recorded_size: 112,
          sha256: '4d91a3f28b0c7e65d1a9f4c2e38b7a605d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a',
          source_verification: '通过（与初始固定值一致）',
        },
      },
    ],
  },
];

const INITIAL_DEMO_AUDIT_RECORDS: AuditRecordDto[] = [
  {
    seq: 1,
    timestamp: '2026-03-10 09:00:00',
    origin: 'manual',
    originLabel: '人工',
    actor: '演示人员',
    action: 'CASE_CREATE',
    actionTitle: '新建案件',
    result: '成功',
    subject: 'DEMO-01',
    details: { target: 'FAT16 演示镜像' },
    previous: '0'.repeat(64),
    hash: '11a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80',
  },
  {
    seq: 2,
    timestamp: '2026-03-10 09:05:12',
    origin: 'manual',
    originLabel: '人工',
    actor: '演示人员',
    action: 'IMAGE_LOAD',
    actionTitle: '载入镜像',
    result: '成功',
    subject: 'evidence/demo.dd',
    details: { size: 33554432, sha256: DEMO_SHA256 },
    previous: '11a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80',
    hash: '22b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091',
  },
  {
    seq: 3,
    timestamp: '2026-03-10 09:05:14',
    origin: 'manual',
    originLabel: '人工',
    actor: '演示人员',
    action: 'HASH_VERIFY',
    actionTitle: '校验镜像完整性',
    result: '通过',
    subject: 'evidence/demo.dd',
    details: { actual: DEMO_SHA256 },
    previous: '22b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091',
    hash: '33c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2',
  },
  {
    seq: 4,
    timestamp: '2026-03-10 09:05:16',
    origin: 'manual',
    originLabel: '人工',
    actor: '演示人员',
    action: 'PARTITIONS_SCAN',
    actionTitle: '扫描所有分区',
    result: '成功',
    subject: 'evidence/demo.dd',
    details: { count: 7 },
    previous: '33c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2',
    hash: '44d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3',
  },
  {
    seq: 5,
    timestamp: '2026-03-10 09:10:00',
    origin: 'manual',
    originLabel: '人工',
    actor: '演示人员',
    action: 'SOURCE_REGISTER',
    actionTitle: '登记证据来源',
    result: '成功',
    subject: 'EVID-DEMO-01',
    details: { source: 'TraceDesk 内置演示检材库' },
    previous: '44d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3',
    hash: '55e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4',
  },
  {
    seq: 6,
    timestamp: '2026-03-10 09:38:05',
    origin: 'manual',
    originLabel: '人工',
    actor: '演示人员',
    action: 'FILE_NOTE',
    actionTitle: '记录取证发现',
    result: '成功',
    subject: 'DOCS/CASE.TXT',
    details: { offset: 2048, inode: '5', note: '关键演示文档' },
    previous: '55e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4',
    hash: '66f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5',
  },
  {
    seq: 7,
    timestamp: '2026-03-10 09:42:18',
    origin: 'mcp',
    originLabel: 'MCP · Cursor',
    mcpUser: 'Cursor',
    actor: '演示人员',
    action: 'FILE_HASH',
    actionTitle: '计算文件摘要',
    result: '成功',
    subject: 'DOCS/CASE.TXT',
    details: { offset: 2048, inode: '5', sha256: '4d91a3f28b0c7e65d1a9f4c2e38b7a605d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a' },
    previous: '66f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5',
    hash: '7708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6',
  },
];

function cloneInitialFindings(): FindingGroupDto[] {
  return INITIAL_DEMO_FINDINGS.map((g) => ({
    ...g,
    records: g.records.map((r) => ({ ...r, details: { ...r.details } })),
  }));
}

function cloneInitialAuditRecords(): AuditRecordDto[] {
  return INITIAL_DEMO_AUDIT_RECORDS.map((r) => ({ ...r, details: { ...r.details } }));
}

let demoFindings: FindingGroupDto[] = cloneInitialFindings();
let demoAuditRecords: AuditRecordDto[] = cloneInitialAuditRecords();

const demoTimelineRows: TimelineRowDto[] = [
  { number: 1, time: '2026-03-10 09:12:00', event: 'B 创建', status: '现存', offset: 2048, inode: '3', path: 'DOCS' },
  { number: 2, time: '2026-03-10 09:15:10', event: 'B 创建', status: '现存', offset: 2048, inode: '5', path: 'DOCS/CASE.TXT' },
  { number: 3, time: '2026-03-10 09:16:22', event: 'M 内容修改', status: '现存', offset: 2048, inode: '5', path: 'DOCS/CASE.TXT' },
  { number: 4, time: '2026-03-10 09:18:30', event: 'B 创建', status: '已删除', offset: 2048, inode: '7', path: 'DOCS/DRAFT_DEL.TXT' },
  { number: 5, time: '2026-03-10 09:20:04', event: 'M 内容修改', status: '已删除', offset: 2048, inode: '7', path: 'DOCS/DRAFT_DEL.TXT' },
  { number: 6, time: '2026-03-10 09:25:14', event: 'M 内容修改', status: '现存', offset: 2048, inode: '9', path: 'EVIDENCE/SAMPLE.PNG' },
  { number: 7, time: '2026-03-10 09:30:40', event: 'M 内容修改', status: '现存', offset: 2048, inode: '11', path: 'LEDGER.CSV' },
  { number: 8, time: '2026-03-10 10:00:00', event: 'A 访问', status: '现存', offset: 2048, inode: '5', path: 'DOCS/CASE.TXT' },
];

/** 浏览器演示模式下的 MCP 实时操作流示例（按最新时间倒序排列） */
function buildInitialMcpActivities(): McpActivityRecord[] {
  const demoCaseDir = 'C:\\TraceDesk\\cases\\DEMO-01-演示人员-FAT16演示镜像';
  return [
    {
      id: 'act-008',
      callId: 'call-demo-008',
      timestamp: '2026-03-10 09:46:12.418',
      phase: 'completed',
      transport: 'desktop-http',
      client: 'Antigravity',
      sessionId: 'sess-ag-9f2a1c',
      method: 'tools/call',
      toolName: 'tracedesk_generate_report',
      toolTitle: '生成 Markdown 报告',
      category: '导出与报告',
      readOnly: false,
      caseDir: demoCaseDir,
      caseNumber: 'DEMO-01',
      paramsSummary: 'case=DEMO-01 · 校验后生成完整报告',
      paramsJson: JSON.stringify(
        {
          case_dir: demoCaseDir,
          include_audit_summary: true,
        },
        null,
        2
      ),
      durationMs: 412,
      resultSummary: '已完成整镜像复核并生成 reports/report_DEMO-01.md（写入审计链 #11）',
      responsePreview: JSON.stringify(
        {
          ok: true,
          report_path: `${demoCaseDir}\\reports\\report_DEMO-01.md`,
          integrity_verified: true,
          audit_seq: 11,
        },
        null,
        2
      ),
      error: null,
    },
    {
      id: 'act-007',
      callId: 'call-demo-007',
      timestamp: '2026-03-10 09:45:48.105',
      phase: 'completed',
      transport: 'desktop-http',
      client: 'Antigravity',
      sessionId: 'sess-ag-9f2a1c',
      method: 'tools/call',
      toolName: 'tracedesk_export_file',
      toolTitle: '导出单个文件',
      category: '导出与报告',
      readOnly: false,
      caseDir: demoCaseDir,
      caseNumber: 'DEMO-01',
      paramsSummary: 'path=DOCS/DRAFT_DEL.TXT · offset=2048 · inode=7（已删除）',
      paramsJson: JSON.stringify(
        {
          case_dir: demoCaseDir,
          offset: 2048,
          inode: '7',
          deleted: true,
        },
        null,
        2
      ),
      durationMs: 186,
      resultSummary: '已恢复导出已删除文件至 exports/DRAFT_DEL.TXT（81 字节）',
      responsePreview: JSON.stringify(
        {
          title: '导出成功',
          output_path: `${demoCaseDir}\\exports\\DRAFT_DEL.TXT`,
          bytes_written: 81,
          sha256: '9c1d4f20a87b3e61d504c2f891a3b7e4c6d0f8123456789abcdef01234567890',
        },
        null,
        2
      ),
      error: null,
    },
    {
      id: 'act-006',
      callId: 'call-demo-006',
      timestamp: '2026-03-10 09:45:03.729',
      phase: 'failed',
      transport: 'desktop-http',
      client: 'Antigravity',
      sessionId: 'sess-ag-9f2a1c',
      method: 'tools/call',
      toolName: 'tracedesk_export_file',
      toolTitle: '导出单个文件',
      category: '导出与报告',
      readOnly: false,
      caseDir: demoCaseDir,
      caseNumber: 'DEMO-01',
      paramsSummary: 'path=$MBR · offset=2048 · inode=0',
      paramsJson: JSON.stringify(
        {
          case_dir: demoCaseDir,
          offset: 2048,
          inode: '0',
          path: '$MBR',
        },
        null,
        2
      ),
      durationMs: 19,
      resultSummary: '导出被拒绝：系统保留区域不支持作为常规文件导出',
      responsePreview: null,
      error: '条目「$MBR」（模式 v/vrwxrwxrwx）属于文件系统保留区域，不可直接导出；请使用 tracedesk_preview_file 以十六进制方式只读查看。',
    },
    {
      id: 'act-005',
      callId: 'call-demo-005',
      timestamp: '2026-03-10 09:44:22.614',
      phase: 'completed',
      transport: 'desktop-http',
      client: 'Antigravity',
      sessionId: 'sess-ag-9f2a1c',
      method: 'tools/call',
      toolName: 'tracedesk_record_finding',
      toolTitle: '记录取证发现',
      category: '取证发现',
      readOnly: false,
      caseDir: demoCaseDir,
      caseNumber: 'DEMO-01',
      paramsSummary: 'path=DOCS/DRAFT_DEL.TXT · 笔记="命中 transfer_id=TD-2026-0091"',
      paramsJson: JSON.stringify(
        {
          case_dir: demoCaseDir,
          offset: 2048,
          inode: '7',
          deleted: true,
          note: '命中 transfer_id=TD-2026-0091，已删除草稿包含机密复核记录，需纳入复核包。',
        },
        null,
        2
      ),
      durationMs: 64,
      resultSummary: '已写入结构化取证发现并绑定镜像 SHA-256 基线',
      responsePreview: JSON.stringify(
        {
          saved: true,
          subject: 'DOCS/DRAFT_DEL.TXT',
          audit_seq: 9,
        },
        null,
        2
      ),
      error: null,
    },
    {
      id: 'act-004',
      callId: 'call-demo-004',
      timestamp: '2026-03-10 09:43:51.092',
      phase: 'completed',
      transport: 'desktop-http',
      client: 'Antigravity',
      sessionId: 'sess-ag-9f2a1c',
      method: 'tools/call',
      toolName: 'tracedesk_search_content',
      toolTitle: '搜索文件内容',
      category: '文件分析',
      readOnly: false,
      caseDir: demoCaseDir,
      caseNumber: 'DEMO-01',
      paramsSummary: 'query="TD-2026-0091" · encoding=UTF-8 · 范围=全案',
      paramsJson: JSON.stringify(
        {
          case_dir: demoCaseDir,
          query: 'TD-2026-0091',
          encoding: 'UTF-8',
        },
        null,
        2
      ),
      durationMs: 248,
      resultSummary: '检索 5 个文件，命中 1 处（DOCS/DRAFT_DEL.TXT 字节偏移 36）',
      responsePreview: JSON.stringify(
        {
          visited: 5,
          total_hits: 1,
          hits: [
            {
              path: 'DOCS/DRAFT_DEL.TXT',
              offset: 2048,
              inode: '7',
              deleted: true,
              pos: 36,
            },
          ],
        },
        null,
        2
      ),
      error: null,
    },
    {
      id: 'act-003',
      callId: 'call-demo-003',
      timestamp: '2026-03-10 09:42:18.342',
      phase: 'completed',
      transport: 'stdio',
      client: 'Cursor',
      sessionId: 'stdio-pid-18420',
      method: 'tools/call',
      toolName: 'tracedesk_examine_file',
      toolTitle: '计算文件哈希/比对',
      category: '文件分析',
      readOnly: false,
      caseDir: demoCaseDir,
      caseNumber: 'DEMO-01',
      paramsSummary: 'path=DOCS/CASE.TXT · offset=2048 · inode=5',
      paramsJson: JSON.stringify(
        {
          case_dir: demoCaseDir,
          offset: 2048,
          inode: '5',
        },
        null,
        2
      ),
      durationMs: 52,
      resultSummary: '已从只读镜像计算 SHA-256：4d91a3f28b0c7e65…（112 字节）',
      responsePreview: JSON.stringify(
        {
          path: 'DOCS/CASE.TXT',
          size: 112,
          sha256: '4d91a3f28b0c7e65d1a9f4c2e38b7a605d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a',
          source_verification: '通过（与初始固定值一致）',
        },
        null,
        2
      ),
      error: null,
    },
    {
      id: 'act-002',
      callId: 'call-demo-002',
      timestamp: '2026-03-10 09:41:36.881',
      phase: 'completed',
      transport: 'desktop-http',
      client: 'Antigravity',
      sessionId: 'sess-ag-9f2a1c',
      method: 'tools/call',
      toolName: 'tracedesk_verify_integrity',
      toolTitle: '校验完整性',
      category: '证据镜像',
      readOnly: false,
      caseDir: demoCaseDir,
      caseNumber: 'DEMO-01',
      paramsSummary: 'case=DEMO-01 · 复算整镜像 SHA-256',
      paramsJson: JSON.stringify(
        {
          case_dir: demoCaseDir,
        },
        null,
        2
      ),
      durationMs: 315,
      resultSummary: '整镜像 SHA-256 校验通过（与初始固定值一致）',
      responsePreview: JSON.stringify(
        {
          ok: true,
          expected_sha256: DEMO_SHA256,
          actual_sha256: DEMO_SHA256,
          checked_at: '2026-03-10 09:41:36',
        },
        null,
        2
      ),
      error: null,
    },
    {
      id: 'act-001',
      callId: 'call-demo-001',
      timestamp: '2026-03-10 09:41:10.120',
      phase: 'completed',
      transport: 'stdio',
      client: 'Antigravity',
      sessionId: 'stdio-pid-18392',
      method: 'tools/call',
      toolName: 'tracedesk_get_case_summary',
      toolTitle: '案件总览',
      category: '案件管理',
      readOnly: true,
      caseDir: demoCaseDir,
      caseNumber: 'DEMO-01',
      paramsSummary: 'case=DEMO-01',
      paramsJson: JSON.stringify(
        {
          case_dir: demoCaseDir,
        },
        null,
        2
      ),
      durationMs: 28,
      resultSummary: '已读取案件 DEMO-01 摘要 · 1 个分区 · 7 项文件 · 审计链有效',
      responsePreview: JSON.stringify(
        {
          case_number: 'DEMO-01',
          examiner: '演示人员',
          partitions: 1,
          inventory_count: 7,
          audit_chain_valid: true,
        },
        null,
        2
      ),
      error: null,
    },
  ];
}

let demoMcpActivities: McpActivityRecord[] = buildInitialMcpActivities();

function bytesToHexRows(bytes: Uint8Array, pageOffset: number): HexRowDto[] {
  const rows: HexRowDto[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16);
    const offsetHex = (pageOffset + i).toString(16).toUpperCase().padStart(8, '0');
    const hexParts: string[] = [];
    let chars = '';
    for (let j = 0; j < slice.length; j += 1) {
      const b = slice[j];
      hexParts.push(b.toString(16).toUpperCase().padStart(2, '0'));
      chars += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '·';
    }
    rows.push({
      offsetHex,
      bytesHex: hexParts.join(' '),
      chars,
    });
  }
  return rows;
}

export const demoBackend = {
  async get_app_paths(): Promise<AppPaths> {
    return {
      rootDir: 'C:\\TraceDesk',
      casesDir: 'C:\\TraceDesk\\cases',
      evidenceDir: 'C:\\TraceDesk\\evidence',
    };
  },

  async suggest_case_dir(args: { number: string; examiner: string; target: string; parentDir?: string }): Promise<SuggestCaseDirResponse> {
    const parent = args.parentDir || 'C:\\TraceDesk\\cases';
    const safe = `${args.number}_${args.examiner}_${args.target}`.replace(/[<>:"/\\|?*]+/g, '_');
    return {
      folderName: safe,
      suggestedPath: `${parent.replace(/[\\/]+$/, '')}\\${safe}`,
    };
  },

  async create_case(args: { parentDir: string; number: string; examiner: string; target: string; folderName?: string }): Promise<CaseSnapshot> {
    const folder = args.folderName || `${args.number}_${args.examiner}_${args.target}`;
    const snap: CaseSnapshot = {
      caseDir: `${args.parentDir.replace(/[\\/]+$/, '')}\\${folder}`,
      id: `demo-${Date.now()}`,
      number: args.number,
      examiner: args.examiner,
      target: args.target,
      created: '2026-03-10 10:15:00',
      custodyState: 'active',
      summaryLine1: `案件 ${args.number}  ·  取证人员：${args.examiner}  ·  对象：${args.target}`,
      summaryLine2: '尚未加载镜像（浏览器只读演示模式）。请点击右侧「加载镜像」载入演示镜像。',
      sourceNote: '尚未加载镜像',
      browsingDirectories: false,
      needsPartitionScan: false,
      inventoryCount: 0,
      exportsCount: 0,
      evidence: null,
      partitionScans: [],
      verification: null,
      fsstat: '',
      quickLocation: null,
      evidenceMissing: false,
    };
    currentCase = snap;
    demoFindings = [];
    demoAuditRecords = [
      {
        seq: 1,
        timestamp: snap.created,
        origin: 'manual',
        originLabel: '人工',
        actor: snap.examiner,
        action: 'CASE_CREATE',
        actionTitle: '新建案件',
        result: '成功',
        subject: snap.number,
        details: { target: snap.target },
        previous: '0'.repeat(64),
        hash: '11a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80',
      },
    ];
    return snap;
  },

  async open_case(): Promise<CaseSnapshot> {
    currentCase = buildInitialCase();
    demoFindings = cloneInitialFindings();
    demoAuditRecords = cloneInitialAuditRecords();
    return currentCase;
  },

  async close_case(): Promise<{ closed: boolean }> {
    currentCase = null;
    demoFindings = [];
    demoAuditRecords = [];
    return { closed: true };
  },

  async get_case_snapshot(): Promise<CaseSnapshot | null> {
    return currentCase;
  },

  async list_recent_cases(): Promise<RecentCaseDto[]> {
    const base = currentCase ?? buildInitialCase();
    if (removedDemoRecentFolders.has(base.caseDir)) {
      return [];
    }
    return [
      {
        folder: base.caseDir,
        name: base.caseDir.split(/[\\/]/).pop() || 'DEMO-01',
        number: base.number,
        examiner: base.examiner,
        target: base.target,
        created: base.created,
        lastOpenedAt: '2026-03-10 10:18:00',
        inHistory: true,
        pinned: false,
        evidenceMissing: Boolean(base.evidenceMissing),
        hasEvidence: Boolean(base.evidence),
        inventoryCount: base.inventoryCount,
        exportsCount: base.exportsCount,
      },
    ];
  },

  async remove_recent_case(args: { folder: string }): Promise<{ removed: boolean }> {
    const target = (args.folder || '').trim();
    if (!target) {
      return { removed: false };
    }
    removedDemoRecentFolders.add(target);
    return { removed: true };
  },

  async load_image(): Promise<CaseSnapshot> {
    emit('task:progress', { stage: '固定镜像 SHA-256', done: 100, total: 100 });
    const base = buildInitialCase();
    if (currentCase) {
      base.number = currentCase.number;
      base.examiner = currentCase.examiner;
      base.target = currentCase.target;
      base.caseDir = currentCase.caseDir;
      base.summaryLine1 = `案件 ${base.number}  ·  取证人员：${base.examiner}  ·  对象：${base.target}  ·  只读演示预览模式`;
    }
    currentCase = base;
    return currentCase;
  },

  async rebind_image_path(args: { newImagePath: string }): Promise<RebindImagePathResponse> {
    if (!currentCase || !currentCase.evidence) {
      throw new Error('当前案件尚未加载证据镜像，无法重绑路径');
    }
    const newImage = (args.newImagePath || '').trim();
    if (!newImage) {
      throw new Error('请选择有效的源证据镜像文件');
    }
    if (/tamper|mismatch|篡改|不符/i.test(newImage)) {
      throw new Error('目标镜像 SHA-256 与案件基线不符，已拒绝覆盖原路径');
    }
    const oldImage = currentCase.evidence.path;
    const sha256 = currentCase.evidence.sha256 || DEMO_SHA256;
    const verified = Boolean(currentCase.evidence.sha256);
    const segmentCount = currentCase.evidence.segments?.length ?? 1;
    const nextSeq = demoAuditRecords.length + 1;
    const nowStr = '2026-03-10 10:35:00';
    currentCase = {
      ...currentCase,
      custodyState: verified ? 'verified' : 'active',
      evidenceMissing: false,
      evidence: {
        ...currentCase.evidence,
        path: newImage,
      },
    };
    demoAuditRecords.push({
      seq: nextSeq,
      timestamp: nowStr,
      origin: 'manual',
      originLabel: '人工',
      actor: currentCase.examiner,
      action: 'IMAGE_REBIND',
      actionTitle: '重绑源镜像路径',
      result: '成功',
      subject: newImage,
      details: { old_image: oldImage, new_image: newImage, sha256, verified },
      previous: demoAuditRecords[demoAuditRecords.length - 1]?.hash || '0'.repeat(64),
      hash: `${nextSeq.toString(16).padStart(2, '0')}b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef1`,
    });
    return {
      snapshot: currentCase,
      oldImage,
      newImage,
      sha256,
      verified,
      segmentCount,
    };
  },

  async verify_integrity(): Promise<{ ok: boolean; initialFixed: boolean; snapshot: CaseSnapshot }> {
    if (!currentCase) throw new Error('尚未打开案件');
    emit('task:progress', { stage: '校验 SHA-256', done: 100, total: 100 });
    currentCase = { ...currentCase, custodyState: 'verified' };
    return { ok: true, initialFixed: false, snapshot: currentCase };
  },

  async cancel_verify_integrity(): Promise<{ cancelled: boolean }> {
    return { cancelled: true };
  },

  async register_source(args: {
    evidenceId: string;
    source: string;
    acquired: string;
    tool: string;
    expectedSha256: string;
  }): Promise<CaseSnapshot> {
    if (!currentCase || !currentCase.evidence) throw new Error('请先加载镜像');
    const exp = args.expectedSha256.trim();
    const fixedHash = currentCase.evidence.sha256;
    const mismatch = Boolean(fixedHash && exp.length > 0 && exp.toLowerCase() !== fixedHash.toLowerCase());
    currentCase = {
      ...currentCase,
      custodyState: !fixedHash ? 'warning' : mismatch ? 'error' : 'verified',
      evidence: {
        ...currentCase.evidence,
        provenance: {
          evidenceId: args.evidenceId,
          source: args.source,
          acquired: args.acquired,
          tool: args.tool,
          expectedSha256: exp,
        },
        sourceStatus: !fixedHash
          ? '本机整镜像 SHA-256 待固定'
          : !exp
            ? '未提供交付方摘要，仅有本机固定值'
            : mismatch
              ? '警告：交付方摘要与本机固定值不一致'
              : '交付方摘要与本机固定值一致',
      },
    };
    return currentCase;
  },

  async export_fsstat(): Promise<{ path: string }> {
    return { path: 'C:\\TraceDesk\\cases\\DEMO-01\\reports\\fsstat_2048.txt' };
  },

  async scan_all_partitions(): Promise<{ completed: boolean; snapshot: CaseSnapshot }> {
    if (!currentCase) throw new Error('尚未打开案件');
    emit('task:progress', { stage: '扫描所有分区', done: 100, total: 100 });
    return { completed: true, snapshot: currentCase };
  },

  async scan_partition(args: { offset: number }): Promise<{ completed: boolean; snapshot: CaseSnapshot }> {
    if (!currentCase) throw new Error('尚未打开案件');
    emit('task:progress', { stage: `扫描分区（偏移 ${args.offset}）`, done: 100, total: 100 });
    return { completed: true, snapshot: currentCase };
  },

  async cancel_scan_partitions(): Promise<{ cancelled: boolean }> {
    return { cancelled: true };
  },

  async cancel_task(): Promise<{ cancelled: boolean }> {
    return { cancelled: true };
  },

  async browse_directory(): Promise<{ snapshot: CaseSnapshot; entries: EntryView[] }> {
    if (!currentCase) throw new Error('尚未打开案件');
    return { snapshot: currentCase, entries: DEMO_ENTRIES };
  },

  async get_tree_children(args: {
    offset: number;
    scopePath: string;
    inode?: string | null;
    groupIndex?: number;
  }): Promise<TreeChildrenResponse> {
    if (!currentCase?.evidence) return { nodes: [], grouped: false, groupCount: 0 };
    const parent = args.scopePath.replace(/^\/+|\/+$/g, '');
    const nodes: TreeNodeDto[] = DEMO_ENTRIES.filter((entry) => {
      if (entry.offset !== args.offset) return false;
      const p = entry.path.replace(/^\/+|\/+$/g, '');
      const idx = p.lastIndexOf('/');
      const dir = idx >= 0 ? p.slice(0, idx) : '';
      return dir === parent;
    }).map((entry) => ({
      id: `${entry.offset}:${entry.path}:${entry.inode}:${entry.deleted ? '1' : '0'}`,
      label: entry.deleted ? `${entry.name}  [已删除 · ${entry.inode}]` : entry.name,
      tooltip: `${entry.path}\n${entry.status} · inode ${entry.inode}`,
      kind: entry.directory ? 'directory' : 'file',
      iconKind: entry.iconKind || (entry.directory ? 'folder' : 'file'),
      offset: entry.offset,
      scopePath: entry.directory ? entry.path : undefined,
      inode: entry.inode,
      entryId: entry.entryId,
      deleted: entry.deleted,
      hasChildren: entry.directory,
    }));
    return { nodes, grouped: false, groupCount: 0 };
  },

  async query_files_page(args: {
    scopeOffset?: number | null;
    scopePath?: string | null;
    suffix: string;
    keyword: string;
    status: 'all' | 'active' | 'deleted';
    page: number;
    pageSize: number;
  }): Promise<QueryFilesPageResponse> {
    if (!currentCase?.evidence) {
      return { total: 0, page: 0, totalPages: 1, items: [] };
    }
    const suffix = args.suffix.trim().toLowerCase();
    const keyword = args.keyword.trim().toLowerCase();
    const filtered = DEMO_ENTRIES.filter((entry) => {
      if (args.scopeOffset != null && entry.offset !== args.scopeOffset) return false;
      if (args.scopePath != null) {
        const cleanScope = args.scopePath.replace(/^\/+|\/+$/g, '');
        const cleanPath = entry.path.replace(/^\/+|\/+$/g, '');
        const lastSlash = cleanPath.lastIndexOf('/');
        const parent = lastSlash >= 0 ? cleanPath.slice(0, lastSlash) : '';
        if (parent !== cleanScope) return false;
      }
      if (suffix && !entry.name.toLowerCase().endsWith(suffix)) return false;
      if (keyword && !entry.path.toLowerCase().includes(keyword)) return false;
      if (args.status === 'active' && (entry.deleted || entry.directory || entry.mode.toLowerCase().startsWith('v/'))) {
        return false;
      }
      if (args.status === 'deleted' && !entry.deleted) return false;
      return true;
    });
    const totalPages = Math.max(1, Math.ceil(filtered.length / args.pageSize));
    const page = Math.max(0, Math.min(args.page, totalPages - 1));
    const start = page * args.pageSize;
    return {
      total: filtered.length,
      page,
      totalPages,
      items: filtered.slice(start, start + args.pageSize),
    };
  },

  async locate_file_in_scope(args: { entryId: string }): Promise<LocateFileResponse> {
    const raw = (args.entryId || '').trim();
    let entry = DEMO_ENTRIES.find((e) => e.entryId === raw);
    if (!entry) {
      const parts = raw.split(':');
      if (parts.length >= 3) {
        const off = Number(parts[0]);
        const inode = parts[1];
        const deleted = parts[2] === '1' || parts[2] === 'true';
        const pathOpt = parts.length >= 4 ? parts.slice(3).join(':') : null;
        entry = DEMO_ENTRIES.find(
          (e) =>
            e.offset === off &&
            e.inode === inode &&
            e.deleted === deleted &&
            (!pathOpt || e.path === pathOpt)
        );
      }
    }
    if (!entry) {
      entry = DEMO_ENTRIES[0];
    }
    const cleanPath = entry.path.replace(/^\/+|\/+$/g, '');
    const lastSlash = cleanPath.lastIndexOf('/');
    const scopePath = lastSlash >= 0 ? cleanPath.slice(0, lastSlash) : '';
    // 计算目标文件在同目录分页中的准确索引
    const siblings = DEMO_ENTRIES.filter((item) => {
      if (item.offset !== entry.offset) return false;
      const p = item.path.replace(/^\/+|\/+$/g, '');
      const idx = p.lastIndexOf('/');
      const parent = idx >= 0 ? p.slice(0, idx) : '';
      return parent === scopePath;
    });
    const siblingIdx = Math.max(0, siblings.findIndex((item) => item.entryId === entry.entryId));
    return {
      scopeOffset: entry.offset,
      scopePath,
      page: Math.floor(siblingIdx / 100),
      indexInPage: siblingIdx % 100,
    };
  },

  async preview_file_page(args: {
    entryId: string;
    page: number;
    pageBytes?: number;
    encoding: PreviewEncoding;
  }): Promise<PreviewPageResponse> {
    const entry = DEMO_ENTRIES.find((e) => e.entryId === args.entryId);
    const rawText = DEMO_FILE_TEXTS[args.entryId] ?? `演示只读预览 · ${entry?.path ?? args.entryId}\n`;
    const bytes = new TextEncoder().encode(rawText);
    const isImg = entry?.iconKind === 'image';
    return {
      page: args.page,
      totalPages: 1,
      size: bytes.length,
      recordedSize: entry?.size ?? bytes.length,
      readNote: `演示解码 (${args.encoding})`,
      sourceNote: entry?.deleted ? '已删除记录（可读字节恢复预览）' : '',
      text: rawText,
      hexRows: bytesToHexRows(bytes, args.page * (args.pageBytes ?? 4096)),
      isImageCandidate: isImg,
    };
  },

  async preview_file_image(args: { entryId: string }): Promise<PreviewImageResponse> {
    if (args.entryId === '2048:9:0') {
      return {
        ok: true,
        dataUrl: DEMO_PNG_DATA_URL,
        width: 420,
        height: 240,
        animated: false,
        sourceNote: '只读演示图片',
      };
    }
    return {
      ok: false,
      error: '图片损坏或格式不受支持',
      sourceNote: '',
    };
  },

  async export_file(args: { entryId: string }): Promise<ExportFileResponse> {
    if (!currentCase) throw new Error('尚未打开案件');
    const entry = DEMO_ENTRIES.find((e) => e.entryId === args.entryId);
    return {
      path: `${currentCase.caseDir}\\exports\\${entry?.name ?? 'exported.bin'}`,
      title: '导出成功',
      note: '浏览器演示模式模拟导出结果（真实桌面端将在校验镜像后写入案件 exports 目录）。',
      snapshot: currentCase,
    };
  },

  async record_finding_note(args: { entryId: string; note: string }): Promise<{ snapshot: CaseSnapshot }> {
    if (!currentCase) throw new Error('尚未打开案件');
    const entry = DEMO_ENTRIES.find((e) => e.entryId === args.entryId);
    if (entry) {
      const nextSeq = demoAuditRecords.length + 1;
      const nowStr = '2026-03-10 10:20:00';
      const rec = {
        seq: nextSeq,
        timestamp: nowStr,
        action: 'FILE_NOTE',
        actionTitle: '取证笔记',
        origin: 'manual',
        originLabel: '人工',
        actor: currentCase.examiner,
        result: '成功',
        details: {
          offset: entry.offset,
          inode: entry.inode,
          deleted: entry.deleted,
          image_sha256: currentCase.evidence?.sha256 || '',
          note: args.note,
          source_verification: '通过（与初始固定值一致）',
        },
      };
      const existing = demoFindings.find((g) => g.subject === entry.path && g.inode === entry.inode);
      if (existing) {
        existing.records.push(rec);
        existing.count = existing.records.length;
        existing.latestTime = nowStr;
      } else {
        demoFindings.push({
          groupKey: `${entry.path}|${entry.offset}|${entry.inode}|${entry.deleted}`,
          seq: demoFindings.length + 1,
          subject: entry.path,
          status: entry.deleted ? '已删除' : '现存',
          deleted: entry.deleted,
          offset: entry.offset,
          inode: entry.inode,
          imageSha256: currentCase.evidence?.sha256 || '',
          count: 1,
          latestTime: nowStr,
          records: [rec],
        });
      }
      demoAuditRecords.push({
        seq: nextSeq,
        timestamp: nowStr,
        origin: 'manual',
        originLabel: '人工',
        actor: currentCase.examiner,
        action: 'FILE_NOTE',
        actionTitle: '记录取证发现',
        result: '成功',
        subject: entry.path,
        details: { offset: entry.offset, inode: entry.inode, note: args.note },
        previous: demoAuditRecords[demoAuditRecords.length - 1]?.hash || '0'.repeat(64),
        hash: `${nextSeq.toString(16).padStart(2, '0')}a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcde`,
      });
    }
    return { snapshot: currentCase };
  },

  async examine_file(args: { entryId: string; comparisonPath?: string }): Promise<ExamineFileResponse> {
    if (!currentCase) throw new Error('尚未打开案件');
    const entry = DEMO_ENTRIES.find((e) => e.entryId === args.entryId) || DEMO_ENTRIES[1];
    const hash = '4d91a3f28b0c7e65d1a9f4c2e38b7a605d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a';
    return {
      title: args.comparisonPath ? '校验文件一致性' : '计算文件 SHA-256',
      path: entry.path,
      result: args.comparisonPath ? '一致' : '成功',
      size: entry.size,
      recordedSize: entry.size,
      sha256: hash,
      comparisonPath: args.comparisonPath,
      comparisonSha256: args.comparisonPath ? hash : undefined,
      sourceNote: entry.deleted ? '已删除记录' : '',
      sourceVerification: '通过（与初始固定值一致）',
      snapshot: currentCase,
    };
  },

  async list_findings(args: {
    status?: string | null;
    offset?: string | null;
    keyword?: string;
    sortColumn: 'seq' | 'latest';
    descending: boolean;
  }): Promise<ListFindingsResponse> {
    if (!currentCase) {
      return { statusText: '尚未打开案件', filterOptions: { statuses: [], offsets: [] }, groups: [] };
    }
    const kw = (args.keyword || '').trim().toLowerCase();
    let groups = demoFindings.filter((g) => {
      if (args.status && g.status !== args.status) return false;
      if (args.offset && String(g.offset) !== args.offset) return false;
      if (kw && !`${g.subject} ${JSON.stringify(g.records)}`.toLowerCase().includes(kw)) return false;
      return true;
    });
    groups = [...groups].sort((a, b) => {
      const cmp =
        args.sortColumn === 'seq'
          ? a.seq - b.seq
          : a.latestTime.localeCompare(b.latestTime) || a.seq - b.seq;
      return args.descending ? -cmp : cmp;
    });
    return {
      statusText: demoFindings.length
        ? `取证发现 · ${demoFindings.length} 个文件 · 日志链校验通过`
        : '尚无取证发现 · 右键文件可记录笔记、计算摘要或比对副本',
      filterOptions: {
        statuses: Array.from(new Set(demoFindings.map((g) => g.status))),
        offsets: Array.from(new Set(demoFindings.map((g) => String(g.offset)))),
      },
      groups,
    };
  },

  async export_findings(): Promise<ExportFindingsResponse> {
    if (!currentCase) throw new Error('尚未打开案件');
    return {
      summaryPath: `${currentCase.caseDir}\\exports\\取证发现汇总_demo0001.md`,
      exportedCount: demoFindings.length,
      failedCount: 0,
      note: `已导出 ${demoFindings.length} 个证据文件至 exports 目录，并生成汇总清单。`,
      snapshot: currentCase,
    };
  },

  async build_timeline(): Promise<BuildTimelineResponse> {
    return {
      total: demoTimelineRows.length,
      hint: `MACB 时间线 · ${demoTimelineRows.length} 条事件 · UTC+8 · C 为元数据变更，B 为创建；FAT 不保存 C 时间`,
      filterOptions: {
        events: ['B 创建', 'M 内容修改', 'A 访问'],
        statuses: ['现存', '已删除'],
        offsets: ['2048'],
      },
    };
  },

  async query_timeline_page(args: {
    query: string;
    event?: string | null;
    status?: string | null;
    offset?: string | null;
    sortColumn: 'seq' | 'time';
    descending: boolean;
    page: number;
    pageSize: number;
  }): Promise<QueryTimelinePageResponse> {
    if (!currentCase) {
      return { total: 0, totalEvents: 0, page: 0, totalPages: 1, items: [] };
    }
    const q = args.query.trim().toLowerCase();
    let rows = demoTimelineRows.filter((r) => {
      if (args.event && r.event !== args.event) return false;
      if (args.status && r.status !== args.status) return false;
      if (args.offset && String(r.offset) !== args.offset) return false;
      if (q && !`${r.time} ${r.event} ${r.status} ${r.offset} ${r.path}`.toLowerCase().includes(q)) return false;
      return true;
    });
    rows = [...rows].sort((a, b) => {
      const cmp = args.sortColumn === 'seq' ? a.number - b.number : a.time.localeCompare(b.time) || a.number - b.number;
      return args.descending ? -cmp : cmp;
    });
    const totalPages = Math.max(1, Math.ceil(rows.length / args.pageSize));
    const page = Math.max(0, Math.min(args.page, totalPages - 1));
    const start = page * args.pageSize;
    return {
      total: rows.length,
      totalEvents: demoTimelineRows.length,
      page,
      totalPages,
      items: rows.slice(start, start + args.pageSize),
    };
  },

  async list_audit_log(args: {
    query: string;
    origin?: string | null;
    actor?: string | null;
    action?: string | null;
    result?: string | null;
    sortColumn: 'seq' | 'time';
    descending: boolean;
  }): Promise<ListAuditLogResponse> {
    if (!currentCase) {
      return {
        valid: true,
        statusText: '尚未打开案件',
        filterOptions: { origins: [], actors: [], actions: [], results: [] },
        records: [],
      };
    }
    const q = args.query.trim().toLowerCase();
    let records = demoAuditRecords.filter((r) => {
      if (args.origin) {
        // 表头筛选“MCP”/“mcp”匹配全部 MCP 记录，筛选“MCP · <使用者>”时精确匹配该调用方
        const originFilter = args.origin.trim();
        const originLower = originFilter.toLowerCase();
        const matched =
          r.originLabel === originFilter ||
          r.origin.toLowerCase() === originLower ||
          (originFilter === '人工' && r.origin === 'manual') ||
          (originLower === 'mcp' && r.origin === 'mcp');
        if (!matched) return false;
      }
      if (args.actor && r.actor !== args.actor) return false;
      if (args.action && r.actionTitle !== args.action) return false;
      if (args.result && r.result !== args.result) return false;
      if (
        q &&
        !`${r.origin} ${r.originLabel} ${r.mcpUser ?? ''} ${r.actor} ${r.actionTitle} ${r.result} ${r.subject} ${JSON.stringify(r.details)}`
          .toLowerCase()
          .includes(q)
      ) {
        return false;
      }
      return true;
    });
    records = [...records].sort((a, b) => {
      const cmp = args.sortColumn === 'seq' ? a.seq - b.seq : a.timestamp.localeCompare(b.timestamp) || a.seq - b.seq;
      return args.descending ? -cmp : cmp;
    });
    const mcpCount = demoAuditRecords.filter((r) => r.origin === 'mcp').length;
    const manualCount = demoAuditRecords.length - mcpCount;
    const originOptions: string[] = [];
    if (manualCount > 0) originOptions.push('人工');
    if (mcpCount > 0) {
      originOptions.push('MCP');
      const specificMcp = Array.from(
        new Set(
          demoAuditRecords
            .filter((r) => r.origin === 'mcp' && r.originLabel && r.originLabel !== 'MCP')
            .map((r) => r.originLabel)
        )
      ).sort();
      originOptions.push(...specificMcp);
    }
    return {
      valid: true,
      statusText: `日志链校验通过 · 共 ${demoAuditRecords.length} 条操作（人工 ${manualCount} · MCP ${mcpCount}）`,
      filterOptions: {
        origins: originOptions,
        actors: Array.from(new Set(demoAuditRecords.map((r) => r.actor))),
        actions: Array.from(new Set(demoAuditRecords.map((r) => r.actionTitle))),
        results: Array.from(new Set(demoAuditRecords.map((r) => r.result))),
      },
      records,
    };
  },

  async start_content_search(args: {
    query: string;
    encoding: SearchEncoding;
    selectedEntryId?: string | null;
  }): Promise<StartContentSearchResponse> {
    const query = args.query.trim();
    if (!query) throw new Error('请输入搜索内容');
    searchCounter += 1;
    const searchId = `demo-search-${searchCounter}`;
    let needleBytes: Uint8Array;
    if (args.encoding === 'HEX') {
      const clean = query.replace(/\s+/g, '');
      if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
        throw new Error('HEX 搜索条件必须为偶数位十六进制字节');
      }
      const pairs = clean.match(/.{2}/g) || [];
      needleBytes = new Uint8Array(pairs.map((h) => parseInt(h, 16)));
    } else if (args.encoding === 'UTF-16LE') {
      needleBytes = new Uint8Array(query.length * 2);
      for (let i = 0; i < query.length; i += 1) {
        const code = query.charCodeAt(i);
        needleBytes[i * 2] = code & 0xff;
        needleBytes[i * 2 + 1] = (code >> 8) & 0xff;
      }
    } else {
      needleBytes = new TextEncoder().encode(query);
    }
    const needleHex = Array.from(needleBytes)
      .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
      .join('');

    const targets = args.selectedEntryId
      ? DEMO_ENTRIES.filter((e) => e.entryId === args.selectedEntryId)
      : DEMO_ENTRIES.filter((e) => !e.directory && !e.mode.toLowerCase().startsWith('v/'));

    // 在原始字节数组上执行精确字节匹配，保证中文/二进制文件的偏移与 HEX 上下文严格准确
    const findBytes = (haystack: Uint8Array, needle: Uint8Array, fromIndex: number): number => {
      if (needle.length === 0 || needle.length > haystack.length) return -1;
      const limit = haystack.length - needle.length;
      outer: for (let i = fromIndex; i <= limit; i += 1) {
        for (let j = 0; j < needle.length; j += 1) {
          if (haystack[i + j] !== needle[j]) continue outer;
        }
        return i;
      }
      return -1;
    };
    const toHex = (arr: Uint8Array) =>
      Array.from(arr)
        .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
        .join(' ');
    const encoder = new TextEncoder();
    const matched: SearchHitDto[] = [];

    for (const entry of targets) {
      const content = DEMO_FILE_TEXTS[entry.entryId] || '';
      const bytes =
        entry.entryId === '2048:9:0'
          ? Uint8Array.from(content, (ch) => ch.charCodeAt(0) & 0xff)
          : encoder.encode(content);
      let pos = findBytes(bytes, needleBytes, 0);
      while (pos !== -1) {
        const beforeSlice = bytes.slice(Math.max(0, pos - 8), pos);
        const afterSlice = bytes.slice(pos + needleBytes.length, pos + needleBytes.length + 12);
        matched.push({
          hitIndex: matched.length,
          entryId: entry.entryId,
          pos,
          offset: entry.offset,
          inode: entry.inode,
          path: entry.path,
          deleted: entry.deleted,
          beforeHex: toHex(beforeSlice) || '—',
          afterHex: toHex(afterSlice) || '—',
        });
        pos = findBytes(bytes, needleBytes, pos + Math.max(1, needleBytes.length));
      }
    }

    searchHitsStore.set(searchId, matched);

    const timer = window.setTimeout(() => {
      activeSearchTimers.delete(searchId);
      const reportName = `search_demo_${searchCounter}.json`;
      if (currentCase) {
        const nextRec: SearchRecordSummaryDto = {
          reportName,
          query: args.query,
          encoding: args.encoding,
          hits: matched.length,
          failed: 0,
          visited: targets.length,
          eligible: targets.length,
          status: '完成',
          time: '2026-03-10 10:25:00',
        };
        currentCase = {
          ...currentCase,
          searchRecords: [nextRec, ...(currentCase.searchRecords ?? [])],
        };
      }
      searchHitsStore.set(`replay:${reportName}`, matched);
      emit('search:progress', { searchId, stage: '检索文件内容', done: targets.length, total: targets.length });
      if (matched.length > 0) {
        emit('search:hits', { searchId, hits: matched });
      }
      emit('search:finished', {
        searchId,
        status: '已完成',
        visited: targets.length,
        eligible: targets.length,
        totalHits: matched.length,
        errorsCount: 0,
        verification: '通过（与初始固定值一致）',
        reportName,
        snapshot: currentCase || undefined,
      });
    }, 180);
    activeSearchTimers.set(searchId, timer);

    return { searchId, needleHex };
  },

  async cancel_content_search(args: { searchId: string }): Promise<{ cancelled: boolean }> {
    const timer = activeSearchTimers.get(args.searchId);
    if (timer !== undefined) {
      window.clearTimeout(timer);
      activeSearchTimers.delete(args.searchId);
      emit('search:finished', {
        searchId: args.searchId,
        status: '已取消',
        visited: 0,
        eligible: 0,
        totalHits: 0,
        errorsCount: 0,
        verification: '已取消',
      });
    }
    return { cancelled: true };
  },

  async bookmark_search_hits(args: { searchId: string; hitIndices: number[] }): Promise<{ savedCount: number; snapshot: CaseSnapshot }> {
    if (!currentCase) throw new Error('尚未打开案件');
    const hits = searchHitsStore.get(args.searchId) || [];
    let savedCount = 0;
    for (const idx of args.hitIndices) {
      const hit = hits.find((h) => h.hitIndex === idx);
      if (hit) {
        await this.record_finding_note({
          entryId: hit.entryId,
          note: `内容命中：文件内字节偏移 ${hit.pos}`,
        });
        savedCount += 1;
      }
    }
    return { savedCount, snapshot: currentCase };
  },

  async load_search_record(args: { reportName: string }): Promise<SearchHitDto[]> {
    const stored = searchHitsStore.get(`replay:${args.reportName}`);
    if (stored) {
      return stored;
    }
    const demoReplay: SearchHitDto[] = [
      {
        hitIndex: 0,
        entryId: '2048:5:0',
        pos: 5,
        offset: 2048,
        inode: '5',
        path: 'DOCS/CASE.TXT',
        deleted: false,
        beforeHex: '43 61 73 65 20',
        afterHex: '20 69 6e 73 69 64 65',
      },
    ];
    searchHitsStore.set(`replay:${args.reportName}`, demoReplay);
    return demoReplay;
  },

  async generate_report(): Promise<{ path: string; snapshot: CaseSnapshot }> {
    if (!currentCase) throw new Error('尚未打开案件');
    return {
      path: `${currentCase.caseDir}\\reports\\report_${currentCase.number}.md`,
      snapshot: currentCase,
    };
  },

  async generate_html_report(): Promise<GenerateHtmlReportResponse> {
    if (!currentCase) throw new Error('尚未打开案件');
    return {
      path: `${currentCase.caseDir}\\reports\\report_${currentCase.number}.html`,
      sha256: '8b4e2f19a7c63d0e5f91a2c3d4e5f60718293a4b5c6d7e8f90123456789abcde',
      bytes: 48620,
      generatedAt: '2026-03-10 10:32:18 UTC+8',
    };
  },

  async verify_review_bundle(args: {
    bundlePath: string;
    expectedSha256?: string | null;
  }): Promise<VerifyReviewBundleResponse> {
    const bundlePath = (args.bundlePath || '').trim();
    if (!bundlePath) {
      throw new Error('请先选择或输入复核包 .zip 文件路径');
    }
    const cleanBundleSha = '5a1f9c2e8d4b7031e6a2f4c890b1d3e5f7a9c1e3b5d7f90123456789abcdef12';
    const expected = args.expectedSha256?.trim().toLowerCase() || null;
    const isDemoTampered =
      bundlePath.toLowerCase().includes('tamper') ||
      bundlePath.includes('篡改') ||
      (expected !== null && expected !== cleanBundleSha);
    const sha256Source: 'manual' | 'sidecar' | 'none' = expected ? 'manual' : 'sidecar';
    const resolvedExpected = expected ?? cleanBundleSha;
    const sha256Matched = isDemoTampered ? false : true;
    const auditHead = '7708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6';

    if (isDemoTampered) {
      return {
        ok: false,
        bundlePath,
        bundleSha256: 'deadbeef8d4b7031e6a2f4c890b1d3e5f7a9c1e3b5d7f90123456789abcdef12',
        expectedSha256: resolvedExpected,
        sha256Source,
        sha256Matched,
        auditValid: false,
        auditCount: 7,
        auditHead,
        auditError: '第 #6 条审计记录哈希重算不一致（期望 66f70819…，实测 99ee4411…），审计哈希链已断裂',
        manifestValid: true,
        members: [
          {
            path: 'report.md',
            category: '报告',
            status: 'tampered',
            expectedSha256: '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809',
            actualSha256: 'ff2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f899',
            size: 12840,
            message: 'SHA-256 摘要不匹配（疑似被修改）',
          },
          {
            path: 'report.html',
            category: 'HTML 报告',
            status: 'ok',
            expectedSha256: '8b4e2f19a7c63d0e5f91a2c3d4e5f60718293a4b5c6d7e8f90123456789abcde',
            actualSha256: '8b4e2f19a7c63d0e5f91a2c3d4e5f60718293a4b5c6d7e8f90123456789abcde',
            size: 48620,
            message: 'SHA-256 一致',
          },
          {
            path: 'audit/audit.jsonl',
            category: '审计日志',
            status: 'tampered',
            expectedSha256: '2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a',
            actualSha256: 'ee3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809ee',
            size: 4218,
            message: 'SHA-256 摘要不匹配且链式校验断裂',
          },
          {
            path: 'exports/CASE.TXT',
            category: '导出副本',
            status: 'ok',
            expectedSha256: '4d91a3f28b0c7e65d1a9f4c2e38b7a605d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a',
            actualSha256: '4d91a3f28b0c7e65d1a9f4c2e38b7a605d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a',
            size: 112,
            message: 'SHA-256 一致',
          },
        ],
        crossChecks: [
          { name: 'report.md', status: 'failed', message: '报告正文摘要与 manifest.json 记录不一致' },
          { name: 'report.html', status: 'ok', message: 'HTML 报告与清单摘要及审计链记录一致' },
          { name: 'searches/search_demo_1.json', status: 'ok', message: '搜索记录与审计链记录一致' },
          { name: 'findings', status: 'failed', message: '审计链 #6 断链导致取证发现链校验失败' },
        ],
        errors: [
          'ZIP 整包 SHA-256 与期望基线不一致',
          '成员 report.md 摘要不匹配（检出篡改）',
          '审计哈希链第 #6 条记录校验断裂',
        ],
      };
    }

    return {
      ok: true,
      bundlePath,
      bundleSha256: cleanBundleSha,
      expectedSha256: resolvedExpected,
      sha256Source,
      sha256Matched: true,
      auditValid: true,
      auditCount: 7,
      auditHead,
      auditError: null,
      manifestValid: true,
      members: [
        {
          path: 'report.md',
          category: '报告',
          status: 'ok',
          expectedSha256: '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809',
          actualSha256: '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809',
          size: 12840,
          message: 'SHA-256 一致',
        },
        {
          path: 'report.html',
          category: 'HTML 报告',
          status: 'ok',
          expectedSha256: '8b4e2f19a7c63d0e5f91a2c3d4e5f60718293a4b5c6d7e8f90123456789abcde',
          actualSha256: '8b4e2f19a7c63d0e5f91a2c3d4e5f60718293a4b5c6d7e8f90123456789abcde',
          size: 48620,
          message: 'SHA-256 一致',
        },
        {
          path: 'audit/audit.jsonl',
          category: '审计日志',
          status: 'ok',
          expectedSha256: '2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a',
          actualSha256: '2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a',
          size: 4218,
          message: 'SHA-256 一致，7 条链式审计完整',
        },
        {
          path: 'exports/CASE.TXT',
          category: '导出副本',
          status: 'ok',
          expectedSha256: '4d91a3f28b0c7e65d1a9f4c2e38b7a605d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a',
          actualSha256: '4d91a3f28b0c7e65d1a9f4c2e38b7a605d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a',
          size: 112,
          message: 'SHA-256 一致',
        },
        {
          path: 'searches/search_demo_1.json',
          category: '搜索记录',
          status: 'ok',
          expectedSha256: '3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b',
          actualSha256: '3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b',
          size: 982,
          message: 'SHA-256 一致',
        },
      ],
      crossChecks: [
        { name: 'report.md', status: 'ok', message: '报告 SHA-256 与审计链及清单一致' },
        { name: 'report.html', status: 'ok', message: 'HTML 报告 SHA-256 与清单一致' },
        { name: 'searches/search_demo_1.json', status: 'ok', message: '检索命中与审计链记录一致' },
        { name: 'findings', status: 'ok', message: '取证发现归组与审计链记录 100% 对应' },
      ],
      errors: [],
    };
  },

  async scan_magic_mismatches(): Promise<ScanMagicMismatchesResponse> {
    if (!currentCase?.evidence) {
      throw new Error('请先加载镜像');
    }
    const result: ScanMagicMismatchesResponse = {
      scannedCount: 4,
      skippedCount: 3,
      mismatchCount: 1,
      elapsedMs: 14,
      cancelled: false,
      typeCounts: [
        { detectedType: 'PNG', detectedFamily: 'image', label: 'PNG 图像', count: 1 },
        { detectedType: 'TEXT', detectedFamily: 'text', label: '纯文本', count: 3 },
      ],
      mismatches: [
        {
          entryKey: '2048:7:1',
          offset: 2048,
          inode: '7',
          path: 'DOCS/DRAFT_DEL.TXT',
          deleted: true,
          size: 81,
          extension: 'txt',
          detectedType: 'PE',
          detectedFamily: 'executable',
          detectedLabel: 'Windows PE 可执行文件',
          severity: 'high',
          reason: '演示检出：扩展名为 .txt，但模拟检测到可执行文件头特征（演示数据）',
          magicHex: '4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00',
        },
      ],
    };
    demoMagicScanCache.set(currentCase.caseDir, result);
    return result;
  },

  async load_cached_magic_scan(): Promise<ScanMagicMismatchesResponse | null> {
    if (!currentCase?.evidence) {
      return null;
    }
    return demoMagicScanCache.get(currentCase.caseDir) ?? null;
  },

  async inspect_entry_magic(args: { entryKey: string }): Promise<InspectEntryMagicResponse> {
    const key = (args.entryKey || '').trim();
    if (key === '2048:9:0') {
      return {
        detectedType: 'PNG',
        detectedFamily: 'image',
        detectedLabel: 'PNG 图像',
        extension: 'png',
        mismatch: false,
        severity: 'none',
        reason: '文件头魔数与扩展名 .png 一致',
        magicHex: '89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52',
      };
    }
    if (key === '2048:7:1') {
      return {
        detectedType: 'PE',
        detectedFamily: 'executable',
        detectedLabel: 'Windows PE 可执行文件',
        extension: 'txt',
        mismatch: true,
        severity: 'high',
        reason: '扩展名为 .txt，但文件头魔数特征指向 Windows PE 可执行文件（演示）',
        magicHex: '4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00',
      };
    }
    const entry = DEMO_ENTRIES.find((e) => e.entryId === key);
    const ext = entry?.name.includes('.') ? entry.name.split('.').pop()?.toLowerCase() ?? '' : '';
    const raw = DEMO_FILE_TEXTS[key] ?? '';
    const bytes = new TextEncoder().encode(raw).slice(0, 16);
    const magicHex = Array.from(bytes)
      .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
      .join(' ');
    return {
      detectedType: null,
      detectedFamily: null,
      detectedLabel: '纯文本 / 无特定二进制魔数',
      extension: ext,
      mismatch: false,
      severity: 'none',
      reason: '未检出扩展名伪装',
      magicHex: magicHex || '—',
    };
  },

  async inspect_bundle_materials(): Promise<BundleMaterialsResponse> {
    return {
      exports: [
        {
          index: 1,
          exists: true,
          displayPath: 'exports/CASE.TXT',
          source: 'DOCS/CASE.TXT',
          size: 112,
          time: '2026-03-10 09:35:00',
        },
        {
          index: 2,
          exists: false,
          displayPath: 'exports/DRAFT_DEL.TXT',
          source: 'DOCS/DRAFT_DEL.TXT',
          size: 81,
          time: '2026-03-10 09:36:12',
          missingReason: '本地文件不存在（可能已被清理或隔离）',
        },
      ],
      searches: [
        {
          index: 1,
          exists: true,
          displayPath: 'reports/search_demo_1.json',
          query: '6E 6F 74 65',
          encoding: 'HEX',
          hits: 1,
          time: '2026-03-10 09:40:00',
        },
      ],
      missingText: '【缺失导出副本】\n#2  exports/DRAFT_DEL.TXT  (来源：DOCS/DRAFT_DEL.TXT) — 本地文件不存在',
    };
  },

  async build_review_bundle(): Promise<{ path: string; snapshot: CaseSnapshot }> {
    if (!currentCase) throw new Error('尚未打开案件');
    return {
      path: `${currentCase.caseDir}\\reports\\review_bundle_${currentCase.number}.zip`,
      snapshot: currentCase,
    };
  },

  async get_mcp_status(args?: { port?: number }): Promise<McpStatus> {
    const port = mcpRunning ? mcpPort : args?.port ?? mcpPort;
    const url = `http://127.0.0.1:${port}/mcp`;
    return {
      running: mcpRunning,
      host: '127.0.0.1',
      port,
      path: '/mcp',
      url,
      stdioConfigJson: JSON.stringify(
        {
          mcpServers: {
            tracedesk: {
              command: 'tracedesk-mcp.exe',
              args: ['--transport', 'stdio', '--cases-dir', 'C:\\TraceDesk\\cases'],
            },
          },
        },
        null,
        2
      ),
      stdioCli: 'tracedesk-mcp.exe --transport stdio --cases-dir "C:\\TraceDesk\\cases"',
      httpConfigJson: JSON.stringify(
        {
          mcpServers: {
            tracedesk: {
              url,
            },
          },
        },
        null,
        2
      ),
      httpCli: `tracedesk-mcp --transport streamable-http --host 127.0.0.1 --port ${port} --path /mcp`,
      tools: DEMO_TOOLS,
      activeCaseNumber: currentCase?.number ?? null,
    };
  },

  async start_mcp_http(args: { port: number }): Promise<McpStatus> {
    mcpRunning = true;
    mcpPort = args.port;
    return this.get_mcp_status({ port: mcpPort });
  },

  async stop_mcp_http(): Promise<McpStatus> {
    mcpRunning = false;
    return this.get_mcp_status({ port: mcpPort });
  },

  async list_mcp_activities(args?: ListMcpActivitiesParams): Promise<McpActivitySnapshot> {
    const keyword = (args?.keyword || '').trim().toLowerCase();
    const client = stripTrailingVersion(args?.client);
    const status = args?.status?.trim() || '';
    const transport = args?.transport?.trim() || '';
    const limit = args?.limit && args.limit > 0 ? args.limit : 500;

    let items = demoMcpActivities.filter((item) => {
      const cleanClient = stripTrailingVersion(item.client);
      if (client && cleanClient !== client) return false;
      if (status && item.phase !== status) return false;
      if (transport && item.transport !== transport) return false;
      if (keyword) {
        const hay = [
          item.toolTitle,
          item.toolName ?? '',
          item.method,
          cleanClient,
          item.caseNumber ?? '',
          item.paramsSummary,
          item.resultSummary,
          item.error ?? '',
        ]
          .join(' ')
          .toLowerCase();
        if (!hay.includes(keyword)) return false;
      }
      return true;
    });

    if (items.length > limit) {
      items = items.slice(0, limit);
    }

    return {
      activities: items,
      stats: computeMcpActivityStats(demoMcpActivities),
    };
  },

  async clear_mcp_activities(): Promise<{ cleared: boolean }> {
    demoMcpActivities = [];
    return { cleared: true };
  },

  async open_in_os(): Promise<{ ok: boolean }> {
    return { ok: true };
  },

  async check_busy_before_close(): Promise<{ busy: boolean; reason?: string }> {
    return { busy: false };
  },
};
