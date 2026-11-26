/**
 * TraceDesk Tauri 2 前后端 IPC 类型契约 (100% 对齐 ui-contract.md §3)
 */

export type CustodyState = 'idle' | 'active' | 'verified' | 'warning' | 'error';

export type PreviewEncoding =
  | 'ASCII'
  | 'UTF-8'
  | 'UTF-16LE'
  | 'UTF-16BE'
  | 'GBK'
  | 'GB18030'
  | 'Big5'
  | 'Windows-1252'
  | 'ISO-8859-1';

export const PREVIEW_ENCODINGS: readonly PreviewEncoding[] = [
  'ASCII',
  'UTF-8',
  'UTF-16LE',
  'UTF-16BE',
  'GBK',
  'GB18030',
  'Big5',
  'Windows-1252',
  'ISO-8859-1',
] as const;

export type SearchEncoding = 'UTF-8' | 'UTF-16LE' | 'GBK' | 'HEX';

export const SEARCH_ENCODINGS: readonly SearchEncoding[] = [
  'UTF-8',
  'UTF-16LE',
  'GBK',
  'HEX',
] as const;

export interface AppPaths {
  rootDir: string;
  casesDir: string;
  evidenceDir: string;
}

export interface SuggestCaseDirResponse {
  suggestedPath: string;
  folderName: string;
}

export interface PartitionInfo {
  offset: number;
  length?: number;
  description: string;
  slot?: string;
}

export interface EwfSegmentInfo {
  name?: string;
  path?: string;
  size: number;
  sha256?: string;
}

export interface CoverageVolume {
  offset: number;
  filesystem: string;
  partitionEnd?: number | null;
  volumeEnd?: number | null;
  missingBytes?: number;
  status: string;
}

export interface CoverageInfo {
  bytes: number;
  volumes: CoverageVolume[];
  text?: string;
}

export interface ProvenanceInfo {
  evidenceId?: string;
  source?: string;
  acquired?: string;
  tool?: string;
  expectedSha256?: string;
  // 兼容后端蛇形/驼峰扩展
  evidence_id?: string;
  expected_sha256?: string;
}

export interface EvidenceInfo {
  path: string;
  size: number;
  sha256: string | null;
  fixedAt?: string | null;
  fixed_at?: string | null;
  format?: string;
  largeImage?: boolean;
  large_image?: boolean;
  layout?: string;
  partitions: PartitionInfo[];
  segments?: EwfSegmentInfo[];
  coverage?: CoverageInfo | null;
  coverageText?: string;
  provenance?: ProvenanceInfo | null;
  sourceStatus?: string;
}

export interface PartitionScan {
  offset: number;
  status: 'ready' | 'error' | 'pending' | string;
  count?: number;
  error?: string;
}

export interface VerificationInfo {
  ok: boolean;
  time?: string;
  checkedAt?: string;
  actual?: string | null;
  method?: string;
  note?: string;
}

export interface QuickLocation {
  offset: number;
  inode: string | null;
  path: string;
}

/** 最近案件目录项（对应后端 RecentCaseDto） */
export interface RecentCaseDto {
  folder: string;
  name: string;
  number: string;
  examiner: string;
  target: string;
  created: string;
  hasEvidence: boolean;
  inventoryCount: number;
  exportsCount: number;
}

/** 案件历史内容搜索记录摘要（用于内容搜索页下拉回放） */
export interface SearchRecordSummaryDto {
  reportName: string;
  query: string;
  encoding: string;
  hits: number;
  failed: number;
  visited: number;
  eligible: number;
  status: string;
  time: string;
}

export interface CaseSnapshot {
  caseDir: string;
  id: string;
  number: string;
  examiner: string;
  target: string;
  created: string;
  custodyState: CustodyState;
  summaryLine1: string;
  summaryLine2: string;
  sourceNote: string;
  browsingDirectories: boolean;
  needsPartitionScan: boolean;
  inventoryCount: number;
  exportsCount: number;
  evidence: EvidenceInfo | null;
  partitionScans: PartitionScan[];
  verification: VerificationInfo | null;
  fsstat: string;
  quickLocation: QuickLocation | null;
  /** 案件内可用于回放的历史内容搜索记录列表（最新在前） */
  searchRecords?: SearchRecordSummaryDto[];
}

export interface EntryView {
  entryId: string;
  name: string;
  path: string;
  status: string;
  size: number;
  inode: string;
  mtime: string;
  atime: string;
  ctime: string;
  crtime: string;
  offset: number;
  directory: boolean;
  deleted: boolean;
  reallocated?: boolean;
  mode: string;
  filesystem?: string;
  canExport?: boolean;
  iconKind?: 'folder' | 'disk' | 'file' | 'image' | 'table' | 'system';
}

export interface TreeNodeDto {
  id: string;
  label: string;
  tooltip?: string;
  kind: 'image' | 'partition' | 'root' | 'directory' | 'file' | 'group';
  iconKind: 'folder' | 'disk' | 'file' | 'image' | 'table' | 'system';
  offset?: number;
  scopePath?: string;
  inode?: string | null;
  entryId?: string;
  deleted?: boolean;
  hasChildren: boolean;
  groupIndex?: number;
}

export interface GetTreeChildrenParams {
  offset: number;
  scopePath: string;
  inode?: string | null;
  groupIndex?: number;
}

export interface TreeChildrenResponse {
  nodes: TreeNodeDto[];
  grouped: boolean;
  groupCount: number;
}

export interface QueryFilesPageResponse {
  total: number;
  page: number;
  totalPages: number;
  items: EntryView[];
}

export interface LocateFileResponse {
  scopeOffset: number;
  scopePath: string;
  page: number;
  indexInPage: number;
}

export interface HexRowDto {
  offsetHex: string;
  bytesHex: string;
  chars: string;
}

export interface PreviewPageResponse {
  page: number;
  totalPages: number;
  size: number;
  recordedSize: number;
  readNote: string;
  sourceNote: string;
  text: string;
  hexRows: HexRowDto[];
  isImageCandidate: boolean;
}

export interface PreviewImageResponse {
  ok: boolean;
  dataUrl?: string;
  width?: number;
  height?: number;
  animated?: boolean;
  error?: string;
  sourceNote: string;
}

export interface ExportFileResponse {
  path: string;
  title: '导出成功' | '部分导出' | string;
  note: string;
  snapshot: CaseSnapshot;
}

export interface ExamineFileResponse {
  title: string;
  path: string;
  result: string;
  size: number;
  recordedSize: number;
  sha256: string;
  comparisonPath?: string;
  comparisonSha256?: string;
  readNote?: string;
  sourceNote?: string;
  sourceVerification?: string;
  snapshot: CaseSnapshot;
}

export interface FindingRecordDto {
  seq: number;
  timestamp: string;
  action: string;
  actionTitle?: string;
  origin: 'manual' | 'mcp' | string;
  originLabel?: string;
  /** MCP 使用者/客户端标识（仅来源为 MCP 且已知使用者/客户端时有值） */
  mcpUser?: string;
  actor: string;
  result: string;
  details: Record<string, unknown>;
}

export interface FindingGroupDto {
  groupKey: string;
  seq: number;
  subject: string;
  status: string;
  deleted: boolean;
  offset: number;
  inode: string;
  imageSha256: string;
  count: number;
  latestTime: string;
  records: FindingRecordDto[];
}

export interface ListFindingsResponse {
  statusText: string;
  filterOptions: {
    statuses: string[];
    offsets: string[];
  };
  groups: FindingGroupDto[];
}

export interface ExportFindingsResponse {
  summaryPath: string;
  exportedCount: number;
  failedCount: number;
  note: string;
  snapshot: CaseSnapshot;
}

export interface BuildTimelineResponse {
  total: number;
  hint: string;
  filterOptions: {
    events: string[];
    statuses: string[];
    offsets: string[];
  };
}

export interface TimelineRowDto {
  number: number;
  time: string;
  event: string;
  status: string;
  offset: number;
  inode: string;
  path: string;
}

export interface QueryTimelinePageResponse {
  total: number;
  totalEvents: number;
  page: number;
  totalPages: number;
  items: TimelineRowDto[];
}

export interface AuditRecordDto {
  seq: number;
  timestamp: string;
  origin: 'manual' | 'mcp' | string;
  originLabel: string;
  /** MCP 使用者/客户端标识（仅来源为 MCP 且已知使用者/客户端时有值） */
  mcpUser?: string;
  actor: string;
  action: string;
  actionTitle: string;
  result: string;
  subject: string;
  details: Record<string, unknown>;
  previous: string;
  hash: string;
}

export interface ListAuditLogResponse {
  valid: boolean;
  statusText: string;
  filterOptions: {
    origins: string[];
    actors: string[];
    actions: string[];
    results: string[];
  };
  records: AuditRecordDto[];
}

export interface SearchHitDto {
  hitIndex: number;
  entryId: string;
  pos: number;
  offset: number;
  inode: string;
  path: string;
  deleted?: boolean;
  reallocated?: boolean;
  beforeHex: string;
  afterHex: string;
}

export interface StartContentSearchResponse {
  searchId: string;
  needleHex: string;
}

export interface BundleExportRow {
  index: number;
  exists: boolean;
  displayPath: string;
  source: string;
  size: number;
  time: string;
  missingReason?: string;
}

export interface BundleSearchRow {
  index: number;
  exists: boolean;
  displayPath: string;
  query: string;
  encoding: string;
  hits: number;
  time: string;
  missingReason?: string;
}

export interface BundleMaterialsResponse {
  exports: BundleExportRow[];
  searches: BundleSearchRow[];
  missingText: string;
}

export interface ToolCatalogItem {
  name: string;
  title?: string;
  category: string;
  readOnly: boolean;
  summary: string;
}

export interface McpStatus {
  running: boolean;
  host: string;
  port: number;
  path: string;
  url: string;
  stdioConfigJson: string;
  stdioCli: string;
  httpConfigJson: string;
  httpCli: string;
  tools: ToolCatalogItem[];
  activeCaseNumber: string | null;
}

/** MCP 实时监控操作阶段 */
export type McpActivityPhase = 'started' | 'completed' | 'failed';

/** MCP 传输通道类型 */
export type McpTransportKind = 'desktop-http' | 'streamable-http' | 'stdio';

/** 单条 MCP 实时调用记录 */
export interface McpActivityRecord {
  id: string;
  callId: string;
  timestamp: string;
  phase: McpActivityPhase;
  transport: McpTransportKind;
  client: string;
  sessionId?: string | null;
  method: string;
  toolName?: string | null;
  toolTitle: string;
  category: string;
  readOnly: boolean;
  caseDir?: string | null;
  caseNumber?: string | null;
  paramsSummary: string;
  paramsJson: string;
  durationMs?: number | null;
  resultSummary: string;
  responsePreview?: string | null;
  error?: string | null;
}

/** 单个 MCP 工具累计调用统计 */
export interface McpToolStat {
  toolName: string;
  calls: number;
  failures: number;
  avgDurationMs: number;
}

/** MCP 实时监控汇总统计 */
export interface McpActivityStats {
  totalCalls: number;
  runningCalls: number;
  succeededCalls: number;
  failedCalls: number;
  readOnlyCalls: number;
  writeCalls: number;
  avgDurationMs: number;
  activeClients: string[];
  toolStats: Record<string, McpToolStat>;
}

/** 查询 MCP 实时活动列表返回快照 */
export interface McpActivitySnapshot {
  activities: McpActivityRecord[];
  stats: McpActivityStats;
}

/** 查询 MCP 活动记录入参 */
export interface ListMcpActivitiesParams {
  limit?: number;
  client?: string | null;
  status?: string | null;
  transport?: string | null;
  keyword?: string | null;
}

/* ---------- 流式事件载荷 (§3.6) ---------- */

/** MCP 对案件执行变更后的通知事件 */
export interface McpCaseUpdatedEvent {
  caseDir: string;
  toolName: string;
  client: string;
  timestamp: string;
}

export interface TaskProgressEvent {
  stage: string;
  done: number;
  total: number;
}

export interface HashProgressEvent {
  done: number;
  total: number;
  rateMiBs: number;
}

export interface HashFinishedEvent {
  cancelled: boolean;
  ok?: boolean;
  initialFixed?: boolean;
  error?: string;
  snapshot?: CaseSnapshot;
}

export interface SearchHitsEvent {
  searchId: string;
  hits: SearchHitDto[];
}

export interface SearchProgressEvent {
  searchId: string;
  stage: string;
  done: number;
  total: number;
}

export interface SearchFinishedEvent {
  searchId: string;
  error?: string;
  status?: string;
  visited?: number;
  eligible?: number;
  totalHits?: number;
  errorsCount?: number;
  verification?: string;
  reportName?: string;
  snapshot?: CaseSnapshot;
}

/* ---------- Phase 2 新增 IPC 契约：HTML 报告 / 复核包核验 / 文件魔数检测 ---------- */

/** 生成离线自包含 HTML 取证报告返回结果 */
export interface GenerateHtmlReportResponse {
  path: string;
  sha256: string;
  bytes: number;
  generatedAt: string;
}

/** 复核包逐成员哈希核对条目 */
export interface ReviewBundleMemberVerifyDto {
  path: string;
  category: string;
  status: string;
  expectedSha256: string | null;
  actualSha256: string | null;
  size: number | null;
  message: string;
}

/** 复核包跨文件审计链交叉核对条目 */
export interface ReviewBundleCrossCheckDto {
  name: string;
  status: string;
  message: string;
}

/** 一键复核包完整性与防篡改核验结果 */
export interface VerifyReviewBundleResponse {
  ok: boolean;
  bundlePath: string;
  bundleSha256: string;
  expectedSha256: string | null;
  sha256Source: 'manual' | 'sidecar' | 'none';
  sha256Matched: boolean | null;
  auditValid: boolean;
  auditCount: number;
  auditHead: string;
  auditError: string | null;
  manifestValid: boolean;
  members: ReviewBundleMemberVerifyDto[];
  crossChecks: ReviewBundleCrossCheckDto[];
  errors: string[];
}

/** 魔数扫描检出类型聚合统计 */
export interface MagicTypeCountDto {
  detectedType: string;
  detectedFamily: string;
  label: string;
  count: number;
}

/** 单条文件魔数与扩展名伪装检出条目 */
export interface MagicMismatchItemDto {
  entryKey: string;
  offset: number;
  inode: string;
  path: string;
  deleted: boolean;
  size: number;
  extension: string;
  detectedType: string;
  detectedFamily: string;
  detectedLabel: string;
  severity: 'high' | 'medium';
  reason: string;
  magicHex: string;
}

/** 全案魔数伪装检测汇总结果 */
export interface ScanMagicMismatchesResponse {
  scannedCount: number;
  skippedCount: number;
  mismatchCount: number;
  elapsedMs: number;
  cancelled: boolean;
  typeCounts: MagicTypeCountDto[];
  mismatches: MagicMismatchItemDto[];
}

/** 单文件魔数与前 16 字节文件头探测结果 */
export interface InspectEntryMagicResponse {
  detectedType: string | null;
  detectedFamily: string | null;
  detectedLabel: string | null;
  extension: string;
  mismatch: boolean;
  severity: 'high' | 'medium' | 'none';
  reason: string;
  magicHex: string;
}

/** 跨模块“一键跳转定位原文件”统一请求载荷 */
export interface LocateEntryRequest {
  /** 单调递增请求序号，保证重复定位同一文件不同字节偏移时仍能触发响应 */
  requestId?: number;
  /** 可选直接条目标识（如内容搜索命中携带的 entryId） */
  entryId?: string | null;
  /** 分区起始扇区偏移 */
  offset: number;
  /** 文件 inode / 元数据地址 */
  inode: string;
  /** 镜像内路径 */
  path: string;
  /** 是否为已删除条目 */
  deleted?: boolean;
  /** 可选目标字节偏移（非空时自动切换至十六进制视图并跳页滚动） */
  byteOffset?: number | null;
  /** 可选精确高亮字节长度（与 byteOffset 配合使用） */
  highlightLength?: number | null;
}
