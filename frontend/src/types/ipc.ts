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
  path: string;
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
  sha256: string;
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
  checkedAt?: string;
  method?: string;
  note?: string;
}

export interface QuickLocation {
  offset: number;
  inode: string | null;
  path: string;
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

/* ---------- Streaming Event Payloads (§3.6) ---------- */

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
