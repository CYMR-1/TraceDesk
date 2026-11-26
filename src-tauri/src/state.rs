//! 线程安全的桌面端应用状态、IPC 数据传输对象（与 `ui-contract.md` §3 及
//! `frontend/src/types/ipc.ts` 100% 对齐），以及后台任务、内容搜索与 MCP 协调。

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter};
use tracedesk_core::{
    AppPaths, BrowserIndex, Case, EvidenceInfo, TimelineIndex, can_export, coverage_text,
    deleted_source_note, display_iso_time, display_timestamp, entry_name, entry_status,
    resolve_clean, source_status,
};
use tracedesk_engines::InventoryEntry;
use tracedesk_mcp::{
    ACTIVITY_LOG_FILENAME, ActivityLogTailer, DEFAULT_ACTIVITY_STORE_CAPACITY, McpActivityRecord,
    McpActivitySnapshot, McpActivityStore, append_activity_record, normalize_activity_client,
    truncate_activity_log,
};

pub use tracedesk_mcp::{McpActivityStats, McpToolStat};

use crate::mcp_http::{LocalMcpHttpServer, default_tool_catalog};

/* ==========================================================================================
 * 1. IPC 数据传输对象（与 frontend/src/types/ipc.ts 100% 对齐）
 * ========================================================================================== */

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPathsDto {
    pub root_dir: String,
    pub cases_dir: String,
    pub evidence_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuggestCaseDirResponse {
    pub suggested_path: String,
    pub folder_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseCaseResponse {
    pub closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelResponse {
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathResponse {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenInOsResponse {
    pub ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BusyCheckResponse {
    pub busy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartitionInfoDto {
    pub offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EwfSegmentInfoDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub size: u64,
    #[serde(rename = "sha256", skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageVolumeDto {
    pub offset: u64,
    pub filesystem: String,
    pub partition_end: Option<u64>,
    pub volume_end: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_bytes: Option<u64>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageInfoDto {
    pub bytes: u64,
    pub volumes: Vec<CoverageVolumeDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceInfoDto {
    #[serde(rename = "evidenceId")]
    pub evidence_id: String,
    pub source: String,
    pub acquired: String,
    pub tool: String,
    #[serde(rename = "expectedSha256")]
    pub expected_sha256: String,
    #[serde(rename = "evidence_id")]
    pub evidence_id_snake: String,
    #[serde(rename = "expected_sha256")]
    pub expected_sha256_snake: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceInfoDto {
    pub path: String,
    pub size: u64,
    #[serde(rename = "sha256")]
    pub sha256: Option<String>,
    pub fixed_at: Option<String>,
    pub format: Option<String>,
    pub large_image: Option<bool>,
    pub layout: Option<String>,
    pub partitions: Vec<PartitionInfoDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segments: Option<Vec<EwfSegmentInfoDto>>,
    pub coverage: Option<CoverageInfoDto>,
    pub coverage_text: Option<String>,
    pub provenance: Option<ProvenanceInfoDto>,
    pub source_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartitionScanDto {
    pub offset: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationInfoDto {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    pub actual: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickLocationDto {
    pub offset: u64,
    pub inode: Option<String>,
    pub path: String,
}

/// 案件历史内容搜索记录摘要（从审计链轻量汇总并校验本地 JSON 文件存在性，供前端下拉回放）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRecordSummaryDto {
    pub report_name: String,
    pub query: String,
    pub encoding: String,
    pub hits: u64,
    pub failed: u64,
    pub visited: u64,
    pub eligible: u64,
    pub status: String,
    pub time: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseSnapshot {
    pub case_dir: String,
    pub id: String,
    pub number: String,
    pub examiner: String,
    pub target: String,
    pub created: String,
    pub custody_state: String,
    #[serde(rename = "summaryLine1")]
    pub summary_line1: String,
    #[serde(rename = "summaryLine2")]
    pub summary_line2: String,
    pub source_note: String,
    pub browsing_directories: bool,
    pub needs_partition_scan: bool,
    pub inventory_count: usize,
    pub exports_count: usize,
    pub evidence: Option<EvidenceInfoDto>,
    pub partition_scans: Vec<PartitionScanDto>,
    pub verification: Option<VerificationInfoDto>,
    pub fsstat: String,
    pub quick_location: Option<QuickLocationDto>,
    /// 案件内可用于回放的历史内容搜索记录列表（按时间倒序，最新在前）。
    #[serde(default)]
    pub search_records: Vec<SearchRecordSummaryDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyIntegrityResponse {
    pub ok: bool,
    pub initial_fixed: bool,
    pub snapshot: CaseSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanPartitionsResponse {
    pub completed: bool,
    pub snapshot: CaseSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    pub entry_id: String,
    pub name: String,
    pub path: String,
    pub status: String,
    pub size: u64,
    pub inode: String,
    pub mtime: String,
    pub atime: String,
    pub ctime: String,
    pub crtime: String,
    pub offset: u64,
    pub directory: bool,
    pub deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reallocated: Option<bool>,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_export: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowseDirectoryResponse {
    pub snapshot: CaseSnapshot,
    pub entries: Vec<EntryView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeNodeIpcDto {
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tooltip: Option<String>,
    pub kind: String,
    pub icon_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    pub has_children: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeChildrenResponse {
    pub nodes: Vec<TreeNodeIpcDto>,
    pub grouped: bool,
    pub group_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryFilesPageResponse {
    pub total: usize,
    pub page: usize,
    pub total_pages: usize,
    pub items: Vec<EntryView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocateFileResponse {
    pub scope_offset: u64,
    pub scope_path: String,
    pub page: usize,
    pub index_in_page: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HexRowDto {
    pub offset_hex: String,
    pub bytes_hex: String,
    pub chars: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewPageResponse {
    pub page: usize,
    pub total_pages: usize,
    pub size: u64,
    pub recorded_size: u64,
    pub read_note: String,
    pub source_note: String,
    pub text: String,
    pub hex_rows: Vec<HexRowDto>,
    pub is_image_candidate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewImageResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub animated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub source_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFileResponse {
    pub path: String,
    pub title: String,
    pub note: String,
    pub snapshot: CaseSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotResponse {
    pub snapshot: CaseSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathAndSnapshotResponse {
    pub path: String,
    pub snapshot: CaseSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExamineFileResponse {
    pub title: String,
    pub path: String,
    pub result: String,
    pub size: u64,
    pub recorded_size: u64,
    #[serde(rename = "sha256")]
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_path: Option<String>,
    #[serde(rename = "comparisonSha256", skip_serializing_if = "Option::is_none")]
    pub comparison_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_verification: Option<String>,
    pub snapshot: CaseSnapshot,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingRecordDto {
    pub seq: u64,
    pub timestamp: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_title: Option<String>,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_label: Option<String>,
    /// MCP 使用者/客户端标识（仅来源为 MCP 且已知使用者/客户端时填充）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_user: Option<String>,
    pub actor: String,
    pub result: String,
    pub details: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingGroupDto {
    pub group_key: String,
    pub seq: usize,
    pub subject: String,
    pub status: String,
    pub deleted: bool,
    pub offset: u64,
    pub inode: String,
    #[serde(rename = "imageSha256")]
    pub image_sha256: String,
    pub count: usize,
    pub latest_time: String,
    pub records: Vec<FindingRecordDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingFilterOptionsDto {
    pub statuses: Vec<String>,
    pub offsets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListFindingsResponse {
    pub status_text: String,
    pub filter_options: FindingFilterOptionsDto,
    pub groups: Vec<FindingGroupDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFindingsResponse {
    pub summary_path: String,
    pub exported_count: usize,
    pub failed_count: usize,
    pub note: String,
    pub snapshot: CaseSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineFilterOptionsDto {
    pub events: Vec<String>,
    pub statuses: Vec<String>,
    pub offsets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildTimelineResponse {
    pub total: usize,
    pub hint: String,
    pub filter_options: TimelineFilterOptionsDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineRowDto {
    pub number: usize,
    pub time: String,
    pub event: String,
    pub status: String,
    pub offset: u64,
    pub inode: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryTimelinePageResponse {
    pub total: usize,
    pub total_events: usize,
    pub page: usize,
    pub total_pages: usize,
    pub items: Vec<TimelineRowDto>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecordDto {
    pub seq: u64,
    pub timestamp: String,
    pub origin: String,
    pub origin_label: String,
    /// MCP 使用者/客户端标识（仅来源为 MCP 且已知使用者/客户端时填充）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_user: Option<String>,
    pub actor: String,
    pub action: String,
    pub action_title: String,
    pub result: String,
    pub subject: String,
    pub details: serde_json::Map<String, Value>,
    pub previous: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFilterOptionsDto {
    pub origins: Vec<String>,
    pub actors: Vec<String>,
    pub actions: Vec<String>,
    pub results: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAuditLogResponse {
    pub valid: bool,
    pub status_text: String,
    pub filter_options: AuditFilterOptionsDto,
    pub records: Vec<AuditRecordDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHitDto {
    pub hit_index: usize,
    pub entry_id: String,
    pub pos: u64,
    pub offset: u64,
    pub inode: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reallocated: Option<bool>,
    pub before_hex: String,
    pub after_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartContentSearchResponse {
    pub search_id: String,
    pub needle_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BookmarkSearchHitsResponse {
    pub saved_count: usize,
    pub snapshot: CaseSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleExportRowDto {
    pub index: usize,
    pub exists: bool,
    pub display_path: String,
    pub source: String,
    pub size: u64,
    pub time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleSearchRowDto {
    pub index: usize,
    pub exists: bool,
    pub display_path: String,
    pub query: String,
    pub encoding: String,
    pub hits: u64,
    pub time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleMaterialsResponse {
    pub exports: Vec<BundleExportRowDto>,
    pub searches: Vec<BundleSearchRowDto>,
    pub missing_text: String,
}

/// 生成离线单文件 HTML 取证报告的 IPC 响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlReportDto {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub generated_at: String,
}

/// 复核包逐成员哈希与结构核验结果 DTO。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleMemberCheckDto {
    pub path: String,
    pub category: String,
    pub status: String,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
    pub size: Option<u64>,
    pub message: String,
}

/// 复核包跨文件审计链交叉核对单项结果 DTO。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleCrossCheckDto {
    pub name: String,
    pub status: String,
    pub message: String,
}

/// 面向桌面端复核包可视化核验面板的完整核验结果 DTO。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleVerificationDetailDto {
    pub ok: bool,
    pub bundle_path: String,
    pub bundle_sha256: String,
    pub expected_sha256: Option<String>,
    pub sha256_source: String,
    pub sha256_matched: Option<bool>,
    pub audit_valid: bool,
    pub audit_count: usize,
    pub audit_head: String,
    pub audit_error: Option<String>,
    pub manifest_valid: bool,
    pub members: Vec<BundleMemberCheckDto>,
    pub cross_checks: Vec<BundleCrossCheckDto>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCatalogItem {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub category: String,
    pub read_only: bool,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpStatus {
    pub running: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub url: String,
    pub stdio_config_json: String,
    pub stdio_cli: String,
    pub http_config_json: String,
    pub http_cli: String,
    pub tools: Vec<ToolCatalogItem>,
    pub active_case_number: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuidePageDto {
    pub index: usize,
    pub title: String,
    pub nav_label: String,
    pub summary: String,
    pub image: String,
    pub caption: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentCaseDto {
    pub folder: String,
    pub name: String,
    pub number: String,
    pub examiner: String,
    pub target: String,
    pub created: String,
    pub has_evidence: bool,
    pub inventory_count: usize,
    pub exports_count: usize,
}

/* ---------- 流式事件载荷（ui-contract.md §3.6） ---------- */

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskStartedEvent {
    pub stage: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskProgressEvent {
    pub stage: String,
    pub done: u64,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskFinishedEvent {
    pub stage: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashProgressEvent {
    pub done: u64,
    pub total: u64,
    #[serde(rename = "rateMiBs")]
    pub rate_mi_bs: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashFinishedEvent {
    pub cancelled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_fixed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<CaseSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHitsEvent {
    pub search_id: String,
    pub hits: Vec<SearchHitDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchProgressEvent {
    pub search_id: String,
    pub stage: String,
    pub done: u64,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchFinishedEvent {
    pub search_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visited: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eligible: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_hits: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<CaseSnapshot>,
}

/* ==========================================================================================
 * 2. 快照与 EntryView 构建辅助函数
 * ========================================================================================== */

/// 推断图标类型，与 `forensic/ui/icons.py::entry_icon_kind` 及 `frontend/src/components/Icons.tsx` 保持一致。
pub fn infer_entry_icon_kind(entry: &InventoryEntry) -> &'static str {
    if entry.directory {
        return "folder";
    }
    if entry.mode.len() >= 2 && entry.mode.as_bytes()[..2].eq_ignore_ascii_case(b"v/") {
        return "system";
    }
    let ext = entry
        .path
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "tif" | "tiff" | "svg" | "ico" => "image",
        "csv" | "tsv" | "xls" | "xlsx" | "ods" => "table",
        _ => "file",
    }
}

/// 缓存用于解析 `fsstat` 分区偏移与文件系统类型的正则表达式，避免每次 `sync_from_case` 重复编译。
fn fsstat_regexes() -> (&'static Regex, &'static Regex) {
    static PART_RE: OnceLock<Regex> = OnceLock::new();
    static FS_RE: OnceLock<Regex> = OnceLock::new();
    let part_re = PART_RE.get_or_init(|| Regex::new(r"分区偏移 (\d+) 扇区").expect("valid part regex"));
    let fs_re = FS_RE.get_or_init(|| Regex::new(r"File System Type:\s*(\S+)").expect("valid fs regex"));
    (part_re, fs_re)
}

/// 从 `fsstat` 输出与 `coverage.volumes` 提取各分区的文件系统名称。
pub fn build_filesystem_map(
    evidence: Option<&EvidenceInfo>,
    fsstat: Option<&str>,
) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    if let Some(ev) = evidence
        && let Some(ref cov) = ev.coverage
    {
        for vol in &cov.volumes {
            if !vol.filesystem.is_empty() && vol.filesystem != "未知" {
                map.insert(vol.offset, vol.filesystem.clone());
            }
        }
    }
    if let Some(raw) = fsstat {
        let (part_re, fs_re) = fsstat_regexes();
        let mut current_offset = evidence
            .and_then(|e| e.partitions.first())
            .map(|p| p.offset)
            .unwrap_or(0);
        for line in raw.lines() {
            if let Some(caps) = part_re.captures(line)
                && let Ok(off) = caps[1].parse::<u64>()
            {
                current_offset = off;
            }
            if let Some(caps) = fs_re.captures(line) {
                map.insert(current_offset, caps[1].to_string());
            }
        }
    }
    map
}

/// 将 [`BrowserIndex::ordered`] 中索引为 `idx` 的 [`InventoryEntry`] 转换为 [`EntryView`]。
pub fn entry_to_view(
    idx: usize,
    entry: &InventoryEntry,
    fs_map: &HashMap<u64, String>,
) -> EntryView {
    let mut name = entry_name(entry);
    if name.is_empty() {
        name = "/".to_string();
    }
    let filesystem = if !entry.filesystem.is_empty() {
        entry.filesystem.clone()
    } else {
        fs_map.get(&entry.offset).cloned().unwrap_or_default()
    };
    let mtime = display_timestamp(entry.mtime, true);
    let atime = display_timestamp(entry.atime, true);
    let mut ctime = display_timestamp(entry.ctime, true);
    if entry.ctime <= 0
        && matches!(
            filesystem.to_ascii_uppercase().as_str(),
            "FAT" | "FAT12" | "FAT16" | "FAT32" | "EXFAT"
        )
    {
        ctime = format!("不支持（{filesystem}）");
    }
    let crtime = display_timestamp(entry.crtime, true);

    EntryView {
        entry_id: idx.to_string(),
        name,
        path: entry.path.clone(),
        status: entry_status(entry).to_string(),
        size: entry.size,
        inode: entry.inode.clone(),
        mtime,
        atime,
        ctime,
        crtime,
        offset: entry.offset,
        directory: entry.directory,
        deleted: entry.deleted,
        reallocated: Some(entry.reallocated),
        mode: entry.mode.clone(),
        filesystem: (!filesystem.is_empty()).then_some(filesystem),
        can_export: Some(can_export(entry)),
        icon_kind: Some(infer_entry_icon_kind(entry).to_string()),
    }
}

/// 计算 `custodyState`，与 `forensic/ui/controller.py::_custody_state` 保持一致。
pub fn compute_custody_state(case: &Case) -> &'static str {
    let data = case.data();
    let Some(ref ev) = data.evidence else {
        return "active";
    };
    if data.verification.as_ref().is_some_and(|v| !v.ok) {
        return "error";
    }
    if let Some(ref prov) = ev.provenance
        && !prov.expected_sha256.is_empty()
        && let Some(ref sha) = ev.sha256
        && !sha.is_empty()
        && !prov.expected_sha256.eq_ignore_ascii_case(sha)
    {
        return "error";
    }
    if ev.sha256.as_deref().is_none_or(str::is_empty) {
        return "warning";
    }
    if ev.is_large_image() && !case.is_session_verified() {
        return "warning";
    }
    "verified"
}

/// 轻量提取案件审计链中本地文件仍存在的历史内容搜索记录（按时间倒序排列），
/// 避免直接解析可能高达数十 MB 的 `reports/search_*.json` 命中明细文件。
fn collect_search_records(case_folder: &Path) -> Vec<SearchRecordSummaryDto> {
    let audit_path = case_folder.join("audit.jsonl");
    let Ok(raw) = std::fs::read_to_string(&audit_path) else {
        return Vec::new();
    };
    let reports_dir = case_folder.join("reports");
    let mut records = Vec::new();
    for line in raw.lines() {
        // 快速过滤非内容搜索行，减少无关 JSON 解析开销。
        if !line.contains("\"CONTENT_SEARCH\"") {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if val.get("action").and_then(Value::as_str) != Some("CONTENT_SEARCH") {
            continue;
        }
        let Some(subject) = val.get("subject").and_then(Value::as_str) else {
            continue;
        };
        let Some(clean_name) = Path::new(subject).file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if clean_name != subject || !reports_dir.join(clean_name).is_file() {
            continue;
        }
        let details = val.get("details");
        let timestamp = val
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or_default();
        records.push(SearchRecordSummaryDto {
            report_name: clean_name.to_string(),
            query: details
                .and_then(|d| d.get("query"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            encoding: details
                .and_then(|d| d.get("encoding"))
                .and_then(Value::as_str)
                .unwrap_or("UTF-8")
                .to_string(),
            hits: details
                .and_then(|d| d.get("hits"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            failed: details
                .and_then(|d| d.get("failed"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            visited: details
                .and_then(|d| d.get("visited"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            eligible: details
                .and_then(|d| d.get("eligible"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            status: val
                .get("result")
                .and_then(Value::as_str)
                .unwrap_or("完成")
                .to_string(),
            time: if timestamp.is_empty() {
                "未记录".to_string()
            } else {
                display_iso_time(timestamp, true)
            },
        });
    }
    records.reverse();
    records
}

/// 根据给定的 [`Case`] 构建完整的 [`CaseSnapshot`]。
pub fn build_case_snapshot(case: &Case) -> CaseSnapshot {
    let data = case.data();
    let custody_state = compute_custody_state(case).to_string();
    let summary_line1 = format!(
        "案件 {}  ·  取证人员 {}  ·  对象 {}",
        data.number, data.examiner, data.target
    );
    let summary_line2 = match data.evidence {
        Some(ref ev) => {
            let mut hash_status = if ev.sha256.as_deref().is_some_and(|s| !s.is_empty()) {
                "已固定 SHA-256（完整摘要见“镜像与文件系统”）".to_string()
            } else {
                "整镜像 SHA-256 待固定 · 可点击“校验完整性”".to_string()
            };
            if ev.is_large_image() && ev.sha256.as_deref().is_some_and(|s| !s.is_empty()) {
                hash_status = case.source_note().to_string();
                if data.verification.as_ref().is_some_and(|v| !v.ok) {
                    hash_status = "警告：完整性校验不匹配".to_string();
                }
            }
            let image_name = Path::new(&ev.path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| ev.path.clone());
            format!("证据 {image_name}  ·  {hash_status}")
        }
        None => "尚未加载镜像".to_string(),
    };

    let evidence_dto = data.evidence.as_ref().map(|ev| {
        let cov_text = coverage_text(ev.coverage.as_ref());
        let src_status = source_status(ev).to_string();
        let partitions = ev
            .partitions
            .iter()
            .map(|p| PartitionInfoDto {
                offset: p.offset,
                length: None,
                description: p.description.clone(),
                slot: None,
            })
            .collect();
        let segments = ev.segments.as_ref().map(|segs| {
            segs.iter()
                .map(|s| EwfSegmentInfoDto {
                    name: Some(s.name.clone()),
                    path: None,
                    size: s.size,
                    sha256: (!s.sha256.is_empty()).then(|| s.sha256.clone()),
                })
                .collect()
        });
        let coverage = ev.coverage.as_ref().map(|c| CoverageInfoDto {
            bytes: c.bytes,
            volumes: c
                .volumes
                .iter()
                .map(|v| CoverageVolumeDto {
                    offset: v.offset,
                    filesystem: v.filesystem.clone(),
                    partition_end: v.partition_end,
                    volume_end: v.volume_end,
                    missing_bytes: Some(v.missing_bytes),
                    status: v.status.clone(),
                })
                .collect(),
            text: Some(cov_text.clone()),
        });
        let provenance = ev.provenance.as_ref().map(|p| ProvenanceInfoDto {
            evidence_id: p.evidence_id.clone(),
            source: p.source.clone(),
            acquired: p.acquired.clone(),
            tool: p.tool.clone(),
            expected_sha256: p.expected_sha256.clone(),
            evidence_id_snake: p.evidence_id.clone(),
            expected_sha256_snake: p.expected_sha256.clone(),
        });
        EvidenceInfoDto {
            path: ev.path.clone(),
            size: ev.size,
            sha256: ev.sha256.clone(),
            fixed_at: ev
                .fixed_at
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| display_iso_time(s, true)),
            format: Some(ev.format_label().to_string()),
            large_image: Some(ev.is_large_image()),
            layout: Some(ev.layout.clone()),
            partitions,
            segments,
            coverage,
            coverage_text: Some(cov_text),
            provenance,
            source_status: Some(src_status),
        }
    });

    let partition_scans = data
        .partition_scans
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|s| PartitionScanDto {
            offset: s.offset,
            status: s.status.clone(),
            count: Some(s.count),
            error: s.error.clone(),
        })
        .collect();

    let verification = data.verification.as_ref().map(|v| {
        let formatted_time = display_iso_time(&v.time, true);
        VerificationInfoDto {
            ok: v.ok,
            time: Some(formatted_time.clone()),
            checked_at: Some(formatted_time),
            actual: v.actual.clone(),
            method: Some(v.method.clone()),
            note: None,
        }
    });

    let quick_location = if data
        .evidence
        .as_ref()
        .is_some_and(EvidenceInfo::is_large_image)
    {
        case.directory_location().map(|loc| QuickLocationDto {
            offset: loc.offset,
            inode: loc.inode.clone(),
            path: loc.path.clone(),
        })
    } else {
        None
    };

    let browsing_directories = case.browsing_directories();
    let inventory_count = if browsing_directories {
        case.displayed_entries().len()
    } else {
        data.inventory.len()
    };

    CaseSnapshot {
        case_dir: case.folder().to_string_lossy().into_owned(),
        id: data.id.clone(),
        number: data.number.clone(),
        examiner: data.examiner.clone(),
        target: data.target.clone(),
        created: display_iso_time(&data.created, true),
        custody_state,
        summary_line1,
        summary_line2,
        source_note: case.source_note().to_string(),
        browsing_directories,
        needs_partition_scan: case.needs_partition_scan(),
        inventory_count,
        exports_count: data.exports.len(),
        evidence: evidence_dto,
        partition_scans,
        verification,
        fsstat: data.fsstat.clone().unwrap_or_default(),
        quick_location,
        search_records: collect_search_records(case.folder()),
    }
}

/* ==========================================================================================
 * 3. 搜索会话与缓存视图状态
 * ========================================================================================== */

#[derive(Debug, Clone)]
pub struct StoredSearchHit {
    pub dto: SearchHitDto,
    pub entry: InventoryEntry,
    pub source_note: String,
}

#[derive(Debug, Clone)]
pub struct SearchSessionState {
    pub search_id: String,
    /// 创建该搜索会话时绑定的案件目录，防止切换案件后误将旧案命中写入新案审计链。
    pub case_folder: PathBuf,
    pub query: String,
    pub encoding: String,
    pub needle_hex: String,
    pub image_sha256: Option<String>,
    pub verification: String,
    pub report_name: Option<String>,
    pub cancel: Arc<AtomicBool>,
    pub running: bool,
    pub hits: Vec<StoredSearchHit>,
}

/// 大镜像按需浏览时，左侧文件树保留的已读取目录分支缓存上限（防止多分区展开后无限占用内存）。
const QUICK_TREE_BRANCH_CACHE_LIMIT: usize = 128;

/// 用于 O(1) 判断当前展示清单是否实质变化的轻量指纹（条数 + 首尾条目定位键）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct EntriesSignature {
    len: usize,
    first: Option<(u64, String, String, bool)>,
    last: Option<(u64, String, String, bool)>,
}

impl EntriesSignature {
    fn from_slice(entries: &[InventoryEntry]) -> Self {
        let first = entries
            .first()
            .map(|e| (e.offset, e.path.clone(), e.inode.clone(), e.deleted));
        let last = entries
            .last()
            .map(|e| (e.offset, e.path.clone(), e.inode.clone(), e.deleted));
        Self {
            len: entries.len(),
            first,
            last,
        }
    }
}

/// 面向读多写少场景的快速视图缓存，确保目录树、分页、预览与时间线读取不会被耗时任务阻塞。
#[derive(Default)]
pub struct ViewCache {
    pub snapshot: Option<CaseSnapshot>,
    pub case_folder: Option<PathBuf>,
    pub image_path: Option<PathBuf>,
    pub is_large_image: bool,
    pub fs_map: HashMap<u64, String>,
    pub browser_index: BrowserIndex,
    /// 已构建 `browser_index` 对应的展示清单签名，避免仅追加审计日志时无效重建 10 万条目录树与时间线。
    entries_sig: EntriesSignature,
    /// 大镜像按需模式下按 `(分区偏移, 归一化目录路径)` 保留的目录树分支索引，
    /// 避免展开另一分区/目录时丢失已展开的树节点，并支持超过 2048 项时的 256 项分桶展开。
    pub quick_tree_branches: HashMap<(u64, String), BrowserIndex>,
    /// 维护 `quick_tree_branches` 的 LRU 访问顺序，满容量时优先淘汰最久未访问分支。
    quick_tree_order: VecDeque<(u64, String)>,
    pub timeline_index: Option<TimelineIndex>,
}

impl ViewCache {
    /// 从当前活跃的 [`Case`] 同步 [`ViewCache`]。
    pub fn sync_from_case(&mut self, case: &Case, rebuild_browser_index: bool) {
        let prev_folder = self.case_folder.clone();
        let prev_image = self.image_path.clone();
        let prev_count = self.snapshot.as_ref().map(|s| s.inventory_count);
        let prev_quick = self.snapshot.as_ref().and_then(|s| s.quick_location.clone());
        let prev_browsing = self.snapshot.as_ref().map(|s| s.browsing_directories);
        let prev_scans = self.snapshot.as_ref().map(|s| s.partition_scans.clone());

        let snap = build_case_snapshot(case);
        let folder = case.folder().to_path_buf();
        let image_path = case.image_path().ok();
        let is_large = case
            .data()
            .evidence
            .as_ref()
            .is_some_and(EvidenceInfo::is_large_image);
        let fs_map = build_filesystem_map(
            case.data().evidence.as_ref(),
            case.data().fsstat.as_deref(),
        );

        let displayed = case.displayed_entries();
        let next_sig = EntriesSignature::from_slice(displayed);

        let folder_changed = prev_folder.as_ref() != Some(&folder);
        let image_changed = prev_image != image_path;
        let entries_changed = prev_count != Some(snap.inventory_count)
            || prev_quick != snap.quick_location
            || prev_browsing != Some(snap.browsing_directories)
            || prev_scans.as_ref() != Some(&snap.partition_scans)
            || self.entries_sig != next_sig
            || rebuild_browser_index;

        if folder_changed || image_changed || entries_changed {
            self.browser_index = BrowserIndex::build(displayed);
            self.entries_sig = next_sig;
            self.timeline_index = None;
        }

        // 切换案件、更换镜像或已完成全盘索引切换至全量模式时，清空按需目录树分支缓存；
        // 在同一大镜像按需浏览会话内切目录时则保留已展开分支，避免跨分区展开互相冲刷。
        if folder_changed || image_changed || !snap.browsing_directories {
            self.quick_tree_branches.clear();
            self.quick_tree_order.clear();
        }

        self.snapshot = Some(snap);
        self.case_folder = Some(folder);
        self.image_path = image_path;
        self.is_large_image = is_large;
        self.fs_map = fs_map;
    }

    /// 缓存大镜像按需模式下单个目录的 [`BrowserIndex`]，供树节点重复展开及分桶读取复用。
    pub fn cache_quick_tree_branch(
        &mut self,
        offset: u64,
        scope_path: &str,
        entries: &[InventoryEntry],
    ) {
        self.cache_quick_tree_branch_index(offset, scope_path, BrowserIndex::build(entries));
    }

    /// 直接接管已构建好的 [`BrowserIndex`] 存入按需目录树分支缓存（按 LRU 淘汰），避免重复建树。
    pub fn cache_quick_tree_branch_index(
        &mut self,
        offset: u64,
        scope_path: &str,
        index: BrowserIndex,
    ) {
        let key = (
            offset,
            tracedesk_core::browser_index::normalize_scope_path(scope_path),
        );
        if self.quick_tree_branches.contains_key(&key) {
            self.quick_tree_order.retain(|k| k != &key);
        } else {
            while self.quick_tree_branches.len() >= QUICK_TREE_BRANCH_CACHE_LIMIT {
                let Some(evict_key) = self.quick_tree_order.pop_front() else {
                    break;
                };
                self.quick_tree_branches.remove(&evict_key);
            }
        }
        self.quick_tree_order.push_back(key.clone());
        self.quick_tree_branches.insert(key, index);
    }

    /// 在已缓存的按需目录树分支或当前 `browser_index` 中反查目标目录的 `inode`。
    pub fn find_directory_inode(&self, offset: u64, scope_path: &str) -> Option<String> {
        let norm = tracedesk_core::browser_index::normalize_scope_path(scope_path);
        if norm.is_empty() {
            return None;
        }
        let parent = tracedesk_core::browser_index::parent_dir(&norm).to_string();
        if let Some(parent_idx) = self.quick_tree_branches.get(&(offset, parent)) {
            for item in parent_idx.ordered() {
                if item.offset == offset
                    && item.directory
                    && tracedesk_core::browser_index::normalize_scope_path(&item.path) == norm
                    && !item.inode.is_empty()
                {
                    return Some(item.inode.clone());
                }
            }
        }
        for item in self.browser_index.ordered() {
            if item.offset == offset
                && item.directory
                && tracedesk_core::browser_index::normalize_scope_path(&item.path) == norm
                && !item.inode.is_empty()
            {
                return Some(item.inode.clone());
            }
        }
        None
    }

    pub fn clear(&mut self) {
        self.snapshot = None;
        self.case_folder = None;
        self.image_path = None;
        self.is_large_image = false;
        self.fs_map.clear();
        self.browser_index = BrowserIndex::default();
        self.entries_sig = EntriesSignature::default();
        self.quick_tree_branches.clear();
        self.quick_tree_order.clear();
        self.timeline_index = None;
    }

    /// 根据 `entryId` 字符串解析对应的 [`InventoryEntry`] 及其在 `BrowserIndex` 中的 0 起始索引。
    /// 支持 `"0"`（0 起始规范索引）、`"offset:inode:deleted"`、`"offset:inode:deleted:path"`
    /// 以及 `"offset:inode:path"` / `"offset:inode::path"`（跨模块定位时忽略删除标志或路径斜杠差异）。
    pub fn resolve_entry(&self, entry_id: &str) -> Option<(usize, InventoryEntry)> {
        let trimmed = entry_id.trim();
        if let Ok(idx) = trimmed.parse::<usize>()
            && let Some(entry) = self.browser_index.get(idx)
        {
            return Some((idx, entry.clone()));
        }
        let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
        if parts.len() >= 3
            && let Ok(offset) = parts[0].parse::<u64>()
        {
            let inode = parts[1].trim();
            let (deleted_opt, path_opt) = if parts.len() == 4 {
                let deleted_opt = match parts[2].trim().to_ascii_lowercase().as_str() {
                    "1" | "true" => Some(true),
                    "0" | "false" => Some(false),
                    "" | "*" | "any" => None,
                    _ => Some(false),
                };
                (deleted_opt, Some(parts[3]))
            } else {
                match parts[2].trim().to_ascii_lowercase().as_str() {
                    "1" | "true" => (Some(true), None),
                    "0" | "false" => (Some(false), None),
                    "" | "*" | "any" => (None, None),
                    _ => (None, Some(parts[2])),
                }
            };

            let ordered = self.browser_index.ordered();

            // 1. 优先精确匹配 `(offset, inode, deleted, path)`。
            for (idx, row) in ordered.iter().enumerate() {
                if row.offset == offset
                    && (inode.is_empty() || row.inode == inode)
                    && deleted_opt.is_none_or(|d| row.deleted == d)
                    && path_opt.is_none_or(|p| row.path == p)
                {
                    return Some((idx, row.clone()));
                }
            }

            // 2. 若精确匹配未命中且携带路径，则对路径做斜杠归一化回退匹配（兼容时间线/发现等跨模块跳转）。
            if let Some(raw_path) = path_opt {
                let norm_target = tracedesk_core::browser_index::normalize_scope_path(raw_path);
                if !norm_target.is_empty() {
                    let mut best: Option<(u8, usize)> = None;
                    for (idx, row) in ordered.iter().enumerate() {
                        if row.offset != offset {
                            continue;
                        }
                        if tracedesk_core::browser_index::normalize_scope_path(&row.path)
                            != norm_target
                        {
                            continue;
                        }
                        let mut score = 1u8;
                        if !inode.is_empty() && row.inode == inode {
                            score += 4;
                        }
                        if deleted_opt.is_some_and(|d| row.deleted == d) {
                            score += 2;
                        }
                        if best.is_none_or(|(best_score, _)| score > best_score) {
                            best = Some((score, idx));
                        }
                    }
                    if let Some((_, idx)) = best
                        && let Some(row) = ordered.get(idx)
                    {
                        return Some((idx, row.clone()));
                    }
                }
            }
        }
        None
    }
}

/* ==========================================================================================
 * 4. 线程安全的应用状态（AppState）
 * ========================================================================================== */

/// 非阻塞磁盘热重载结果：用于区分“成功同步/无需更新”与“因 `case_lock` 被占用而延迟”。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonblockingReloadOutcome {
    Reloaded,
    Unchanged,
    WouldBlock,
}

pub struct AppState {
    pub app_paths: AppPaths,
    pub case_lock: Mutex<Option<Case>>,
    pub view: RwLock<ViewCache>,
    /// 当跨进程写入到达但 `case_lock` 暂时繁忙导致非阻塞热重载跳过时置为 `true`，
    /// 以便后续释放锁或拉取快照时主动从磁盘补做热重载，杜绝前端“假刷新”。
    pub disk_dirty: AtomicBool,
    /// 因 `WouldBlock` 延迟发送的 `mcp:case-updated` 通知载荷，待热重载完成后再补发。
    pub pending_case_updated: Mutex<Option<Value>>,
    pub scan_cancel: Arc<AtomicBool>,
    pub hash_cancel: Arc<AtomicBool>,
    pub task_cancel: Arc<AtomicBool>,
    pub scanning_active: Arc<AtomicBool>,
    pub hashing_active: Arc<AtomicBool>,
    pub hash_worker: Mutex<Option<JoinHandle<()>>>,
    /// 后台内容搜索工作线程句柄列表（退出时统一回收，避免遗留孤儿线程）。
    pub search_workers: Mutex<Vec<JoinHandle<()>>>,
    pub searches: Mutex<HashMap<String, SearchSessionState>>,
    pub mcp_server: Mutex<LocalMcpHttpServer>,
    /// MCP 实时活动内存环形队列（按 `callId` 合并，上限 500 条）。
    pub mcp_activities: Mutex<McpActivityStore>,
    /// 跨进程 `logs/mcp-activity.jsonl` 增量字节偏移尾随读取器。
    pub mcp_tailer: Mutex<ActivityLogTailer>,
    /// 后台遥测日志尾随线程退出信号。
    pub mcp_tailer_cancel: Arc<AtomicBool>,
    /// 后台遥测日志尾随线程句柄。
    pub mcp_tailer_worker: Mutex<Option<JoinHandle<()>>>,
    /// Tauri 应用句柄，用于向前端实时推送 `mcp:activity` 与 `mcp:case-updated` 事件。
    pub app_handle: Mutex<Option<AppHandle>>,
}

impl AppState {
    pub fn new() -> Arc<Self> {
        Self::with_paths(AppPaths::discover())
    }

    pub fn with_paths(app_paths: AppPaths) -> Arc<Self> {
        let _ = std::fs::create_dir_all(&app_paths.cases_dir);
        let log_path = app_paths.logs_dir.join(ACTIVITY_LOG_FILENAME);
        let mut activity_store = McpActivityStore::new(DEFAULT_ACTIVITY_STORE_CAPACITY);
        let initial_offset = activity_store.load_from_file(&log_path);
        let tailer = ActivityLogTailer::new(log_path, initial_offset);

        Arc::new(Self {
            app_paths,
            case_lock: Mutex::new(None),
            view: RwLock::new(ViewCache::default()),
            disk_dirty: AtomicBool::new(false),
            pending_case_updated: Mutex::new(None),
            scan_cancel: Arc::new(AtomicBool::new(false)),
            hash_cancel: Arc::new(AtomicBool::new(false)),
            task_cancel: Arc::new(AtomicBool::new(false)),
            scanning_active: Arc::new(AtomicBool::new(false)),
            hashing_active: Arc::new(AtomicBool::new(false)),
            hash_worker: Mutex::new(None),
            search_workers: Mutex::new(Vec::new()),
            searches: Mutex::new(HashMap::new()),
            mcp_server: Mutex::new(LocalMcpHttpServer::new()),
            mcp_activities: Mutex::new(activity_store),
            mcp_tailer: Mutex::new(tailer),
            mcp_tailer_cancel: Arc::new(AtomicBool::new(false)),
            mcp_tailer_worker: Mutex::new(None),
            app_handle: Mutex::new(None),
        })
    }

    /// 清理所有已缓存的搜索会话（在新建/打开/关闭案件时调用，释放命中内存并防止跨案误存书签）。
    pub fn clear_search_sessions(&self) {
        if let Ok(mut searches) = self.searches.lock() {
            for session in searches.values_mut() {
                session.cancel.store(true, Ordering::Relaxed);
                session.running = false;
            }
            searches.clear();
        }
        if let Ok(mut workers) = self.search_workers.lock() {
            workers.retain(|h| !h.is_finished());
        }
    }

    /// 记录新的内容搜索工作线程句柄并顺带清理已完成线程，防止列表增长。
    pub fn track_search_worker(&self, handle: JoinHandle<()>) {
        if let Ok(mut workers) = self.search_workers.lock() {
            workers.retain(|h| !h.is_finished());
            workers.push(handle);
        }
    }

    /// 返回当前应用对应的 MCP 遥测日志路径（`<logs_dir>/mcp-activity.jsonl`）。
    pub fn activity_log_path(&self) -> PathBuf {
        self.app_paths.logs_dir.join(ACTIVITY_LOG_FILENAME)
    }

    /// 注册 Tauri `AppHandle`（在应用 `setup` 阶段调用），开启前端实时事件推送。
    pub fn set_app_handle(&self, handle: AppHandle) {
        if let Ok(mut guard) = self.app_handle.lock() {
            *guard = Some(handle);
        }
    }

    fn current_app_handle(&self) -> Option<AppHandle> {
        self.app_handle.lock().ok().and_then(|g| g.clone())
    }

    /// 记录由桌面内嵌 `desktop-http` 产生的 MCP 活动：
    /// 写入内存环形队列 + 落盘 `mcp-activity.jsonl` + 零延迟推送 `mcp:activity` 事件。
    /// 若 `emit_case_updated_now` 为 `true`，同步检查并推送 `mcp:case-updated`。
    pub fn record_desktop_mcp_activity(
        &self,
        mut record: McpActivityRecord,
        emit_case_updated_now: bool,
    ) -> bool {
        record.client = normalize_activity_client(&record.client);
        let accepted = self
            .mcp_activities
            .lock()
            .ok()
            .is_some_and(|mut store| store.ingest(record.clone()));

        // 无论是否重复，均由本进程直写落盘，读写失败绝不阻断 MCP 正常执行。
        let _ = append_activity_record(&self.activity_log_path(), &record);

        if accepted {
            if let Some(app) = self.current_app_handle() {
                let _ = app.emit("mcp:activity", &record);
            }
            if emit_case_updated_now {
                let _ = self.emit_case_updated_if_matching(&record);
            }
        }
        accepted
    }

    /// 清除磁盘脏标记与延迟热刷新通知（用于新建/打开/关闭案件时重置状态）。
    pub fn clear_disk_dirty(&self) {
        self.disk_dirty.store(false, Ordering::SeqCst);
        if let Ok(mut pending) = self.pending_case_updated.lock() {
            *pending = None;
        }
    }

    /// 在调用方已持有 `case_lock` 的前提下检测磁盘变化并按需热重载内存 `Case` 与 `ViewCache`。
    /// 仅当清单或镜像等视图相关字段实质变化时才重建 `BrowserIndex` 并重置时间线索引，
    /// 避免仅追加审计日志时无效重建 10 万条目录树与 40 万条时间线。
    pub fn reload_case_and_sync_view(&self, case: &mut Case) -> Result<bool, String> {
        let changed = case
            .sync_from_disk_if_changed()
            .map_err(|e| e.to_string())?;
        if changed {
            let mut view = self
                .view
                .write()
                .map_err(|_| "视图缓存锁异常".to_string())?;
            view.sync_from_case(case, false);
        }
        // 已成功与磁盘最新指纹对齐，清除跨进程热刷新脏标记。
        self.disk_dirty.store(false, Ordering::SeqCst);
        Ok(changed)
    }

    /// 检测当前桌面端打开案件的磁盘文件（`case.json` 与 `audit.head`/`audit.jsonl`）是否已被外部进程更新；
    /// 若发生变化则热重载内存 `Case` 数据与清单，并同步刷新 `ViewCache`，返回 `Ok(true)`。
    pub fn reload_active_case_from_disk(&self) -> Result<bool, String> {
        let mut case_guard = self
            .case_lock
            .lock()
            .map_err(|_| "案件状态锁异常".to_string())?;
        let Some(case) = case_guard.as_mut() else {
            self.clear_disk_dirty();
            return Ok(false);
        };
        let changed = self.reload_case_and_sync_view(case)?;
        drop(case_guard);
        self.emit_pending_case_updated_if_any();
        Ok(changed)
    }

    /// 非阻塞版磁盘热重载（返回详细状态）：若 `case_lock` 正被占用则置 `disk_dirty = true` 并返回 `WouldBlock`，
    /// 确保快照读取与后台 MCP 遥测尾随线程不会被阻塞，同时避免丢弃跨进程变更。
    pub fn reload_active_case_from_disk_nonblocking_outcome(
        &self,
    ) -> Result<NonblockingReloadOutcome, String> {
        let mut case_guard = match self.case_lock.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::WouldBlock) => {
                self.disk_dirty.store(true, Ordering::SeqCst);
                return Ok(NonblockingReloadOutcome::WouldBlock);
            }
            Err(std::sync::TryLockError::Poisoned(_)) => return Err("案件状态锁异常".to_string()),
        };
        let Some(case) = case_guard.as_mut() else {
            self.clear_disk_dirty();
            return Ok(NonblockingReloadOutcome::Unchanged);
        };
        let changed = self.reload_case_and_sync_view(case)?;
        Ok(if changed {
            NonblockingReloadOutcome::Reloaded
        } else {
            NonblockingReloadOutcome::Unchanged
        })
    }

    /// 非阻塞版磁盘热重载：若 `case_lock` 正被占用则置脏并立即返回 `Ok(false)`。
    pub fn reload_active_case_from_disk_nonblocking(&self) -> Result<bool, String> {
        match self.reload_active_case_from_disk_nonblocking_outcome()? {
            NonblockingReloadOutcome::Reloaded => {
                self.emit_pending_case_updated_if_any();
                Ok(true)
            }
            NonblockingReloadOutcome::Unchanged => {
                self.emit_pending_case_updated_if_any();
                Ok(false)
            }
            NonblockingReloadOutcome::WouldBlock => Ok(false),
        }
    }

    /// 补发先前因 `WouldBlock` 暂存的 `mcp:case-updated` 通知（此时 `ViewCache` 已对齐最新磁盘状态）。
    fn emit_pending_case_updated_if_any(&self) {
        let payload = self
            .pending_case_updated
            .lock()
            .ok()
            .and_then(|mut g| g.take());
        if let Some(body) = payload
            && let Some(app) = self.current_app_handle()
        {
            let _ = app.emit("mcp:case-updated", body);
        }
    }

    /// 若存在因锁竞争延迟的跨进程热刷新脏标记，则在锁空闲时主动补做磁盘重载并补发通知。
    pub fn flush_disk_dirty_if_ready(&self) -> Result<bool, String> {
        let has_pending = self
            .pending_case_updated
            .lock()
            .ok()
            .is_some_and(|g| g.is_some());
        if !self.disk_dirty.load(Ordering::Acquire) && !has_pending {
            return Ok(false);
        }
        match self.reload_active_case_from_disk_nonblocking_outcome()? {
            NonblockingReloadOutcome::Reloaded => {
                self.emit_pending_case_updated_if_any();
                Ok(true)
            }
            NonblockingReloadOutcome::Unchanged => {
                self.emit_pending_case_updated_if_any();
                Ok(false)
            }
            NonblockingReloadOutcome::WouldBlock => Ok(false),
        }
    }

    /// 当非只读写入工具成功完成且作用于当前打开案件时，先热重载磁盘变更并刷新 `ViewCache`，
    /// 再向前端推送 `mcp:case-updated` 事件；若此时 `case_lock` 正被占用遇到 `WouldBlock`，
    /// 则置 `disk_dirty = true` 并暂存通知，待锁释放后真正完成热重载再推送，杜绝前端“假刷新”。
    pub fn emit_case_updated_if_matching(&self, record: &McpActivityRecord) -> bool {
        if record.phase != "completed" || record.read_only {
            return false;
        }
        let Some(raw_case_dir) = record
            .case_dir
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return false;
        };

        let matched_open_case_dir = self.view.read().ok().and_then(|view| {
            let open_folder = view.case_folder.as_ref()?;
            let mut resolved_rec = resolve_clean(Path::new(raw_case_dir));
            // 兼容遥测记录中携带 `.../case.json` 的路径形式。
            if resolved_rec
                .file_name()
                .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("case.json"))
                && let Some(parent) = resolved_rec.parent()
            {
                resolved_rec = parent.to_path_buf();
            }
            let resolved_open = resolve_clean(open_folder);
            if same_case_path(&resolved_rec, &resolved_open) {
                let display_dir = view
                    .snapshot
                    .as_ref()
                    .map(|s| s.case_dir.clone())
                    .unwrap_or_else(|| resolved_open.to_string_lossy().into_owned());
                Some(display_dir)
            } else {
                None
            }
        });

        let Some(case_dir_str) = matched_open_case_dir else {
            return false;
        };

        let tool_name = record
            .tool_name
            .as_deref()
            .unwrap_or(record.method.as_str());
        let payload = json!({
            "caseDir": case_dir_str,
            "toolName": tool_name,
            "client": record.client,
            "timestamp": record.timestamp,
        });

        // 推送前端前先非阻塞热重载最新磁盘状态与 ViewCache；若遇到 WouldBlock 则置脏并暂存通知，
        // 杜绝在 ViewCache 仍是旧快照时就通知前端“已自动刷新”。
        match self.reload_active_case_from_disk_nonblocking_outcome() {
            Ok(NonblockingReloadOutcome::WouldBlock) => {
                if let Ok(mut pending) = self.pending_case_updated.lock() {
                    *pending = Some(payload);
                }
                return false;
            }
            Ok(NonblockingReloadOutcome::Reloaded | NonblockingReloadOutcome::Unchanged) => {
                if let Ok(mut pending) = self.pending_case_updated.lock() {
                    *pending = None;
                }
            }
            Err(_) => {
                self.disk_dirty.store(true, Ordering::SeqCst);
                if let Ok(mut pending) = self.pending_case_updated.lock() {
                    *pending = Some(payload);
                }
                return false;
            }
        }

        if let Some(app) = self.current_app_handle() {
            let _ = app.emit("mcp:case-updated", payload);
        }
        true
    }

    /// 轮询一次 `logs/mcp-activity.jsonl` 的字节增量，将外部 `stdio` / `streamable-http`
    /// 进程写入的新事件吸收进内存队列并实时推送给前端；若存在因锁冲突延迟的热刷新脏标记也会在此自动补刷。
    pub fn poll_activity_log_once(&self) -> usize {
        let new_records = match self.mcp_tailer.lock() {
            Ok(mut tailer) => tailer.poll_new_records(),
            Err(_) => return 0,
        };
        if new_records.is_empty() {
            let _ = self.flush_disk_dirty_if_ready();
            return 0;
        }
        let app_opt = self.current_app_handle();
        let mut ingested = 0usize;
        for rec in new_records {
            let accepted = self
                .mcp_activities
                .lock()
                .ok()
                .is_some_and(|mut store| store.ingest(rec.clone()));
            if !accepted {
                continue;
            }
            ingested += 1;
            if let Some(ref app) = app_opt {
                let _ = app.emit("mcp:activity", &rec);
            }
            let _ = self.emit_case_updated_if_matching(&rec);
        }
        let _ = self.flush_disk_dirty_if_ready();
        ingested
    }

    /// 启动极轻量的后台尾随线程（每 350ms 检查一次 `logs/mcp-activity.jsonl` 字节偏移增量），
    /// 幂等防重入，并在 [`AppState::shutdown_all`] 时优雅退出。
    pub fn start_activity_tailer(self: &Arc<Self>) {
        let Ok(mut worker_guard) = self.mcp_tailer_worker.lock() else {
            return;
        };
        if worker_guard.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        self.mcp_tailer_cancel.store(false, Ordering::SeqCst);
        let cancel = Arc::clone(&self.mcp_tailer_cancel);
        let st = Arc::clone(self);
        if let Ok(handle) = thread::Builder::new()
            .name("tracedesk-mcp-tailer".to_string())
            .spawn(move || {
                while !cancel.load(Ordering::Relaxed) {
                    st.poll_activity_log_once();
                    // 将 350ms 拆分为 7 段 50ms 休眠，保证关闭应用时毫秒级响应退出信号。
                    for _ in 0..7 {
                        if cancel.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            })
        {
            *worker_guard = Some(handle);
        }
    }

    /// 查询合并后的 MCP 实时活动快照（先同步最新增量日志再应用筛选与统计）。
    pub fn list_mcp_activities(
        &self,
        limit: Option<usize>,
        client: Option<&str>,
        status: Option<&str>,
        transport: Option<&str>,
        keyword: Option<&str>,
    ) -> McpActivitySnapshot {
        self.poll_activity_log_once();
        self.mcp_activities
            .lock()
            .map(|store| store.snapshot(limit, client, status, transport, keyword))
            .unwrap_or_default()
    }

    /// 清空内存活动队列并截断 `logs/mcp-activity.jsonl`，同时重置尾随偏移。
    /// 按统一锁序（`mcp_tailer` -> `mcp_activities`）原子完成清空与偏移重置，防止与后台尾随线程竞态。
    pub fn clear_mcp_activities(&self) {
        let mut tailer_guard = self.mcp_tailer.lock().ok();
        let mut store_guard = self.mcp_activities.lock().ok();
        if let Some(ref mut store) = store_guard {
            store.clear();
        }
        let _ = truncate_activity_log(&self.activity_log_path());
        if let Some(ref mut tailer) = tailer_guard {
            tailer.reset();
        }
    }

    /// 检查是否存在正在运行的后台任务（分区扫描、大镜像哈希校验或内容搜索）。
    pub fn check_busy(&self) -> BusyCheckResponse {
        if self.scanning_active.load(Ordering::Relaxed) {
            return BusyCheckResponse {
                busy: true,
                reason: Some("正在建立完整文件索引，请先取消或等待完成后再继续。".to_string()),
            };
        }
        if self.hashing_active.load(Ordering::Relaxed) {
            return BusyCheckResponse {
                busy: true,
                reason: Some("正在后台执行整镜像完整性校验，请先取消或等待完成后再继续。".to_string()),
            };
        }
        if let Ok(searches) = self.searches.lock()
            && searches.values().any(|s| s.running)
        {
            return BusyCheckResponse {
                busy: true,
                reason: Some("存在正在运行的内容搜索任务，请先取消或等待完成后再继续。".to_string()),
            };
        }
        BusyCheckResponse {
            busy: false,
            reason: None,
        }
    }

    /// 取消全部活跃后台操作（分区扫描、哈希校验、内容搜索、MCP 遥测尾随线程）并停止内嵌 HTTP MCP 服务。
    pub fn shutdown_all(&self) {
        self.scan_cancel.store(true, Ordering::Relaxed);
        self.hash_cancel.store(true, Ordering::Relaxed);
        self.task_cancel.store(true, Ordering::Relaxed);
        self.mcp_tailer_cancel.store(true, Ordering::SeqCst);

        if let Ok(mut searches) = self.searches.lock() {
            for session in searches.values_mut() {
                session.cancel.store(true, Ordering::Relaxed);
                session.running = false;
            }
            searches.clear();
        }
        if let Ok(mut workers) = self.search_workers.lock() {
            for handle in workers.drain(..) {
                let _ = handle.join();
            }
        }
        if let Ok(mut worker) = self.hash_worker.lock()
            && let Some(handle) = worker.take()
        {
            let _ = handle.join();
        }
        if let Ok(mut tailer_worker) = self.mcp_tailer_worker.lock()
            && let Some(handle) = tailer_worker.take()
        {
            let _ = handle.join();
        }
        if let Ok(mut mcp) = self.mcp_server.lock() {
            mcp.stop();
        }
        if let Ok(mut case_guard) = self.case_lock.lock()
            && let Some(mut c) = case_guard.take()
        {
            c.close();
        }
        if let Ok(mut view) = self.view.write() {
            view.clear();
        }
    }

    /// 协调委托给 `tracedesk_mcp::McpServer` 的调用与桌面端当前打开的 [`Case`]。
    ///
    /// 桌面端打开案件期间不常驻持有 `case.lock`（仅在写入瞬间加短锁），因此可直接执行 `work()`
    /// 由 `tracedesk_mcp::CaseService` 按短锁超时自动排队访问；若本次调用作用于桌面端当前打开案件，
    /// 执行完成后立即热重载磁盘变更并同步刷新 [`ViewCache`]。
    pub fn coordinate_mcp_call<T, F>(&self, target_folders: &[PathBuf], work: F) -> T
    where
        F: FnOnce() -> T,
    {
        let result = work();
        if target_folders.is_empty() {
            return result;
        }

        let resolved_targets: Vec<PathBuf> = target_folders
            .iter()
            .map(|p| tracedesk_core::resolve_clean(p))
            .collect();

        let matches_active = self.view.read().ok().is_some_and(|view| {
            view.case_folder.as_ref().is_some_and(|open_dir| {
                let resolved_open = tracedesk_core::resolve_clean(open_dir);
                resolved_targets
                    .iter()
                    .any(|t| same_case_path(t, &resolved_open))
            })
        });

        if matches_active {
            let _ = self.reload_active_case_from_disk();
        }
        result
    }

    /// 按可选的指定端口构建 [`McpStatus`]。
    pub fn build_mcp_status(&self, requested_port: Option<u16>) -> McpStatus {
        let (running, host, active_port, path) = match self.mcp_server.lock() {
            Ok(srv) => {
                let p = if srv.is_running() {
                    srv.port()
                } else {
                    requested_port.unwrap_or(srv.port())
                };
                (
                    srv.is_running(),
                    srv.host().to_string(),
                    p,
                    srv.path().to_string(),
                )
            }
            Err(_) => (
                false,
                "127.0.0.1".to_string(),
                requested_port.unwrap_or(8765),
                "/mcp".to_string(),
            ),
        };

        let url_host = if host == "::1" { "[::1]" } else { &host };
        let url = format!("http://{url_host}:{active_port}{path}");
        let mcp_bin = discover_mcp_binary(&self.app_paths);
        let cases_dir = self.app_paths.cases_dir.to_string_lossy().into_owned();

        let stdio_config = serde_json::json!({
            "mcpServers": {
                "tracedesk": {
                    "command": mcp_bin,
                    "args": [
                        "--transport",
                        "stdio",
                        "--cases-dir",
                        cases_dir
                    ]
                }
            }
        });
        let stdio_config_json =
            serde_json::to_string_pretty(&stdio_config).unwrap_or_default();
        let stdio_cli = format!(
            "& \"{mcp_bin}\" --transport stdio --cases-dir \"{cases_dir}\""
        );

        let http_config = serde_json::json!({
            "mcpServers": {
                "tracedesk": {
                    "url": url
                }
            }
        });
        let http_config_json = serde_json::to_string_pretty(&http_config).unwrap_or_default();
        let http_cli = format!(
            "& \"{mcp_bin}\" --transport streamable-http --host {host} --port {active_port} --path {path} --cases-dir \"{cases_dir}\""
        );

        let active_case_number = self
            .view
            .read()
            .ok()
            .and_then(|v| v.snapshot.as_ref().map(|s| s.number.clone()));

        McpStatus {
            running,
            host,
            port: active_port,
            path,
            url,
            stdio_config_json,
            stdio_cli,
            http_config_json,
            http_cli,
            tools: default_tool_catalog(),
            active_case_number,
        }
    }
}

fn discover_mcp_binary(app_paths: &AppPaths) -> String {
    let exe_name = if cfg!(windows) {
        "tracedesk-mcp.exe"
    } else {
        "tracedesk-mcp"
    };
    if let Ok(cur_exe) = std::env::current_exe()
        && let Some(dir) = cur_exe.parent()
    {
        let sibling = dir.join(exe_name);
        if sibling.is_file() {
            return tracedesk_core::strip_verbatim_prefix(&sibling)
                .to_string_lossy()
                .into_owned();
        }
    }
    for sub in ["target/release", "target/debug"] {
        let candidate = app_paths.root.join(sub).join(exe_name);
        if candidate.is_file() {
            return tracedesk_core::strip_verbatim_prefix(&candidate)
                .to_string_lossy()
                .into_owned();
        }
    }
    tracedesk_core::strip_verbatim_prefix(&app_paths.root.join("target/release").join(exe_name))
        .to_string_lossy()
        .into_owned()
}

pub fn build_deleted_source_note(entry: &InventoryEntry) -> String {
    deleted_source_note(entry).to_string()
}

fn same_case_path(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}
