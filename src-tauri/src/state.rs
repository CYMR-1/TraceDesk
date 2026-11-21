//! Thread-safe desktop application state, IPC data transfer objects (100% aligned with
//! `ui-contract.md` §3 and `frontend/src/types/ipc.ts`), and background task / search / MCP
//! coordination.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracedesk_core::{
    AppPaths, AuditOrigin, BrowserIndex, Case, EvidenceInfo, TimelineIndex, can_export,
    coverage_text, deleted_source_note, display_iso_time, display_timestamp, entry_name,
    entry_status, source_status,
};
use tracedesk_engines::InventoryEntry;

use crate::mcp_http::{LocalMcpHttpServer, default_tool_catalog};

/* ==========================================================================================
 * 1. IPC Data Transfer Objects (100% aligned with frontend/src/types/ipc.ts)
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

/* ---------- Streaming Event Payloads (ui-contract.md §3.6) ---------- */

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
 * 2. Helper Functions for Snapshot & EntryView Construction
 * ========================================================================================== */

/// Infer icon kind matching `forensic/ui/icons.py::entry_icon_kind` and `frontend/src/components/Icons.tsx`.
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

/// Extract per-partition filesystem names from `fsstat` output and `coverage.volumes`.
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
        let part_re = Regex::new(r"分区偏移 (\d+) 扇区").expect("valid part regex");
        let fs_re = Regex::new(r"File System Type:\s*(\S+)").expect("valid fs regex");
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

/// Convert an [`InventoryEntry`] at index `idx` in [`BrowserIndex::ordered`] into [`EntryView`].
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

/// Compute `custodyState` matching `forensic/ui/controller.py::_custody_state`.
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

/// Build a full [`CaseSnapshot`] from the given [`Case`].
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
    }
}

/* ==========================================================================================
 * 3. Search Session & Cached View State
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

/// Fast read-mostly view state so tree/page/preview/timeline reads never block on long task execution.
#[derive(Default)]
pub struct ViewCache {
    pub snapshot: Option<CaseSnapshot>,
    pub case_folder: Option<PathBuf>,
    pub image_path: Option<PathBuf>,
    pub is_large_image: bool,
    pub fs_map: HashMap<u64, String>,
    pub browser_index: BrowserIndex,
    pub timeline_index: Option<TimelineIndex>,
}

impl ViewCache {
    /// Synchronize [`ViewCache`] from the active [`Case`].
    pub fn sync_from_case(&mut self, case: &Case, rebuild_browser_index: bool) {
        let prev_folder = self.case_folder.clone();
        let prev_count = self.snapshot.as_ref().map(|s| s.inventory_count);
        let prev_quick = self.snapshot.as_ref().and_then(|s| s.quick_location.clone());

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

        let folder_changed = prev_folder.as_ref() != Some(&folder);
        let entries_changed = prev_count != Some(snap.inventory_count)
            || prev_quick != snap.quick_location
            || rebuild_browser_index;

        if folder_changed || entries_changed {
            self.browser_index = BrowserIndex::build(case.displayed_entries());
            self.timeline_index = None;
        }

        self.snapshot = Some(snap);
        self.case_folder = Some(folder);
        self.image_path = image_path;
        self.is_large_image = is_large;
        self.fs_map = fs_map;
    }

    pub fn clear(&mut self) {
        self.snapshot = None;
        self.case_folder = None;
        self.image_path = None;
        self.is_large_image = false;
        self.fs_map.clear();
        self.browser_index = BrowserIndex::default();
        self.timeline_index = None;
    }

    /// Resolve an [`InventoryEntry`] and its 0-based `BrowserIndex` index from an `entryId` string.
    /// Accepts either `"0"` (0-based canonical index) or `"offset:inode:deleted"` / `"offset:inode:deleted:path"`.
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
            let inode = parts[1];
            let deleted = matches!(parts[2], "1" | "true");
            let path_opt = parts.get(3).copied();
            for (idx, row) in self.browser_index.ordered().iter().enumerate() {
                if row.offset == offset
                    && row.inode == inode
                    && row.deleted == deleted
                    && path_opt.is_none_or(|p| row.path == p)
                {
                    return Some((idx, row.clone()));
                }
            }
        }
        None
    }
}

/* ==========================================================================================
 * 4. Thread-Safe Application State (AppState)
 * ========================================================================================== */

pub struct AppState {
    pub app_paths: AppPaths,
    pub case_lock: Mutex<Option<Case>>,
    pub view: RwLock<ViewCache>,
    pub scan_cancel: Arc<AtomicBool>,
    pub hash_cancel: Arc<AtomicBool>,
    pub task_cancel: Arc<AtomicBool>,
    pub scanning_active: Arc<AtomicBool>,
    pub hashing_active: Arc<AtomicBool>,
    pub hash_worker: Mutex<Option<JoinHandle<()>>>,
    pub searches: Mutex<HashMap<String, SearchSessionState>>,
    pub mcp_server: Mutex<LocalMcpHttpServer>,
}

impl AppState {
    pub fn new() -> Arc<Self> {
        Self::with_paths(AppPaths::discover())
    }

    pub fn with_paths(app_paths: AppPaths) -> Arc<Self> {
        let _ = std::fs::create_dir_all(&app_paths.cases_dir);
        Arc::new(Self {
            app_paths,
            case_lock: Mutex::new(None),
            view: RwLock::new(ViewCache::default()),
            scan_cancel: Arc::new(AtomicBool::new(false)),
            hash_cancel: Arc::new(AtomicBool::new(false)),
            task_cancel: Arc::new(AtomicBool::new(false)),
            scanning_active: Arc::new(AtomicBool::new(false)),
            hashing_active: Arc::new(AtomicBool::new(false)),
            hash_worker: Mutex::new(None),
            searches: Mutex::new(HashMap::new()),
            mcp_server: Mutex::new(LocalMcpHttpServer::new()),
        })
    }

    /// Check if any background task (partition scan, large-image hash verification, or content search) is running.
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

    /// Cancel all active background operations (partition scan, hash verification, content searches)
    /// and stop the embedded HTTP MCP server.
    pub fn shutdown_all(&self) {
        self.scan_cancel.store(true, Ordering::Relaxed);
        self.hash_cancel.store(true, Ordering::Relaxed);
        self.task_cancel.store(true, Ordering::Relaxed);

        if let Ok(mut searches) = self.searches.lock() {
            for session in searches.values_mut() {
                session.cancel.store(true, Ordering::Relaxed);
                session.running = false;
            }
        }
        if let Ok(mut worker) = self.hash_worker.lock()
            && let Some(handle) = worker.take()
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

    /// Coordinate a delegated `tracedesk_mcp::McpServer` call with the active desktop [`Case`].
    ///
    /// If any path in `target_folders` matches the case currently open in the desktop UI,
    /// this temporarily closes the desktop `Case` (releasing `case.lock` and any image handles),
    /// runs `work()` while holding `case_lock` to prevent concurrent UI mutation, and then
    /// reopens the desktop `Case` in [`AuditOrigin::Manual`] mode and refreshes [`ViewCache`].
    pub fn coordinate_mcp_call<T, F>(&self, target_folders: &[PathBuf], work: F) -> T
    where
        F: FnOnce() -> T,
    {
        if target_folders.is_empty() {
            return work();
        }

        let resolved_targets: Vec<PathBuf> = target_folders
            .iter()
            .map(|p| tracedesk_core::resolve_clean(p))
            .collect();

        let Ok(mut case_guard) = self.case_lock.lock() else {
            return work();
        };

        let matched_open_dir = case_guard.as_ref().and_then(|c| {
            let open_dir = tracedesk_core::resolve_clean(c.folder());
            resolved_targets
                .iter()
                .any(|t| same_case_path(t, &open_dir))
                .then_some(open_dir)
        });

        let Some(open_dir) = matched_open_dir else {
            drop(case_guard);
            return work();
        };

        let prev_dir_loc = case_guard
            .as_ref()
            .and_then(|c| c.directory_location().cloned());

        // Release desktop case.lock so tracedesk_mcp::CaseService can acquire it cleanly.
        if let Some(mut open_case) = case_guard.take() {
            open_case.close();
        }

        let result = work();

        // Re-open the desktop Case in Manual mode and refresh ViewCache.
        if let Ok(mut reopened) = Case::open(&open_dir, None, AuditOrigin::Manual) {
            if reopened.browsing_directories()
                && let Some(loc) = prev_dir_loc
            {
                let _ = reopened.browse_directory(
                    loc.offset,
                    loc.inode.as_deref(),
                    &loc.path,
                    None,
                );
            }
            if let Ok(mut view) = self.view.write() {
                view.sync_from_case(&reopened, true);
            }
            *case_guard = Some(reopened);
        }
        result
    }

    /// Build [`McpStatus`] for the given optional port override.
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

        let url = format!("http://{host}:{active_port}{path}");
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
