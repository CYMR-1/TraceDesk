//! TraceDesk 核心取证业务逻辑 crate：
//! - 项目与运行时路径解析（`paths`）
//! - UTC+8 时间格式化、Windows 文件名净化与规范化 JSON（`formatting`）
//! - 卷声明覆盖范围与证据来源校验（`coverage`）
//! - 案件生命周期、gzip 清单、`case.lock`、大镜像快速浏览与 SHA-256 审计链（`case`）
//! - 规范浏览排序、延迟树分组与多条件过滤（`browser_index`）
//! - 紧凑 `u64` MACB 时间线及多核并行排序与过滤（`timeline`）
//! - 单文件哈希/比对/笔记工具（`file_tools`）与分组研判记录及导出（`findings`）
//! - 9 种编码跨页预览、HEX 格式化与安全图片预览（`preview`）
//! - 多核 AVX2 SIMD 精确字节搜索及确定性排序（`content_search`）
//! - 10 节 Markdown 取证报告生成（`reporting`）
//! - ZIP64 可核验复核包构建器与原生 Rust 校验器（`review`）

pub mod browser_index;
pub mod case;
pub mod content_search;
pub mod coverage;
pub mod error;
pub mod file_tools;
pub mod findings;
pub mod formatting;
pub mod paths;
pub mod preview;
pub mod reporting;
pub mod review;
pub mod timeline;

pub use browser_index::{
    BrowserFilter, BrowserIndex, BrowserPage, DEFAULT_PAGE_SIZE, EntryLocation, PAGING_THRESHOLD,
    StatusFilter, TREE_GROUP_SIZE, TREE_GROUP_THRESHOLD, TreeBranchItem, TreeChildrenPage,
    TreeNodeDto,
};
pub use case::{
    ByteProgress, Case, CaseData, DirectoryLocation, EvidenceInfo, ExportRecord, GENESIS_HASH,
    LARGE_IMAGE_BYTES, MeasuredHash, PartitionScan, SourceStampRow, StageProgress,
    VerificationInfo, read_inventory_gz, save_json_atomic, strip_trailing_version,
    verify_audit_chain_at, write_inventory_gz,
};
pub use content_search::{
    CONTEXT_BYTES, HitCallback, ICAT_THREADS, PIECE_BYTES, PIECE_SPLIT_MIN, RawHit,
    SearchErrorEntry, SearchHit, SearchOptions, SearchOutput, SearchRecord, SelectedSearchTarget,
    StreamMatcher, WIN_INIT_BYTES, WIN_INIT_FILES, WIN_MAX_BYTES, WIN_MAX_FILES,
    find_matches_in_reader, hex_spaced_lower, parse_pattern, search_case,
};
pub use coverage::{
    CoverageReport, Provenance, SOURCE_FIELDS, VolumeCoverage, assess_coverage, coverage_text,
    source_status,
};
pub use error::{CoreError, CoreResult};
pub use file_tools::{ExamineResult, entry_identity, examine, record_note, record_search_hit_note};
pub use findings::{
    ACTION_TITLES, AUDIT_ORIGINS, AuditOrigin, AuditRecord, ExportFindingsResult, FindingGroup,
    FindingGroupKey, OPERATIONS, action_title, audit_mcp_user, audit_origin, audit_origin_label,
    export_findings, findings_text, group_findings, operation_title,
};
pub use formatting::{
    EAST_8_OFFSET_SECS, TimeValue, can_export, canonical_json, canonical_json_value,
    case_folder_name, create_unique_case_folder, deleted_export_summary, deleted_source_note,
    display_iso_time, display_time, display_timestamp, east_8, entry_name, entry_status,
    export_filename, format_commas, format_size, format_unix_east8_stack, hex_lower,
    next_case_folder_path, now, parse_iso_to_east8, sha256_hex, truncate_utf16_units,
    utf16_unit_len, windows_filename,
};
pub use paths::{AppPaths, is_within, resolve_clean, strip_verbatim_prefix};
pub use preview::{
    HexRow, IMAGE_SUFFIXES, MAX_IMAGE_BYTES, MAX_IMAGE_DIM, MAX_IMAGE_PIXELS, PAGE_BYTES,
    PREVIEW_ENCODINGS, PageWindow, PreviewEncoding, PreviewPageResult, PreviewSession, ROW_BYTES,
    compute_legacy_carry, is_image_candidate, page_characters, preview_entry_page, preview_rows,
    preview_text,
};
#[cfg(feature = "image-preview")]
pub use preview::{ImagePreviewResult, decode_image_preview, preview_entry_image};
pub use reporting::render_report;
pub use review::{
    BuildBundleOptions, BuildBundleResult, BundleExportRow, BundleSearchRow,
    EMBEDDED_VERIFY_BUNDLE_PY, build_bundle, format_missing_materials, inspect_bundle_exports,
    inspect_bundle_searches, resolve_export_path, verify_bundle,
};
pub use timeline::{
    TIMELINE_FIELDS, TimelineFilter, TimelineFilterOptions, TimelineIndex, TimelinePage,
    TimelineRow, normalize_event_filter,
};
