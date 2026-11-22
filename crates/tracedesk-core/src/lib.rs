//! TraceDesk core forensic business logic crate:
//! - Project & runtime path resolution (`paths`)
//! - UTC+8 formatting, Windows filename sanitization, and canonical JSON (`formatting`)
//! - Volume declared coverage & evidence provenance (`coverage`)
//! - Case lifecycle, gzip inventory, `case.lock`, large-image quick browse, and SHA-256 audit chain (`case`)
//! - Canonical browser sorting, lazy tree grouping, and multi-condition filtering (`browser_index`)
//! - Compact `u64` MACB timeline with multi-core parallel sorting & filtering (`timeline`)
//! - Single-file hash/compare/note tools (`file_tools`) and grouped findings & export (`findings`)
//! - 9-encoding cross-page preview, HEX formatter, and safe image preview (`preview`)
//! - Multi-core AVX2 SIMD exact byte search with deterministic ordering (`content_search`)
//! - 10-section Markdown forensic reporting (`reporting`)
//! - ZIP64 verifiable review bundle builder & native Rust verifier (`review`)

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
    VerificationInfo, read_inventory_gz, save_json_atomic, verify_audit_chain_at,
    write_inventory_gz,
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
    HexRow, IMAGE_SUFFIXES, ImagePreviewResult, MAX_IMAGE_BYTES, MAX_IMAGE_DIM, MAX_IMAGE_PIXELS,
    PAGE_BYTES, PREVIEW_ENCODINGS, PageWindow, PreviewEncoding, PreviewPageResult, PreviewSession,
    ROW_BYTES, compute_legacy_carry, decode_image_preview, is_image_candidate, page_characters,
    preview_entry_image, preview_entry_page, preview_rows, preview_text,
};
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
