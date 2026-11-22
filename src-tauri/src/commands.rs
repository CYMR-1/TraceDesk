//! Implementation of all 38 Tauri Commands and 6 streaming Events defined in
//! `ui-contract.md` §3 and `frontend/src/api/tauri.ts` (plus convenience aliases).

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use tauri::{AppHandle, Emitter, State};
use tracedesk_core::{
    AuditOrigin, BrowserFilter, BuildBundleOptions, Case, CoreError, EvidenceInfo, FindingGroup,
    PreviewEncoding, Provenance, SearchHit, SearchOptions, SearchRecord, StatusFilter,
    TimelineFilter, TimelineIndex, action_title, audit_mcp_user, audit_origin, audit_origin_label,
    build_bundle, case_folder_name,
    deleted_export_summary, deleted_source_note, display_iso_time, entry_status, examine,
    export_findings as core_export_findings, format_missing_materials, group_findings, hex_lower,
    inspect_bundle_exports, inspect_bundle_searches, is_within, next_case_folder_path,
    operation_title, parse_pattern, preview_entry_image, preview_entry_page, record_note,
    resolve_clean, search_case,
};
use tracedesk_engines::{InventoryEntry, SourceGuard, TskCli, ewf, sha256_file};
use uuid::Uuid;

use crate::mcp_http::mcp_list_cases;
use crate::state::{
    AppPathsDto, AppState, AuditFilterOptionsDto, AuditRecordDto, BookmarkSearchHitsResponse,
    BrowseDirectoryResponse, BuildTimelineResponse, BundleExportRowDto, BundleMaterialsResponse,
    BundleSearchRowDto, BusyCheckResponse, CancelResponse, CaseSnapshot, CloseCaseResponse,
    EntryView, ExamineFileResponse, ExportFileResponse, ExportFindingsResponse,
    FindingFilterOptionsDto, FindingGroupDto, FindingRecordDto, GuidePageDto, HashFinishedEvent,
    HashProgressEvent, HexRowDto, ListAuditLogResponse, ListFindingsResponse, LocateFileResponse,
    McpStatus, OpenInOsResponse, PathAndSnapshotResponse, PathResponse, PreviewImageResponse,
    PreviewPageResponse, QueryFilesPageResponse, QueryTimelinePageResponse, RecentCaseDto,
    ScanPartitionsResponse, SearchFinishedEvent, SearchHitDto, SearchHitsEvent,
    SearchProgressEvent, SearchSessionState, SnapshotResponse, StartContentSearchResponse,
    StoredSearchHit, SuggestCaseDirResponse, TaskFinishedEvent, TaskProgressEvent,
    TaskStartedEvent, TimelineFilterOptionsDto, TimelineRowDto, TreeChildrenResponse,
    TreeNodeIpcDto, VerifyIntegrityResponse, entry_to_view, infer_entry_icon_kind,
};

/* ==========================================================================================
 * Helper: Event Emission
 * ========================================================================================== */

fn emit_task_started(app: Option<&AppHandle>, stage: &str) {
    if let Some(handle) = app {
        let _ = handle.emit(
            "task:started",
            TaskStartedEvent {
                stage: stage.to_string(),
            },
        );
    }
}

fn emit_task_progress(app: Option<&AppHandle>, stage: &str, done: u64, total: u64) {
    if let Some(handle) = app {
        let _ = handle.emit(
            "task:progress",
            TaskProgressEvent {
                stage: stage.to_string(),
                done,
                total,
            },
        );
    }
}

fn emit_task_finished(app: Option<&AppHandle>, stage: &str, ok: bool, error: Option<String>) {
    if let Some(handle) = app {
        let _ = handle.emit(
            "task:finished",
            TaskFinishedEvent {
                stage: stage.to_string(),
                ok,
                error,
            },
        );
    }
}

/* ==========================================================================================
 * 3.1 App 状态与案件管理 Commands (Core Functions + Tauri Command Wrappers)
 * ========================================================================================== */

pub fn cmd_get_app_paths(state: &Arc<AppState>) -> Result<AppPathsDto, String> {
    Ok(AppPathsDto {
        root_dir: state.app_paths.root.to_string_lossy().into_owned(),
        cases_dir: state.app_paths.cases_dir.to_string_lossy().into_owned(),
        evidence_dir: state.app_paths.evidence_dir.to_string_lossy().into_owned(),
    })
}

pub fn cmd_suggest_case_dir(
    state: &Arc<AppState>,
    number: &str,
    examiner: &str,
    target: &str,
    parent_dir: Option<&str>,
) -> Result<SuggestCaseDirResponse, String> {
    let base_name = case_folder_name(number, examiner, target);
    let parent = match parent_dir.map(str::trim).filter(|s| !s.is_empty()) {
        Some(p) => resolve_clean(Path::new(p)),
        None => resolve_clean(&state.app_paths.cases_dir),
    };
    let suggested = next_case_folder_path(&parent, &base_name);
    let folder_name = suggested
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or(base_name);
    Ok(SuggestCaseDirResponse {
        suggested_path: suggested.to_string_lossy().into_owned(),
        folder_name,
    })
}

pub fn cmd_create_case(
    state: &Arc<AppState>,
    parent_dir: &str,
    number: &str,
    examiner: &str,
    target: &str,
    folder_name: Option<&str>,
) -> Result<CaseSnapshot, String> {
    let busy = state.check_busy();
    if busy.busy {
        return Err(busy
            .reason
            .unwrap_or_else(|| "存在正在运行的后台任务".to_string()));
    }
    let parent = if parent_dir.trim().is_empty() {
        state.app_paths.cases_dir.clone()
    } else {
        PathBuf::from(parent_dir.trim())
    };
    let explicit_folder = folder_name.map(str::trim).filter(|s| !s.is_empty());

    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let new_case = Case::create(
        &parent,
        number.trim(),
        examiner.trim(),
        target.trim(),
        explicit_folder,
        None,
        AuditOrigin::Manual,
    )
    .map_err(|e| e.to_string())?;

    if let Some(mut old) = case_guard.take() {
        old.close();
    }
    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(&new_case, true);
    let snap = view.snapshot.clone().expect("snapshot created");
    *case_guard = Some(new_case);
    Ok(snap)
}

pub fn cmd_open_case(state: &Arc<AppState>, case_path: &str) -> Result<CaseSnapshot, String> {
    let busy = state.check_busy();
    if busy.busy {
        return Err(busy
            .reason
            .unwrap_or_else(|| "存在正在运行的后台任务".to_string()));
    }
    let trimmed = case_path.trim();
    if trimmed.is_empty() {
        return Err("请选择或输入案件目录或 case.json 路径".to_string());
    }
    let raw_path = resolve_clean(Path::new(trimmed));
    let (folder, log_subject) = if raw_path.is_file()
        || raw_path
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("case.json"))
    {
        let parent = raw_path
            .parent()
            .ok_or_else(|| "无效的案件文件路径".to_string())?
            .to_path_buf();
        (parent, raw_path.to_string_lossy().into_owned())
    } else {
        let meta = raw_path.join("case.json");
        (raw_path, meta.to_string_lossy().into_owned())
    };

    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;

    // If re-opening the currently open case folder, release the existing lock first.
    if case_guard
        .as_ref()
        .is_some_and(|c| resolve_clean(c.folder()) == folder)
        && let Some(mut cur) = case_guard.take()
    {
        cur.close();
    }

    let mut opened =
        Case::open(&folder, None, AuditOrigin::Manual).map_err(|e| e.to_string())?;
    if let Err(err) = opened.log("CASE_OPEN", &log_subject, "成功", Map::new()) {
        opened.close();
        return Err(err.to_string());
    }

    if let Some(mut old) = case_guard.take() {
        old.close();
    }

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(&opened, true);
    let snap = view.snapshot.clone().expect("snapshot created");
    *case_guard = Some(opened);
    Ok(snap)
}

pub fn cmd_close_case(state: &Arc<AppState>) -> Result<CloseCaseResponse, String> {
    let busy = state.check_busy();
    if busy.busy {
        return Err(busy
            .reason
            .unwrap_or_else(|| "存在正在运行的后台任务，无法关闭案件".to_string()));
    }
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    if let Some(mut cur) = case_guard.take() {
        cur.close();
    }
    if let Ok(mut view) = state.view.write() {
        view.clear();
    }
    Ok(CloseCaseResponse { closed: true })
}

pub fn cmd_get_case_snapshot(state: &Arc<AppState>) -> Result<Option<CaseSnapshot>, String> {
    let view = state
        .view
        .read()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    Ok(view.snapshot.clone())
}

pub fn cmd_list_recent_cases(state: &Arc<AppState>) -> Result<Vec<RecentCaseDto>, String> {
    let val = mcp_list_cases(state, None, 50, 0)?;
    let mut list = Vec::new();
    if let Some(items) = val.get("items").and_then(Value::as_array) {
        for item in items {
            if item.get("status").and_then(Value::as_str) != Some("ok") {
                continue;
            }
            list.push(RecentCaseDto {
                folder: item
                    .get("folder")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                name: item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                number: item
                    .get("number")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                examiner: item
                    .get("examiner")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                target: item
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                created: item
                    .get("created")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                has_evidence: item
                    .get("has_evidence")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                inventory_count: item
                    .get("inventory_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize,
                exports_count: item
                    .get("exports_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize,
            });
        }
    }
    Ok(list)
}

/* ==========================================================================================
 * 3.2 证据镜像与文件浏览 Commands
 * ========================================================================================== */

pub fn cmd_load_image(
    state: &Arc<AppState>,
    image_path: &str,
    app: Option<&AppHandle>,
) -> Result<CaseSnapshot, String> {
    emit_task_started(app, "打开镜像并识别分区");
    state.task_cancel.store(false, Ordering::Relaxed);
    let cancel = Arc::clone(&state.task_cancel);

    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let progress_cb = |done: u64, total: u64| {
        emit_task_progress(app, "固定镜像 SHA-256", done, total);
    };

    if let Err(err) = case.load_image(
        Path::new(image_path.trim()),
        None,
        Some(&cancel),
        Some(&progress_cb),
    ) {
        let msg = err.to_string();
        emit_task_finished(app, "打开镜像并识别分区", false, Some(msg.clone()));
        return Err(msg);
    }

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, true);
    let snap = view.snapshot.clone().expect("snapshot updated");
    emit_task_finished(app, "打开镜像并识别分区", true, None);
    Ok(snap)
}

pub fn cmd_verify_integrity(
    state: &Arc<AppState>,
    app: Option<&AppHandle>,
) -> Result<VerifyIntegrityResponse, String> {
    // Check if the loaded image is a large image (>= 1 GiB) and we have an AppHandle for background streaming.
    let (is_large, initial_fixed_pre, snap_pre) = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        let snap = view
            .snapshot
            .clone()
            .ok_or_else(|| "请先新建或打开案件".to_string())?;
        let ev = snap
            .evidence
            .as_ref()
            .ok_or_else(|| "请先加载镜像".to_string())?;
        let large = ev.large_image.unwrap_or(false);
        let init_fixed = ev.sha256.as_deref().is_none_or(str::is_empty);
        (large, init_fixed, snap)
    };

    if is_large && let Some(app_handle) = app.cloned() {
        spawn_large_image_hash_worker(Arc::clone(state), app_handle)?;
        return Ok(VerifyIntegrityResponse {
            ok: true,
            initial_fixed: initial_fixed_pre,
            snapshot: snap_pre,
        });
    }

    // Synchronous / small-image verification (with task:progress events).
    emit_task_started(app, "校验 SHA-256");
    state.hash_cancel.store(false, Ordering::Relaxed);
    let cancel = Arc::clone(&state.hash_cancel);

    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;
    let initial_fixed = case
        .data()
        .evidence
        .as_ref()
        .ok_or_else(|| "请先加载镜像".to_string())?
        .sha256
        .as_deref()
        .is_none_or(str::is_empty);

    let progress_cb = |done: u64, total: u64| {
        emit_task_progress(app, "校验 SHA-256", done, total);
    };

    let ok = match case.verify_integrity(None, Some(&cancel), Some(&progress_cb)) {
        Ok(ok) => ok,
        Err(err) => {
            let msg = err.to_string();
            emit_task_finished(app, "校验 SHA-256", false, Some(msg.clone()));
            return Err(msg);
        }
    };

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, false);
    let snapshot = view.snapshot.clone().expect("snapshot updated");
    emit_task_finished(app, "校验 SHA-256", true, None);

    Ok(VerifyIntegrityResponse {
        ok,
        initial_fixed,
        snapshot,
    })
}

/// Spawn a non-blocking background worker for large-image (`>= 1 GiB`) SHA-256 verification.
/// Releases `case_lock` during disk hashing so the user can continue browsing directories!
fn spawn_large_image_hash_worker(state: Arc<AppState>, app: AppHandle) -> Result<(), String> {
    if state.hashing_active.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    state.hash_cancel.store(false, Ordering::Relaxed);

    // Step 1: Under case_lock, verify source guard and clone EvidenceInfo.
    let (ev, case_folder) = {
        let mut case_guard = match state.case_lock.lock() {
            Ok(g) => g,
            Err(_) => {
                state.hashing_active.store(false, Ordering::SeqCst);
                return Err("案件状态锁异常".to_string());
            }
        };
        let Some(case) = case_guard.as_mut() else {
            state.hashing_active.store(false, Ordering::SeqCst);
            return Err("请先新建或打开案件".to_string());
        };
        if let Err(e) = case.check_source() {
            state.hashing_active.store(false, Ordering::SeqCst);
            return Err(e.to_string());
        }
        let Some(ev) = case.data().evidence.clone() else {
            state.hashing_active.store(false, Ordering::SeqCst);
            return Err("请先加载镜像".to_string());
        };
        (ev, case.folder().to_path_buf())
    };

    let cancel = Arc::clone(&state.hash_cancel);
    let state_clone = Arc::clone(&state);

    let handle = thread::Builder::new()
        .name("tracedesk-large-hash".to_string())
        .spawn(move || {
            let started = Instant::now();
            let last_emit = std::sync::Mutex::new(Instant::now() - Duration::from_secs(1));
            let progress_cb = |done: u64, total: u64| {
                if let Ok(mut last) = last_emit.lock()
                    && (done >= total || last.elapsed() >= Duration::from_millis(60))
                {
                    *last = Instant::now();
                    let elapsed = started.elapsed().as_secs_f64().max(0.001);
                    let rate_mi_bs = (done as f64) / elapsed / ((1u64 << 20) as f64);
                    let _ = app.emit(
                        "hash:progress",
                        HashProgressEvent {
                            done,
                            total,
                            rate_mi_bs,
                        },
                    );
                }
            };

            let measure_res = measure_hash_detached(&ev, &cancel, &progress_cb);

            // Re-acquire case_lock briefly to commit `accept_hash` or log cancellation/error.
            let mut finished_event = HashFinishedEvent {
                cancelled: false,
                ok: None,
                initial_fixed: None,
                error: None,
                snapshot: None,
            };

            if let Ok(mut case_guard) = state_clone.case_lock.lock()
                && let Some(case) = case_guard.as_mut()
                && case.folder() == case_folder
            {
                let image_str = ev.path.clone();
                match measure_res {
                    Err(ref err) if err.is_cancelled() || cancel.load(Ordering::Relaxed) => {
                        let _ = case.log("HASH_VERIFY", &image_str, "已取消", Map::new());
                        finished_event.cancelled = true;
                    }
                    Err(err) => {
                        let msg = err.to_string();
                        let mut d = Map::new();
                        d.insert("error".to_string(), Value::String(msg.clone()));
                        let _ = case.log("HASH_VERIFY", &image_str, "失败", d);
                        finished_event.error = Some(msg);
                    }
                    Ok(measured) => {
                        let initial_fixed = measured.sha256_update.is_some();
                        match case.accept_hash(measured) {
                            Ok(ok) => {
                                finished_event.ok = Some(ok);
                                finished_event.initial_fixed = Some(initial_fixed);
                            }
                            Err(err) => {
                                let msg = err.to_string();
                                let mut d = Map::new();
                                d.insert("error".to_string(), Value::String(msg.clone()));
                                let _ = case.log("HASH_VERIFY", &image_str, "失败", d);
                                finished_event.error = Some(msg);
                            }
                        }
                    }
                }
                if let Ok(mut view) = state_clone.view.write() {
                    view.sync_from_case(case, false);
                    finished_event.snapshot = view.snapshot.clone();
                }
            } else if cancel.load(Ordering::Relaxed) {
                finished_event.cancelled = true;
            }

            state_clone.hashing_active.store(false, Ordering::SeqCst);
            let _ = app.emit("hash:finished", finished_event);
        })
        .map_err(|e| {
            state.hashing_active.store(false, Ordering::SeqCst);
            format!("无法启动后台哈希线程：{e}")
        })?;

    if let Ok(mut w) = state.hash_worker.lock() {
        *w = Some(handle);
    }
    Ok(())
}

fn measure_hash_detached(
    ev: &EvidenceInfo,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<tracedesk_core::MeasuredHash, CoreError> {
    let image = PathBuf::from(&ev.path);
    let first = ev.sha256.as_deref().is_none_or(str::is_empty);
    let mut segments_update = None;
    let mut coverage_update = None;

    let (actual, ok, mut method) = if ev.is_ewf() {
        let parts = ewf::discover_segments(&image)?;
        let before = SourceGuard::snapshot(&parts)?;
        let mut total_bytes = 0u64;
        for p in &parts {
            total_bytes = total_bytes.saturating_add(fs::metadata(p)?.len());
        }
        let logical_size = ev.size;
        let combined_total = logical_size.saturating_add(total_bytes);

        let logical_digest = if first {
            let tool = TskCli::discover(None)?;
            let cb = |done: u64, _t: u64| progress(done, combined_total);
            Some(ewf::hash_logical_stream(
                &tool,
                &image,
                logical_size,
                Some(cancel),
                Some(&cb),
            )?)
        } else {
            ev.sha256.clone()
        };

        let phys_cb = |done: u64, _t: u64| {
            if first {
                progress(logical_size.saturating_add(done), combined_total);
            } else {
                progress(done, total_bytes);
            }
        };
        let segs = ewf::hash_physical_segments(&parts, Some(cancel), Some(&phys_cb))?;
        let after_parts = ewf::discover_segments(&image)?;
        if SourceGuard::snapshot(&after_parts)? != before {
            return Err(CoreError::IntegrityFailed(
                "校验期间 EWF 分段发生变化".to_string(),
            ));
        }
        let ok = first || ev.segments.as_ref() == Some(&segs);
        if first {
            segments_update = Some(segs);
        }
        let actual = if ok { logical_digest } else { None };
        (
            actual,
            ok,
            "逐段复算封装 SHA-256，与首次逻辑流校验时的全部分段比对".to_string(),
        )
    } else {
        let digest = sha256_file(&image, Some(cancel), Some(progress))?;
        let ok = first || ev.sha256.as_deref() == Some(digest.as_str());
        (Some(digest), ok, "复算 RAW SHA-256".to_string())
    };

    let sha256_update = if first {
        method = "首次完整读取并建立 SHA-256 基线".to_string();
        actual.as_ref().map(|d| (d.clone(), tracedesk_core::now()))
    } else {
        None
    };

    if ok && ev.coverage.is_none() {
        coverage_update = Some(tracedesk_core::assess_coverage::<fn(u64) -> Option<Vec<u8>>>(
            &image,
            &ev.partitions,
            &ev.layout,
            None,
            None,
        )?);
    }

    Ok(tracedesk_core::MeasuredHash {
        verification: tracedesk_core::VerificationInfo {
            time: tracedesk_core::now(),
            actual,
            ok,
            method,
        },
        sha256_update,
        segments_update,
        source_stamp_update: None,
        coverage_update,
    })
}

pub fn cmd_cancel_verify_integrity(state: &Arc<AppState>) -> Result<CancelResponse, String> {
    state.hash_cancel.store(true, Ordering::Relaxed);
    Ok(CancelResponse { cancelled: true })
}

pub fn cmd_register_source(
    state: &Arc<AppState>,
    evidence_id: &str,
    source: &str,
    acquired: &str,
    tool: &str,
    expected_sha256: &str,
) -> Result<CaseSnapshot, String> {
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let prov = Provenance {
        evidence_id: evidence_id.to_string(),
        source: source.to_string(),
        acquired: acquired.to_string(),
        tool: tool.to_string(),
        expected_sha256: expected_sha256.to_string(),
    };
    case.register_source(&prov).map_err(|e| e.to_string())?;

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, false);
    Ok(view.snapshot.clone().expect("snapshot updated"))
}

pub fn cmd_export_fsstat(state: &Arc<AppState>, offset: u64) -> Result<PathResponse, String> {
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;
    let dest = case
        .export_fsstat(offset, None)
        .map_err(|e| e.to_string())?;
    Ok(PathResponse {
        path: dest.to_string_lossy().into_owned(),
    })
}

pub fn cmd_scan_all_partitions(
    state: &Arc<AppState>,
    app: Option<&AppHandle>,
) -> Result<ScanPartitionsResponse, String> {
    emit_task_started(app, "读取所有分区与文件树");
    state.scan_cancel.store(false, Ordering::Relaxed);
    state.scanning_active.store(true, Ordering::SeqCst);
    let cancel = Arc::clone(&state.scan_cancel);

    let res = (|| -> Result<ScanPartitionsResponse, String> {
        let mut case_guard = state
            .case_lock
            .lock()
            .map_err(|_| "案件状态锁异常".to_string())?;
        let case = case_guard
            .as_mut()
            .ok_or_else(|| "请先新建或打开案件".to_string())?;

        let progress_cb = |stage: &str, done: u64, total: u64| {
            emit_task_progress(app, stage, done, total);
        };

        match case.scan_partitions(None, Some(&cancel), Some(&progress_cb)) {
            Ok(_) => {
                let mut view = state
                    .view
                    .write()
                    .map_err(|_| "视图缓存锁异常".to_string())?;
                view.sync_from_case(case, true);
                let snapshot = view.snapshot.clone().expect("snapshot updated");
                Ok(ScanPartitionsResponse {
                    completed: true,
                    snapshot,
                })
            }
            Err(err) if err.is_cancelled() => {
                let mut view = state
                    .view
                    .write()
                    .map_err(|_| "视图缓存锁异常".to_string())?;
                view.sync_from_case(case, false);
                let snapshot = view.snapshot.clone().expect("snapshot updated");
                Ok(ScanPartitionsResponse {
                    completed: false,
                    snapshot,
                })
            }
            Err(err) => Err(err.to_string()),
        }
    })();

    state.scanning_active.store(false, Ordering::SeqCst);
    match &res {
        Ok(_) => emit_task_finished(app, "读取所有分区与文件树", true, None),
        Err(e) => emit_task_finished(app, "读取所有分区与文件树", false, Some(e.clone())),
    }
    res
}

pub fn cmd_scan_partition(
    state: &Arc<AppState>,
    offset: u64,
) -> Result<ScanPartitionsResponse, String> {
    state.scan_cancel.store(false, Ordering::Relaxed);
    let cancel = Arc::clone(&state.scan_cancel);
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;
    case.scan_partition(offset, None, Some(&cancel))
        .map_err(|e| e.to_string())?;
    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, true);
    let snapshot = view.snapshot.clone().expect("snapshot updated");
    Ok(ScanPartitionsResponse {
        completed: true,
        snapshot,
    })
}

pub fn cmd_cancel_scan_partitions(state: &Arc<AppState>) -> Result<CancelResponse, String> {
    state.scan_cancel.store(true, Ordering::Relaxed);
    Ok(CancelResponse { cancelled: true })
}

pub fn cmd_cancel_task(state: &Arc<AppState>) -> Result<CancelResponse, String> {
    state.scan_cancel.store(true, Ordering::Relaxed);
    state.hash_cancel.store(true, Ordering::Relaxed);
    state.task_cancel.store(true, Ordering::Relaxed);
    Ok(CancelResponse { cancelled: true })
}

pub fn cmd_browse_directory(
    state: &Arc<AppState>,
    offset: u64,
    inode: Option<&str>,
    path: &str,
) -> Result<BrowseDirectoryResponse, String> {
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let clean_inode = inode.map(str::trim).filter(|s| !s.is_empty());
    let clean_path = path.replace('\\', "/").trim_matches('/').to_string();
    case.browse_directory(offset, clean_inode, &clean_path, None)
        .map_err(|e| e.to_string())?;

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, true);
    let snapshot = view.snapshot.clone().expect("snapshot updated");
    let entries: Vec<EntryView> = view
        .browser_index
        .ordered()
        .iter()
        .enumerate()
        .map(|(idx, e)| entry_to_view(idx, e, &view.fs_map))
        .collect();

    Ok(BrowseDirectoryResponse { snapshot, entries })
}

pub fn cmd_get_tree_children(
    state: &Arc<AppState>,
    offset: u64,
    scope_path: &str,
    group_index: Option<usize>,
) -> Result<TreeChildrenResponse, String> {
    let view = state
        .view
        .read()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    if view.snapshot.as_ref().and_then(|s| s.evidence.as_ref()).is_none() {
        return Ok(TreeChildrenResponse {
            nodes: Vec::new(),
            grouped: false,
            group_count: 0,
        });
    }

    let page = view
        .browser_index
        .tree_children(offset, scope_path, group_index);
    let mut nodes = Vec::with_capacity(page.nodes.len());

    for n in page.nodes {
        if n.is_group {
            let g_idx = n.group_index.unwrap_or(0);
            nodes.push(TreeNodeIpcDto {
                id: format!("grp:{}:{}:{g_idx}", n.offset, n.path),
                label: n.label.clone(),
                tooltip: Some(n.label),
                kind: "group".to_string(),
                icon_kind: "folder".to_string(),
                offset: Some(n.offset),
                scope_path: Some(n.path),
                inode: None,
                entry_id: None,
                deleted: Some(false),
                has_children: true,
                group_index: Some(g_idx),
            });
        } else if n.directory {
            let tooltip = if let Some(idx) = n.entry_id
                && let Some(entry) = view.browser_index.get(idx)
            {
                format!(
                    "{}\n{} · inode {}",
                    entry.path,
                    entry_status(entry),
                    if entry.inode.is_empty() {
                        "—"
                    } else {
                        &entry.inode
                    }
                )
            } else {
                n.path.clone()
            };
            nodes.push(TreeNodeIpcDto {
                id: format!("dir:{}:{}", n.offset, n.path),
                label: n.label,
                tooltip: Some(tooltip),
                kind: "directory".to_string(),
                icon_kind: "folder".to_string(),
                offset: Some(n.offset),
                scope_path: Some(n.path),
                inode: (!n.inode.is_empty()).then_some(n.inode),
                entry_id: n.entry_id.map(|id| id.to_string()),
                deleted: Some(n.deleted),
                has_children: n.has_children,
                group_index: None,
            });
        } else {
            let (icon_kind, status_str) = match n.entry_id.and_then(|id| view.browser_index.get(id))
            {
                Some(entry) => (infer_entry_icon_kind(entry), entry_status(entry)),
                None => ("file", "现存"),
            };
            let ino_disp = if n.inode.is_empty() { "—" } else { &n.inode };
            let entry_id_str = n.entry_id.map(|id| id.to_string());
            nodes.push(TreeNodeIpcDto {
                id: format!(
                    "file:{}:{}:{}",
                    n.offset,
                    n.path,
                    n.entry_id.unwrap_or(0)
                ),
                label: n.label,
                tooltip: Some(format!("{}\n{status_str} · inode {ino_disp}", n.path)),
                kind: "file".to_string(),
                icon_kind: icon_kind.to_string(),
                offset: Some(n.offset),
                scope_path: None,
                inode: (!n.inode.is_empty()).then_some(n.inode),
                entry_id: entry_id_str,
                deleted: Some(n.deleted),
                has_children: false,
                group_index: None,
            });
        }
    }

    Ok(TreeChildrenResponse {
        nodes,
        grouped: page.grouped,
        group_count: page.group_count,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_query_files_page(
    state: &Arc<AppState>,
    scope_offset: Option<u64>,
    scope_path: Option<String>,
    suffix: &str,
    keyword: &str,
    status: &str,
    page: usize,
    page_size: usize,
    log_filter: Option<bool>,
) -> Result<QueryFilesPageResponse, String> {
    if log_filter == Some(true) {
        let mut case_guard = state
            .case_lock
            .lock()
            .map_err(|_| "案件状态锁异常".to_string())?;
        if let Some(case) = case_guard.as_mut() {
            case.filtered(suffix, keyword).map_err(|e| e.to_string())?;
        }
    }

    let view = state
        .view
        .read()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    if view.snapshot.as_ref().and_then(|s| s.evidence.as_ref()).is_none() {
        return Ok(QueryFilesPageResponse {
            total: 0,
            page: 0,
            total_pages: 1,
            items: Vec::new(),
        });
    }

    let status_filter = match status.trim().to_ascii_lowercase().as_str() {
        "active" => StatusFilter::ActiveFile,
        "deleted" => StatusFilter::Deleted,
        "system" => StatusFilter::System,
        _ => StatusFilter::All,
    };

    let filter = BrowserFilter {
        scope_offset,
        scope_path,
        path_prefix: None,
        suffix: suffix.to_string(),
        keyword: keyword.to_string(),
        status: status_filter,
        files_only: false,
    };

    let res = view.browser_index.query_page(&filter, page, page_size);
    let items: Vec<EntryView> = res
        .entry_ids
        .into_iter()
        .filter_map(|idx| {
            view.browser_index
                .get(idx)
                .map(|e| entry_to_view(idx, e, &view.fs_map))
        })
        .collect();

    Ok(QueryFilesPageResponse {
        total: res.total,
        page: res.page,
        total_pages: res.total_pages,
        items,
    })
}

pub fn cmd_locate_file_in_scope(
    state: &Arc<AppState>,
    entry_id: &str,
) -> Result<LocateFileResponse, String> {
    let view = state
        .view
        .read()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    let (idx, _) = view
        .resolve_entry(entry_id)
        .ok_or_else(|| format!("未找到目标文件条目：{entry_id}"))?;
    let loc = view
        .browser_index
        .locate_entry(idx, tracedesk_core::DEFAULT_PAGE_SIZE)
        .ok_or_else(|| "无法定位文件所在目录页".to_string())?;
    Ok(LocateFileResponse {
        scope_offset: loc.scope_offset,
        scope_path: loc.scope_path,
        page: loc.page,
        index_in_page: loc.index_in_page,
    })
}

/* ==========================================================================================
 * 3.3 文件预览、导出与取证发现 Commands
 * ========================================================================================== */

pub fn cmd_preview_file_page(
    state: &Arc<AppState>,
    entry_id: &str,
    page: usize,
    page_bytes: Option<usize>,
    encoding: &str,
) -> Result<PreviewPageResponse, String> {
    let (image_path, is_large, entry) = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        let image = view
            .image_path
            .clone()
            .ok_or_else(|| "请先加载镜像".to_string())?;
        let (_, entry) = view
            .resolve_entry(entry_id)
            .ok_or_else(|| format!("未在当前清单中找到条目：{entry_id}"))?;
        (image, view.is_large_image, entry)
    };

    if is_large
        && let Ok(mut cg) = state.case_lock.try_lock()
        && let Some(case) = cg.as_mut()
    {
        case.check_source().map_err(|e| e.to_string())?;
    }

    let enc = PreviewEncoding::parse(encoding).map_err(|e| e.to_string())?;
    let pb = page_bytes.unwrap_or(tracedesk_core::PAGE_BYTES).max(64);
    let res =
        preview_entry_page(&image_path, &entry, page, pb, enc, None).map_err(|e| e.to_string())?;

    let hex_rows: Vec<HexRowDto> = res
        .hex_rows
        .into_iter()
        .map(|r| HexRowDto {
            offset_hex: r.offset_hex,
            bytes_hex: r.bytes_hex,
            chars: r.chars,
        })
        .collect();

    Ok(PreviewPageResponse {
        page: res.page,
        total_pages: res.total_pages,
        size: res.readable_size,
        recorded_size: res.recorded_size,
        read_note: res.read_note,
        source_note: res.source_note,
        text: res.text,
        hex_rows,
        is_image_candidate: res.is_image_candidate,
    })
}

pub fn cmd_preview_file_image(
    state: &Arc<AppState>,
    entry_id: &str,
) -> Result<PreviewImageResponse, String> {
    let (image_path, is_large, entry) = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        let image = view
            .image_path
            .clone()
            .ok_or_else(|| "请先加载镜像".to_string())?;
        let (_, entry) = view
            .resolve_entry(entry_id)
            .ok_or_else(|| format!("未在当前清单中找到条目：{entry_id}"))?;
        (image, view.is_large_image, entry)
    };

    if is_large
        && let Ok(mut cg) = state.case_lock.try_lock()
        && let Some(case) = cg.as_mut()
    {
        case.check_source().map_err(|e| e.to_string())?;
    }

    let res = preview_entry_image(&image_path, &entry, None).map_err(|e| e.to_string())?;
    Ok(PreviewImageResponse {
        ok: res.ok,
        data_url: res.data_url,
        width: res.width,
        height: res.height,
        animated: Some(res.animated),
        error: res.error,
        source_note: res.source_note,
    })
}

pub fn cmd_export_file(
    state: &Arc<AppState>,
    entry_id: &str,
) -> Result<ExportFileResponse, String> {
    let entry = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        view.resolve_entry(entry_id)
            .map(|(_, e)| e)
            .ok_or_else(|| format!("未在当前清单中找到条目：{entry_id}"))?
    };

    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let dest = case.export(&entry, None).map_err(|e| e.to_string())?;
    let dest_str = dest.to_string_lossy().into_owned();

    let (title, note) = match case.data().exports.last() {
        Some(record) => {
            let t = if record.size < entry.size {
                "部分导出"
            } else {
                "导出成功"
            };
            let del_sum = deleted_export_summary(record);
            let sv = record.source_verification.as_deref().unwrap_or("");
            let parts: Vec<&str> = [del_sum.as_str(), sv]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect();
            (t.to_string(), parts.join(" · "))
        }
        None => ("导出成功".to_string(), String::new()),
    };

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, false);
    let snapshot = view.snapshot.clone().expect("snapshot updated");

    Ok(ExportFileResponse {
        path: dest_str,
        title,
        note,
        snapshot,
    })
}

pub fn cmd_record_finding_note(
    state: &Arc<AppState>,
    entry_id: &str,
    note: &str,
) -> Result<SnapshotResponse, String> {
    let entry = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        view.resolve_entry(entry_id)
            .map(|(_, e)| e)
            .ok_or_else(|| format!("未在当前清单中找到条目：{entry_id}"))?
    };

    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    record_note(case, &entry, note).map_err(|e| e.to_string())?;

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, false);
    let snapshot = view.snapshot.clone().expect("snapshot updated");
    Ok(SnapshotResponse { snapshot })
}

pub fn cmd_examine_file(
    state: &Arc<AppState>,
    entry_id: &str,
    comparison_path: Option<&str>,
) -> Result<ExamineFileResponse, String> {
    let entry = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        view.resolve_entry(entry_id)
            .map(|(_, e)| e)
            .ok_or_else(|| format!("未在当前清单中找到条目：{entry_id}"))?
    };

    let cmp_clean = comparison_path
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let res = examine(case, &entry, cmp_clean.as_deref(), None).map_err(|e| e.to_string())?;
    let d = &res.details;

    let title = if cmp_clean.is_some() {
        "校验文件一致性".to_string()
    } else {
        "计算文件 SHA-256".to_string()
    };
    let size = d.get("size").and_then(Value::as_u64).unwrap_or(entry.size);
    let recorded_size = d
        .get("recorded_size")
        .and_then(Value::as_u64)
        .unwrap_or(entry.size);
    let sha256 = d
        .get("sha256")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let comparison_sha256 = d
        .get("comparison_sha256")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let read_note = d
        .get("read_note")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let source_note = d
        .get("source_note")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let source_verification = d
        .get("source_verification")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, false);
    let snapshot = view.snapshot.clone().expect("snapshot updated");

    Ok(ExamineFileResponse {
        title,
        path: entry.path,
        result: res.result,
        size,
        recorded_size,
        sha256,
        comparison_path: cmp_clean.map(|p| p.to_string_lossy().into_owned()),
        comparison_sha256,
        read_note,
        source_note,
        source_verification,
        snapshot,
    })
}

fn format_finding_group_key(g: &FindingGroup) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        g.key.subject,
        g.key.offset,
        g.key.inode,
        g.key.deleted,
        g.key.image_sha256.as_deref().unwrap_or("")
    )
}

pub fn cmd_list_findings(
    state: &Arc<AppState>,
    status: Option<&str>,
    offset: Option<&str>,
    keyword: Option<&str>,
    sort_column: &str,
    descending: bool,
) -> Result<ListFindingsResponse, String> {
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let Some(case) = case_guard.as_mut() else {
        return Ok(ListFindingsResponse {
            status_text: "尚未打开案件".to_string(),
            filter_options: FindingFilterOptionsDto {
                statuses: Vec::new(),
                offsets: Vec::new(),
            },
            groups: Vec::new(),
        });
    };

    let records = match case.check_audit() {
        Ok(r) => r,
        Err(err) => {
            return Ok(ListFindingsResponse {
                status_text: format!("操作记录校验失败：{err}"),
                filter_options: FindingFilterOptionsDto {
                    statuses: Vec::new(),
                    offsets: Vec::new(),
                },
                groups: Vec::new(),
            });
        }
    };

    let mut raw_groups = group_findings(&records);
    let total_group_count = raw_groups.len();
    let status_text = if total_group_count > 0 {
        format!("取证发现 · {total_group_count} 个文件 · 日志链校验通过")
    } else {
        "尚无取证发现 · 右键文件可记录笔记、计算摘要或比对副本".to_string()
    };

    // Match FindingsPanel.set_text: sort original groups ascending by (display_time(last.timestamp), last.seq)
    // and assign 1-based `seq` in that order.
    raw_groups.sort_by(|a, b| {
        let a_last = a.records.last();
        let b_last = b.records.last();
        let a_key = (
            a_last
                .map(|r| display_iso_time(&r.timestamp, false))
                .unwrap_or_default(),
            a_last.map(|r| r.seq).unwrap_or(0),
        );
        let b_key = (
            b_last
                .map(|r| display_iso_time(&r.timestamp, false))
                .unwrap_or_default(),
            b_last.map(|r| r.seq).unwrap_or(0),
        );
        a_key.cmp(&b_key)
    });

    let mut statuses_set: BTreeSet<String> = BTreeSet::new();
    let mut offsets_set: BTreeSet<u64> = BTreeSet::new();
    let mut all_dtos: Vec<(String, FindingGroupDto)> = Vec::with_capacity(raw_groups.len());

    for (idx, g) in raw_groups.into_iter().enumerate() {
        let group_seq = idx + 1;
        let status_label = if g.key.deleted { "已删除" } else { "现存" }.to_string();
        statuses_set.insert(status_label.clone());
        offsets_set.insert(g.key.offset);

        let latest_full = g
            .records
            .last()
            .map(|r| display_iso_time(&r.timestamp, false))
            .unwrap_or_default();
        let latest_compact = g
            .records
            .last()
            .map(|r| display_iso_time(&r.timestamp, true))
            .unwrap_or_default();
        let group_key = format_finding_group_key(&g);

        let rec_dtos: Vec<FindingRecordDto> = g
            .records
            .into_iter()
            .map(|r| {
                let origin_enum = audit_origin(&r);
                let origin_label = audit_origin_label(&r);
                let mcp_user = audit_mcp_user(&r);
                let op_title = operation_title(&r.action).unwrap_or(&r.action).to_string();
                FindingRecordDto {
                    seq: r.seq,
                    timestamp: display_iso_time(&r.timestamp, true),
                    action: r.action,
                    action_title: Some(op_title),
                    origin: origin_enum.as_str().to_string(),
                    origin_label: Some(origin_label),
                    mcp_user,
                    actor: r.actor,
                    result: r.result,
                    details: r.details,
                }
            })
            .collect();

        all_dtos.push((
            latest_full,
            FindingGroupDto {
                group_key,
                seq: group_seq,
                subject: g.key.subject,
                status: status_label,
                deleted: g.key.deleted,
                offset: g.key.offset,
                inode: g.key.inode,
                image_sha256: g.key.image_sha256.unwrap_or_default(),
                count: rec_dtos.len(),
                latest_time: latest_compact,
                records: rec_dtos,
            },
        ));
    }

    let status_filter = status.map(str::trim).filter(|s| !s.is_empty());
    let offset_filter = offset.map(str::trim).filter(|s| !s.is_empty());
    let kw_filter = keyword
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);

    let mut filtered: Vec<(String, FindingGroupDto)> = all_dtos
        .into_iter()
        .filter(|(_, g)| {
            if let Some(sf) = status_filter
                && g.status != sf
            {
                return false;
            }
            if let Some(of) = offset_filter
                && g.offset.to_string() != of
            {
                return false;
            }
            if let Some(ref kw) = kw_filter {
                let rec_json = serde_json::to_string(&g.records).unwrap_or_default();
                let hay = format!(
                    "{} {} {} {} {} {} {} {rec_json}",
                    g.seq, g.subject, g.status, g.offset, g.inode, g.count, g.latest_time
                )
                .to_lowercase();
                if !hay.contains(kw) {
                    return false;
                }
            }
            true
        })
        .collect();

    filtered.sort_by(|(a_iso, a), (b_iso, b)| {
        let cmp = if sort_column == "seq" {
            a.seq.cmp(&b.seq)
        } else {
            (a_iso.as_str(), a.seq).cmp(&(b_iso.as_str(), b.seq))
        };
        if descending { cmp.reverse() } else { cmp }
    });

    Ok(ListFindingsResponse {
        status_text,
        filter_options: FindingFilterOptionsDto {
            statuses: statuses_set.into_iter().collect(),
            offsets: offsets_set.into_iter().map(|o| o.to_string()).collect(),
        },
        groups: filtered.into_iter().map(|(_, g)| g).collect(),
    })
}

pub fn cmd_export_findings(
    state: &Arc<AppState>,
    group_keys: &[String],
) -> Result<ExportFindingsResponse, String> {
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let records = case.check_audit().map_err(|e| e.to_string())?;
    let all_groups = group_findings(&records);

    let target_groups: Vec<FindingGroup> = if group_keys.is_empty() {
        all_groups
    } else {
        let mut by_key: HashMap<String, FindingGroup> = all_groups
            .into_iter()
            .map(|g| (format_finding_group_key(&g), g))
            .collect();
        let mut selected = Vec::with_capacity(group_keys.len());
        for k in group_keys {
            if let Some(g) = by_key.remove(k) {
                selected.push(g);
            } else {
                // Fallback match without trailing image_sha256 for compatibility with 4-part keys.
                let found_key = by_key
                    .keys()
                    .find(|cand| cand.starts_with(&format!("{k}|")))
                    .cloned();
                if let Some(fk) = found_key
                    && let Some(g) = by_key.remove(&fk)
                {
                    selected.push(g);
                }
            }
        }
        selected
    };

    let res = core_export_findings(case, &target_groups).map_err(|e| e.to_string())?;
    let mut note = format!(
        "已导出 {} 个证据文件至 exports 目录，并生成汇总清单。",
        res.exported_count
    );
    if !res.failed.is_empty() {
        note.push_str(&format!(
            "\n另有 {} 项未能导出，详见汇总清单。",
            res.failed.len()
        ));
    }

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, false);
    let snapshot = view.snapshot.clone().expect("snapshot updated");

    Ok(ExportFindingsResponse {
        summary_path: res.summary_path.to_string_lossy().into_owned(),
        exported_count: res.exported_count,
        failed_count: res.failed.len(),
        note,
        snapshot,
    })
}

/* ==========================================================================================
 * 3.4 时间线、审计、内容搜索与复核包 Commands
 * ========================================================================================== */

pub fn cmd_build_timeline(state: &Arc<AppState>) -> Result<BuildTimelineResponse, String> {
    let entries = {
        let case_guard = state
            .case_lock
            .lock()
            .map_err(|_| "案件状态锁异常".to_string())?;
        let case = case_guard
            .as_ref()
            .ok_or_else(|| "请先新建或打开案件".to_string())?;
        if case.browsing_directories() {
            return Err("请先在文件浏览中建立完整文件索引以生成全案时间线。".to_string());
        }
        case.data().inventory.clone()
    };

    let tl = TimelineIndex::build(entries);
    let total = tl.len();
    let opts = tl.filter_options();
    let hint = format!(
        "MACB 时间线 · {total} 条事件 · UTC+8 · C 为元数据变更，B 为创建；FAT 不保存 C 时间"
    );

    if let Ok(mut view) = state.view.write() {
        view.timeline_index = Some(tl);
    }

    Ok(BuildTimelineResponse {
        total,
        hint,
        filter_options: TimelineFilterOptionsDto {
            events: opts.events,
            statuses: opts.statuses,
            offsets: opts.offsets,
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_query_timeline_page(
    state: &Arc<AppState>,
    query: &str,
    event: Option<&str>,
    status: Option<&str>,
    offset: Option<&str>,
    _sort_column: &str,
    descending: bool,
    page: usize,
    page_size: usize,
) -> Result<QueryTimelinePageResponse, String> {
    // Ensure timeline is built in ViewCache.
    let needs_build = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        if view.snapshot.is_none() {
            return Ok(QueryTimelinePageResponse {
                total: 0,
                total_events: 0,
                page: 0,
                total_pages: 1,
                items: Vec::new(),
            });
        }
        view.timeline_index.is_none()
    };
    if needs_build {
        let _ = cmd_build_timeline(state)?;
    }

    let view = state
        .view
        .read()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    let Some(ref tl) = view.timeline_index else {
        return Ok(QueryTimelinePageResponse {
            total: 0,
            total_events: 0,
            page: 0,
            total_pages: 1,
            items: Vec::new(),
        });
    };

    let filter = TimelineFilter {
        query: query.to_string(),
        event: event
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        status: status
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        offset: offset
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<u64>().ok()),
    };

    let res = tl
        .query_page(&filter, descending, page, page_size)
        .map_err(|e| e.to_string())?;
    let items: Vec<TimelineRowDto> = res
        .items
        .into_iter()
        .map(|r| TimelineRowDto {
            number: r.number,
            time: display_iso_time(&r.time, true),
            event: r.event,
            status: r.status,
            offset: r.offset,
            inode: r.inode,
            path: r.path,
        })
        .collect();

    Ok(QueryTimelinePageResponse {
        total: res.total,
        total_events: res.total_events,
        page: res.page,
        total_pages: res.total_pages,
        items,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_list_audit_log(
    state: &Arc<AppState>,
    query: &str,
    origin: Option<&str>,
    actor: Option<&str>,
    action: Option<&str>,
    result: Option<&str>,
    sort_column: &str,
    descending: bool,
) -> Result<ListAuditLogResponse, String> {
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let Some(case) = case_guard.as_mut() else {
        return Ok(ListAuditLogResponse {
            valid: true,
            status_text: "尚未打开案件".to_string(),
            filter_options: AuditFilterOptionsDto {
                origins: Vec::new(),
                actors: Vec::new(),
                actions: Vec::new(),
                results: Vec::new(),
            },
            records: Vec::new(),
        });
    };

    let raw_records = match case.check_audit() {
        Ok(r) => r,
        Err(err) => {
            return Ok(ListAuditLogResponse {
                valid: false,
                status_text: format!("日志校验失败：{err}"),
                filter_options: AuditFilterOptionsDto {
                    origins: Vec::new(),
                    actors: Vec::new(),
                    actions: Vec::new(),
                    results: Vec::new(),
                },
                records: Vec::new(),
            });
        }
    };

    let mcp_count = raw_records
        .iter()
        .filter(|r| audit_origin(r) == AuditOrigin::Mcp)
        .count();
    let manual_count = raw_records.len() - mcp_count;
    let status_text = format!(
        "日志链校验通过 · 共 {} 条操作（人工 {manual_count} · MCP {mcp_count}）",
        raw_records.len()
    );

    let mut has_manual_origin = false;
    let mut has_mcp_origin = false;
    let mut specific_mcp_origins: BTreeSet<String> = BTreeSet::new();
    let mut actors_set: BTreeSet<String> = BTreeSet::new();
    let mut actions_set: BTreeSet<String> = BTreeSet::new();
    let mut results_set: BTreeSet<String> = BTreeSet::new();

    let mut all_dtos: Vec<(String, AuditRecordDto)> = Vec::with_capacity(raw_records.len());
    for r in raw_records {
        let orig = audit_origin(&r);
        let orig_label = audit_origin_label(&r);
        let mcp_user = audit_mcp_user(&r);
        let act_title = action_title(&r.action).to_string();
        let full_time = display_iso_time(&r.timestamp, false);
        let compact_time = display_iso_time(&r.timestamp, true);

        match orig {
            AuditOrigin::Manual => has_manual_origin = true,
            AuditOrigin::Mcp => {
                has_mcp_origin = true;
                if orig_label != AuditOrigin::Mcp.label() {
                    specific_mcp_origins.insert(orig_label.clone());
                }
            }
        }
        if !r.actor.is_empty() {
            actors_set.insert(r.actor.clone());
        }
        if !act_title.is_empty() {
            actions_set.insert(act_title.clone());
        }
        if !r.result.is_empty() {
            results_set.insert(r.result.clone());
        }

        all_dtos.push((
            full_time,
            AuditRecordDto {
                seq: r.seq,
                timestamp: compact_time,
                origin: orig.as_str().to_string(),
                origin_label: orig_label,
                mcp_user,
                actor: r.actor,
                action: r.action,
                action_title: act_title,
                result: r.result,
                subject: r.subject,
                details: r.details,
                previous: r.previous,
                hash: r.hash,
            },
        ));
    }

    // 来源筛选选项始终保留顶层大类（“人工” / “MCP”），并追加具体“MCP · <使用者>”细项以便按调用方精筛。
    let mut origin_options: Vec<String> = Vec::new();
    if has_manual_origin {
        origin_options.push(AuditOrigin::Manual.label().to_string());
    }
    if has_mcp_origin {
        origin_options.push(AuditOrigin::Mcp.label().to_string());
        origin_options.extend(specific_mcp_origins);
    }

    let origin_f = origin.map(str::trim).filter(|s| !s.is_empty());
    let actor_f = actor.map(str::trim).filter(|s| !s.is_empty());
    let action_f = action.map(str::trim).filter(|s| !s.is_empty());
    let result_f = result.map(str::trim).filter(|s| !s.is_empty());
    let q_f = {
        let t = query.trim();
        (!t.is_empty()).then(|| t.to_lowercase())
    };

    let mut filtered: Vec<(String, AuditRecordDto)> = all_dtos
        .into_iter()
        .filter(|(_, r)| {
            if let Some(of) = origin_f {
                // 选择 “MCP” / “mcp” 时匹配全部 MCP 记录，选择 “MCP · <使用者>” 时精确匹配该调用方。
                let matches_origin = r.origin_label == of
                    || r.origin.eq_ignore_ascii_case(of)
                    || (of == "人工" && r.origin == "manual")
                    || (of.eq_ignore_ascii_case("mcp") && r.origin == "mcp");
                if !matches_origin {
                    return false;
                }
            }
            if let Some(af) = actor_f
                && r.actor != af
            {
                return false;
            }
            if let Some(acf) = action_f
                && r.action_title != acf
                && r.action != acf
            {
                return false;
            }
            if let Some(rf) = result_f
                && r.result != rf
            {
                return false;
            }
            if let Some(ref kw) = q_f {
                let details_str = serde_json::to_string(&r.details).unwrap_or_default();
                let mcp_user_str = r.mcp_user.as_deref().unwrap_or("");
                let hay = format!(
                    "{} {} {} {} {mcp_user_str} {} {} {} {} {} {details_str} {} {}",
                    r.seq,
                    r.timestamp,
                    r.origin,
                    r.origin_label,
                    r.actor,
                    r.action_title,
                    r.action,
                    r.result,
                    r.subject,
                    r.previous,
                    r.hash
                )
                .to_lowercase();
                if !hay.contains(kw) {
                    return false;
                }
            }
            true
        })
        .collect();

    filtered.sort_by(|(a_iso, a), (b_iso, b)| {
        let cmp = if sort_column == "time" {
            (a_iso.as_str(), a.seq).cmp(&(b_iso.as_str(), b.seq))
        } else {
            a.seq.cmp(&b.seq)
        };
        if descending { cmp.reverse() } else { cmp }
    });

    Ok(ListAuditLogResponse {
        valid: true,
        status_text,
        filter_options: AuditFilterOptionsDto {
            origins: origin_options,
            actors: actors_set.into_iter().collect(),
            actions: actions_set.into_iter().collect(),
            results: results_set.into_iter().collect(),
        },
        records: filtered.into_iter().map(|(_, r)| r).collect(),
    })
}

pub fn cmd_start_content_search(
    state: &Arc<AppState>,
    query: &str,
    encoding: &str,
    selected_entry_id: Option<&str>,
    app: Option<&AppHandle>,
) -> Result<StartContentSearchResponse, String> {
    let needle = parse_pattern(query, encoding).map_err(|e| e.to_string())?;
    let needle_hex = hex_lower(&needle);

    let (selected_entry, image_sha256, source_note, entry_lookup) = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        let snap = view
            .snapshot
            .as_ref()
            .ok_or_else(|| "请先新建或打开案件".to_string())?;
        let ev = snap
            .evidence
            .as_ref()
            .ok_or_else(|| "请先加载镜像".to_string())?;
        let selected = match selected_entry_id.map(str::trim).filter(|s| !s.is_empty()) {
            Some(eid) => {
                let (_, e) = view
                    .resolve_entry(eid)
                    .ok_or_else(|| format!("未在当前清单中找到选中文件：{eid}"))?;
                Some(e)
            }
            None => {
                if snap.browsing_directories {
                    return Err("全案搜索需要先在文件浏览中建立完整文件索引，亦可选择搜索单个文件。".to_string());
                }
                None
            }
        };

        let mut map: HashMap<(u64, String, bool, String), (String, InventoryEntry)> =
            HashMap::with_capacity(view.browser_index.ordered().len());
        for (idx, row) in view.browser_index.ordered().iter().enumerate() {
            map.insert(
                (row.offset, row.inode.clone(), row.deleted, row.path.clone()),
                (idx.to_string(), row.clone()),
            );
        }
        (
            selected,
            ev.sha256.clone(),
            snap.source_note.clone(),
            Arc::new(map),
        )
    };

    let search_id = format!("search-{}", Uuid::new_v4().simple());
    let cancel = Arc::new(AtomicBool::new(false));
    let session = SearchSessionState {
        search_id: search_id.clone(),
        query: query.to_string(),
        encoding: encoding.to_string(),
        needle_hex: needle_hex.clone(),
        image_sha256,
        verification: if source_note.is_empty() {
            "搜索进行中（实时命中）".to_string()
        } else {
            source_note
        },
        report_name: None,
        cancel: Arc::clone(&cancel),
        running: true,
        hits: Vec::new(),
    };

    if let Ok(mut searches) = state.searches.lock() {
        searches.insert(search_id.clone(), session);
    }

    let state_clone = Arc::clone(state);
    let sid = search_id.clone();
    let q_owned = query.to_string();
    let enc_owned = encoding.to_string();
    let app_clone = app.cloned();

    if app_clone.is_some() {
        thread::Builder::new()
            .name(format!("tracedesk-search-{sid}"))
            .spawn(move || {
                run_content_search_worker(
                    state_clone,
                    sid,
                    q_owned,
                    enc_owned,
                    selected_entry,
                    cancel,
                    entry_lookup,
                    app_clone,
                );
            })
            .map_err(|e| format!("无法启动后台内容搜索线程：{e}"))?;
    } else {
        // Synchronous execution when called from direct Rust tests without an AppHandle.
        run_content_search_worker(
            state_clone,
            sid,
            q_owned,
            enc_owned,
            selected_entry,
            cancel,
            entry_lookup,
            None,
        );
    }

    Ok(StartContentSearchResponse {
        search_id,
        needle_hex,
    })
}

type EntryLookupMap = HashMap<(u64, String, bool, String), (String, InventoryEntry)>;

#[allow(clippy::too_many_arguments)]
fn run_content_search_worker(
    state: Arc<AppState>,
    search_id: String,
    query: String,
    encoding: String,
    selected: Option<InventoryEntry>,
    cancel: Arc<AtomicBool>,
    entry_lookup: Arc<EntryLookupMap>,
    app: Option<AppHandle>,
) {
    let mut next_hit_index = 0usize;
    let mut pending_batch: Vec<SearchHitDto> = Vec::with_capacity(256);
    let mut last_hits_emit = Instant::now();
    let last_prog_emit = std::sync::Mutex::new(Instant::now() - Duration::from_secs(1));

    let progress_cb = |stage: &str, done: u64, total: u64| {
        if let Some(ref handle) = app
            && let Ok(mut last) = last_prog_emit.lock()
            && (done >= total || last.elapsed() >= Duration::from_millis(50))
        {
            *last = Instant::now();
            let _ = handle.emit(
                "search:progress",
                SearchProgressEvent {
                    search_id: search_id.clone(),
                    stage: stage.to_string(),
                    done,
                    total,
                },
            );
        }
    };

    let mut hit_cb = |batch: &[SearchHit]| {
        if batch.is_empty() {
            return;
        }
        let mut stored_chunk = Vec::with_capacity(batch.len());
        for h in batch {
            let key = (h.offset, h.inode.clone(), h.deleted, h.path.clone());
            let (entry_id, entry_obj) = match entry_lookup.get(&key) {
                Some((id, e)) => (id.clone(), e.clone()),
                None => (
                    format!(
                        "{}:{}:{}:{}",
                        h.offset,
                        h.inode,
                        if h.deleted { 1 } else { 0 },
                        h.path
                    ),
                    InventoryEntry {
                        offset: h.offset,
                        inode: h.inode.clone(),
                        path: h.path.clone(),
                        deleted: h.deleted,
                        reallocated: h.reallocated,
                        directory: false,
                        mode: "r/rrwxrwxrwx".to_string(),
                        size: h.file_byte.saturating_add(4096),
                        mtime: 0,
                        atime: 0,
                        ctime: 0,
                        crtime: 0,
                        filesystem: String::new(),
                        start_cluster_allocated: None,
                        extents: None,
                    },
                ),
            };
            let dto = SearchHitDto {
                hit_index: next_hit_index,
                entry_id,
                pos: h.file_byte,
                offset: h.offset,
                inode: h.inode.clone(),
                path: h.path.clone(),
                deleted: Some(h.deleted),
                reallocated: Some(h.reallocated),
                before_hex: h.before.clone(),
                after_hex: h.after.clone(),
            };
            next_hit_index += 1;
            pending_batch.push(dto.clone());
            stored_chunk.push(StoredSearchHit {
                dto,
                entry: entry_obj,
                source_note: h.source_note.clone(),
            });
        }

        if let Ok(mut searches) = state.searches.lock()
            && let Some(sess) = searches.get_mut(&search_id)
        {
            sess.hits.extend(stored_chunk);
        }

        if let Some(ref handle) = app
            && (pending_batch.len() >= 256 || last_hits_emit.elapsed() >= Duration::from_millis(45))
        {
            for chunk in pending_batch.chunks(500) {
                let _ = handle.emit(
                    "search:hits",
                    SearchHitsEvent {
                        search_id: search_id.clone(),
                        hits: chunk.to_vec(),
                    },
                );
            }
            pending_batch.clear();
            last_hits_emit = Instant::now();
        }
    };

    let search_res = {
        let mut case_guard = match state.case_lock.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let Some(case) = case_guard.as_mut() else {
            return;
        };
        let out = search_case(
            case,
            &SearchOptions {
                query,
                encoding,
                limit: None,
                selected,
            },
            &cancel,
            Some(&progress_cb),
            Some(&mut hit_cb),
            None,
        );
        let snap = if let Ok(mut view) = state.view.write() {
            view.sync_from_case(case, false);
            view.snapshot.clone()
        } else {
            None
        };
        (out, snap)
    };

    // Flush any remaining hits before emitting search:finished!
    if let Some(ref handle) = app
        && !pending_batch.is_empty()
    {
        for chunk in pending_batch.chunks(500) {
            let _ = handle.emit(
                "search:hits",
                SearchHitsEvent {
                    search_id: search_id.clone(),
                    hits: chunk.to_vec(),
                },
            );
        }
        pending_batch.clear();
    }

    let finished_ev = match search_res {
        (Ok(output), snap) => {
            if let Ok(mut searches) = state.searches.lock()
                && let Some(sess) = searches.get_mut(&search_id)
            {
                sess.running = false;
                sess.verification = output.record.verification.clone();
                sess.image_sha256 = output.record.image_sha256.clone();
                sess.report_name = Some(output.report_name.clone());
            }
            SearchFinishedEvent {
                search_id: search_id.clone(),
                error: None,
                status: Some(output.record.status),
                visited: Some(output.record.visited),
                eligible: Some(output.record.eligible),
                total_hits: Some(output.record.hits.len()),
                errors_count: Some(output.record.errors.len()),
                verification: Some(output.record.verification),
                report_name: Some(output.report_name),
                snapshot: snap,
            }
        }
        (Err(err), snap) if err.is_cancelled() || cancel.load(Ordering::Relaxed) => {
            if let Ok(mut searches) = state.searches.lock()
                && let Some(sess) = searches.get_mut(&search_id)
            {
                sess.running = false;
            }
            SearchFinishedEvent {
                search_id: search_id.clone(),
                error: None,
                status: Some("已取消".to_string()),
                visited: Some(0),
                eligible: Some(0),
                total_hits: Some(next_hit_index),
                errors_count: Some(0),
                verification: Some("已取消".to_string()),
                report_name: None,
                snapshot: snap,
            }
        }
        (Err(err), snap) => {
            if let Ok(mut searches) = state.searches.lock()
                && let Some(sess) = searches.get_mut(&search_id)
            {
                sess.running = false;
            }
            SearchFinishedEvent {
                search_id: search_id.clone(),
                error: Some(err.to_string()),
                status: None,
                visited: None,
                eligible: None,
                total_hits: None,
                errors_count: None,
                verification: None,
                report_name: None,
                snapshot: snap,
            }
        }
    };

    if let Some(ref handle) = app {
        let _ = handle.emit("search:finished", finished_ev);
    }
}

pub fn cmd_cancel_content_search(
    state: &Arc<AppState>,
    search_id: &str,
) -> Result<CancelResponse, String> {
    if let Ok(searches) = state.searches.lock()
        && let Some(sess) = searches.get(search_id)
    {
        sess.cancel.store(true, Ordering::Relaxed);
    }
    Ok(CancelResponse { cancelled: true })
}

pub fn cmd_bookmark_search_hits(
    state: &Arc<AppState>,
    search_id: &str,
    hit_indices: &[usize],
) -> Result<BookmarkSearchHitsResponse, String> {
    let (query, encoding, needle_hex, image_sha256, verification, report_name, selected_hits) = {
        let searches = state
            .searches
            .lock()
            .map_err(|_| "搜索状态锁异常".to_string())?;
        let sess = searches
            .get(search_id)
            .ok_or_else(|| format!("未找到对应的内容搜索会话：{search_id}"))?;
        let mut chosen = Vec::with_capacity(hit_indices.len());
        for &idx in hit_indices {
            if let Some(h) = sess.hits.get(idx) {
                chosen.push(h.clone());
            }
        }
        (
            sess.query.clone(),
            sess.encoding.clone(),
            sess.needle_hex.clone(),
            sess.image_sha256.clone(),
            sess.verification.clone(),
            sess.report_name
                .clone()
                .unwrap_or_else(|| "实时搜索中".to_string()),
            chosen,
        )
    };

    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let mut saved_count = 0usize;
    for item in selected_hits {
        let pos = item.dto.pos;
        let entry = &item.entry;
        let src_note = if !item.source_note.is_empty() {
            item.source_note
        } else {
            deleted_source_note(entry).to_string()
        };
        let mut details = Map::new();
        details.insert("offset".to_string(), Value::from(entry.offset));
        details.insert("inode".to_string(), Value::String(entry.inode.clone()));
        details.insert("deleted".to_string(), Value::from(entry.deleted));
        details.insert(
            "image_sha256".to_string(),
            image_sha256
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "source_verification".to_string(),
            Value::String(verification.clone()),
        );
        details.insert(
            "note".to_string(),
            Value::String(format!(
                "内容命中：{query}；{encoding}；文件内字节偏移 {pos}"
            )),
        );
        details.insert("file_byte".to_string(), Value::from(pos));
        details.insert("needle".to_string(), Value::String(needle_hex.clone()));
        details.insert("before".to_string(), Value::String(item.dto.before_hex));
        details.insert("after".to_string(), Value::String(item.dto.after_hex));
        details.insert(
            "search_record".to_string(),
            Value::String(report_name.clone()),
        );
        details.insert("source_note".to_string(), Value::String(src_note));
        details.insert("reallocated".to_string(), Value::from(entry.reallocated));

        case.log("FILE_NOTE", &entry.path, "成功", details)
            .map_err(|e| e.to_string())?;
        saved_count += 1;
    }

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, false);
    let snapshot = view.snapshot.clone().expect("snapshot updated");

    Ok(BookmarkSearchHitsResponse {
        saved_count,
        snapshot,
    })
}

pub fn cmd_load_search_record(
    state: &Arc<AppState>,
    report_name: &str,
) -> Result<Vec<SearchHitDto>, String> {
    let (case_folder, entry_lookup) = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        let folder = view
            .case_folder
            .clone()
            .ok_or_else(|| "请先新建或打开案件".to_string())?;
        let mut map = HashMap::new();
        for (idx, row) in view.browser_index.ordered().iter().enumerate() {
            map.insert(
                (row.offset, row.inode.clone(), row.deleted, row.path.clone()),
                idx.to_string(),
            );
        }
        (folder, map)
    };
    let clean_name = Path::new(report_name.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "搜索记录文件名无效".to_string())?;
    let report_path = case_folder.join("reports").join(clean_name);
    let raw = fs::read_to_string(&report_path)
        .map_err(|e| format!("无法读取历史搜索记录 {clean_name}：{e}"))?;
    let record: SearchRecord =
        serde_json::from_str(&raw).map_err(|e| format!("历史搜索记录格式错误：{e}"))?;

    let dtos: Vec<SearchHitDto> = record
        .hits
        .into_iter()
        .enumerate()
        .map(|(idx, h)| {
            let entry_id = entry_lookup
                .get(&(h.offset, h.inode.clone(), h.deleted, h.path.clone()))
                .cloned()
                .unwrap_or_else(|| {
                    format!(
                        "{}:{}:{}:{}",
                        h.offset,
                        h.inode,
                        if h.deleted { 1 } else { 0 },
                        h.path
                    )
                });
            SearchHitDto {
                hit_index: idx,
                entry_id,
                pos: h.file_byte,
                offset: h.offset,
                inode: h.inode,
                path: h.path,
                deleted: Some(h.deleted),
                reallocated: Some(h.reallocated),
                before_hex: h.before,
                after_hex: h.after,
            }
        })
        .collect();
    Ok(dtos)
}

pub fn cmd_generate_report(state: &Arc<AppState>) -> Result<PathAndSnapshotResponse, String> {
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let path = case.report(None).map_err(|e| e.to_string())?;

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, false);
    let snapshot = view.snapshot.clone().expect("snapshot updated");

    Ok(PathAndSnapshotResponse {
        path: path.to_string_lossy().into_owned(),
        snapshot,
    })
}

pub fn cmd_inspect_bundle_materials(
    state: &Arc<AppState>,
) -> Result<BundleMaterialsResponse, String> {
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let export_rows = inspect_bundle_exports(case).map_err(|e| e.to_string())?;
    let search_rows = inspect_bundle_searches(case).map_err(|e| e.to_string())?;

    let missing_exports: Vec<_> = export_rows.iter().filter(|r| !r.exists).cloned().collect();
    let missing_searches: Vec<_> = search_rows.iter().filter(|r| !r.exists).cloned().collect();
    let missing_text = format_missing_materials(&missing_exports, &missing_searches);

    let exports = export_rows
        .into_iter()
        .map(|r| BundleExportRowDto {
            index: r.index,
            exists: r.exists,
            display_path: r.display_path,
            source: r.source,
            size: r.size,
            time: if r.time.is_empty() {
                "未记录".to_string()
            } else {
                display_iso_time(&r.time, true)
            },
            missing_reason: (!r.missing_reason.is_empty()).then_some(r.missing_reason),
        })
        .collect();

    let searches = search_rows
        .into_iter()
        .map(|r| BundleSearchRowDto {
            index: r.index,
            exists: r.exists,
            display_path: r.display_path,
            query: r.query,
            encoding: r.encoding,
            hits: r.hits,
            time: if r.time.is_empty() {
                "未记录".to_string()
            } else {
                display_iso_time(&r.time, true)
            },
            missing_reason: (!r.missing_reason.is_empty()).then_some(r.missing_reason),
        })
        .collect();

    Ok(BundleMaterialsResponse {
        exports,
        searches,
        missing_text,
    })
}

pub fn cmd_build_review_bundle(
    state: &Arc<AppState>,
    selected_export_indices: Option<Vec<usize>>,
    selected_search_indices: Option<Vec<usize>>,
) -> Result<PathAndSnapshotResponse, String> {
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let res = build_bundle(
        case,
        &BuildBundleOptions {
            selected_export_indices,
            selected_search_indices,
            skip_missing: true,
        },
        None,
    )
    .map_err(|e| e.to_string())?;

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, false);
    let snapshot = view.snapshot.clone().expect("snapshot updated");

    Ok(PathAndSnapshotResponse {
        path: res.bundle_path.to_string_lossy().into_owned(),
        snapshot,
    })
}

/* ==========================================================================================
 * 3.5 MCP 托管与系统工具 Commands
 * ========================================================================================== */

pub fn cmd_get_mcp_status(state: &Arc<AppState>, port: Option<u16>) -> Result<McpStatus, String> {
    Ok(state.build_mcp_status(port))
}

pub fn cmd_start_mcp_http(state: &Arc<AppState>, port: u16) -> Result<McpStatus, String> {
    {
        let mut srv = state
            .mcp_server
            .lock()
            .map_err(|_| "MCP 服务状态锁异常".to_string())?;
        srv.start(port, Arc::clone(state))?;
    }
    Ok(state.build_mcp_status(Some(port)))
}

pub fn cmd_stop_mcp_http(state: &Arc<AppState>) -> Result<McpStatus, String> {
    let port = {
        let mut srv = state
            .mcp_server
            .lock()
            .map_err(|_| "MCP 服务状态锁异常".to_string())?;
        let p = srv.port();
        srv.stop();
        p
    };
    Ok(state.build_mcp_status(Some(port)))
}

pub fn cmd_open_in_os(
    state: &Arc<AppState>,
    path: &str,
    reveal_folder: bool,
) -> Result<OpenInOsResponse, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Ok(OpenInOsResponse { ok: false });
    }
    let resolved = resolve_clean(Path::new(trimmed));
    if !resolved.exists() {
        return Ok(OpenInOsResponse { ok: false });
    }

    // Security guard: only open files/folders inside the current case folder, cases_dir, or root.
    let allowed = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        let in_active_case = view
            .case_folder
            .as_ref()
            .is_some_and(|cf| is_within(&resolved, cf));
        let in_cases = is_within(&resolved, &state.app_paths.cases_dir);
        let in_root = is_within(&resolved, &state.app_paths.root);
        in_active_case || in_cases || in_root
    };
    if !allowed {
        return Err("出于安全边界限制，仅允许打开案件与工作区目录内的导出结果".to_string());
    }

    #[cfg(windows)]
    {
        let mut cmd = std::process::Command::new("explorer.exe");
        if reveal_folder {
            if resolved.is_file() {
                cmd.arg(format!("/select,{}", resolved.display()));
            } else {
                cmd.arg(&resolved);
            }
        } else {
            cmd.arg(&resolved);
        }
        let ok = cmd.spawn().is_ok();
        Ok(OpenInOsResponse { ok })
    }
    #[cfg(not(windows))]
    {
        let _ = reveal_folder;
        Ok(OpenInOsResponse { ok: true })
    }
}

pub fn cmd_check_busy_before_close(state: &Arc<AppState>) -> Result<BusyCheckResponse, String> {
    Ok(state.check_busy())
}

pub fn cmd_get_guide_pages() -> Result<Vec<GuidePageDto>, String> {
    Ok(vec![
        GuidePageDto {
            index: 1,
            title: "用演示镜像走一遍流程".to_string(),
            nav_label: "快速上手：演示镜像".to_string(),
            summary: "用项目内置的 FAT16 演示镜像，5 步走通建案、浏览、预览、导出校验与报告生成闭环。".to_string(),
            image: "/assets/guide/01_quickstart.png".to_string(),
            caption: "图 1 · 工作台分区布局与演示流程五大核心入口（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 2,
            title: "创建案件、加载镜像与登记来源".to_string(),
            nav_label: "建案、加载与来源".to_string(),
            summary: "确保源镜像与案件库分离存放，在“镜像与文件系统”页核对固定摘要、卷声明范围与交付方摘要比对结果。".to_string(),
            image: "/assets/guide/02_case_and_source.png".to_string(),
            caption: "图 2 · 镜像与文件系统页：固定摘要、覆盖范围评估与来源登记（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 3,
            title: "大镜像、完整索引与 SHA-256".to_string(),
            nav_label: "大镜像与 SHA-256".to_string(),
            summary: "逻辑容量达到 1 GiB 时自动切换为按需目录浏览，可边浏览边在后台校验基线，按需建立完整索引。".to_string(),
            image: "/assets/guide/03_large_image.png".to_string(),
            caption: "图 3 · 大容量镜像按需目录浏览、完整索引与后台校验入口（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 4,
            title: "定位目录、筛选文件与多格式预览".to_string(),
            nav_label: "浏览、筛选与预览".to_string(),
            summary: "左侧保留完整目录树，筛选仅过滤当前范围列表；下方支持文本（9 编码）、图片与十六进制分页预览。".to_string(),
            image: "/assets/guide/04_browse_preview.png".to_string(),
            caption: "图 4 · 文件树、条件筛选栏与十六进制/多编码分页预览（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 5,
            title: "搜索文件内容并实时复核命中".to_string(),
            nav_label: "内容搜索与复核".to_string(),
            summary: "支持 UTF-8、UTF-16LE、GBK 与 HEX 精确字节检索，结果实时流式展示，搜索期间即可筛选、排除并保存为取证发现。".to_string(),
            image: "/assets/guide/05_content_search.png".to_string(),
            caption: "图 5 · 内容搜索与复核页：实时流式命中、三态全选与批量保存（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 6,
            title: "导出副本、恢复删除文件与取证发现".to_string(),
            nav_label: "导出与取证发现".to_string(),
            summary: "导出前后自动复核原镜像，支持已删除文件可读字节恢复；右键文件工具与“取证发现”页形成结构化证据归档。".to_string(),
            image: "/assets/guide/06_export_findings.png".to_string(),
            caption: "图 6 · 取证发现页：表头筛选排序、一键批量导出与分栏取证详情（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 7,
            title: "MACB 时间线与审计日志核验".to_string(),
            nav_label: "时间线与审计日志".to_string(),
            summary: "通过 MACB 时间线还原文件活动脉络，在审计日志中追踪人工与 MCP 全部操作并核验 SHA-256 哈希链。".to_string(),
            image: "/assets/guide/07_timeline_audit.png".to_string(),
            caption: "图 7 · 审计日志页：人工/MCP 来源筛选、正倒序切换与哈希链详情（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 8,
            title: "生成报告与交付可核验复核包".to_string(),
            nav_label: "报告与复核包".to_string(),
            summary: "生成结构化 Markdown 取证报告，并通过材料选择窗口按需构建可独立离线核验的复核包 ZIP。".to_string(),
            image: "/assets/guide/08_report_bundle.png".to_string(),
            caption: "图 8 · 复核包材料选择弹窗：缺失中文清单提示、双标签勾选与导出（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 9,
            title: "MCP 服务端接入与 AI 协同".to_string(),
            nav_label: "MCP 服务端接入".to_string(),
            summary: "内置标准 MCP 服务端 tracedesk_mcp（19 工具 + 2 资源），支持在桌面端一键复制配置、启停本地 HTTP 服务与释放案件锁。".to_string(),
            image: "/assets/guide/09_mcp_dialog.png".to_string(),
            caption: "图 9 · MCP 服务配置弹窗：案件锁释放、本地 HTTP 启停与客户端配置（点击查看大图）".to_string(),
        },
    ])
}

/* ==========================================================================================
 * Tauri #[tauri::command] Wrappers (Non-blocking via spawn_blocking for heavy I/O)
 * ========================================================================================== */

#[tauri::command]
pub async fn get_app_paths(state: State<'_, Arc<AppState>>) -> Result<AppPathsDto, String> {
    cmd_get_app_paths(&state)
}

#[tauri::command]
pub async fn suggest_case_dir(
    state: State<'_, Arc<AppState>>,
    number: String,
    examiner: String,
    target: String,
    parent_dir: Option<String>,
) -> Result<SuggestCaseDirResponse, String> {
    cmd_suggest_case_dir(&state, &number, &examiner, &target, parent_dir.as_deref())
}

#[tauri::command]
pub async fn create_case(
    state: State<'_, Arc<AppState>>,
    parent_dir: String,
    number: String,
    examiner: String,
    target: String,
    folder_name: Option<String>,
) -> Result<CaseSnapshot, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_create_case(
            &st,
            &parent_dir,
            &number,
            &examiner,
            &target,
            folder_name.as_deref(),
        )
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn open_case(
    state: State<'_, Arc<AppState>>,
    case_path: String,
) -> Result<CaseSnapshot, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_open_case(&st, &case_path))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn close_case(state: State<'_, Arc<AppState>>) -> Result<CloseCaseResponse, String> {
    cmd_close_case(&state)
}

#[tauri::command]
pub async fn release_case_lock(
    state: State<'_, Arc<AppState>>,
) -> Result<CloseCaseResponse, String> {
    cmd_close_case(&state)
}

#[tauri::command]
pub async fn get_case_snapshot(
    state: State<'_, Arc<AppState>>,
) -> Result<Option<CaseSnapshot>, String> {
    cmd_get_case_snapshot(&state)
}

#[tauri::command]
pub async fn list_recent_cases(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<RecentCaseDto>, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_list_recent_cases(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn load_image(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    image_path: String,
) -> Result<CaseSnapshot, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_load_image(&st, &image_path, Some(&app)))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn verify_integrity(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<VerifyIntegrityResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_verify_integrity(&st, Some(&app)))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn fix_hash(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<VerifyIntegrityResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_verify_integrity(&st, Some(&app)))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn cancel_verify_integrity(
    state: State<'_, Arc<AppState>>,
) -> Result<CancelResponse, String> {
    cmd_cancel_verify_integrity(&state)
}

#[tauri::command]
pub async fn register_source(
    state: State<'_, Arc<AppState>>,
    evidence_id: String,
    source: String,
    acquired: String,
    tool: String,
    expected_sha256: String,
) -> Result<CaseSnapshot, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_register_source(
            &st,
            &evidence_id,
            &source,
            &acquired,
            &tool,
            &expected_sha256,
        )
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn export_fsstat(
    state: State<'_, Arc<AppState>>,
    offset: u64,
) -> Result<PathResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_export_fsstat(&st, offset))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn scan_all_partitions(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<ScanPartitionsResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_scan_all_partitions(&st, Some(&app)))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn scan_partition(
    state: State<'_, Arc<AppState>>,
    offset: u64,
) -> Result<ScanPartitionsResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_scan_partition(&st, offset))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn cancel_scan_partitions(
    state: State<'_, Arc<AppState>>,
) -> Result<CancelResponse, String> {
    cmd_cancel_scan_partitions(&state)
}

#[tauri::command]
pub async fn cancel_task(state: State<'_, Arc<AppState>>) -> Result<CancelResponse, String> {
    cmd_cancel_task(&state)
}

#[tauri::command]
pub async fn browse_directory(
    state: State<'_, Arc<AppState>>,
    offset: u64,
    inode: Option<String>,
    path: String,
) -> Result<BrowseDirectoryResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_browse_directory(&st, offset, inode.as_deref(), &path)
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn get_tree_children(
    state: State<'_, Arc<AppState>>,
    offset: u64,
    scope_path: String,
    group_index: Option<usize>,
) -> Result<TreeChildrenResponse, String> {
    cmd_get_tree_children(&state, offset, &scope_path, group_index)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn query_files_page(
    state: State<'_, Arc<AppState>>,
    scope_offset: Option<u64>,
    scope_path: Option<String>,
    suffix: String,
    keyword: String,
    status: String,
    page: usize,
    page_size: usize,
    log_filter: Option<bool>,
) -> Result<QueryFilesPageResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_query_files_page(
            &st,
            scope_offset,
            scope_path,
            &suffix,
            &keyword,
            &status,
            page,
            page_size,
            log_filter,
        )
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn locate_file_in_scope(
    state: State<'_, Arc<AppState>>,
    entry_id: String,
) -> Result<LocateFileResponse, String> {
    cmd_locate_file_in_scope(&state, &entry_id)
}

#[tauri::command]
pub async fn preview_file_page(
    state: State<'_, Arc<AppState>>,
    entry_id: String,
    page: usize,
    page_bytes: Option<usize>,
    encoding: String,
) -> Result<PreviewPageResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_preview_file_page(&st, &entry_id, page, page_bytes, &encoding)
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn preview_file_image(
    state: State<'_, Arc<AppState>>,
    entry_id: String,
) -> Result<PreviewImageResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_preview_file_image(&st, &entry_id))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn export_file(
    state: State<'_, Arc<AppState>>,
    entry_id: String,
) -> Result<ExportFileResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_export_file(&st, &entry_id))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn record_finding_note(
    state: State<'_, Arc<AppState>>,
    entry_id: String,
    note: String,
) -> Result<SnapshotResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_record_finding_note(&st, &entry_id, &note))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn examine_file(
    state: State<'_, Arc<AppState>>,
    entry_id: String,
    comparison_path: Option<String>,
) -> Result<ExamineFileResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_examine_file(&st, &entry_id, comparison_path.as_deref())
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn list_findings(
    state: State<'_, Arc<AppState>>,
    status: Option<String>,
    offset: Option<String>,
    keyword: Option<String>,
    sort_column: String,
    descending: bool,
) -> Result<ListFindingsResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_list_findings(
            &st,
            status.as_deref(),
            offset.as_deref(),
            keyword.as_deref(),
            &sort_column,
            descending,
        )
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn export_findings(
    state: State<'_, Arc<AppState>>,
    group_keys: Vec<String>,
) -> Result<ExportFindingsResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_export_findings(&st, &group_keys))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn build_timeline(
    state: State<'_, Arc<AppState>>,
) -> Result<BuildTimelineResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_build_timeline(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn query_timeline_page(
    state: State<'_, Arc<AppState>>,
    query: String,
    event: Option<String>,
    status: Option<String>,
    offset: Option<String>,
    sort_column: String,
    descending: bool,
    page: usize,
    page_size: usize,
) -> Result<QueryTimelinePageResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_query_timeline_page(
            &st,
            &query,
            event.as_deref(),
            status.as_deref(),
            offset.as_deref(),
            &sort_column,
            descending,
            page,
            page_size,
        )
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn list_audit_log(
    state: State<'_, Arc<AppState>>,
    query: String,
    origin: Option<String>,
    actor: Option<String>,
    action: Option<String>,
    result: Option<String>,
    sort_column: String,
    descending: bool,
) -> Result<ListAuditLogResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_list_audit_log(
            &st,
            &query,
            origin.as_deref(),
            actor.as_deref(),
            action.as_deref(),
            result.as_deref(),
            &sort_column,
            descending,
        )
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn start_content_search(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    query: String,
    encoding: String,
    selected_entry_id: Option<String>,
) -> Result<StartContentSearchResponse, String> {
    cmd_start_content_search(
        &state,
        &query,
        &encoding,
        selected_entry_id.as_deref(),
        Some(&app),
    )
}

#[tauri::command]
pub async fn cancel_content_search(
    state: State<'_, Arc<AppState>>,
    search_id: String,
) -> Result<CancelResponse, String> {
    cmd_cancel_content_search(&state, &search_id)
}

#[tauri::command]
pub async fn bookmark_search_hits(
    state: State<'_, Arc<AppState>>,
    search_id: String,
    hit_indices: Vec<usize>,
) -> Result<BookmarkSearchHitsResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_bookmark_search_hits(&st, &search_id, &hit_indices)
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn load_search_record(
    state: State<'_, Arc<AppState>>,
    report_name: String,
) -> Result<Vec<SearchHitDto>, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_load_search_record(&st, &report_name))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn generate_report(
    state: State<'_, Arc<AppState>>,
) -> Result<PathAndSnapshotResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_generate_report(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn inspect_bundle_materials(
    state: State<'_, Arc<AppState>>,
) -> Result<BundleMaterialsResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_inspect_bundle_materials(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn inspect_review_bundle(
    state: State<'_, Arc<AppState>>,
) -> Result<BundleMaterialsResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_inspect_bundle_materials(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn prepare_review_bundle(
    state: State<'_, Arc<AppState>>,
) -> Result<BundleMaterialsResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_inspect_bundle_materials(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn build_review_bundle(
    state: State<'_, Arc<AppState>>,
    selected_export_indices: Option<Vec<usize>>,
    selected_search_indices: Option<Vec<usize>>,
) -> Result<PathAndSnapshotResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_build_review_bundle(&st, selected_export_indices, selected_search_indices)
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn get_mcp_status(
    state: State<'_, Arc<AppState>>,
    port: Option<u16>,
) -> Result<McpStatus, String> {
    cmd_get_mcp_status(&state, port)
}

#[tauri::command]
pub async fn start_mcp_http(
    state: State<'_, Arc<AppState>>,
    port: u16,
) -> Result<McpStatus, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_start_mcp_http(&st, port))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn stop_mcp_http(state: State<'_, Arc<AppState>>) -> Result<McpStatus, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_stop_mcp_http(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn open_in_os(
    state: State<'_, Arc<AppState>>,
    path: String,
    reveal_folder: bool,
) -> Result<OpenInOsResponse, String> {
    cmd_open_in_os(&state, &path, reveal_folder)
}

#[tauri::command]
pub async fn check_busy_before_close(
    state: State<'_, Arc<AppState>>,
) -> Result<BusyCheckResponse, String> {
    cmd_check_busy_before_close(&state)
}

#[tauri::command]
pub async fn get_guide_pages() -> Result<Vec<GuidePageDto>, String> {
    cmd_get_guide_pages()
}
