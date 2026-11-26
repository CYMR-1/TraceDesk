//! 实现 `ui-contract.md` §3 与 `frontend/src/api/tauri.ts` 中定义的全部 Tauri IPC 命令及
//! 6 类流式事件（含便捷别名、魔数伪装检测、离线 HTML 报告与可视化复核包核验）。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use memchr::memmem;
use rayon::prelude::*;
use serde_json::{Map, Value, json};
use tauri::{AppHandle, Emitter, State};
use tracedesk_core::magic::{
    MagicCheckItem, MagicScanReport, inspect_entry_magic_at_image, scan_entries_magic_mismatches,
};
use tracedesk_core::review::verify_bundle_detailed;
use tracedesk_mcp::McpActivitySnapshot;
use tracedesk_core::{
    AuditOrigin, BrowserFilter, BuildBundleOptions, CONTEXT_BYTES, Case, CoreError, EvidenceInfo,
    FindingGroup, ICAT_THREADS, PIECE_BYTES, PIECE_SPLIT_MIN, PartitionScan, PreviewEncoding,
    Provenance, RawHit, SearchErrorEntry, SearchHit, SearchOutput, SearchRecord,
    SelectedSearchTarget, StatusFilter, StreamMatcher, TimelineFilter, TimelineIndex,
    WIN_INIT_BYTES, WIN_INIT_FILES, WIN_MAX_BYTES, WIN_MAX_FILES, action_title, audit_mcp_user,
    audit_origin, audit_origin_label, build_bundle, case_folder_name, deleted_export_summary,
    deleted_source_note, display_iso_time, entry_status, examine,
    export_findings as core_export_findings, format_missing_materials, group_findings, hex_lower,
    inspect_bundle_exports, inspect_bundle_searches, is_within, next_case_folder_path,
    operation_title, parse_pattern, preview_entry_image, preview_entry_page, record_note,
    resolve_clean, sha256_hex,
};
use tracedesk_engines::{
    ByteInterval, EngineError, EntryReadPlan, InventoryEntry, MediaReader, SourceGuard, TskCli,
    VolumeReader, can_export, ewf, open_media, sha256_file,
};
use uuid::Uuid;

use crate::mcp_http::mcp_list_cases;
use crate::state::{
    AppPathsDto, AppState, AuditFilterOptionsDto, AuditRecordDto, BookmarkSearchHitsResponse,
    BrowseDirectoryResponse, BuildTimelineResponse, BundleCrossCheckDto, BundleExportRowDto,
    BundleMaterialsResponse, BundleMemberCheckDto, BundleSearchRowDto, BundleVerificationDetailDto,
    BusyCheckResponse, CancelResponse, CaseSnapshot, CloseCaseResponse, EntryView,
    ExamineFileResponse, ExportFileResponse, ExportFindingsResponse, FindingFilterOptionsDto,
    FindingGroupDto, FindingRecordDto, GuidePageDto, HashFinishedEvent, HashProgressEvent,
    HexRowDto, HtmlReportDto, ListAuditLogResponse, ListFindingsResponse, LocateFileResponse,
    McpStatus, OpenInOsResponse, PathAndSnapshotResponse, PathResponse, PreviewImageResponse,
    PreviewPageResponse, QueryFilesPageResponse, QueryTimelinePageResponse, RecentCaseDto,
    ScanPartitionsResponse, SearchFinishedEvent, SearchHitDto, SearchHitsEvent,
    SearchProgressEvent, SearchSessionState, SnapshotResponse, StartContentSearchResponse,
    StoredSearchHit, SuggestCaseDirResponse, TaskFinishedEvent, TaskProgressEvent,
    TaskStartedEvent, TimelineFilterOptionsDto, TimelineRowDto, TreeChildrenResponse,
    TreeNodeIpcDto, VerifyIntegrityResponse, entry_to_view, infer_entry_icon_kind,
};

/* ==========================================================================================
 * 辅助函数与常量：事件推送、写入瞬间短锁超时
 * ========================================================================================== */

/// 桌面端写盘或写审计时等待 `case.lock` 短锁排队的超时时间。
const DESKTOP_WRITE_LOCK_TIMEOUT: Duration = Duration::from_secs(8);

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
 * 3.1 应用状态与案件管理命令（核心函数 + Tauri 命令封装）
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
    let mut new_case = Case::create(
        &parent,
        number.trim(),
        examiner.trim(),
        target.trim(),
        explicit_folder,
        None,
        AuditOrigin::Manual,
    )
    .map_err(|e| e.to_string())?;
    // 建案落盘完成后立即释放 OS `case.lock` 句柄，浏览期间不常驻占锁，允许外部 MCP 实时协同。
    new_case.release_lock();

    if let Some(mut old) = case_guard.take() {
        old.close();
    }
    // 切换至新建案件前清理旧案件残留的搜索会话与热刷新脏标记，避免内存泄漏或跨案误存书签。
    state.clear_search_sessions();
    state.clear_disk_dirty();
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

    // 若重新打开当前已打开的案件目录，需先释放现有锁。
    if case_guard
        .as_ref()
        .is_some_and(|c| resolve_clean(c.folder()) == folder)
        && let Some(mut cur) = case_guard.take()
    {
        cur.close();
    }

    let mut opened = Case::open_with_mcp_client_and_timeout(
        &folder,
        None,
        AuditOrigin::Manual,
        None,
        DESKTOP_WRITE_LOCK_TIMEOUT,
    )
    .map_err(|e| e.to_string())?;
    if let Err(err) = opened.log("CASE_OPEN", &log_subject, "成功", Map::new()) {
        opened.close();
        return Err(err.to_string());
    }
    // 写入 CASE_OPEN 审计记录后立即释放 `case.lock`，桌面端空闲浏览期间不长期占锁。
    opened.release_lock();

    if let Some(mut old) = case_guard.take() {
        old.close();
    }
    state.clear_search_sessions();
    state.clear_disk_dirty();

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
    state.clear_search_sessions();
    state.clear_disk_dirty();
    if let Ok(mut view) = state.view.write() {
        view.clear();
    }
    Ok(CloseCaseResponse { closed: true })
}

pub fn cmd_get_case_snapshot(state: &Arc<AppState>) -> Result<Option<CaseSnapshot>, String> {
    // 非阻塞轻量检测外部 MCP 进程是否修改了磁盘案件状态：
    // 若存在因先前 WouldBlock 积压的 disk_dirty 脏标记，只要锁已空闲即立即从磁盘热重载并补发通知；
    // 若当前仍被长耗时任务占锁，则保留 disk_dirty 标记待锁释放后自动补刷，同时不卡顿 UI。
    let _ = state.reload_active_case_from_disk_nonblocking();
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
 * 3.2 证据镜像与文件浏览命令
 * ========================================================================================== */

pub fn cmd_load_image(
    state: &Arc<AppState>,
    image_path: &str,
    app: Option<&AppHandle>,
) -> Result<CaseSnapshot, String> {
    state.task_cancel.store(false, Ordering::Relaxed);
    let cancel = Arc::clone(&state.task_cancel);

    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    emit_task_started(app, "打开镜像并识别分区");
    let progress_cb = |done: u64, total: u64| {
        emit_task_progress(app, "固定镜像 SHA-256", done, total);
    };

    if let Err(err) = case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
        c.load_image(
            Path::new(image_path.trim()),
            None,
            Some(&cancel),
            Some(&progress_cb),
        )
    }) {
        let msg = err.to_string();
        emit_task_finished(app, "打开镜像并识别分区", false, Some(msg.clone()));
        return Err(msg);
    }

    let mut view = match state.view.write() {
        Ok(v) => v,
        Err(_) => {
            let msg = "视图缓存锁异常".to_string();
            emit_task_finished(app, "打开镜像并识别分区", false, Some(msg.clone()));
            return Err(msg);
        }
    };
    view.sync_from_case(case, true);
    let snap = view.snapshot.clone().expect("snapshot updated");
    emit_task_finished(app, "打开镜像并识别分区", true, None);
    Ok(snap)
}

pub fn cmd_verify_integrity(
    state: &Arc<AppState>,
    app: Option<&AppHandle>,
) -> Result<VerifyIntegrityResponse, String> {
    // 检查已加载镜像是否为大镜像（>= 1 GiB），且持有用于后台流式推送进度的 AppHandle。
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

    // 同步/小镜像校验（先完成锁与状态前置校验，确保每次 `task:started` 都有匹配的 `task:finished`）。
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

    emit_task_started(app, "校验 SHA-256");
    let progress_cb = |done: u64, total: u64| {
        emit_task_progress(app, "校验 SHA-256", done, total);
    };

    let ok = match case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
        c.verify_integrity(None, Some(&cancel), Some(&progress_cb))
    }) {
        Ok(ok) => ok,
        Err(err) => {
            let msg = err.to_string();
            emit_task_finished(app, "校验 SHA-256", false, Some(msg.clone()));
            return Err(msg);
        }
    };

    let mut view = match state.view.write() {
        Ok(v) => v,
        Err(_) => {
            let msg = "视图缓存锁异常".to_string();
            emit_task_finished(app, "校验 SHA-256", false, Some(msg.clone()));
            return Err(msg);
        }
    };
    view.sync_from_case(case, false);
    let snapshot = view.snapshot.clone().expect("snapshot updated");
    emit_task_finished(app, "校验 SHA-256", true, None);

    Ok(VerifyIntegrityResponse {
        ok,
        initial_fixed,
        snapshot,
    })
}

/// 启动非阻塞后台工作线程执行大镜像（`>= 1 GiB`）SHA-256 校验。
/// 磁盘计算哈希期间会释放 `case_lock`，确保用户可继续浏览目录。
fn spawn_large_image_hash_worker(state: Arc<AppState>, app: AppHandle) -> Result<(), String> {
    if state.hashing_active.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    state.hash_cancel.store(false, Ordering::Relaxed);

    // 第 1 步：在持有 case_lock 期间校验源镜像守卫并克隆 EvidenceInfo。
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

            // 短暂重新获取 case_lock，以提交 `accept_hash` 结果或记录取消/错误日志。
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
                        let _ = case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
                            c.log("HASH_VERIFY", &image_str, "已取消", Map::new())
                        });
                        finished_event.cancelled = true;
                    }
                    Err(err) => {
                        let msg = err.to_string();
                        let mut d = Map::new();
                        d.insert("error".to_string(), Value::String(msg.clone()));
                        let _ = case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
                            c.log("HASH_VERIFY", &image_str, "失败", d)
                        });
                        finished_event.error = Some(msg);
                    }
                    Ok(measured) => {
                        let initial_fixed = measured.sha256_update.is_some();
                        match case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
                            c.accept_hash(measured)
                        }) {
                            Ok(ok) => {
                                finished_event.ok = Some(ok);
                                finished_event.initial_fixed = Some(initial_fixed);
                            }
                            Err(err) => {
                                let msg = err.to_string();
                                let mut d = Map::new();
                                d.insert("error".to_string(), Value::String(msg.clone()));
                                let _ = case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
                                    c.log("HASH_VERIFY", &image_str, "失败", d)
                                });
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
    case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| c.register_source(&prov))
        .map_err(|e| e.to_string())?;

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
        .with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| c.export_fsstat(offset, None))
        .map_err(|e| e.to_string())?;
    if let Ok(mut view) = state.view.write() {
        view.sync_from_case(case, false);
    }
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

        match case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
            c.scan_partitions(None, Some(&cancel), Some(&progress_cb))
        }) {
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
    let _ = state.flush_disk_dirty_if_ready();
    match &res {
        Ok(_) => emit_task_finished(app, "读取所有分区与文件树", true, None),
        Err(e) => emit_task_finished(app, "读取所有分区与文件树", false, Some(e.clone())),
    }
    res
}

pub fn cmd_scan_partition(
    state: &Arc<AppState>,
    offset: u64,
    app: Option<&AppHandle>,
) -> Result<ScanPartitionsResponse, String> {
    let stage = format!("扫描分区（偏移 {offset}）");
    emit_task_started(app, &stage);
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
        match case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
            c.scan_partition(offset, None, Some(&cancel))
        }) {
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
    let _ = state.flush_disk_dirty_if_ready();
    match &res {
        Ok(_) => emit_task_finished(app, &stage, true, None),
        Err(e) => emit_task_finished(app, &stage, false, Some(e.clone())),
    }
    res
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

/// 将按需目录读取错误转换为清晰的中文提示（尤其针对无文件系统的保留分区，如 GPT 128 扇区 MSR 分区）。
fn format_browse_directory_error(offset: u64, scope_path: &str, err: &CoreError) -> String {
    let raw = err.to_string();
    let lower = raw.to_ascii_lowercase();
    let target = if scope_path.is_empty() {
        format!("分区偏移 {offset} 扇区根目录")
    } else {
        format!("目录 /{scope_path}（分区偏移 {offset}）")
    };
    if lower.contains("cannot determine file system type")
        || lower.contains("invalid magic")
        || lower.contains("unsupported file system")
    {
        format!(
            "{target}未检测到可识别的文件系统（可能为 MSR 保留分区、未格式化区域或加密卷）：{raw}"
        )
    } else if raw.contains("分区") || raw.contains("目录") || raw.contains("镜像") {
        raw
    } else {
        format!("读取{target}失败：{raw}")
    }
}

/// 将指定 [`tracedesk_core::BrowserIndex`] 的某层分支转换为前端目录树所需的 [`TreeChildrenResponse`]。
/// 当 `lazy_dir_expandable` 为 `true`（大镜像按需模式）时，仅读取了单层目录条目，无法预先得知子目录是否非空，
/// 因此对具备有效 `inode` 的目录项一律置 `has_children = true`，允许用户继续逐层点击展开。
fn build_tree_children_response(
    index: &tracedesk_core::BrowserIndex,
    offset: u64,
    scope_path: &str,
    group_index: Option<usize>,
    lazy_dir_expandable: bool,
) -> TreeChildrenResponse {
    let page = index.tree_children(offset, scope_path, group_index);
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
                && let Some(entry) = index.get(idx)
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
            let has_children = if lazy_dir_expandable {
                !n.inode.is_empty()
            } else {
                n.has_children
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
                has_children,
                group_index: None,
            });
        } else {
            let (icon_kind, status_str) = match n.entry_id.and_then(|id| index.get(id)) {
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

    TreeChildrenResponse {
        nodes,
        grouped: page.grouped,
        group_count: page.group_count,
    }
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
    let clean_path = tracedesk_core::browser_index::normalize_scope_path(path);
    // 说明：`Case::browse_directory` 为只读按需列举单层目录（经 `check_source` 核对源镜像身份），
    // 不写入 `case.json` 也不追加 `FILE_BROWSE` 审计日志，因此无需占用 `case.lock` 磁盘短锁，
    // 避免与外部 MCP 写入产生不必要锁竞争。
    let raw_entries = case
        .browse_directory(offset, clean_inode, &clean_path, None)
        .map_err(|e| format_browse_directory_error(offset, &clean_path, &e))?;

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, true);
    if case.browsing_directories() {
        view.cache_quick_tree_branch(offset, &clean_path, &raw_entries);
    }
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
    inode: Option<&str>,
    group_index: Option<usize>,
) -> Result<TreeChildrenResponse, String> {
    let norm_scope = tracedesk_core::browser_index::normalize_scope_path(scope_path);
    let clean_inode = inode.map(str::trim).filter(|s| !s.is_empty());

    // 第 1 阶段：在视图读锁下检查全量模式或按需分支缓存命中，避免重复触发磁盘 I/O。
    let fallback_inode = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        let Some(ref snap) = view.snapshot else {
            return Ok(TreeChildrenResponse {
                nodes: Vec::new(),
                grouped: false,
                group_count: 0,
            });
        };
        if snap.evidence.is_none() {
            return Ok(TreeChildrenResponse {
                nodes: Vec::new(),
                grouped: false,
                group_count: 0,
            });
        }

        let partition_ready = snap
            .partition_scans
            .iter()
            .any(|s| s.offset == offset && s.status == "ready");
        if !snap.browsing_directories || partition_ready {
            // 全量扫描模式或该分区已完成全量索引：照常从内存完整清单索引返回子节点。
            return Ok(build_tree_children_response(
                &view.browser_index,
                offset,
                &norm_scope,
                group_index,
                false,
            ));
        }

        // 大镜像按需模式：优先命中 ViewCache 中保留的多目录树分支缓存（支持多分区与 256 项分桶展开）。
        if let Some(cached_idx) = view.quick_tree_branches.get(&(offset, norm_scope.clone())) {
            return Ok(build_tree_children_response(
                cached_idx,
                offset,
                &norm_scope,
                group_index,
                true,
            ));
        }

        // 若当前 browser_index 恰好对应同一目录且已有节点（如通过外部状态同步加载），直接复用。
        let quick_matches_browser = snap.quick_location.as_ref().is_some_and(|loc| {
            loc.offset == offset
                && tracedesk_core::browser_index::normalize_scope_path(&loc.path) == norm_scope
        });
        if quick_matches_browser
            && !view.browser_index.branch_items(offset, &norm_scope).is_empty()
        {
            return Ok(build_tree_children_response(
                &view.browser_index,
                offset,
                &norm_scope,
                group_index,
                true,
            ));
        }

        if clean_inode.is_none() && !norm_scope.is_empty() {
            view.find_directory_inode(offset, &norm_scope)
        } else {
            None
        }
    };

    // 第 2 阶段：大镜像按需模式缓存未命中，调用 `case.browse_directory` 实时读取该层真实目录项。
    let effective_inode = clean_inode.map(str::to_string).or(fallback_inode);
    if !norm_scope.is_empty() && effective_inode.is_none() {
        return Err(format!(
            "无法按需展开子目录 /{norm_scope}：缺少目录 inode，请先展开上级目录。"
        ));
    }

    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    // 二次确认仍处于按需模式；若期间刚完成全盘扫描则回退到全量视图。
    if !case.browsing_directories() {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        return Ok(build_tree_children_response(
            &view.browser_index,
            offset,
            &norm_scope,
            group_index,
            false,
        ));
    }

    // 记录展开树节点前右侧列表正在浏览的位置，避免仅点击树箭头展开其他分区时破坏右侧已展示条目的索引上下文。
    let prev_loc = case.directory_location().cloned();
    let prev_can_restore_from_cache = prev_loc.as_ref().is_some_and(|loc| {
        !(loc.offset == offset
            && tracedesk_core::browser_index::normalize_scope_path(&loc.path) == norm_scope)
            && case.displayed_entries().len() <= 20_000
    });

    // 说明：`Case::browse_directory` 为只读按需列举单层目录，不写 `case.json` 也不追加 `FILE_BROWSE` 审计日志，
    // 不占用 `case.lock` 磁盘短锁，保持与外部 MCP 协同访问不冲突。
    let entries = case
        .browse_directory(offset, effective_inode.as_deref(), &norm_scope, None)
        .map_err(|e| format_browse_directory_error(offset, &norm_scope, &e))?;

    let dir_index = tracedesk_core::BrowserIndex::build(&entries);
    let resp = build_tree_children_response(&dir_index, offset, &norm_scope, group_index, true);

    // 若此前右侧列表正在浏览另一目录且该目录仍位于 LRU 缓存容量内，则 O(1) 恢复右侧上下文。
    if prev_can_restore_from_cache && let Some(ref prev) = prev_loc {
        let _ = case.browse_directory(prev.offset, prev.inode.as_deref(), &prev.path, None);
    }

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    if prev_loc.is_none() {
        // 案件刚加载大镜像、此前尚未浏览任何目录时，同步刷新快照与 browser_index。
        view.sync_from_case(case, true);
    }
    // 直接接管已构建好的 `dir_index`，避免对同一批 `entries` 重复执行 `BrowserIndex::build`。
    view.cache_quick_tree_branch_index(offset, &norm_scope, dir_index);

    Ok(resp)
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
            case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| c.filtered(suffix, keyword))
                .map_err(|e| e.to_string())?;
            if let Ok(mut view) = state.view.write() {
                view.sync_from_case(case, false);
            }
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

/// 扫描当前案件清单中的文件头魔数与扩展名伪装情况（短锁提取快照数据后释放 `case_lock`，无锁并行扫描）。
pub fn cmd_scan_magic_mismatches(state: &Arc<AppState>) -> Result<MagicScanReport, String> {
    state.task_cancel.store(false, Ordering::Relaxed);
    let cancel = Arc::clone(&state.task_cancel);

    // 仅持短锁提取镜像路径、清单克隆与分区偏移列表，随即立即释放 `case_lock` 避免阻塞桌面与 MCP 协同。
    let (image_path, entries, partition_offsets) = {
        let case_guard = state
            .case_lock
            .lock()
            .map_err(|_| "案件状态锁异常".to_string())?;
        let case = case_guard
            .as_ref()
            .ok_or_else(|| "请先新建或打开案件".to_string())?;
        let ev = case
            .data()
            .evidence
            .as_ref()
            .ok_or_else(|| "请先加载镜像".to_string())?;
        let image_path = PathBuf::from(&ev.path);
        // 常规模式扫描完整清单；大镜像按需目录浏览模式下若完整清单尚未建立，则扫描当前已展示目录条目。
        let entries = if !case.data().inventory.is_empty() {
            case.data().inventory.clone()
        } else {
            case.displayed_entries().to_vec()
        };
        let partition_offsets: Vec<u64> = ev.partitions.iter().map(|p| p.offset).collect();
        (image_path, entries, partition_offsets)
    };

    scan_entries_magic_mismatches(
        &image_path,
        &entries,
        &partition_offsets,
        Some(cancel.as_ref()),
    )
    .map_err(|e| e.to_string())
}

/// 只读识别单个文件的前 4096 字节魔数并与扩展名比对（短锁解析条目后释放读锁再执行镜像 I/O）。
pub fn cmd_inspect_entry_magic(
    state: &Arc<AppState>,
    entry_key: &str,
) -> Result<MagicCheckItem, String> {
    let (image_path, entry) = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        let image = view
            .image_path
            .clone()
            .ok_or_else(|| "请先加载镜像".to_string())?;
        let (_, entry) = view
            .resolve_entry(entry_key)
            .ok_or_else(|| format!("未在当前清单中找到条目：{entry_key}"))?;
        (image, entry)
    };

    let tsk: Option<TskCli> = None;
    inspect_entry_magic_at_image(&image_path, &entry, tsk.as_ref()).map_err(|e| e.to_string())
}

/* ==========================================================================================
 * 3.3 文件预览、导出与取证发现命令
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

    let dest = case
        .with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| c.export(&entry, None))
        .map_err(|e| e.to_string())?;
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

    case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| record_note(c, &entry, note))
        .map_err(|e| e.to_string())?;

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

    let res = case
        .with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
            examine(c, &entry, cmp_clean.as_deref(), None)
        })
        .map_err(|e| e.to_string())?;
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
    // 在单次 `case_lock` 内同步外部磁盘变更，避免重复加锁。
    let _ = state.reload_case_and_sync_view(case);

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

    let raw_groups = group_findings(&records);
    let total_group_count = raw_groups.len();
    let status_text = if total_group_count > 0 {
        format!("取证发现 · {total_group_count} 个文件 · 日志链校验通过")
    } else {
        "尚无取证发现 · 右键文件可记录笔记、计算摘要或比对副本".to_string()
    };

    // 预计算每个分组的 `(最新完整时间, 最新序号)` 排序键，避免在 O(N log N) 比较器内重复格式化时间戳。
    let mut keyed_groups: Vec<(String, u64, FindingGroup)> = raw_groups
        .into_iter()
        .map(|g| {
            let (ts, seq) = g
                .records
                .last()
                .map(|r| (display_iso_time(&r.timestamp, false), r.seq))
                .unwrap_or_default();
            (ts, seq, g)
        })
        .collect();
    keyed_groups.sort_by(|a, b| (a.0.as_str(), a.1).cmp(&(b.0.as_str(), b.1)));

    let mut statuses_set: BTreeSet<String> = BTreeSet::new();
    let mut offsets_set: BTreeSet<u64> = BTreeSet::new();
    let mut all_dtos: Vec<(String, FindingGroupDto)> = Vec::with_capacity(keyed_groups.len());

    for (idx, (latest_full, _last_seq, g)) in keyed_groups.into_iter().enumerate() {
        let group_seq = idx + 1;
        let status_label = if g.key.deleted { "已删除" } else { "现存" }.to_string();
        statuses_set.insert(status_label.clone());
        offsets_set.insert(g.key.offset);

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
                // 先在高频轻量字符串字段上短路匹配，未命中时再序列化 `records` JSON，降低搜索开销。
                let cheap_hit = g.subject.to_lowercase().contains(kw)
                    || g.inode.to_lowercase().contains(kw)
                    || g.status.to_lowercase().contains(kw)
                    || g.latest_time.to_lowercase().contains(kw)
                    || g.offset.to_string().contains(kw)
                    || g.seq.to_string().contains(kw);
                if !cheap_hit {
                    let rec_json = serde_json::to_string(&g.records)
                        .unwrap_or_default()
                        .to_lowercase();
                    if !rec_json.contains(kw) {
                        return false;
                    }
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

    let res = case
        .with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
            let records = c.check_audit()?;
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
                        // 兼容 4 段式分组键：忽略末尾的 image_sha256 进行回退匹配。
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

            core_export_findings(c, &target_groups)
        })
        .map_err(|e| e.to_string())?;
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
 * 3.4 时间线、审计、内容搜索与复核包命令
 * ========================================================================================== */

pub fn cmd_build_timeline(state: &Arc<AppState>) -> Result<BuildTimelineResponse, String> {
    let entries = {
        let mut case_guard = state
            .case_lock
            .lock()
            .map_err(|_| "案件状态锁异常".to_string())?;
        let case = case_guard
            .as_mut()
            .ok_or_else(|| "请先新建或打开案件".to_string())?;
        // 在单次 `case_lock` 内同步外部磁盘变更，避免重复加锁。
        let _ = state.reload_case_and_sync_view(case);
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
    // 确保 ViewCache 中已构建时间线索引。
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
    let _ = state.reload_case_and_sync_view(case);

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
                // 先在高频轻量字符串字段上短路匹配，未命中时再序列化 `details` JSON。
                let mcp_user_str = r.mcp_user.as_deref().unwrap_or("");
                let cheap_hit = r.subject.to_lowercase().contains(kw)
                    || r.actor.to_lowercase().contains(kw)
                    || r.action_title.to_lowercase().contains(kw)
                    || r.action.to_lowercase().contains(kw)
                    || r.result.to_lowercase().contains(kw)
                    || r.origin.to_lowercase().contains(kw)
                    || r.origin_label.to_lowercase().contains(kw)
                    || mcp_user_str.to_lowercase().contains(kw)
                    || r.timestamp.to_lowercase().contains(kw)
                    || r.seq.to_string().contains(kw)
                    || r.previous.to_lowercase().contains(kw)
                    || r.hash.to_lowercase().contains(kw);
                if !cheap_hit {
                    let details_str = serde_json::to_string(&r.details)
                        .unwrap_or_default()
                        .to_lowercase();
                    if !details_str.contains(kw) {
                        return false;
                    }
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

/// 内存中最多保留的已完成内容搜索会话数，防止连续多次搜索后命中列表长期占满内存。
const MAX_RETAINED_COMPLETED_SEARCHES: usize = 16;

/// 轻量级搜索命中索引：避免在搜索开始前克隆 10 万条 `InventoryEntry`。
enum EntryLookupMode {
    /// 单文件搜索仅保留单个选中条目。
    Single(String, InventoryEntry),
    /// 全案搜索仅保存 `(offset, inode, deleted, path) -> browser_index 下标`，命中时按需查找。
    IndexMap(HashMap<(u64, String, bool, String), usize>),
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

    let (case_folder, selected_entry, image_sha256, source_note, entry_lookup) = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        let snap = view
            .snapshot
            .as_ref()
            .ok_or_else(|| "请先新建或打开案件".to_string())?;
        let folder = view
            .case_folder
            .clone()
            .ok_or_else(|| "请先新建或打开案件".to_string())?;
        let ev = snap
            .evidence
            .as_ref()
            .ok_or_else(|| "请先加载镜像".to_string())?;
        let (selected, lookup) = match selected_entry_id.map(str::trim).filter(|s| !s.is_empty()) {
            Some(eid) => {
                let (idx, e) = view
                    .resolve_entry(eid)
                    .ok_or_else(|| format!("未在当前清单中找到选中文件：{eid}"))?;
                let lookup = EntryLookupMode::Single(idx.to_string(), e.clone());
                (Some(e), lookup)
            }
            None => {
                if snap.browsing_directories {
                    return Err("全案搜索需要先在文件浏览中建立完整文件索引，亦可选择搜索单个文件。".to_string());
                }
                let ordered = view.browser_index.ordered();
                let mut map: HashMap<(u64, String, bool, String), usize> =
                    HashMap::with_capacity(ordered.len());
                for (idx, row) in ordered.iter().enumerate() {
                    map.insert(
                        (row.offset, row.inode.clone(), row.deleted, row.path.clone()),
                        idx,
                    );
                }
                (None, EntryLookupMode::IndexMap(map))
            }
        };

        (
            folder,
            selected,
            ev.sha256.clone(),
            snap.source_note.clone(),
            Arc::new(lookup),
        )
    };

    let search_id = format!("search-{}", Uuid::new_v4().simple());
    let cancel = Arc::new(AtomicBool::new(false));
    let session = SearchSessionState {
        search_id: search_id.clone(),
        case_folder,
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
        // 清理超量的已完成旧搜索会话，控制内存占用。
        let completed_keys: Vec<String> = searches
            .iter()
            .filter(|(_, s)| !s.running)
            .map(|(k, _)| k.clone())
            .collect();
        if completed_keys.len() >= MAX_RETAINED_COMPLETED_SEARCHES {
            for old_key in completed_keys
                .into_iter()
                .take(MAX_RETAINED_COMPLETED_SEARCHES / 2)
            {
                searches.remove(&old_key);
            }
        }
        searches.insert(search_id.clone(), session);
    }

    let state_clone = Arc::clone(state);
    let sid = search_id.clone();
    let q_owned = query.to_string();
    let enc_owned = encoding.to_string();
    let app_clone = app.cloned();

    if app_clone.is_some() {
        let spawn_res = thread::Builder::new()
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
            });
        match spawn_res {
            Ok(handle) => state.track_search_worker(handle),
            Err(e) => {
                // 线程创建失败时必须移除或终止已登记的 `running = true` 会话，防止永久触发 `check_busy`。
                if let Ok(mut searches) = state.searches.lock() {
                    searches.remove(&search_id);
                }
                return Err(format!("无法启动后台内容搜索线程：{e}"));
            }
        }
    } else {
        // 在无 AppHandle 的 Rust 集成测试直接调用时采用同步执行。
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

fn fallback_hit_entry(h: &SearchHit) -> (String, InventoryEntry) {
    (
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
    )
}

/// 流式内容搜索单块读取缓冲大小（1 MiB）。
const SEARCH_STREAM_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DetachedDedupKey {
    Shared {
        offset: u64,
        inode: String,
        size: u64,
    },
    Unique(usize),
}

struct DetachedDirectTask {
    key: DetachedDedupKey,
    piece_start: u64,
    entry: InventoryEntry,
    sort_key: (u64, u64, u64),
    preplanned_intervals: Option<Vec<ByteInterval>>,
}

enum DetachedDirectOutcome {
    Hits(Vec<RawHit>),
    NeedsIcat,
}

type DetachedIcatOutcome = Result<(DetachedDedupKey, Vec<RawHit>, Option<String>), CoreError>;
type DetachedStageProgress<'a> = &'a (dyn Fn(&str, u64, u64) + Sync);

/// 在短锁阶段提取的只读搜索上下文快照，释放 `case_lock` 与 `case.lock` 后独立执行流式搜索。
struct DetachedSearchContext {
    case_folder: PathBuf,
    image: PathBuf,
    evidence: EvidenceInfo,
    entries: Vec<InventoryEntry>,
    source_note: String,
    partition_scans: Vec<PartitionScan>,
    selected_target: Option<SelectedSearchTarget>,
    needle: Vec<u8>,
}

fn parse_search_inode_num(inode: &str) -> Option<u64> {
    let first = inode.split('-').next()?;
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    first.parse::<u64>().ok()
}

#[allow(clippy::too_many_arguments)]
fn scan_detached_direct_intervals(
    vol: &mut VolumeReader,
    entry: &InventoryEntry,
    intervals: &[ByteInterval],
    needle: &[u8],
    finder: &memmem::Finder<'_>,
    cancel: &AtomicBool,
    io_buf: &mut Vec<u8>,
) -> Result<Vec<RawHit>, CoreError> {
    let mut hits = Vec::new();
    let extra = (needle.len() as u64).saturating_sub(1) + CONTEXT_BYTES as u64;
    for iv in intervals {
        if cancel.load(Ordering::Relaxed) {
            return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
        }
        let read_lo = iv.start.saturating_sub(CONTEXT_BYTES as u64);
        let read_hi = iv.end.saturating_add(extra).min(entry.size);
        if read_hi.saturating_sub(read_lo) < needle.len() as u64 {
            continue;
        }
        let total = read_hi - read_lo;
        let mut matcher = StreamMatcher::new(
            finder,
            needle.len(),
            total,
            read_lo,
            iv.start,
            iv.end,
            None,
        );
        let mut pos = read_lo;
        while pos < read_hi {
            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
            }
            let want = (read_hi - pos).min(SEARCH_STREAM_CHUNK_BYTES as u64) as usize;
            if io_buf.len() < want {
                io_buf.resize(want, 0);
            }
            vol.read_entry_into(entry, pos, &mut io_buf[..want])?;
            let _ = matcher.push_chunk(&io_buf[..want], Some(cancel))?;
            pos += want as u64;
        }
        hits.extend(matcher.into_hits());
    }
    Ok(hits)
}

#[allow(clippy::too_many_arguments)]
fn scan_detached_via_icat(
    tool: &TskCli,
    image: &Path,
    entry: &InventoryEntry,
    needle: &[u8],
    finder: &memmem::Finder<'_>,
    cancel: &AtomicBool,
    byte_progress: Option<DetachedStageProgress<'_>>,
) -> Result<(Vec<RawHit>, Option<String>), CoreError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
    }
    if entry.size < needle.len() as u64 {
        return Ok((Vec::new(), None));
    }
    let mut matcher = StreamMatcher::new(finder, needle.len(), entry.size, 0, 0, entry.size, None);
    let stream_res = tool.stream_entry(image, entry, Some(cancel), |chunk| {
        if cancel.load(Ordering::Relaxed) {
            return Err(EngineError::Cancelled("已取消内容搜索".to_string()));
        }
        let _ = matcher
            .push_chunk(chunk, Some(cancel))
            .map_err(|e| EngineError::Cancelled(e.to_string()))?;
        if let Some(cb) = byte_progress {
            cb("搜索文件字节", matcher.consumed(), entry.size);
        }
        Ok(())
    });
    if cancel.load(Ordering::Relaxed) {
        return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
    }
    let _ = matcher.push_chunk(&[], Some(cancel))?;
    match stream_res {
        Ok((written, note)) => {
            let err_msg = if !note.is_empty() {
                Some(note)
            } else if written < entry.size {
                Some(format!("仅读到 {written}/{} 字节", entry.size))
            } else {
                None
            };
            Ok((matcher.into_hits(), err_msg))
        }
        Err(err) if err.is_cancelled() => Err(CoreError::Cancelled("已取消内容搜索".to_string())),
        Err(err) => Ok((matcher.into_hits(), Some(err.to_string()))),
    }
}

/// 在不持有 `case_lock` 与 `case.lock` 期间对小镜像执行一次无锁哈希复算，并仅在提交结果时短暂持锁写入审计日志。
fn verify_small_image_detached(
    state: &Arc<AppState>,
    case_folder: &Path,
    evidence: &EvidenceInfo,
    stage_label: &str,
    cancel: &AtomicBool,
    progress_cb: &(dyn Fn(&str, u64, u64) + Sync),
) -> Result<bool, CoreError> {
    let cb = |done: u64, total: u64| {
        progress_cb(stage_label, done, total);
    };
    let measured = measure_hash_detached(evidence, cancel, &cb)?;
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| CoreError::Other("案件状态锁异常".to_string()))?;
    let Some(case) = case_guard.as_mut() else {
        return Err(CoreError::InvalidInput(
            "当前案件已关闭，内容搜索已中止".to_string(),
        ));
    };
    if resolve_clean(case.folder()) != resolve_clean(case_folder) {
        return Err(CoreError::InvalidInput(
            "当前案件已切换，内容搜索已中止".to_string(),
        ));
    }
    let ok = case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| c.accept_hash(measured))?;
    if let Ok(mut view) = state.view.write() {
        view.sync_from_case(case, false);
    }
    Ok(ok)
}

#[allow(clippy::too_many_arguments)]
fn run_content_search_worker(
    state: Arc<AppState>,
    search_id: String,
    query: String,
    encoding: String,
    selected: Option<InventoryEntry>,
    cancel: Arc<AtomicBool>,
    entry_lookup: Arc<EntryLookupMode>,
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

    let state_for_hits = Arc::clone(&state);
    let mut hit_cb = |batch: &[SearchHit]| {
        if batch.is_empty() {
            return;
        }
        let mut stored_chunk = Vec::with_capacity(batch.len());
        // 命中到达时再按需从 `ViewCache` 读锁中取对应条目，避免搜索开始前克隆全部 10 万条清单。
        let view_guard = match *entry_lookup {
            EntryLookupMode::IndexMap(_) => state_for_hits.view.read().ok(),
            EntryLookupMode::Single(_, _) => None,
        };
        for h in batch {
            let (entry_id, entry_obj) = match &*entry_lookup {
                EntryLookupMode::Single(id, e) => (id.clone(), e.clone()),
                EntryLookupMode::IndexMap(map) => {
                    let key = (h.offset, h.inode.clone(), h.deleted, h.path.clone());
                    if let Some(&idx) = map.get(&key)
                        && let Some(ref view) = view_guard
                        && let Some(e) = view.browser_index.get(idx)
                    {
                        (idx.to_string(), e.clone())
                    } else {
                        fallback_hit_entry(h)
                    }
                }
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
        drop(view_guard);

        if let Ok(mut searches) = state_for_hits.searches.lock()
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

    // 统一将所有异常路径汇总至 `search_res`，保证无论任何原因退出都会复位 `sess.running = false` 并推送 `search:finished`。
    // 参考 `spawn_large_image_hash_worker` 采用三段式锁设计：
    // 1. 短锁获取只读案件/清单快照并做前置校验 → 立即释放 `case_lock`（全程不持有磁盘 `case.lock`）；
    // 2. 无锁执行流式 SIMD / Rayon / icat 内容搜索，搜索期间用户可随时保存取证发现、查看审计或由外部 MCP 并发读写；
    // 3. 搜索结束后再短锁校验磁盘指纹、原子落盘 `reports/search_*.json` 并追加 `CONTENT_SEARCH` 审计记录。
    let search_res = (|| -> (Result<SearchOutput, CoreError>, Option<CaseSnapshot>) {
        // 第 1 步：短锁获取只读案件与清单快照（不获取磁盘 `case.lock`）。
        let ctx = match (|| -> Result<DetachedSearchContext, CoreError> {
            let needle = parse_pattern(&query, &encoding)?;
            let mut case_guard = state
                .case_lock
                .lock()
                .map_err(|_| CoreError::Other("案件状态锁异常".to_string()))?;
            let Some(case) = case_guard.as_mut() else {
                return Err(CoreError::InvalidInput(
                    "当前案件已关闭，内容搜索已中止".to_string(),
                ));
            };
            let image = case.image_path()?;
            let evidence = case
                .data()
                .evidence
                .as_ref()
                .ok_or_else(|| CoreError::InvalidInput("请先加载镜像".to_string()))?
                .clone();

            if let Some(ref sel) = selected
                && (!can_export(sel) || !case.displayed_entries().contains(sel))
            {
                return Err(CoreError::InvalidInput(
                    "请选择当前案件中的普通文件".to_string(),
                ));
            }
            if selected.is_none() && case.browsing_directories() {
                return Err(CoreError::InvalidInput(
                    "全案搜索需要先在文件浏览中建立完整文件索引，亦可选择搜索单个文件。"
                        .to_string(),
                ));
            }
            // 大镜像在短锁阶段即时校验 SourceGuard 与会话复核标记（零读盘哈希开销）。
            if evidence.is_large_image() {
                case.operation_check(None, Some(&cancel), None)?;
            }

            let entries: Vec<InventoryEntry> = match selected {
                Some(ref sel) => vec![sel.clone()],
                None => case
                    .data()
                    .inventory
                    .iter()
                    .filter(|e| can_export(e))
                    .cloned()
                    .collect(),
            };
            let selected_target = selected.as_ref().map(|s| SelectedSearchTarget {
                path: s.path.clone(),
                offset: s.offset,
                inode: s.inode.clone(),
            });

            Ok(DetachedSearchContext {
                case_folder: case.folder().to_path_buf(),
                image,
                evidence,
                entries,
                source_note: case.source_note().to_string(),
                partition_scans: case.data().partition_scans.clone().unwrap_or_default(),
                selected_target,
                needle,
            })
        })() {
            Ok(c) => c,
            Err(e) => return (Err(e), None),
        };

        // 第 2 步：已彻底释放 `case_lock` 与磁盘 `case.lock`，执行无锁流式内容搜索。
        let tool = match TskCli::discover(None) {
            Ok(t) => t,
            Err(e) => return (Err(CoreError::Engine(e)), None),
        };

        let mut hits: Vec<SearchHit> = Vec::new();
        let mut errors: Vec<SearchErrorEntry> = Vec::new();
        let mut completed: usize = 0;
        let mut state_text = "完成".to_string();
        let mut verification = "校验未完成".to_string();

        let run_result: Result<(), CoreError> = (|| {
            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
            }

            let source_paths = if ctx.evidence.is_ewf() {
                ewf::discover_segments(&ctx.image)?
            } else {
                vec![ctx.image.clone()]
            };
            let guard = SourceGuard::acquire(&source_paths).ok();
            let protected = guard.is_some();

            if !ctx.evidence.is_large_image() {
                let ok = verify_small_image_detached(
                    &state,
                    &ctx.case_folder,
                    &ctx.evidence,
                    "搜索前校验",
                    &cancel,
                    &progress_cb,
                )?;
                if !ok {
                    return Err(CoreError::IntegrityFailed(
                        "镜像摘要与案件不一致，拒绝使用搜索结果".to_string(),
                    ));
                }
            }

            verification = if !ctx.source_note.is_empty() {
                ctx.source_note.clone()
            } else if protected {
                "全程持有镜像只读共享句柄，搜索前复算 SHA-256".to_string()
            } else {
                "搜索前后分别复算 SHA-256".to_string()
            };

            let total = ctx.entries.len();
            if total > 0 {
                let nlen = ctx.needle.len() as u64;
                let finder = memmem::Finder::new(&ctx.needle);
                let byte_progress: Option<DetachedStageProgress<'_>> =
                    if total == 1 { Some(&progress_cb) } else { None };
                if byte_progress.is_none() {
                    progress_cb("搜索文件内容", 0, total as u64);
                }

                // 统计未删除常规文件的硬链接引用计数。
                let mut key_counts: HashMap<DetachedDedupKey, usize> = HashMap::new();
                for entry in &ctx.entries {
                    if entry.size >= nlen && !entry.deleted && entry.mode.starts_with("r/") {
                        let key = DetachedDedupKey::Shared {
                            offset: entry.offset,
                            inode: entry.inode.clone(),
                            size: entry.size,
                        };
                        *key_counts.entry(key).or_insert(0) += 1;
                    }
                }
                let mut shared_remaining: HashMap<DetachedDedupKey, usize> = key_counts
                    .into_iter()
                    .filter(|&(_, count)| count > 1)
                    .collect();
                let mut shared_cache: HashMap<DetachedDedupKey, (Vec<RawHit>, Option<String>)> =
                    HashMap::new();

                let media: Option<Arc<dyn MediaReader>> = open_media(&ctx.image).ok();
                let mut probe_vol: Option<VolumeReader> = media
                    .as_ref()
                    .map(|m| VolumeReader::open_with_media(Arc::clone(m)));
                if let Some(ref mut pv) = probe_vol {
                    for part in &ctx.evidence.partitions {
                        pv.prime_partition(part.offset);
                    }
                }
                let mut icat_pool: Option<rayon::ThreadPool> = None;

                let mut cursor = 0usize;
                let mut emitted = 0usize;
                let mut win_files = WIN_INIT_FILES;
                let mut max_win_bytes = WIN_INIT_BYTES;

                while cursor < total {
                    if cancel.load(Ordering::Relaxed) {
                        return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
                    }

                    // 1. 按原始清单顺序切分滚动窗口。
                    let mut win_end = cursor;
                    let mut win_bytes: u64 = 0;
                    let mut win_seen_keys: HashSet<DetachedDedupKey> = HashSet::new();
                    while win_end < total && (win_end - cursor) < win_files {
                        let entry = &ctx.entries[win_end];
                        let size = entry.size;
                        let mut cost = 0u64;
                        if size >= nlen {
                            if !entry.deleted && entry.mode.starts_with("r/") {
                                let key = DetachedDedupKey::Shared {
                                    offset: entry.offset,
                                    inode: entry.inode.clone(),
                                    size,
                                };
                                if !shared_cache.contains_key(&key) && win_seen_keys.insert(key) {
                                    cost = size.min(128 << 20);
                                }
                            } else {
                                cost = size.min(128 << 20);
                            }
                        }
                        if win_end > cursor && win_bytes.saturating_add(cost) > max_win_bytes {
                            break;
                        }
                        win_bytes = win_bytes.saturating_add(cost);
                        win_end += 1;
                    }

                    // 2. 将窗口内条目分类为跳过 / 硬链接复用 / 直读 / icat 回退。
                    let mut entry_keys: HashMap<usize, DetachedDedupKey> = HashMap::new();
                    let mut key_entry: HashMap<DetachedDedupKey, InventoryEntry> = HashMap::new();
                    let mut key_results: HashMap<DetachedDedupKey, (Vec<RawHit>, Option<String>)> =
                        HashMap::new();
                    let mut direct_tasks: Vec<DetachedDirectTask> = Vec::new();
                    let mut icat_tasks: Vec<(DetachedDedupKey, InventoryEntry)> = Vec::new();

                    for (idx, entry) in ctx.entries.iter().enumerate().take(win_end).skip(cursor) {
                        if entry.size < nlen {
                            let k = DetachedDedupKey::Unique(idx);
                            entry_keys.insert(idx, k.clone());
                            key_results.insert(k, (Vec::new(), None));
                            continue;
                        }

                        let is_regular = !entry.deleted && entry.mode.starts_with("r/");
                        let key = if is_regular {
                            DetachedDedupKey::Shared {
                                offset: entry.offset,
                                inode: entry.inode.clone(),
                                size: entry.size,
                            }
                        } else {
                            DetachedDedupKey::Unique(idx)
                        };
                        entry_keys.insert(idx, key.clone());

                        if shared_cache.contains_key(&key) || key_entry.contains_key(&key) {
                            continue;
                        }
                        key_entry.insert(key.clone(), entry.clone());

                        let Some(ino_num) = parse_search_inode_num(&entry.inode) else {
                            icat_tasks.push((key, entry.clone()));
                            continue;
                        };
                        if media.is_none() {
                            icat_tasks.push((key, entry.clone()));
                            continue;
                        }

                        if is_regular && entry.size >= PIECE_SPLIT_MIN {
                            let plan = probe_vol
                                .as_mut()
                                .map(|v| v.plan_entry(entry, &ctx.needle))
                                .unwrap_or(EntryReadPlan::FallbackToIcat);
                            match plan {
                                EntryReadPlan::FallbackToIcat => {
                                    icat_tasks.push((key, entry.clone()));
                                }
                                EntryReadPlan::Direct { intervals, .. } => {
                                    if intervals.is_empty() {
                                        key_results.insert(key, (Vec::new(), None));
                                    } else {
                                        for iv in intervals {
                                            let mut p_start = iv.start;
                                            while p_start < iv.end {
                                                let p_end = (p_start + PIECE_BYTES).min(iv.end);
                                                direct_tasks.push(DetachedDirectTask {
                                                    key: key.clone(),
                                                    piece_start: p_start,
                                                    entry: entry.clone(),
                                                    sort_key: (entry.offset, ino_num, p_start),
                                                    preplanned_intervals: Some(vec![ByteInterval {
                                                        start: p_start,
                                                        end: p_end,
                                                    }]),
                                                });
                                                p_start = p_end;
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            direct_tasks.push(DetachedDirectTask {
                                key,
                                piece_start: 0,
                                entry: entry.clone(),
                                sort_key: (entry.offset, ino_num, 0),
                                preplanned_intervals: None,
                            });
                        }
                    }

                    // 3. 按 (offset, inode_num, piece_start) 排序直读任务并在 rayon 线程池并行扫描。
                    direct_tasks.sort_unstable_by_key(|t| t.sort_key);
                    let window_done = AtomicUsize::new(0);

                    if let Some(ref pv_ref) = probe_vol
                        && !direct_tasks.is_empty()
                    {
                        let raw_outcomes: Vec<
                            Result<(DetachedDedupKey, u64, DetachedDirectOutcome), CoreError>,
                        > = direct_tasks
                            .into_par_iter()
                            .map_init(
                                || (pv_ref.fork_worker(), Vec::<u8>::new()),
                                |(vol, io_buf), task| {
                                    if cancel.load(Ordering::Relaxed) {
                                        return Err(CoreError::Cancelled(
                                            "已取消内容搜索".to_string(),
                                        ));
                                    }
                                    let intervals = match task.preplanned_intervals {
                                        Some(iv) => iv,
                                        None => match vol.plan_entry(&task.entry, &ctx.needle) {
                                            EntryReadPlan::Direct { intervals, .. } => intervals,
                                            EntryReadPlan::FallbackToIcat => {
                                                return Ok((
                                                    task.key,
                                                    task.piece_start,
                                                    DetachedDirectOutcome::NeedsIcat,
                                                ));
                                            }
                                        },
                                    };
                                    match scan_detached_direct_intervals(
                                        vol,
                                        &task.entry,
                                        &intervals,
                                        &ctx.needle,
                                        &finder,
                                        &cancel,
                                        io_buf,
                                    ) {
                                        Ok(found) => {
                                            let done =
                                                window_done.fetch_add(1, Ordering::Relaxed) + 1;
                                            if byte_progress.is_none() && done.is_multiple_of(64) {
                                                progress_cb(
                                                    "搜索文件内容",
                                                    (emitted + done).min(total) as u64,
                                                    total as u64,
                                                );
                                            }
                                            Ok((
                                                task.key,
                                                task.piece_start,
                                                DetachedDirectOutcome::Hits(found),
                                            ))
                                        }
                                        Err(err) if err.is_cancelled() => Err(err),
                                        Err(_) => Ok((
                                            task.key,
                                            task.piece_start,
                                            DetachedDirectOutcome::NeedsIcat,
                                        )),
                                    }
                                },
                            )
                            .collect();

                        let mut assembled: HashMap<
                            DetachedDedupKey,
                            (bool, BTreeMap<u64, Vec<RawHit>>),
                        > = HashMap::new();
                        for item in raw_outcomes {
                            let (key, p_start, outcome) = item?;
                            let slot = assembled
                                .entry(key)
                                .or_insert_with(|| (false, BTreeMap::new()));
                            match outcome {
                                DetachedDirectOutcome::Hits(list) => {
                                    slot.1.insert(p_start, list);
                                }
                                DetachedDirectOutcome::NeedsIcat => {
                                    slot.0 = true;
                                }
                            }
                        }

                        for (key, (needs_icat, pieces)) in assembled {
                            if needs_icat {
                                if let Some(entry) = key_entry.get(&key) {
                                    icat_tasks.push((key, entry.clone()));
                                }
                            } else {
                                let mut merged = Vec::new();
                                for (_, mut piece_hits) in pieces {
                                    merged.append(&mut piece_hits);
                                }
                                key_results.insert(key, (merged, None));
                            }
                        }
                    }

                    // 4. 在按需创建的 `icat` 池上并发执行回退条目与 FAT 已删除条目。
                    if !icat_tasks.is_empty() {
                        let pool = match icat_pool {
                            Some(ref p) => p,
                            None => {
                                let threads = icat_tasks.len().clamp(1, ICAT_THREADS);
                                let built = rayon::ThreadPoolBuilder::new()
                                    .num_threads(threads)
                                    .build()
                                    .map_err(|e| {
                                        CoreError::Other(format!("无法创建 icat 线程池：{e}"))
                                    })?;
                                icat_pool.insert(built)
                            }
                        };
                        let icat_outcomes: Vec<DetachedIcatOutcome> = pool.install(|| {
                            icat_tasks
                                .into_par_iter()
                                .map(|(key, entry)| {
                                    let (found, err) = scan_detached_via_icat(
                                        &tool,
                                        &ctx.image,
                                        &entry,
                                        &ctx.needle,
                                        &finder,
                                        &cancel,
                                        byte_progress,
                                    )?;
                                    Ok((key, found, err))
                                })
                                .collect()
                        });
                        for item in icat_outcomes {
                            let (key, found, err) = item?;
                            key_results.insert(key, (found, err));
                        }
                    }

                    for (key, val) in &key_results {
                        if shared_remaining.contains_key(key) {
                            shared_cache.insert(key.clone(), val.clone());
                        }
                    }

                    // 5. 严格按原始清单顺序流式发布命中结果。
                    for (idx, entry) in ctx.entries.iter().enumerate().take(win_end).skip(cursor) {
                        if cancel.load(Ordering::Relaxed) {
                            return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
                        }
                        let key = &entry_keys[&idx];
                        let (raw_hits, err_msg) = key_results
                            .get(key)
                            .or_else(|| shared_cache.get(key))
                            .cloned()
                            .unwrap_or_default();

                        if let Some(rem) = shared_remaining.get_mut(key) {
                            *rem -= 1;
                            if *rem == 0 {
                                shared_remaining.remove(key);
                                shared_cache.remove(key);
                            }
                        }

                        let src_note = deleted_source_note(entry).to_string();
                        let entry_hits: Vec<SearchHit> = raw_hits
                            .into_iter()
                            .map(|h| SearchHit {
                                path: entry.path.clone(),
                                offset: entry.offset,
                                inode: entry.inode.clone(),
                                deleted: entry.deleted,
                                file_byte: h.file_byte,
                                before: h.before,
                                after: h.after,
                                reallocated: entry.reallocated,
                                source_note: src_note.clone(),
                            })
                            .collect();

                        if !entry_hits.is_empty() {
                            hit_cb(&entry_hits);
                            hits.extend(entry_hits);
                        }
                        emitted += 1;
                        if let Some(msg) = err_msg {
                            errors.push(SearchErrorEntry {
                                path: entry.path.clone(),
                                offset: entry.offset,
                                inode: entry.inode.clone(),
                                error: msg,
                            });
                        }
                        completed += 1;
                    }

                    if byte_progress.is_none() {
                        progress_cb("搜索文件内容", emitted.min(total) as u64, total as u64);
                    }

                    cursor = win_end;
                    win_files = (win_files * 2).min(WIN_MAX_FILES);
                    max_win_bytes = (max_win_bytes * 2).min(WIN_MAX_BYTES);
                }
            }

            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
            }

            if let Some(ref g) = guard {
                let latest_paths = if ctx.evidence.is_ewf() {
                    ewf::discover_segments(&ctx.image)?
                } else {
                    vec![ctx.image.clone()]
                };
                if g.verify_unchanged(&latest_paths).is_err() {
                    return Err(CoreError::IntegrityFailed(
                        "搜索期间镜像或分段清单发生变化，结果未发布".to_string(),
                    ));
                }
            }
            drop(guard);

            if !protected && !ctx.evidence.is_large_image() {
                let ok = verify_small_image_detached(
                    &state,
                    &ctx.case_folder,
                    &ctx.evidence,
                    "搜索后校验",
                    &cancel,
                    &progress_cb,
                )?;
                if !ok {
                    return Err(CoreError::IntegrityFailed(
                        "镜像摘要与案件不一致，拒绝使用搜索结果".to_string(),
                    ));
                }
            }

            Ok(())
        })();

        let was_cancelled = match run_result {
            Ok(()) => false,
            Err(err) if err.is_cancelled() => {
                state_text = "已取消；结果未发布".to_string();
                hits.clear();
                true
            }
            Err(err) => return (Err(err), None),
        };

        if !was_cancelled && cancel.load(Ordering::Relaxed) {
            state_text = "已取消；结果未发布".to_string();
            hits.clear();
        }
        if !errors.is_empty() && state_text == "完成" {
            state_text = "部分文件读取失败".to_string();
        }

        let record = SearchRecord {
            query: query.clone(),
            encoding: encoding.clone(),
            needle: hex_lower(&ctx.needle),
            image_sha256: ctx.evidence.sha256.clone(),
            verification,
            scope: if ctx.selected_target.is_some() {
                "选中文件".to_string()
            } else {
                "清单内可读取的文件，不含未分配空间".to_string()
            },
            selected: ctx.selected_target,
            partition_scans: ctx.partition_scans,
            status: state_text.clone(),
            visited: completed,
            eligible: ctx.entries.len(),
            errors,
            hits,
        };

        // 第 3 步：搜索结束后短暂重新获取 `case_lock` 与 `case.lock`，
        // 同步磁盘指纹（合并搜索期间产生的发现笔记或外部 MCP 写入）、落盘 `reports/search_*.json` 并追加审计日志。
        let mut case_guard = match state.case_lock.lock() {
            Ok(g) => g,
            Err(_) => {
                return (
                    Err(CoreError::Other("案件状态锁异常".to_string())),
                    None,
                );
            }
        };
        let Some(case) = case_guard.as_mut() else {
            return (
                Err(CoreError::InvalidInput(
                    "当前案件已关闭，搜索记录未写入".to_string(),
                )),
                None,
            );
        };
        if resolve_clean(case.folder()) != resolve_clean(&ctx.case_folder) {
            return (
                Err(CoreError::InvalidInput(
                    "当前案件已切换，搜索记录未写入".to_string(),
                )),
                None,
            );
        }

        let is_large = ctx.evidence.is_large_image();
        let commit_res = case.with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
            if is_large && !was_cancelled && !cancel.load(Ordering::Relaxed) {
                c.check_source()?;
            }
            let report_name = format!("search_{}.json", Uuid::new_v4().simple());
            let report_path = c.folder().join("reports").join(&report_name);
            let json_text = serde_json::to_string_pretty(&record)?;
            fs::write(&report_path, json_text.as_bytes())?;
            let report_sha256 = sha256_hex(json_text.as_bytes());

            let mut details = Map::new();
            details.insert("query".to_string(), Value::String(query.clone()));
            details.insert("encoding".to_string(), Value::String(encoding.clone()));
            details.insert("hits".to_string(), Value::from(record.hits.len() as u64));
            details.insert(
                "failed".to_string(),
                Value::from(record.errors.len() as u64),
            );
            details.insert("visited".to_string(), Value::from(record.visited as u64));
            details.insert("eligible".to_string(), Value::from(record.eligible as u64));
            details.insert("sha256".to_string(), Value::String(report_sha256));
            c.log("CONTENT_SEARCH", &report_name, &state_text, details)?;

            Ok(SearchOutput {
                record,
                report_name,
                report_path,
            })
        });

        let snap = if let Ok(mut view) = state.view.write() {
            view.sync_from_case(case, false);
            view.snapshot.clone()
        } else {
            None
        };
        drop(case_guard);
        let _ = state.flush_disk_dirty_if_ready();
        (commit_res, snap)
    })();

    // 在发送 search:finished 之前刷新所有剩余命中结果。
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
    let (
        session_case_folder,
        query,
        encoding,
        needle_hex,
        image_sha256,
        verification,
        report_name,
        selected_hits,
    ) = {
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
            sess.case_folder.clone(),
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

    // 校验搜索会话所属案件目录与当前打开案件一致，防止跨案误将旧搜索命中写入新案件审计链。
    if resolve_clean(&session_case_folder) != resolve_clean(case.folder()) {
        return Err("该搜索会话属于其他案件，请重新执行搜索后再保存为取证发现。".to_string());
    }

    let saved_count = case
        .with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
            let mut count = 0usize;
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

                c.log("FILE_NOTE", &entry.path, "成功", details)?;
                count += 1;
            }
            Ok(count)
        })
        .map_err(|e| e.to_string())?;

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
    let case_folder = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        view.case_folder
            .clone()
            .ok_or_else(|| "请先新建或打开案件".to_string())?
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

    let replay_session_id = format!("replay:{clean_name}");
    if record.hits.is_empty() {
        if let Ok(mut searches) = state.searches.lock() {
            searches.insert(
                replay_session_id.clone(),
                SearchSessionState {
                    search_id: replay_session_id,
                    case_folder,
                    query: record.query,
                    encoding: record.encoding,
                    needle_hex: record.needle,
                    image_sha256: record.image_sha256,
                    verification: record.verification,
                    report_name: Some(clean_name.to_string()),
                    cancel: Arc::new(AtomicBool::new(false)),
                    running: false,
                    hits: Vec::new(),
                },
            );
        }
        return Ok(Vec::new());
    }

    // 仅在搜索记录确有命中时再按需构建索引映射，避免 0 命中时扫描 10 万条清单。
    let (dtos, stored_hits): (Vec<SearchHitDto>, Vec<StoredSearchHit>) = {
        let view = state
            .view
            .read()
            .map_err(|_| "视图缓存锁异常".to_string())?;
        let ordered = view.browser_index.ordered();
        let mut entry_lookup = HashMap::with_capacity(ordered.len());
        for (idx, row) in ordered.iter().enumerate() {
            entry_lookup.insert(
                (row.offset, row.inode.clone(), row.deleted, row.path.clone()),
                idx,
            );
        }

        let mut dtos = Vec::with_capacity(record.hits.len());
        let mut stored = Vec::with_capacity(record.hits.len());
        for (idx, h) in record.hits.into_iter().enumerate() {
            let (entry_id, entry_obj) = if let Some(&i) =
                entry_lookup.get(&(h.offset, h.inode.clone(), h.deleted, h.path.clone()))
                && let Some(e) = view.browser_index.get(i)
            {
                (i.to_string(), e.clone())
            } else {
                fallback_hit_entry(&h)
            };
            let dto = SearchHitDto {
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
            };
            stored.push(StoredSearchHit {
                dto: dto.clone(),
                entry: entry_obj,
                source_note: h.source_note,
            });
            dtos.push(dto);
        }
        (dtos, stored)
    };

    // 将历史回放会话注册到 `state.searches`，使回放后的命中项亦可直接点击“保存为取证发现”。
    if let Ok(mut searches) = state.searches.lock() {
        searches.insert(
            replay_session_id.clone(),
            SearchSessionState {
                search_id: replay_session_id,
                case_folder,
                query: record.query,
                encoding: record.encoding,
                needle_hex: record.needle,
                image_sha256: record.image_sha256,
                verification: record.verification,
                report_name: Some(clean_name.to_string()),
                cancel: Arc::new(AtomicBool::new(false)),
                running: false,
                hits: stored_hits,
            },
        );
    }

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

    let path = case
        .with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| c.report(None))
        .map_err(|e| e.to_string())?;

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

/// 生成当前案件的离线自包含单文件 HTML 取证报告（落盘至 `reports/report_*.html` 并追加 `REPORT_GENERATE` 审计记录）。
pub fn cmd_generate_html_report(state: &Arc<AppState>) -> Result<HtmlReportDto, String> {
    let mut case_guard = state
        .case_lock
        .lock()
        .map_err(|_| "案件状态锁异常".to_string())?;
    let case = case_guard
        .as_mut()
        .ok_or_else(|| "请先新建或打开案件".to_string())?;

    let res = case
        .with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| c.generate_html_report(None))
        .map_err(|e| e.to_string())?;

    let mut view = state
        .view
        .write()
        .map_err(|_| "视图缓存锁异常".to_string())?;
    view.sync_from_case(case, false);

    Ok(HtmlReportDto {
        path: res.path.to_string_lossy().into_owned(),
        sha256: res.sha256,
        bytes: res.bytes,
        generated_at: res.generated_at,
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
    let _ = state.reload_case_and_sync_view(case);

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

    let res = case
        .with_write_lock(DESKTOP_WRITE_LOCK_TIMEOUT, |c| {
            build_bundle(
                c,
                &BuildBundleOptions {
                    selected_export_indices,
                    selected_search_indices,
                    skip_missing: true,
                },
                None,
            )
        })
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

/// 独立核验可交付复核包 ZIP（无需先打开案件），返回整包摘要、审计哈希链、跨文件交叉核对与逐成员明细。
pub fn cmd_verify_review_bundle(
    bundle_path: &str,
    expected_sha256: Option<&str>,
) -> Result<BundleVerificationDetailDto, String> {
    let trimmed_path = bundle_path.trim();
    if trimmed_path.is_empty() {
        return Err("请选择或输入复核包 ZIP 文件路径".to_string());
    }
    let clean_expected = expected_sha256.map(str::trim).filter(|s| !s.is_empty());

    let detail = verify_bundle_detailed(Path::new(trimmed_path), clean_expected)
        .map_err(|e| e.to_string())?;

    Ok(BundleVerificationDetailDto {
        ok: detail.ok,
        bundle_path: detail.bundle_path,
        bundle_sha256: detail.bundle_sha256,
        expected_sha256: detail.expected_sha256,
        sha256_source: detail.sha256_source,
        sha256_matched: detail.sha256_matched,
        audit_valid: detail.audit_valid,
        audit_count: detail.audit_count,
        audit_head: detail.audit_head,
        audit_error: detail.audit_error,
        manifest_valid: detail.manifest_valid,
        members: detail
            .members
            .into_iter()
            .map(|m| BundleMemberCheckDto {
                path: m.path,
                category: m.category,
                status: m.status,
                expected_sha256: m.expected_sha256,
                actual_sha256: m.actual_sha256,
                size: m.size,
                message: m.message,
            })
            .collect(),
        cross_checks: detail
            .cross_checks
            .into_iter()
            .map(|c| BundleCrossCheckDto {
                name: c.name,
                status: c.status,
                message: c.message,
            })
            .collect(),
        errors: detail.errors,
    })
}

/* ==========================================================================================
 * 3.5 MCP 托管与系统工具命令
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

/// 查询合并后的 MCP 实时活动与聚合统计（支持客户端、状态、传输方式与关键词筛选）。
pub fn cmd_list_mcp_activities(
    state: &Arc<AppState>,
    limit: Option<usize>,
    client: Option<&str>,
    status: Option<&str>,
    transport: Option<&str>,
    keyword: Option<&str>,
) -> Result<McpActivitySnapshot, String> {
    Ok(state.list_mcp_activities(limit, client, status, transport, keyword))
}

/// 清空内存中的 MCP 活动流并截断跨进程遥测日志 `logs/mcp-activity.jsonl`。
pub fn cmd_clear_mcp_activities(state: &Arc<AppState>) -> Result<Value, String> {
    state.clear_mcp_activities();
    Ok(json!({ "cleared": true }))
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

    // 安全边界校验：仅允许打开当前案件目录、cases_dir 或工作区根目录内的文件与文件夹。
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
        use std::os::windows::process::CommandExt;

        let mut cmd = std::process::Command::new("explorer.exe");
        if reveal_folder {
            if resolved.is_file() {
                let raw_str = resolved.to_string_lossy();
                // Windows `explorer.exe /select,"<path>"` 要求引号紧跟逗号之后，避免路径含空格或逗号时定位失效。
                if !raw_str.contains(['"', '\r', '\n']) {
                    cmd.raw_arg(format!("/select,\"{raw_str}\""));
                } else {
                    cmd.arg(format!("/select,{raw_str}"));
                }
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
            image: "/assets/guide/01_quickstart.webp".to_string(),
            caption: "图 1 · 工作台分区布局与演示流程五大核心入口（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 2,
            title: "创建案件、加载镜像与登记来源".to_string(),
            nav_label: "建案、加载与来源".to_string(),
            summary: "确保源镜像与案件库分离存放，在“镜像与文件系统”页核对固定摘要、卷声明范围与交付方摘要比对结果。".to_string(),
            image: "/assets/guide/02_case_and_source.webp".to_string(),
            caption: "图 2 · 镜像与文件系统页：固定摘要、覆盖范围评估与来源登记（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 3,
            title: "大镜像、完整索引与 SHA-256".to_string(),
            nav_label: "大镜像与 SHA-256".to_string(),
            summary: "逻辑容量达到 1 GiB 时自动切换为按需目录浏览，可边浏览边在后台校验基线，按需建立完整索引。".to_string(),
            image: "/assets/guide/03_large_image.webp".to_string(),
            caption: "图 3 · 大容量镜像按需目录浏览、完整索引与后台校验入口（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 4,
            title: "定位目录、筛选文件与多格式预览".to_string(),
            nav_label: "浏览、筛选与预览".to_string(),
            summary: "左侧保留完整目录树，筛选仅过滤当前范围列表；下方支持文本（9 编码）、图片与十六进制分页预览。".to_string(),
            image: "/assets/guide/04_browse_preview.webp".to_string(),
            caption: "图 4 · 文件树、条件筛选栏与十六进制/多编码分页预览（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 5,
            title: "搜索文件内容并实时复核命中".to_string(),
            nav_label: "内容搜索与复核".to_string(),
            summary: "支持 UTF-8、UTF-16LE、GBK 与 HEX 精确字节检索，结果实时流式展示，搜索期间即可筛选、排除并保存为取证发现。".to_string(),
            image: "/assets/guide/05_content_search.webp".to_string(),
            caption: "图 5 · 内容搜索与复核页：实时流式命中、三态全选与批量保存（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 6,
            title: "导出副本、恢复删除文件与取证发现".to_string(),
            nav_label: "导出与取证发现".to_string(),
            summary: "导出前后自动复核原镜像，支持已删除文件可读字节恢复；右键文件工具与“取证发现”页形成结构化证据归档。".to_string(),
            image: "/assets/guide/06_export_findings.webp".to_string(),
            caption: "图 6 · 取证发现页：表头筛选排序、一键批量导出与分栏取证详情（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 7,
            title: "MACB 时间线与审计日志核验".to_string(),
            nav_label: "时间线与审计日志".to_string(),
            summary: "通过 MACB 时间线还原文件活动脉络，在审计日志中追踪人工与 MCP 全部操作并核验 SHA-256 哈希链。".to_string(),
            image: "/assets/guide/07_timeline_audit.webp".to_string(),
            caption: "图 7 · 审计日志页：人工/MCP 来源筛选、正倒序切换与哈希链详情（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 8,
            title: "生成报告与交付可核验复核包".to_string(),
            nav_label: "报告与复核包".to_string(),
            summary: "生成结构化 Markdown 取证报告，并通过材料选择窗口按需构建可独立离线核验的复核包 ZIP。".to_string(),
            image: "/assets/guide/08_report_bundle.webp".to_string(),
            caption: "图 8 · 复核包材料选择弹窗：缺失中文清单提示、双标签勾选与导出（点击查看大图）".to_string(),
        },
        GuidePageDto {
            index: 9,
            title: "MCP 服务端接入与 AI 协同".to_string(),
            nav_label: "MCP 服务端接入".to_string(),
            summary: "内置标准 MCP 服务端 tracedesk_mcp（19 工具 + 2 资源），采用仅写入瞬间短锁机制，支持在桌面端实时监控外部 stdio 与 HTTP 客户端并自动同步界面。".to_string(),
            image: "/assets/guide/09_mcp_dialog.webp".to_string(),
            caption: "图 9 · MCP 服务配置与实时监控：客户端配置、本地 HTTP 启停与实时协同（点击查看大图）".to_string(),
        },
    ])
}

/* ==========================================================================================
 * Tauri #[tauri::command] 命令封装（重型 I/O 通过 spawn_blocking 非阻塞执行）
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
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_suggest_case_dir(&st, &number, &examiner, &target, parent_dir.as_deref())
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
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
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_close_case(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn release_case_lock(
    state: State<'_, Arc<AppState>>,
) -> Result<CloseCaseResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_close_case(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn get_case_snapshot(
    state: State<'_, Arc<AppState>>,
) -> Result<Option<CaseSnapshot>, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_get_case_snapshot(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
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
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    offset: u64,
) -> Result<ScanPartitionsResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_scan_partition(&st, offset, Some(&app)))
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
    inode: Option<String>,
    group_index: Option<usize>,
) -> Result<TreeChildrenResponse, String> {
    let st = Arc::clone(&state);
    // 大镜像按需模式下首次展开目录会调用 TSK `fls` 读盘，放入阻塞线程池避免卡住 UI 主线程。
    tauri::async_runtime::spawn_blocking(move || {
        cmd_get_tree_children(&st, offset, &scope_path, inode.as_deref(), group_index)
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
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
pub async fn scan_magic_mismatches(
    state: State<'_, Arc<AppState>>,
) -> Result<MagicScanReport, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_scan_magic_mismatches(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn inspect_entry_magic(
    state: State<'_, Arc<AppState>>,
    entry_key: String,
) -> Result<MagicCheckItem, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_inspect_entry_magic(&st, &entry_key))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
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
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_start_content_search(
            &st,
            &query,
            &encoding,
            selected_entry_id.as_deref(),
            Some(&app),
        )
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
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
pub async fn generate_html_report(
    state: State<'_, Arc<AppState>>,
) -> Result<HtmlReportDto, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_generate_html_report(&st))
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
pub async fn verify_review_bundle(
    bundle_path: String,
    expected_sha256: Option<String>,
) -> Result<BundleVerificationDetailDto, String> {
    tauri::async_runtime::spawn_blocking(move || {
        cmd_verify_review_bundle(&bundle_path, expected_sha256.as_deref())
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
pub async fn list_mcp_activities(
    state: State<'_, Arc<AppState>>,
    limit: Option<usize>,
    client: Option<String>,
    status: Option<String>,
    transport: Option<String>,
    keyword: Option<String>,
) -> Result<McpActivitySnapshot, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        cmd_list_mcp_activities(
            &st,
            limit,
            client.as_deref(),
            status.as_deref(),
            transport.as_deref(),
            keyword.as_deref(),
        )
    })
    .await
    .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn clear_mcp_activities(state: State<'_, Arc<AppState>>) -> Result<Value, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_clear_mcp_activities(&st))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
}

#[tauri::command]
pub async fn open_in_os(
    state: State<'_, Arc<AppState>>,
    path: String,
    reveal_folder: bool,
) -> Result<OpenInOsResponse, String> {
    let st = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || cmd_open_in_os(&st, &path, reveal_folder))
        .await
        .map_err(|e| format!("后台任务执行异常：{e}"))?
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
