//! TraceDesk MCP 业务服务编排层：
//! - 单次工具调用按需获取 `case.lock` 并在调用结束时立即释放锁（避免与桌面端死锁）
//! - 强制写入审计链 `origin = "mcp"`
//! - 针对只读高频查询（`list_files` / `query_timeline` / `list_findings` / `query_audit_log` / `get_case_summary`）
//!   按 `(case_dir, case.json 指纹, inventory 文件指纹, audit 指纹)` 缓存只读解析视图与时间线索引，
//!   消除重复 gunzip 解压与时间线重排开销，且磁盘文件一旦变化立即刷新
//! - 提供强制释放残留 `case.lock` 及客户端配置生成辅助函数

use std::cell::RefCell;
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use lru::LruCache;
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;
use tracedesk_core::{
    AppPaths, AuditOrigin, AuditRecord, BuildBundleOptions, Case, CaseData, CoreError,
    FindingGroup, PAGE_BYTES, PREVIEW_ENCODINGS, Provenance, SOURCE_FIELDS, SearchOptions,
    TimelineFilter, TimelineIndex, action_title, audit_mcp_user, audit_origin, audit_origin_label,
    build_bundle, can_export, coverage_text, deleted_source_note, display_iso_time,
    display_timestamp, entry_name, entry_status, examine, export_findings as do_export_findings,
    group_findings, is_within, normalize_event_filter, operation_title, preview_entry_page,
    record_note, resolve_clean, search_case, sha256_hex, source_status, verify_audit_chain_at,
};
use tracedesk_engines::{CaseFileLock, InventoryEntry};

/// MCP 服务层统一错误类型，对应 Python `ValueError` / `FileNotFoundError` / `RuntimeError` / `OSError`。
#[derive(Debug, Error)]
pub enum McpError {
    #[error("{0}")]
    ValueError(String),

    #[error("{0}")]
    FileNotFoundError(String),

    #[error("{0}")]
    RuntimeError(String),

    #[error("{0}")]
    IoError(String),
}

impl McpError {
    /// 返回与 `mcp-contract.md` §1.3.6 对齐的错误分类名。
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::ValueError(_) => "ValueError",
            Self::FileNotFoundError(_) => "FileNotFoundError",
            Self::RuntimeError(_) => "RuntimeError",
            Self::IoError(_) => "OSError",
        }
    }

    /// 格式化为 `Error (<ErrorKind>): <中文错误说明>`。
    pub fn format_error(&self) -> String {
        format!("Error ({}): {}", self.kind_name(), self)
    }
}

impl From<CoreError> for McpError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::InvalidInput(msg) => Self::ValueError(msg),
            CoreError::CorruptCase(msg) => Self::ValueError(format!("案件数据损坏：{msg}")),
            CoreError::NotFound(msg) | CoreError::MissingMaterials(msg) => {
                Self::FileNotFoundError(msg)
            }
            CoreError::Locked(msg) => Self::RuntimeError(msg),
            CoreError::Io(e) => Self::IoError(e.to_string()),
            CoreError::Json(e) => Self::ValueError(e.to_string()),
            other => Self::RuntimeError(other.to_string()),
        }
    }
}

impl From<std::io::Error> for McpError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

pub type McpResult<T> = Result<T, McpError>;

const READ_CACHE_CAPACITY: usize = 16;

/// 当人工使用者与客户端标识均缺失时的默认 MCP 调用方回退标记。
pub const DEFAULT_MCP_CLIENT_LABEL: &str = "本地 MCP 客户端";

/// MCP 使用者/客户端标识允许的最大字符长度，避免异常长请求头污染审计日志。
const MAX_MCP_IDENTITY_CHARS: usize = 120;

/// 当前线程单次 MCP 调用生效的传输层调用方上下文。
#[derive(Debug, Clone, Default)]
struct ActiveCallerScope {
    /// 来自 HTTP 头 `X-MCP-User` 等传输层的显式使用者名称。
    header_user: Option<String>,
    /// 来自 HTTP 头或 `initialize.clientInfo` 的客户端标识。
    client_name: Option<String>,
}

thread_local! {
    static ACTIVE_CALLER_SCOPE: RefCell<Option<ActiveCallerScope>> = const { RefCell::new(None) };
}

/// 线程局部调用方上下文 RAII 守卫，确保函数正常返回或 panic 时均自动恢复先前状态。
struct CallerScopeGuard {
    previous: Option<ActiveCallerScope>,
}

impl Drop for CallerScopeGuard {
    fn drop(&mut self) {
        ACTIVE_CALLER_SCOPE.with(|cell| {
            *cell.borrow_mut() = self.previous.take();
        });
    }
}

/// 清理 MCP 使用者/客户端标识字符串：过滤控制字符、折叠空白并限制最大字符数。
pub fn sanitize_mcp_identity(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    let truncated: String = collapsed.chars().take(MAX_MCP_IDENTITY_CHARS).collect();
    let trimmed = truncated.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// 去除文本中的 `(MCP)` / `（MCP）` 泛化标记（大小写不敏感）。
fn strip_generic_mcp_marker(raw: &str) -> String {
    let mut current = raw.trim().to_string();
    loop {
        let lower = current.to_lowercase();
        let found = lower
            .find("(mcp)")
            .map(|pos| (pos, "(mcp)".len()))
            .or_else(|| lower.find("（mcp）").map(|pos| (pos, "（mcp）".len())));
        let Some((pos, len)) = found else {
            break;
        };
        if current.len() == lower.len()
            && current.is_char_boundary(pos)
            && current.is_char_boundary(pos + len)
        {
            current.replace_range(pos..pos + len, " ");
        } else {
            let replaced = current
                .replace("(MCP)", " ")
                .replace("(mcp)", " ")
                .replace("(Mcp)", " ")
                .replace("（MCP）", " ")
                .replace("（mcp）", " ")
                .replace("（Mcp）", " ");
            if replaced == current {
                break;
            }
            current = replaced;
        }
    }
    current.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// 规范化显式人工使用者名称（排除空值与泛化 `"MCP"`）。
pub fn normalize_explicit_user(raw: Option<&str>) -> Option<String> {
    let sanitized = raw.and_then(sanitize_mcp_identity)?;
    let stripped = strip_generic_mcp_marker(&sanitized);
    if stripped.is_empty() || stripped.eq_ignore_ascii_case("MCP") {
        None
    } else {
        Some(stripped)
    }
}

/// 按统一规则合成写入 `audit.jsonl` 的 `mcp_client` 标识：
/// - 若同时存在明确人工使用者（非泛化 `"MCP"`）与客户端名（且二者不同），合并为 `"<使用者> / <客户端>"`；
/// - 若仅有一项，则直接使用该项；
/// - 若均缺失，则回退为 `"本地 MCP 客户端"`。
pub fn compose_mcp_client(explicit_user: Option<&str>, client_name: Option<&str>) -> String {
    let user = normalize_explicit_user(explicit_user);
    let client = client_name
        .and_then(sanitize_mcp_identity)
        .filter(|s| !s.eq_ignore_ascii_case("MCP"));

    match (user, client) {
        (Some(u), Some(c)) => {
            if u.eq_ignore_ascii_case(&c) {
                c
            } else {
                format!("{u} / {c}")
            }
        }
        (Some(u), None) => u,
        (None, Some(c)) => c,
        (None, None) => DEFAULT_MCP_CLIENT_LABEL.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStampKey {
    len: u64,
    mtime_ns: Option<i128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaseDataCacheKey {
    case_dir: PathBuf,
    case_json_stamp: FileStampKey,
    case_json_sha256: String,
    inventory_file: Option<String>,
    inventory_stamp: Option<FileStampKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditCacheKey {
    audit_jsonl_stamp: FileStampKey,
    audit_jsonl_sha256: String,
    audit_head_raw: Option<String>,
}

struct CachedCaseView {
    key: CaseDataCacheKey,
    data: Arc<CaseData>,
    browsing_directories: bool,
    needs_partition_scan: bool,
    timeline: OnceLock<Arc<TimelineIndex>>,
}

struct CachedAuditView {
    key: AuditCacheKey,
    records: Arc<Vec<AuditRecord>>,
}

#[derive(Default)]
struct ServiceCache {
    cases: Option<LruCache<PathBuf, Arc<CachedCaseView>>>,
    audits: Option<LruCache<PathBuf, Arc<CachedAuditView>>>,
}

impl ServiceCache {
    fn new() -> Self {
        let cap = NonZeroUsize::new(READ_CACHE_CAPACITY).expect("non-zero cache capacity");
        Self {
            cases: Some(LruCache::new(cap)),
            audits: Some(LruCache::new(cap)),
        }
    }

    fn cases_mut(&mut self) -> &mut LruCache<PathBuf, Arc<CachedCaseView>> {
        self.cases.get_or_insert_with(|| {
            LruCache::new(NonZeroUsize::new(READ_CACHE_CAPACITY).expect("non-zero"))
        })
    }

    fn audits_mut(&mut self) -> &mut LruCache<PathBuf, Arc<CachedAuditView>> {
        self.audits.get_or_insert_with(|| {
            LruCache::new(NonZeroUsize::new(READ_CACHE_CAPACITY).expect("non-zero"))
        })
    }
}

fn system_time_to_ns(t: SystemTime) -> Option<i128> {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos() as i128)
}

fn file_stamp_key(path: &Path) -> Option<FileStampKey> {
    let meta = fs::metadata(path).ok()?;
    Some(FileStampKey {
        len: meta.len(),
        mtime_ns: meta.modified().ok().and_then(system_time_to_ns),
    })
}

fn compute_case_cache_key(folder: &Path) -> Option<CaseDataCacheKey> {
    let case_json_path = folder.join("case.json");
    let case_json_stamp = file_stamp_key(&case_json_path)?;
    let raw_bytes = fs::read(&case_json_path).ok()?;
    let case_json_sha256 = sha256_hex(&raw_bytes);
    let root_val: Value = serde_json::from_slice(&raw_bytes).ok()?;
    let obj = root_val.as_object()?;
    // 若旧版内联 `inventory` 非空且尚未生成 `inventory_file`，则跳过缓存键，以便 `Case::open`
    // 优先执行自动 `.jsonl.gz` 迁移。
    let inventory_file = obj
        .get("inventory_file")
        .and_then(Value::as_str)
        .map(str::to_string);
    if inventory_file.is_none()
        && obj
            .get("inventory")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
    {
        return None;
    }
    let inventory_stamp = match inventory_file {
        Some(ref name) => Some(file_stamp_key(&folder.join(name))?),
        None => None,
    };
    Some(CaseDataCacheKey {
        case_dir: folder.to_path_buf(),
        case_json_stamp,
        case_json_sha256,
        inventory_file,
        inventory_stamp,
    })
}

fn compute_audit_cache_key(folder: &Path) -> Option<AuditCacheKey> {
    let audit_path = folder.join("audit.jsonl");
    let audit_jsonl_stamp = file_stamp_key(&audit_path)?;
    let raw_bytes = fs::read(&audit_path).ok()?;
    let audit_jsonl_sha256 = sha256_hex(&raw_bytes);
    let head_path = folder.join("audit.head");
    let audit_head_raw = if head_path.exists() {
        Some(fs::read_to_string(&head_path).ok()?)
    } else {
        None
    };
    Some(AuditCacheKey {
        audit_jsonl_stamp,
        audit_jsonl_sha256,
        audit_head_raw,
    })
}

/// 规范化镜像内文件路径（把 `\` 转为 `/`，去除首尾空白与前导 `/`）。
pub fn normalize_entry_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim()
        .trim_start_matches('/')
        .to_string()
}

/// 将 [`InventoryEntry`] 转换为 MCP 契约规定的 `FormattedEntry` JSON 结构。
pub fn format_entry(entry: &InventoryEntry) -> Value {
    json!({
        "path": entry.path,
        "name": entry_name(entry),
        "partition_offset": entry.offset,
        "inode": entry.inode,
        "directory": entry.directory,
        "mode": entry.mode,
        "size": entry.size,
        "deleted": entry.deleted,
        "reallocated": entry.reallocated,
        "start_cluster_allocated": entry.start_cluster_allocated.unwrap_or(false),
        "status": entry_status(entry),
        "exportable": can_export(entry),
        "filesystem": entry.filesystem,
        "mtime": display_timestamp(entry.mtime, false),
        "atime": display_timestamp(entry.atime, false),
        "ctime": display_timestamp(entry.ctime, false),
        "crtime": display_timestamp(entry.crtime, false),
        "source_note": deleted_source_note(entry),
    })
}

/// 通用分页结果包装（`total`, `count`, `offset`, `limit`, `has_more`, `next_offset`, `items`）。
pub fn paginate<T: Serialize>(items: &[T], limit: usize, offset: usize) -> Value {
    let total = items.len();
    let start = offset.min(total);
    let end = start.saturating_add(limit).min(total);
    let sliced = &items[start..end];
    let count = sliced.len();
    let has_more = offset.saturating_add(count) < total;
    let next_offset = if has_more {
        Some(offset.saturating_add(count))
    } else {
        None
    };
    json!({
        "total": total,
        "count": count,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
        "next_offset": next_offset,
        "items": sliced,
    })
}

fn lock_contention_error(folder: &Path) -> McpError {
    McpError::RuntimeError(format!(
        "案件目录 {} 当前已被 TraceDesk 桌面端或其他进程锁定。请先在桌面端关闭该案件或切换至其他案件后再重试。",
        folder.display()
    ))
}

/// 尝试清理/强制释放指定案件目录下的残留 `case.lock` 文件。
///
/// - 若 `case.lock` 当前正被其他存活进程持有 OS 内核锁，返回明确错误提示；
/// - 若 `case.lock` 是上次异常退出残留的未加锁文件，安全释放并删除该锁文件，返回 `Ok(true)`；
/// - 若 `case.lock` 不存在，返回 `Ok(false)`。
pub fn force_release_case_lock(case_dir: &Path) -> McpResult<bool> {
    let resolved = resolve_clean(case_dir);
    let folder = if resolved.is_file()
        && resolved
            .file_name()
            .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("case.json"))
    {
        resolved
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or(resolved)
    } else {
        resolved
    };
    let lock_path = folder.join("case.lock");
    if !lock_path.exists() {
        return Ok(false);
    }
    let lease = CaseFileLock::acquire(&lock_path).map_err(|_| lock_contention_error(&folder))?;
    lease.unlock();
    let _ = fs::remove_file(&lock_path);
    Ok(true)
}

/// 面向 MCP 工具的案件与证据编排服务，按单次调用安全加锁并及时释放 `case.lock`。
pub struct CaseService {
    cases_root: PathBuf,
    default_actor: Option<String>,
    cache: Mutex<ServiceCache>,
}

impl CaseService {
    /// 创建绑定到指定 `cases_root` 与可选默认操作人 `default_actor` 的 [`CaseService`]。
    pub fn new(cases_root: Option<PathBuf>, default_actor: Option<String>) -> Self {
        let resolved_root = match cases_root {
            Some(p) if !p.as_os_str().is_empty() => resolve_clean(&p),
            _ => AppPaths::discover().cases_dir,
        };
        let clean_actor = default_actor
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self {
            cases_root: resolved_root,
            default_actor: clean_actor,
            cache: Mutex::new(ServiceCache::new()),
        }
    }

    pub fn cases_root(&self) -> &Path {
        &self.cases_root
    }

    pub fn default_actor(&self) -> Option<&str> {
        self.default_actor.as_deref()
    }

    /// 解析 `case_dir` 参数（支持绝对路径、相对 `cases_root` 的文件夹名、或直接传 `case.json` 路径）。
    pub fn resolve_case_dir(&self, case_dir: &str) -> McpResult<PathBuf> {
        let trimmed = case_dir.trim();
        let raw = Path::new(trimmed);
        let candidates: Vec<PathBuf> = if raw.is_absolute() {
            vec![raw.to_path_buf()]
        } else {
            vec![self.cases_root.join(raw), raw.to_path_buf()]
        };

        for candidate in candidates {
            let mut resolved = resolve_clean(&candidate);
            if resolved.is_file()
                && resolved
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("case.json"))
                && let Some(parent) = resolved.parent()
            {
                resolved = parent.to_path_buf();
            }
            if resolved.join("case.json").is_file() {
                return Ok(resolved);
            }
        }

        Err(McpError::FileNotFoundError(format!(
            "未找到有效案件目录（缺少 case.json）：{trimmed}。请先调用 tracedesk_list_cases 查看已有案件，或调用 tracedesk_create_case 新建案件。"
        )))
    }

    /// 强制释放指定案件目录的残留 `case.lock`。
    pub fn release_case_lock(&self, case_dir: &str) -> McpResult<bool> {
        let folder = self.resolve_case_dir(case_dir)?;
        force_release_case_lock(&folder)
    }

    /// 在当前线程作用域内绑定本次 MCP 调用的传输层使用者与客户端标识（支持嵌套并自动恢复）。
    pub fn with_caller_scope<F, R>(
        header_user: Option<&str>,
        client_name: Option<&str>,
        f: F,
    ) -> R
    where
        F: FnOnce() -> R,
    {
        let next = ActiveCallerScope {
            header_user: header_user.and_then(sanitize_mcp_identity),
            client_name: client_name.and_then(sanitize_mcp_identity),
        };
        let previous = ACTIVE_CALLER_SCOPE.with(|cell| cell.borrow_mut().replace(next));
        let _guard = CallerScopeGuard { previous };
        f()
    }

    /// 结合工具参数 `actor`、传输层 `X-MCP-User`、`--actor`/`TRACEDESK_MCP_ACTOR` 与客户端名，
    /// 解析本次操作应写入审计链的 `(actor, mcp_client)`。
    fn resolve_caller_identity(&self, actor: Option<&str>) -> (Option<String>, String) {
        let (scoped_user, scoped_client) = ACTIVE_CALLER_SCOPE.with(|cell| {
            cell.borrow()
                .as_ref()
                .map(|s| (s.header_user.clone(), s.client_name.clone()))
                .unwrap_or((None, None))
        });
        let explicit_actor = actor
            .and_then(sanitize_mcp_identity)
            .or(scoped_user)
            .or_else(|| self.default_actor.clone());
        let mcp_client = compose_mcp_client(explicit_actor.as_deref(), scoped_client.as_deref());
        (explicit_actor, mcp_client)
    }

    /// 打开案件并持有 `case.lock`（固定 `AuditOrigin::Mcp` 且写入 `mcp_client`），随返回值 `Drop` 自动释放锁。
    pub fn open_case(&self, case_dir: &str, actor: Option<&str>) -> McpResult<Case> {
        let folder = self.resolve_case_dir(case_dir)?;
        let (explicit_actor, mcp_client) = self.resolve_caller_identity(actor);
        match Case::open_with_mcp_client(
            &folder,
            explicit_actor.as_deref(),
            AuditOrigin::Mcp,
            Some(&mcp_client),
        ) {
            Ok(case) => Ok(case),
            Err(err) if err.is_locked() => Err(lock_contention_error(&folder)),
            Err(err) => Err(McpError::from(err)),
        }
    }

    /// 从已打开的 [`Case`] 刷新只读视图缓存。
    fn update_case_cache_from_open(&self, case: &Case) {
        let folder = case.folder();
        if let Some(key) = compute_case_cache_key(folder) {
            let view = Arc::new(CachedCaseView {
                key,
                data: Arc::new(case.data().clone()),
                browsing_directories: case.browsing_directories(),
                needs_partition_scan: case.needs_partition_scan(),
                timeline: OnceLock::new(),
            });
            if let Ok(mut guard) = self.cache.lock() {
                guard.cases_mut().put(folder.to_path_buf(), view);
            }
        }
    }

    fn update_audit_cache(&self, folder: &Path, records: Vec<AuditRecord>) -> Arc<Vec<AuditRecord>> {
        let arc_records = Arc::new(records);
        if let Some(key) = compute_audit_cache_key(folder) {
            let view = Arc::new(CachedAuditView {
                key,
                records: Arc::clone(&arc_records),
            });
            if let Ok(mut guard) = self.cache.lock() {
                guard.audits_mut().put(folder.to_path_buf(), view);
            }
        }
        arc_records
    }

    /// 在持有 `case.lock` 的前提下获取只读 [`CachedCaseView`]（命中缓存时免除 gunzip 开销）。
    fn with_read_case_view<F, R>(
        &self,
        case_dir: &str,
        actor: Option<&str>,
        f: F,
    ) -> McpResult<R>
    where
        F: FnOnce(&Path, &Arc<CachedCaseView>) -> McpResult<R>,
    {
        let folder = self.resolve_case_dir(case_dir)?;
        let lease = CaseFileLock::acquire(&folder.join("case.lock"))
            .map_err(|_| lock_contention_error(&folder))?;

        if let Some(expected_key) = compute_case_cache_key(&folder) {
            let cached = self
                .cache
                .lock()
                .ok()
                .and_then(|mut g| g.cases_mut().get(&folder).cloned())
                .filter(|v| v.key == expected_key);
            if let Some(view) = cached {
                let res = self
                    .verified_audit_records(&folder)
                    .and_then(|_| f(&folder, &view));
                lease.unlock();
                return res;
            }
        }

        // 缓存未命中或磁盘文件已变更：先释放探测锁，再完整打开 `Case`（自动校验元数据、审计链
        // 并在需要时迁移内联清单），随后刷新缓存并在 `case` 持有 `case.lock` 期间执行 `f`。
        lease.unlock();
        let mut case = self.open_case(case_dir, actor)?;
        let records = case.check_audit()?;
        self.update_case_cache_from_open(&case);
        self.update_audit_cache(&folder, records);

        let fallback_key = compute_case_cache_key(&folder).unwrap_or_else(|| CaseDataCacheKey {
            case_dir: folder.clone(),
            case_json_stamp: FileStampKey {
                len: 0,
                mtime_ns: None,
            },
            case_json_sha256: String::new(),
            inventory_file: None,
            inventory_stamp: None,
        });
        let view = self
            .cache
            .lock()
            .ok()
            .and_then(|mut g| g.cases_mut().get(&folder).cloned())
            .unwrap_or_else(|| {
                Arc::new(CachedCaseView {
                    key: fallback_key,
                    data: Arc::new(case.data().clone()),
                    browsing_directories: case.browsing_directories(),
                    needs_partition_scan: case.needs_partition_scan(),
                    timeline: OnceLock::new(),
                })
            });
        let res = f(&folder, &view);
        case.close();
        res
    }

    /// 在已持有 `case.lock` 的作用域内核验或读取缓存的审计链记录（磁盘一旦修改立即重新验链）。
    fn verified_audit_records(&self, folder: &Path) -> McpResult<Arc<Vec<AuditRecord>>> {
        if let Some(expected_key) = compute_audit_cache_key(folder) {
            let cached = self
                .cache
                .lock()
                .ok()
                .and_then(|mut g| g.audits_mut().get(folder).cloned())
                .filter(|v| v.key == expected_key);
            if let Some(view) = cached {
                return Ok(Arc::clone(&view.records));
            }
        }
        let records = verify_audit_chain_at(folder)?;
        Ok(self.update_audit_cache(folder, records))
    }

    fn ensure_large_image_session(case: &mut Case, verify_if_needed: bool) -> McpResult<()> {
        let Some(ref evidence) = case.data().evidence else {
            return Ok(());
        };
        if !evidence.is_large_image() {
            return Ok(());
        }
        let has_sha = evidence
            .sha256
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
        if has_sha && !case.is_session_verified() {
            if verify_if_needed {
                case.verify_integrity(None, None, None)?;
            } else {
                return Err(McpError::ValueError(
                    "该案件为 1 GiB 以上大容量镜像，重新打开后尚未完成本次会话校验。请将 verify_large_image 设为 true，或先在工作台执行完整性校验。"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn find_entry_in_slice(
        entries: &[InventoryEntry],
        raw_path: &str,
        partition_offset: Option<u64>,
        inode: Option<&str>,
        deleted: Option<bool>,
    ) -> McpResult<InventoryEntry> {
        let target_path = normalize_entry_path(raw_path);
        if target_path.is_empty() {
            return Err(McpError::ValueError("文件路径 path 不能为空。".to_string()));
        }
        let target_lower = target_path.to_lowercase();
        let inode_filter = inode.map(str::trim).filter(|s| !s.is_empty());

        let mut matches = Vec::new();
        for entry in entries {
            if normalize_entry_path(&entry.path).to_lowercase() != target_lower {
                continue;
            }
            if let Some(off) = partition_offset
                && entry.offset != off
            {
                continue;
            }
            if let Some(ino) = inode_filter
                && entry.inode != ino
            {
                continue;
            }
            if let Some(del) = deleted
                && entry.deleted != del
            {
                continue;
            }
            matches.push(entry.clone());
        }

        if matches.is_empty() {
            return Err(McpError::ValueError(format!(
                "未在当前案件清单中找到文件：{raw_path}。请先调用 tracedesk_list_files 确认准确的 path、partition_offset 和 inode。"
            )));
        }
        if matches.len() > 1 {
            let candidates: Vec<String> = matches
                .iter()
                .take(10)
                .map(|e| {
                    format!(
                        "(partition_offset={}, inode={}, deleted={}, size={})",
                        e.offset, e.inode, e.deleted, e.size
                    )
                })
                .collect();
            return Err(McpError::ValueError(format!(
                "路径 {raw_path} 匹配到 {} 条记录，存在同名或跨分区歧义：{}。请补充 partition_offset、inode 或 deleted 参数以唯一定位目标文件。",
                matches.len(),
                candidates.join("；")
            )));
        }
        Ok(matches.swap_remove(0))
    }

    fn find_entry(
        case: &mut Case,
        path: &str,
        partition_offset: Option<u64>,
        inode: Option<&str>,
        deleted: Option<bool>,
        dir_inode: Option<&str>,
        dir_path: &str,
    ) -> McpResult<InventoryEntry> {
        let target_path = normalize_entry_path(path);
        if target_path.is_empty() {
            return Err(McpError::ValueError("文件路径 path 不能为空。".to_string()));
        }

        if case.browsing_directories() {
            let Some(off) = partition_offset else {
                return Err(McpError::ValueError(
                    "当前为大容量镜像快速浏览模式（尚未建立完整文件索引）。请先调用 tracedesk_scan_partitions 建立完整文件索引，或同时提供 partition_offset 与所在目录参数。"
                        .to_string(),
                ));
            };
            let trimmed_dir = dir_path.trim();
            let parent = if !trimmed_dir.is_empty() {
                normalize_entry_path(trimmed_dir)
            } else if let Some((p, _)) = target_path.rsplit_once('/') {
                p.to_string()
            } else {
                String::new()
            };
            let clean_dir_inode = dir_inode.map(str::trim).filter(|s| !s.is_empty());
            case.browse_directory(off, clean_dir_inode, &parent, None)?;
        }

        Self::find_entry_in_slice(
            case.displayed_entries(),
            path,
            partition_offset,
            inode,
            deleted,
        )
    }

    /// 1. `tracedesk_list_cases`：只读扫描案件库目录，不获取 `case.lock`。
    pub fn list_cases(
        &self,
        cases_root: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> McpResult<Value> {
        let root = match cases_root.map(str::trim).filter(|s| !s.is_empty()) {
            Some(explicit) => resolve_clean(Path::new(explicit)),
            None => self.cases_root.clone(),
        };
        let root_str = root.to_string_lossy().into_owned();
        if !root.exists() {
            let page = paginate::<Value>(&[], limit, offset);
            let mut out = serde_json::Map::new();
            out.insert("cases_root".to_string(), Value::String(root_str));
            if let Some(obj) = page.as_object() {
                for (k, v) in obj {
                    out.insert(k.clone(), v.clone());
                }
            }
            return Ok(Value::Object(out));
        }
        if !root.is_dir() {
            return Err(McpError::ValueError(format!(
                "案件库路径不是有效目录：{root_str}"
            )));
        }

        let mut children: Vec<PathBuf> = fs::read_dir(&root)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        children.sort_by_key(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default()
        });

        let mut rows: Vec<Value> = Vec::new();
        for child in children {
            let metadata_file = child.join("case.json");
            if !child.is_dir() || !metadata_file.is_file() {
                continue;
            }
            let folder_str = resolve_clean(&child).to_string_lossy().into_owned();
            let name_str = child
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            let parsed: Option<Value> = fs::read_to_string(&metadata_file)
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok());
            let Some(Value::Object(data)) = parsed else {
                rows.push(json!({
                    "folder": folder_str,
                    "name": name_str,
                    "status": "invalid_metadata",
                }));
                continue;
            };

            let ev_obj = data.get("evidence").and_then(Value::as_object);
            let has_evidence = ev_obj.is_some();
            let image_path = ev_obj
                .and_then(|e| e.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let image_name = if !image_path.is_empty() {
                Path::new(image_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let image_format = if has_evidence {
                ev_obj
                    .and_then(|e| e.get("format"))
                    .and_then(Value::as_str)
                    .unwrap_or("RAW")
            } else {
                ""
            };
            let image_size = if has_evidence {
                ev_obj
                    .and_then(|e| e.get("size"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            } else {
                0
            };
            let sha256_fixed = ev_obj
                .and_then(|e| e.get("sha256"))
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty());
            let inventory_count = data
                .get("inventory_count")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| {
                    data.get("inventory")
                        .and_then(Value::as_array)
                        .map_or(0, |a| a.len() as u64)
                });
            let exports_count = data
                .get("exports")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            let created_raw = data.get("created").and_then(Value::as_str).unwrap_or("");

            rows.push(json!({
                "folder": folder_str,
                "name": name_str,
                "id": data.get("id").and_then(Value::as_str).unwrap_or(""),
                "number": data.get("number").and_then(Value::as_str).unwrap_or(""),
                "examiner": data.get("examiner").and_then(Value::as_str).unwrap_or(""),
                "target": data.get("target").and_then(Value::as_str).unwrap_or(""),
                "created": display_iso_time(created_raw, false),
                "has_evidence": has_evidence,
                "image_name": image_name,
                "image_path": image_path,
                "image_format": image_format,
                "image_size": image_size,
                "sha256_fixed": sha256_fixed,
                "inventory_count": inventory_count,
                "exports_count": exports_count,
                "status": "ok",
            }));
        }

        rows.sort_by(|a, b| {
            let ca = a.get("created").and_then(Value::as_str).unwrap_or("");
            let cb = b.get("created").and_then(Value::as_str).unwrap_or("");
            cb.cmp(ca)
        });

        let page = paginate(&rows, limit, offset);
        let mut out = serde_json::Map::new();
        out.insert("cases_root".to_string(), Value::String(root_str));
        if let Some(obj) = page.as_object() {
            for (k, v) in obj {
                out.insert(k.clone(), v.clone());
            }
        }
        Ok(Value::Object(out))
    }

    /// 2. `tracedesk_create_case`：创建隔离案件并以 `origin = "mcp"` 记录初始审计链。
    pub fn create_case(
        &self,
        number: &str,
        examiner: &str,
        target: &str,
        cases_root: Option<&str>,
        folder_name: Option<&str>,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let root = match cases_root.map(str::trim).filter(|s| !s.is_empty()) {
            Some(explicit) => resolve_clean(Path::new(explicit)),
            None => self.cases_root.clone(),
        };
        let clean_folder = folder_name.map(str::trim).filter(|s| !s.is_empty());
        let (explicit_actor, mcp_client) = self.resolve_caller_identity(actor);
        let mut case = Case::create_with_mcp_client(
            &root,
            number.trim(),
            examiner.trim(),
            target.trim(),
            clean_folder,
            explicit_actor.as_deref(),
            AuditOrigin::Mcp,
            Some(&mcp_client),
        )?;
        let latest = case.check_audit()?.pop();
        self.update_case_cache_from_open(&case);
        let data = case.data();
        let origin_label = latest
            .as_ref()
            .map(audit_origin_label)
            .unwrap_or_else(|| format!("MCP · {mcp_client}"));
        let resolved_client = latest.as_ref().and_then(audit_mcp_user).or(Some(mcp_client));
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "id": data.id,
            "number": data.number,
            "examiner": data.examiner,
            "target": data.target,
            "origin": "mcp",
            "origin_label": origin_label,
            "mcp_client": resolved_client,
            "created": display_iso_time(&data.created, false),
        });
        case.close();
        Ok(out)
    }

    /// 3. `tracedesk_get_case_summary`：读取案件总览并核验审计哈希链。
    pub fn get_case_summary(&self, case_dir: &str, actor: Option<&str>) -> McpResult<Value> {
        self.with_read_case_view(case_dir, actor, |folder, view| {
            let records = self.verified_audit_records(folder)?;
            let data = &view.data;
            let findings_groups = group_findings(&records);
            let findings_file_count = findings_groups.len();
            let findings_record_count: usize =
                findings_groups.iter().map(|g| g.records.len()).sum();
            let mcp_count = records
                .iter()
                .filter(|r| audit_origin(r) == AuditOrigin::Mcp)
                .count();
            let manual_count = records.len().saturating_sub(mcp_count);
            let audit_head = records
                .last()
                .map(|r| r.hash.clone())
                .unwrap_or_default();

            let evidence_val = match data.evidence.as_ref() {
                None => Value::Null,
                Some(ev) => {
                    let fixed_at = ev
                        .fixed_at
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .map(|s| display_iso_time(s, false))
                        .unwrap_or_default();
                    let provenance_val = match ev.provenance.as_ref() {
                        Some(p) => serde_json::to_value(p).unwrap_or_else(|_| json!({})),
                        None => json!({}),
                    };
                    json!({
                        "path": ev.path,
                        "format": ev.format_label(),
                        "size": ev.size,
                        "large_image": ev.is_large_image(),
                        "sha256": ev.sha256,
                        "fixed_at": fixed_at,
                        "partitions": ev.partitions,
                        "provenance": provenance_val,
                        "source_comparison": source_status(ev),
                        "coverage": ev.coverage,
                        "coverage_text": coverage_text(ev.coverage.as_ref()),
                        "segments_count": ev.segments.as_ref().map_or(0, Vec::len),
                    })
                }
            };

            Ok(json!({
                "case_dir": folder.to_string_lossy(),
                "id": data.id,
                "number": data.number,
                "examiner": data.examiner,
                "target": data.target,
                "created": display_iso_time(&data.created, false),
                "browsing_directories": view.browsing_directories,
                "needs_partition_scan": view.needs_partition_scan,
                "inventory_count": data.inventory.len(),
                "exports_count": data.exports.len(),
                "findings_file_count": findings_file_count,
                "findings_record_count": findings_record_count,
                "audit_count": records.len(),
                "audit_origin_counts": {
                    "manual": manual_count,
                    "mcp": mcp_count,
                },
                "audit_head": audit_head,
                "audit_chain_valid": true,
                "evidence": evidence_val,
                "partition_scans": data.partition_scans.clone().unwrap_or_default(),
                "verification": data.verification,
            }))
        })
    }

    /// 4. `tracedesk_load_image`：以只读模式载入 RAW 或分段 EWF (`.E01`) 镜像。
    pub fn load_image(
        &self,
        case_dir: &str,
        image_path: &str,
        scan_all: bool,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let mut case = self.open_case(case_dir, actor)?;
        let img = Path::new(image_path.trim());
        if is_within(img, &self.cases_root) {
            return Err(McpError::ValueError(
                "镜像必须是案件库目录之外的普通文件".to_string(),
            ));
        }
        case.load_image(img, None, None, None)?;
        let is_large = case
            .data()
            .evidence
            .as_ref()
            .is_some_and(|e| e.is_large_image());
        let mut scanned = false;
        let mut inventory_count = case.data().inventory.len();
        if scan_all && !is_large {
            let entries = case.scan_partitions(None, None, None)?;
            scanned = true;
            inventory_count = entries.len();
        }
        self.update_case_cache_from_open(&case);
        let ev = case
            .data()
            .evidence
            .as_ref()
            .expect("evidence populated after load_image");
        let fixed_at = ev
            .fixed_at
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| display_iso_time(s, false))
            .unwrap_or_default();
        let note = if ev.is_large_image() {
            "镜像容量达到 1 GiB，已按快速浏览模式载入。如需全案索引请调用 tracedesk_scan_partitions，如需建立 SHA-256 基线请调用 tracedesk_verify_integrity。"
        } else {
            ""
        };
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "image_path": ev.path,
            "format": ev.format_label(),
            "size": ev.size,
            "large_image": ev.is_large_image(),
            "sha256": ev.sha256,
            "fixed_at": fixed_at,
            "partitions": ev.partitions,
            "coverage_text": coverage_text(ev.coverage.as_ref()),
            "scanned_all_partitions": scanned,
            "partition_scans": case.data().partition_scans.clone().unwrap_or_default(),
            "inventory_count": inventory_count,
            "note": note,
        });
        case.close();
        Ok(out)
    }

    /// 5. `tracedesk_verify_integrity`：校验镜像 SHA-256 完整性。
    pub fn verify_integrity(&self, case_dir: &str, actor: Option<&str>) -> McpResult<Value> {
        let mut case = self.open_case(case_dir, actor)?;
        let ok = case.verify_integrity(None, None, None)?;
        self.update_case_cache_from_open(&case);
        let ev = case
            .data()
            .evidence
            .as_ref()
            .ok_or_else(|| McpError::ValueError("请先加载镜像".to_string()))?;
        let ver = case.data().verification.as_ref();
        let verified_at = ver
            .map(|v| display_iso_time(&v.time, false))
            .unwrap_or_default();
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "image_path": ev.path,
            "ok": ok,
            "sha256": ev.sha256,
            "actual": ver.and_then(|v| v.actual.clone()),
            "method": ver.map(|v| v.method.as_str()).unwrap_or(""),
            "verified_at": verified_at,
            "source_comparison": source_status(ev),
            "coverage_text": coverage_text(ev.coverage.as_ref()),
        });
        case.close();
        Ok(out)
    }

    /// 6. `tracedesk_register_source`：登记证据来源 5 字段。
    #[allow(clippy::too_many_arguments)]
    pub fn register_source(
        &self,
        case_dir: &str,
        evidence_id: &str,
        source: &str,
        acquired: &str,
        tool: &str,
        expected_sha256: &str,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let mut case = self.open_case(case_dir, actor)?;
        let prov = Provenance {
            evidence_id: evidence_id.to_string(),
            source: source.to_string(),
            acquired: acquired.to_string(),
            tool: tool.to_string(),
            expected_sha256: expected_sha256.to_string(),
        };
        case.register_source(&prov)?;
        self.update_case_cache_from_open(&case);
        let ev = case
            .data()
            .evidence
            .as_ref()
            .ok_or_else(|| McpError::ValueError("请先加载镜像".to_string()))?;
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "image_path": ev.path,
            "provenance": ev.provenance.clone().unwrap_or_default(),
            "source_fields": SOURCE_FIELDS,
            "source_comparison": source_status(ev),
        });
        case.close();
        Ok(out)
    }

    /// 7. `tracedesk_scan_partitions`：扫描全部分区或单个分区。
    pub fn scan_partitions(
        &self,
        case_dir: &str,
        partition_offset: Option<u64>,
        verify_large_image: bool,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let mut case = self.open_case(case_dir, actor)?;
        Self::ensure_large_image_session(&mut case, verify_large_image)?;
        let entries = match partition_offset {
            Some(off) => case.scan_partition(off, None, None)?,
            None => case.scan_partitions(None, None, None)?,
        };
        self.update_case_cache_from_open(&case);
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "partition_offset": partition_offset,
            "inventory_count": entries.len(),
            "partition_scans": case.data().partition_scans.clone().unwrap_or_default(),
        });
        case.close();
        Ok(out)
    }

    /// 8. `tracedesk_list_files`：分页浏览和筛选案件中的镜像文件清单（只读，利用缓存消除重复 gunzip）。
    #[allow(clippy::too_many_arguments)]
    pub fn list_files(
        &self,
        case_dir: &str,
        partition_offset: Option<u64>,
        path_prefix: &str,
        suffix: &str,
        keyword: &str,
        status: &str,
        files_only: bool,
        dir_inode: Option<&str>,
        dir_path: &str,
        limit: usize,
        offset: usize,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let filter_entries = |folder_str: String,
                              mode: &str,
                              entries: &[InventoryEntry]|
         -> Value {
            let norm_prefix = normalize_entry_path(path_prefix)
                .trim_end_matches('/')
                .to_lowercase();
            let mut norm_suffix = suffix.trim().to_lowercase();
            if !norm_suffix.is_empty() && !norm_suffix.starts_with('.') {
                norm_suffix.insert(0, '.');
            }
            let norm_keyword = keyword.trim().to_lowercase();

            let mut matched: Vec<Value> = Vec::new();
            for entry in entries {
                if let Some(off) = partition_offset
                    && entry.offset != off
                {
                    continue;
                }
                if files_only && (entry.directory || entry.mode.starts_with("V/")) {
                    continue;
                }
                if status == "active" && entry_status(entry) != "现存" {
                    continue;
                }
                if status == "deleted" && !entry.deleted {
                    continue;
                }
                if status == "system"
                    && !(entry.mode.starts_with("v/") || entry.mode.starts_with("V/"))
                {
                    continue;
                }
                let entry_path_cf = normalize_entry_path(&entry.path).to_lowercase();
                if !norm_prefix.is_empty()
                    && entry_path_cf != norm_prefix
                    && !entry_path_cf.starts_with(&format!("{norm_prefix}/"))
                {
                    continue;
                }
                if !norm_suffix.is_empty() && !entry.path.to_lowercase().ends_with(&norm_suffix) {
                    continue;
                }
                if !norm_keyword.is_empty()
                    && !entry_path_cf.contains(&norm_keyword)
                    && !entry_name(entry).to_lowercase().contains(&norm_keyword)
                {
                    continue;
                }
                matched.push(format_entry(entry));
            }

            let page = paginate(&matched, limit, offset);
            let mut out = serde_json::Map::new();
            out.insert("case_dir".to_string(), Value::String(folder_str));
            out.insert("browse_mode".to_string(), Value::String(mode.to_string()));
            if let Some(obj) = page.as_object() {
                for (k, v) in obj {
                    out.insert(k.clone(), v.clone());
                }
            }
            Value::Object(out)
        };

        // 快速路径：优先检查只读缓存视图；若不处于 `browsing_directories` 模式则直接筛选返回。
        let quick_browse_needed = self.with_read_case_view(case_dir, actor, |folder, view| {
            let Some(ref _ev) = view.data.evidence else {
                return Err(McpError::ValueError(
                    "当前案件尚未加载镜像，请先调用 tracedesk_load_image。".to_string(),
                ));
            };
            if view.browsing_directories {
                Ok(None)
            } else {
                let folder_str = folder.to_string_lossy().into_owned();
                Ok(Some(filter_entries(
                    folder_str,
                    "full_inventory",
                    &view.data.inventory,
                )))
            }
        })?;

        if let Some(result) = quick_browse_needed {
            return Ok(result);
        }

        // 大镜像按目录快速浏览路径。
        let mut case = self.open_case(case_dir, actor)?;
        let Some(ref ev) = case.data().evidence else {
            return Err(McpError::ValueError(
                "当前案件尚未加载镜像，请先调用 tracedesk_load_image。".to_string(),
            ));
        };
        let target_offset = match partition_offset {
            Some(off) => off,
            None => {
                if ev.partitions.is_empty() {
                    return Err(McpError::ValueError("当前镜像未识别到分区。".to_string()));
                }
                ev.partitions[0].offset
            }
        };
        let clean_dir_inode = dir_inode.map(str::trim).filter(|s| !s.is_empty());
        let entries = case.browse_directory(
            target_offset,
            clean_dir_inode,
            &normalize_entry_path(dir_path),
            None,
        )?;
        let folder_str = case.folder().to_string_lossy().into_owned();
        let out = filter_entries(folder_str, "directory_browse", &entries);
        case.close();
        Ok(out)
    }

    /// 9. `tracedesk_preview_file`：按页读取文件文本解码和/或十六进制转储。
    #[allow(clippy::too_many_arguments)]
    pub fn preview_file(
        &self,
        case_dir: &str,
        path: &str,
        partition_offset: Option<u64>,
        inode: Option<&str>,
        deleted: Option<bool>,
        dir_inode: Option<&str>,
        dir_path: &str,
        page: usize,
        page_bytes: usize,
        encoding: &str,
        mode: &str,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let enc_trimmed = encoding.trim();
        if !PREVIEW_ENCODINGS.contains(&enc_trimmed) {
            return Err(McpError::ValueError(format!(
                "不支持的编码 {enc_trimmed}；可选编码：{}",
                PREVIEW_ENCODINGS.join(", ")
            )));
        }
        let preview_enc = tracedesk_core::PreviewEncoding::parse(enc_trimmed)?;
        let pb = if page_bytes == 0 {
            PAGE_BYTES
        } else {
            page_bytes
        };

        let mut case = self.open_case(case_dir, actor)?;
        let entry = Self::find_entry(
            &mut case,
            path,
            partition_offset,
            inode,
            deleted,
            dir_inode,
            dir_path,
        )?;
        if entry.directory || entry.mode.starts_with("V/") {
            return Err(McpError::ValueError(format!(
                "{} 是目录，无法按文件内容预览。",
                entry.path
            )));
        }
        let is_large = case
            .data()
            .evidence
            .as_ref()
            .is_some_and(|e| e.is_large_image());
        if is_large {
            case.check_source()?;
        }
        let image_path = case.image_path()?;
        let page_res = preview_entry_page(&image_path, &entry, page, pb, preview_enc, None)?;

        let mut out = serde_json::Map::new();
        out.insert(
            "case_dir".to_string(),
            Value::String(case.folder().to_string_lossy().into_owned()),
        );
        out.insert("entry".to_string(), format_entry(&entry));
        out.insert(
            "encoding".to_string(),
            Value::String(enc_trimmed.to_string()),
        );
        out.insert("page".to_string(), Value::from(page_res.page));
        out.insert("total_pages".to_string(), Value::from(page_res.total_pages));
        out.insert("page_bytes".to_string(), Value::from(page_res.page_bytes));
        out.insert("byte_start".to_string(), Value::from(page_res.byte_start));
        out.insert("byte_end".to_string(), Value::from(page_res.byte_end));
        out.insert(
            "readable_size".to_string(),
            Value::from(page_res.readable_size),
        );
        out.insert(
            "recorded_size".to_string(),
            Value::from(page_res.recorded_size),
        );
        out.insert("read_note".to_string(), Value::String(page_res.read_note));
        out.insert(
            "source_note".to_string(),
            Value::String(page_res.source_note),
        );

        if matches!(mode, "text" | "both") {
            out.insert("text".to_string(), Value::String(page_res.text));
        }
        if matches!(mode, "hex" | "both") {
            let hex_lines: Vec<String> = page_res
                .hex_rows
                .iter()
                .map(|r| format!("{}  {:<47}  {}", r.offset_hex, r.bytes_hex, r.chars))
                .collect();
            out.insert("hex_lines".to_string(), serde_json::to_value(hex_lines).unwrap());
        }
        case.close();
        Ok(Value::Object(out))
    }

    /// 10. `tracedesk_search_content`：按精确字节搜索全案或单文件，并生成 `reports/search_*.json`。
    #[allow(clippy::too_many_arguments)]
    pub fn search_content(
        &self,
        case_dir: &str,
        query: &str,
        encoding: &str,
        path: Option<&str>,
        partition_offset: Option<u64>,
        inode: Option<&str>,
        deleted: Option<bool>,
        dir_inode: Option<&str>,
        dir_path: &str,
        max_hits: usize,
        limit: usize,
        offset: usize,
        verify_large_image: bool,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let mut case = self.open_case(case_dir, actor)?;
        Self::ensure_large_image_session(&mut case, verify_large_image)?;

        let selected = match path.map(str::trim).filter(|s| !s.is_empty()) {
            Some(p) => Some(Self::find_entry(
                &mut case,
                p,
                partition_offset,
                inode,
                deleted,
                dir_inode,
                dir_path,
            )?),
            None => None,
        };

        let cancel = AtomicBool::new(false);
        let options = SearchOptions {
            query: query.to_string(),
            encoding: encoding.to_string(),
            limit: Some(max_hits),
            selected,
        };
        let output = search_case(&mut case, &options, &cancel, None, None, None)?;
        self.update_case_cache_from_open(&case);

        let record = output.record;
        let errors_count = record.errors.len();
        let errors_preview: Vec<_> = record.errors.into_iter().take(20).collect();
        let page_data = paginate(&record.hits, limit, offset);

        let mut out = serde_json::Map::new();
        out.insert(
            "case_dir".to_string(),
            Value::String(case.folder().to_string_lossy().into_owned()),
        );
        out.insert(
            "report_file".to_string(),
            Value::String(output.report_path.to_string_lossy().into_owned()),
        );
        out.insert("query".to_string(), Value::String(record.query));
        out.insert("encoding".to_string(), Value::String(record.encoding));
        out.insert("needle_hex".to_string(), Value::String(record.needle));
        out.insert("scope".to_string(), Value::String(record.scope));
        out.insert("status".to_string(), Value::String(record.status));
        out.insert(
            "verification".to_string(),
            Value::String(record.verification),
        );
        out.insert("visited".to_string(), Value::from(record.visited));
        out.insert("eligible".to_string(), Value::from(record.eligible));
        out.insert("errors_count".to_string(), Value::from(errors_count));
        out.insert(
            "errors".to_string(),
            serde_json::to_value(errors_preview).unwrap_or_else(|_| json!([])),
        );
        if let Some(obj) = page_data.as_object() {
            for (k, v) in obj {
                out.insert(k.clone(), v.clone());
            }
        }
        case.close();
        Ok(Value::Object(out))
    }

    /// 11. `tracedesk_examine_file`：计算文件 SHA-256 或与外部对照副本比对。
    #[allow(clippy::too_many_arguments)]
    pub fn examine_file(
        &self,
        case_dir: &str,
        path: &str,
        partition_offset: Option<u64>,
        inode: Option<&str>,
        deleted: Option<bool>,
        dir_inode: Option<&str>,
        dir_path: &str,
        comparison_path: Option<&str>,
        verify_large_image: bool,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let comparison: Option<PathBuf> =
            match comparison_path.map(str::trim).filter(|s| !s.is_empty()) {
                Some(raw) => {
                    let resolved = resolve_clean(Path::new(raw));
                    if !resolved.is_file() {
                        return Err(McpError::FileNotFoundError(format!(
                            "对照文件不存在：{}",
                            resolved.display()
                        )));
                    }
                    Some(resolved)
                }
                None => None,
            };

        let mut case = self.open_case(case_dir, actor)?;
        Self::ensure_large_image_session(&mut case, verify_large_image)?;
        let entry = Self::find_entry(
            &mut case,
            path,
            partition_offset,
            inode,
            deleted,
            dir_inode,
            dir_path,
        )?;
        let res = examine(&mut case, &entry, comparison.as_deref(), None)?;
        self.update_case_cache_from_open(&case);
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "operation": res.operation,
            "path": entry.path,
            "partition_offset": entry.offset,
            "inode": entry.inode,
            "deleted": entry.deleted,
            "result": res.result,
            "details": res.details,
        });
        case.close();
        Ok(out)
    }

    /// 12. `tracedesk_record_finding`：为指定文件记录结构化取证发现笔记 (`FILE_NOTE`)。
    #[allow(clippy::too_many_arguments)]
    pub fn record_finding(
        &self,
        case_dir: &str,
        path: &str,
        note: &str,
        partition_offset: Option<u64>,
        inode: Option<&str>,
        deleted: Option<bool>,
        dir_inode: Option<&str>,
        dir_path: &str,
        verify_large_image: bool,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let mut case = self.open_case(case_dir, actor)?;
        Self::ensure_large_image_session(&mut case, verify_large_image)?;
        let entry = Self::find_entry(
            &mut case,
            path,
            partition_offset,
            inode,
            deleted,
            dir_inode,
            dir_path,
        )?;
        let latest = record_note(&mut case, &entry, note)?;
        self.update_case_cache_from_open(&case);
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "seq": latest.seq,
            "timestamp": display_iso_time(&latest.timestamp, false),
            "origin": audit_origin(&latest).as_str(),
            "origin_label": audit_origin_label(&latest),
            "mcp_client": audit_mcp_user(&latest),
            "actor": latest.actor,
            "path": entry.path,
            "partition_offset": entry.offset,
            "inode": entry.inode,
            "deleted": entry.deleted,
            "note": latest.details.get("note").and_then(Value::as_str).unwrap_or(""),
            "audit_hash": latest.hash,
        });
        case.close();
        Ok(out)
    }

    fn filter_finding_groups(
        records: &[AuditRecord],
        status: &str,
        partition_offset: Option<u64>,
        keyword: &str,
    ) -> Vec<FindingGroup> {
        let groups = group_findings(records);
        let needle = keyword.trim().to_lowercase();
        let mut matched = Vec::new();
        for group in groups {
            let deleted = group.key.deleted;
            if status == "active" && deleted {
                continue;
            }
            if status == "deleted" && !deleted {
                continue;
            }
            if let Some(off) = partition_offset
                && group.key.offset != off
            {
                continue;
            }
            if !needle.is_empty() {
                let mut parts: Vec<String> =
                    vec![group.key.subject.clone(), group.key.inode.clone()];
                for item in &group.records {
                    if let Some(n) = item.details.get("note").and_then(Value::as_str) {
                        parts.push(n.to_string());
                    }
                    if let Some(s) = item.details.get("sha256").and_then(Value::as_str) {
                        parts.push(s.to_string());
                    }
                }
                let haystack = parts.join(" ").to_lowercase();
                if !haystack.contains(&needle) {
                    continue;
                }
            }
            matched.push(group);
        }
        matched
    }

    /// 13. `tracedesk_list_findings`：按文件归组查询取证发现。
    #[allow(clippy::too_many_arguments)]
    pub fn list_findings(
        &self,
        case_dir: &str,
        status: &str,
        partition_offset: Option<u64>,
        keyword: &str,
        limit: usize,
        offset: usize,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        self.with_read_case_view(case_dir, actor, |folder, _view| {
            let records = self.verified_audit_records(folder)?;
            let groups = Self::filter_finding_groups(&records, status, partition_offset, keyword);
            let mut formatted = Vec::with_capacity(groups.len());
            for g in groups {
                let recs: Vec<Value> = g
                    .records
                    .iter()
                    .map(|r| {
                        json!({
                            "seq": r.seq,
                            "timestamp": display_iso_time(&r.timestamp, false),
                            "origin": audit_origin(r).as_str(),
                            "origin_label": audit_origin_label(r),
                            "mcp_client": audit_mcp_user(r),
                            "actor": r.actor,
                            "action": r.action,
                            "operation": operation_title(&r.action).unwrap_or(&r.action),
                            "result": r.result,
                            "details": r.details,
                        })
                    })
                    .collect();
                formatted.push(json!({
                    "path": g.key.subject,
                    "partition_offset": g.key.offset,
                    "inode": g.key.inode,
                    "deleted": g.key.deleted,
                    "status": if g.key.deleted { "已删除" } else { "现存" },
                    "image_sha256": g.key.image_sha256.unwrap_or_default(),
                    "records": recs,
                }));
            }

            let page = paginate(&formatted, limit, offset);
            let mut out = serde_json::Map::new();
            out.insert(
                "case_dir".to_string(),
                Value::String(folder.to_string_lossy().into_owned()),
            );
            if let Some(obj) = page.as_object() {
                for (k, v) in obj {
                    out.insert(k.clone(), v.clone());
                }
            }
            Ok(Value::Object(out))
        })
    }

    /// 14. `tracedesk_query_timeline`：分页查询 MACB 时间线（利用缓存的 `TimelineIndex` 避免重复排序）。
    #[allow(clippy::too_many_arguments)]
    pub fn query_timeline(
        &self,
        case_dir: &str,
        event: Option<&str>,
        status: Option<&str>,
        partition_offset: Option<u64>,
        query: &str,
        sort_order: &str,
        limit: usize,
        offset: usize,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let normalized_event = match event.map(str::trim).filter(|s| !s.is_empty()) {
            Some(ev) => Some(normalize_event_filter(ev)?.to_string()),
            None => None,
        };
        self.with_read_case_view(case_dir, actor, |folder, view| {
            if view.data.evidence.is_none() {
                return Err(McpError::ValueError("当前案件尚未加载镜像。".to_string()));
            }
            if view.browsing_directories {
                return Err(McpError::ValueError(
                    "大容量镜像尚未建立完整文件索引，请先调用 tracedesk_scan_partitions。"
                        .to_string(),
                ));
            }
            let timeline = view
                .timeline
                .get_or_init(|| Arc::new(TimelineIndex::build(view.data.inventory.clone())));

            let filter = TimelineFilter {
                query: query.trim().to_string(),
                event: normalized_event,
                status: status
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                offset: partition_offset,
            };
            let indices = timeline.matching(&filter)?;
            let total = indices.len();
            let start = offset.min(total);
            let end = start.saturating_add(limit).min(total);

            let mut items: Vec<Value> = Vec::with_capacity(end.saturating_sub(start));
            if sort_order == "desc" {
                for i in start..end {
                    if let Some(row) = timeline.get(indices[total - 1 - i]) {
                        items.push(json!({
                            "time": row.time,
                            "event": row.event,
                            "path": row.path,
                            "inode": row.inode,
                            "offset": row.offset,
                            "status": row.status,
                        }));
                    }
                }
            } else {
                for &idx in &indices[start..end] {
                    if let Some(row) = timeline.get(idx) {
                        items.push(json!({
                            "time": row.time,
                            "event": row.event,
                            "path": row.path,
                            "inode": row.inode,
                            "offset": row.offset,
                            "status": row.status,
                        }));
                    }
                }
            }

            let count = items.len();
            let has_more = offset.saturating_add(count) < total;
            let next_offset = if has_more {
                Some(offset.saturating_add(count))
            } else {
                None
            };
            let opts = timeline.filter_options();

            Ok(json!({
                "case_dir": folder.to_string_lossy(),
                "total": total,
                "count": count,
                "offset": offset,
                "limit": limit,
                "has_more": has_more,
                "next_offset": next_offset,
                "sort_order": sort_order,
                "available_filters": {
                    "events": opts.events,
                    "statuses": opts.statuses,
                    "partition_offsets": opts.offsets,
                },
                "items": items,
            }))
        })
    }

    /// 15. `tracedesk_query_audit_log`：核验审计哈希链并分页检索审计日志。
    #[allow(clippy::too_many_arguments)]
    pub fn query_audit_log(
        &self,
        case_dir: &str,
        origin: &str,
        action: Option<&str>,
        actor_filter: Option<&str>,
        result: Option<&str>,
        query: &str,
        sort_order: &str,
        limit: usize,
        offset: usize,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        self.with_read_case_view(case_dir, actor, |folder, _view| {
            let records = self.verified_audit_records(folder)?;
            let audit_head = records
                .last()
                .map(|r| r.hash.clone())
                .unwrap_or_default();
            let mcp_total = records
                .iter()
                .filter(|r| audit_origin(r) == AuditOrigin::Mcp)
                .count();
            let manual_total = records.len().saturating_sub(mcp_total);

            let origin_filter = origin.trim().to_lowercase();
            let action_cf = action
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase);
            let actor_cf = actor_filter
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase);
            let result_cf = result
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase);
            let query_cf = query.trim().to_lowercase();

            let mut matched: Vec<Value> = Vec::new();
            for r in records.iter() {
                let rec_origin = audit_origin(r).as_str();
                let rec_mcp_client = audit_mcp_user(r);
                let rec_origin_label = audit_origin_label(r);
                if matches!(origin_filter.as_str(), "manual" | "mcp")
                    && rec_origin != origin_filter
                {
                    continue;
                }
                let title = action_title(&r.action);
                if let Some(ref act) = action_cf
                    && r.action.to_lowercase() != *act
                    && title.to_lowercase() != *act
                {
                    continue;
                }
                if let Some(ref af) = actor_cf {
                    let actor_matched = r.actor.to_lowercase().contains(af)
                        || rec_mcp_client
                            .as_deref()
                            .is_some_and(|c| c.to_lowercase().contains(af));
                    if !actor_matched {
                        continue;
                    }
                }
                if let Some(ref rf) = result_cf
                    && r.result.to_lowercase() != *rf
                {
                    continue;
                }
                let formatted_time = display_iso_time(&r.timestamp, false);
                if !query_cf.is_empty() {
                    let blob = serde_json::to_string(&json!([
                        r.seq,
                        formatted_time,
                        rec_origin,
                        rec_origin_label,
                        rec_mcp_client,
                        r.actor,
                        r.action,
                        title,
                        r.subject,
                        r.result,
                        r.details,
                    ]))
                    .unwrap_or_default()
                    .to_lowercase();
                    if !blob.contains(&query_cf) {
                        continue;
                    }
                }
                matched.push(json!({
                    "seq": r.seq,
                    "timestamp": formatted_time,
                    "origin": rec_origin,
                    "origin_label": rec_origin_label,
                    "mcp_client": rec_mcp_client,
                    "actor": r.actor,
                    "action": r.action,
                    "action_title": title,
                    "subject": r.subject,
                    "result": r.result,
                    "details": r.details,
                    "previous": r.previous,
                    "hash": r.hash,
                }));
            }

            if sort_order == "desc" {
                matched.reverse();
            }

            let page = paginate(&matched, limit, offset);
            let mut out = serde_json::Map::new();
            out.insert(
                "case_dir".to_string(),
                Value::String(folder.to_string_lossy().into_owned()),
            );
            out.insert("audit_chain_valid".to_string(), Value::Bool(true));
            out.insert("audit_head".to_string(), Value::String(audit_head));
            out.insert(
                "origin_counts".to_string(),
                json!({
                    "manual": manual_total,
                    "mcp": mcp_total,
                }),
            );
            out.insert(
                "sort_order".to_string(),
                Value::String(sort_order.to_string()),
            );
            if let Some(obj) = page.as_object() {
                for (k, v) in obj {
                    out.insert(k.clone(), v.clone());
                }
            }
            Ok(Value::Object(out))
        })
    }

    /// 16. `tracedesk_export_file`：导出单个镜像文件副本到 `<case_dir>/exports/`。
    #[allow(clippy::too_many_arguments)]
    pub fn export_file(
        &self,
        case_dir: &str,
        path: &str,
        partition_offset: Option<u64>,
        inode: Option<&str>,
        deleted: Option<bool>,
        dir_inode: Option<&str>,
        dir_path: &str,
        verify_large_image: bool,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let mut case = self.open_case(case_dir, actor)?;
        Self::ensure_large_image_session(&mut case, verify_large_image)?;
        let entry = Self::find_entry(
            &mut case,
            path,
            partition_offset,
            inode,
            deleted,
            dir_inode,
            dir_path,
        )?;
        let destination = case.export(&entry, None)?;
        self.update_case_cache_from_open(&case);
        let record = case
            .data()
            .exports
            .last()
            .cloned()
            .ok_or_else(|| McpError::RuntimeError("未找到导出记录".to_string()))?;
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "exported_path": destination.to_string_lossy(),
            "record": record,
        });
        case.close();
        Ok(out)
    }

    /// 17. `tracedesk_export_findings`：一键批量导出取证发现关联文件与 Markdown 汇总清单。
    pub fn export_findings(
        &self,
        case_dir: &str,
        status: &str,
        partition_offset: Option<u64>,
        keyword: &str,
        verify_large_image: bool,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let mut case = self.open_case(case_dir, actor)?;
        Self::ensure_large_image_session(&mut case, verify_large_image)?;
        let records = case.check_audit()?;
        let groups = Self::filter_finding_groups(&records, status, partition_offset, keyword);
        let res = do_export_findings(&mut case, &groups)?;
        self.update_case_cache_from_open(&case);
        let failed: Vec<Value> = res
            .failed
            .iter()
            .map(|(p, r)| json!({ "path": p, "reason": r }))
            .collect();
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "summary_path": res.summary_path.to_string_lossy(),
            "total_groups": groups.len(),
            "exported_count": res.exported_count,
            "failed_count": failed.len(),
            "failed": failed,
        });
        case.close();
        Ok(out)
    }

    /// 18. `tracedesk_generate_report`：执行完整性校验并生成 10 节 Markdown 取证报告。
    pub fn generate_report(
        &self,
        case_dir: &str,
        verify_large_image: bool,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let mut case = self.open_case(case_dir, actor)?;
        Self::ensure_large_image_session(&mut case, verify_large_image)?;
        let report_path = case.report(None)?;
        let records = case.check_audit()?;
        self.update_case_cache_from_open(&case);
        self.update_audit_cache(case.folder(), records.clone());
        let sha256 = records
            .last()
            .and_then(|r| r.details.get("sha256"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "report_path": report_path.to_string_lossy(),
            "sha256": sha256,
            "verification": case.data().verification,
        });
        case.close();
        Ok(out)
    }

    /// 19. `tracedesk_build_review_bundle`：构建可核验 ZIP64 复核包与 `.zip.sha256`。
    pub fn build_review_bundle(
        &self,
        case_dir: &str,
        selected_export_indices: Option<Vec<usize>>,
        selected_search_indices: Option<Vec<usize>>,
        skip_missing_exports: bool,
        verify_large_image: bool,
        actor: Option<&str>,
    ) -> McpResult<Value> {
        let mut case = self.open_case(case_dir, actor)?;
        Self::ensure_large_image_session(&mut case, verify_large_image)?;
        let options = BuildBundleOptions {
            selected_export_indices,
            selected_search_indices,
            skip_missing: skip_missing_exports,
        };
        let res = build_bundle(&mut case, &options, None)?;
        let records = case.check_audit()?;
        self.update_case_cache_from_open(&case);
        self.update_audit_cache(case.folder(), records);
        let out = json!({
            "case_dir": case.folder().to_string_lossy(),
            "bundle_path": res.bundle_path.to_string_lossy(),
            "sha256_file": res.sha256_path.to_string_lossy(),
            "sha256": res.sha256,
            "included_exports": res.included_exports,
            "omitted_exports": res.omitted_exports,
            "missing_exports": res.missing_exports,
            "included_searches": res.included_searches,
            "omitted_searches": res.omitted_searches,
            "missing_searches": res.missing_searches,
        });
        case.close();
        Ok(out)
    }
}
