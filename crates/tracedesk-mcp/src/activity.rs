//! TraceDesk MCP 实时过程监控与跨进程遥测模块：
//! - 定义与前端 `frontend/src/types/ipc.ts` 100% 对齐的活动记录、统计与快照结构（`camelCase`）
//! - 提供跨进程 JSONL 遥测日志（`<app_root>/logs/mcp-activity.jsonl`）追加与温和截断（超 1,200 行保留最近 600 行）
//! - 提供 `McpActivitySink` 钩子抽象、`FileActivitySink`、`CallbackActivitySink` 与 `McpActivityStore` 内存环形聚合队列
//! - 提供 `ActivityLogTailer` 增量字节偏移尾随读取器（支持截断重置与半行保护）

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracedesk_core::{
    AppPaths, format_commas, format_unix_east8_stack, resolve_clean, strip_trailing_version,
};
use tracedesk_engines::CaseFileLock;
use uuid::Uuid;

use crate::tools::TOOL_CATALOG;

/// 跨进程 MCP 活动遥测日志文件名（位于 `<logs_dir>/mcp-activity.jsonl`）。
pub const ACTIVITY_LOG_FILENAME: &str = "mcp-activity.jsonl";

/// 遥测日志文件触发温和截断的行数阈值。
pub const MAX_ACTIVITY_LOG_LINES: usize = 1_200;

/// 触发温和截断后保留的最近记录行数。
pub const KEEP_ACTIVITY_LOG_LINES: usize = 600;

/// 参数 JSON 与返回预览允许保留的最大字节数（16 KiB）。
pub const MAX_PREVIEW_BYTES: usize = 16 * 1024;

/// 内存中按 `callId` 合并后保留的最大调用记录条数。
pub const DEFAULT_ACTIVITY_STORE_CAPACITY: usize = 500;

/// 超过该字节数才检查遥测日志行数，避免小文件场景下的额外读取开销
/// （单条合法记录至少约 270 字节，1,200 行必定远超 100 KiB）。
const TRIM_CHECK_MIN_BYTES: u64 = 100 * 1024;

/// 进程内共享的文件写锁，防止同进程多线程并发追加与截断互相干扰。
fn file_write_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// 单条 MCP 实时活动遥测记录（与前端 `McpActivityRecord` 100% 字段对齐）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpActivityRecord {
    /// 唯一事件 ID，供跨进程尾随读取与前端去重。
    pub id: String,
    /// 调用关联 ID，同一次调用的 `started` 与 `completed`/`failed` 共享同一 `callId`。
    pub call_id: String,
    /// UTC+8 ISO-8601 时间戳（精确到毫秒）。
    pub timestamp: String,
    /// 执行阶段：`"started"` | `"completed"` | `"failed"`。
    pub phase: String,
    /// 传输方式：`"desktop-http"` | `"streamable-http"` | `"stdio"`。
    pub transport: String,
    /// 使用者/客户端标识，如 `"Antigravity"`、`"Cursor"`、`"本地 MCP 客户端"`。
    pub client: String,
    /// 会话 ID（HTTP 为 `Mcp-Session-Id`，stdio 为会话循环 ID）。
    #[serde(default)]
    pub session_id: Option<String>,
    /// JSON-RPC 方法名：`"initialize"` | `"tools/call"` | `"resources/read"`。
    pub method: String,
    /// 工具名称或资源 URI（`initialize` 时为 `None`）。
    #[serde(default)]
    pub tool_name: Option<String>,
    /// 工具中文标题（来自 `TOOL_CATALOG`；`initialize` 为 `"客户端握手初始化"`，`resources/read` 为 `"读取 MCP 资源"`）。
    pub tool_title: String,
    /// 工具分类（协议类为 `"协议会话"`）。
    pub category: String,
    /// 是否为只读操作。
    pub read_only: bool,
    /// 目标案件目录路径（若入参或输出包含案件目录）。
    #[serde(default)]
    pub case_dir: Option<String>,
    /// 目标案件编号（能快速从案件目录或参数得知则填）。
    #[serde(default)]
    pub case_number: Option<String>,
    /// 一行精炼的关键入参摘要，如 `query="accountNum" · encoding="UTF-8"`。
    pub params_summary: String,
    /// 美化后的参数 JSON 字符串（超过 16 KiB 时截断并附提示）。
    pub params_json: String,
    /// 调用耗时毫秒数（`completed` / `failed` 时填）。
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// 一行清晰的结果摘要（如 `"执行中..."`、`"执行成功（返回 2,418 字符）"` 或失败首行原因）。
    pub result_summary: String,
    /// 返回文本或 JSON 预览（超过 16 KiB 时截断并附提示）。
    #[serde(default)]
    pub response_preview: Option<String>,
    /// 失败时的错误详情。
    #[serde(default)]
    pub error: Option<String>,
}

/// 单个 MCP 工具的聚合调用统计。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolStat {
    /// 工具名称（或资源 URI）。
    pub tool_name: String,
    /// 累计调用次数。
    pub calls: usize,
    /// 失败次数。
    pub failures: usize,
    /// 平均耗时（毫秒）。
    pub avg_duration_ms: u64,
}

/// MCP 实时活动全局或筛选后的聚合统计。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpActivityStats {
    /// 总调用数（按 `callId` 合并去重）。
    pub total_calls: usize,
    /// 当前仍在执行的调用数（`phase == "started"`）。
    pub running_calls: usize,
    /// 已成功完成的调用数（`phase == "completed"`）。
    pub succeeded_calls: usize,
    /// 执行失败的调用数（`phase == "failed"`）。
    pub failed_calls: usize,
    /// 只读调用数。
    pub read_only_calls: usize,
    /// 受控写入调用数。
    pub write_calls: usize,
    /// 已完成/失败调用的平均耗时（毫秒）。
    pub avg_duration_ms: u64,
    /// 活跃调用客户端名称列表（按最近出现顺序去重）。
    pub active_clients: Vec<String>,
    /// 各工具调用统计映射（按工具名有序排列）。
    pub tool_stats: BTreeMap<String, McpToolStat>,
}

/// `list_mcp_activities` 返回的完整快照（最新记录在前）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpActivitySnapshot {
    /// 按 `callId` 合并后的活动列表，按时间倒序（最新在前）。
    pub activities: Vec<McpActivityRecord>,
    /// 聚合遥测统计。
    pub stats: McpActivityStats,
}

/// 返回当前 UTC+8 东八区 ISO-8601 时间戳（固定含 3 位毫秒，例如 `2026-11-23T17:25:01.123+08:00`）。
pub fn now_east8_millis() -> String {
    if let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let secs = dur.as_secs() as i64;
        let millis = dur.subsec_millis();
        if let Some(buf) = format_unix_east8_stack(secs)
            && let Ok(base) = std::str::from_utf8(&buf)
        {
            // `base` 固定为 25 字节：`YYYY-MM-DDTHH:MM:SS+08:00`
            return format!("{}.{:03}{}", &base[..19], millis, &base[19..]);
        }
    }
    tracedesk_core::now()
}

/// 规范化 MCP 活动记录的客户端展示名称，去除各段末尾的版本号数字（兼容历史已落盘记录）。
pub fn normalize_activity_client(raw: &str) -> String {
    strip_trailing_version(raw)
}

/// 生成新的唯一事件或调用 ID。
pub fn new_activity_id() -> String {
    Uuid::new_v4().to_string()
}

/// 返回默认的跨进程遥测日志路径：优先读取 `TRACEDESK_MCP_ACTIVITY_LOG` 环境变量，
/// 未设置时回退至 `<app_root>/logs/mcp-activity.jsonl`。
pub fn default_activity_log_path() -> PathBuf {
    if let Ok(explicit) = env::var("TRACEDESK_MCP_ACTIVITY_LOG") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    AppPaths::discover().logs_dir.join(ACTIVITY_LOG_FILENAME)
}

/// 安全按 UTF-8 字符边界截断字符串至最多 `max_bytes` 字节，超限时附加中文截断提示。
pub fn truncate_preview(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n...（已截断，完整内容共 {} 字节，仅展示前 {} KiB）",
        &text[..end],
        format_commas(text.len() as u64),
        max_bytes / 1024
    )
}

/// 将任意文本压缩为单行并限制最大字符数（用于 `paramsSummary` / 失败摘要）。
fn sanitize_single_line(raw: &str, max_chars: usize) -> String {
    let cleaned: String = raw
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let char_count = collapsed.chars().count();
    if char_count <= max_chars {
        collapsed
    } else {
        let head: String = collapsed.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

/// 取路径末尾的文件名或目录名，避免超长路径挤占单行摘要。
fn compact_path_display(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.chars().count() <= 36 {
        return trimmed.to_string();
    }
    Path::new(trimmed)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| sanitize_single_line(trimmed, 36))
}

/// 格式化 JSON 值用于单行入参摘要。
fn format_summary_value(key: &str, val: &Value) -> Option<String> {
    match val {
        Value::Null => None,
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            let display = if matches!(
                key,
                "case_dir" | "image_path" | "cases_root" | "comparison_path" | "report_path"
            ) {
                compact_path_display(trimmed)
            } else {
                sanitize_single_line(trimmed, 44)
            };
            Some(format!("\"{display}\""))
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                None
            } else {
                Some(format!("[{} 项]", arr.len()))
            }
        }
        Value::Object(map) => {
            if map.is_empty() {
                None
            } else {
                Some(format!("{{{} 项}}", map.len()))
            }
        }
    }
}

/// 兼容解包 FastMCP `{"params": {...}}` 参数结构（不消费原值）。
pub fn unwrap_params_for_display(raw: &Value) -> Value {
    match raw {
        Value::Null => Value::Object(serde_json::Map::new()),
        Value::Object(map) => {
            if let Some(Value::Object(inner)) = map.get("params") {
                let mut merged = inner.clone();
                for (k, v) in map {
                    if k != "params" {
                        merged.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
                return Value::Object(merged);
            }
            Value::Object(map.clone())
        }
        other => other.clone(),
    }
}

/// 为 `initialize` / `resources/read` / `tools/call` 生成一行精炼入参摘要。
pub fn summarize_params(method: &str, params: &Value) -> String {
    match method {
        "initialize" => {
            let mut parts = Vec::new();
            if let Some(info) = params
                .get("clientInfo")
                .or_else(|| params.get("client_info"))
                .and_then(Value::as_object)
                && let Some(name) = info.get("name").and_then(Value::as_str)
                && !name.trim().is_empty()
            {
                let label = normalize_activity_client(name);
                parts.push(format!("client=\"{}\"", sanitize_single_line(&label, 48)));
            }
            if let Some(ver) = params.get("protocolVersion").and_then(Value::as_str)
                && !ver.trim().is_empty()
            {
                parts.push(format!("protocol=\"{}\"", sanitize_single_line(ver, 24)));
            }
            if parts.is_empty() {
                "协议握手初始化".to_string()
            } else {
                parts.join(" · ")
            }
        }
        "resources/read" => {
            if let Some(uri) = params.get("uri").and_then(Value::as_str)
                && !uri.trim().is_empty()
            {
                return format!("uri=\"{}\"", sanitize_single_line(uri, 80));
            }
            "未指定资源 URI".to_string()
        }
        _ => {
            let unwrapped = unwrap_params_for_display(params);
            let Some(map) = unwrapped.as_object() else {
                return sanitize_single_line(&unwrapped.to_string(), 80);
            };
            // 高信号业务参数优先展示；`case_dir` 与 `cases_root` 仅在无足够业务参数时补充。
            const PRIMARY_KEYS: &[&str] = &[
                "query",
                "encoding",
                "report_path",
                "path",
                "image_path",
                "number",
                "examiner",
                "target",
                "note",
                "partition_offset",
                "inode",
                "deleted",
                "status",
                "keyword",
                "path_prefix",
                "suffix",
                "event",
                "origin",
                "action",
                "comparison_path",
                "evidence_id",
                "source",
                "page",
                "mode",
                "limit",
                "offset",
                "response_format",
            ];
            let mut parts = Vec::new();
            let mut used_keys = HashSet::new();
            for &key in PRIMARY_KEYS {
                if parts.len() >= 4 {
                    break;
                }
                if let Some(val) = map.get(key)
                    && let Some(formatted) = format_summary_value(key, val)
                {
                    parts.push(format!("{key}={formatted}"));
                    used_keys.insert(key);
                }
            }
            if parts.is_empty() {
                for fallback_key in ["case_dir", "cases_root", "actor"] {
                    if let Some(val) = map.get(fallback_key)
                        && let Some(formatted) = format_summary_value(fallback_key, val)
                    {
                        parts.push(format!("{fallback_key}={formatted}"));
                        used_keys.insert(fallback_key);
                        if parts.len() >= 2 {
                            break;
                        }
                    }
                }
            }
            if parts.is_empty() {
                for (k, v) in map {
                    if used_keys.contains(k.as_str()) {
                        continue;
                    }
                    if let Some(formatted) = format_summary_value(k, v) {
                        parts.push(format!("{k}={formatted}"));
                        if parts.len() >= 3 {
                            break;
                        }
                    }
                }
            }
            if parts.is_empty() {
                "无附加参数".to_string()
            } else {
                parts.join(" · ")
            }
        }
    }
}

/// 将参数 JSON 美化格式化并在超过 16 KiB 时安全截断。
pub fn format_params_json(params: &Value) -> String {
    let pretty = serde_json::to_string_pretty(params).unwrap_or_else(|_| params.to_string());
    truncate_preview(&pretty, MAX_PREVIEW_BYTES)
}

/// 根据工具名从 `TOOL_CATALOG` 查找 `(中文标题, 分类, 是否只读)`。
pub fn lookup_tool_meta(tool_name: &str) -> (String, String, bool) {
    if let Some(item) = TOOL_CATALOG.iter().find(|item| item.name == tool_name) {
        (
            item.title.to_string(),
            item.category.to_string(),
            item.read_only,
        )
    } else {
        (tool_name.to_string(), "未知工具".to_string(), true)
    }
}

/// 快速解析目标案件目录与案件编号（轻量只读，绝不阻塞调用）。
pub fn resolve_case_context(
    args: &Value,
    cases_root: &Path,
) -> (Option<String>, Option<String>) {
    let unwrapped = unwrap_params_for_display(args);
    let raw_dir = unwrapped
        .get("case_dir")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let resolved_dir = raw_dir.map(|raw| {
        let p = PathBuf::from(raw);
        let candidate = if p.is_absolute() {
            p
        } else {
            let under_root = cases_root.join(&p);
            if under_root.exists() || !p.exists() {
                under_root
            } else {
                p
            }
        };
        let mut clean = resolve_clean(&candidate);
        // 兼容直接传入 `.../case.json` 路径的场景，与 `CaseService::resolve_case_dir` 保持一致。
        if clean
            .file_name()
            .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("case.json"))
            && let Some(parent) = clean.parent()
        {
            clean = parent.to_path_buf();
        }
        clean
    });

    let case_number = resolved_dir
        .as_deref()
        .and_then(read_case_number_quick)
        .or_else(|| {
            unwrapped
                .get("number")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        });

    let case_dir_str = resolved_dir.map(|p| p.to_string_lossy().into_owned());
    (case_dir_str, case_number)
}

/// 轻量读取 `<case_dir>/case.json` 中的 `number` 字段（仅解析不大于 512 KiB 的元数据文件）。
pub fn read_case_number_quick(case_dir: &Path) -> Option<String> {
    let meta_path = case_dir.join("case.json");
    let meta = fs::metadata(&meta_path).ok()?;
    if meta.len() > 512 * 1024 {
        return None;
    }
    let raw = fs::read_to_string(&meta_path).ok()?;
    let val: Value = serde_json::from_str(&raw).ok()?;
    val.get("number")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// 针对 `tracedesk_create_case` 等创建类工具，尝试从成功输出中补充解析新建的 `case_dir` 与 `number`。
pub fn extract_case_info_from_output(output_text: &str) -> (Option<String>, Option<String>) {
    let trimmed = output_text.trim();
    if trimmed.starts_with('{')
        && let Ok(val) = serde_json::from_str::<Value>(trimmed)
    {
        let dir = val
            .get("case_dir")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| resolve_clean(Path::new(s)).to_string_lossy().into_owned());
        let num = val
            .get("number")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        return (dir, num);
    }
    // 兼容 Markdown 键值输出格式：`- **case_dir**：`path``
    let mut dir = None;
    let mut num = None;
    for line in trimmed.lines() {
        let l = line.trim();
        if let Some(rest) = l
            .strip_prefix("- **case_dir**：")
            .or_else(|| l.strip_prefix("- **case_dir**:"))
        {
            let clean = rest.trim().trim_matches('`').trim();
            if !clean.is_empty() {
                dir = Some(
                    resolve_clean(Path::new(clean))
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        } else if let Some(rest) = l
            .strip_prefix("- **number**：")
            .or_else(|| l.strip_prefix("- **number**:"))
        {
            let clean = rest.trim().trim_matches('`').trim();
            if !clean.is_empty() {
                num = Some(clean.to_string());
            }
        }
    }
    (dir, num)
}

/// 生成工具调用成功时的一行结果摘要（例如 `"执行成功（返回 2,418 字符）"`）。
pub fn format_success_result_summary(method: &str, text: &str, negotiated_protocol: Option<&str>) -> String {
    match method {
        "initialize" => {
            if let Some(proto) = negotiated_protocol {
                format!("握手成功（协议 {proto}）")
            } else {
                "客户端握手成功".to_string()
            }
        }
        "resources/read" => {
            let chars = text.chars().count() as u64;
            format!("读取成功（返回 {} 字符）", format_commas(chars))
        }
        _ => {
            let chars = text.chars().count() as u64;
            format!("执行成功（返回 {} 字符）", format_commas(chars))
        }
    }
}

/// 提取错误详情的首行非空文本作为失败摘要。
pub fn format_error_summary(err: &str) -> String {
    let first_line = err
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("执行失败");
    sanitize_single_line(first_line, 140)
}

/* ==========================================================================================
 * 遥测接收器抽象（McpActivitySink）与跨进程 JSONL 日志读写
 * ========================================================================================== */

/// MCP 实时活动遥测接收器接口（实现方必须线程安全且内部吞掉 I/O 错误，绝不阻断 MCP 协议）。
pub trait McpActivitySink: Send + Sync {
    /// 处理单条实时活动记录（`started` / `completed` / `failed`）。
    fn emit(&self, record: McpActivityRecord);
}

/// 基于闭包的轻量遥测接收器（供桌面端 `src-tauri` 零延迟聚合推送及单元测试使用）。
pub struct CallbackActivitySink<F>
where
    F: Fn(McpActivityRecord) + Send + Sync,
{
    callback: F,
}

impl<F> CallbackActivitySink<F>
where
    F: Fn(McpActivityRecord) + Send + Sync,
{
    pub fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F> McpActivitySink for CallbackActivitySink<F>
where
    F: Fn(McpActivityRecord) + Send + Sync,
{
    fn emit(&self, record: McpActivityRecord) {
        (self.callback)(record);
    }
}

/// 基于跨进程 JSONL 文件的遥测接收器（默认写入 `<app_root>/logs/mcp-activity.jsonl`）。
#[derive(Debug, Clone)]
pub struct FileActivitySink {
    log_path: PathBuf,
}

impl FileActivitySink {
    /// 创建写入指定路径的 JSONL 遥测接收器。
    pub fn new(log_path: PathBuf) -> Self {
        Self { log_path }
    }

    /// 创建写入默认路径（`<app_root>/logs/mcp-activity.jsonl`）的遥测接收器。
    pub fn default_location() -> Self {
        Self::new(default_activity_log_path())
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }
}

impl McpActivitySink for FileActivitySink {
    fn emit(&self, record: McpActivityRecord) {
        // 遥测写入失败绝不阻断正常 MCP 协议执行。
        let _ = append_activity_record(&self.log_path, &record);
    }
}

/// 跨进程遥测日志锁超时时间（短锁排队，绝不长时间阻塞 MCP 调用）。
const ACTIVITY_LOCK_TIMEOUT: Duration = Duration::from_millis(500);

/// 返回指定 JSONL 遥测日志对应的跨进程伴随锁文件路径（`<path>.lock`）。
fn activity_lock_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".lock");
    PathBuf::from(os)
}

/// 尝试获取跨进程遥测伴随锁；若父目录存在则创建锁文件并等待短锁。
fn acquire_activity_cross_process_lock(path: &Path) -> Option<CaseFileLock> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = fs::create_dir_all(parent);
    }
    CaseFileLock::acquire_with_timeout(&activity_lock_path(path), ACTIVITY_LOCK_TIMEOUT).ok()
}

/// 向指定 JSONL 文件追加单条活动记录，并在超过 1,200 行时温和截断保留最近 600 行。
pub fn append_activity_record(path: &Path, record: &McpActivityRecord) -> io::Result<()> {
    let _guard = file_write_lock().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    // 加跨进程短锁，防止与其他进程的温和截断/清空交错导致丢失或半行损坏。
    let _proc_lock = acquire_activity_cross_process_lock(path);

    let mut line = serde_json::to_string(record)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push('\n');

    {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
    }

    if let Ok(meta) = fs::metadata(path)
        && meta.len() >= TRIM_CHECK_MIN_BYTES
    {
        let _ = trim_activity_log_locked(path, MAX_ACTIVITY_LOG_LINES, KEEP_ACTIVITY_LOG_LINES);
    }
    Ok(())
}

/// 若遥测日志行数超过 `max_lines`，温和截断并仅保留最近 `keep_lines` 行。
/// 返回 `Ok(true)` 表示执行了截断，`Ok(false)` 表示未超限。
pub fn trim_activity_log_if_needed(
    path: &Path,
    max_lines: usize,
    keep_lines: usize,
) -> io::Result<bool> {
    let _guard = file_write_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _proc_lock = acquire_activity_cross_process_lock(path);
    trim_activity_log_locked(path, max_lines, keep_lines)
}

fn trim_activity_log_locked(path: &Path, max_lines: usize, keep_lines: usize) -> io::Result<bool> {
    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() <= max_lines {
        return Ok(false);
    }
    let keep = keep_lines.min(lines.len());
    let start = lines.len().saturating_sub(keep);
    let mut trimmed = String::with_capacity(content.len() / 2);
    for line in &lines[start..] {
        trimmed.push_str(line);
        trimmed.push('\n');
    }

    // 优先通过临时文件写入再替换，避免截断窗口暴露空文件或半写内容；若目标被外部只读句柄占用则回退到锁内原地覆写。
    let tmp_path = path.with_extension(format!("jsonl.tmp.{}", Uuid::new_v4().simple()));
    let write_tmp = (|| -> io::Result<()> {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        f.write_all(trimmed.as_bytes())?;
        f.flush()?;
        Ok(())
    })();
    if write_tmp.is_ok() {
        if fs::rename(&tmp_path, path).is_ok() {
            return Ok(true);
        }
        let _ = fs::remove_file(&tmp_path);
    }

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(trimmed.as_bytes())?;
    file.flush()?;
    Ok(true)
}

/// 清空并截断遥测日志文件（文件不存在时静默视为成功）。
pub fn truncate_activity_log(path: &Path) -> io::Result<()> {
    let _guard = file_write_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _proc_lock = acquire_activity_cross_process_lock(path);
    if !path.exists() {
        return Ok(());
    }
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.flush()?;
    Ok(())
}

/* ==========================================================================================
 * 增量字节偏移尾随读取器（ActivityLogTailer）
 * ========================================================================================== */

/// 用于检测文件被清空/滚动截断后又重写至 `new_len >= old_offset` 的头部指纹长度（字节）。
const TAILER_HEAD_FINGERPRINT_BYTES: usize = 128;

/// 极轻量的 JSONL 增量尾随读取器：跟踪已读字节偏移与头部指纹，检测截断重置并保护未写完的半行。
#[derive(Debug, Clone)]
pub struct ActivityLogTailer {
    path: PathBuf,
    offset: u64,
    /// 已读取文件的头部字节前缀指纹，用于识别“截断/滚动后又写到不小于旧偏移”的重写场景。
    head_prefix: Vec<u8>,
}

impl ActivityLogTailer {
    /// 创建绑定到 `path` 且初始字节偏移为 `initial_offset` 的尾随读取器。
    pub fn new(path: PathBuf, initial_offset: u64) -> Self {
        let head_prefix = if initial_offset > 0 {
            read_head_prefix(&path)
        } else {
            Vec::new()
        };
        Self {
            path,
            offset: initial_offset,
            head_prefix,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// 重置读取偏移与头部指纹为 0（例如在手动清空日志后调用）。
    pub fn reset(&mut self) {
        self.offset = 0;
        self.head_prefix.clear();
    }

    /// 检查文件增量并解析所有新到达的完整 JSONL 活动记录。
    pub fn poll_new_records(&mut self) -> Vec<McpActivityRecord> {
        let Ok(meta) = fs::metadata(&self.path) else {
            self.offset = 0;
            self.head_prefix.clear();
            return Vec::new();
        };
        let len = meta.len();
        if len < self.offset {
            // 检测到文件被清空或滚动截断，自动从头读取。
            self.offset = 0;
            self.head_prefix.clear();
        }

        let Ok(mut file) = File::open(&self.path) else {
            return Vec::new();
        };

        // 当已有偏移且文件头部前缀发生变化时（例如清空/温和截断后迅速写到 >= old_offset），
        // 主动重置偏移到 0，防止 seek 落入某行 JSON 中间导致丢数据或解析失败。
        if self.offset > 0 && !self.head_prefix.is_empty() {
            let mut probe = vec![0u8; self.head_prefix.len()];
            let n = read_prefix_from_file(&mut file, &mut probe);
            if n < self.head_prefix.len() || probe[..n] != self.head_prefix[..] {
                self.offset = 0;
                self.head_prefix.clear();
            }
        }

        if len == self.offset {
            return Vec::new();
        }

        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_err() || buf.is_empty() {
            return Vec::new();
        }

        // 仅消费至最后一个换行符，防止读入外部进程尚未刷完的半行 JSON。
        let Some(last_nl) = buf.iter().rposition(|&b| b == b'\n') else {
            return Vec::new();
        };
        let consumed = last_nl + 1;
        let was_from_start = self.offset == 0;
        self.offset = self.offset.saturating_add(consumed as u64);
        if was_from_start {
            let fp_len = consumed.min(TAILER_HEAD_FINGERPRINT_BYTES);
            self.head_prefix = buf[..fp_len].to_vec();
        } else if self.head_prefix.is_empty() {
            self.head_prefix = read_head_prefix(&self.path);
        }

        let text = String::from_utf8_lossy(&buf[..consumed]);
        let mut records = Vec::new();
        for raw_line in text.lines() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(mut rec) = serde_json::from_str::<McpActivityRecord>(trimmed) {
                rec.client = normalize_activity_client(&rec.client);
                records.push(rec);
            }
        }
        records
    }
}

fn read_prefix_from_file(file: &mut File, buf: &mut [u8]) -> usize {
    if file.seek(SeekFrom::Start(0)).is_err() {
        return 0;
    }
    let mut total = 0usize;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    total
}

fn read_head_prefix(path: &Path) -> Vec<u8> {
    let Ok(mut file) = File::open(path) else {
        return Vec::new();
    };
    let mut buf = vec![0u8; TAILER_HEAD_FINGERPRINT_BYTES];
    let n = read_prefix_from_file(&mut file, &mut buf);
    buf.truncate(n);
    buf
}

/* ==========================================================================================
 * 内存环形聚合队列与实时统计（McpActivityStore）
 * ========================================================================================== */

/// 线程外层加锁使用的 MCP 活动内存环形存储：
/// - 按事件 `id` 去重（防止桌面直写与后台尾随重复入队）
/// - 按 `callId` 合并 `started` -> `completed` / `failed`
/// - 上限默认 500 条合并后调用记录，超限时淘汰最早记录
#[derive(Debug, Clone)]
pub struct McpActivityStore {
    capacity: usize,
    /// 按入队时间正序存储合并后的调用记录（最新记录位于末尾，使用环形双端队列 O(1) 淘汰队首）。
    records: VecDeque<McpActivityRecord>,
    /// 已接收事件 `id` 去重集合。
    seen_ids: HashSet<String>,
    /// 维护 `seen_ids` 的淘汰顺序，限制最大缓存规模。
    seen_id_order: VecDeque<String>,
}

impl Default for McpActivityStore {
    fn default() -> Self {
        Self::new(DEFAULT_ACTIVITY_STORE_CAPACITY)
    }
}

impl McpActivityStore {
    /// 创建指定容量的活动存储（容量最小为 1）。
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            records: VecDeque::with_capacity(cap.min(64)),
            seen_ids: HashSet::new(),
            seen_id_order: VecDeque::new(),
        }
    }

    /// 吸收一条活动事件：
    /// - 若 `record.id` 已被处理过，返回 `false`；
    /// - 若同 `callId` 已有终态（`completed` / `failed`）而新事件为过时 `started`，忽略状态倒退并返回 `false`；
    /// - 否则合并更新并返回 `true`。
    pub fn ingest(&mut self, mut record: McpActivityRecord) -> bool {
        if !record.id.is_empty() && !self.seen_ids.insert(record.id.clone()) {
            return false;
        }
        record.client = normalize_activity_client(&record.client);
        if !record.id.is_empty() {
            self.seen_id_order.push_back(record.id.clone());
            let max_seen = self.capacity.saturating_mul(6).max(1_000);
            while self.seen_id_order.len() > max_seen {
                if let Some(oldest_id) = self.seen_id_order.pop_front() {
                    self.seen_ids.remove(&oldest_id);
                }
            }
        }

        if let Some(existing) = self
            .records
            .iter_mut()
            .rev()
            .find(|r| r.call_id == record.call_id)
        {
            // 避免并发或乱序到达的旧 `started` 覆盖已经完成/失败的终态。
            if record.phase == "started" && existing.phase != "started" {
                return false;
            }
            let merged_case_dir = record.case_dir.or_else(|| existing.case_dir.clone());
            let merged_case_number = record.case_number.or_else(|| existing.case_number.clone());
            let merged_session = record.session_id.or_else(|| existing.session_id.clone());
            let merged_tool = record.tool_name.or_else(|| existing.tool_name.clone());
            *existing = McpActivityRecord {
                case_dir: merged_case_dir,
                case_number: merged_case_number,
                session_id: merged_session,
                tool_name: merged_tool,
                ..record
            };
            return true;
        }

        self.records.push_back(record);
        while self.records.len() > self.capacity {
            self.records.pop_front();
        }
        true
    }

    /// 启动时从既有 `mcp-activity.jsonl` 加载历史活动记录，并返回已消费的字节偏移。
    pub fn load_from_file(&mut self, path: &Path) -> u64 {
        let mut tailer = ActivityLogTailer::new(path.to_path_buf(), 0);
        for rec in tailer.poll_new_records() {
            self.ingest(rec);
        }
        tailer.offset()
    }

    /// 清空全部内存活动记录与去重索引。
    pub fn clear(&mut self) {
        self.records.clear();
        self.seen_ids.clear();
        self.seen_id_order.clear();
    }

    /// 当前合并后的调用总条数。
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// 按筛选条件生成 [`McpActivitySnapshot`]（最新记录在前，统计覆盖筛选后的全部记录，`activities` 按 `limit` 截断）。
    pub fn snapshot(
        &self,
        limit: Option<usize>,
        client: Option<&str>,
        status: Option<&str>,
        transport: Option<&str>,
        keyword: Option<&str>,
    ) -> McpActivitySnapshot {
        let client_filter = normalize_filter_opt(client)
            .map(|c| normalize_activity_client(&c))
            .filter(|c| !c.is_empty());
        let status_filter = normalize_status_filter(status);
        let transport_filter = normalize_filter_opt(transport);
        let kw_filter = keyword
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);

        // 先仅收集匹配记录的引用并计算全量统计，再仅克隆前 `max_items` 条，避免大预览文本的无效克隆。
        let mut matched_refs: Vec<&McpActivityRecord> = Vec::new();
        for rec in self.records.iter().rev() {
            if let Some(ref cf) = client_filter
                && !rec.client.eq_ignore_ascii_case(cf)
            {
                continue;
            }
            if let Some(sf) = status_filter
                && rec.phase != sf
            {
                continue;
            }
            if let Some(ref tf) = transport_filter
                && !rec.transport.trim().eq_ignore_ascii_case(tf)
            {
                continue;
            }
            if let Some(ref kw) = kw_filter
                && !record_matches_keyword(rec, kw)
            {
                continue;
            }
            matched_refs.push(rec);
        }

        let stats = compute_activity_stats_refs(matched_refs.iter().copied(), false);
        let max_items = limit.unwrap_or(self.capacity);
        let activities = matched_refs
            .into_iter()
            .take(max_items)
            .cloned()
            .collect();

        McpActivitySnapshot { activities, stats }
    }
}

fn normalize_filter_opt(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_status_filter(raw: Option<&str>) -> Option<&'static str> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
        return None;
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "started" | "running" | "in_progress" => Some("started"),
        "completed" | "succeeded" | "success" | "ok" => Some("completed"),
        "failed" | "error" => Some("failed"),
        _ => Some("__unmatched__"),
    }
}

fn record_matches_keyword(rec: &McpActivityRecord, kw_lower: &str) -> bool {
    let contains = |s: &str| s.to_lowercase().contains(kw_lower);
    if contains(&rec.tool_title)
        || contains(&rec.category)
        || contains(&rec.client)
        || contains(&rec.method)
        || contains(&rec.transport)
        || contains(&rec.params_summary)
        || contains(&rec.result_summary)
        || contains(&rec.params_json)
    {
        return true;
    }
    if rec.tool_name.as_deref().is_some_and(contains)
        || rec.case_dir.as_deref().is_some_and(contains)
        || rec.case_number.as_deref().is_some_and(contains)
        || rec.session_id.as_deref().is_some_and(contains)
        || rec.response_preview.as_deref().is_some_and(contains)
        || rec.error.as_deref().is_some_and(contains)
    {
        return true;
    }
    false
}

/// 基于合并后的活动记录列表计算聚合统计信息。
pub fn compute_activity_stats(records: &[McpActivityRecord]) -> McpActivityStats {
    compute_activity_stats_refs(records.iter(), true)
}

fn compute_activity_stats_refs<'a, I>(records: I, normalize_client: bool) -> McpActivityStats
where
    I: IntoIterator<Item = &'a McpActivityRecord>,
{
    let mut total_calls = 0usize;
    let mut running_calls = 0usize;
    let mut succeeded_calls = 0usize;
    let mut failed_calls = 0usize;
    let mut read_only_calls = 0usize;
    let mut write_calls = 0usize;
    let mut duration_sum = 0u128;
    let mut duration_count = 0u128;

    let mut active_clients = Vec::new();
    let mut seen_clients = HashSet::new();

    // 记录每个工具的 `(总调用, 失败数, 耗时总和, 有耗时样本数)`
    let mut tool_acc: BTreeMap<String, (usize, usize, u128, u128)> = BTreeMap::new();

    for rec in records {
        total_calls += 1;
        match rec.phase.as_str() {
            "started" => running_calls += 1,
            "completed" => succeeded_calls += 1,
            "failed" => failed_calls += 1,
            _ => {}
        }
        if rec.read_only {
            read_only_calls += 1;
        } else {
            write_calls += 1;
        }
        if let Some(ms) = rec.duration_ms {
            duration_sum += u128::from(ms);
            duration_count += 1;
        }
        let client_clean = if normalize_client {
            normalize_activity_client(&rec.client)
        } else {
            rec.client.clone()
        };
        if !client_clean.is_empty() && seen_clients.insert(client_clean.clone()) {
            active_clients.push(client_clean);
        }
        if let Some(ref tool_name) = rec.tool_name {
            let entry = tool_acc.entry(tool_name.clone()).or_insert((0, 0, 0, 0));
            entry.0 += 1;
            if rec.phase == "failed" {
                entry.1 += 1;
            }
            if let Some(ms) = rec.duration_ms {
                entry.2 += u128::from(ms);
                entry.3 += 1;
            }
        }
    }

    let avg_duration_ms = duration_sum.checked_div(duration_count).unwrap_or(0) as u64;

    let tool_stats = tool_acc
        .into_iter()
        .map(|(tool_name, (calls, failures, d_sum, d_cnt))| {
            let tool_avg = d_sum.checked_div(d_cnt).unwrap_or(0) as u64;
            (
                tool_name.clone(),
                McpToolStat {
                    tool_name,
                    calls,
                    failures,
                    avg_duration_ms: tool_avg,
                },
            )
        })
        .collect();

    McpActivityStats {
        total_calls,
        running_calls,
        succeeded_calls,
        failed_calls,
        read_only_calls,
        write_calls,
        avg_duration_ms,
        active_clients,
        tool_stats,
    }
}

/// 便捷构建默认的共享文件遥测接收器。
pub fn default_file_activity_sink() -> Arc<dyn McpActivitySink> {
    Arc::new(FileActivitySink::default_location())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[allow(clippy::too_many_arguments)]
    fn sample_record(
        id: &str,
        call_id: &str,
        phase: &str,
        transport: &str,
        client: &str,
        tool_name: Option<&str>,
        read_only: bool,
        duration_ms: Option<u64>,
    ) -> McpActivityRecord {
        McpActivityRecord {
            id: id.to_string(),
            call_id: call_id.to_string(),
            timestamp: now_east8_millis(),
            phase: phase.to_string(),
            transport: transport.to_string(),
            client: client.to_string(),
            session_id: Some("sess-1".to_string()),
            method: "tools/call".to_string(),
            tool_name: tool_name.map(str::to_string),
            tool_title: tool_name
                .map(|t| lookup_tool_meta(t).0)
                .unwrap_or_else(|| "客户端握手初始化".to_string()),
            category: tool_name
                .map(|t| lookup_tool_meta(t).1)
                .unwrap_or_else(|| "协议会话".to_string()),
            read_only,
            case_dir: None,
            case_number: None,
            params_summary: "query=\"test\"".to_string(),
            params_json: "{}".to_string(),
            duration_ms,
            result_summary: if phase == "started" {
                "执行中...".to_string()
            } else if phase == "completed" {
                "执行成功（返回 120 字符）".to_string()
            } else {
                "Error (ValueError): 参数错误".to_string()
            },
            response_preview: (phase != "started").then(|| "ok".to_string()),
            error: (phase == "failed").then(|| "Error (ValueError): 参数错误".to_string()),
        }
    }

    #[test]
    fn test_timestamp_east8_millis_format() {
        let ts = now_east8_millis();
        assert!(ts.ends_with("+08:00"), "unexpected timestamp: {ts}");
        assert_eq!(ts.len(), 29, "expected YYYY-MM-DDTHH:MM:SS.mmm+08:00, got {ts}");
        assert_eq!(&ts[19..20], ".");
    }

    #[test]
    fn test_truncate_preview_utf8_boundary_safe() {
        let chinese = "取证分析报告内容测试".repeat(2000);
        let truncated = truncate_preview(&chinese, MAX_PREVIEW_BYTES);
        assert!(truncated.contains("已截断"));
        assert!(truncated.len() < chinese.len());
    }

    #[test]
    fn test_summarize_params_and_camel_case_serialization() {
        let summary = summarize_params(
            "tools/call",
            &json!({
                "params": {
                    "case_dir": "D:/cases/CASE-01",
                    "query": "accountNum",
                    "encoding": "UTF-8"
                }
            }),
        );
        assert_eq!(summary, "query=\"accountNum\" · encoding=\"UTF-8\"");

        let rec = sample_record(
            "evt-1",
            "call-1",
            "completed",
            "desktop-http",
            "Antigravity 1.0",
            Some("tracedesk_search_content"),
            false,
            Some(42),
        );
        let val = serde_json::to_value(&rec).expect("serialize McpActivityRecord");
        assert_eq!(val["callId"], "call-1");
        assert_eq!(val["sessionId"], "sess-1");
        assert_eq!(val["toolName"], "tracedesk_search_content");
        assert_eq!(val["toolTitle"], "搜索文件内容");
        assert_eq!(val["readOnly"], false);
        assert_eq!(val["paramsSummary"], "query=\"test\"");
        assert_eq!(val["paramsJson"], "{}");
        assert_eq!(val["durationMs"], 42);
        assert_eq!(val["resultSummary"], "执行成功（返回 120 字符）");
        assert_eq!(val["responsePreview"], "ok");
    }

    #[test]
    fn test_store_merge_dedup_filter_and_stats() {
        let mut store = McpActivityStore::new(500);
        let r1_start = sample_record(
            "e1",
            "c1",
            "started",
            "stdio",
            "Cursor",
            Some("tracedesk_list_cases"),
            true,
            None,
        );
        let r1_done = sample_record(
            "e2",
            "c1",
            "completed",
            "stdio",
            "Cursor",
            Some("tracedesk_list_cases"),
            true,
            Some(20),
        );
        let r2_fail = sample_record(
            "e3",
            "c2",
            "failed",
            "desktop-http",
            "Antigravity 1.0",
            Some("tracedesk_search_content"),
            false,
            Some(80),
        );
        assert!(store.ingest(r1_start.clone()));
        // 相同事件 ID 去重
        assert!(!store.ingest(r1_start));
        assert!(store.ingest(r1_done));
        // 过时 started 不应覆盖已完成终态
        let stale_start = sample_record(
            "e2-stale",
            "c1",
            "started",
            "stdio",
            "Cursor",
            Some("tracedesk_list_cases"),
            true,
            None,
        );
        assert!(!store.ingest(stale_start));
        assert!(store.ingest(r2_fail));

        let snap = store.snapshot(None, None, None, None, None);
        assert_eq!(snap.activities.len(), 2);
        assert_eq!(snap.activities[0].call_id, "c2");
        assert_eq!(snap.activities[1].call_id, "c1");
        assert_eq!(snap.stats.total_calls, 2);
        assert_eq!(snap.stats.running_calls, 0);
        assert_eq!(snap.stats.succeeded_calls, 1);
        assert_eq!(snap.stats.failed_calls, 1);
        assert_eq!(snap.stats.read_only_calls, 1);
        assert_eq!(snap.stats.write_calls, 1);
        assert_eq!(snap.stats.avg_duration_ms, 50);
        // 历史记录中的 "Antigravity 1.0" 在入队与统计时应自动去除末尾版本号数字
        assert_eq!(snap.activities[0].client, "Antigravity");
        assert_eq!(snap.stats.active_clients, vec!["Antigravity", "Cursor"]);
        assert_eq!(
            snap.stats.tool_stats["tracedesk_search_content"].failures,
            1
        );

        // 兼容历史筛选词（含或不含末尾版本号）均应命中同一归一化客户端
        let filtered_by_clean = store.snapshot(None, Some("Antigravity"), None, None, None);
        assert_eq!(filtered_by_clean.activities.len(), 1);
        let filtered_by_legacy = store.snapshot(None, Some("Antigravity 1.0"), None, None, None);
        assert_eq!(filtered_by_legacy.activities.len(), 1);

        let filtered = store.snapshot(None, Some("Cursor"), Some("completed"), Some("stdio"), None);
        assert_eq!(filtered.activities.len(), 1);
        assert_eq!(filtered.activities[0].call_id, "c1");
        assert_eq!(filtered.stats.total_calls, 1);
    }

    #[test]
    fn test_log_trim_and_tailer_reset() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join(ACTIVITY_LOG_FILENAME);

        let mut tailer = ActivityLogTailer::new(log_path.clone(), 0);
        for i in 0..10 {
            let rec = sample_record(
                &format!("id-{i}"),
                &format!("call-{i}"),
                "completed",
                "stdio",
                "Cursor",
                Some("tracedesk_list_cases"),
                true,
                Some(10),
            );
            append_activity_record(&log_path, &rec).expect("append");
        }
        let first_batch = tailer.poll_new_records();
        assert_eq!(first_batch.len(), 10);
        assert!(tailer.poll_new_records().is_empty());

        // 模拟温和截断（保留最近 4 行）
        let trimmed = trim_activity_log_if_needed(&log_path, 8, 4).expect("trim");
        assert!(trimmed);
        let after_trim = tailer.poll_new_records();
        assert_eq!(after_trim.len(), 4);
        assert_eq!(after_trim[0].id, "id-6");
        assert_eq!(after_trim[3].id, "id-9");
    }

    #[test]
    fn test_tailer_detects_rewrite_when_new_len_exceeds_old_offset() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join(ACTIVITY_LOG_FILENAME);

        let mut tailer = ActivityLogTailer::new(log_path.clone(), 0);
        let rec0 = sample_record(
            "old-0",
            "call-old-0",
            "completed",
            "stdio",
            "Cursor",
            Some("tracedesk_list_cases"),
            true,
            Some(5),
        );
        append_activity_record(&log_path, &rec0).expect("append old");
        let first = tailer.poll_new_records();
        assert_eq!(first.len(), 1);
        let old_offset = tailer.offset();
        assert!(old_offset > 0);

        // 清空文件后立即写入 3 条新记录，使新文件长度大于旧偏移量。
        truncate_activity_log(&log_path).expect("truncate");
        for i in 0..3 {
            let rec = sample_record(
                &format!("new-{i}"),
                &format!("call-new-{i}"),
                "completed",
                "stdio",
                "Cursor",
                Some("tracedesk_list_cases"),
                true,
                Some(12),
            );
            append_activity_record(&log_path, &rec).expect("append new");
        }
        assert!(fs::metadata(&log_path).unwrap().len() > old_offset);

        // 头部指纹变化应触发从头重读，避免 seek 落到半行中间导致丢记录。
        let reloaded = tailer.poll_new_records();
        assert_eq!(reloaded.len(), 3);
        assert_eq!(reloaded[0].id, "new-0");
        assert_eq!(reloaded[2].id, "new-2");
    }

    #[test]
    fn test_resolve_case_context_strips_case_json_filename() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let case_dir = tmp.path().join("CASE-01");
        fs::create_dir_all(&case_dir).expect("mkdir");
        let case_json = case_dir.join("case.json");
        fs::write(&case_json, r#"{"number":"CASE-2026-99"}"#).expect("write case.json");

        let (dir_opt, num_opt) = resolve_case_context(
            &json!({ "case_dir": case_json.to_string_lossy() }),
            tmp.path(),
        );
        assert_eq!(
            dir_opt.as_deref(),
            Some(resolve_clean(&case_dir).to_string_lossy().as_ref())
        );
        assert_eq!(num_opt.as_deref(), Some("CASE-2026-99"));
    }
}
