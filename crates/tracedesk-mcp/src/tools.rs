//! TraceDesk MCP 全部 19 个工具、2 个资源、JSON Schema 定义、Markdown/JSON 渲染器与 JSON-RPC 2.0 协议分发。

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracedesk_core::{PAGE_BYTES, PREVIEW_ENCODINGS, format_commas};

use crate::service::{CaseService, McpError, McpResult};

/// MCP 服务端固定名称（`mcp-contract.md` §1.1）。
pub const SERVER_NAME: &str = "tracedesk_mcp";

/// MCP 服务端版本号。
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 默认支持的 MCP 协议版本。
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-03-26";

/// MCP 服务端说明文本（`mcp-contract.md` §1.1）。
pub const SERVER_INSTRUCTIONS: &str = "TraceDesk 是本地电子数据取证工作台 MCP 服务。\
所有源镜像（RAW / 分段 EWF .E01）均以只读方式打开，绝不修改原始证据；\
所有受控写操作（新建案件、载入镜像、校验、登记来源、搜索、记录发现、导出、生成报告与复核包）\
都会写入案件目录并追加到可核验 SHA-256 审计哈希链。\
同名或跨分区文件请通过 partition_offset、inode 和 deleted 参数唯一定位。\
界面与返回时间统一采用东八区（UTC+8）。";

/// `tracedesk://guide/workflow` 资源返回的 6 步标准取证流程 Markdown。
pub const WORKFLOW_GUIDE_MARKDOWN: &str = "# TraceDesk MCP 标准取证流程\n\n\
1. 使用 `tracedesk_list_cases` 查看现有案件，或用 `tracedesk_create_case` 新建隔离案件。\n\
2. 使用 `tracedesk_load_image` 只读载入 RAW 或 `.E01` 首段镜像（镜像必须位于案件库目录之外）。\n\
3. 使用 `tracedesk_get_case_summary` 查看 SHA-256、卷声明范围和分区扫描状态。\n\
4. 使用 `tracedesk_list_files`、`tracedesk_preview_file`、`tracedesk_search_content`、`tracedesk_query_timeline` 开展分析。\n\
5. 使用 `tracedesk_examine_file` 校验文件哈希，用 `tracedesk_record_finding` 记录取证发现。\n\
6. 使用 `tracedesk_export_file` / `tracedesk_export_findings` 导出副本，并用 `tracedesk_generate_report` 或 `tracedesk_build_review_bundle` 输出正式报告和可核验复核包。\n\n\
注意：同名文件可能存在于不同分区或包含已删除记录，定位文件时请优先提供 `partition_offset`、`inode` 与 `deleted` 参数。";

/// 工具目录元数据项（供桌面端“可用工具清单（19）”标签页展示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ToolCatalogItem {
    pub name: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub read_only: bool,
    #[serde(rename = "readOnly")]
    pub read_only_camel: bool,
    pub summary: &'static str,
}

impl ToolCatalogItem {
    const fn new(
        name: &'static str,
        title: &'static str,
        category: &'static str,
        read_only: bool,
        summary: &'static str,
    ) -> Self {
        Self {
            name,
            title,
            category,
            read_only,
            read_only_camel: read_only,
            summary,
        }
    }
}

/// 全部 19 个 MCP 工具目录（严格顺序对齐 `forensic/mcp/server.py::TOOL_CATALOG`）。
pub const TOOL_CATALOG: [ToolCatalogItem; 19] = [
    ToolCatalogItem::new(
        "tracedesk_list_cases",
        "列出案件",
        "案件管理",
        true,
        "列出案件库目录中的已有取证案件及其摘要状态",
    ),
    ToolCatalogItem::new(
        "tracedesk_create_case",
        "新建案件",
        "案件管理",
        false,
        "创建隔离的取证案件目录、元数据与审计链起点",
    ),
    ToolCatalogItem::new(
        "tracedesk_get_case_summary",
        "案件总览",
        "案件管理",
        true,
        "查看案件元数据、镜像哈希、覆盖范围、分区扫描与审计链状态",
    ),
    ToolCatalogItem::new(
        "tracedesk_load_image",
        "加载镜像",
        "证据镜像",
        false,
        "以只读方式加载 RAW 或 .E01 首段镜像，固定 SHA-256 并识别分区",
    ),
    ToolCatalogItem::new(
        "tracedesk_verify_integrity",
        "校验完整性",
        "证据镜像",
        false,
        "复算镜像 SHA-256 并与初始固定基线比对，更新校验记录",
    ),
    ToolCatalogItem::new(
        "tracedesk_register_source",
        "登记证据来源",
        "证据镜像",
        false,
        "登记证据编号、交付方、采集时间/工具和交付方 SHA-256",
    ),
    ToolCatalogItem::new(
        "tracedesk_scan_partitions",
        "扫描分区清单",
        "证据镜像",
        false,
        "扫描全部分区或指定偏移分区，建立/刷新完整文件清单",
    ),
    ToolCatalogItem::new(
        "tracedesk_list_files",
        "浏览与筛选文件",
        "文件分析",
        true,
        "按分区、路径前缀、后缀、关键词和状态分页查询镜像内文件",
    ),
    ToolCatalogItem::new(
        "tracedesk_preview_file",
        "预览文件内容",
        "文件分析",
        true,
        "按页读取文件或系统区域的文本（多编码）与十六进制转储",
    ),
    ToolCatalogItem::new(
        "tracedesk_search_content",
        "搜索文件内容",
        "文件分析",
        false,
        "按 UTF-8 / UTF-16LE / GBK / HEX 精确搜索全案或单文件字节",
    ),
    ToolCatalogItem::new(
        "tracedesk_examine_file",
        "计算文件哈希/比对",
        "文件分析",
        false,
        "直接从只读镜像计算文件 SHA-256，或与本地副本核验一致性",
    ),
    ToolCatalogItem::new(
        "tracedesk_record_finding",
        "记录取证发现",
        "取证发现",
        false,
        "绑定镜像摘要、分区偏移、路径与 inode 写入结构化取证笔记",
    ),
    ToolCatalogItem::new(
        "tracedesk_list_findings",
        "查询取证发现",
        "取证发现",
        true,
        "按文件归组查看取证笔记、哈希计算与副本比对记录",
    ),
    ToolCatalogItem::new(
        "tracedesk_query_timeline",
        "查询 MACB 时间线",
        "时间线与审计",
        true,
        "按事件类型、状态、分区偏移与关键词分页查询 MACB 时间线",
    ),
    ToolCatalogItem::new(
        "tracedesk_query_audit_log",
        "核验并查询审计日志",
        "时间线与审计",
        true,
        "核验审计哈希链完整性，并按操作/人员/结果分页检索日志",
    ),
    ToolCatalogItem::new(
        "tracedesk_export_file",
        "导出单个文件",
        "导出与报告",
        false,
        "导出镜像中现存或已删除文件到案件 exports 目录并记录副本哈希",
    ),
    ToolCatalogItem::new(
        "tracedesk_export_findings",
        "一键导出取证发现",
        "导出与报告",
        false,
        "批量导出取证发现涉及的文件副本及 Markdown 汇总清单",
    ),
    ToolCatalogItem::new(
        "tracedesk_generate_report",
        "生成 Markdown 报告",
        "导出与报告",
        false,
        "执行完整性校验并生成分节 Markdown 取证报告",
    ),
    ToolCatalogItem::new(
        "tracedesk_build_review_bundle",
        "构建复核包 ZIP",
        "导出与报告",
        false,
        "生成含报告、副本、搜索记录、审计链与 SHA256SUMS 的复核包",
    ),
];

/// 工具输出格式枚举（`markdown` 或 `json`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseFormat {
    #[default]
    Markdown,
    Json,
}

fn default_limit_20() -> usize {
    20
}
fn default_limit_50() -> usize {
    50
}
fn default_max_hits_200() -> usize {
    200
}
fn default_true() -> bool {
    true
}
fn default_page_bytes() -> usize {
    PAGE_BYTES
}
fn default_utf8() -> String {
    "UTF-8".to_string()
}
fn default_status_all() -> String {
    "all".to_string()
}
fn default_mode_both() -> String {
    "both".to_string()
}
fn default_sort_asc() -> String {
    "asc".to_string()
}
fn default_sort_desc() -> String {
    "desc".to_string()
}

fn check_non_empty(val: &str, field: &str, max_len: Option<usize>) -> McpResult<String> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Err(McpError::ValueError(format!(
            "参数 {field} 不能为空。"
        )));
    }
    if let Some(max) = max_len
        && trimmed.chars().count() > max
    {
        return Err(McpError::ValueError(format!(
            "参数 {field} 长度不能超过 {max} 个字符。"
        )));
    }
    Ok(trimmed.to_string())
}

fn check_optional_str(
    val: &Option<String>,
    field: &str,
    max_len: Option<usize>,
) -> McpResult<Option<String>> {
    match val {
        None => Ok(None),
        Some(raw) => {
            let trimmed = raw.trim();
            if let Some(max) = max_len
                && trimmed.chars().count() > max
            {
                return Err(McpError::ValueError(format!(
                    "参数 {field} 长度不能超过 {max} 个字符。"
                )));
            }
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
    }
}

fn check_bounded_str(val: &str, field: &str, max_len: usize) -> McpResult<String> {
    let trimmed = val.trim();
    if trimmed.chars().count() > max_len {
        return Err(McpError::ValueError(format!(
            "参数 {field} 长度不能超过 {max_len} 个字符。"
        )));
    }
    Ok(trimmed.to_string())
}

fn check_range(val: usize, field: &str, min: usize, max: usize) -> McpResult<usize> {
    if val < min || val > max {
        return Err(McpError::ValueError(format!(
            "参数 {field} 必须在 {min} 到 {max} 之间（当前值：{val}）。"
        )));
    }
    Ok(val)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListCasesInput {
    #[serde(default)]
    cases_root: Option<String>,
    #[serde(default = "default_limit_20")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateCaseInput {
    number: String,
    examiner: String,
    target: String,
    #[serde(default)]
    cases_root: Option<String>,
    #[serde(default)]
    folder_name: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseBaseInput {
    case_dir: String,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadImageInput {
    case_dir: String,
    image_path: String,
    #[serde(default = "default_true")]
    scan_all: bool,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterSourceInput {
    case_dir: String,
    #[serde(default)]
    evidence_id: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    acquired: String,
    #[serde(default)]
    tool: String,
    #[serde(default)]
    expected_sha256: String,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanPartitionsInput {
    case_dir: String,
    #[serde(default)]
    partition_offset: Option<u64>,
    #[serde(default)]
    verify_large_image: bool,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListFilesInput {
    case_dir: String,
    #[serde(default)]
    partition_offset: Option<u64>,
    #[serde(default)]
    path_prefix: String,
    #[serde(default)]
    suffix: String,
    #[serde(default)]
    keyword: String,
    #[serde(default = "default_status_all")]
    status: String,
    #[serde(default)]
    files_only: bool,
    #[serde(default)]
    dir_inode: Option<String>,
    #[serde(default)]
    dir_path: String,
    #[serde(default = "default_limit_50")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewFileInput {
    case_dir: String,
    path: String,
    #[serde(default)]
    partition_offset: Option<u64>,
    #[serde(default)]
    inode: Option<String>,
    #[serde(default)]
    deleted: Option<bool>,
    #[serde(default)]
    dir_inode: Option<String>,
    #[serde(default)]
    dir_path: String,
    #[serde(default)]
    page: usize,
    #[serde(default = "default_page_bytes")]
    page_bytes: usize,
    #[serde(default = "default_utf8")]
    encoding: String,
    #[serde(default = "default_mode_both")]
    mode: String,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchContentInput {
    case_dir: String,
    query: String,
    #[serde(default = "default_utf8")]
    encoding: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    partition_offset: Option<u64>,
    #[serde(default)]
    inode: Option<String>,
    #[serde(default)]
    deleted: Option<bool>,
    #[serde(default)]
    dir_inode: Option<String>,
    #[serde(default)]
    dir_path: String,
    #[serde(default = "default_max_hits_200")]
    max_hits: usize,
    #[serde(default = "default_limit_50")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    verify_large_image: bool,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExamineFileInput {
    case_dir: String,
    path: String,
    #[serde(default)]
    partition_offset: Option<u64>,
    #[serde(default)]
    inode: Option<String>,
    #[serde(default)]
    deleted: Option<bool>,
    #[serde(default)]
    dir_inode: Option<String>,
    #[serde(default)]
    dir_path: String,
    #[serde(default)]
    comparison_path: Option<String>,
    #[serde(default)]
    verify_large_image: bool,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFindingInput {
    case_dir: String,
    path: String,
    note: String,
    #[serde(default)]
    partition_offset: Option<u64>,
    #[serde(default)]
    inode: Option<String>,
    #[serde(default)]
    deleted: Option<bool>,
    #[serde(default)]
    dir_inode: Option<String>,
    #[serde(default)]
    dir_path: String,
    #[serde(default)]
    verify_large_image: bool,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListFindingsInput {
    case_dir: String,
    #[serde(default = "default_status_all")]
    status: String,
    #[serde(default)]
    partition_offset: Option<u64>,
    #[serde(default)]
    keyword: String,
    #[serde(default = "default_limit_50")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryTimelineInput {
    case_dir: String,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    partition_offset: Option<u64>,
    #[serde(default)]
    query: String,
    #[serde(default = "default_sort_asc")]
    sort_order: String,
    #[serde(default = "default_limit_50")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryAuditLogInput {
    case_dir: String,
    #[serde(default = "default_status_all")]
    origin: String,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    actor_filter: Option<String>,
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    query: String,
    #[serde(default = "default_sort_desc")]
    sort_order: String,
    #[serde(default = "default_limit_50")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportFileInput {
    case_dir: String,
    path: String,
    #[serde(default)]
    partition_offset: Option<u64>,
    #[serde(default)]
    inode: Option<String>,
    #[serde(default)]
    deleted: Option<bool>,
    #[serde(default)]
    dir_inode: Option<String>,
    #[serde(default)]
    dir_path: String,
    #[serde(default)]
    verify_large_image: bool,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportFindingsInput {
    case_dir: String,
    #[serde(default = "default_status_all")]
    status: String,
    #[serde(default)]
    partition_offset: Option<u64>,
    #[serde(default)]
    keyword: String,
    #[serde(default)]
    verify_large_image: bool,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportActionInput {
    case_dir: String,
    #[serde(default)]
    verify_large_image: bool,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewBundleInput {
    case_dir: String,
    #[serde(default)]
    selected_export_indices: Option<Vec<usize>>,
    #[serde(default)]
    selected_search_indices: Option<Vec<usize>>,
    #[serde(default)]
    skip_missing_exports: bool,
    #[serde(default)]
    verify_large_image: bool,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    response_format: ResponseFormat,
}

/// 兼容直接扁平参数 `{"case_dir": "..."}` 与 FastMCP 风格包装参数 `{"params": {"case_dir": "..."}}`。
fn unwrap_tool_arguments(arguments: Value) -> Value {
    match arguments {
        Value::Null => json!({}),
        Value::Object(mut map) => {
            if let Some(Value::Object(mut inner)) = map.remove("params") {
                for (k, v) in map {
                    inner.entry(k).or_insert(v);
                }
                return Value::Object(inner);
            }
            Value::Object(map)
        }
        other => other,
    }
}

fn parse_input<T: for<'de> Deserialize<'de>>(arguments: Value) -> McpResult<T> {
    let unwrapped = unwrap_tool_arguments(arguments);
    serde_json::from_value(unwrapped).map_err(|e| McpError::ValueError(format!("参数校验失败：{e}")))
}

fn to_pretty_json(data: &Value) -> String {
    serde_json::to_string_pretty(data).unwrap_or_else(|_| data.to_string())
}

fn format_output<F>(data: &Value, fmt: ResponseFormat, md_renderer: F) -> String
where
    F: FnOnce(&Value) -> String,
{
    match fmt {
        ResponseFormat::Json => to_pretty_json(data),
        ResponseFormat::Markdown => md_renderer(data),
    }
}

/* -------------------- Markdown Renderers (100% aligned with server.py) -------------------- */

pub fn render_cases_md(data: &Value) -> String {
    let cases_root = data.get("cases_root").and_then(Value::as_str).unwrap_or("");
    let total = data.get("total").and_then(Value::as_u64).unwrap_or(0);
    let count = data.get("count").and_then(Value::as_u64).unwrap_or(0);
    let offset = data.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let mut lines = vec![
        "# TraceDesk 案件列表".to_string(),
        format!("- 案件库目录：`{cases_root}`"),
        format!("- 共 {total} 个案件，当前显示 {count} 个（offset={offset}）"),
        String::new(),
    ];
    let items = data
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if items.is_empty() {
        lines.push("当前案件库为空，可调用 `tracedesk_create_case` 新建案件。".to_string());
        return lines.join("\n");
    }
    for item in items {
        let status = item.get("status").and_then(Value::as_str).unwrap_or("");
        let name = item.get("name").and_then(Value::as_str).unwrap_or("");
        let folder = item.get("folder").and_then(Value::as_str).unwrap_or("");
        if status != "ok" {
            lines.push(format!("- **{name}**（元数据损坏）· `{folder}`"));
            continue;
        }
        let has_ev = item
            .get("has_evidence")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ev = if has_ev {
            let img_name = item.get("image_name").and_then(Value::as_str).unwrap_or("");
            let fixed = item
                .get("sha256_fixed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            format!(
                "{img_name}（{}）",
                if fixed {
                    "已固定 SHA-256"
                } else {
                    "待固定"
                }
            )
        } else {
            "尚未加载镜像".to_string()
        };
        let number = item.get("number").and_then(Value::as_str).unwrap_or("");
        let examiner = item.get("examiner").and_then(Value::as_str).unwrap_or("");
        let target = item.get("target").and_then(Value::as_str).unwrap_or("");
        let created = item.get("created").and_then(Value::as_str).unwrap_or("");
        let inv_cnt = item
            .get("inventory_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let exp_cnt = item
            .get("exports_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        lines.push(format!(
            "- **{number}** · {examiner} · {target}  \n  目录：`{folder}` · 创建：{created} · 镜像：{ev} · 清单：{inv_cnt} 项 · 导出：{exp_cnt} 项"
        ));
    }
    if data
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && let Some(next_off) = data.get("next_offset").and_then(Value::as_u64)
    {
        lines.push(format!(
            "\n> 还有更多案件，请使用 `offset={next_off}` 继续翻页。"
        ));
    }
    lines.join("\n")
}

pub fn render_summary_md(data: &Value) -> String {
    let number = data.get("number").and_then(Value::as_str).unwrap_or("");
    let case_dir = data.get("case_dir").and_then(Value::as_str).unwrap_or("");
    let examiner = data.get("examiner").and_then(Value::as_str).unwrap_or("");
    let target = data.get("target").and_then(Value::as_str).unwrap_or("");
    let created = data.get("created").and_then(Value::as_str).unwrap_or("");
    let inv_cnt = data
        .get("inventory_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let exp_cnt = data
        .get("exports_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let f_files = data
        .get("findings_file_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let f_recs = data
        .get("findings_record_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let audit_cnt = data.get("audit_count").and_then(Value::as_u64).unwrap_or(0);
    let audit_head = data.get("audit_head").and_then(Value::as_str).unwrap_or("");
    let manual_cnt = data
        .get("audit_origin_counts")
        .and_then(|c| c.get("manual"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mcp_cnt = data
        .get("audit_origin_counts")
        .and_then(|c| c.get("mcp"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let audit_line = if !audit_head.is_empty() {
        let prefix = &audit_head[..audit_head.len().min(16)];
        format!(
            "- **审计链**：校验通过（共 {audit_cnt} 条：人工 {manual_cnt} · MCP {mcp_cnt}，尾部锚点 `{prefix}…`）"
        )
    } else {
        "- **审计链**：暂无记录".to_string()
    };

    let mut lines = vec![
        format!("# 案件总览 · {number}"),
        format!("- **案件目录**：`{case_dir}`"),
        format!("- **取证人员**：{examiner} · **取证对象**：{target}"),
        format!("- **创建时间（UTC+8）**：{created}"),
        format!(
            "- **清单条目**：{inv_cnt} · **已导出**：{exp_cnt} · **取证发现**：{f_files} 个文件（{f_recs} 条记录）"
        ),
        audit_line,
    ];

    let Some(ev) = data.get("evidence").and_then(Value::as_object) else {
        lines.push(
            "\n## 证据镜像\n尚未加载镜像，可调用 `tracedesk_load_image` 载入 RAW 或 .E01 镜像。"
                .to_string(),
        );
        return lines.join("\n");
    };

    let path = ev.get("path").and_then(Value::as_str).unwrap_or("");
    let fmt = ev.get("format").and_then(Value::as_str).unwrap_or("RAW");
    let size = ev.get("size").and_then(Value::as_u64).unwrap_or(0);
    let large = ev
        .get("large_image")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let sha = ev
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("待固定");
    let fixed_at = ev
        .get("fixed_at")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("未固定");
    let src_cmp = ev
        .get("source_comparison")
        .and_then(Value::as_str)
        .unwrap_or("");
    let cov_txt = ev
        .get("coverage_text")
        .and_then(Value::as_str)
        .unwrap_or("");
    let parts = ev
        .get("partitions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    lines.extend([
        String::new(),
        "## 证据镜像".to_string(),
        format!("- **路径**：`{path}`"),
        format!(
            "- **格式 / 大小**：{fmt} · {} 字节{}",
            format_commas(size),
            if large {
                "（大容量快速浏览模式）"
            } else {
                ""
            }
        ),
        format!("- **SHA-256**：`{sha}`（固定时间：{fixed_at}）"),
        format!("- **交付方摘要比对**：{src_cmp}"),
        format!("- **声明范围评估**：{cov_txt}"),
        format!("- **识别分区**：{} 个", parts.len()),
    ]);

    for part in parts {
        let off = part.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let desc = part
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("");
        let len = part.get("length").and_then(Value::as_u64).unwrap_or(0);
        lines.push(format!(
            "  - 偏移 `{off}` 扇区 · {desc}（长度 {len} 扇区）"
        ));
    }

    if let Some(scans) = data.get("partition_scans").and_then(Value::as_array)
        && !scans.is_empty()
    {
        lines.push("- **分区扫描状态**：".to_string());
        for scan in scans {
            let off = scan.get("offset").and_then(Value::as_u64).unwrap_or(0);
            let st = scan.get("status").and_then(Value::as_str).unwrap_or("");
            let cnt = scan.get("count").and_then(Value::as_u64).unwrap_or(0);
            let extra = scan
                .get("error")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(|e| format!("，错误：{e}"))
                .unwrap_or_default();
            lines.push(format!("  - 偏移 `{off}`：{st}（{cnt} 项{extra}）"));
        }
    }
    lines.join("\n")
}

pub fn render_files_md(data: &Value) -> String {
    let mode = data
        .get("browse_mode")
        .and_then(Value::as_str)
        .unwrap_or("");
    let total = data.get("total").and_then(Value::as_u64).unwrap_or(0);
    let count = data.get("count").and_then(Value::as_u64).unwrap_or(0);
    let offset = data.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let mut lines = vec![
        format!("# 文件列表（{mode}）"),
        format!("- 匹配总数：{total} · 当前返回：{count}（offset={offset}）"),
        String::new(),
    ];
    let items = data
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if items.is_empty() {
        lines.push("未匹配到任何条目。".to_string());
        return lines.join("\n");
    }
    lines.push("| 路径 | 状态 | 分区偏移 | inode | 大小(字节) | 修改时间(UTC+8) |".to_string());
    lines.push("| --- | --- | ---: | --- | ---: | --- |".to_string());
    for item in items {
        let is_dir = item
            .get("directory")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let kind = if is_dir { "[目录] " } else { "" };
        let path = item.get("path").and_then(Value::as_str).unwrap_or("");
        let safe_path = format!("{kind}{path}").replace('|', "\\|");
        let status = item.get("status").and_then(Value::as_str).unwrap_or("");
        let off = item
            .get("partition_offset")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let inode = item.get("inode").and_then(Value::as_str).unwrap_or("");
        let size = item.get("size").and_then(Value::as_u64).unwrap_or(0);
        let mtime = item
            .get("mtime")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("-");
        lines.push(format!(
            "| `{safe_path}` | {status} | {off} | `{inode}` | {size} | {mtime} |"
        ));
    }
    if data
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && let Some(next_off) = data.get("next_offset").and_then(Value::as_u64)
    {
        lines.push(format!(
            "\n> 还有更多条目，请使用 `offset={next_off}` 继续翻页。"
        ));
    }
    lines.join("\n")
}

pub fn render_preview_md(data: &Value) -> String {
    let entry = data.get("entry").unwrap_or(&Value::Null);
    let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
    let off = entry
        .get("partition_offset")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let inode = entry.get("inode").and_then(Value::as_str).unwrap_or("");
    let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
    let enc = data.get("encoding").and_then(Value::as_str).unwrap_or("");
    let page = data.get("page").and_then(Value::as_u64).unwrap_or(0);
    let total_pages = data.get("total_pages").and_then(Value::as_u64).unwrap_or(1);
    let b_start = data.get("byte_start").and_then(Value::as_u64).unwrap_or(0);
    let b_end = data.get("byte_end").and_then(Value::as_u64).unwrap_or(0);
    let r_size = data
        .get("readable_size")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let rec_size = data
        .get("recorded_size")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let mut lines = vec![
        format!("# 文件预览 · `{path}`"),
        format!("- 分区偏移：`{off}` · inode：`{inode}` · 状态：{status} · 编码：{enc}"),
        format!(
            "- 页码：{} / {total_pages} · 字节范围：{b_start}..{b_end} / 可读 {r_size} 字节（目录记录 {rec_size} 字节）",
            page + 1
        ),
    ];
    if let Some(sn) = data
        .get("source_note")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        lines.push(format!("- **删除提示**：{sn}"));
    }
    if let Some(rn) = data
        .get("read_note")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        lines.push(format!("- **读取说明**：{rn}"));
    }
    if let Some(txt) = data.get("text").and_then(Value::as_str) {
        lines.extend([
            String::new(),
            "## 文本内容".to_string(),
            "```text".to_string(),
            txt.to_string(),
            "```".to_string(),
        ]);
    }
    if let Some(hex_arr) = data.get("hex_lines").and_then(Value::as_array) {
        let joined: Vec<&str> = hex_arr.iter().filter_map(Value::as_str).collect();
        lines.extend([
            String::new(),
            "## 十六进制".to_string(),
            "```text".to_string(),
            joined.join("\n"),
            "```".to_string(),
        ]);
    }
    lines.join("\n")
}

pub fn render_search_md(data: &Value) -> String {
    let query = data.get("query").and_then(Value::as_str).unwrap_or("");
    let enc = data.get("encoding").and_then(Value::as_str).unwrap_or("");
    let status = data.get("status").and_then(Value::as_str).unwrap_or("");
    let scope = data.get("scope").and_then(Value::as_str).unwrap_or("");
    let needle = data.get("needle_hex").and_then(Value::as_str).unwrap_or("");
    let ver = data
        .get("verification")
        .and_then(Value::as_str)
        .unwrap_or("");
    let visited = data.get("visited").and_then(Value::as_u64).unwrap_or(0);
    let eligible = data.get("eligible").and_then(Value::as_u64).unwrap_or(0);
    let total = data.get("total").and_then(Value::as_u64).unwrap_or(0);
    let count = data.get("count").and_then(Value::as_u64).unwrap_or(0);
    let offset = data.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let err_cnt = data
        .get("errors_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let report_file = data
        .get("report_file")
        .and_then(Value::as_str)
        .unwrap_or("");

    let mut lines = vec![
        format!("# 内容搜索结果 · `{query}` ({enc})"),
        format!("- 状态：{status} · 范围：{scope} · 十六进制模式：`{needle}`"),
        format!("- 校验方式：{ver}"),
        format!(
            "- 扫描文件：{visited} / {eligible} · 命中总数：{total}（当前显示 {count}，offset={offset}） · 读取失败：{err_cnt}"
        ),
        format!("- 完整搜索记录：`{report_file}`"),
        String::new(),
    ];

    let items = data
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if items.is_empty() {
        lines.push("未命中任何内容。".to_string());
    } else {
        for (i, hit) in items.iter().enumerate() {
            let idx = offset + (i as u64) + 1;
            let del = hit
                .get("deleted")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let st = if del { "已删除" } else { "现存" };
            let path = hit.get("path").and_then(Value::as_str).unwrap_or("");
            let off = hit.get("offset").and_then(Value::as_u64).unwrap_or(0);
            let ino = hit.get("inode").and_then(Value::as_str).unwrap_or("");
            let fb = hit.get("file_byte").and_then(Value::as_u64).unwrap_or(0);
            let before = hit.get("before").and_then(Value::as_str).unwrap_or("");
            let after = hit.get("after").and_then(Value::as_str).unwrap_or("");
            lines.push(format!(
                "{idx}. `{path}`（偏移 `{off}` / inode `{ino}` / {st}）· 文件内字节偏移 **{fb}** · 上下文 `{before} | {needle} | {after}`"
            ));
        }
    }
    if data
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && let Some(next_off) = data.get("next_offset").and_then(Value::as_u64)
    {
        lines.push(format!(
            "\n> 还有更多命中，请使用 `offset={next_off}` 继续翻页。"
        ));
    }
    lines.join("\n")
}

pub fn render_findings_md(data: &Value) -> String {
    let total = data.get("total").and_then(Value::as_u64).unwrap_or(0);
    let count = data.get("count").and_then(Value::as_u64).unwrap_or(0);
    let offset = data.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let mut lines = vec![
        "# 取证发现".to_string(),
        format!("- 归组文件数：{total} · 当前返回：{count}（offset={offset}）"),
        String::new(),
    ];
    let items = data
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if items.is_empty() {
        lines.push("当前尚无符合条件的取证发现。".to_string());
        return lines.join("\n");
    }
    for group in items {
        let path = group.get("path").and_then(Value::as_str).unwrap_or("");
        let off = group
            .get("partition_offset")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let ino = group.get("inode").and_then(Value::as_str).unwrap_or("");
        let st = group.get("status").and_then(Value::as_str).unwrap_or("");
        let img_sha = group
            .get("image_sha256")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("记录时待固定");
        lines.push(format!("## `{path}`（偏移 `{off}` · inode `{ino}` · {st}）"));
        lines.push(format!("- 来源镜像 SHA-256：`{img_sha}`"));
        if let Some(records) = group.get("records").and_then(Value::as_array) {
            for r in records {
                let seq = r.get("seq").and_then(Value::as_u64).unwrap_or(0);
                let ts = r.get("timestamp").and_then(Value::as_str).unwrap_or("");
                let ol = r.get("origin_label").and_then(Value::as_str).unwrap_or("");
                let actor = r.get("actor").and_then(Value::as_str).unwrap_or("");
                let op = r.get("operation").and_then(Value::as_str).unwrap_or("");
                let res = r.get("result").and_then(Value::as_str).unwrap_or("");
                let d = r.get("details");
                let note = d
                    .and_then(|m| m.get("note"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(|n| format!(" · 笔记：{n}"))
                    .unwrap_or_default();
                let digest = d
                    .and_then(|m| m.get("sha256"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(|s| format!(" · SHA-256：`{s}`"))
                    .unwrap_or_default();
                lines.push(format!(
                    "  - `#{seq}` {ts} · [{ol}] · {actor} · {op} · **{res}**{note}{digest}"
                ));
            }
        }
        lines.push(String::new());
    }
    if data
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && let Some(next_off) = data.get("next_offset").and_then(Value::as_u64)
    {
        lines.push(format!(
            "> 还有更多发现，请使用 `offset={next_off}` 继续翻页。"
        ));
    }
    lines.join("\n")
}

pub fn render_timeline_md(data: &Value) -> String {
    let total = data.get("total").and_then(Value::as_u64).unwrap_or(0);
    let count = data.get("count").and_then(Value::as_u64).unwrap_or(0);
    let offset = data.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let sort_order = data
        .get("sort_order")
        .and_then(Value::as_str)
        .unwrap_or("asc");
    let mut lines = vec![
        "# MACB 时间线（UTC+8）".to_string(),
        format!(
            "- 匹配事件总数：{total} · 当前返回：{count}（offset={offset}，排序：{sort_order}）"
        ),
        String::new(),
    ];
    let items = data
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if items.is_empty() {
        lines.push("未匹配到时间线事件。".to_string());
        return lines.join("\n");
    }
    lines.push("| 时间（UTC+8） | 事件 | 路径 | 状态 | 分区偏移 | inode |".to_string());
    lines.push("| --- | --- | --- | --- | ---: | --- |".to_string());
    for item in items {
        let time = item.get("time").and_then(Value::as_str).unwrap_or("");
        let ev = item.get("event").and_then(Value::as_str).unwrap_or("");
        let path = item
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .replace('|', "\\|");
        let st = item.get("status").and_then(Value::as_str).unwrap_or("");
        let off = item.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let ino = item.get("inode").and_then(Value::as_str).unwrap_or("");
        lines.push(format!(
            "| {time} | {ev} | `{path}` | {st} | {off} | `{ino}` |"
        ));
    }
    if data
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && let Some(next_off) = data.get("next_offset").and_then(Value::as_u64)
    {
        lines.push(format!(
            "\n> 还有更多事件，请使用 `offset={next_off}` 继续翻页。"
        ));
    }
    lines.join("\n")
}

pub fn render_audit_md(data: &Value) -> String {
    let audit_head = data
        .get("audit_head")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("无");
    let manual = data
        .get("origin_counts")
        .and_then(|c| c.get("manual"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mcp = data
        .get("origin_counts")
        .and_then(|c| c.get("mcp"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total = data.get("total").and_then(Value::as_u64).unwrap_or(0);
    let count = data.get("count").and_then(Value::as_u64).unwrap_or(0);
    let offset = data.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let sort_order = data
        .get("sort_order")
        .and_then(Value::as_str)
        .unwrap_or("desc");

    let mut lines = vec![
        "# 审计日志（哈希链核验通过）".to_string(),
        format!("- 尾部锚点：`{audit_head}`"),
        format!("- 来源统计：人工 {manual} 条 · MCP {mcp} 条"),
        format!("- 匹配总数：{total} · 当前返回：{count}（offset={offset}，排序：{sort_order}）"),
        String::new(),
    ];
    let items = data
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if items.is_empty() {
        lines.push("未匹配到审计记录。".to_string());
        return lines.join("\n");
    }
    for r in items {
        let seq = r.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let ts = r.get("timestamp").and_then(Value::as_str).unwrap_or("");
        let ol = r.get("origin_label").and_then(Value::as_str).unwrap_or("");
        let title = r.get("action_title").and_then(Value::as_str).unwrap_or("");
        let action = r.get("action").and_then(Value::as_str).unwrap_or("");
        let actor = r.get("actor").and_then(Value::as_str).unwrap_or("");
        let res = r.get("result").and_then(Value::as_str).unwrap_or("");
        let subj = r.get("subject").and_then(Value::as_str).unwrap_or("");
        lines.push(format!(
            "- `#{seq}` {ts} · **[{ol}]** · **{title}** (`{action}`) · {actor} · {res} · 对象：`{subj}`"
        ));
    }
    if data
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && let Some(next_off) = data.get("next_offset").and_then(Value::as_u64)
    {
        lines.push(format!(
            "\n> 还有更多日志，请使用 `offset={next_off}` 继续翻页。"
        ));
    }
    lines.join("\n")
}

pub fn render_simple_kv_md(title: &str, data: &Value) -> String {
    let mut lines = vec![format!("# {title}")];
    if let Some(obj) = data.as_object() {
        for (key, value) in obj {
            match value {
                Value::Object(_) | Value::Array(_) => {
                    lines.push(format!(
                        "- **{key}**：\n```json\n{}\n```",
                        to_pretty_json(value)
                    ));
                }
                Value::String(s) if s.is_empty() => {
                    lines.push(format!("- **{key}**：（空）"));
                }
                Value::String(s) => {
                    lines.push(format!("- **{key}**：`{s}`"));
                }
                Value::Null => {
                    lines.push(format!("- **{key}**：`None`"));
                }
                other => {
                    lines.push(format!("- **{key}**：`{other}`"));
                }
            }
        }
    }
    lines.join("\n")
}

/* -------------------- MCP Protocol Definition Types -------------------- */

/// MCP 工具注解（`ToolAnnotations`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolAnnotations {
    pub title: String,
    pub read_only_hint: bool,
    pub destructive_hint: bool,
    pub idempotent_hint: bool,
    pub open_world_hint: bool,
}

/// MCP `tools/list` 单个工具定义。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub annotations: McpToolAnnotations,
}

/// MCP `resources/list` 单个资源定义。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResourceDefinition {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: String,
}

/// MCP `resources/read` 内容项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResourceContent {
    pub uri: String,
    pub mime_type: String,
    pub text: String,
}

/// MCP `tools/call` 返回结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolCallOutput {
    pub content: Vec<McpTextContent>,
    pub is_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpTextContent {
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
}

impl McpToolCallOutput {
    pub fn ok(text: String) -> Self {
        Self {
            content: vec![McpTextContent {
                kind: "text".to_string(),
                text,
            }],
            is_error: false,
        }
    }

    pub fn err(err: &McpError) -> Self {
        Self {
            content: vec![McpTextContent {
                kind: "text".to_string(),
                text: err.format_error(),
            }],
            is_error: true,
        }
    }

    pub fn text(&self) -> &str {
        self.content
            .first()
            .map(|c| c.text.as_str())
            .unwrap_or("")
    }
}

fn build_tool_definitions() -> Vec<McpToolDefinition> {
    let case_base_props = || {
        json!({
            "case_dir": {
                "type": "string",
                "minLength": 1,
                "description": "案件目录路径（绝对路径、相对案件库文件夹名，或 case.json 路径）"
            },
            "actor": {
                "type": ["string", "null"],
                "maxLength": 80,
                "default": null,
                "description": "可选操作人员标识，写入审计日志；无论是否指定，MCP 调用均在审计链中固定标记为 MCP 来源"
            },
            "response_format": {
                "type": "string",
                "enum": ["markdown", "json"],
                "default": "markdown",
                "description": "输出格式：markdown 或 json"
            }
        })
    };

    let entry_locator_props = || {
        let mut map = case_base_props().as_object().cloned().unwrap();
        let extra = json!({
            "path": {
                "type": "string",
                "minLength": 1,
                "description": "镜像内文件路径，例如 DOCS/CASE.TXT 或 README.TXT"
            },
            "partition_offset": {
                "type": ["integer", "null"],
                "minimum": 0,
                "default": null,
                "description": "可选分区起始扇区偏移，用于区分跨分区同名文件"
            },
            "inode": {
                "type": ["string", "null"],
                "maxLength": 64,
                "default": null,
                "description": "可选 inode 标识，用于区分同路径多条记录"
            },
            "deleted": {
                "type": ["boolean", "null"],
                "default": null,
                "description": "可选删除标记（true=已删除，false=现存）"
            },
            "dir_inode": {
                "type": ["string", "null"],
                "maxLength": 64,
                "default": null,
                "description": "仅大容量镜像快速浏览模式需要：所在目录 inode"
            },
            "dir_path": {
                "type": "string",
                "default": "",
                "description": "仅大容量镜像快速浏览模式需要：所在目录路径"
            }
        });
        for (k, v) in extra.as_object().unwrap() {
            map.insert(k.clone(), v.clone());
        }
        Value::Object(map)
    };

    let merge_props = |base: Value, extra: Value| -> Value {
        let mut map = base.as_object().cloned().unwrap();
        for (k, v) in extra.as_object().unwrap() {
            map.insert(k.clone(), v.clone());
        }
        Value::Object(map)
    };

    let def = |name: &str,
               title: &str,
               read_only: bool,
               idempotent: bool,
               description: &str,
               properties: Value,
               required: &[&str]|
     -> McpToolDefinition {
        McpToolDefinition {
            name: name.to_string(),
            description: description.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": false
            }),
            annotations: McpToolAnnotations {
                title: title.to_string(),
                read_only_hint: read_only,
                destructive_hint: false,
                idempotent_hint: idempotent,
                open_world_hint: false,
            },
        }
    };

    vec![
        def(
            "tracedesk_list_cases",
            "列出 TraceDesk 案件",
            true,
            true,
            "列出案件库目录中的所有 TraceDesk 案件及其摘要状态（只读，不加锁）。",
            json!({
                "cases_root": { "type": ["string", "null"], "default": null, "description": "可选案件库目录路径，省略时使用默认 cases 目录" },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 20, "description": "每页最多返回案件数（1-200）" },
                "offset": { "type": "integer", "minimum": 0, "default": 0, "description": "分页偏移量" },
                "response_format": { "type": "string", "enum": ["markdown", "json"], "default": "markdown", "description": "输出格式：markdown 或 json" }
            }),
            &[],
        ),
        def(
            "tracedesk_create_case",
            "新建取证案件",
            false,
            false,
            "创建新的隔离取证案件目录、元数据文件与初始审计链。",
            json!({
                "number": { "type": "string", "minLength": 1, "maxLength": 120, "description": "案件编号，例如 CASE-2026-01" },
                "examiner": { "type": "string", "minLength": 1, "maxLength": 80, "description": "取证人员姓名或工号" },
                "target": { "type": "string", "minLength": 1, "maxLength": 200, "description": "取证对象说明，例如 FAT16 演示镜像" },
                "cases_root": { "type": ["string", "null"], "default": null, "description": "可选案件库根目录，省略时使用项目默认 cases 目录" },
                "folder_name": { "type": ["string", "null"], "maxLength": 180, "default": null, "description": "可选自定义案件目录名，省略时自动按“编号-人员-对象”生成" },
                "actor": { "type": ["string", "null"], "maxLength": 80, "default": null, "description": "可选操作人员标识（默认使用取证人员，审计来源固定标记为 MCP）" },
                "response_format": { "type": "string", "enum": ["markdown", "json"], "default": "markdown", "description": "输出格式：markdown 或 json" }
            }),
            &["number", "examiner", "target"],
        ),
        def(
            "tracedesk_get_case_summary",
            "获取案件总览",
            true,
            true,
            "读取案件元数据、镜像哈希与覆盖范围、分区扫描状态以及审计链完整性结论。",
            case_base_props(),
            &["case_dir"],
        ),
        def(
            "tracedesk_load_image",
            "加载取证镜像",
            false,
            false,
            "以只读模式载入 RAW 或分段 EWF（.E01 首段）镜像，识别分区并固定 SHA-256。",
            merge_props(
                case_base_props(),
                json!({
                    "image_path": { "type": "string", "minLength": 1, "description": "源镜像路径（RAW 镜像或分段 EWF 的 .E01 首段），必须位于案件库目录之外" },
                    "scan_all": { "type": "boolean", "default": true, "description": "小于 1 GiB 的镜像是否在载入后自动扫描全部分区文件树（默认 true）" }
                }),
            ),
            &["case_dir", "image_path"],
        ),
        def(
            "tracedesk_verify_integrity",
            "校验镜像完整性",
            false,
            true,
            "重新计算源镜像（或全部 EWF 分段）的 SHA-256，与初始固定基线比对并记录审计日志。",
            case_base_props(),
            &["case_dir"],
        ),
        def(
            "tracedesk_register_source",
            "登记证据来源",
            false,
            true,
            "登记证据编号、来源、采集时间、采集工具和交付方 SHA-256，并与本机固定值比对。",
            merge_props(
                case_base_props(),
                json!({
                    "evidence_id": { "type": "string", "maxLength": 120, "default": "", "description": "证据编号" },
                    "source": { "type": "string", "maxLength": 200, "default": "", "description": "来源 / 交付方" },
                    "acquired": { "type": "string", "maxLength": 120, "default": "", "description": "采集时间与时区" },
                    "tool": { "type": "string", "maxLength": 160, "default": "", "description": "采集工具与版本" },
                    "expected_sha256": { "type": "string", "maxLength": 64, "default": "", "description": "交付方提供的 64 位十六进制 SHA-256（可选）" }
                }),
            ),
            &["case_dir"],
        ),
        def(
            "tracedesk_scan_partitions",
            "扫描分区文件清单",
            false,
            true,
            "扫描全部分区或单个指定扇区偏移的分区，建立或更新完整文件清单。",
            merge_props(
                case_base_props(),
                json!({
                    "partition_offset": { "type": ["integer", "null"], "minimum": 0, "default": null, "description": "指定要扫描的单个分区扇区偏移；省略时扫描全部已识别分区" },
                    "verify_large_image": { "type": "boolean", "default": false, "description": "大容量镜像（>=1 GiB）已固定基线时，是否在扫描前先执行整镜像复算校验" }
                }),
            ),
            &["case_dir"],
        ),
        def(
            "tracedesk_list_files",
            "浏览与筛选文件清单",
            true,
            true,
            "分页浏览和筛选案件中的镜像文件清单，支持按分区偏移、路径前缀、后缀、关键词和状态过滤。",
            merge_props(
                case_base_props(),
                json!({
                    "partition_offset": { "type": ["integer", "null"], "minimum": 0, "default": null, "description": "按分区起始扇区偏移筛选" },
                    "path_prefix": { "type": "string", "default": "", "description": "按路径前缀筛选，例如 DOCS" },
                    "suffix": { "type": "string", "maxLength": 32, "default": "", "description": "按扩展名筛选，例如 .txt 或 txt" },
                    "keyword": { "type": "string", "maxLength": 120, "default": "", "description": "按路径或文件名关键词筛选（不区分大小写）" },
                    "status": { "type": "string", "enum": ["all", "active", "deleted", "system"], "default": "all", "description": "状态筛选：all / active / deleted / system" },
                    "files_only": { "type": "boolean", "default": false, "description": "仅返回文件，排除目录项" },
                    "dir_inode": { "type": ["string", "null"], "maxLength": 64, "default": null, "description": "仅大容量镜像快速浏览模式有效：要浏览的目录 inode" },
                    "dir_path": { "type": "string", "default": "", "description": "仅大容量镜像快速浏览模式有效：要浏览的目录路径" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50, "description": "每页返回条目数（1-200）" },
                    "offset": { "type": "integer", "minimum": 0, "default": 0, "description": "分页偏移量" }
                }),
            ),
            &["case_dir"],
        ),
        def(
            "tracedesk_preview_file",
            "预览文件内容",
            true,
            true,
            "按页读取镜像内文件（现存、已删除或 FAT 系统区域）的文本解码和/或十六进制转储。",
            merge_props(
                entry_locator_props(),
                json!({
                    "page": { "type": "integer", "minimum": 0, "default": 0, "description": "页码（从 0 开始）" },
                    "page_bytes": { "type": "integer", "minimum": 64, "maximum": 16384, "default": 4096, "description": "每页读取字节数（64-16384，默认 4096）" },
                    "encoding": { "type": "string", "default": "UTF-8", "description": format!("文本解码编码，可选：{}", PREVIEW_ENCODINGS.join(", ")) },
                    "mode": { "type": "string", "enum": ["text", "hex", "both"], "default": "both", "description": "返回内容模式：text / hex / both" }
                }),
            ),
            &["case_dir", "path"],
        ),
        def(
            "tracedesk_search_content",
            "搜索文件内容",
            false,
            true,
            "按精确字节（UTF-8 / UTF-16LE / GBK / HEX）搜索全案可读文件或单个文件，并生成 search_*.json 审计记录。",
            merge_props(
                case_base_props(),
                json!({
                    "query": { "type": "string", "minLength": 1, "maxLength": 4096, "description": "要检索的文本或 HEX 字节串（如 \"6E 6F 74 65\"）" },
                    "encoding": { "type": "string", "enum": ["UTF-8", "UTF-16LE", "GBK", "HEX"], "default": "UTF-8", "description": "检索编码：UTF-8 / UTF-16LE / GBK / HEX" },
                    "path": { "type": ["string", "null"], "default": null, "description": "可选单文件路径；指定时仅搜索该文件，省略时搜索全部可读取清单" },
                    "partition_offset": { "type": ["integer", "null"], "minimum": 0, "default": null, "description": "配合 path 使用：指定分区起始扇区偏移" },
                    "inode": { "type": ["string", "null"], "maxLength": 64, "default": null, "description": "配合 path 使用：指定 inode" },
                    "deleted": { "type": ["boolean", "null"], "default": null, "description": "配合 path 使用：指定删除标记" },
                    "dir_inode": { "type": ["string", "null"], "maxLength": 64, "default": null, "description": "仅大容量镜像单文件搜索需要：所在目录 inode" },
                    "dir_path": { "type": "string", "default": "", "description": "仅大容量镜像单文件搜索需要：所在目录路径" },
                    "max_hits": { "type": "integer", "minimum": 1, "maximum": 5000, "default": 200, "description": "单次搜索最多收集命中条数（1-5000）" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50, "description": "本次响应最多返回命中条数（1-200）" },
                    "offset": { "type": "integer", "minimum": 0, "default": 0, "description": "命中列表分页偏移量" },
                    "verify_large_image": { "type": "boolean", "default": false, "description": "大容量镜像已固定基线时，是否在搜索前执行整镜像校验" }
                }),
            ),
            &["case_dir", "query"],
        ),
        def(
            "tracedesk_examine_file",
            "计算文件哈希或比对副本",
            false,
            true,
            "从只读镜像计算指定文件的 SHA-256，或与本地对照文件核验一致性并记入取证发现与审计链。",
            merge_props(
                entry_locator_props(),
                json!({
                    "comparison_path": { "type": ["string", "null"], "default": null, "description": "可选本地对照文件路径；省略时仅计算镜像文件 SHA-256，提供时进行一致性比对" },
                    "verify_large_image": { "type": "boolean", "default": false, "description": "大容量镜像已固定基线时，是否在操作前执行整镜像校验" }
                }),
            ),
            &["case_dir", "path"],
        ),
        def(
            "tracedesk_record_finding",
            "记录取证发现",
            false,
            false,
            "为镜像内指定文件记录结构化取证发现笔记，绑定来源镜像 SHA-256、分区偏移与 inode。",
            merge_props(
                entry_locator_props(),
                json!({
                    "note": { "type": "string", "minLength": 1, "maxLength": 4000, "description": "取证发现说明与依据，将写入案件审计链并纳入报告" },
                    "verify_large_image": { "type": "boolean", "default": false, "description": "大容量镜像已固定基线时，是否在操作前执行整镜像校验" }
                }),
            ),
            &["case_dir", "path", "note"],
        ),
        def(
            "tracedesk_list_findings",
            "查询取证发现",
            true,
            true,
            "按文件归组列出案件中的取证笔记、文件哈希计算与副本比对记录。",
            merge_props(
                case_base_props(),
                json!({
                    "status": { "type": "string", "enum": ["all", "active", "deleted"], "default": "all", "description": "状态筛选：all / active / deleted" },
                    "partition_offset": { "type": ["integer", "null"], "minimum": 0, "default": null, "description": "按分区起始扇区偏移筛选" },
                    "keyword": { "type": "string", "maxLength": 120, "default": "", "description": "按路径、inode、笔记或哈希关键词筛选" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50, "description": "每页返回归组文件数（1-200）" },
                    "offset": { "type": "integer", "minimum": 0, "default": 0, "description": "分页偏移量" }
                }),
            ),
            &["case_dir"],
        ),
        def(
            "tracedesk_query_timeline",
            "查询 MACB 时间线",
            true,
            true,
            "分页查询案件的 MACB 时间线（UTC+8），支持按事件类型、状态、分区偏移和关键词筛选。",
            merge_props(
                case_base_props(),
                json!({
                    "event": { "type": ["string", "null"], "default": null, "description": "事件类型筛选：M / A / C / B，或完整中文名（如 \"M 内容修改\"）" },
                    "status": { "type": ["string", "null"], "default": null, "description": "文件状态筛选，例如 现存 / 已删除 / 系统区域" },
                    "partition_offset": { "type": ["integer", "null"], "minimum": 0, "default": null, "description": "按分区起始扇区偏移筛选" },
                    "query": { "type": "string", "maxLength": 120, "default": "", "description": "按路径、时间、inode 或状态关键词筛选" },
                    "sort_order": { "type": "string", "enum": ["asc", "desc"], "default": "asc", "description": "时间排序方向：asc（正序）或 desc（倒序）" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50, "description": "每页返回事件数（1-200）" },
                    "offset": { "type": "integer", "minimum": 0, "default": 0, "description": "分页偏移量" }
                }),
            ),
            &["case_dir"],
        ),
        def(
            "tracedesk_query_audit_log",
            "核验并查询审计日志",
            true,
            true,
            "核验审计哈希链及尾部锚点，并按来源（人工/MCP）、操作、操作人员、结果和关键词分页检索审计日志。",
            merge_props(
                case_base_props(),
                json!({
                    "origin": { "type": "string", "enum": ["all", "manual", "mcp"], "default": "all", "description": "按操作来源筛选：all（全部）/ manual（人工）/ mcp（MCP）" },
                    "action": { "type": ["string", "null"], "default": null, "description": "按操作代码或中文名称筛选，例如 FILE_EXPORT 或 导出文件" },
                    "actor_filter": { "type": ["string", "null"], "default": null, "description": "按操作人员关键词筛选" },
                    "result": { "type": ["string", "null"], "default": null, "description": "按结果筛选，例如 成功 / 失败 / 通过" },
                    "query": { "type": "string", "maxLength": 120, "default": "", "description": "按对象、详情或哈希关键词筛选" },
                    "sort_order": { "type": "string", "enum": ["asc", "desc"], "default": "desc", "description": "排序方向：desc（最新在前）或 asc（最早在前）" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50, "description": "每页返回日志条数（1-200）" },
                    "offset": { "type": "integer", "minimum": 0, "default": 0, "description": "分页偏移量" }
                }),
            ),
            &["case_dir"],
        ),
        def(
            "tracedesk_export_file",
            "导出镜像文件副本",
            false,
            false,
            "导出镜像内现存或已删除文件到案件 exports 目录，前后校验原镜像并记录副本 SHA-256。",
            merge_props(
                entry_locator_props(),
                json!({
                    "verify_large_image": { "type": "boolean", "default": false, "description": "大容量镜像已固定基线时，是否在导出前执行整镜像校验" }
                }),
            ),
            &["case_dir", "path"],
        ),
        def(
            "tracedesk_export_findings",
            "一键导出取证发现",
            false,
            false,
            "批量导出取证发现涉及的镜像文件副本，并在 exports 目录生成 Markdown 汇总清单。",
            merge_props(
                case_base_props(),
                json!({
                    "status": { "type": "string", "enum": ["all", "active", "deleted"], "default": "all", "description": "仅导出指定状态的发现：all / active / deleted" },
                    "partition_offset": { "type": ["integer", "null"], "minimum": 0, "default": null, "description": "仅导出指定分区偏移的发现" },
                    "keyword": { "type": "string", "maxLength": 120, "default": "", "description": "仅导出匹配关键词的发现" },
                    "verify_large_image": { "type": "boolean", "default": false, "description": "大容量镜像已固定基线时，是否在导出前执行整镜像校验" }
                }),
            ),
            &["case_dir"],
        ),
        def(
            "tracedesk_generate_report",
            "生成 Markdown 取证报告",
            false,
            false,
            "执行完整性校验并在案件 reports 目录生成分节 Markdown 取证报告。",
            merge_props(
                case_base_props(),
                json!({
                    "verify_large_image": { "type": "boolean", "default": false, "description": "大容量镜像在生成正式报告或复核包前需要本次会话校验，设为 true 可自动复算" }
                }),
            ),
            &["case_dir"],
        ),
        def(
            "tracedesk_build_review_bundle",
            "构建可核验复核包",
            false,
            false,
            "构建包含报告、导出副本、搜索记录、审计链、SHA256SUMS 与核验脚本的复核包 ZIP；支持按序号选择副本或跳过缺失项。",
            merge_props(
                case_base_props(),
                json!({
                    "selected_export_indices": {
                        "type": ["array", "null"],
                        "items": { "type": "integer", "minimum": 1 },
                        "default": null,
                        "description": "可选要纳入复核包的导出记录序号列表（从 1 开始）；省略时默认纳入全部历史导出"
                    },
                    "selected_search_indices": {
                        "type": ["array", "null"],
                        "items": { "type": "integer", "minimum": 1 },
                        "default": null,
                        "description": "可选要纳入复核包的内容搜索记录序号列表（从 1 开始）；省略时默认纳入全部历史搜索记录"
                    },
                    "skip_missing_exports": {
                        "type": "boolean",
                        "default": false,
                        "description": "本地 exports/reports 目录中存在缺失副本或搜索记录时，是否自动跳过缺失项并在 manifest.json 中标注（默认 false）"
                    },
                    "verify_large_image": {
                        "type": "boolean",
                        "default": false,
                        "description": "大容量镜像在生成正式报告或复核包前需要本次会话校验，设为 true 可自动复算"
                    }
                }),
            ),
            &["case_dir"],
        ),
    ]
}

fn build_resource_definitions() -> Vec<McpResourceDefinition> {
    vec![
        McpResourceDefinition {
            uri: "tracedesk://cases".to_string(),
            name: "cases_list".to_string(),
            description: "默认案件库中的 TraceDesk 案件清单（JSON）".to_string(),
            mime_type: "application/json".to_string(),
        },
        McpResourceDefinition {
            uri: "tracedesk://guide/workflow".to_string(),
            name: "forensic_workflow".to_string(),
            description: "TraceDesk 标准电子数据取证流程与证据边界说明".to_string(),
            mime_type: "text/markdown".to_string(),
        },
    ]
}

/// TraceDesk MCP 核心协议服务实例（同时供 `stdio`、`streamable-http`、桌面端与集成测试调用）。
#[derive(Clone)]
pub struct McpServer {
    service: Arc<CaseService>,
    tools: Arc<Vec<McpToolDefinition>>,
    resources: Arc<Vec<McpResourceDefinition>>,
}

impl McpServer {
    /// 构建绑定到指定案件库目录与默认操作人的 [`McpServer`]。
    pub fn new(cases_root: Option<PathBuf>, default_actor: Option<String>) -> Self {
        Self::with_service(Arc::new(CaseService::new(cases_root, default_actor)))
    }

    pub fn with_service(service: Arc<CaseService>) -> Self {
        Self {
            service,
            tools: Arc::new(build_tool_definitions()),
            resources: Arc::new(build_resource_definitions()),
        }
    }

    pub fn service(&self) -> &Arc<CaseService> {
        &self.service
    }

    /// 返回全部 19 个 MCP 工具定义。
    pub fn list_tools(&self) -> Vec<McpToolDefinition> {
        (*self.tools).clone()
    }

    /// 返回全部 2 个 MCP 资源定义。
    pub fn list_resources(&self) -> Vec<McpResourceDefinition> {
        (*self.resources).clone()
    }

    /// 读取指定 URI 的 MCP 资源。
    pub fn read_resource(&self, uri: &str) -> McpResult<McpResourceContent> {
        match uri.trim() {
            "tracedesk://cases" => {
                let data = self.service.list_cases(None, 200, 0)?;
                Ok(McpResourceContent {
                    uri: "tracedesk://cases".to_string(),
                    mime_type: "application/json".to_string(),
                    text: to_pretty_json(&data),
                })
            }
            "tracedesk://guide/workflow" => Ok(McpResourceContent {
                uri: "tracedesk://guide/workflow".to_string(),
                mime_type: "text/markdown".to_string(),
                text: WORKFLOW_GUIDE_MARKDOWN.to_string(),
            }),
            other => Err(McpError::ValueError(format!("未知的 MCP 资源 URI：{other}"))),
        }
    }

    /// 执行指定名称的 MCP 工具并返回结构化 [`McpToolCallOutput`]。
    pub fn call_tool(&self, name: &str, arguments: Value) -> McpToolCallOutput {
        match self.dispatch_tool(name, arguments) {
            Ok(text) => McpToolCallOutput::ok(text),
            Err(err) => McpToolCallOutput::err(&err),
        }
    }

    /// 执行指定名称的 MCP 工具并直接返回文本（成功时为 Markdown/JSON，失败时为 `Error (<Kind>): ...`）。
    pub fn call_tool_text(&self, name: &str, arguments: Value) -> String {
        self.call_tool(name, arguments).text().to_string()
    }

    fn dispatch_tool(&self, name: &str, arguments: Value) -> McpResult<String> {
        match name {
            "tracedesk_list_cases" => {
                let params: ListCasesInput = parse_input(arguments)?;
                let limit = check_range(params.limit, "limit", 1, 200)?;
                let cases_root = check_optional_str(&params.cases_root, "cases_root", None)?;
                let data = self
                    .service
                    .list_cases(cases_root.as_deref(), limit, params.offset)?;
                Ok(format_output(&data, params.response_format, render_cases_md))
            }
            "tracedesk_create_case" => {
                let params: CreateCaseInput = parse_input(arguments)?;
                let number = check_non_empty(&params.number, "number", Some(120))?;
                let examiner = check_non_empty(&params.examiner, "examiner", Some(80))?;
                let target = check_non_empty(&params.target, "target", Some(200))?;
                let cases_root = check_optional_str(&params.cases_root, "cases_root", None)?;
                let folder_name =
                    check_optional_str(&params.folder_name, "folder_name", Some(180))?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.create_case(
                    &number,
                    &examiner,
                    &target,
                    cases_root.as_deref(),
                    folder_name.as_deref(),
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("已创建新案件", d)
                }))
            }
            "tracedesk_get_case_summary" => {
                let params: CaseBaseInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.get_case_summary(&case_dir, actor.as_deref())?;
                Ok(format_output(
                    &data,
                    params.response_format,
                    render_summary_md,
                ))
            }
            "tracedesk_load_image" => {
                let params: LoadImageInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let image_path = check_non_empty(&params.image_path, "image_path", None)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.load_image(
                    &case_dir,
                    &image_path,
                    params.scan_all,
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("镜像已载入", d)
                }))
            }
            "tracedesk_verify_integrity" => {
                let params: CaseBaseInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.verify_integrity(&case_dir, actor.as_deref())?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("完整性校验结果", d)
                }))
            }
            "tracedesk_register_source" => {
                let params: RegisterSourceInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let evidence_id = check_bounded_str(&params.evidence_id, "evidence_id", 120)?;
                let source = check_bounded_str(&params.source, "source", 200)?;
                let acquired = check_bounded_str(&params.acquired, "acquired", 120)?;
                let tool = check_bounded_str(&params.tool, "tool", 160)?;
                let expected_sha256 =
                    check_bounded_str(&params.expected_sha256, "expected_sha256", 64)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.register_source(
                    &case_dir,
                    &evidence_id,
                    &source,
                    &acquired,
                    &tool,
                    &expected_sha256,
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("证据来源已登记", d)
                }))
            }
            "tracedesk_scan_partitions" => {
                let params: ScanPartitionsInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.scan_partitions(
                    &case_dir,
                    params.partition_offset,
                    params.verify_large_image,
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("分区扫描完成", d)
                }))
            }
            "tracedesk_list_files" => {
                let params: ListFilesInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let suffix = check_bounded_str(&params.suffix, "suffix", 32)?;
                let keyword = check_bounded_str(&params.keyword, "keyword", 120)?;
                let status = params.status.trim().to_lowercase();
                if !matches!(status.as_str(), "all" | "active" | "deleted" | "system") {
                    return Err(McpError::ValueError(format!(
                        "无效的文件状态筛选：{}（可选：all / active / deleted / system）",
                        params.status
                    )));
                }
                let dir_inode = check_optional_str(&params.dir_inode, "dir_inode", Some(64))?;
                let limit = check_range(params.limit, "limit", 1, 200)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.list_files(
                    &case_dir,
                    params.partition_offset,
                    params.path_prefix.trim(),
                    &suffix,
                    &keyword,
                    &status,
                    params.files_only,
                    dir_inode.as_deref(),
                    params.dir_path.trim(),
                    limit,
                    params.offset,
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, render_files_md))
            }
            "tracedesk_preview_file" => {
                let params: PreviewFileInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let path = check_non_empty(&params.path, "path", None)?;
                let inode = check_optional_str(&params.inode, "inode", Some(64))?;
                let dir_inode = check_optional_str(&params.dir_inode, "dir_inode", Some(64))?;
                let page_bytes = check_range(params.page_bytes, "page_bytes", 64, 16384)?;
                let mode = params.mode.trim().to_lowercase();
                if !matches!(mode.as_str(), "text" | "hex" | "both") {
                    return Err(McpError::ValueError(format!(
                        "无效的预览模式：{}（可选：text / hex / both）",
                        params.mode
                    )));
                }
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.preview_file(
                    &case_dir,
                    &path,
                    params.partition_offset,
                    inode.as_deref(),
                    params.deleted,
                    dir_inode.as_deref(),
                    params.dir_path.trim(),
                    params.page,
                    page_bytes,
                    params.encoding.trim(),
                    &mode,
                    actor.as_deref(),
                )?;
                Ok(format_output(
                    &data,
                    params.response_format,
                    render_preview_md,
                ))
            }
            "tracedesk_search_content" => {
                let params: SearchContentInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let query = check_non_empty(&params.query, "query", Some(4096))?;
                let encoding = params.encoding.trim();
                if !matches!(encoding, "UTF-8" | "UTF-16LE" | "GBK" | "HEX") {
                    return Err(McpError::ValueError(format!(
                        "不支持的内容搜索编码：{encoding}（支持 UTF-8 / UTF-16LE / GBK / HEX）"
                    )));
                }
                let path = check_optional_str(&params.path, "path", None)?;
                let inode = check_optional_str(&params.inode, "inode", Some(64))?;
                let dir_inode = check_optional_str(&params.dir_inode, "dir_inode", Some(64))?;
                let max_hits = check_range(params.max_hits, "max_hits", 1, 5000)?;
                let limit = check_range(params.limit, "limit", 1, 200)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.search_content(
                    &case_dir,
                    &query,
                    encoding,
                    path.as_deref(),
                    params.partition_offset,
                    inode.as_deref(),
                    params.deleted,
                    dir_inode.as_deref(),
                    params.dir_path.trim(),
                    max_hits,
                    limit,
                    params.offset,
                    params.verify_large_image,
                    actor.as_deref(),
                )?;
                Ok(format_output(
                    &data,
                    params.response_format,
                    render_search_md,
                ))
            }
            "tracedesk_examine_file" => {
                let params: ExamineFileInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let path = check_non_empty(&params.path, "path", None)?;
                let inode = check_optional_str(&params.inode, "inode", Some(64))?;
                let dir_inode = check_optional_str(&params.dir_inode, "dir_inode", Some(64))?;
                let cmp = check_optional_str(&params.comparison_path, "comparison_path", None)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.examine_file(
                    &case_dir,
                    &path,
                    params.partition_offset,
                    inode.as_deref(),
                    params.deleted,
                    dir_inode.as_deref(),
                    params.dir_path.trim(),
                    cmp.as_deref(),
                    params.verify_large_image,
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("文件核验结果", d)
                }))
            }
            "tracedesk_record_finding" => {
                let params: RecordFindingInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let path = check_non_empty(&params.path, "path", None)?;
                let note = check_non_empty(&params.note, "note", Some(4000))?;
                let inode = check_optional_str(&params.inode, "inode", Some(64))?;
                let dir_inode = check_optional_str(&params.dir_inode, "dir_inode", Some(64))?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.record_finding(
                    &case_dir,
                    &path,
                    &note,
                    params.partition_offset,
                    inode.as_deref(),
                    params.deleted,
                    dir_inode.as_deref(),
                    params.dir_path.trim(),
                    params.verify_large_image,
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("已记录取证发现", d)
                }))
            }
            "tracedesk_list_findings" => {
                let params: ListFindingsInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let status = params.status.trim().to_lowercase();
                if !matches!(status.as_str(), "all" | "active" | "deleted") {
                    return Err(McpError::ValueError(format!(
                        "无效的取证发现状态筛选：{}（可选：all / active / deleted）",
                        params.status
                    )));
                }
                let keyword = check_bounded_str(&params.keyword, "keyword", 120)?;
                let limit = check_range(params.limit, "limit", 1, 200)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.list_findings(
                    &case_dir,
                    &status,
                    params.partition_offset,
                    &keyword,
                    limit,
                    params.offset,
                    actor.as_deref(),
                )?;
                Ok(format_output(
                    &data,
                    params.response_format,
                    render_findings_md,
                ))
            }
            "tracedesk_query_timeline" => {
                let params: QueryTimelineInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let event = check_optional_str(&params.event, "event", None)?;
                let status = check_optional_str(&params.status, "status", None)?;
                let query = check_bounded_str(&params.query, "query", 120)?;
                let sort_order = params.sort_order.trim().to_lowercase();
                if !matches!(sort_order.as_str(), "asc" | "desc") {
                    return Err(McpError::ValueError(format!(
                        "无效的排序方向：{}（可选：asc / desc）",
                        params.sort_order
                    )));
                }
                let limit = check_range(params.limit, "limit", 1, 200)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.query_timeline(
                    &case_dir,
                    event.as_deref(),
                    status.as_deref(),
                    params.partition_offset,
                    &query,
                    &sort_order,
                    limit,
                    params.offset,
                    actor.as_deref(),
                )?;
                Ok(format_output(
                    &data,
                    params.response_format,
                    render_timeline_md,
                ))
            }
            "tracedesk_query_audit_log" => {
                let params: QueryAuditLogInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let origin = params.origin.trim().to_lowercase();
                if !matches!(origin.as_str(), "all" | "manual" | "mcp") {
                    return Err(McpError::ValueError(format!(
                        "无效的审计来源筛选：{}（可选：all / manual / mcp）",
                        params.origin
                    )));
                }
                let action = check_optional_str(&params.action, "action", None)?;
                let actor_filter =
                    check_optional_str(&params.actor_filter, "actor_filter", None)?;
                let result = check_optional_str(&params.result, "result", None)?;
                let query = check_bounded_str(&params.query, "query", 120)?;
                let sort_order = params.sort_order.trim().to_lowercase();
                if !matches!(sort_order.as_str(), "asc" | "desc") {
                    return Err(McpError::ValueError(format!(
                        "无效的排序方向：{}（可选：asc / desc）",
                        params.sort_order
                    )));
                }
                let limit = check_range(params.limit, "limit", 1, 200)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.query_audit_log(
                    &case_dir,
                    &origin,
                    action.as_deref(),
                    actor_filter.as_deref(),
                    result.as_deref(),
                    &query,
                    &sort_order,
                    limit,
                    params.offset,
                    actor.as_deref(),
                )?;
                Ok(format_output(
                    &data,
                    params.response_format,
                    render_audit_md,
                ))
            }
            "tracedesk_export_file" => {
                let params: ExportFileInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let path = check_non_empty(&params.path, "path", None)?;
                let inode = check_optional_str(&params.inode, "inode", Some(64))?;
                let dir_inode = check_optional_str(&params.dir_inode, "dir_inode", Some(64))?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.export_file(
                    &case_dir,
                    &path,
                    params.partition_offset,
                    inode.as_deref(),
                    params.deleted,
                    dir_inode.as_deref(),
                    params.dir_path.trim(),
                    params.verify_large_image,
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("文件已导出", d)
                }))
            }
            "tracedesk_export_findings" => {
                let params: ExportFindingsInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let status = params.status.trim().to_lowercase();
                if !matches!(status.as_str(), "all" | "active" | "deleted") {
                    return Err(McpError::ValueError(format!(
                        "无效的状态筛选：{}（可选：all / active / deleted）",
                        params.status
                    )));
                }
                let keyword = check_bounded_str(&params.keyword, "keyword", 120)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.export_findings(
                    &case_dir,
                    &status,
                    params.partition_offset,
                    &keyword,
                    params.verify_large_image,
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("取证发现导出完成", d)
                }))
            }
            "tracedesk_generate_report" => {
                let params: ReportActionInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.generate_report(
                    &case_dir,
                    params.verify_large_image,
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("Markdown 报告已生成", d)
                }))
            }
            "tracedesk_build_review_bundle" => {
                let params: ReviewBundleInput = parse_input(arguments)?;
                let case_dir = check_non_empty(&params.case_dir, "case_dir", None)?;
                let actor = check_optional_str(&params.actor, "actor", Some(80))?;
                let data = self.service.build_review_bundle(
                    &case_dir,
                    params.selected_export_indices,
                    params.selected_search_indices,
                    params.skip_missing_exports,
                    params.verify_large_image,
                    actor.as_deref(),
                )?;
                Ok(format_output(&data, params.response_format, |d| {
                    render_simple_kv_md("复核包已构建", d)
                }))
            }
            other => Err(McpError::ValueError(format!("未知的 MCP 工具：{other}"))),
        }
    }

    /// 处理单条或批量 JSON-RPC 2.0 消息；对于纯 Notification（无 `id`）返回 `None`。
    pub fn handle_jsonrpc_value(&self, msg: Value) -> Option<Value> {
        match msg {
            Value::Array(batch) => {
                if batch.is_empty() {
                    return Some(jsonrpc_error(Value::Null, -32600, "Invalid Request: empty batch"));
                }
                let mut responses = Vec::new();
                for item in batch {
                    if let Some(resp) = self.handle_single_jsonrpc(item) {
                        responses.push(resp);
                    }
                }
                if responses.is_empty() {
                    None
                } else {
                    Some(Value::Array(responses))
                }
            }
            single => self.handle_single_jsonrpc(single),
        }
    }

    /// 解析并处理 UTF-8 JSON-RPC 字符串，返回序列化后的响应（或 `None` 表示无需响应的通知）。
    pub fn handle_jsonrpc_str(&self, raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let parsed: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let resp = jsonrpc_error(Value::Null, -32700, &format!("Parse error: {e}"));
                return serde_json::to_string(&resp).ok();
            }
        };
        let resp = self.handle_jsonrpc_value(parsed)?;
        serde_json::to_string(&resp).ok()
    }

    fn handle_single_jsonrpc(&self, msg: Value) -> Option<Value> {
        let Some(obj) = msg.as_object() else {
            return Some(jsonrpc_error(Value::Null, -32600, "Invalid Request"));
        };
        let has_id = obj.contains_key("id");
        let id = obj.get("id").cloned().unwrap_or(Value::Null);

        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            // If it has an `id` and `result`/`error` without `method`, it's a client response; ignore.
            if obj.contains_key("result") || obj.contains_key("error") {
                return None;
            }
            return if has_id {
                Some(jsonrpc_error(id, -32600, "Invalid Request: missing method"))
            } else {
                None
            };
        };

        let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));

        // Notifications (no `id` key) never emit a response in JSON-RPC 2.0.
        if !has_id {
            return None;
        }

        match method {
            "initialize" => {
                let requested_version = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(DEFAULT_PROTOCOL_VERSION);
                let negotiated = match requested_version {
                    "2024-11-05" | "2025-03-26" | "2025-06-18" => requested_version,
                    _ => DEFAULT_PROTOCOL_VERSION,
                };
                Some(jsonrpc_result(
                    id,
                    json!({
                        "protocolVersion": negotiated,
                        "capabilities": {
                            "tools": {
                                "listChanged": false
                            },
                            "resources": {
                                "subscribe": false,
                                "listChanged": false
                            }
                        },
                        "serverInfo": {
                            "name": SERVER_NAME,
                            "version": SERVER_VERSION
                        },
                        "instructions": SERVER_INSTRUCTIONS
                    }),
                ))
            }
            "notifications/initialized" | "initialized" | "ping" => {
                Some(jsonrpc_result(id, json!({})))
            }
            m if m.starts_with("notifications/") => Some(jsonrpc_result(id, json!({}))),
            "tools/list" => Some(jsonrpc_result(
                id,
                json!({
                    "tools": *self.tools
                }),
            )),
            "tools/call" => {
                let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
                    return Some(jsonrpc_error(
                        id,
                        -32602,
                        "Invalid params: tools/call requires string 'name'",
                    ));
                };
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let output = self.call_tool(tool_name, args);
                Some(jsonrpc_result(
                    id,
                    serde_json::to_value(output).unwrap_or_else(|_| json!({})),
                ))
            }
            "resources/list" => Some(jsonrpc_result(
                id,
                json!({
                    "resources": *self.resources
                }),
            )),
            "resources/read" => {
                let Some(uri) = params.get("uri").and_then(Value::as_str) else {
                    return Some(jsonrpc_error(
                        id,
                        -32602,
                        "Invalid params: resources/read requires string 'uri'",
                    ));
                };
                match self.read_resource(uri) {
                    Ok(content) => Some(jsonrpc_result(
                        id,
                        json!({
                            "contents": [content]
                        }),
                    )),
                    Err(err) => Some(jsonrpc_error(id, -32602, &err.to_string())),
                }
            }
            "resources/templates/list" => Some(jsonrpc_result(
                id,
                json!({
                    "resourceTemplates": []
                }),
            )),
            "prompts/list" => Some(jsonrpc_result(
                id,
                json!({
                    "prompts": []
                }),
            )),
            other => Some(jsonrpc_error(
                id,
                -32601,
                &format!("Method not found: {other}"),
            )),
        }
    }
}

fn jsonrpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn jsonrpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}
