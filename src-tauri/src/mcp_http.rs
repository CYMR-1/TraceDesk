//! Built-in local `127.0.0.1` Streamable HTTP MCP server for `tracedesk-desktop`,
//! with DNS rebinding protection, 19 forensic tools + 2 resources, and seamless
//! `case.lock` coordination with the desktop's active [`AppState`].

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tracedesk_core::{
    AuditOrigin, BuildBundleOptions, Case, PreviewEncoding, Provenance, SearchOptions,
    TimelineFilter, action_title, audit_origin, audit_origin_label, build_bundle, can_export,
    coverage_text, deleted_source_note, display_iso_time, display_timestamp, entry_name,
    entry_status, examine, export_findings, group_findings, operation_title, preview_entry_page,
    record_note, resolve_clean, search_case, source_status,
};
use tracedesk_engines::InventoryEntry;

use crate::state::{AppState, ToolCatalogItem};

pub const DEFAULT_MCP_HOST: &str = "127.0.0.1";
pub const DEFAULT_MCP_PORT: u16 = 8765;
pub const DEFAULT_MCP_PATH: &str = "/mcp";

pub const SERVER_INSTRUCTIONS: &str = "TraceDesk 是本地电子数据取证工作台 MCP 服务。\
所有源镜像（RAW / 分段 EWF .E01）均以只读方式打开，绝不修改原始证据；\
所有受控写操作（新建案件、载入镜像、校验、登记来源、搜索、记录发现、导出、生成报告与复核包）\
都会写入案件目录并追加到可核验 SHA-256 审计哈希链。\
同名或跨分区文件请通过 partition_offset、inode 和 deleted 参数唯一定位。\
界面与返回时间统一采用东八区（UTC+8）。";

pub fn default_tool_catalog() -> Vec<ToolCatalogItem> {
    vec![
        ToolCatalogItem {
            name: "tracedesk_list_cases".to_string(),
            title: Some("列出案件".to_string()),
            category: "案件管理".to_string(),
            read_only: true,
            summary: "列出案件库目录中的已有取证案件及其摘要状态".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_create_case".to_string(),
            title: Some("新建案件".to_string()),
            category: "案件管理".to_string(),
            read_only: false,
            summary: "创建隔离的取证案件目录、元数据与审计链起点".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_get_case_summary".to_string(),
            title: Some("案件总览".to_string()),
            category: "案件管理".to_string(),
            read_only: true,
            summary: "查看案件元数据、镜像哈希、覆盖范围、分区扫描与审计链状态".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_load_image".to_string(),
            title: Some("加载镜像".to_string()),
            category: "证据镜像".to_string(),
            read_only: false,
            summary: "以只读方式加载 RAW 或 .E01 首段镜像，固定 SHA-256 并识别分区".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_verify_integrity".to_string(),
            title: Some("校验完整性".to_string()),
            category: "证据镜像".to_string(),
            read_only: false,
            summary: "复算镜像 SHA-256 并与初始固定基线比对，更新校验记录".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_register_source".to_string(),
            title: Some("登记证据来源".to_string()),
            category: "证据镜像".to_string(),
            read_only: false,
            summary: "登记证据编号、交付方、采集时间/工具和交付方 SHA-256".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_scan_partitions".to_string(),
            title: Some("扫描分区清单".to_string()),
            category: "证据镜像".to_string(),
            read_only: false,
            summary: "扫描全部分区或指定偏移分区，建立/刷新完整文件清单".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_list_files".to_string(),
            title: Some("浏览与筛选文件".to_string()),
            category: "文件分析".to_string(),
            read_only: true,
            summary: "按分区、路径前缀、后缀、关键词和状态分页查询镜像内文件".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_preview_file".to_string(),
            title: Some("预览文件内容".to_string()),
            category: "文件分析".to_string(),
            read_only: true,
            summary: "按页读取文件或系统区域的文本（多编码）与十六进制转储".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_search_content".to_string(),
            title: Some("搜索文件内容".to_string()),
            category: "文件分析".to_string(),
            read_only: false,
            summary: "按 UTF-8 / UTF-16LE / GBK / HEX 精确搜索全案或单文件字节".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_examine_file".to_string(),
            title: Some("计算文件哈希/比对".to_string()),
            category: "文件分析".to_string(),
            read_only: false,
            summary: "直接从只读镜像计算文件 SHA-256，或与本地副本核验一致性".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_record_finding".to_string(),
            title: Some("记录取证发现".to_string()),
            category: "取证发现".to_string(),
            read_only: false,
            summary: "绑定镜像摘要、分区偏移、路径与 inode 写入结构化取证笔记".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_list_findings".to_string(),
            title: Some("查询取证发现".to_string()),
            category: "取证发现".to_string(),
            read_only: true,
            summary: "按文件归组查看取证笔记、哈希计算与副本比对记录".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_query_timeline".to_string(),
            title: Some("查询 MACB 时间线".to_string()),
            category: "时间线与审计".to_string(),
            read_only: true,
            summary: "按事件类型、状态、分区偏移与关键词分页查询 MACB 时间线".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_query_audit_log".to_string(),
            title: Some("核验并查询审计日志".to_string()),
            category: "时间线与审计".to_string(),
            read_only: true,
            summary: "核验审计哈希链完整性，并按操作/人员/结果分页检索日志".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_export_file".to_string(),
            title: Some("导出单个文件".to_string()),
            category: "导出与报告".to_string(),
            read_only: false,
            summary: "导出镜像中现存或已删除文件到案件 exports 目录并记录副本哈希".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_export_findings".to_string(),
            title: Some("一键导出取证发现".to_string()),
            category: "导出与报告".to_string(),
            read_only: false,
            summary: "批量导出取证发现涉及的文件副本及 Markdown 汇总清单".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_generate_report".to_string(),
            title: Some("生成 Markdown 报告".to_string()),
            category: "导出与报告".to_string(),
            read_only: false,
            summary: "执行完整性校验并生成分节 Markdown 取证报告".to_string(),
        },
        ToolCatalogItem {
            name: "tracedesk_build_review_bundle".to_string(),
            title: Some("构建复核包 ZIP".to_string()),
            category: "导出与报告".to_string(),
            read_only: false,
            summary: "生成含报告、副本、搜索记录、审计链与 SHA256SUMS 的复核包".to_string(),
        },
    ]
}

pub struct LocalMcpHttpServer {
    host: String,
    port: u16,
    path: String,
    stop_flag: Option<Arc<AtomicBool>>,
    handle: Option<JoinHandle<()>>,
}

impl Default for LocalMcpHttpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalMcpHttpServer {
    pub fn new() -> Self {
        Self {
            host: DEFAULT_MCP_HOST.to_string(),
            port: DEFAULT_MCP_PORT,
            path: DEFAULT_MCP_PATH.to_string(),
            stop_flag: None,
            handle: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.stop_flag
            .as_ref()
            .is_some_and(|flag| !flag.load(Ordering::Relaxed))
            && self
                .handle
                .as_ref()
                .is_some_and(|h| !h.is_finished())
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn start(&mut self, port: u16, app_state: Arc<AppState>) -> Result<String, String> {
        if !(1024..=65535).contains(&port) {
            return Err("端口号必须在 1024 到 65535 之间。".to_string());
        }
        if self.is_running() {
            if self.port == port {
                return Ok(format!("http://{}:{}{}", self.host, self.port, self.path));
            }
            self.stop();
        } else {
            self.stop();
        }

        let bind_addr = format!("{DEFAULT_MCP_HOST}:{port}");
        let listener = TcpListener::bind(&bind_addr).map_err(|err| {
            format!(
                "端口 {DEFAULT_MCP_HOST}:{port} 已被占用或无法监听，请更换端口后重试（{err}）。"
            )
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("无法配置本地 HTTP 监听套接字：{e}"))?;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop_flag);
        let endpoint_path = self.path.clone();

        let handle = thread::Builder::new()
            .name("tracedesk-mcp-http".to_string())
            .spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _peer)) => {
                            let st = Arc::clone(&app_state);
                            let ep = endpoint_path.clone();
                            let _ = handle_http_connection(stream, port, &ep, &st);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(15));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
            })
            .map_err(|e| format!("无法启动本地 MCP HTTP 后台线程：{e}"))?;

        self.port = port;
        self.stop_flag = Some(stop_flag);
        self.handle = Some(handle);
        Ok(format!("http://{}:{}{}", self.host, self.port, self.path))
    }

    pub fn stop(&mut self) {
        if let Some(flag) = self.stop_flag.take() {
            flag.store(true, Ordering::Relaxed);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LocalMcpHttpServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn is_allowed_host(host_header: &str, port: u16) -> bool {
    let trimmed = host_header.trim().to_ascii_lowercase();
    let allowed = [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        "127.0.0.1".to_string(),
        "localhost".to_string(),
    ];
    allowed.iter().any(|a| a == &trimmed)
}

fn is_allowed_origin(origin_header: &str, port: u16) -> bool {
    let trimmed = origin_header.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return true;
    }
    let allowed = [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        "http://127.0.0.1".to_string(),
        "http://localhost".to_string(),
    ];
    allowed.iter().any(|a| a == &trimmed)
}

fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status_code} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn handle_http_connection(
    mut stream: TcpStream,
    port: u16,
    endpoint_path: &str,
    app_state: &Arc<AppState>,
) -> std::io::Result<()> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return write_http_response(
            &mut stream,
            400,
            "Bad Request",
            "text/plain; charset=utf-8",
            b"Invalid HTTP request line",
        );
    }
    let method = parts[0].to_ascii_uppercase();
    let raw_target = parts[1];
    let path_only = raw_target.split('?').next().unwrap_or(raw_target);

    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    // DNS Rebinding protection: enforce loopback Host and Origin headers.
    if let Some(host_val) = headers.get("host")
        && !is_allowed_host(host_val, port)
    {
        return write_http_response(
            &mut stream,
            403,
            "Forbidden",
            "application/json; charset=utf-8",
            br#"{"error":"Invalid Host header (DNS rebinding protection)"}"#,
        );
    }
    if let Some(origin_val) = headers.get("origin")
        && !is_allowed_origin(origin_val, port)
    {
        return write_http_response(
            &mut stream,
            403,
            "Forbidden",
            "application/json; charset=utf-8",
            br#"{"error":"Invalid Origin header (DNS rebinding protection)"}"#,
        );
    }

    if path_only != endpoint_path && path_only.trim_end_matches('/') != endpoint_path {
        return write_http_response(
            &mut stream,
            404,
            "Not Found",
            "application/json; charset=utf-8",
            br#"{"error":"Not Found"}"#,
        );
    }

    const MAX_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;
    let content_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if content_len > MAX_HTTP_BODY_BYTES {
        return write_http_response(
            &mut stream,
            413,
            "Payload Too Large",
            "application/json; charset=utf-8",
            br#"{"error":"Request body exceeds 16 MiB limit"}"#,
        );
    }
    let mut body_bytes = vec![0u8; content_len];
    if content_len > 0 {
        reader.read_exact(&mut body_bytes)?;
    }

    match method.as_str() {
        "OPTIONS" | "DELETE" => {
            write_http_response(&mut stream, 200, "OK", "text/plain; charset=utf-8", b"")
        }
        "GET" => write_http_response(
            &mut stream,
            405,
            "Method Not Allowed",
            "application/json; charset=utf-8",
            br#"{"error":"Use POST for stateless Streamable HTTP MCP requests"}"#,
        ),
        "POST" => {
            let payload: Value = match serde_json::from_slice(&body_bytes) {
                Ok(v) => v,
                Err(err) => {
                    let resp = json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {
                            "code": -32700,
                            "message": format!("Parse error: {err}")
                        }
                    });
                    let raw = serde_json::to_vec(&resp).unwrap_or_default();
                    return write_http_response(
                        &mut stream,
                        200,
                        "OK",
                        "application/json; charset=utf-8",
                        &raw,
                    );
                }
            };

            if let Some(arr) = payload.as_array() {
                let mut responses = Vec::new();
                for item in arr {
                    if let Some(r) = dispatch_jsonrpc(item, app_state) {
                        responses.push(r);
                    }
                }
                if responses.is_empty() {
                    write_http_response(&mut stream, 202, "Accepted", "text/plain", b"")
                } else {
                    let raw = serde_json::to_vec(&Value::Array(responses)).unwrap_or_default();
                    write_http_response(
                        &mut stream,
                        200,
                        "OK",
                        "application/json; charset=utf-8",
                        &raw,
                    )
                }
            } else if let Some(resp) = dispatch_jsonrpc(&payload, app_state) {
                let raw = serde_json::to_vec(&resp).unwrap_or_default();
                write_http_response(
                    &mut stream,
                    200,
                    "OK",
                    "application/json; charset=utf-8",
                    &raw,
                )
            } else {
                write_http_response(&mut stream, 202, "Accepted", "text/plain", b"")
            }
        }
        _ => write_http_response(
            &mut stream,
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"Method Not Allowed",
        ),
    }
}

/// Dispatch a single JSON-RPC 2.0 MCP message. Returns `None` for notifications (no `id`).
pub fn dispatch_jsonrpc(req: &Value, app_state: &Arc<AppState>) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

    // Notifications without an id do not produce a response.
    if id.is_none() || method.starts_with("notifications/") {
        return None;
    }
    let id_val = id.unwrap_or(Value::Null);

    match method {
        "initialize" => {
            let protocol_version = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2024-11-05");
            Some(json!({
                "jsonrpc": "2.0",
                "id": id_val,
                "result": {
                    "protocolVersion": protocol_version,
                    "capabilities": {
                        "tools": { "listChanged": false },
                        "resources": { "subscribe": false, "listChanged": false }
                    },
                    "serverInfo": {
                        "name": "tracedesk_mcp",
                        "version": "0.1.0"
                    },
                    "instructions": SERVER_INSTRUCTIONS
                }
            }))
        }
        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": id_val,
            "result": {}
        })),
        "tools/list" => {
            let tools: Vec<Value> = default_tool_catalog()
                .into_iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.summary,
                        "inputSchema": {
                            "type": "object",
                            "additionalProperties": true
                        },
                        "annotations": {
                            "title": t.title.unwrap_or_else(|| t.name.clone()),
                            "readOnlyHint": t.read_only,
                            "destructiveHint": false,
                            "idempotentHint": t.read_only,
                            "openWorldHint": false
                        }
                    })
                })
                .collect();
            Some(json!({
                "jsonrpc": "2.0",
                "id": id_val,
                "result": { "tools": tools }
            }))
        }
        "resources/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id_val,
            "result": {
                "resources": [
                    {
                        "uri": "tracedesk://cases",
                        "name": "cases_list",
                        "description": "默认案件库中的 TraceDesk 案件清单（JSON）",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "tracedesk://guide/workflow",
                        "name": "forensic_workflow",
                        "description": "TraceDesk 标准电子数据取证流程与证据边界说明",
                        "mimeType": "text/markdown"
                    }
                ]
            }
        })),
        "resources/read" => {
            let uri = params.get("uri").and_then(Value::as_str).unwrap_or("");
            match uri {
                "tracedesk://cases" => {
                    let data = mcp_list_cases(app_state, None, 200, 0)
                        .unwrap_or_else(|e| json!({ "error": e }));
                    let text = serde_json::to_string_pretty(&data).unwrap_or_default();
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": id_val,
                        "result": {
                            "contents": [{
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": text
                            }]
                        }
                    }))
                }
                "tracedesk://guide/workflow" => {
                    let wf = "# TraceDesk MCP 标准取证流程\n\n\
                        1. 使用 `tracedesk_list_cases` 查看现有案件，或用 `tracedesk_create_case` 新建隔离案件。\n\
                        2. 使用 `tracedesk_load_image` 只读载入 RAW 或 `.E01` 首段镜像（镜像必须位于案件库目录之外）。\n\
                        3. 使用 `tracedesk_get_case_summary` 查看 SHA-256、卷声明范围和分区扫描状态。\n\
                        4. 使用 `tracedesk_list_files`、`tracedesk_preview_file`、`tracedesk_search_content`、`tracedesk_query_timeline` 开展分析。\n\
                        5. 使用 `tracedesk_examine_file` 校验文件哈希，用 `tracedesk_record_finding` 记录取证发现。\n\
                        6. 使用 `tracedesk_export_file` / `tracedesk_export_findings` 导出副本，并用 `tracedesk_generate_report` 或 `tracedesk_build_review_bundle` 输出正式报告和可核验复核包。";
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": id_val,
                        "result": {
                            "contents": [{
                                "uri": uri,
                                "mimeType": "text/markdown",
                                "text": wf
                            }]
                        }
                    }))
                }
                other => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "error": {
                        "code": -32602,
                        "message": format!("未知资源 URI：{other}")
                    }
                })),
            }
        }
        "tools/call" => {
            let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match execute_mcp_tool(app_state, tool_name, &args) {
                Ok(text) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "result": {
                        "content": [{ "type": "text", "text": text }],
                        "isError": false
                    }
                })),
                Err(err_msg) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "result": {
                        "content": [{ "type": "text", "text": format!("Error: {err_msg}") }],
                        "isError": true
                    }
                })),
            }
        }
        other => Some(json!({
            "jsonrpc": "2.0",
            "id": id_val,
            "error": {
                "code": -32601,
                "message": format!("Method not found: {other}")
            }
        })),
    }
}

fn resolve_mcp_case_dir(app_state: &AppState, raw_case_dir: &str) -> Result<PathBuf, String> {
    let trimmed = raw_case_dir.trim();
    if trimmed.is_empty() {
        return Err("case_dir 不能为空".to_string());
    }
    let raw = Path::new(trimmed);
    let candidates = if raw.is_absolute() {
        vec![raw.to_path_buf()]
    } else {
        vec![app_state.app_paths.cases_dir.join(raw), raw.to_path_buf()]
    };
    for cand in candidates {
        let mut resolved = resolve_clean(&cand);
        if resolved.is_file()
            && resolved
                .file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case("case.json"))
            && let Some(parent) = resolved.parent()
        {
            resolved = parent.to_path_buf();
        }
        if resolved.join("case.json").is_file() {
            return Ok(resolved);
        }
    }
    Err(format!(
        "未找到有效案件目录（缺少 case.json）：{trimmed}。请先调用 tracedesk_list_cases 查看已有案件，或调用 tracedesk_create_case 新建案件。"
    ))
}

fn find_mcp_entry(
    case: &mut Case,
    path: &str,
    partition_offset: Option<u64>,
    inode: Option<&str>,
    deleted: Option<bool>,
    dir_inode: Option<&str>,
    dir_path: &str,
) -> Result<InventoryEntry, String> {
    let target_path = path.replace('\\', "/").trim().trim_start_matches('/').to_string();
    if target_path.is_empty() {
        return Err("文件路径 path 不能为空。".to_string());
    }
    if case.browsing_directories() {
        let Some(off) = partition_offset else {
            return Err("当前为大容量镜像快速浏览模式（尚未建立完整文件索引）。请先调用 tracedesk_scan_partitions 建立完整文件索引，或同时提供 partition_offset 与所在目录参数。".to_string());
        };
        let parent = if !dir_path.trim().is_empty() {
            dir_path.trim().to_string()
        } else {
            target_path
                .rsplit_once('/')
                .map(|(p, _)| p.to_string())
                .unwrap_or_default()
        };
        case.browse_directory(off, dir_inode, &parent, None)
            .map_err(|e| e.to_string())?;
    }

    let matches: Vec<InventoryEntry> = case
        .displayed_entries()
        .iter()
        .filter(|e| {
            let norm = e.path.replace('\\', "/");
            let norm = norm.trim().trim_start_matches('/');
            if !norm.eq_ignore_ascii_case(&target_path) {
                return false;
            }
            if let Some(off) = partition_offset
                && e.offset != off
            {
                return false;
            }
            if let Some(ino) = inode
                && !ino.is_empty()
                && e.inode != ino
            {
                return false;
            }
            if let Some(del) = deleted
                && e.deleted != del
            {
                return false;
            }
            true
        })
        .cloned()
        .collect();

    if matches.is_empty() {
        return Err(format!(
            "未在当前案件清单中找到文件：{path}。请先调用 tracedesk_list_files 确认准确的 path、partition_offset 和 inode。"
        ));
    }
    if matches.len() > 1 {
        return Err(format!(
            "路径 {path} 匹配到 {} 条记录，存在同名或跨分区歧义。请补充 partition_offset、inode 或 deleted 参数以唯一定位目标文件。",
            matches.len()
        ));
    }
    Ok(matches.into_iter().next().expect("non-empty matches"))
}

pub fn mcp_list_cases(
    app_state: &AppState,
    cases_root: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Value, String> {
    let root = match cases_root.filter(|s| !s.trim().is_empty()) {
        Some(r) => resolve_clean(Path::new(r)),
        None => resolve_clean(&app_state.app_paths.cases_dir),
    };
    if !root.exists() {
        return Ok(json!({
            "cases_root": root.to_string_lossy(),
            "total": 0,
            "count": 0,
            "offset": offset,
            "limit": limit,
            "has_more": false,
            "next_offset": null,
            "items": []
        }));
    }
    let mut rows: Vec<Value> = Vec::new();
    let rd = fs::read_dir(&root).map_err(|e| format!("无法读取案件库目录：{e}"))?;
    for entry in rd.flatten() {
        let child = entry.path();
        let meta_file = child.join("case.json");
        if !child.is_dir() || !meta_file.is_file() {
            continue;
        }
        let child_clean = resolve_clean(&child);
        let folder_str = child_clean.to_string_lossy().into_owned();
        let folder_name = child_clean
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Ok(raw) = fs::read_to_string(&meta_file) else {
            continue;
        };
        let Ok(data) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let ev = data.get("evidence").and_then(Value::as_object);
        let inv_count = data
            .get("inventory_count")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .or_else(|| {
                data.get("inventory")
                    .and_then(Value::as_array)
                    .map(Vec::len)
            })
            .unwrap_or(0);
        let exp_count = data
            .get("exports")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let created = display_iso_time(
            data.get("created").and_then(Value::as_str).unwrap_or(""),
            false,
        );
        rows.push(json!({
            "folder": folder_str,
            "name": folder_name,
            "id": data.get("id").and_then(Value::as_str).unwrap_or(""),
            "number": data.get("number").and_then(Value::as_str).unwrap_or(""),
            "examiner": data.get("examiner").and_then(Value::as_str).unwrap_or(""),
            "target": data.get("target").and_then(Value::as_str).unwrap_or(""),
            "created": created,
            "has_evidence": ev.is_some(),
            "sha256_fixed": ev.and_then(|e| e.get("sha256")).and_then(Value::as_str).is_some_and(|s| !s.is_empty()),
            "inventory_count": inv_count,
            "exports_count": exp_count,
            "status": "ok"
        }));
    }
    rows.sort_by(|a, b| {
        let ca = a.get("created").and_then(Value::as_str).unwrap_or("");
        let cb = b.get("created").and_then(Value::as_str).unwrap_or("");
        cb.cmp(ca)
    });
    let total = rows.len();
    let sliced: Vec<Value> = rows.into_iter().skip(offset).take(limit).collect();
    let count = sliced.len();
    let has_more = offset + count < total;
    Ok(json!({
        "cases_root": root.to_string_lossy(),
        "total": total,
        "count": count,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
        "next_offset": has_more.then_some(offset + count),
        "items": sliced
    }))
}

fn execute_mcp_tool(
    app_state: &Arc<AppState>,
    tool_name: &str,
    args: &Value,
) -> Result<String, String> {
    let actor = args
        .get("actor")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let data: Value = match tool_name {
        "tracedesk_list_cases" => {
            let cases_root = args.get("cases_root").and_then(Value::as_str);
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(20) as usize;
            let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
            mcp_list_cases(app_state, cases_root, limit, offset)?
        }
        "tracedesk_create_case" => {
            let number = args.get("number").and_then(Value::as_str).unwrap_or("");
            let examiner = args.get("examiner").and_then(Value::as_str).unwrap_or("");
            let target = args.get("target").and_then(Value::as_str).unwrap_or("");
            let folder_name = args.get("folder_name").and_then(Value::as_str);
            let root = args
                .get("cases_root")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(|r| resolve_clean(Path::new(r)))
                .unwrap_or_else(|| resolve_clean(&app_state.app_paths.cases_dir));
            let mut case = Case::create(
                &root,
                number,
                examiner,
                target,
                folder_name,
                actor,
                AuditOrigin::Mcp,
            )
            .map_err(|e| e.to_string())?;
            let out = json!({
                "case_dir": case.folder().to_string_lossy(),
                "id": case.data().id,
                "number": case.data().number,
                "examiner": case.data().examiner,
                "target": case.data().target,
                "origin": "mcp",
                "origin_label": "MCP",
                "created": display_iso_time(&case.data().created, false),
            });
            case.close();
            out
        }
        "tracedesk_get_case_summary" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let records = case.check_audit().map_err(|e| e.to_string())?;
                let groups = group_findings(&records);
                let mcp_count = records
                    .iter()
                    .filter(|r| audit_origin(r) == AuditOrigin::Mcp)
                    .count();
                let d = case.data();
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "id": d.id,
                    "number": d.number,
                    "examiner": d.examiner,
                    "target": d.target,
                    "created": display_iso_time(&d.created, false),
                    "browsing_directories": case.browsing_directories(),
                    "needs_partition_scan": case.needs_partition_scan(),
                    "inventory_count": d.inventory.len(),
                    "exports_count": d.exports.len(),
                    "findings_file_count": groups.len(),
                    "findings_record_count": groups.iter().map(|g| g.records.len()).sum::<usize>(),
                    "audit_count": records.len(),
                    "audit_origin_counts": {
                        "manual": records.len() - mcp_count,
                        "mcp": mcp_count
                    },
                    "audit_head": records.last().map(|r| r.hash.as_str()).unwrap_or(""),
                    "audit_chain_valid": true,
                    "evidence": d.evidence,
                    "partition_scans": d.partition_scans.clone().unwrap_or_default(),
                    "verification": d.verification,
                }))
            })?
        }
        "tracedesk_load_image" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let image_path = args.get("image_path").and_then(Value::as_str).unwrap_or("");
            let scan_all = args.get("scan_all").and_then(Value::as_bool).unwrap_or(true);
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                case.load_image(Path::new(image_path), None, None, None)
                    .map_err(|e| e.to_string())?;
                let is_large = case
                    .data()
                    .evidence
                    .as_ref()
                    .is_some_and(|e| e.is_large_image());
                let mut scanned = false;
                if scan_all && !is_large {
                    case.scan_partitions(None, None, None)
                        .map_err(|e| e.to_string())?;
                    scanned = true;
                }
                let ev = case.data().evidence.as_ref().expect("loaded evidence");
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "image_path": ev.path,
                    "format": ev.format_label(),
                    "size": ev.size,
                    "large_image": ev.is_large_image(),
                    "sha256": ev.sha256,
                    "scanned_all_partitions": scanned,
                    "inventory_count": case.data().inventory.len(),
                }))
            })?
        }
        "tracedesk_verify_integrity" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let ok = case
                    .verify_integrity(None, None, None)
                    .map_err(|e| e.to_string())?;
                let ev = case.data().evidence.as_ref().expect("evidence");
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "image_path": ev.path,
                    "ok": ok,
                    "sha256": ev.sha256,
                    "source_comparison": source_status(ev),
                    "coverage_text": coverage_text(ev.coverage.as_ref()),
                }))
            })?
        }
        "tracedesk_register_source" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            let prov = Provenance {
                evidence_id: args
                    .get("evidence_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                source: args
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                acquired: args
                    .get("acquired")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                tool: args
                    .get("tool")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                expected_sha256: args
                    .get("expected_sha256")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            };
            app_state.with_mcp_case(&folder, actor, |case| {
                case.register_source(&prov).map_err(|e| e.to_string())?;
                let ev = case.data().evidence.as_ref().expect("evidence");
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "provenance": ev.provenance,
                    "source_comparison": source_status(ev),
                }))
            })?
        }
        "tracedesk_scan_partitions" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let partition_offset = args.get("partition_offset").and_then(Value::as_u64);
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let entries = match partition_offset {
                    Some(off) => case
                        .scan_partition(off, None, None)
                        .map_err(|e| e.to_string())?,
                    None => case
                        .scan_partitions(None, None, None)
                        .map_err(|e| e.to_string())?,
                };
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "partition_offset": partition_offset,
                    "inventory_count": entries.len(),
                    "partition_scans": case.data().partition_scans.clone().unwrap_or_default(),
                }))
            })?
        }
        "tracedesk_list_files" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let partition_offset = args.get("partition_offset").and_then(Value::as_u64);
            let suffix = args.get("suffix").and_then(Value::as_str).unwrap_or("");
            let keyword = args.get("keyword").and_then(Value::as_str).unwrap_or("");
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
            let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let kw = keyword.trim().to_lowercase();
                let mut sfx = suffix.trim().to_lowercase();
                if !sfx.is_empty() && !sfx.starts_with('.') {
                    sfx.insert(0, '.');
                }
                let matched: Vec<Value> = case
                    .displayed_entries()
                    .iter()
                    .filter(|e| {
                        if let Some(off) = partition_offset
                            && e.offset != off
                        {
                            return false;
                        }
                        if !sfx.is_empty() && !e.path.to_lowercase().ends_with(&sfx) {
                            return false;
                        }
                        if !kw.is_empty()
                            && !e.path.to_lowercase().contains(&kw)
                            && !entry_name(e).to_lowercase().contains(&kw)
                        {
                            return false;
                        }
                        true
                    })
                    .map(|e| {
                        json!({
                            "path": e.path,
                            "name": entry_name(e),
                            "partition_offset": e.offset,
                            "inode": e.inode,
                            "directory": e.directory,
                            "size": e.size,
                            "deleted": e.deleted,
                            "status": entry_status(e),
                            "exportable": can_export(e),
                            "mtime": display_timestamp(e.mtime, false),
                        })
                    })
                    .collect();
                let total = matched.len();
                let items: Vec<Value> = matched.into_iter().skip(offset).take(limit).collect();
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "total": total,
                    "count": items.len(),
                    "offset": offset,
                    "limit": limit,
                    "items": items,
                }))
            })?
        }
        "tracedesk_preview_file" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let path = args.get("path").and_then(Value::as_str).unwrap_or("");
            let partition_offset = args.get("partition_offset").and_then(Value::as_u64);
            let inode = args.get("inode").and_then(Value::as_str);
            let deleted = args.get("deleted").and_then(Value::as_bool);
            let dir_inode = args.get("dir_inode").and_then(Value::as_str);
            let dir_path = args.get("dir_path").and_then(Value::as_str).unwrap_or("");
            let page = args.get("page").and_then(Value::as_u64).unwrap_or(0) as usize;
            let page_bytes = args
                .get("page_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(4096) as usize;
            let encoding = args
                .get("encoding")
                .and_then(Value::as_str)
                .unwrap_or("UTF-8");
            let enc = PreviewEncoding::parse(encoding).map_err(|e| e.to_string())?;
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let entry = find_mcp_entry(
                    case,
                    path,
                    partition_offset,
                    inode,
                    deleted,
                    dir_inode,
                    dir_path,
                )?;
                let image = case.image_path().map_err(|e| e.to_string())?;
                let res = preview_entry_page(&image, &entry, page, page_bytes, enc, None)
                    .map_err(|e| e.to_string())?;
                serde_json::to_value(&res).map_err(|e| e.to_string())
            })?
        }
        "tracedesk_search_content" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let query = args.get("query").and_then(Value::as_str).unwrap_or("");
            let encoding = args
                .get("encoding")
                .and_then(Value::as_str)
                .unwrap_or("UTF-8");
            let path = args.get("path").and_then(Value::as_str);
            let partition_offset = args.get("partition_offset").and_then(Value::as_u64);
            let inode = args.get("inode").and_then(Value::as_str);
            let deleted = args.get("deleted").and_then(Value::as_bool);
            let dir_inode = args.get("dir_inode").and_then(Value::as_str);
            let dir_path = args.get("dir_path").and_then(Value::as_str).unwrap_or("");
            let max_hits = args
                .get("max_hits")
                .and_then(Value::as_u64)
                .map(|n| n as usize);
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let selected = match path.filter(|s| !s.trim().is_empty()) {
                    Some(p) => Some(find_mcp_entry(
                        case,
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
                let out = search_case(
                    case,
                    &SearchOptions {
                        query: query.to_string(),
                        encoding: encoding.to_string(),
                        limit: max_hits,
                        selected,
                    },
                    &cancel,
                    None,
                    None,
                    None,
                )
                .map_err(|e| e.to_string())?;
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "report_file": out.report_path.to_string_lossy(),
                    "query": out.record.query,
                    "encoding": out.record.encoding,
                    "needle_hex": out.record.needle,
                    "status": out.record.status,
                    "visited": out.record.visited,
                    "eligible": out.record.eligible,
                    "total": out.record.hits.len(),
                    "items": out.record.hits,
                }))
            })?
        }
        "tracedesk_examine_file" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let path = args.get("path").and_then(Value::as_str).unwrap_or("");
            let partition_offset = args.get("partition_offset").and_then(Value::as_u64);
            let inode = args.get("inode").and_then(Value::as_str);
            let deleted = args.get("deleted").and_then(Value::as_bool);
            let dir_inode = args.get("dir_inode").and_then(Value::as_str);
            let dir_path = args.get("dir_path").and_then(Value::as_str).unwrap_or("");
            let comparison_path = args
                .get("comparison_path")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from);
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let entry = find_mcp_entry(
                    case,
                    path,
                    partition_offset,
                    inode,
                    deleted,
                    dir_inode,
                    dir_path,
                )?;
                let res = examine(case, &entry, comparison_path.as_deref(), None)
                    .map_err(|e| e.to_string())?;
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "operation": res.operation,
                    "path": entry.path,
                    "partition_offset": entry.offset,
                    "inode": entry.inode,
                    "deleted": entry.deleted,
                    "result": res.result,
                    "details": res.details,
                }))
            })?
        }
        "tracedesk_record_finding" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let path = args.get("path").and_then(Value::as_str).unwrap_or("");
            let note = args.get("note").and_then(Value::as_str).unwrap_or("");
            let partition_offset = args.get("partition_offset").and_then(Value::as_u64);
            let inode = args.get("inode").and_then(Value::as_str);
            let deleted = args.get("deleted").and_then(Value::as_bool);
            let dir_inode = args.get("dir_inode").and_then(Value::as_str);
            let dir_path = args.get("dir_path").and_then(Value::as_str).unwrap_or("");
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let entry = find_mcp_entry(
                    case,
                    path,
                    partition_offset,
                    inode,
                    deleted,
                    dir_inode,
                    dir_path,
                )?;
                let rec = record_note(case, &entry, note).map_err(|e| e.to_string())?;
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "seq": rec.seq,
                    "timestamp": display_iso_time(&rec.timestamp, false),
                    "origin": "mcp",
                    "origin_label": "MCP",
                    "actor": rec.actor,
                    "path": entry.path,
                    "partition_offset": entry.offset,
                    "inode": entry.inode,
                    "deleted": entry.deleted,
                    "note": note.trim(),
                    "audit_hash": rec.hash,
                }))
            })?
        }
        "tracedesk_list_findings" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let records = case.check_audit().map_err(|e| e.to_string())?;
                let groups = group_findings(&records);
                let items: Vec<Value> = groups
                    .iter()
                    .map(|g| {
                        json!({
                            "path": g.key.subject,
                            "partition_offset": g.key.offset,
                            "inode": g.key.inode,
                            "deleted": g.key.deleted,
                            "status": if g.key.deleted { "已删除" } else { "现存" },
                            "image_sha256": g.key.image_sha256.clone().unwrap_or_default(),
                            "records": g.records.iter().map(|r| json!({
                                "seq": r.seq,
                                "timestamp": display_iso_time(&r.timestamp, false),
                                "origin": audit_origin(r).as_str(),
                                "origin_label": audit_origin_label(r),
                                "actor": r.actor,
                                "action": r.action,
                                "operation": operation_title(&r.action).unwrap_or(&r.action),
                                "result": r.result,
                                "details": r.details,
                            })).collect::<Vec<_>>()
                        })
                    })
                    .collect();
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "total": items.len(),
                    "count": items.len(),
                    "items": items,
                }))
            })?
        }
        "tracedesk_query_timeline" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let event = args.get("event").and_then(Value::as_str).map(str::to_string);
            let status = args
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_string);
            let partition_offset = args.get("partition_offset").and_then(Value::as_u64);
            let query = args
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let sort_order = args
                .get("sort_order")
                .and_then(Value::as_str)
                .unwrap_or("asc");
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
            let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let tl = case.timeline_events();
                let matched = tl
                    .matching(&TimelineFilter {
                        query,
                        event,
                        status,
                        offset: partition_offset,
                    })
                    .map_err(|e| e.to_string())?;
                let mut rows: Vec<Value> = matched
                    .iter()
                    .filter_map(|&idx| tl.get(idx))
                    .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                    .collect();
                if sort_order.eq_ignore_ascii_case("desc") {
                    rows.reverse();
                }
                let total = rows.len();
                let items: Vec<Value> = rows.into_iter().skip(offset).take(limit).collect();
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "total": total,
                    "count": items.len(),
                    "sort_order": sort_order,
                    "items": items,
                }))
            })?
        }
        "tracedesk_query_audit_log" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let origin_filter = args
                .get("origin")
                .and_then(Value::as_str)
                .unwrap_or("all");
            let sort_order = args
                .get("sort_order")
                .and_then(Value::as_str)
                .unwrap_or("desc");
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
            let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let records = case.check_audit().map_err(|e| e.to_string())?;
                let mcp_count = records
                    .iter()
                    .filter(|r| audit_origin(r) == AuditOrigin::Mcp)
                    .count();
                let manual_count = records.len() - mcp_count;
                let head = records.last().map(|r| r.hash.clone()).unwrap_or_default();
                let mut list: Vec<Value> = records
                    .iter()
                    .filter(|r| match origin_filter {
                        "manual" => audit_origin(r) == AuditOrigin::Manual,
                        "mcp" => audit_origin(r) == AuditOrigin::Mcp,
                        _ => true,
                    })
                    .map(|r| {
                        json!({
                            "seq": r.seq,
                            "timestamp": display_iso_time(&r.timestamp, false),
                            "origin": audit_origin(r).as_str(),
                            "origin_label": audit_origin_label(r),
                            "actor": r.actor,
                            "action": r.action,
                            "action_title": action_title(&r.action),
                            "result": r.result,
                            "subject": r.subject,
                            "details": r.details,
                            "previous": r.previous,
                            "hash": r.hash,
                        })
                    })
                    .collect();
                if sort_order.eq_ignore_ascii_case("desc") {
                    list.reverse();
                }
                let total = list.len();
                let items: Vec<Value> = list.into_iter().skip(offset).take(limit).collect();
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "audit_chain_valid": true,
                    "audit_head": head,
                    "origin_counts": {
                        "manual": manual_count,
                        "mcp": mcp_count,
                    },
                    "total": total,
                    "count": items.len(),
                    "sort_order": sort_order,
                    "items": items,
                }))
            })?
        }
        "tracedesk_export_file" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let path = args.get("path").and_then(Value::as_str).unwrap_or("");
            let partition_offset = args.get("partition_offset").and_then(Value::as_u64);
            let inode = args.get("inode").and_then(Value::as_str);
            let deleted = args.get("deleted").and_then(Value::as_bool);
            let dir_inode = args.get("dir_inode").and_then(Value::as_str);
            let dir_path = args.get("dir_path").and_then(Value::as_str).unwrap_or("");
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let entry = find_mcp_entry(
                    case,
                    path,
                    partition_offset,
                    inode,
                    deleted,
                    dir_inode,
                    dir_path,
                )?;
                let dest = case.export(&entry, None).map_err(|e| e.to_string())?;
                let rec = case.data().exports.last().cloned();
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "exported_path": dest.to_string_lossy(),
                    "record": rec,
                    "source_note": deleted_source_note(&entry),
                }))
            })?
        }
        "tracedesk_export_findings" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let records = case.check_audit().map_err(|e| e.to_string())?;
                let groups = group_findings(&records);
                let res = export_findings(case, &groups).map_err(|e| e.to_string())?;
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "summary_path": res.summary_path.to_string_lossy(),
                    "exported_count": res.exported_count,
                    "failed_count": res.failed.len(),
                }))
            })?
        }
        "tracedesk_generate_report" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let report_path = case.report(None).map_err(|e| e.to_string())?;
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "report_path": report_path.to_string_lossy(),
                }))
            })?
        }
        "tracedesk_build_review_bundle" => {
            let case_dir = args.get("case_dir").and_then(Value::as_str).unwrap_or("");
            let skip_missing = args
                .get("skip_missing_exports")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let selected_export_indices = args
                .get("selected_export_indices")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_u64().map(|n| n as usize))
                        .collect::<Vec<_>>()
                });
            let selected_search_indices = args
                .get("selected_search_indices")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_u64().map(|n| n as usize))
                        .collect::<Vec<_>>()
                });
            let folder = resolve_mcp_case_dir(app_state, case_dir)?;
            app_state.with_mcp_case(&folder, actor, |case| {
                let res = build_bundle(
                    case,
                    &BuildBundleOptions {
                        selected_export_indices,
                        selected_search_indices,
                        skip_missing,
                    },
                    None,
                )
                .map_err(|e| e.to_string())?;
                Ok(json!({
                    "case_dir": case.folder().to_string_lossy(),
                    "bundle_path": res.bundle_path.to_string_lossy(),
                    "sha256_path": res.sha256_path.to_string_lossy(),
                    "bundle_sha256": res.sha256,
                    "included_exports": res.included_exports,
                    "omitted_exports": res.omitted_exports,
                    "included_searches": res.included_searches,
                    "omitted_searches": res.omitted_searches,
                }))
            })?
        }
        other => return Err(format!("未知 MCP 工具：{other}")),
    };

    serde_json::to_string_pretty(&data).map_err(|e| e.to_string())
}

pub fn make_empty_details() -> Map<String, Value> {
    Map::new()
}
