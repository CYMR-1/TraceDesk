//! TraceDesk 桌面端内嵌的本地 Streamable HTTP MCP 服务（`127.0.0.1:<port>/mcp`）。
//!
//! - 将全部 JSON-RPC 2.0 协议处理、19 个取证工具（含完整 JSON Schema、
//!   FastMCP `{"params": {...}}` 解包、`response_format` 以及 `Error (<Kind>): ...`）与
//!   2 个资源直接委托给 [`tracedesk_mcp::McpServer`]，与独立版 `tracedesk-mcp` 服务保持 100% 契约一致。
//! - 复用 [`tracedesk_mcp::verify_dns_rebinding`]（缺失或无效 `Host` 返回 HTTP 421，
//!   无效 `Origin` 返回 HTTP 403）、[`tracedesk_mcp::validate_loopback_host`]、
//!   [`tracedesk_mcp::normalize_http_path`] 以及 [`tracedesk_mcp::MAX_HTTP_BODY_BYTES`]（16 MiB）。
//! - 支持 HTTP/1.1 keep-alive、`Transfer-Encoding: chunked`（带 `checked_add` 溢出保护，
//!   超限时返回 HTTP 413）、严格的 `Content-Length` 解析（格式错误返回 HTTP 400，超过 16 MiB
//!   返回 HTTP 413）、严格的请求路径匹配（挂载在 `/mcp` 时访问根路径 `/` 返回 HTTP 404），
//!   以及每连接独立工作线程，确保耗时工具不会阻塞 accept 循环。
//! - 当 `tools/call` 指向桌面端 UI 当前打开的案件时，与活跃的 [`AppState`] 平滑协调 `case.lock`。

use std::cell::RefCell;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Value, json};
use tracedesk_mcp::{
    CallbackActivitySink, CaseService, DEFAULT_HOST, DEFAULT_HTTP_PATH, DEFAULT_PORT,
    HttpConnectionPermit, HttpParseError, MAX_CONCURRENT_HTTP_CONNS, MAX_HTTP_BODY_BYTES,
    McpActivityRecord, McpServer, TOOL_CATALOG, normalize_http_path, normalize_request_path,
    parse_http_request, request_context_from_http_headers, sanitize_session_id,
    validate_loopback_host, verify_dns_rebinding, write_http_response,
};

use crate::state::{AppState, ToolCatalogItem};

thread_local! {
    /// 暂存当前连接线程上已完成但需等待 `coordinate_mcp_call` 重新同步 `ViewCache` 后再推送的写入活动记录。
    static DEFERRED_CASE_UPDATES: RefCell<Vec<McpActivityRecord>> = const { RefCell::new(Vec::new()) };
}

fn push_deferred_case_update(record: McpActivityRecord) {
    DEFERRED_CASE_UPDATES.with(|cell| {
        cell.borrow_mut().push(record);
    });
}

fn drain_deferred_case_updates() -> Vec<McpActivityRecord> {
    DEFERRED_CASE_UPDATES.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
}

/// 线程局部延迟事件守卫，确保请求处理结束或异常退出时自动清空暂存队列。
struct DeferredCaseUpdateGuard;

impl DeferredCaseUpdateGuard {
    fn enter() -> Self {
        let _ = drain_deferred_case_updates();
        Self
    }
}

impl Drop for DeferredCaseUpdateGuard {
    fn drop(&mut self) {
        let _ = drain_deferred_case_updates();
    }
}

/// 直接从 [`tracedesk_mcp::TOOL_CATALOG`] 统一生成 19 个工具的目录。
pub fn default_tool_catalog() -> Vec<ToolCatalogItem> {
    TOOL_CATALOG
        .iter()
        .map(|item| ToolCatalogItem {
            name: item.name.to_string(),
            title: Some(item.title.to_string()),
            category: item.category.to_string(),
            read_only: item.read_only,
            summary: item.summary.to_string(),
        })
        .collect()
}

/// 通过 `CaseService` 列出 `cases_dir`（或默认工作区 `cases/` 根目录）下的最近案件。
pub fn mcp_list_cases(
    state: &Arc<AppState>,
    cases_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Value, String> {
    let svc = CaseService::new(Some(state.app_paths.cases_dir.clone()), None);
    svc.list_cases(cases_dir, limit, offset)
        .map_err(|e| e.to_string())
}

/// 管理内嵌本地回环 Streamable HTTP MCP 服务的生命周期。
pub struct LocalMcpHttpServer {
    host: String,
    port: u16,
    path: String,
    running: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
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
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            path: DEFAULT_HTTP_PATH.to_string(),
            running: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
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

    /// 在 `127.0.0.1:<port>/mcp` 启动回环 Streamable HTTP MCP 监听器。
    pub fn start(&mut self, port: u16, app_state: Arc<AppState>) -> Result<(), String> {
        if port == 0 {
            return Err("端口号必须在 1 到 65535 之间。".to_string());
        }
        if self.is_running() {
            if self.port == port {
                return Ok(());
            }
            self.stop();
        }

        let clean_host = validate_loopback_host(DEFAULT_HOST).map_err(|e| e.to_string())?;
        let clean_path = normalize_http_path(&self.path);
        let bind_ip = resolve_bind_ip(&clean_host);
        let addr = SocketAddr::new(bind_ip, port);

        let listener = TcpListener::bind(addr).map_err(|err| {
            format!("无法在 {clean_host}:{port} 启动本地 MCP HTTP 服务（端口可能已被占用）：{err}")
        })?;

        let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
        let st_for_sink = Arc::clone(&app_state);
        let mcp_server = Arc::new(
            McpServer::new(Some(app_state.app_paths.cases_dir.clone()), None).with_activity_sink(
                Arc::new(CallbackActivitySink::new(move |record: McpActivityRecord| {
                    let is_completed_write = record.phase == "completed" && !record.read_only;
                    st_for_sink.record_desktop_mcp_activity(record.clone(), false);
                    if is_completed_write {
                        push_deferred_case_update(record);
                    }
                })),
            ),
        );

        let shutdown = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));
        let shutdown_bg = Arc::clone(&shutdown);
        let running_bg = Arc::clone(&running);
        let host_bg = clean_host.clone();
        let path_bg = clean_path.clone();

        let join = thread::Builder::new()
            .name(format!("tracedesk-mcp-http-{actual_port}"))
            .spawn(move || {
                accept_loop(
                    listener,
                    mcp_server,
                    app_state,
                    host_bg,
                    actual_port,
                    path_bg,
                    shutdown_bg,
                );
                running_bg.store(false, Ordering::SeqCst);
            })
            .map_err(|err| format!("创建本地 MCP HTTP 监听线程失败：{err}"))?;

        self.host = clean_host;
        self.port = actual_port;
        self.path = clean_path;
        self.shutdown = shutdown;
        self.running = running;
        self.handle = Some(join);
        Ok(())
    }

    /// 优雅停止本地 Streamable HTTP MCP 服务。
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // 仅在实际启动过监听线程时发起回环唤醒连接，避免未启动状态在关闭应用时误连本机默认端口。
        if let Some(handle) = self.handle.take() {
            let bind_ip = resolve_bind_ip(&self.host);
            let wake_addr = SocketAddr::new(bind_ip, self.port);
            for _ in 0..10 {
                if handle.is_finished() {
                    break;
                }
                let _ = TcpStream::connect_timeout(&wake_addr, Duration::from_millis(50));
                if handle.is_finished() {
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
            let _ = handle.join();
        }
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Drop for LocalMcpHttpServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn resolve_bind_ip(host: &str) -> IpAddr {
    match host {
        "::1" => IpAddr::V6(Ipv6Addr::LOCALHOST),
        _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
    }
}

fn accept_loop(
    listener: TcpListener,
    server: Arc<McpServer>,
    app_state: Arc<AppState>,
    configured_host: String,
    port: u16,
    expected_path: String,
    shutdown: Arc<AtomicBool>,
) {
    // 使用阻塞 accept 消除空闲 40ms 忙轮询唤醒，并通过并发连接槽位限制线程数。
    let active_conns = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Ok(mut stream) = incoming else {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            continue;
        };
        let Some(permit) =
            HttpConnectionPermit::try_acquire(&active_conns, MAX_CONCURRENT_HTTP_CONNS)
        else {
            let _ = write_http_response(
                &mut stream,
                503,
                "Service Unavailable",
                Some("application/json; charset=utf-8"),
                &[],
                b"{\"error\":\"Too many concurrent HTTP connections\"}",
                true,
            );
            continue;
        };
        let srv = Arc::clone(&server);
        let st = Arc::clone(&app_state);
        let host = configured_host.clone();
        let path = expected_path.clone();
        let sd = Arc::clone(&shutdown);
        let _ = thread::Builder::new()
            .name("tracedesk-mcp-conn".to_string())
            .spawn(move || {
                let _permit = permit;
                handle_client_connection(stream, srv, st, host, port, path, sd);
            });
    }
}

fn handle_client_connection(
    mut stream: TcpStream,
    server: Arc<McpServer>,
    app_state: Arc<AppState>,
    configured_host: String,
    port: u16,
    expected_path: String,
    shutdown: Arc<AtomicBool>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let Ok(cloned) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(cloned);

    while !shutdown.load(Ordering::Relaxed) {
        let req = match parse_http_request(&mut reader) {
            Ok(Some(r)) => r,
            Ok(None) | Err(HttpParseError::Io) => break,
            Err(HttpParseError::BadRequest(msg)) => {
                let err_body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
                let _ = write_http_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    Some("application/json; charset=utf-8"),
                    &[],
                    &err_body,
                    true,
                );
                break;
            }
            Err(HttpParseError::PayloadTooLarge) => {
                let err_body = serde_json::to_vec(&json!({
                    "error": format!(
                        "Payload Too Large: request body exceeds {} bytes limit",
                        MAX_HTTP_BODY_BYTES
                    )
                }))
                .unwrap_or_default();
                let _ = write_http_response(
                    &mut stream,
                    413,
                    "Payload Too Large",
                    Some("application/json; charset=utf-8"),
                    &[],
                    &err_body,
                    true,
                );
                break;
            }
        };

        let want_close = req
            .headers
            .get("connection")
            .is_some_and(|c| c.eq_ignore_ascii_case("close"))
            || shutdown.load(Ordering::Relaxed);

        // 1. 通过 tracedesk-mcp 执行 DNS 重绑定防护（缺失或无效 Host 返回 421，无效 Origin 返回 403）。
        if let Err((code, reason, msg)) = verify_dns_rebinding(
            &configured_host,
            port,
            req.headers.get("host").map(String::as_str),
            req.headers.get("origin").map(String::as_str),
        ) {
            let err_body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
            let _ = write_http_response(
                &mut stream,
                code,
                reason,
                Some("application/json; charset=utf-8"),
                &[],
                &err_body,
                true,
            );
            break;
        }

        // 2. 端点路径匹配（根路径 "/" 不得回退为 "/mcp"）。
        let raw_path = req.target.split('?').next().unwrap_or("/");
        let norm_req_path = normalize_request_path(raw_path);
        if norm_req_path != expected_path {
            let err_body =
                serde_json::to_vec(&json!({ "error": format!("Not Found: {raw_path}") }))
                    .unwrap_or_default();
            let _ = write_http_response(
                &mut stream,
                404,
                "Not Found",
                Some("application/json; charset=utf-8"),
                &[],
                &err_body,
                want_close,
            );
            if want_close {
                break;
            }
            continue;
        }

        // 3. HTTP 方法分发（清理并校验 Mcp-Session-Id 防止响应头注入）。
        let session_id = sanitize_session_id(req.headers.get("mcp-session-id").map(String::as_str));

        match req.method.as_str() {
            "OPTIONS" => {
                let _ = write_http_response(
                    &mut stream,
                    204,
                    "No Content",
                    None,
                    &[
                        ("Allow", "POST, DELETE, OPTIONS"),
                        ("Mcp-Session-Id", &session_id),
                    ],
                    &[],
                    want_close,
                );
            }
            "DELETE" => {
                // 会话结束时同步清理会话对应的 clientInfo 缓存。
                server.remove_session(&session_id);
                let _ = write_http_response(
                    &mut stream,
                    200,
                    "OK",
                    Some("application/json; charset=utf-8"),
                    &[("Mcp-Session-Id", &session_id)],
                    b"{\"ok\":true}",
                    want_close,
                );
            }
            "GET" => {
                let _ = write_http_response(
                    &mut stream,
                    405,
                    "Method Not Allowed",
                    Some("application/json; charset=utf-8"),
                    &[("Allow", "POST, DELETE, OPTIONS")],
                    b"{\"error\":\"Method Not Allowed: stateless Streamable HTTP uses POST\"}",
                    want_close,
                );
            }
            "POST" => {
                let parsed: Value = match serde_json::from_slice(&req.body) {
                    Ok(v) => v,
                    Err(err) => {
                        let err_resp = json!({
                            "jsonrpc": "2.0",
                            "id": Value::Null,
                            "error": {
                                "code": -32700,
                                "message": format!("Parse error: {err}")
                            }
                        });
                        let bytes = serde_json::to_vec(&err_resp).unwrap_or_default();
                        let _ = write_http_response(
                            &mut stream,
                            400,
                            "Bad Request",
                            Some("application/json; charset=utf-8"),
                            &[("Mcp-Session-Id", &session_id)],
                            &bytes,
                            want_close,
                        );
                        if want_close {
                            break;
                        }
                        continue;
                    }
                };

                // 提取 HTTP 请求头（X-MCP-User / X-MCP-Client / X-Client-Name / 非通用 User-Agent）与会话标识，并标记传输为 desktop-http。
                let mut req_ctx =
                    request_context_from_http_headers(&req.headers, session_id.clone());
                req_ctx.transport = Some("desktop-http".to_string());
                let target_dirs = extract_target_case_dirs(&parsed, &app_state.app_paths.cases_dir);
                let _deferred_guard = DeferredCaseUpdateGuard::enter();
                let resp_opt = app_state.coordinate_mcp_call(&target_dirs, || {
                    server.handle_jsonrpc_value_with_context(parsed, &req_ctx)
                });
                // 在 `coordinate_mcp_call` 热重载磁盘变更并刷新 `ViewCache` 之后再推送 `mcp:case-updated`，
                // 防止前端立即拉取快照时读到刷新前的旧视图。
                for completed_write in drain_deferred_case_updates() {
                    let _ = app_state.emit_case_updated_if_matching(&completed_write);
                }

                match resp_opt {
                    None => {
                        let _ = write_http_response(
                            &mut stream,
                            202,
                            "Accepted",
                            None,
                            &[("Mcp-Session-Id", &session_id)],
                            &[],
                            want_close,
                        );
                    }
                    Some(resp_val) => {
                        let bytes = serde_json::to_vec(&resp_val).unwrap_or_default();
                        let _ = write_http_response(
                            &mut stream,
                            200,
                            "OK",
                            Some("application/json; charset=utf-8"),
                            &[("Mcp-Session-Id", &session_id)],
                            &bytes,
                            want_close,
                        );
                    }
                }
            }
            _ => {
                let _ = write_http_response(
                    &mut stream,
                    405,
                    "Method Not Allowed",
                    Some("application/json; charset=utf-8"),
                    &[("Allow", "POST, DELETE, OPTIONS")],
                    b"{\"error\":\"Method Not Allowed\"}",
                    want_close,
                );
            }
        }

        if want_close {
            break;
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

/// 从单条 JSON-RPC 请求或批处理请求中提取候选目标案件目录，以便在 `tools/call` 指向
/// 桌面端 UI 当前打开的案件时，由 [`AppState::coordinate_mcp_call`] 协调 `case.lock`。
/// 同时兼容扁平结构 `arguments.case_dir` 与 FastMCP 嵌套结构 `arguments.params.case_dir`。
fn extract_target_case_dirs(payload: &Value, cases_root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    match payload {
        Value::Array(items) => {
            for item in items {
                collect_case_dir_from_request(item, cases_root, &mut dirs);
            }
        }
        other => collect_case_dir_from_request(other, cases_root, &mut dirs),
    }
    dirs
}

fn collect_case_dir_from_request(req: &Value, cases_root: &Path, out: &mut Vec<PathBuf>) {
    if req.get("method").and_then(Value::as_str) != Some("tools/call") {
        return;
    }
    let Some(args) = req.get("params").and_then(|p| p.get("arguments")) else {
        return;
    };
    let raw_dir = args
        .get("case_dir")
        .and_then(Value::as_str)
        .or_else(|| {
            args.get("params")
                .and_then(|p| p.get("case_dir"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let Some(raw) = raw_dir else {
        return;
    };

    let push_normalized = |mut candidate: PathBuf, out: &mut Vec<PathBuf>| {
        // 兼容 MCP 调用直接传入 `.../case.json` 路径，归一化至其父目录以便匹配当前打开案件。
        if candidate
            .file_name()
            .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("case.json"))
            && let Some(parent) = candidate.parent()
        {
            candidate = parent.to_path_buf();
        }
        out.push(candidate);
    };

    let p = PathBuf::from(raw);
    if p.is_absolute() {
        push_normalized(p, out);
    } else {
        push_normalized(cases_root.join(&p), out);
        push_normalized(p, out);
    }
}
