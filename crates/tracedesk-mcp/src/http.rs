//! MCP `streamable-http` 传输实现：
//! - 严格仅允许绑定本机回环地址（`127.0.0.1` / `localhost` / `::1`）
//! - 内置 DNS 重绑定防护中间件（强制校验 `Host` 与 `Origin` 请求头，拦截非回环主机并返回 HTTP 421/403）
//! - 支持 `/mcp` 端点无状态 JSON-RPC 2.0 (`POST` / `DELETE` / `OPTIONS` / `GET`、`Mcp-Session-Id`、chunked 编码与 keep-alive)
//! - 提供可随时在毫秒级优雅关闭的 [`McpHttpServerHandle`]（供桌面端 UI 开关与命令行使用）

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use crate::service::{McpError, McpResult};
use crate::tools::McpServer;

/// 默认 Streamable HTTP 监听地址（仅本机回环）。
pub const DEFAULT_HOST: &str = "127.0.0.1";

/// 默认 Streamable HTTP 监听端口。
pub const DEFAULT_PORT: u16 = 8765;

/// 默认 Streamable HTTP 挂载路径。
pub const DEFAULT_HTTP_PATH: &str = "/mcp";

/// 允许监听的回环地址白名单。
pub const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

/// 单个 Streamable HTTP 请求体允许的最大字节数（16 MiB），防止恶意超长请求体导致 OOM。
pub const MAX_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;

/// 校验监听地址是否属于本机回环地址（`127.0.0.1` / `localhost` / `::1`）。
pub fn validate_loopback_host(host: &str) -> McpResult<String> {
    let trimmed = host.trim();
    let value = if trimmed.is_empty() {
        DEFAULT_HOST
    } else {
        trimmed
    };
    let lower = value.to_ascii_lowercase();
    if !LOOPBACK_HOSTS.contains(&lower.as_str()) {
        return Err(McpError::ValueError(
            "出于证据保护边界限制，本地 HTTP MCP 服务仅允许监听本机回环地址（127.0.0.1 / localhost）。"
                .to_string(),
        ));
    }
    Ok(lower)
}

/// 规范化配置级 HTTP 挂载路径为 `/` + `path.trim_matches('/')`（空则回退到默认 `/mcp`）。
pub fn normalize_http_path(path: &str) -> String {
    let clean = path.trim().trim_matches('/');
    if clean.is_empty() {
        DEFAULT_HTTP_PATH.to_string()
    } else {
        format!("/{clean}")
    }
}

/// 规范化入站 HTTP 请求路径（仅去除尾部冗余 `/`，根路径保留为 `"/"`，绝不回退到 `/mcp`）。
fn normalize_request_path(raw_path: &str) -> String {
    let clean = raw_path.trim().trim_end_matches('/');
    if clean.is_empty() {
        "/".to_string()
    } else if clean.starts_with('/') {
        clean.to_string()
    } else {
        format!("/{clean}")
    }
}

fn resolve_bind_ip(host: &str) -> IpAddr {
    match host {
        "::1" => IpAddr::V6(Ipv6Addr::LOCALHOST),
        _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
    }
}

/// 检查指定回环端口是否空闲可用。
pub fn check_port_available(host: &str, port: u16) -> McpResult<()> {
    let clean_host = validate_loopback_host(host)?;
    let ip = resolve_bind_ip(&clean_host);
    let addr = SocketAddr::new(ip, port);

    if port != 0 && TcpStream::connect_timeout(&addr, Duration::from_millis(40)).is_ok() {
        return Err(McpError::IoError(format!(
            "端口 {clean_host}:{port} 已被占用或无法监听，请更换端口后重试。"
        )));
    }
    match TcpListener::bind(addr) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(err) => Err(McpError::IoError(format!(
            "端口 {clean_host}:{port} 已被占用或无法监听，请更换端口后重试（{err}）。"
        ))),
    }
}

/// DNS 重绑定校验：检查 HTTP 请求的 `Host` 与 `Origin` 头。
///
/// - `Host` 缺失或不在回环白名单中 -> 返回 `Err((421, "Misdirected Request", ...))`
/// - `Origin` 存在且不在回环白名单中 -> 返回 `Err((403, "Forbidden", ...))`
pub fn verify_dns_rebinding(
    configured_host: &str,
    port: u16,
    host_header: Option<&str>,
    origin_header: Option<&str>,
) -> Result<(), (u16, &'static str, String)> {
    let Some(raw_host) = host_header.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err((
            421,
            "Misdirected Request",
            "DNS rebinding protection: missing Host header".to_string(),
        ));
    };

    let h_lower = raw_host.to_ascii_lowercase();
    let cfg = configured_host.to_ascii_lowercase();

    let mut allowed_hosts = vec![
        format!("{cfg}:{port}"),
        format!("localhost:{port}"),
        cfg.clone(),
        "localhost".to_string(),
    ];
    if cfg == "127.0.0.1" || cfg == "localhost" {
        allowed_hosts.push(format!("127.0.0.1:{port}"));
        allowed_hosts.push("127.0.0.1".to_string());
    }
    if cfg == "::1" {
        allowed_hosts.push(format!("[::1]:{port}"));
        allowed_hosts.push("[::1]".to_string());
    }

    if !allowed_hosts.iter().any(|a| a == &h_lower) {
        return Err((
            421,
            "Misdirected Request",
            format!("DNS rebinding protection: rejected non-loopback Host '{raw_host}'"),
        ));
    }

    if let Some(raw_origin) = origin_header.map(str::trim).filter(|s| !s.is_empty()) {
        let o_lower = raw_origin.to_ascii_lowercase();
        let mut allowed_origins = vec![
            format!("http://{cfg}:{port}"),
            format!("http://localhost:{port}"),
        ];
        if cfg == "127.0.0.1" || cfg == "localhost" {
            allowed_origins.push(format!("http://127.0.0.1:{port}"));
        }
        if cfg == "::1" {
            allowed_origins.push(format!("http://[::1]:{port}"));
        }
        if !allowed_origins.iter().any(|a| a == &o_lower) {
            return Err((
                403,
                "Forbidden",
                format!("DNS rebinding protection: rejected Origin '{raw_origin}'"),
            ));
        }
    }

    Ok(())
}

struct ParsedHttpRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_crlf_line<R: BufRead>(reader: &mut R, max_len: usize) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            break;
        }
        let len = available.len();
        buf.extend_from_slice(available);
        reader.consume(len);
        if buf.len() > max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header line too long",
            ));
        }
    }
    while matches!(buf.last(), Some(b'\r' | b'\n')) {
        buf.pop();
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

enum HttpParseError {
    Io,
    BadRequest(&'static str),
    PayloadTooLarge,
}

impl From<io::Error> for HttpParseError {
    fn from(_err: io::Error) -> Self {
        Self::Io
    }
}

fn read_chunked_body<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, HttpParseError> {
    let mut out = Vec::new();
    loop {
        let Some(size_line) = read_crlf_line(reader, 1024)? else {
            return Err(HttpParseError::Io);
        };
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_part, 16)
            .map_err(|_| HttpParseError::BadRequest("invalid chunk size in HTTP body"))?;
        if chunk_len == 0 {
            // Consume trailing headers up to empty line.
            while let Some(trailer) = read_crlf_line(reader, 4096)? {
                if trailer.is_empty() {
                    break;
                }
            }
            break;
        }
        let start = out.len();
        let next_len = start
            .checked_add(chunk_len)
            .ok_or(HttpParseError::PayloadTooLarge)?;
        if next_len > MAX_HTTP_BODY_BYTES {
            return Err(HttpParseError::PayloadTooLarge);
        }
        out.resize(next_len, 0);
        reader.read_exact(&mut out[start..next_len])?;
        let _ = read_crlf_line(reader, 64)?;
    }
    Ok(out)
}

fn parse_http_request<R: BufRead>(
    reader: &mut R,
) -> Result<Option<ParsedHttpRequest>, HttpParseError> {
    let Some(request_line) = read_crlf_line(reader, 8192)? else {
        return Ok(None);
    };
    if request_line.trim().is_empty() {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    if method.is_empty() {
        return Ok(None);
    }

    let mut headers = HashMap::new();
    while let Some(line) = read_crlf_line(reader, 16384)? {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        read_chunked_body(reader)?
    } else if let Some(raw_cl) = headers.get("content-length") {
        let cl_u64 = raw_cl
            .trim()
            .parse::<u64>()
            .map_err(|_| HttpParseError::BadRequest("invalid Content-Length header"))?;
        if cl_u64 > MAX_HTTP_BODY_BYTES as u64 {
            return Err(HttpParseError::PayloadTooLarge);
        }
        let cl = cl_u64 as usize;
        let mut buf = vec![0u8; cl];
        if cl > 0 {
            reader.read_exact(&mut buf)?;
        }
        buf
    } else {
        Vec::new()
    };

    Ok(Some(ParsedHttpRequest {
        method,
        target,
        headers,
        body,
    }))
}

fn write_http_response<W: Write>(
    writer: &mut W,
    status_code: u16,
    reason: &str,
    content_type: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    close: bool,
) -> io::Result<()> {
    write!(writer, "HTTP/1.1 {status_code} {reason}\r\n")?;
    if let Some(ct) = content_type {
        write!(writer, "Content-Type: {ct}\r\n")?;
    }
    write!(writer, "Content-Length: {}\r\n", body.len())?;
    write!(
        writer,
        "Connection: {}\r\n",
        if close { "close" } else { "keep-alive" }
    )?;
    for &(k, v) in extra_headers {
        write!(writer, "{k}: {v}\r\n")?;
    }
    write!(writer, "\r\n")?;
    if !body.is_empty() {
        writer.write_all(body)?;
    }
    writer.flush()
}

fn handle_client_connection(
    mut stream: TcpStream,
    server: Arc<McpServer>,
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
                    "error": format!("Payload Too Large: request body exceeds {} bytes limit", MAX_HTTP_BODY_BYTES)
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

        // 1. DNS Rebinding Protection
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

        // 2. Endpoint path matching (root "/" must NOT fall back to "/mcp")
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

        // 3. Dispatch HTTP Method
        let session_id = req
            .headers
            .get("mcp-session-id")
            .cloned()
            .unwrap_or_else(|| Uuid::new_v4().simple().to_string());

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
                // Stateless JSON response mode does not use standalone GET SSE streams (MCP spec §2.1 -> 405).
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
                    Err(e) => {
                        let err_resp = json!({
                            "jsonrpc": "2.0",
                            "id": Value::Null,
                            "error": {
                                "code": -32700,
                                "message": format!("Parse error: {e}")
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

                match server.handle_jsonrpc_value(parsed) {
                    None => {
                        // Notification or client response -> HTTP 202 Accepted with empty body.
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
}

/// 可随时优雅关闭的本地 Streamable HTTP MCP 服务句柄。
pub struct McpHttpServerHandle {
    host: String,
    bind_addr: SocketAddr,
    port: u16,
    path: String,
    url: String,
    shutdown: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<()>>,
}

impl McpHttpServerHandle {
    /// 启动本地回环 Streamable HTTP MCP 服务。
    ///
    /// - 强制校验 `host` 属于 `{"127.0.0.1", "localhost", "::1"}`；
    /// - 绑定前探测端口是否已被占用；
    /// - 在独立后台线程监听并处理请求。
    pub fn start(
        server: McpServer,
        host: &str,
        port: u16,
        path: &str,
    ) -> McpResult<Self> {
        let clean_host = validate_loopback_host(host)?;
        let clean_path = normalize_http_path(path);
        let bind_ip = resolve_bind_ip(&clean_host);
        let requested_addr = SocketAddr::new(bind_ip, port);

        if port != 0 && TcpStream::connect_timeout(&requested_addr, Duration::from_millis(40)).is_ok()
        {
            return Err(McpError::IoError(format!(
                "端口 {clean_host}:{port} 已被占用或无法监听，请更换端口后重试。"
            )));
        }

        let listener = TcpListener::bind(requested_addr).map_err(|e| {
            McpError::IoError(format!(
                "端口 {clean_host}:{port} 已被占用或无法监听，请更换端口后重试（{e}）。"
            ))
        })?;
        let bound_addr = listener.local_addr()?;
        let actual_port = bound_addr.port();
        let url_host = if clean_host == "::1" {
            "[::1]".to_string()
        } else {
            clean_host.clone()
        };
        let url = format!("http://{url_host}:{actual_port}{clean_path}");

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_bg = Arc::clone(&shutdown);
        let server_arc = Arc::new(server);
        let host_bg = clean_host.clone();
        let path_bg = clean_path.clone();

        let join_handle = thread::Builder::new()
            .name("tracedesk-mcp-http".to_string())
            .spawn(move || {
                for incoming in listener.incoming() {
                    if shutdown_bg.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(stream) = incoming else {
                        if shutdown_bg.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    };
                    let srv = Arc::clone(&server_arc);
                    let h = host_bg.clone();
                    let p = path_bg.clone();
                    let sd = Arc::clone(&shutdown_bg);
                    thread::spawn(move || {
                        handle_client_connection(stream, srv, h, actual_port, p, sd);
                    });
                }
            })?;

        Ok(Self {
            host: clean_host,
            bind_addr: bound_addr,
            port: actual_port,
            path: clean_path,
            url,
            shutdown,
            join_handle: Some(join_handle),
        })
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

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::Relaxed)
            && self
                .join_handle
                .as_ref()
                .is_some_and(|h| !h.is_finished())
    }

    /// 立即通知后台监听线程退出并等待优雅关闭。
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.join_handle.take() {
            // Wake the blocking `accept()` immediately by making a local loopback connect.
            let _ = TcpStream::connect_timeout(&self.bind_addr, Duration::from_millis(50));
            let _ = handle.join();
        }
    }
}

impl Drop for McpHttpServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 阻塞式运行 Streamable HTTP MCP 服务（供 CLI `--transport streamable-http` 调用）。
pub fn run_http_blocking(
    server: McpServer,
    host: &str,
    port: u16,
    path: &str,
) -> McpResult<()> {
    let mut handle = McpHttpServerHandle::start(server, host, port, path)?;
    eprintln!(
        "[TraceDesk MCP] Streamable HTTP listening on {}",
        handle.url()
    );
    if let Some(join) = handle.join_handle.take() {
        let _ = join.join();
    }
    Ok(())
}
