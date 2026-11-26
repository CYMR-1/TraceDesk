//! MCP `streamable-http` 传输实现：
//! - 严格仅允许绑定本机回环地址（`127.0.0.1` / `localhost` / `::1`）
//! - 内置 DNS 重绑定防护中间件（强制校验 `Host` 与 `Origin` 请求头，拦截非回环主机并返回 HTTP 421/403）
//! - 支持 `/mcp` 端点无状态 JSON-RPC 2.0 (`POST` / `DELETE` / `OPTIONS` / `GET`、`Mcp-Session-Id`、chunked 编码与 keep-alive)
//! - 提供可随时在毫秒级优雅关闭的 [`McpHttpServerHandle`]（供桌面端 UI 开关与命令行使用）

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use crate::service::{McpError, McpResult, sanitize_mcp_identity};
use crate::tools::{McpRequestContext, McpServer};

/// 默认 Streamable HTTP 监听地址（仅本机回环）。
pub const DEFAULT_HOST: &str = "127.0.0.1";

/// 默认 Streamable HTTP 监听端口。
pub const DEFAULT_PORT: u16 = 8765;

/// 默认 Streamable HTTP 挂载路径。
pub const DEFAULT_HTTP_PATH: &str = "/mcp";

/// 独立 CLI Streamable HTTP 服务的默认传输通道标识。
pub const DEFAULT_HTTP_TRANSPORT_LABEL: &str = "streamable-http";

/// 桌面端进程内托管 HTTP 服务的传输通道标识。
pub const DESKTOP_HTTP_TRANSPORT_LABEL: &str = "desktop-http";

/// 允许监听的回环地址白名单。
pub const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

/// 单个 Streamable HTTP 请求体允许的最大字节数（16 MiB），防止恶意超长请求体导致 OOM。
pub const MAX_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;

/// 单次 HTTP 请求允许的最大请求头数量，防止无限请求头导致内存膨胀。
pub const MAX_HTTP_HEADERS: usize = 64;

/// 分块传输（chunked）尾部 trailer 允许的最大行数。
pub const MAX_CHUNKED_TRAILERS: usize = 32;

/// `Mcp-Session-Id` 头允许的最大字节长度。
pub const MAX_SESSION_ID_BYTES: usize = 128;

/// 本地回环 HTTP MCP 服务允许同时处理的 TCP 连接上限，防止连接耗尽线程资源。
pub const MAX_CONCURRENT_HTTP_CONNS: usize = 64;

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
pub fn normalize_request_path(raw_path: &str) -> String {
    let clean = raw_path.trim().trim_end_matches('/');
    if clean.is_empty() {
        "/".to_string()
    } else if clean.starts_with('/') {
        clean.to_string()
    } else {
        format!("/{clean}")
    }
}

/// 校验并清理 `Mcp-Session-Id` 请求头，拒绝控制字符/空白/超长输入以防止 HTTP 响应头注入（CRLF 拆分）；
/// 若输入缺失或非法则自动生成新的随机 UUID 会话 ID。
pub fn sanitize_session_id(raw: Option<&str>) -> String {
    if let Some(trimmed) = raw.map(str::trim)
        && !trimmed.is_empty()
        && trimmed.len() <= MAX_SESSION_ID_BYTES
        && trimmed.bytes().all(|b| (0x21..=0x7E).contains(&b))
    {
        return trimmed.to_string();
    }
    Uuid::new_v4().simple().to_string()
}

/// 并发连接计数 RAII 守卫，离开作用域时自动归还连接名额。
pub struct HttpConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl HttpConnectionPermit {
    /// 尝试占用一个并发连接槽位；达到 `max` 上限时返回 `None`。
    pub fn try_acquire(active: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        let mut cur = active.load(Ordering::Relaxed);
        loop {
            if cur >= max {
                return None;
            }
            match active.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => {
                    return Some(Self {
                        active: Arc::clone(active),
                    });
                }
                Err(next) => cur = next,
            }
        }
    }
}

impl Drop for HttpConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
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

/// 通用 HTTP 客户端或浏览器 `User-Agent` 首段标识黑名单（不作为 MCP 客户端名称回退）。
const GENERIC_USER_AGENT_TOKENS: &[&str] = &[
    "mozilla",
    "curl",
    "wget",
    "python-requests",
    "python-urllib",
    "python-httpx",
    "httpx",
    "aiohttp",
    "urllib",
    "go-http-client",
    "node-fetch",
    "undici",
    "node",
    "axios",
    "got",
    "reqwest",
    "hyper",
    "okhttp",
    "java",
    "apache-httpclient",
    "libwww-perl",
    "ruby",
    "php",
    "winhttp",
    "powershell",
    "windows-powershell",
    "postmanruntime",
    "insomnia",
];

/// 从 HTTP `User-Agent` 头提取非通用客户端名称作为补充回退；通用库/浏览器 UA 返回 `None`。
pub fn extract_user_agent_client(raw_ua: &str) -> Option<String> {
    let sanitized = sanitize_mcp_identity(raw_ua)?;
    let first_token = sanitized
        .split_whitespace()
        .next()
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if first_token.is_empty()
        || GENERIC_USER_AGENT_TOKENS
            .iter()
            .any(|generic| *generic == first_token)
    {
        return None;
    }
    Some(sanitized)
}

/// 从小写键 HTTP 请求头、当前会话 ID 与传输通道标记构建 [`McpRequestContext`]。
///
/// 优先识别 `X-MCP-User` 与 `X-MCP-Client` / `X-Client-Name`，并以非通用 `User-Agent` 作为补充回退；
/// `transport_label` 为空时默认回退为 `"streamable-http"`。
pub fn request_context_from_http_headers_with_transport(
    headers: &HashMap<String, String>,
    session_id: String,
    transport_label: &str,
) -> McpRequestContext {
    let header_user = headers
        .get("x-mcp-user")
        .and_then(|v| sanitize_mcp_identity(v));
    let header_client = headers
        .get("x-mcp-client")
        .and_then(|v| sanitize_mcp_identity(v))
        .or_else(|| {
            headers
                .get("x-client-name")
                .and_then(|v| sanitize_mcp_identity(v))
        });
    let user_agent_client = headers
        .get("user-agent")
        .and_then(|v| extract_user_agent_client(v));
    let clean_transport = transport_label.trim();
    let transport = if clean_transport.is_empty() {
        DEFAULT_HTTP_TRANSPORT_LABEL.to_string()
    } else {
        clean_transport.to_string()
    };

    McpRequestContext {
        session_id: Some(session_id),
        header_user,
        header_client,
        user_agent_client,
        transport: Some(transport),
    }
}

/// 从小写键 HTTP 请求头与当前会话 ID 构建 [`McpRequestContext`]（默认传输通道标记为 `"streamable-http"`）。
///
/// 优先识别 `X-MCP-User` 与 `X-MCP-Client` / `X-Client-Name`，并以非通用 `User-Agent` 作为补充回退。
pub fn request_context_from_http_headers(
    headers: &HashMap<String, String>,
    session_id: String,
) -> McpRequestContext {
    request_context_from_http_headers_with_transport(
        headers,
        session_id,
        DEFAULT_HTTP_TRANSPORT_LABEL,
    )
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

/// 已解析的 HTTP/1.1 请求（供独立版与桌面内嵌 Streamable HTTP 服务共享）。
pub struct ParsedHttpRequest {
    pub method: String,
    pub target: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

fn read_crlf_line<R: BufRead>(
    reader: &mut R,
    max_len: usize,
) -> Result<Option<String>, HttpParseError> {
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
            // 在找到换行符的分支同样强制检查长度上限，避免单次 fill_buf 绕过 max_len。
            let slice = &available[..=pos];
            if buf.len().saturating_add(slice.len()) > max_len {
                reader.consume(pos + 1);
                return Err(HttpParseError::BadRequest("HTTP header line too long"));
            }
            buf.extend_from_slice(slice);
            reader.consume(pos + 1);
            break;
        }
        let len = available.len();
        if buf.len().saturating_add(len) > max_len {
            reader.consume(len);
            return Err(HttpParseError::BadRequest("HTTP header line too long"));
        }
        buf.extend_from_slice(available);
        reader.consume(len);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    // 拒绝行内裸回车符，防止请求走私与 HTTP 响应头拆分。
    if buf.contains(&b'\r') {
        return Err(HttpParseError::BadRequest(
            "invalid bare CR in HTTP header line",
        ));
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// HTTP 请求解析错误分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpParseError {
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
        if hex_part.is_empty() {
            return Err(HttpParseError::BadRequest("empty chunk size in HTTP body"));
        }
        let chunk_len = usize::from_str_radix(hex_part, 16)
            .map_err(|_| HttpParseError::BadRequest("invalid chunk size in HTTP body"))?;
        if chunk_len == 0 {
            // 读取并跳过尾部 chunked trailer 头直至遇到空行，同时限制最大行数防止 DoS。
            let mut trailer_count = 0usize;
            while let Some(trailer) = read_crlf_line(reader, 4096)? {
                if trailer.is_empty() {
                    break;
                }
                trailer_count += 1;
                if trailer_count > MAX_CHUNKED_TRAILERS {
                    return Err(HttpParseError::BadRequest(
                        "too many chunked trailer headers",
                    ));
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
        // 严格校验每个 chunk 数据后的 CRLF 终止空行，防止 keep-alive 流错位。
        match read_crlf_line(reader, 64)? {
            Some(ref term) if term.is_empty() => {}
            _ => {
                return Err(HttpParseError::BadRequest(
                    "invalid chunk terminator in HTTP body",
                ));
            }
        }
    }
    Ok(out)
}

/// 解析单条 HTTP/1.1 请求（支持 `Content-Length`、`Transfer-Encoding: chunked` 与安全头校验）。
pub fn parse_http_request<R: BufRead>(
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
    let mut header_count = 0usize;
    while let Some(line) = read_crlf_line(reader, 16384)? {
        if line.is_empty() {
            break;
        }
        header_count += 1;
        if header_count > MAX_HTTP_HEADERS {
            return Err(HttpParseError::BadRequest("too many HTTP headers"));
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err(HttpParseError::BadRequest("malformed HTTP header line"));
        };
        let key = k.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(HttpParseError::BadRequest("empty HTTP header name"));
        }
        let val = v.trim().to_string();
        // 拒绝重复的安全与分帧关键头，防止通过后置头覆盖绕过 DNS 重绑定检查或造成请求走私。
        if matches!(
            key.as_str(),
            "host" | "origin" | "content-length" | "transfer-encoding"
        ) && headers.contains_key(&key)
        {
            return Err(HttpParseError::BadRequest(
                "duplicate critical HTTP header",
            ));
        }
        headers.insert(key, val);
    }

    let has_te = headers.contains_key("transfer-encoding");
    let has_cl = headers.contains_key("content-length");
    if has_te && has_cl {
        return Err(HttpParseError::BadRequest(
            "conflicting Transfer-Encoding and Content-Length headers",
        ));
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

/// 输出完整 HTTP/1.1 响应报文并刷新流。
pub fn write_http_response<W: Write>(
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
    transport_label: String,
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

        // 1. DNS 重绑定防护校验
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

        // 2. 端点路径匹配（根路径 "/" 绝不能回退匹配到 "/mcp"）
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

        // 3. 按 HTTP 方法分发请求（清理并校验 Mcp-Session-Id 防止响应头注入）
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
                // 无状态 JSON 响应模式不支持独立的 GET SSE 流（依据 MCP 规范 §2.1 返回 405）。
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

                let ctx = request_context_from_http_headers_with_transport(
                    &req.headers,
                    session_id.clone(),
                    &transport_label,
                );
                match server.handle_jsonrpc_value_with_context(parsed, &ctx) {
                    None => {
                        // 通知消息或客户端响应 -> 返回 HTTP 202 Accepted 与空响应体。
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
    // 主动优雅关闭写半部，避免 Windows 上对端读取响应尾时出现 WSAECONNRESET。
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

/// 可随时优雅关闭的本地 Streamable HTTP MCP 服务句柄。
pub struct McpHttpServerHandle {
    host: String,
    bind_addr: SocketAddr,
    port: u16,
    path: String,
    url: String,
    transport_label: String,
    shutdown: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<()>>,
}

impl McpHttpServerHandle {
    /// 启动本地回环 Streamable HTTP MCP 服务（默认传输通道标记为 `"streamable-http"`）。
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
        Self::start_with_transport(server, host, port, path, DEFAULT_HTTP_TRANSPORT_LABEL)
    }

    /// 启动本地回环 Streamable HTTP MCP 服务，并显式注入遥测传输通道标记（例如 `"desktop-http"` 或 `"streamable-http"`）。
    pub fn start_with_transport(
        server: McpServer,
        host: &str,
        port: u16,
        path: &str,
        transport_label: &str,
    ) -> McpResult<Self> {
        let clean_host = validate_loopback_host(host)?;
        let clean_path = normalize_http_path(path);
        let clean_transport = {
            let trimmed = transport_label.trim();
            if trimmed.is_empty() {
                DEFAULT_HTTP_TRANSPORT_LABEL.to_string()
            } else {
                trimmed.to_string()
            }
        };
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

        // 独立 Streamable HTTP 服务默认启用跨进程文件遥测写入。
        server.ensure_default_file_activity_sink();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_bg = Arc::clone(&shutdown);
        let server_arc = Arc::new(server);
        let host_bg = clean_host.clone();
        let path_bg = clean_path.clone();
        let transport_bg = clean_transport.clone();

        let active_conns = Arc::new(AtomicUsize::new(0));
        let join_handle = thread::Builder::new()
            .name("tracedesk-mcp-http".to_string())
            .spawn(move || {
                for incoming in listener.incoming() {
                    if shutdown_bg.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(mut stream) = incoming else {
                        if shutdown_bg.load(Ordering::Relaxed) {
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
                    let srv = Arc::clone(&server_arc);
                    let h = host_bg.clone();
                    let p = path_bg.clone();
                    let t = transport_bg.clone();
                    let sd = Arc::clone(&shutdown_bg);
                    let _ = thread::Builder::new()
                        .name("tracedesk-mcp-http-conn".to_string())
                        .spawn(move || {
                            let _permit = permit;
                            handle_client_connection(stream, srv, h, actual_port, p, t, sd);
                        });
                }
            })?;

        Ok(Self {
            host: clean_host,
            bind_addr: bound_addr,
            port: actual_port,
            path: clean_path,
            url,
            transport_label: clean_transport,
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

    /// 返回当前 HTTP 服务实例注入的遥测传输通道标识（如 `"streamable-http"` 或 `"desktop-http"`）。
    pub fn transport_label(&self) -> &str {
        &self.transport_label
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
            // 发起本机回环连接以立即唤醒阻塞中的 `accept()`；若首次尝试未能立即唤醒则短时重试避免 join 卡死。
            for _ in 0..10 {
                if handle.is_finished() {
                    break;
                }
                let _ = TcpStream::connect_timeout(&self.bind_addr, Duration::from_millis(50));
                if handle.is_finished() {
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
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
