//! `tracedesk-desktop` 端到端集成测试，覆盖 IPC 命令、与 `frontend/src/types/ipc.ts` 的
//! JSON 契约对齐，以及内嵌 Streamable HTTP MCP 服务协调。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::tempdir;
use tracedesk_core::{AppPaths, verify_bundle};
use tracedesk_desktop_lib::AppState;
use tracedesk_desktop_lib::commands::{
    cmd_bookmark_search_hits, cmd_build_review_bundle, cmd_build_timeline,
    cmd_cancel_content_search, cmd_cancel_scan_partitions, cmd_cancel_verify_integrity,
    cmd_check_busy_before_close, cmd_clear_mcp_activities, cmd_close_case, cmd_create_case,
    cmd_examine_file, cmd_export_file, cmd_export_findings, cmd_export_fsstat, cmd_generate_report,
    cmd_get_app_paths, cmd_get_case_snapshot, cmd_get_guide_pages, cmd_get_mcp_status,
    cmd_get_tree_children, cmd_inspect_bundle_materials, cmd_list_audit_log, cmd_list_findings,
    cmd_list_mcp_activities, cmd_list_recent_cases, cmd_load_image, cmd_load_search_record,
    cmd_locate_file_in_scope, cmd_open_case, cmd_preview_file_image, cmd_preview_file_page,
    cmd_query_files_page, cmd_query_timeline_page, cmd_record_finding_note, cmd_register_source,
    cmd_scan_all_partitions, cmd_start_content_search, cmd_start_mcp_http, cmd_stop_mcp_http,
    cmd_suggest_case_dir, cmd_verify_integrity,
};

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .expect("src-tauri parent is repo root")
        .to_path_buf()
}

fn make_test_state(cases_dir: PathBuf) -> Arc<AppState> {
    let root = repo_root();
    let mut paths = AppPaths::from_root(root);
    paths.cases_dir = cases_dir;
    AppState::with_paths(paths)
}

fn demo_image_path() -> PathBuf {
    let p = repo_root().join("evidence").join("demo.dd");
    assert!(p.is_file(), "expected real demo fixture at {}", p.display());
    p
}

fn send_raw_http(port: u16, raw_req: &str) -> (u16, String) {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).expect("connect to local MCP HTTP server");
    stream.write_all(raw_req.as_bytes()).expect("write request");
    stream.flush().expect("flush request");

    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read response");
    let status_line = resp.lines().next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body_part = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (code, body_part)
}

fn send_http_request(port: u16, host_header: &str, body: &str) -> (u16, String) {
    let req = format!(
        "POST /mcp HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    send_raw_http(port, &req)
}

#[test]
fn full_desktop_ipc_workflow_and_json_contract_with_demo_dd() {
    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());
    let demo_dd = demo_image_path();

    // 1. 应用路径、suggest_case_dir 与指引页
    let paths_dto = cmd_get_app_paths(&state).expect("get_app_paths");
    let paths_json = serde_json::to_value(&paths_dto).expect("serialize AppPathsDto");
    assert!(paths_json.get("rootDir").and_then(Value::as_str).is_some());
    assert!(paths_json.get("casesDir").and_then(Value::as_str).is_some());
    assert!(paths_json.get("evidenceDir").and_then(Value::as_str).is_some());

    let suggested = cmd_suggest_case_dir(
        &state,
        "DEMO-IPC-01",
        "测试员",
        "FAT16镜像",
        Some(&cases_dir.to_string_lossy()),
    )
    .expect("suggest_case_dir");
    let sugg_json = serde_json::to_value(&suggested).expect("serialize SuggestCaseDirResponse");
    assert_eq!(sugg_json["folderName"], "DEMO-IPC-01-测试员-FAT16镜像");
    assert!(
        sugg_json["suggestedPath"]
            .as_str()
            .unwrap()
            .ends_with("DEMO-IPC-01-测试员-FAT16镜像")
    );

    let guides = cmd_get_guide_pages().expect("get_guide_pages");
    assert_eq!(guides.len(), 9);
    assert_eq!(guides[0].image, "/assets/guide/01_quickstart.png");
    assert_eq!(guides[8].image, "/assets/guide/09_mcp_dialog.png");

    // 2. 新建案件及快照 JSON 字段
    assert!(cmd_get_case_snapshot(&state).unwrap().is_none());
    let snap = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "DEMO-IPC-01",
        "测试员",
        "FAT16镜像",
        None,
    )
    .expect("create_case");
    let snap_json = serde_json::to_value(&snap).expect("serialize CaseSnapshot");
    assert_eq!(snap_json["custodyState"], "active");
    assert_eq!(snap_json["number"], "DEMO-IPC-01");
    assert!(snap_json["summaryLine1"].as_str().unwrap().contains("DEMO-IPC-01"));
    assert_eq!(snap_json["summaryLine2"], "尚未加载镜像");
    assert_eq!(snap_json["inventoryCount"], 0);
    assert!(snap_json["evidence"].is_null());

    let recent = cmd_list_recent_cases(&state).expect("list_recent_cases");
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].number, "DEMO-IPC-01");

    // 3. 加载真实 demo.dd 镜像并扫描全部分区
    let snap = cmd_load_image(&state, &demo_dd.to_string_lossy(), None).expect("load_image");
    assert_eq!(snap.custody_state, "verified");
    let ev = snap.evidence.as_ref().expect("evidence loaded");
    let fixed_sha = ev.sha256.clone().expect("sha256 fixed");
    assert_eq!(fixed_sha.len(), 64);
    assert!(!ev.partitions.is_empty());
    let part_offset = ev.partitions[0].offset;

    let scan_res = cmd_scan_all_partitions(&state, None).expect("scan_all_partitions");
    assert!(scan_res.completed);
    assert!(scan_res.snapshot.inventory_count > 0);
    assert!(!scan_res.snapshot.needs_partition_scan);

    // 4. 完整性校验与来源登记（不匹配 -> error，一致 -> verified）
    let verify_res = cmd_verify_integrity(&state, None).expect("verify_integrity");
    let verify_json = serde_json::to_value(&verify_res).expect("serialize verify");
    assert_eq!(verify_json["ok"], true);
    assert_eq!(verify_json["initialFixed"], false);
    assert_eq!(verify_json["snapshot"]["custodyState"], "verified");

    let mismatch_snap = cmd_register_source(
        &state,
        "EVID-01",
        "测试交付方",
        "2026-11-21 10:00 UTC+8",
        "dd 1.0",
        &"0".repeat(64),
    )
    .expect("register_source mismatch");
    assert_eq!(mismatch_snap.custody_state, "error");

    let matched_snap = cmd_register_source(
        &state,
        "EVID-01",
        "测试交付方",
        "2026-11-21 10:00 UTC+8",
        "dd 1.0",
        &fixed_sha,
    )
    .expect("register_source match");
    assert_eq!(matched_snap.custody_state, "verified");
    let matched_json = serde_json::to_value(&matched_snap).unwrap();
    assert_eq!(
        matched_json["evidence"]["provenance"]["expectedSha256"],
        fixed_sha
    );
    assert_eq!(
        matched_json["evidence"]["sourceStatus"],
        "交付方摘要与本机固定值一致"
    );

    // 5. 导出 fsstat
    let fsstat_res = cmd_export_fsstat(&state, part_offset).expect("export_fsstat");
    assert!(PathBuf::from(&fsstat_res.path).is_file());

    // 6. 目录树懒加载、query_files_page（含 logFilter 审计检查）与 locate_file_in_scope
    let root_tree = cmd_get_tree_children(&state, part_offset, "", None).expect("get_tree_children");
    assert!(!root_tree.nodes.is_empty());
    assert!(root_tree.nodes.iter().any(|n| n.kind == "directory" && n.scope_path.as_deref() == Some("DOCS")));

    let audit_before_filter = cmd_list_audit_log(&state, "", None, None, Some("FILE_FILTER"), None, "seq", false)
        .expect("audit before filter");
    assert_eq!(audit_before_filter.records.len(), 0);

    // 未开启 logFilter 查询 -> 不得写入 FILE_FILTER 审计记录
    let page_no_log = cmd_query_files_page(
        &state,
        Some(part_offset),
        Some("DOCS".to_string()),
        ".txt",
        "case",
        "active",
        0,
        100,
        Some(false),
    )
    .expect("query_files_page no log");
    assert_eq!(page_no_log.total, 1);
    assert_eq!(page_no_log.items[0].path, "DOCS/CASE.TXT");
    assert!(page_no_log.items[0].ctime.starts_with("不支持（FAT"));

    let audit_still_zero = cmd_list_audit_log(&state, "", None, None, Some("FILE_FILTER"), None, "seq", false)
        .expect("audit still zero");
    assert_eq!(audit_still_zero.records.len(), 0);

    // 开启 logFilter = true 查询 -> 精确写入 1 条 FILE_FILTER 审计记录
    let page_with_log = cmd_query_files_page(
        &state,
        None,
        None,
        ".txt",
        "CASE",
        "all",
        0,
        100,
        Some(true),
    )
    .expect("query_files_page with log");
    assert!(page_with_log.total >= 1);
    let audit_after_filter = cmd_list_audit_log(&state, "", None, None, Some("FILE_FILTER"), None, "seq", false)
        .expect("audit after filter");
    assert_eq!(audit_after_filter.records.len(), 1);

    let case_txt_id = page_no_log.items[0].entry_id.clone();
    let located = cmd_locate_file_in_scope(&state, &case_txt_id).expect("locate_file_in_scope");
    assert_eq!(located.scope_offset, part_offset);
    assert_eq!(located.scope_path, "DOCS");

    // 7. 文件分页预览（UTF-8 + HEX）与非图片预览
    let preview = cmd_preview_file_page(&state, &case_txt_id, 0, Some(4096), "UTF-8")
        .expect("preview_file_page");
    let preview_json = serde_json::to_value(&preview).expect("serialize PreviewPageResponse");
    assert!(preview.text.contains("Case note inside a nested directory."));
    assert_eq!(preview.hex_rows[0].offset_hex, "00000000");
    assert!(preview.hex_rows[0].bytes_hex.starts_with("43 61 73 65"));
    assert!(preview_json.get("size").is_some());
    assert!(preview_json.get("recordedSize").is_some());
    assert!(preview_json.get("isImageCandidate").is_some());

    let img_preview = cmd_preview_file_image(&state, &case_txt_id).expect("preview_file_image");
    assert!(!img_preview.ok);

    // 8. 导出文件、检视（哈希 + 比对）、记录笔记、查询并导出取证发现
    let exported = cmd_export_file(&state, &case_txt_id).expect("export_file");
    assert_eq!(exported.title, "导出成功");
    assert!(PathBuf::from(&exported.path).is_file());

    let hash_res = cmd_examine_file(&state, &case_txt_id, None).expect("examine_file hash");
    assert_eq!(hash_res.title, "计算文件 SHA-256");
    assert_eq!(hash_res.result, "成功");
    assert_eq!(hash_res.sha256.len(), 64);

    let cmp_res = cmd_examine_file(&state, &case_txt_id, Some(&exported.path))
        .expect("examine_file compare");
    assert_eq!(cmp_res.title, "校验文件一致性");
    assert_eq!(cmp_res.result, "一致");
    assert_eq!(cmp_res.comparison_sha256.as_deref(), Some(hash_res.sha256.as_str()));

    cmd_record_finding_note(&state, &case_txt_id, "关键演示取证笔记")
        .expect("record_finding_note");

    let findings = cmd_list_findings(&state, None, None, Some("关键演示"), "latest", false)
        .expect("list_findings");
    assert_eq!(findings.groups.len(), 1);
    assert_eq!(findings.groups[0].subject, "DOCS/CASE.TXT");
    assert_eq!(findings.groups[0].count, 3); // 包含 FILE_HASH、FILE_COMPARE 与 FILE_NOTE 共 3 条记录

    let group_keys: Vec<String> = findings.groups.iter().map(|g| g.group_key.clone()).collect();
    let exp_findings = cmd_export_findings(&state, &group_keys).expect("export_findings");
    assert_eq!(exp_findings.exported_count, 1);
    assert_eq!(exp_findings.failed_count, 0);
    assert!(PathBuf::from(&exp_findings.summary_path).is_file());

    // 9. 构建 MACB 时间线并分页查询
    let tl_build = cmd_build_timeline(&state).expect("build_timeline");
    assert!(tl_build.total > 0);
    assert!(!tl_build.filter_options.events.is_empty());

    let tl_page = cmd_query_timeline_page(&state, "CASE.TXT", Some("M 内容修改"), None, None, "seq", false, 0, 100)
        .expect("query_timeline_page");
    assert!(tl_page.total >= 1);
    assert!(tl_page.items.iter().all(|r| r.event == "M 内容修改"));

    // 10. 内容搜索（HEX："6E 6F 74 65" -> 命中 DOCS/CASE.TXT 字节偏移 5 处的 "note"）、保存书签与重载记录
    let search_res = cmd_start_content_search(&state, "6E 6F 74 65", "HEX", None, None)
        .expect("start_content_search");
    assert_eq!(search_res.needle_hex, "6e6f7465");

    let bookmark_res = cmd_bookmark_search_hits(&state, &search_res.search_id, &[0])
        .expect("bookmark_search_hits");
    assert_eq!(bookmark_res.saved_count, 1);

    // 验证历史搜索记录可重新加载
    let report_name = {
        let searches = state.searches.lock().unwrap();
        searches
            .get(&search_res.search_id)
            .and_then(|s| s.report_name.clone())
            .expect("search report saved")
    };
    let reloaded_hits = cmd_load_search_record(&state, &report_name).expect("load_search_record");
    assert!(reloaded_hits.iter().any(|h| h.path == "DOCS/CASE.TXT" && h.pos == 5));

    // 11. 生成报告与复核包材料检查（包含缺失导出副本检测）
    let report_res = cmd_generate_report(&state).expect("generate_report");
    let report_text = std::fs::read_to_string(&report_res.path).expect("read report.md");
    assert!(report_text.contains("# 电子数据取证报告"));
    assert!(report_text.contains("## 适用边界"));

    // 删除首个导出文件以测试缺失材料检测
    std::fs::remove_file(&exported.path).expect("simulate missing exported copy");
    let materials = cmd_inspect_bundle_materials(&state).expect("inspect_bundle_materials");
    assert!(materials.exports.iter().any(|e| !e.exists));
    assert!(!materials.missing_text.is_empty());
    assert!(!materials.searches.is_empty());

    let avail_exports: Vec<usize> = materials
        .exports
        .iter()
        .filter(|e| e.exists)
        .map(|e| e.index)
        .collect();
    let avail_searches: Vec<usize> = materials
        .searches
        .iter()
        .filter(|s| s.exists)
        .map(|s| s.index)
        .collect();

    let bundle_res = cmd_build_review_bundle(&state, Some(avail_exports), Some(avail_searches))
        .expect("build_review_bundle");
    let bundle_path = PathBuf::from(&bundle_res.path);
    assert!(bundle_path.is_file());
    let verified_count = verify_bundle(&bundle_path, None).expect("verify_bundle passed");
    assert!(verified_count >= 6);

    // 12. 审计日志校验 + 取消/忙碌状态辅助检查 + 重新打开与关闭案件
    let audit = cmd_list_audit_log(&state, "", None, None, None, None, "seq", true)
        .expect("list_audit_log");
    assert!(audit.valid);
    assert!(!audit.records.is_empty());
    assert!(audit.records[0].seq > audit.records.last().unwrap().seq);

    assert!(!cmd_check_busy_before_close(&state).unwrap().busy);
    assert!(cmd_cancel_verify_integrity(&state).unwrap().cancelled);
    assert!(cmd_cancel_scan_partitions(&state).unwrap().cancelled);
    assert!(cmd_cancel_content_search(&state, &search_res.search_id).unwrap().cancelled);

    let case_dir_str = snap.case_dir.clone();
    assert!(cmd_close_case(&state).expect("close_case").closed);
    assert!(cmd_get_case_snapshot(&state).unwrap().is_none());

    let reopened = cmd_open_case(&state, &case_dir_str).expect("open_case");
    assert_eq!(reopened.number, "DEMO-IPC-01");
    assert!(cmd_close_case(&state).expect("final close_case").closed);
}

#[test]
fn embedded_mcp_http_server_and_case_lock_coordination() {
    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());
    let demo_dd = demo_image_path();

    // 在桌面端 AppState 中打开案件（持有 case.lock）
    let snap = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "MCP-COORD-01",
        "桌面人员",
        "协调测试",
        None,
    )
    .expect("create_case");
    cmd_load_image(&state, &demo_dd.to_string_lossy(), None).expect("load_image");
    cmd_scan_all_partitions(&state, None).expect("scan_all_partitions");

    // 在 127.0.0.1 上分配一个空闲临时端口
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let st_before = cmd_get_mcp_status(&state, Some(port)).expect("get_mcp_status");
    assert!(!st_before.running);
    assert_eq!(st_before.tools.len(), 19);
    assert_eq!(st_before.active_case_number.as_deref(), Some("MCP-COORD-01"));

    let st_started = cmd_start_mcp_http(&state, port).expect("start_mcp_http");
    assert!(st_started.running);
    assert_eq!(st_started.url, format!("http://127.0.0.1:{port}/mcp"));

    let host = format!("127.0.0.1:{port}");
    let ping_body = json!({"jsonrpc":"2.0","id":1,"method":"ping"}).to_string();

    // 1. DNS 重绑定与 HTTP 安全加固校验
    // 1a. 缺失 Host 请求头 -> 返回 421 Misdirected Request
    let (code_no_host, _) = send_raw_http(
        port,
        &format!(
            "POST /mcp HTTP/1.1\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {ping_body}",
            ping_body.len()
        ),
    );
    assert_eq!(code_no_host, 421);

    // 1b. 非本地 Host 请求头 -> 返回 421 Misdirected Request
    let (code_bad_host, _) = send_http_request(port, "evil.example.com:8765", &ping_body);
    assert_eq!(code_bad_host, 421);

    // 1c. 外部 Origin 请求头 -> 返回 403 Forbidden
    let (code_bad_origin, _) = send_raw_http(
        port,
        &format!(
            "POST /mcp HTTP/1.1\r\n\
             Host: {host}\r\n\
             Origin: https://evil.example.com\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {ping_body}",
            ping_body.len()
        ),
    );
    assert_eq!(code_bad_origin, 403);

    // 1d. 根路径 POST / 必须返回 404（不得回退至 /mcp），而 POST /mcp/ 返回 200
    let (code_root, _) = send_raw_http(
        port,
        &format!(
            "POST / HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {ping_body}",
            ping_body.len()
        ),
    );
    assert_eq!(code_root, 404);

    let (code_slash, _) = send_raw_http(
        port,
        &format!(
            "POST /mcp/ HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {ping_body}",
            ping_body.len()
        ),
    );
    assert_eq!(code_slash, 200);

    // 1e. 非法 Content-Length 返回 400 Bad Request；超过 16 MiB 返回 413 Payload Too Large
    let (code_bad_cl, _) = send_raw_http(
        port,
        &format!(
            "POST /mcp HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: not-a-number\r\n\
             Connection: close\r\n\r\n"
        ),
    );
    assert_eq!(code_bad_cl, 400);

    let (code_huge_cl, _) = send_raw_http(
        port,
        &format!(
            "POST /mcp HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 999999999\r\n\
             Connection: close\r\n\r\n"
        ),
    );
    assert_eq!(code_huge_cl, 413);

    // 1f. 分块传输（chunked）请求超过 16 MiB -> 返回 413 Payload Too Large
    let (code_huge_chunk, _) = send_raw_http(
        port,
        &format!(
            "POST /mcp HTTP/1.1\r\n\
             Host: {host}\r\n\
             Transfer-Encoding: chunked\r\n\
             Connection: close\r\n\r\n\
             1000001\r\n"
        ),
    );
    assert_eq!(code_huge_chunk, 413);

    // 2. initialize 与 tools/list（必须暴露包含 properties/required/additionalProperties=false 的完整 JSON Schema）
    let (code_init, body_init) = send_http_request(
        port,
        &host,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}})
            .to_string(),
    );
    assert_eq!(code_init, 200);
    let init_val: Value = serde_json::from_str(&body_init).expect("parse init");
    assert_eq!(init_val["result"]["serverInfo"]["name"], "tracedesk_mcp");

    let (code_tools, body_tools) = send_http_request(
        port,
        &host,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
    );
    assert_eq!(code_tools, 200);
    let tools_val: Value = serde_json::from_str(&body_tools).expect("parse tools");
    let tools_arr = tools_val["result"]["tools"].as_array().unwrap();
    assert_eq!(tools_arr.len(), 19);
    let record_tool = tools_arr
        .iter()
        .find(|t| t["name"] == "tracedesk_record_finding")
        .expect("tracedesk_record_finding present");
    assert_eq!(record_tool["inputSchema"]["additionalProperties"], false);
    assert!(record_tool["inputSchema"]["properties"]["case_dir"].is_object());
    assert!(record_tool["inputSchema"]["properties"]["path"].is_object());
    assert!(record_tool["inputSchema"]["properties"]["note"].is_object());

    // 3. 在桌面端持有 case.lock 期间，通过 FastMCP 嵌套 `{"params": ...}` 及
    //    response_format="json" 调用 tracedesk_record_finding
    let (code_call, body_call) = send_http_request(
        port,
        &host,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_record_finding",
                "arguments": {
                    "params": {
                        "case_dir": snap.case_dir,
                        "path": "DOCS/CASE.TXT",
                        "note": "来自本地 HTTP MCP 协同写入的取证发现",
                        "actor": "ai-assistant",
                        "response_format": "json"
                    }
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code_call, 200);
    let call_val: Value = serde_json::from_str(&body_call).expect("parse tool call");
    assert_eq!(call_val["result"]["isError"], false);
    let payload_text = call_val["result"]["content"][0]["text"]
        .as_str()
        .expect("json text");
    let payload_json: Value = serde_json::from_str(payload_text).expect("valid JSON output");
    assert_eq!(payload_json["origin"], "mcp");
    assert_eq!(payload_json["actor"], "ai-assistant");
    assert_eq!(payload_json["note"], "来自本地 HTTP MCP 协同写入的取证发现");

    // 3b. 使用合法的 Transfer-Encoding: chunked 请求并按契约参数调用 tracedesk_list_files
    let chunk_json = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "tracedesk_list_files",
            "arguments": {
                "case_dir": snap.case_dir,
                "status": "all",
                "response_format": "json"
            }
        }
    })
    .to_string();
    let chunked_req = format!(
        "POST /mcp HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n\
         {:x}\r\n{chunk_json}\r\n0\r\n\r\n",
        chunk_json.len()
    );
    let (code_chunk, body_chunk) = send_raw_http(port, &chunked_req);
    assert_eq!(code_chunk, 200);
    let chunk_val: Value = serde_json::from_str(&body_chunk).expect("parse chunked tool call");
    assert_eq!(chunk_val["result"]["isError"], false);
    let list_text = chunk_val["result"]["content"][0]["text"]
        .as_str()
        .expect("list json text");
    let list_json: Value = serde_json::from_str(list_text).expect("valid list JSON");
    assert!(list_json["total"].as_u64().unwrap_or(0) >= 13);

    // 4. 桌面端审计日志必须立即可见 origin="mcp" 的 MCP 记录且哈希链校验通过
    let audit = cmd_list_audit_log(&state, "", Some("MCP"), None, None, None, "seq", true)
        .expect("list_audit_log after mcp");
    assert!(audit.valid);
    assert_eq!(audit.records.len(), 1);
    assert_eq!(audit.records[0].origin, "mcp");
    assert_eq!(audit.records[0].origin_label, "MCP · ai-assistant");
    assert_eq!(audit.records[0].mcp_user.as_deref(), Some("ai-assistant"));
    assert_eq!(audit.records[0].action, "FILE_NOTE");

    let st_stopped = cmd_stop_mcp_http(&state).expect("stop_mcp_http");
    assert!(!st_stopped.running);
    let _ = cmd_close_case(&state);
}

/// 发送原始 HTTP 请求并解析 `(状态码, 响应头小写映射, 响应体字符串)`。
fn send_raw_http_with_headers(port: u16, raw_request: &str) -> (u16, std::collections::HashMap<String, String>, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect local mcp http");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(raw_request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let mut headers = std::collections::HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    (code, headers, body.to_string())
}

#[test]
fn desktop_embedded_mcp_http_caller_identity_and_audit_filter() {
    let tmp = tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());
    let demo_dd = demo_image_path();

    let snap = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "DESK-MCP-WHO-01",
        "桌面取证员",
        "桌面端MCP来源使用者回归测试",
        None,
    )
    .expect("create case");
    cmd_load_image(&state, &demo_dd.to_string_lossy(), None).expect("load image");
    cmd_scan_all_partitions(&state, None).expect("scan partitions");

    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let st_running = cmd_start_mcp_http(&state, port).expect("start desktop mcp http");
    assert!(st_running.running);
    let host = format!("127.0.0.1:{port}");

    // 1. 客户端通过 initialize 上报 clientInfo = Cursor 1.5，服务端返回 Mcp-Session-Id 头。
    let init_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "Cursor", "version": "1.5" }
        }
    })
    .to_string();
    let (init_code, init_headers, _) = send_raw_http_with_headers(
        port,
        &format!(
            "POST /mcp HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {init_body}",
            init_body.len()
        ),
    );
    assert_eq!(init_code, 200);
    let sid = init_headers
        .get("mcp-session-id")
        .cloned()
        .expect("桌面端内嵌 HTTP MCP 必须返回 Mcp-Session-Id");

    // 2. 携带该 Mcp-Session-Id 调用 tracedesk_record_finding（不传 actor）-> 记录为 Cursor 1.5。
    let call_cursor_body = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "tracedesk_record_finding",
            "arguments": {
                "case_dir": snap.case_dir,
                "path": "DOCS/CASE.TXT",
                "partition_offset": 2048,
                "note": "桌面端内嵌 MCP 会话标记测试",
                "response_format": "json"
            }
        }
    })
    .to_string();
    let (code_cursor, _, body_cursor) = send_raw_http_with_headers(
        port,
        &format!(
            "POST /mcp HTTP/1.1\r\n\
             Host: {host}\r\n\
             Mcp-Session-Id: {sid}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {call_cursor_body}",
            call_cursor_body.len()
        ),
    );
    assert_eq!(code_cursor, 200);
    let cursor_rpc: Value = serde_json::from_str(&body_cursor).expect("parse cursor rpc");
    assert_eq!(cursor_rpc["result"]["isError"], false);

    // 3. 携带 X-MCP-User + X-MCP-Client 请求头 -> 覆盖为 “赵六 / Claude Desktop”。
    let call_hdr_body = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "tracedesk_record_finding",
            "arguments": {
                "case_dir": snap.case_dir,
                "path": "DOCS/CASE.TXT",
                "partition_offset": 2048,
                "note": "桌面端 HTTP 头使用者标记测试",
                "response_format": "json"
            }
        }
    })
    .to_string();
    let (code_hdr, _, body_hdr) = send_raw_http_with_headers(
        port,
        &format!(
            "POST /mcp HTTP/1.1\r\n\
             Host: {host}\r\n\
             Mcp-Session-Id: {sid}\r\n\
             X-MCP-User: 赵六\r\n\
             X-MCP-Client: Claude Desktop\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {call_hdr_body}",
            call_hdr_body.len()
        ),
    );
    assert_eq!(code_hdr, 200);
    let hdr_rpc: Value = serde_json::from_str(&body_hdr).expect("parse hdr rpc");
    assert_eq!(hdr_rpc["result"]["isError"], false);

    // 4. 校验桌面端 list_audit_log：按 “mcp” / “MCP” 筛出全部 MCP 记录，并支持按使用者关键词检索。
    let all_mcp = cmd_list_audit_log(&state, "", Some("mcp"), None, None, None, "seq", true)
        .expect("按 mcp 筛选");
    assert!(all_mcp.valid);
    assert_eq!(all_mcp.records.len(), 2);
    assert!(all_mcp.filter_options.origins.contains(&"人工".to_string()));
    assert!(all_mcp.filter_options.origins.contains(&"MCP".to_string()));
    assert!(
        all_mcp
            .filter_options
            .origins
            .contains(&"MCP · Cursor 1.5".to_string())
    );
    assert!(
        all_mcp
            .filter_options
            .origins
            .contains(&"MCP · 赵六 / Claude Desktop".to_string())
    );

    let all_mcp_upper = cmd_list_audit_log(&state, "", Some("MCP"), None, None, None, "seq", true)
        .expect("按 MCP 筛选");
    assert_eq!(all_mcp_upper.records.len(), 2);

    let by_cursor_kw = cmd_list_audit_log(&state, "Cursor 1.5", None, None, None, None, "seq", true)
        .expect("按 Cursor 1.5 关键词搜索");
    assert_eq!(by_cursor_kw.records.len(), 1);
    assert_eq!(by_cursor_kw.records[0].origin_label, "MCP · Cursor 1.5");
    assert_eq!(
        by_cursor_kw.records[0].mcp_user.as_deref(),
        Some("Cursor 1.5")
    );

    let by_claude_kw =
        cmd_list_audit_log(&state, "Claude Desktop", None, None, None, None, "seq", true)
            .expect("按 Claude Desktop 关键词搜索");
    assert_eq!(by_claude_kw.records.len(), 1);
    assert_eq!(
        by_claude_kw.records[0].origin_label,
        "MCP · 赵六 / Claude Desktop"
    );
    assert_eq!(
        by_claude_kw.records[0].mcp_user.as_deref(),
        Some("赵六 / Claude Desktop")
    );

    // 5. 校验桌面端 list_findings 同步携带 originLabel 与 mcpUser。
    let findings = cmd_list_findings(&state, None, None, Some("Cursor"), "seq", false)
        .expect("按 Cursor 搜索取证发现");
    assert_eq!(findings.groups.len(), 1);
    assert!(
        findings.groups[0]
            .records
            .iter()
            .any(|r| r.origin_label.as_deref() == Some("MCP · Cursor 1.5")
                && r.mcp_user.as_deref() == Some("Cursor 1.5"))
    );

    // 6. 生成复核包并验签通过。
    let bundle_res = cmd_build_review_bundle(&state, None, None).expect("生成复核包");
    let verified = verify_bundle(Path::new(&bundle_res.path), None).expect("复核包验签通过");
    assert!(verified >= 5);

    let _ = cmd_stop_mcp_http(&state);
    let _ = cmd_close_case(&state);
}

#[test]
fn desktop_mcp_activity_telemetry_tailing_filter_and_clear() {
    use tracedesk_mcp::{McpActivityRecord, append_activity_record, now_east8_millis};

    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    let logs_dir = tmp.path().join("logs");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    std::fs::create_dir_all(&logs_dir).expect("mkdir logs");

    let mut paths = AppPaths::from_root(repo_root());
    paths.cases_dir = cases_dir.clone();
    paths.logs_dir = logs_dir.clone();
    let state = AppState::with_paths(paths.clone());

    // 启动后台尾随线程，测试其随 AppState 正常运行并在 shutdown_all 优雅退出。
    state.start_activity_tailer();

    // 1. 新建案件并加载 demo.dd，随后启动桌面内嵌 desktop-http MCP 服务。
    let snap = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "TELEM-DESK-01",
        "桌面测试员",
        "FAT16镜像",
        None,
    )
    .expect("create_case");
    let _ = cmd_load_image(&state, &demo_image_path().to_string_lossy(), None).expect("load_image");
    let _ = cmd_scan_all_partitions(&state, None).expect("scan_all");

    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = probe.local_addr().expect("local_addr").port();
    drop(probe);
    let _ = cmd_start_mcp_http(&state, port).expect("start_mcp_http");
    let host = format!("127.0.0.1:{port}");

    // 2. 通过 desktop-http 执行 initialize、只读工具、写入工具、资源读取与一次失败工具调用。
    let init_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "Antigravity", "version": "1.0" }
        }
    })
    .to_string();
    let (code_init, hdrs_init, _) = send_raw_http_with_headers(
        port,
        &format!(
            "POST /mcp HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {init_body}",
            init_body.len()
        ),
    );
    assert_eq!(code_init, 200);
    let sid = hdrs_init
        .get("mcp-session-id")
        .cloned()
        .expect("Mcp-Session-Id");

    let send_with_sid = |body: &str| {
        send_raw_http_with_headers(
            port,
            &format!(
                "POST /mcp HTTP/1.1\r\n\
                 Host: {host}\r\n\
                 Mcp-Session-Id: {sid}\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n\
                 {body}",
                body.len()
            ),
        )
    };

    // 2a. 只读工具：案件总览
    let (c1, _, _) = send_with_sid(
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_get_case_summary",
                "arguments": { "case_dir": snap.case_dir, "response_format": "json" }
            }
        })
        .to_string(),
    );
    assert_eq!(c1, 200);

    // 2b. 受控写入工具：记录取证发现（作用于当前打开案件）
    let (c2, _, _) = send_with_sid(
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_record_finding",
                "arguments": {
                    "case_dir": snap.case_dir,
                    "path": "DOCS/CASE.TXT",
                    "partition_offset": 2048,
                    "note": "桌面内嵌 HTTP 实时过程监控测试",
                    "response_format": "json"
                }
            }
        })
        .to_string(),
    );
    assert_eq!(c2, 200);

    // 2c. 失败调用：未知工具名
    let (c3, _, _) = send_with_sid(
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_non_existent_tool",
                "arguments": {}
            }
        })
        .to_string(),
    );
    assert_eq!(c3, 200);

    // 2d. 资源读取
    let (c4, _, _) = send_with_sid(
        &json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/read",
            "params": { "uri": "tracedesk://guide/workflow" }
        })
        .to_string(),
    );
    assert_eq!(c4, 200);

    // 3. 模拟外部独立 stdio 进程向 logs/mcp-activity.jsonl 追加 started -> completed 事件。
    let log_path = state.activity_log_path();
    assert!(log_path.is_file(), "desktop-http 应同步落盘 mcp-activity.jsonl");
    let ext_call_id = "ext-stdio-call-001".to_string();
    let ext_started = McpActivityRecord {
        id: "ext-evt-start".to_string(),
        call_id: ext_call_id.clone(),
        timestamp: now_east8_millis(),
        phase: "started".to_string(),
        transport: "stdio".to_string(),
        client: "Cursor".to_string(),
        session_id: Some("stdio-sess-9".to_string()),
        method: "tools/call".to_string(),
        tool_name: Some("tracedesk_search_content".to_string()),
        tool_title: "搜索文件内容".to_string(),
        category: "文件分析".to_string(),
        read_only: false,
        case_dir: Some(snap.case_dir.clone()),
        case_number: Some("TELEM-DESK-01".to_string()),
        params_summary: "query=\"accountNum\" · encoding=\"UTF-8\"".to_string(),
        params_json: "{\n  \"query\": \"accountNum\"\n}".to_string(),
        duration_ms: None,
        result_summary: "执行中...".to_string(),
        response_preview: None,
        error: None,
    };
    let ext_done = McpActivityRecord {
        id: "ext-evt-done".to_string(),
        call_id: ext_call_id,
        timestamp: now_east8_millis(),
        phase: "completed".to_string(),
        duration_ms: Some(135),
        result_summary: "执行成功（返回 1,024 字符）".to_string(),
        response_preview: Some("# 搜索结果\n命中 3 处".to_string()),
        ..ext_started.clone()
    };
    append_activity_record(&log_path, &ext_started).expect("append ext started");
    append_activity_record(&log_path, &ext_done).expect("append ext done");

    // 稍候让后台 350ms 尾随线程（或即时刷新）吸收外部记录，同时确保 desktop-http 记录不重复。
    std::thread::sleep(Duration::from_millis(450));

    // 4. 校验 list_mcp_activities 全量合并、JSON camelCase 契约、多维筛选与统计。
    let full = cmd_list_mcp_activities(&state, None, None, None, None, None)
        .expect("list_mcp_activities");
    assert_eq!(full.activities.len(), 6, "5 次 desktop-http + 1 次外部 stdio 合并后应为 6 条");
    assert_eq!(full.stats.total_calls, 6);
    assert_eq!(full.stats.running_calls, 0);
    assert_eq!(full.stats.succeeded_calls, 5);
    assert_eq!(full.stats.failed_calls, 1);
    assert_eq!(full.stats.read_only_calls, 4);
    assert_eq!(full.stats.write_calls, 2);
    assert!(full.stats.active_clients.contains(&"Antigravity 1.0".to_string()));
    assert!(full.stats.active_clients.contains(&"Cursor".to_string()));
    assert_eq!(
        full.stats
            .tool_stats
            .get("tracedesk_search_content")
            .map(|s| (s.calls, s.failures, s.avg_duration_ms)),
        Some((1, 0, 135))
    );

    // 校验 JSON 字段严格符合 camelCase 前端契约。
    let full_json = serde_json::to_value(&full).expect("serialize McpActivitySnapshot");
    assert_eq!(full_json["stats"]["totalCalls"], 6);
    assert_eq!(full_json["stats"]["runningCalls"], 0);
    assert_eq!(full_json["stats"]["succeededCalls"], 5);
    assert_eq!(full_json["stats"]["failedCalls"], 1);
    assert_eq!(full_json["stats"]["readOnlyCalls"], 4);
    assert_eq!(full_json["stats"]["writeCalls"], 2);
    assert!(full_json["stats"]["toolStats"]["tracedesk_record_finding"]["calls"] == 1);
    assert_eq!(full_json["activities"][0]["transport"], "stdio");
    assert_eq!(full_json["activities"][0]["toolTitle"], "搜索文件内容");
    assert_eq!(full_json["activities"][0]["paramsSummary"], "query=\"accountNum\" · encoding=\"UTF-8\"");

    // 4a. 按传输方式 + 状态 + 客户端 + 关键词 + limit 筛选。
    let only_desktop_failed = cmd_list_mcp_activities(
        &state,
        Some(10),
        Some("Antigravity 1.0"),
        Some("failed"),
        Some("desktop-http"),
        Some("non_existent"),
    )
    .expect("filter failed");
    assert_eq!(only_desktop_failed.activities.len(), 1);
    assert_eq!(only_desktop_failed.stats.failed_calls, 1);

    let only_stdio = cmd_list_mcp_activities(&state, None, Some("Cursor"), None, Some("stdio"), None)
        .expect("filter stdio");
    assert_eq!(only_stdio.activities.len(), 1);
    assert_eq!(only_stdio.activities[0].case_number.as_deref(), Some("TELEM-DESK-01"));

    let limited = cmd_list_mcp_activities(&state, Some(2), None, None, None, None)
        .expect("limit 2");
    assert_eq!(limited.activities.len(), 2);
    assert_eq!(limited.stats.total_calls, 6);

    // 5. 验证新启动的 AppState 会自动从 logs/mcp-activity.jsonl 加载历史记录。
    let reloaded_state = AppState::with_paths(paths);
    let reloaded_snap = cmd_list_mcp_activities(&reloaded_state, None, None, None, None, None)
        .expect("reloaded list");
    assert_eq!(reloaded_snap.activities.len(), 6);
    reloaded_state.shutdown_all();

    // 6. 校验 clear_mcp_activities 清空内存与日志文件，且清空后尾随读取可自动重置并捕获新记录。
    let cleared = cmd_clear_mcp_activities(&state).expect("clear_mcp_activities");
    assert_eq!(cleared["cleared"], true);
    let after_clear = cmd_list_mcp_activities(&state, None, None, None, None, None)
        .expect("after clear");
    assert!(after_clear.activities.is_empty());
    assert_eq!(after_clear.stats.total_calls, 0);
    assert_eq!(std::fs::metadata(&log_path).expect("log meta").len(), 0);

    let post_clear_rec = McpActivityRecord {
        id: "post-clear-evt".to_string(),
        call_id: "post-clear-call".to_string(),
        timestamp: now_east8_millis(),
        phase: "completed".to_string(),
        duration_ms: Some(12),
        ..ext_done
    };
    append_activity_record(&log_path, &post_clear_rec).expect("append after clear");
    let after_new = cmd_list_mcp_activities(&state, None, None, None, None, None)
        .expect("after new external record");
    assert_eq!(after_new.activities.len(), 1);
    assert_eq!(after_new.activities[0].call_id, "post-clear-call");

    // 7. shutdown_all 优雅退出尾随线程与内嵌 HTTP 服务。
    state.shutdown_all();
    assert!(!cmd_get_mcp_status(&state, Some(port)).expect("status").running);
}
