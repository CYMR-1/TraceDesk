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
    cmd_bookmark_search_hits, cmd_browse_directory, cmd_build_review_bundle, cmd_build_timeline,
    cmd_cancel_content_search, cmd_cancel_scan_partitions, cmd_cancel_verify_integrity,
    cmd_check_busy_before_close, cmd_clear_mcp_activities, cmd_close_case, cmd_create_case,
    cmd_examine_file, cmd_export_file, cmd_export_findings, cmd_export_fsstat,
    cmd_generate_html_report, cmd_generate_report, cmd_get_app_paths, cmd_get_case_snapshot,
    cmd_get_guide_pages, cmd_get_mcp_status, cmd_get_tree_children, cmd_inspect_bundle_materials,
    cmd_inspect_entry_magic, cmd_list_audit_log, cmd_list_findings, cmd_list_mcp_activities,
    cmd_list_recent_cases, cmd_load_cached_magic_scan, cmd_load_image, cmd_load_search_record,
    cmd_locate_file_in_scope, cmd_open_case, cmd_preview_file_image, cmd_preview_file_page,
    cmd_query_files_page, cmd_query_timeline_page, cmd_rebind_image_path, cmd_record_finding_note,
    cmd_register_source, cmd_remove_recent_case, cmd_scan_all_partitions,
    cmd_scan_magic_mismatches, cmd_start_content_search, cmd_start_mcp_http, cmd_stop_mcp_http,
    cmd_suggest_case_dir, cmd_verify_integrity, cmd_verify_review_bundle,
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
    // 将测试态的遥测与运行日志隔离到临时目录，避免污染仓库 `logs/mcp-activity.jsonl`。
    if let Some(parent) = cases_dir.parent() {
        paths.logs_dir = parent.join("logs");
    }
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
    assert_eq!(sugg_json["folderName"], "DEMO-IPC-01_测试员_FAT16镜像");
    assert!(
        sugg_json["suggestedPath"]
            .as_str()
            .unwrap()
            .ends_with("DEMO-IPC-01_测试员_FAT16镜像")
    );

    let guides = cmd_get_guide_pages().expect("get_guide_pages");
    assert_eq!(guides.len(), 9);
    assert_eq!(guides[0].image, "/assets/guide/01_quickstart.webp");
    assert_eq!(guides[8].image, "/assets/guide/09_mcp_dialog.webp");

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
    assert!(!snap.browsing_directories, "常规镜像加载后不应进入大镜像按需模式");
    assert!(
        snap.needs_partition_scan,
        "常规镜像加载后未扫描前 needs_partition_scan 必须为 true，以触发前端自动扫描"
    );
    let ev = snap.evidence.as_ref().expect("evidence loaded");
    assert_eq!(ev.large_image, Some(false));
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
    let root_tree =
        cmd_get_tree_children(&state, part_offset, "", None, None).expect("get_tree_children");
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
    assert_eq!(st_before.tools.len(), tracedesk_mcp::TOOL_CATALOG.len());
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
    assert_eq!(tools_arr.len(), tracedesk_mcp::TOOL_CATALOG.len());
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

    // 1. 客户端通过 initialize 上报 clientInfo = Cursor (version 1.5)，服务端返回 Mcp-Session-Id 头且仅记录名称 Cursor。
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

    // 2. 携带该 Mcp-Session-Id 调用 tracedesk_record_finding（不传 actor）-> 记录为 Cursor（不带末尾版本号）。
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
            .contains(&"MCP · Cursor".to_string())
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

    let by_cursor_kw = cmd_list_audit_log(&state, "Cursor", None, None, None, None, "seq", true)
        .expect("按 Cursor 关键词搜索");
    assert_eq!(by_cursor_kw.records.len(), 1);
    assert_eq!(by_cursor_kw.records[0].origin_label, "MCP · Cursor");
    assert_eq!(by_cursor_kw.records[0].mcp_user.as_deref(), Some("Cursor"));

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

    // 5. 校验桌面端 list_findings 同步携带去除版本号后的 originLabel 与 mcpUser。
    let findings = cmd_list_findings(&state, None, None, Some("Cursor"), "seq", false)
        .expect("按 Cursor 搜索取证发现");
    assert_eq!(findings.groups.len(), 1);
    assert!(
        findings.groups[0]
            .records
            .iter()
            .any(|r| r.origin_label.as_deref() == Some("MCP · Cursor")
                && r.mcp_user.as_deref() == Some("Cursor"))
    );

    // 5b. 模拟历史磁盘记录含 "workbuddy 1.0" 与 "WorkBuddy HTTP / workbuddy-http-forensics 1.0"，
    //     与新版 "workbuddy" 共存于同一案件时，筛选下拉自然合并为 "MCP · workbuddy" 且哈希链 100% 校验通过。
    {
        let mut legacy_writer = tracedesk_core::Case::open_with_mcp_client(
            Path::new(&snap.case_dir),
            Some("测试员"),
            tracedesk_core::AuditOrigin::Mcp,
            Some("workbuddy 1.0"),
        )
        .expect("以历史带版本号 MCP 身份写入审计链");
        legacy_writer
            .log("FILE_NOTE", "DOCS/CASE.TXT", "成功", serde_json::Map::new())
            .expect("写入 workbuddy 1.0 记录");
        legacy_writer
            .log_with_mcp_client(
                "FILE_NOTE",
                "DOCS/CASE.TXT",
                "成功",
                serde_json::Map::new(),
                Some("workbuddy"),
            )
            .expect("写入 workbuddy 新记录");
        legacy_writer
            .log_with_mcp_client(
                "FILE_NOTE",
                "DOCS/CASE.TXT",
                "成功",
                serde_json::Map::new(),
                Some("WorkBuddy HTTP / workbuddy-http-forensics 1.0"),
            )
            .expect("写入 WorkBuddy HTTP 历史记录");
        legacy_writer.close();
    }
    let _ = state
        .reload_active_case_from_disk()
        .expect("热重载含历史版本号记录的案件");

    let wb_filtered = cmd_list_audit_log(
        &state,
        "",
        Some("MCP · workbuddy"),
        None,
        None,
        None,
        "seq",
        true,
    )
    .expect("按合并后的 MCP · workbuddy 筛选");
    assert!(wb_filtered.valid);
    assert_eq!(
        wb_filtered.records.len(),
        2,
        "旧 workbuddy 1.0 与新 workbuddy 应合并为同一筛选项并同时命中"
    );
    assert!(
        wb_filtered
            .records
            .iter()
            .all(|r| r.origin_label == "MCP · workbuddy" && r.mcp_user.as_deref() == Some("workbuddy"))
    );
    assert_eq!(
        wb_filtered
            .filter_options
            .origins
            .iter()
            .filter(|o| o.as_str() == "MCP · workbuddy")
            .count(),
        1
    );
    assert!(
        wb_filtered
            .filter_options
            .origins
            .contains(&"MCP · WorkBuddy HTTP / workbuddy-http-forensics".to_string())
    );
    assert!(
        !wb_filtered
            .filter_options
            .origins
            .iter()
            .any(|o| o.contains("1.0") || o.contains("1.5"))
    );
    let raw_audit = std::fs::read_to_string(Path::new(&snap.case_dir).join("audit.jsonl"))
        .expect("读取原始 audit.jsonl");
    assert!(raw_audit.contains("\"workbuddy 1.0\""));
    assert!(tracedesk_core::verify_audit_chain_at(Path::new(&snap.case_dir)).is_ok());

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
    assert!(full.stats.active_clients.contains(&"Antigravity".to_string()));
    assert!(full.stats.active_clients.contains(&"Cursor".to_string()));
    assert!(
        !full
            .stats
            .active_clients
            .iter()
            .any(|c| c.contains("1.0"))
    );
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
        Some("Antigravity"),
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

#[test]
fn desktop_open_case_concurrent_external_mcp_write_and_hot_reload() {
    use tracedesk_core::verify_audit_chain_at;
    use tracedesk_engines::CaseFileLock;
    use tracedesk_mcp::CaseService;

    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());

    // 1. 桌面端创建案件、加载演示镜像并完成全部分区扫描，随后重新打开一次案件模拟完整日常流程。
    let created = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "SHORT-LOCK-01",
        "桌面取证员",
        "FAT16镜像",
        None,
    )
    .expect("create_case");
    let _ = cmd_load_image(&state, &demo_image_path().to_string_lossy(), None).expect("load_image");
    let scanned = cmd_scan_all_partitions(&state, None).expect("scan_all");
    assert!(scanned.completed);

    // 重新打开同一案件后，桌面端应立即释放 OS case.lock，不长期占锁。
    let opened = cmd_open_case(&state, &created.case_dir).expect("reopen case");
    assert_eq!(opened.number, "SHORT-LOCK-01");
    {
        let cg = state.case_lock.lock().expect("case_lock");
        let active_case = cg.as_ref().expect("active case");
        assert!(
            !active_case.has_lock(),
            "桌面端打开案件后浏览期间不应长期持有 case.lock"
        );
    }

    // 2. 验证短锁退避重试机制：后台线程持锁 80ms 后释放，acquire_with_timeout 应自动排队成功获取。
    let lock_file = PathBuf::from(&opened.case_dir).join("case.lock");
    let held_lock = CaseFileLock::acquire(&lock_file).expect("acquire initial lock");
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(80));
        held_lock.unlock();
    });
    let queued = CaseFileLock::acquire_with_timeout(&lock_file, Duration::from_secs(2))
        .expect("acquire_with_timeout should succeed after brief contention");
    queued.unlock();
    releaser.join().expect("join releaser");

    // 3. 在桌面端保持案件打开（不关闭案件、不手动释放锁）的同时，
    //    外部独立 CaseService（模拟独立 stdio MCP 进程）直接对该案件执行受控写入。
    let external_svc = CaseService::new(Some(cases_dir.clone()), Some("外部AI助手".to_string()));
    CaseService::with_caller_scope(Some("外部AI助手"), Some("Cursor"), || {
        let note_res = external_svc
            .record_finding(
                &opened.case_dir,
                "DOCS/CASE.TXT",
                "外部 stdio 进程在桌面端打开案件期间写入的取证笔记",
                Some(2048),
                None,
                Some(false),
                None,
                "",
                false,
                None,
            )
            .expect("external stdio record_finding");
        assert!(note_res.is_object());

        let exam_res = external_svc
            .examine_file(
                &opened.case_dir,
                "DOCS/CASE.TXT",
                Some(2048),
                None,
                Some(false),
                None,
                "",
                None,
                false,
                None,
            )
            .expect("external stdio examine_file");
        assert!(
            exam_res["details"]["sha256"]
                .as_str()
                .is_some_and(|s| s.len() == 64),
            "应计算出 64 位十六进制 SHA-256，实际返回：{exam_res}"
        );

        let reg_res = external_svc
            .register_source(
                &opened.case_dir,
                "EV-SHORT-LOCK",
                "外部 MCP 协同测试交付方",
                "2026-11-23 18:00:00",
                "TraceDesk MCP",
                "",
                None,
            )
            .expect("external stdio register_source");
        assert!(reg_res.is_object());
    });

    // 4. 桌面端调用 reload_active_case_from_disk 应立即检测到外部写入并热重载最新状态。
    let changed = state
        .reload_active_case_from_disk()
        .expect("reload_active_case_from_disk");
    assert!(changed, "外部 MCP 写入后应检测到磁盘指纹变更并热重载");
    assert!(
        !state
            .reload_active_case_from_disk()
            .expect("second reload"),
        "无新增外部写入时重复检测应返回 false"
    );

    let snap_after = cmd_get_case_snapshot(&state)
        .expect("get_case_snapshot")
        .expect("snapshot exists");
    let prov = snap_after
        .evidence
        .as_ref()
        .and_then(|e| e.provenance.as_ref())
        .expect("provenance reloaded from disk");
    assert_eq!(prov.evidence_id, "EV-SHORT-LOCK");
    assert_eq!(prov.source, "外部 MCP 协同测试交付方");

    let findings = cmd_list_findings(&state, None, None, None, "latest_time", true)
        .expect("cmd_list_findings");
    assert!(
        findings.groups.iter().any(|g| {
            g.records.iter().any(|r| {
                r.origin == "mcp"
                    && r.details
                        .get("note")
                        .and_then(|v| v.as_str())
                        .is_some_and(|n| n.contains("外部 stdio 进程"))
            })
        }),
        "桌面端取证发现应立即可见外部 MCP 写入的笔记"
    );

    let audit_after_mcp =
        cmd_list_audit_log(&state, "", None, None, None, None, "seq", false).expect("audit log");
    assert!(audit_after_mcp.valid);
    assert!(
        audit_after_mcp
            .records
            .iter()
            .any(|r| r.origin == "mcp" && r.action == "FILE_HASH"),
        "桌面端审计日志应可见外部 MCP 写入的 FILE_HASH 记录"
    );

    // 5. 桌面端紧接着自身再执行一次受控写入（通过 with_write_lock 短锁对齐），验证哈希链 100% 完整。
    let page = cmd_query_files_page(&state, None, None, "", "CASE.TXT", "all", 0, 50, Some(false))
        .expect("query CASE.TXT");
    let target_entry = page
        .items
        .iter()
        .find(|e| e.path.eq_ignore_ascii_case("DOCS/CASE.TXT"))
        .expect("find DOCS/CASE.TXT");
    let _ = cmd_record_finding_note(
        &state,
        &target_entry.entry_id,
        "桌面端协同后的后续人工笔记",
    )
    .expect("desktop record_finding_note");

    let verified_records =
        verify_audit_chain_at(Path::new(&opened.case_dir)).expect("audit chain 100% valid");
    assert!(
        verified_records
            .iter()
            .any(|r| r.origin.as_deref() == Some("mcp") && r.action == "FILE_NOTE")
    );
    assert!(
        verified_records
            .iter()
            .any(|r| r.origin.as_deref() == Some("manual")
                && r.details
                    .get("note")
                    .and_then(|v| v.as_str())
                    .is_some_and(|n| n.contains("后续人工笔记")))
    );

    // 写入结束后桌面端依然不持有常驻锁。
    {
        let cg = state.case_lock.lock().expect("case_lock");
        assert!(!cg.as_ref().expect("active case").has_lock());
    }

    state.shutdown_all();
}

/// 回归测试：大镜像按需快速浏览模式（`browsing_directories = true`，初始 `inventory = 0`）下，
/// 直接展开文件树 `/ 根目录` 与子目录 `DOCS` 应按需调用只读目录列举返回真实目录与文件，
/// 同时保留多分支缓存、对无文件系统保留分区返回清晰中文错误，并保持审计链与短锁完好。
#[test]
fn large_image_quick_mode_lazy_tree_children_and_audit_integrity() {
    use tracedesk_core::verify_audit_chain_at;

    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());
    let demo_dd = demo_image_path();

    // 1. 新建案件并加载真实 demo.dd，随后关闭案件并在 case.json 中模拟大镜像按需模式：
    //    `evidence.large_image = true`、`partition_scans = null`、`inventory = []`，
    //    并附加一个无文件系统的保留分区偏移（offset = 1）模拟 GPT MSR 分区。
    let created = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "LARGE-LAZY-01",
        "测试员",
        "大镜像按需目录树回归",
        None,
    )
    .expect("create_case");
    let loaded = cmd_load_image(&state, &demo_dd.to_string_lossy(), None).expect("load_image");
    let real_part_offset = loaded
        .evidence
        .as_ref()
        .expect("evidence loaded")
        .partitions[0]
        .offset;
    cmd_close_case(&state).expect("close_case");

    let case_json_path = PathBuf::from(&created.case_dir).join("case.json");
    let raw_json = std::fs::read_to_string(&case_json_path).expect("read case.json");
    let mut doc: Value = serde_json::from_str(&raw_json).expect("parse case.json");
    doc["evidence"]["large_image"] = json!(true);
    doc["partition_scans"] = Value::Null;
    doc["inventory"] = json!([]);
    doc.as_object_mut()
        .expect("case.json object")
        .remove("inventory_file");
    doc.as_object_mut()
        .expect("case.json object")
        .remove("inventory_count");
    let fake_msr_offset: u64 = 1;
    doc["evidence"]["partitions"]
        .as_array_mut()
        .expect("partitions array")
        .insert(
            0,
            json!({
                "offset": fake_msr_offset,
                "description": "Microsoft Reserved (MSR)"
            }),
        );
    std::fs::write(
        &case_json_path,
        serde_json::to_string_pretty(&doc).expect("serialize case.json"),
    )
    .expect("write modified case.json");

    // 2. 重新打开案件，确认进入大镜像按需模式且初始清单为 0 项。
    let opened = cmd_open_case(&state, &created.case_dir).expect("open_case");
    assert!(opened.browsing_directories, "应处于大镜像按需浏览模式");
    assert_eq!(opened.inventory_count, 0, "初始未浏览前清单应为 0 项");
    assert!(opened.partition_scans.is_empty(), "初始分区扫描状态应为空");

    // 3. 在初始 inventory = 0 状态下直接调用 cmd_get_tree_children 展开根目录：
    //    必须按需读取到真实目录与文件，且目录节点 has_children == true 且携带有效 inode。
    let root_tree = cmd_get_tree_children(&state, real_part_offset, "", None, None)
        .expect("lazy root tree children");
    assert!(
        !root_tree.nodes.is_empty(),
        "按需展开 / 根目录不得为空，必须返回真实目录与文件节点"
    );
    let docs_node = root_tree
        .nodes
        .iter()
        .find(|n| n.kind == "directory" && n.scope_path.as_deref() == Some("DOCS"))
        .expect("根目录中应包含 DOCS 子目录");
    assert!(
        docs_node.has_children,
        "按需模式下的目录节点必须标记 has_children = true 以便继续逐层展开"
    );
    let docs_inode = docs_node
        .inode
        .clone()
        .filter(|s| !s.is_empty())
        .expect("DOCS 目录节点必须携带有效 inode");

    // 4. 传入 inode 继续按需展开子目录 DOCS，应返回真实文件 DOCS/CASE.TXT。
    let docs_tree = cmd_get_tree_children(
        &state,
        real_part_offset,
        "DOCS",
        Some(docs_inode.as_str()),
        None,
    )
    .expect("lazy DOCS tree children");
    assert!(
        docs_tree
            .nodes
            .iter()
            .any(|n| n.kind == "file" && n.label.to_ascii_uppercase().contains("CASE.TXT")),
        "按需展开 DOCS 子目录应返回真实的 CASE.TXT 文件节点"
    );

    // 5. 再次读取根目录分支，验证先前已加载的根目录缓存未因展开子目录而被清空。
    let root_tree_again = cmd_get_tree_children(&state, real_part_offset, "", None, None)
        .expect("cached root tree children");
    assert!(
        root_tree_again
            .nodes
            .iter()
            .any(|n| n.kind == "directory" && n.scope_path.as_deref() == Some("DOCS")),
        "根目录分支缓存应持续保留"
    );

    // 6. 展开无可读文件系统的保留分区（模拟 GPT MSR），应返回清晰中文错误而非静默空列表。
    let msr_err = cmd_get_tree_children(&state, fake_msr_offset, "", None, None)
        .expect_err("MSR 保留分区不应静默返回空列表");
    assert!(
        msr_err.contains("文件系统") || msr_err.contains("读取"),
        "保留分区失败应返回清晰的中文错误提示，实际：{msr_err}"
    );

    // 7. 通过 cmd_browse_directory 刷新右侧列表，验证快照与条目同步正常。
    let browsed = cmd_browse_directory(&state, real_part_offset, Some(docs_inode.as_str()), "DOCS")
        .expect("cmd_browse_directory DOCS");
    assert!(
        browsed
            .entries
            .iter()
            .any(|e| e.path.eq_ignore_ascii_case("DOCS/CASE.TXT")),
        "右侧目录列表应包含 DOCS/CASE.TXT"
    );
    assert_eq!(
        browsed
            .snapshot
            .quick_location
            .as_ref()
            .map(|l| l.path.as_str()),
        Some("DOCS")
    );

    // 8. 核验完整 SHA-256 审计链 100% 有效，且桌面端依然不常驻占用 case.lock。
    let audit =
        cmd_list_audit_log(&state, "", None, None, None, None, "seq", false).expect("audit log");
    assert!(audit.valid, "按需目录树浏览后审计链必须完整有效");
    let _verified =
        verify_audit_chain_at(Path::new(&created.case_dir)).expect("disk audit chain valid");
    {
        let cg = state.case_lock.lock().expect("case_lock");
        assert!(
            !cg.as_ref().expect("active case").has_lock(),
            "按需目录浏览不得残留常驻 case.lock"
        );
    }

    state.shutdown_all();
}

#[test]
fn load_and_scan_real_drf2024_image_end_to_end_readonly() {
    let drf_path = repo_root().join("evidence").join("DRF2024.dd");
    if !drf_path.is_file() {
        // 本地未放置 DRF2024.dd 时跳过，保证无本地大样本环境下测试套件仍可完整通过
        return;
    }

    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());

    // 1. 在临时目录新建案件并只读加载本地 DRF2024.dd
    let created = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "DRF-VERIFY-01",
        "自动化核验",
        "DRF2024",
        None,
    )
    .expect("create_case");
    assert_eq!(created.inventory_count, 0);

    let loaded = cmd_load_image(&state, &drf_path.to_string_lossy(), None).expect("load_image");
    let ev = loaded.evidence.as_ref().expect("evidence present");
    assert_eq!(ev.size, 262_144_512, "DRF2024.dd 实际大小应为 262,144,512 字节");
    assert_eq!(ev.large_image, Some(false), "DRF2024.dd 小于 1 GiB，不应被判为大镜像");
    assert!(!loaded.browsing_directories, "常规镜像不应进入大镜像按需目录浏览模式");
    assert!(
        loaded.needs_partition_scan,
        "load_image 完成后 needs_partition_scan 必须为 true"
    );
    let offsets: Vec<u64> = ev.partitions.iter().map(|p| p.offset).collect();
    assert_eq!(offsets, vec![128, 409_728], "应准确识别 FAT32(128) 与 NTFS(409728) 两个分区");

    // 2. 紧接执行全分区自动扫描，验证两分区均可正常扫描出文件清单
    let scanned = cmd_scan_all_partitions(&state, None).expect("scan_all_partitions");
    assert!(scanned.completed, "全部分区扫描应完整完成");
    assert!(
        !scanned.snapshot.needs_partition_scan,
        "全部分区扫描完成后 needs_partition_scan 应为 false"
    );
    assert!(
        scanned.snapshot.inventory_count > 0,
        "扫描完成后完整清单不得为 0 项"
    );
    assert_eq!(scanned.snapshot.partition_scans.len(), 2);
    for ps in &scanned.snapshot.partition_scans {
        assert_eq!(
            ps.status, "ready",
            "分区偏移 {} 扫描状态应为 ready，错误：{:?}",
            ps.offset, ps.error
        );
        assert!(
            ps.count.unwrap_or(0) > 0,
            "分区偏移 {} 应扫描出有效文件条目",
            ps.offset
        );
    }

    // 3. 核验左侧文件树根节点与右侧分页查询均可返回真实条目
    let tree_fat =
        cmd_get_tree_children(&state, 128, "", None, None).expect("tree children offset 128");
    let tree_ntfs = cmd_get_tree_children(&state, 409_728, "", None, None)
        .expect("tree children offset 409728");
    assert!(!tree_fat.nodes.is_empty(), "偏移 128 (FAT32) 根目录树节点不应为空");
    assert!(!tree_ntfs.nodes.is_empty(), "偏移 409728 (NTFS) 根目录树节点不应为空");

    let page = cmd_query_files_page(&state, None, None, "", "", "all", 0, 100, Some(false))
        .expect("query_files_page");
    assert_eq!(page.total, scanned.snapshot.inventory_count);
    assert!(!page.items.is_empty());

    println!(
        "[DRF2024.dd 实测] size={} bytes, sha256={}, inventory_count={}, scans={:?}, fat_root_nodes={}, ntfs_root_nodes={}",
        ev.size,
        ev.sha256.as_deref().unwrap_or(""),
        scanned.snapshot.inventory_count,
        scanned.snapshot.partition_scans,
        tree_fat.nodes.len(),
        tree_ntfs.nodes.len(),
    );

    state.shutdown_all();
}

#[test]
fn mcp_hot_refresh_case_json_preserves_timeline_and_blocks_cross_case_bookmark() {
    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let img_path = tmp.path().join("demo_hot.dd");
    std::fs::copy(demo_image_path(), &img_path).expect("copy demo.dd");
    let state = make_test_state(cases_dir.clone());

    // 1. 新建案件 A、加载演示镜像、全盘扫描并构建时间线索引与内容搜索会话。
    let snap_a = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "HOT-CASE-A",
        "测试员",
        "热重载与跨案保护测试",
        None,
    )
    .expect("create case A");
    cmd_load_image(&state, &img_path.to_string_lossy(), None).expect("load_image");
    cmd_scan_all_partitions(&state, None).expect("scan_all_partitions");
    let tl = cmd_build_timeline(&state).expect("build_timeline");
    assert!(tl.total > 0);
    assert!(
        state.view.read().expect("view read").timeline_index.is_some(),
        "构建时间线后 timeline_index 应已缓存"
    );

    let search_resp =
        cmd_start_content_search(&state, "TraceDesk", "UTF-8", None, None).expect("search");
    let old_search_id = search_resp.search_id;

    // 2. 启动内嵌 HTTP MCP，并以 `.../case.json` 路径调用仅写审计的 `tracedesk_record_finding`，
    //    验证桌面端可正常热重载且不销毁已缓存的 `timeline_index`。
    let port = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
        l.local_addr().expect("local_addr").port()
    };
    cmd_start_mcp_http(&state, port).expect("start_mcp_http");
    let case_json_path = PathBuf::from(&snap_a.case_dir).join("case.json");
    let body_str = serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "tracedesk_record_finding",
            "arguments": {
                "case_dir": case_json_path.to_string_lossy(),
                "path": "DOCS/CASE.TXT",
                "note": "通过 case.json 路径触发的审计热重载测试",
                "response_format": "json"
            }
        }
    }))
    .expect("serialize");
    let (status, _) = send_http_request(port, &format!("127.0.0.1:{port}"), &body_str);
    assert_eq!(status, 200);

    // 仅追加审计记录时，热重载应保留已构建的 `timeline_index`，同时在取证发现页立即可见新笔记。
    assert!(
        state.view.read().expect("view read").timeline_index.is_some(),
        "仅追加审计日志的热重载不应销毁已缓存的时间线索引"
    );
    let findings = cmd_list_findings(&state, None, None, None, "seq", false).expect("list_findings");
    assert!(
        findings
            .groups
            .iter()
            .any(|g| g.subject == "DOCS/CASE.TXT"),
        "桌面端应同步看到通过 case.json 路径写入的 MCP 取证发现"
    );

    // 3. 切换到新建案件 B，确认旧案件搜索会话已被清理，且无法将旧案命中误存到新案审计链。
    let _snap_b = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "HOT-CASE-B",
        "测试员",
        "切换目标案件",
        None,
    )
    .expect("create case B");
    assert!(
        state.searches.lock().expect("searches").is_empty(),
        "切换案件后应自动清理旧案件搜索会话"
    );
    let bookmark_err = cmd_bookmark_search_hits(&state, &old_search_id, &[0])
        .expect_err("跨案件保存旧搜索会话命中必须被拒绝");
    assert!(bookmark_err.contains("未找到"));

    cmd_stop_mcp_http(&state).expect("stop_mcp_http");
    state.shutdown_all();
}

/// 回归测试：当 `case_lock` 被占用导致 `emit_case_updated_if_matching` 遇到 `WouldBlock` 时，
/// 必须置位 `disk_dirty` 并延迟通知（杜绝“假刷新”），待释放锁后再经由 `cmd_get_case_snapshot`
/// 主动从磁盘热重载最新案件数据与审计记录。
#[test]
fn disk_dirty_defers_wouldblock_hot_reload_and_recovers_on_snapshot() {
    use std::sync::atomic::Ordering;
    use tracedesk_mcp::{CaseService, McpActivityRecord};

    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());

    let snap = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "DIRTY-RELOAD-01",
        "测试员",
        "热刷新脏标记回归",
        None,
    )
    .expect("create case");
    let _ = cmd_load_image(&state, &demo_image_path().to_string_lossy(), None).expect("load_image");
    let _ = cmd_scan_all_partitions(&state, None).expect("scan_all");

    // 1. 模拟长任务占用内存 `case_lock`（但未持有磁盘 `case.lock`），外部 MCP 进程直接向磁盘写入。
    let held_guard = state.case_lock.lock().expect("hold case_lock");
    let external_svc = CaseService::new(Some(cases_dir.clone()), Some("外部AI助手".to_string()));
    CaseService::with_caller_scope(Some("外部AI助手"), Some("Cursor"), || {
        external_svc
            .register_source(
                &snap.case_dir,
                "EV-DIRTY-01",
                "跨进程延迟热刷新交付方",
                "2026-11-26 11:00:00",
                "TraceDesk MCP",
                "",
                None,
            )
            .expect("external register_source");
    });

    // 2. 此时触发 `emit_case_updated_if_matching`，由于 `case_lock` 正被占用应返回 false 并置脏。
    let rec = McpActivityRecord {
        id: "act-dirty-1".to_string(),
        call_id: "call-dirty-1".to_string(),
        timestamp: "2026-11-26 11:00:01.000".to_string(),
        phase: "completed".to_string(),
        transport: "stdio".to_string(),
        client: "Cursor".to_string(),
        session_id: None,
        method: "tools/call".to_string(),
        tool_name: Some("tracedesk_register_source".to_string()),
        tool_title: "登记证据来源".to_string(),
        category: "证据镜像".to_string(),
        read_only: false,
        case_dir: Some(snap.case_dir.clone()),
        case_number: Some("DIRTY-RELOAD-01".to_string()),
        params_summary: String::new(),
        params_json: "{}".to_string(),
        duration_ms: Some(12),
        result_summary: "ok".to_string(),
        response_preview: None,
        error: None,
    };
    let emitted_now = state.emit_case_updated_if_matching(&rec);
    assert!(
        !emitted_now,
        "遇到 WouldBlock 时不得立即广播假刷新，应延迟至真正热重载之后"
    );
    assert!(
        state.disk_dirty.load(Ordering::Acquire),
        "遇到 WouldBlock 后必须置位 disk_dirty 脏标记"
    );
    assert!(
        state
            .pending_case_updated
            .lock()
            .expect("pending lock")
            .is_some(),
        "遇到 WouldBlock 后应暂存待补发通知载荷"
    );

    // 持锁期间调用 get_case_snapshot 不阻塞且保持 disk_dirty=true。
    let stale_snap = cmd_get_case_snapshot(&state)
        .expect("get_case_snapshot while locked")
        .expect("cached snapshot");
    assert!(stale_snap.evidence.and_then(|e| e.provenance).is_none());
    assert!(state.disk_dirty.load(Ordering::Acquire));

    // 3. 释放 `case_lock` 后再次获取快照，应自动从磁盘重载最新数据并清除脏标记。
    drop(held_guard);
    let fresh_snap = cmd_get_case_snapshot(&state)
        .expect("get_case_snapshot after unlock")
        .expect("fresh snapshot");
    assert!(
        !state.disk_dirty.load(Ordering::Acquire),
        "成功热重载后必须清除 disk_dirty 脏标记"
    );
    assert!(
        state
            .pending_case_updated
            .lock()
            .expect("pending lock")
            .is_none(),
        "成功热重载后应清空待补发通知载荷"
    );
    let prov = fresh_snap
        .evidence
        .and_then(|e| e.provenance)
        .expect("provenance should be reloaded from disk");
    assert_eq!(prov.evidence_id, "EV-DIRTY-01");
    assert_eq!(prov.source, "跨进程延迟热刷新交付方");

    state.shutdown_all();
}

/// 回归测试：无锁三段式内容搜索结束后应自动更新 `CaseSnapshot.search_records`，
/// 且历史搜索记录回放（`cmd_load_search_record`）注册的 `replay:*` 会话可直接保存为取证发现，
/// 全程保持审计哈希链 100% 完整且不残留常驻 `case.lock`。
#[test]
fn detached_content_search_updates_snapshot_records_and_supports_replay_bookmark() {
    use tracedesk_core::verify_audit_chain_at;

    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());

    let snap = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "SEARCH-REPLAY-01",
        "测试员",
        "无锁搜索与历史回放回归",
        None,
    )
    .expect("create case");
    let _ = cmd_load_image(&state, &demo_image_path().to_string_lossy(), None).expect("load_image");
    let _ = cmd_scan_all_partitions(&state, None).expect("scan_all");

    let search_res = cmd_start_content_search(&state, "6E 6F 74 65", "HEX", None, None)
        .expect("start_content_search");
    assert_eq!(search_res.needle_hex, "6e6f7465");

    // 搜索完成后不残留常驻 `case.lock`，且 `CaseSnapshot.search_records` 应包含刚生成的搜索记录。
    {
        let cg = state.case_lock.lock().expect("case_lock");
        assert!(
            !cg.as_ref().expect("case open").has_lock(),
            "内容搜索结束后不应残留常驻 case.lock"
        );
    }

    let snap_after = cmd_get_case_snapshot(&state)
        .expect("get_case_snapshot")
        .expect("snapshot");
    assert!(
        !snap_after.search_records.is_empty(),
        "CaseSnapshot.search_records 应包含历史内容搜索摘要"
    );
    let latest_rec = &snap_after.search_records[0];
    assert_eq!(latest_rec.query, "6E 6F 74 65");
    assert_eq!(latest_rec.encoding, "HEX");
    assert!(latest_rec.hits >= 1);

    // 模拟重启或新会话：清空内存搜索会话后通过 `cmd_load_search_record` 回放并保存为取证发现。
    state.clear_search_sessions();
    let replayed = cmd_load_search_record(&state, &latest_rec.report_name)
        .expect("load_search_record replay");
    assert!(
        replayed
            .iter()
            .any(|h| h.path == "DOCS/CASE.TXT" && h.pos == 5),
        "回放历史搜索记录应还原准确命中位置"
    );

    let replay_session_id = format!("replay:{}", latest_rec.report_name);
    let bookmarked = cmd_bookmark_search_hits(&state, &replay_session_id, &[0])
        .expect("bookmark replayed hit");
    assert_eq!(bookmarked.saved_count, 1);

    let verified = verify_audit_chain_at(Path::new(&snap.case_dir)).expect("audit chain valid");
    assert!(verified.iter().any(|r| r.action == "CONTENT_SEARCH"));
    assert!(verified.iter().any(|r| r.action == "FILE_NOTE"));

    state.shutdown_all();
}

/// 在 ZIP 原始字节流中定位指定成员（本地文件头 `PK\x03\x04`）并翻转其压缩数据区首字节，用于模拟单字节篡改。
fn flip_single_byte_in_zip_member(zip_bytes: &mut [u8], member_name: &str) -> bool {
    let target = member_name.as_bytes();
    let mut i = 0usize;
    while i + 30 <= zip_bytes.len() {
        if &zip_bytes[i..i + 4] == b"PK\x03\x04" {
            let name_len = u16::from_le_bytes([zip_bytes[i + 26], zip_bytes[i + 27]]) as usize;
            let extra_len = u16::from_le_bytes([zip_bytes[i + 28], zip_bytes[i + 29]]) as usize;
            let name_start = i + 30;
            let data_start = name_start + name_len + extra_len;
            if data_start < zip_bytes.len() && &zip_bytes[name_start..name_start + name_len] == target
            {
                zip_bytes[data_start] ^= 0xFF;
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Phase 2 集成测试：离线 HTML 报告生成、无打开案件时的复核包详细核验（正常通过 + 单字节篡改精确定位）。
#[test]
fn html_report_and_review_bundle_detailed_verification_and_tamper_detection() {
    use tracedesk_core::verify_audit_chain_at;

    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());
    let demo_dd = demo_image_path();

    // 1. 建案、加载演示镜像、全盘扫描并生成 Markdown 与离线单文件 HTML 报告。
    let snap = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "P2-REPORT-01",
        "答辩核验员",
        "HTML报告与复核包核验",
        None,
    )
    .expect("create_case");
    cmd_load_image(&state, &demo_dd.to_string_lossy(), None).expect("load_image");
    cmd_scan_all_partitions(&state, None).expect("scan_all_partitions");

    let page = cmd_query_files_page(&state, None, None, ".txt", "CASE", "active", 0, 50, Some(false))
        .expect("query CASE.TXT");
    assert!(!page.items.is_empty());
    cmd_record_finding_note(&state, &page.items[0].entry_id, "Phase 2 HTML 报告联调笔记")
        .expect("record_finding_note");

    let md_report = cmd_generate_report(&state).expect("generate_report");
    assert!(PathBuf::from(&md_report.path).is_file());

    let html_report = cmd_generate_html_report(&state).expect("generate_html_report");
    let html_json = serde_json::to_value(&html_report).expect("serialize HtmlReportDto");
    assert!(html_json.get("path").and_then(Value::as_str).is_some());
    assert_eq!(
        html_json
            .get("sha256")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );
    assert!(html_json.get("bytes").and_then(Value::as_u64).unwrap_or(0) > 100);
    assert!(
        html_json
            .get("generatedAt")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    );

    let html_path = PathBuf::from(&html_report.path);
    assert!(html_path.is_file(), "HTML 报告文件应已落盘");
    let html_raw = std::fs::read(&html_path).expect("read html report");
    assert_eq!(html_raw.len() as u64, html_report.bytes);
    let html_text = String::from_utf8(html_raw).expect("valid utf-8 html");
    assert!(html_text.starts_with("<!DOCTYPE html>"));
    assert!(html_text.contains("P2-REPORT-01"));

    // 确认 HTML 报告生成已写入 REPORT_GENERATE 审计记录且不残留 case.lock。
    let audit_records =
        verify_audit_chain_at(Path::new(&snap.case_dir)).expect("audit chain valid");
    assert!(
        audit_records
            .iter()
            .any(|r| r.action == "REPORT_GENERATE" && r.details.get("format").and_then(Value::as_str) == Some("html")),
        "审计链中应记录 HTML 格式的 REPORT_GENERATE"
    );
    {
        let cg = state.case_lock.lock().expect("case_lock");
        assert!(
            !cg.as_ref().expect("case open").has_lock(),
            "生成 HTML 报告后不得残留常驻 case.lock"
        );
    }

    // 2. 构建复核包并关闭案件，验证 `cmd_verify_review_bundle` 无需打开案件即可独立核验。
    let bundle_res = cmd_build_review_bundle(&state, None, None).expect("build_review_bundle");
    let bundle_path = PathBuf::from(&bundle_res.path);
    assert!(bundle_path.is_file());
    assert!(cmd_close_case(&state).expect("close_case").closed);
    assert!(cmd_get_case_snapshot(&state).expect("snapshot none").is_none());

    // 2a. 未传 expected_sha256 时自动读取同目录 `.zip.sha256` 并全部核验通过。
    let detail =
        cmd_verify_review_bundle(&bundle_res.path, None).expect("verify_review_bundle intact");
    assert!(detail.ok, "完整复核包核验应通过，错误：{:?}", detail.errors);
    assert_eq!(detail.sha256_source, "sidecar");
    assert_eq!(detail.sha256_matched, Some(true));
    assert!(detail.audit_valid);
    assert!(detail.audit_count >= 5);
    assert_eq!(detail.audit_head.len(), 64);
    assert!(detail.audit_error.is_none());
    assert!(detail.manifest_valid);
    assert!(detail.errors.is_empty());
    assert!(detail.members.iter().any(|m| m.path == "report.md" && m.status == "ok"));
    assert!(detail.members.iter().any(|m| m.path == "report.html" && m.status == "ok"));
    assert!(!detail.cross_checks.is_empty());
    assert!(detail.cross_checks.iter().all(|c| c.status != "mismatch"));

    // 严格核对前后端约定 camelCase JSON 键名。
    let detail_json = serde_json::to_value(&detail).expect("serialize BundleVerificationDetailDto");
    for key in [
        "ok",
        "bundlePath",
        "bundleSha256",
        "expectedSha256",
        "sha256Source",
        "sha256Matched",
        "auditValid",
        "auditCount",
        "auditHead",
        "auditError",
        "manifestValid",
        "members",
        "crossChecks",
        "errors",
    ] {
        assert!(
            detail_json.get(key).is_some(),
            "BundleVerificationDetailDto 缺少约定 JSON 键：{key}"
        );
    }
    let first_member = &detail_json["members"][0];
    for key in [
        "path",
        "category",
        "status",
        "expectedSha256",
        "actualSha256",
        "size",
        "message",
    ] {
        assert!(
            first_member.get(key).is_some(),
            "BundleMemberCheckDto 缺少约定 JSON 键：{key}"
        );
    }
    let first_cc = &detail_json["crossChecks"][0];
    for key in ["name", "status", "message"] {
        assert!(
            first_cc.get(key).is_some(),
            "BundleCrossCheckDto 缺少约定 JSON 键：{key}"
        );
    }

    // 2b. 手工传入错误期望 SHA-256 -> 应精确报出手工摘要不匹配。
    let wrong_sha = "f".repeat(64);
    let mismatch_sha = cmd_verify_review_bundle(&bundle_res.path, Some(&wrong_sha))
        .expect("verify_review_bundle manual mismatch");
    assert!(!mismatch_sha.ok);
    assert_eq!(mismatch_sha.sha256_source, "manual");
    assert_eq!(mismatch_sha.sha256_matched, Some(false));
    assert!(!mismatch_sha.errors.is_empty());

    // 2c. 复制复核包与伴随 `.sha256`，仅翻转 `report.md` 压缩流中的 1 个字节 -> 检出篡改并定位受损成员。
    let tampered_zip = tmp.path().join("tampered_bundle.zip");
    let tampered_sha = tmp.path().join("tampered_bundle.zip.sha256");
    let orig_sha_path = PathBuf::from(format!("{}.sha256", bundle_path.display()));
    let mut zip_bytes = std::fs::read(&bundle_path).expect("read original bundle");
    assert!(
        flip_single_byte_in_zip_member(&mut zip_bytes, "report.md"),
        "应能在复核包 ZIP 中定位到 report.md 成员数据区"
    );
    std::fs::write(&tampered_zip, &zip_bytes).expect("write tampered zip");
    std::fs::copy(&orig_sha_path, &tampered_sha).expect("copy sidecar sha256");

    let tampered_with_sidecar =
        cmd_verify_review_bundle(&tampered_zip.to_string_lossy(), None)
            .expect("verify tampered bundle with sidecar");
    assert!(!tampered_with_sidecar.ok, "单字节篡改复核包必须检出失败");
    assert_eq!(tampered_with_sidecar.sha256_source, "sidecar");
    assert_eq!(tampered_with_sidecar.sha256_matched, Some(false));
    assert!(
        tampered_with_sidecar
            .members
            .iter()
            .any(|m| m.path == "report.md" && m.status == "mismatch"),
        "逐成员核验应精确定位被篡改的 report.md"
    );

    // 移除伴随 `.sha256` 后再次核验，确认包内哈希与结构校验仍独立拦截篡改。
    std::fs::remove_file(&tampered_sha).expect("remove sidecar sha256");
    let tampered_no_sidecar = cmd_verify_review_bundle(&tampered_zip.to_string_lossy(), None)
        .expect("verify tampered bundle without sidecar");
    assert!(!tampered_no_sidecar.ok);
    assert_eq!(tampered_no_sidecar.sha256_source, "none");
    assert_eq!(tampered_no_sidecar.sha256_matched, None);
    assert!(
        tampered_no_sidecar
            .members
            .iter()
            .any(|m| m.path == "report.md" && m.status == "mismatch"),
        "无伴随 .sha256 时逐成员核验仍须精确定位被篡改的 report.md"
    );

    state.shutdown_all();
}

/// Phase 2 集成测试：无锁魔数批量伪装检测、单条目魔数识别与跨模块精确定位（含根目录与子目录）。
#[test]
fn magic_scan_single_entry_inspection_and_cross_module_locate() {
    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());

    // 在临时目录复制 demo.dd 并将 DOCS/CASE.TXT 内容头替换为 PNG 魔数，制造真实 `.txt` 伪装 PNG 样本。
    let mut img_bytes = std::fs::read(demo_image_path()).expect("read demo.dd");
    let marker = b"Case note inside a nested directory.";
    let pos = img_bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("locate DOCS/CASE.TXT payload in demo.dd");
    let png_header: [u8; 16] = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52,
    ];
    img_bytes[pos..pos + png_header.len()].copy_from_slice(&png_header);
    let patched_img = tmp.path().join("demo_magic_spoof.dd");
    std::fs::write(&patched_img, &img_bytes).expect("write patched image");

    cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "P2-MAGIC-01",
        "答辩核验员",
        "魔数伪装检测与定位",
        None,
    )
    .expect("create_case");
    cmd_load_image(&state, &patched_img.to_string_lossy(), None).expect("load_image");
    cmd_scan_all_partitions(&state, None).expect("scan_all_partitions");

    // 1. 全案魔数伪装扫描（无锁执行，返回 camelCase MagicScanReport）。
    let report = cmd_scan_magic_mismatches(&state).expect("scan_magic_mismatches");
    assert!(report.scanned_count > 0);
    assert!(!report.cancelled);
    assert!(report.mismatch_count >= 1);

    let report_json = serde_json::to_value(&report).expect("serialize MagicScanReport");
    for key in [
        "scannedCount",
        "skippedCount",
        "mismatchCount",
        "elapsedMs",
        "cancelled",
        "typeCounts",
        "mismatches",
    ] {
        assert!(
            report_json.get(key).is_some(),
            "MagicScanReport 缺少约定 JSON 键：{key}"
        );
    }

    let spoof = report
        .mismatches
        .iter()
        .find(|m| m.path == "DOCS/CASE.TXT")
        .expect("应检出 DOCS/CASE.TXT 伪装为 PNG 图像");
    assert_eq!(spoof.detected_type, "PNG");
    assert_eq!(spoof.detected_family, "IMAGE");
    assert_eq!(spoof.extension, ".txt");
    assert_eq!(spoof.severity, "medium");
    assert!(spoof.magic_hex.starts_with("89 50 4E 47"));

    // 2. 使用扫描产出的 `entryKey` 调用单条目魔数识别。
    let item = cmd_inspect_entry_magic(&state, &spoof.entry_key).expect("inspect_entry_magic");
    assert!(item.mismatch);
    assert_eq!(item.detected_type.as_deref(), Some("PNG"));
    assert_eq!(item.detected_family.as_deref(), Some("IMAGE"));
    assert_eq!(item.extension, ".txt");
    assert_eq!(item.severity, "medium");
    assert!(item.magic_hex.starts_with("89 50 4E 47"));

    let item_json = serde_json::to_value(&item).expect("serialize MagicCheckItem");
    for key in [
        "detectedType",
        "detectedFamily",
        "detectedLabel",
        "extension",
        "mismatch",
        "severity",
        "reason",
        "magicHex",
    ] {
        assert!(
            item_json.get(key).is_some(),
            "MagicCheckItem 缺少约定 JSON 键：{key}"
        );
    }

    // 3. 验证跨模块精确定位 `cmd_locate_file_in_scope`（子目录文件与分区根目录文件均准确命中）。
    // 3a. 子目录文件：支持 `offset:inode:deleted:path`、`offset:inode::path` 与 `offset:inode:path`。
    let loc_full = cmd_locate_file_in_scope(&state, &spoof.entry_key).expect("locate by entryKey");
    let loc_wildcard = cmd_locate_file_in_scope(
        &state,
        &format!("{}:{}::{}", spoof.offset, spoof.inode, spoof.path),
    )
    .expect("locate by wildcard deleted");
    let loc_triple = cmd_locate_file_in_scope(
        &state,
        &format!("{}:{}:{}", spoof.offset, spoof.inode, spoof.path),
    )
    .expect("locate by offset:inode:path");
    assert_eq!(loc_full, loc_wildcard);
    assert_eq!(loc_full, loc_triple);
    assert_eq!(loc_full.scope_offset, spoof.offset);
    assert_eq!(loc_full.scope_path, "DOCS");

    let docs_page = cmd_query_files_page(
        &state,
        Some(loc_full.scope_offset),
        Some(loc_full.scope_path.clone()),
        "",
        "",
        "all",
        loc_full.page,
        100,
        Some(false),
    )
    .expect("query DOCS page");
    assert_eq!(docs_page.items[loc_full.index_in_page].path, "DOCS/CASE.TXT");

    // 3b. 分区根目录文件定位与普通文本单条目魔数识别（无误报）。
    let root_page = cmd_query_files_page(
        &state,
        Some(spoof.offset),
        Some(String::new()),
        "",
        "",
        "active",
        0,
        100,
        Some(false),
    )
    .expect("query root files");
    let root_file = root_page
        .items
        .iter()
        .find(|e| !e.directory && !e.path.contains('/'))
        .expect("分区根目录应存在现存普通文件");
    let root_key = format!(
        "{}:{}:{}:{}",
        root_file.offset,
        root_file.inode,
        if root_file.deleted { 1 } else { 0 },
        root_file.path
    );
    let loc_root = cmd_locate_file_in_scope(&state, &root_key).expect("locate root file");
    assert_eq!(loc_root.scope_offset, root_file.offset);
    assert_eq!(loc_root.scope_path, "");

    let root_all_page = cmd_query_files_page(
        &state,
        Some(loc_root.scope_offset),
        Some(String::new()),
        "",
        "",
        "all",
        loc_root.page,
        100,
        Some(false),
    )
    .expect("query root all page");
    assert_eq!(
        root_all_page.items[loc_root.index_in_page].path,
        root_file.path
    );

    let normal_magic =
        cmd_inspect_entry_magic(&state, &root_key).expect("inspect normal root file magic");
    assert!(!normal_magic.mismatch);
    assert_eq!(normal_magic.severity, "none");

    state.shutdown_all();
}

/// Stage B-1 集成测试 1：跨目录案件打开/记录到最近历史、`list_recent_cases` 合并返回、
/// `remove_recent_case` 仅移除历史清单而绝不删除磁盘案件文件。
#[test]
fn cross_directory_recent_cases_history_merge_and_remove_without_deleting_files() {
    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    let external_dir = tmp.path().join("external_drive_cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    std::fs::create_dir_all(&external_dir).expect("mkdir external");
    let state = make_test_state(cases_dir.clone());
    let demo_dd = demo_image_path();

    // 1. 直接在默认 `cases_dir` 下创建一个未通过桌面端打开过的案件（验证合并后 `inHistory == false`）。
    let mut unrecorded = tracedesk_core::Case::create(
        &cases_dir,
        "ROOT-ONLY-01",
        "取证员甲",
        "默认目录案件",
        None,
        None,
        tracedesk_core::AuditOrigin::Manual,
    )
    .expect("create unrecorded case");
    let unrecorded_folder = unrecorded.folder().to_path_buf();
    unrecorded.close();

    // 2. 通过桌面端在默认 `cases_dir` 新建案件并关闭。
    let default_snap = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "DEFAULT-HIST-02",
        "取证员乙",
        "默认目录历史案件",
        None,
    )
    .expect("create default case");
    cmd_close_case(&state).expect("close default case");

    std::thread::sleep(Duration::from_millis(20));

    // 3. 通过桌面端在跨目录 `external_dir` 新建案件、加载镜像并扫描分区（生成分分区 `inventory_files`）。
    let ext_snap = cmd_create_case(
        &state,
        &external_dir.to_string_lossy(),
        "EXT-HIST-03",
        "取证员丙",
        "跨目录外部案件",
        None,
    )
    .expect("create external case");
    cmd_load_image(&state, &demo_dd.to_string_lossy(), None).expect("load image");
    let scan_res = cmd_scan_all_partitions(&state, None).expect("scan partitions");
    assert!(scan_res.snapshot.inventory_count > 0);
    cmd_close_case(&state).expect("close external case");

    // 4. `list_recent_cases` 应合并返回全部 3 个案件，且跨目录最新打开者排首位。
    let recent = cmd_list_recent_cases(&state).expect("list_recent_cases");
    assert_eq!(recent.len(), 3, "应合并返回历史案件与默认目录案件");
    assert_eq!(recent[0].number, "EXT-HIST-03");
    assert!(recent[0].in_history);
    assert!(!recent[0].pinned);
    assert!(recent[0].last_opened_at.is_some());
    assert!(recent[0].has_evidence);
    assert!(!recent[0].evidence_missing);
    assert_eq!(recent[0].inventory_count, scan_res.snapshot.inventory_count);

    let default_item = recent
        .iter()
        .find(|c| c.number == "DEFAULT-HIST-02")
        .expect("default history case present");
    assert!(default_item.in_history);
    assert!(default_item.last_opened_at.is_some());
    assert!(!default_item.evidence_missing);

    let root_only_item = recent
        .iter()
        .find(|c| c.number == "ROOT-ONLY-01")
        .expect("unrecorded cases_dir case present");
    assert!(!root_only_item.in_history);
    assert!(root_only_item.last_opened_at.is_none());
    assert!(!root_only_item.pinned);

    // 校验 camelCase JSON 契约字段名。
    let first_json = serde_json::to_value(&recent[0]).expect("serialize RecentCaseDto");
    for key in [
        "folder",
        "name",
        "number",
        "examiner",
        "target",
        "created",
        "hasEvidence",
        "inventoryCount",
        "exportsCount",
        "lastOpenedAt",
        "inHistory",
        "pinned",
        "evidenceMissing",
    ] {
        assert!(
            first_json.get(key).is_some(),
            "RecentCaseDto 缺少约定 JSON 键：{key}"
        );
    }

    // 5. 重新打开 `default_snap` 应将其置顶到历史最前。
    std::thread::sleep(Duration::from_millis(20));
    cmd_open_case(&state, &default_snap.case_dir).expect("reopen default case");
    cmd_close_case(&state).expect("close reopened default case");
    let recent_after_reopen = cmd_list_recent_cases(&state).expect("list after reopen");
    assert_eq!(recent_after_reopen[0].number, "DEFAULT-HIST-02");

    // 6. 移除跨目录案件历史记录：返回 `removed: true`，列表不再包含该跨目录案件，但磁盘文件毫发无损。
    let rem_res = cmd_remove_recent_case(&state, &ext_snap.case_dir).expect("remove_recent_case");
    let rem_json = serde_json::to_value(&rem_res).expect("serialize RemoveRecentCaseResponse");
    assert_eq!(rem_json["removed"], true);

    let rem_again =
        cmd_remove_recent_case(&state, &ext_snap.case_dir).expect("remove_recent_case again");
    assert!(!rem_again.removed);

    let recent_after_remove = cmd_list_recent_cases(&state).expect("list after remove");
    assert!(
        recent_after_remove
            .iter()
            .all(|c| c.number != "EXT-HIST-03"),
        "移出历史后跨目录案件不应再出现在最近列表"
    );
    assert_eq!(recent_after_remove.len(), 2);

    // 确认磁盘上的跨目录案件与默认目录案件均完好无损。
    let ext_folder_path = PathBuf::from(&ext_snap.case_dir);
    assert!(ext_folder_path.is_dir(), "移出历史绝不能删除案件目录");
    assert!(ext_folder_path.join("case.json").is_file(), "case.json 必须保留");
    assert!(ext_folder_path.join("audit.jsonl").is_file(), "audit.jsonl 必须保留");
    assert!(unrecorded_folder.join("case.json").is_file());

    state.shutdown_all();
}

/// Stage B-1 集成测试 2：`evidence_missing` 检测与受 SHA-256 强制校验保护的 `rebind_image_path`
/// （正常重绑成功 + 篡改镜像拦截拒绝且保留原路径）。
#[test]
fn evidence_missing_detection_and_rebind_image_path_with_sha256_guard() {
    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    let orig_drive = tmp.path().join("drive_e");
    let new_drive = tmp.path().join("drive_f");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    std::fs::create_dir_all(&orig_drive).expect("mkdir orig_drive");
    std::fs::create_dir_all(&new_drive).expect("mkdir new_drive");
    let state = make_test_state(cases_dir.clone());

    let orig_img = orig_drive.join("demo_case.dd");
    let relocated_img = new_drive.join("demo_case_moved.dd");
    let tampered_img = new_drive.join("demo_case_tampered.dd");

    let raw_bytes = std::fs::read(demo_image_path()).expect("read demo.dd");
    std::fs::write(&orig_img, &raw_bytes).expect("write orig_img");
    std::fs::write(&relocated_img, &raw_bytes).expect("write relocated_img");
    let mut bad_bytes = raw_bytes.clone();
    let mid = bad_bytes.len() / 2;
    bad_bytes[mid] ^= 0xFF;
    std::fs::write(&tampered_img, &bad_bytes).expect("write tampered_img");

    // 1. 新建案件、加载镜像并扫描分区：此时 `evidence_missing == false`。
    let created = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "REBIND-01",
        "取证员",
        "镜像重绑测试",
        None,
    )
    .expect("create_case");
    assert!(!created.evidence_missing);

    let loaded = cmd_load_image(&state, &orig_img.to_string_lossy(), None).expect("load_image");
    assert!(!loaded.evidence_missing);
    let loaded_json = serde_json::to_value(&loaded).expect("serialize CaseSnapshot");
    assert_eq!(loaded_json["evidenceMissing"], false);
    let expected_sha = loaded
        .evidence
        .as_ref()
        .and_then(|e| e.sha256.clone())
        .expect("fixed sha256");

    cmd_scan_all_partitions(&state, None).expect("scan_all_partitions");
    let orig_recorded_path = loaded.evidence.as_ref().unwrap().path.clone();

    // 2. 关闭案件并移除原路径镜像，模拟移动盘符或迁移目录导致的源镜像缺失。
    cmd_close_case(&state).expect("close_case");
    std::fs::remove_file(&orig_img).expect("remove orig_img to simulate missing evidence");

    // 最近案件列表应立即识别 `evidenceMissing == true`。
    let recent = cmd_list_recent_cases(&state).expect("list_recent_cases");
    let rec = recent
        .iter()
        .find(|c| c.number == "REBIND-01")
        .expect("case in recent");
    assert!(rec.has_evidence);
    assert!(rec.evidence_missing, "源镜像缺失时最近案件必须标记 evidenceMissing = true");

    // 重开案件后 `CaseSnapshot.evidence_missing` 也应为 `true`。
    let reopened = cmd_open_case(&state, &created.case_dir).expect("reopen case with missing image");
    assert!(reopened.evidence_missing);
    let reopened_json = serde_json::to_value(&reopened).expect("serialize reopened snapshot");
    assert_eq!(reopened_json["evidenceMissing"], true);

    // 3. 尝试重绑到单字节篡改镜像：必须被 SHA-256 校验拦截拒绝，且保留原路径不覆盖。
    let bad_err = cmd_rebind_image_path(&state, &tampered_img.to_string_lossy(), None)
        .expect_err("tampered image must be rejected by SHA-256 verification");
    assert!(
        bad_err.contains("SHA-256") || bad_err.contains("不匹配"),
        "错误信息应明确指出 SHA-256 校验不匹配，实际：{bad_err}"
    );
    let snap_after_reject = cmd_get_case_snapshot(&state)
        .expect("get_case_snapshot")
        .expect("case still open");
    assert!(snap_after_reject.evidence_missing);
    assert_eq!(
        snap_after_reject.evidence.as_ref().unwrap().path,
        orig_recorded_path,
        "重绑失败后必须完整保留原镜像路径"
    );

    // 4. 重绑到字节完全一致的新路径镜像：必须通过 SHA-256 校验并刷新快照。
    let rebind_res = cmd_rebind_image_path(&state, &relocated_img.to_string_lossy(), None)
        .expect("rebind to identical image must succeed");
    assert!(rebind_res.verified);
    assert_eq!(rebind_res.sha256, expected_sha);
    assert_eq!(rebind_res.segment_count, 1);
    assert_eq!(rebind_res.old_image, orig_recorded_path);
    assert!(!rebind_res.snapshot.evidence_missing);
    assert_eq!(
        rebind_res.snapshot.evidence.as_ref().unwrap().path,
        rebind_res.new_image
    );

    // 校验 `RebindImageResponse` camelCase JSON 契约字段名。
    let rebind_json = serde_json::to_value(&rebind_res).expect("serialize RebindImageResponse");
    for key in [
        "snapshot",
        "oldImage",
        "newImage",
        "sha256",
        "verified",
        "segmentCount",
    ] {
        assert!(
            rebind_json.get(key).is_some(),
            "RebindImageResponse 缺少约定 JSON 键：{key}"
        );
    }
    assert_eq!(rebind_json["snapshot"]["evidenceMissing"], false);

    // 重绑后最近案件列表的 `evidence_missing` 恢复为 `false`，且文件预览可从新路径正常读取。
    let recent_after = cmd_list_recent_cases(&state).expect("list_recent_cases after rebind");
    let rec_after = recent_after
        .iter()
        .find(|c| c.number == "REBIND-01")
        .expect("case in recent after rebind");
    assert!(!rec_after.evidence_missing);

    let page = cmd_query_files_page(&state, None, None, ".txt", "CASE", "active", 0, 50, Some(false))
        .expect("query CASE.TXT after rebind");
    assert_eq!(page.total, 1);
    let preview = cmd_preview_file_page(&state, &page.items[0].entry_id, 0, Some(4096), "UTF-8")
        .expect("preview CASE.TXT from relocated image");
    assert!(preview.text.contains("Case note inside a nested directory."));

    // 审计日志应记录失败与成功两条 `IMAGE_REBIND` 记录且哈希链校验通过。
    let audit = cmd_list_audit_log(&state, "", None, None, Some("IMAGE_REBIND"), None, "seq", false)
        .expect("list IMAGE_REBIND audit");
    assert!(audit.valid);
    assert_eq!(audit.records.len(), 2);
    assert_eq!(audit.records[0].result, "失败");
    assert_eq!(audit.records[0].action_title, "重绑源镜像路径");
    assert_eq!(audit.records[1].result, "成功");
    assert_eq!(audit.records[1].action_title, "重绑源镜像路径");

    state.shutdown_all();
}

/// Stage B-1 集成测试 3：`scan_magic_mismatches` 自动写入 `.cache/magic-scan.json`，
/// 经 `load_cached_magic_scan` 秒级恢复（重开案件同样命中缓存）。
#[test]
fn magic_scan_disk_cache_persistence_and_reopen_hit() {
    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());

    // 构造含真实 PNG-in-TXT 魔数伪装的镜像副本。
    let mut img_bytes = std::fs::read(demo_image_path()).expect("read demo.dd");
    let marker = b"Case note inside a nested directory.";
    let pos = img_bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("locate DOCS/CASE.TXT payload");
    let png_header: [u8; 16] = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52,
    ];
    img_bytes[pos..pos + png_header.len()].copy_from_slice(&png_header);
    let spoof_img = tmp.path().join("demo_magic_cache.dd");
    std::fs::write(&spoof_img, &img_bytes).expect("write spoof image");

    let snap = cmd_create_case(
        &state,
        &cases_dir.to_string_lossy(),
        "MAGIC-CACHE-01",
        "取证员",
        "魔数扫描缓存测试",
        None,
    )
    .expect("create_case");
    cmd_load_image(&state, &spoof_img.to_string_lossy(), None).expect("load_image");
    cmd_scan_all_partitions(&state, None).expect("scan_all_partitions");

    // 1. 首次扫描前缓存不存在，返回 `None`。
    assert!(
        cmd_load_cached_magic_scan(&state)
            .expect("load_cached before scan")
            .is_none()
    );

    // 2. 执行扫描后自动落盘 `<case_folder>/.cache/magic-scan.json`。
    let report = cmd_scan_magic_mismatches(&state).expect("scan_magic_mismatches");
    assert!(!report.cancelled);
    assert!(report.mismatch_count >= 1);
    let cache_file = PathBuf::from(&snap.case_dir)
        .join(".cache")
        .join("magic-scan.json");
    assert!(cache_file.is_file(), "魔数扫描完成后应落盘 .cache/magic-scan.json");

    // 3. 当次会话直接读取缓存命中且内容完全一致。
    let cached_now = cmd_load_cached_magic_scan(&state)
        .expect("load_cached after scan")
        .expect("cache hit in same session");
    assert_eq!(cached_now, report);

    // 4. 关闭案件后读取缓存安全返回 `None`；重新打开案件后立即命中同一份磁盘缓存。
    cmd_close_case(&state).expect("close_case");
    assert!(
        cmd_load_cached_magic_scan(&state)
            .expect("load_cached when closed")
            .is_none()
    );

    cmd_open_case(&state, &snap.case_dir).expect("reopen_case");
    let cached_reopen = cmd_load_cached_magic_scan(&state)
        .expect("load_cached after reopen")
        .expect("cache hit after reopen");
    assert_eq!(cached_reopen, report);
    assert!(
        cached_reopen
            .mismatches
            .iter()
            .any(|m| m.path == "DOCS/CASE.TXT" && m.detected_type == "PNG")
    );

    state.shutdown_all();
}
