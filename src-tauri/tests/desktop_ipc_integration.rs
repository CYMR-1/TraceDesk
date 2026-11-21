//! End-to-end integration tests for `tracedesk-desktop` IPC commands, JSON contract
//! alignment with `frontend/src/types/ipc.ts`, and embedded Streamable HTTP MCP coordination.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use tempfile::tempdir;
use tracedesk_core::{AppPaths, verify_bundle};
use tracedesk_desktop_lib::AppState;
use tracedesk_desktop_lib::commands::{
    cmd_bookmark_search_hits, cmd_build_review_bundle, cmd_build_timeline,
    cmd_cancel_content_search, cmd_cancel_scan_partitions, cmd_cancel_verify_integrity,
    cmd_check_busy_before_close, cmd_close_case, cmd_create_case, cmd_examine_file,
    cmd_export_file, cmd_export_findings, cmd_export_fsstat, cmd_generate_report,
    cmd_get_app_paths, cmd_get_case_snapshot, cmd_get_guide_pages, cmd_get_mcp_status,
    cmd_get_tree_children, cmd_inspect_bundle_materials, cmd_list_audit_log, cmd_list_findings,
    cmd_list_recent_cases, cmd_load_image, cmd_load_search_record, cmd_locate_file_in_scope,
    cmd_open_case, cmd_preview_file_image, cmd_preview_file_page, cmd_query_files_page,
    cmd_query_timeline_page, cmd_record_finding_note, cmd_register_source, cmd_scan_all_partitions,
    cmd_start_content_search, cmd_start_mcp_http, cmd_stop_mcp_http, cmd_suggest_case_dir,
    cmd_verify_integrity,
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

fn send_http_request(port: u16, host_header: &str, body: &str) -> (u16, String) {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).expect("connect to local MCP HTTP server");
    let req = format!(
        "POST /mcp HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).expect("write request");
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

#[test]
fn full_desktop_ipc_workflow_and_json_contract_with_demo_dd() {
    let tmp = tempdir().expect("create tempdir");
    let cases_dir = tmp.path().join("cases");
    std::fs::create_dir_all(&cases_dir).expect("mkdir cases");
    let state = make_test_state(cases_dir.clone());
    let demo_dd = demo_image_path();

    // 1. App paths & suggest_case_dir & guide pages
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

    // 2. Create case & snapshot JSON keys
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

    // 3. Load real demo.dd & scan all partitions
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

    // 4. Verify integrity & register source (mismatch -> error, match -> verified)
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

    // 5. Export fsstat
    let fsstat_res = cmd_export_fsstat(&state, part_offset).expect("export_fsstat");
    assert!(PathBuf::from(&fsstat_res.path).is_file());

    // 6. Lazy tree children & query_files_page (with logFilter audit check) & locate_file_in_scope
    let root_tree = cmd_get_tree_children(&state, part_offset, "", None).expect("get_tree_children");
    assert!(!root_tree.nodes.is_empty());
    assert!(root_tree.nodes.iter().any(|n| n.kind == "directory" && n.scope_path.as_deref() == Some("DOCS")));

    let audit_before_filter = cmd_list_audit_log(&state, "", None, None, Some("FILE_FILTER"), None, "seq", false)
        .expect("audit before filter");
    assert_eq!(audit_before_filter.records.len(), 0);

    // Query without logFilter -> must NOT write FILE_FILTER
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

    // Query with logFilter = true -> writes exactly 1 FILE_FILTER
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

    // 7. Preview file page (UTF-8 + HEX) & non-image preview
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

    // 8. Export file, examine (hash + compare), record note, list & export findings
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
    assert_eq!(findings.groups[0].count, 3); // FILE_HASH + FILE_COMPARE + FILE_NOTE

    let group_keys: Vec<String> = findings.groups.iter().map(|g| g.group_key.clone()).collect();
    let exp_findings = cmd_export_findings(&state, &group_keys).expect("export_findings");
    assert_eq!(exp_findings.exported_count, 1);
    assert_eq!(exp_findings.failed_count, 0);
    assert!(PathBuf::from(&exp_findings.summary_path).is_file());

    // 9. MACB Timeline build & paginated query
    let tl_build = cmd_build_timeline(&state).expect("build_timeline");
    assert!(tl_build.total > 0);
    assert!(!tl_build.filter_options.events.is_empty());

    let tl_page = cmd_query_timeline_page(&state, "CASE.TXT", Some("M 内容修改"), None, None, "seq", false, 0, 100)
        .expect("query_timeline_page");
    assert!(tl_page.total >= 1);
    assert!(tl_page.items.iter().all(|r| r.event == "M 内容修改"));

    // 10. Content search (HEX: "6E 6F 74 65" -> "note" at byte 5 in DOCS/CASE.TXT) & bookmark & reload
    let search_res = cmd_start_content_search(&state, "6E 6F 74 65", "HEX", None, None)
        .expect("start_content_search");
    assert_eq!(search_res.needle_hex, "6e6f7465");

    let bookmark_res = cmd_bookmark_search_hits(&state, &search_res.search_id, &[0])
        .expect("bookmark_search_hits");
    assert_eq!(bookmark_res.saved_count, 1);

    // Verify historical search record can be reloaded
    let report_name = {
        let searches = state.searches.lock().unwrap();
        searches
            .get(&search_res.search_id)
            .and_then(|s| s.report_name.clone())
            .expect("search report saved")
    };
    let reloaded_hits = cmd_load_search_record(&state, &report_name).expect("load_search_record");
    assert!(reloaded_hits.iter().any(|h| h.path == "DOCS/CASE.TXT" && h.pos == 5));

    // 11. Report generation & review bundle material inspection (including missing export detection)
    let report_res = cmd_generate_report(&state).expect("generate_report");
    let report_text = std::fs::read_to_string(&report_res.path).expect("read report.md");
    assert!(report_text.contains("# 电子数据取证报告"));
    assert!(report_text.contains("## 适用边界"));

    // Delete the first exported file to test missing-material detection
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

    // 12. Audit log verification + cancel/busy helpers + reopen/close case
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

    // Open a case in the desktop AppState (holding case.lock!)
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

    // Pick a free ephemeral port on 127.0.0.1
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

    // 1. DNS rebinding guard must reject foreign Host header with 403
    let (code_403, _) = send_http_request(
        port,
        "evil.example.com:8765",
        &json!({"jsonrpc":"2.0","id":1,"method":"ping"}).to_string(),
    );
    assert_eq!(code_403, 403);

    // 2. initialize & tools/list & resources/list
    let host = format!("127.0.0.1:{port}");
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
    assert_eq!(tools_val["result"]["tools"].as_array().unwrap().len(), 19);

    // 3. Call tracedesk_record_finding via HTTP MCP WHILE the desktop holds case.lock!
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
                    "case_dir": snap.case_dir,
                    "path": "DOCS/CASE.TXT",
                    "note": "来自本地 HTTP MCP 协同写入的取证发现",
                    "actor": "ai-assistant"
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code_call, 200);
    let call_val: Value = serde_json::from_str(&body_call).expect("parse tool call");
    assert_eq!(call_val["result"]["isError"], false);

    // 4. Desktop audit log must immediately see the MCP record with origin="mcp" & valid chain!
    let audit = cmd_list_audit_log(&state, "", Some("MCP"), None, None, None, "seq", true)
        .expect("list_audit_log after mcp");
    assert!(audit.valid);
    assert_eq!(audit.records.len(), 1);
    assert_eq!(audit.records[0].origin, "mcp");
    assert_eq!(audit.records[0].origin_label, "MCP");
    assert_eq!(audit.records[0].action, "FILE_NOTE");

    let st_stopped = cmd_stop_mcp_http(&state).expect("stop_mcp_http");
    assert!(!st_stopped.running);
    let _ = cmd_close_case(&state);
}
