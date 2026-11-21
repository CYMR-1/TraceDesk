//! Bidirectional cross-language compatibility integration tests between Rust `tracedesk-core`
//! and Python `forensic/core` + `scripts/verify_bundle.py`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;

use tracedesk_core::{
    AppPaths, AuditOrigin, BuildBundleOptions, Case, Provenance, SearchHit, SearchOptions,
    build_bundle, examine, export_findings, group_findings, record_note, search_case,
    source_status, verify_bundle,
};

const GOLDEN_CASE_SRC: &str = r"C:\Users\cymr1\.gemini\antigravity\brain\17680ca1-4084-4cc1-9fbe-b9bcc92744bb\scratch\baseline\golden_case\demo_case";

fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create dst dir");
    for entry in fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let ty = entry.file_type().expect("file type");
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

fn find_python_executable(root: &Path) -> Option<PathBuf> {
    let cand = root.join(".venv").join("Scripts").join("python.exe");
    cand.is_file().then_some(cand)
}

#[test]
fn open_golden_python_case_and_verify_all_artifacts() {
    let src = Path::new(GOLDEN_CASE_SRC);
    if !src.is_dir() {
        eprintln!(
            "skipping external Python golden_case compatibility check (not present at {})",
            src.display()
        );
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let copied = tmp.path().join("demo_case");
    copy_dir_recursive(src, &copied);

    // 1. Open Python-generated golden case with Rust `Case::open`.
    let mut case = Case::open(&copied, None, AuditOrigin::Manual).expect("open golden case");
    assert_eq!(case.data().id, "77544962e34c412dbc68605e97a4ef1f");
    assert_eq!(case.data().number, "GOLDEN-2026-001");
    assert_eq!(case.data().examiner, "基线取证员");
    assert_eq!(case.data().target, "demo.dd 黄金兼容性样本");

    // 2. Verify all 27 audit chain records pass SHA-256 verification.
    let records = case.check_audit().expect("check golden audit chain");
    assert_eq!(records.len(), 27);
    assert_eq!(
        records.last().unwrap().hash,
        "c7c6169cd584a2ea91d0548200395599030d03cfec1a57279292d32b3037cf53"
    );
    let raw_head = fs::read(copied.join("audit.head")).expect("read audit.head");
    assert_eq!(raw_head.len(), 64);
    assert_eq!(
        std::str::from_utf8(&raw_head).unwrap(),
        "c7c6169cd584a2ea91d0548200395599030d03cfec1a57279292d32b3037cf53"
    );

    // 3. Verify 13 inventory entries and 18 MACB timeline events.
    assert_eq!(case.data().inventory.len(), 13);
    assert!(case.data().inventory.iter().any(|e| e.path == "DOCS/CASE.TXT"));
    assert!(case.data().inventory.iter().any(|e| e.path == "NOTES.TXT"));
    assert!(
        case.data()
            .inventory
            .iter()
            .any(|e| e.path == "空余空间（未分配簇）" && e.extents.is_some())
    );

    let timeline = case.timeline_events();
    assert_eq!(timeline.len(), 18);

    // 4. Verify exports and findings parsing.
    assert_eq!(case.data().exports.len(), 2);
    assert_eq!(case.data().exports[0].source, "DOCS/CASE.TXT");
    assert_eq!(case.data().exports[0].size, 38);
    assert_eq!(case.data().exports[1].source, "NOTES.TXT");
    assert_eq!(case.data().exports[1].size, 56);
    let _findings = group_findings(&records);

    // 5. Verify the Python-generated golden review bundle ZIP using native Rust `verify_bundle`.
    let golden_zip = copied.join("reports").join("report_c49fe3d534c9.zip");
    let verified_count = verify_bundle(
        &golden_zip,
        Some("a393ea20650f96e64a3423c569f403ab4b157c5b936e02645ecb02b7fb00ca0c"),
    )
    .expect("native Rust verify_bundle on Python golden ZIP");
    assert_eq!(verified_count, 10);

    case.close();
}

#[test]
fn rust_end_to_end_demo_dd_and_dual_verify_bundle() {
    let paths = AppPaths::discover();
    let demo_dd = paths.evidence_dir.join("demo.dd");
    assert!(demo_dd.is_file(), "demo.dd missing at {}", demo_dd.display());

    let tmp_cases = tempfile::tempdir().expect("temp cases root");

    // 1. Create case
    let mut case = Case::create(
        tmp_cases.path(),
        "RUST-E2E-001",
        "Rust 取证工程师",
        "demo.dd 端到端双向兼容测试",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create case");

    // 2. Load image
    case.load_image(&demo_dd, None, None, None)
        .expect("load demo.dd");
    let ev = case.data().evidence.as_ref().expect("evidence loaded");
    assert_eq!(ev.size, 9_437_184);
    assert_eq!(
        ev.sha256.as_deref(),
        Some("83029884b25c65f5cd8e94415c9a4e6a60f762459130cf96eac1e626890c70e8")
    );
    assert_eq!(ev.partitions.len(), 1);
    assert_eq!(ev.partitions[0].offset, 2048);

    // 3. Register provenance & check source status matches
    case.register_source(&Provenance {
        evidence_id: "EV-DEMO-001".to_string(),
        source: "教学测试样本".to_string(),
        acquired: "2026-11-21 18:00:00 +08:00".to_string(),
        tool: "make_demo.py".to_string(),
        expected_sha256: "83029884b25c65f5cd8e94415c9a4e6a60f762459130cf96eac1e626890c70e8"
            .to_string(),
    })
    .expect("register provenance");
    assert_eq!(
        source_status(case.data().evidence.as_ref().unwrap()),
        "交付方摘要与本机固定值一致"
    );

    // 4. Scan all partitions
    let inventory = case
        .scan_partitions(None, None, None)
        .expect("scan partitions");
    assert_eq!(inventory.len(), 13);

    // 5. Verify integrity
    assert!(case.verify_integrity(None, None, None).expect("verify"));

    // 6. Filter files
    let txt_files = case.filtered("txt", "").expect("filter txt");
    assert_eq!(txt_files.len(), 3);

    // 7. Export CASE.TXT, NOTES.TXT, and duplicate NOTES.TXT (triggers `同名副本-` subfolder)
    let case_txt = inventory
        .iter()
        .find(|e| e.path == "DOCS/CASE.TXT")
        .expect("CASE.TXT")
        .clone();
    let notes_txt = inventory
        .iter()
        .find(|e| e.path == "NOTES.TXT")
        .expect("NOTES.TXT")
        .clone();

    let exported_case = case.export(&case_txt, None).expect("export CASE.TXT");
    assert!(exported_case.is_file());
    assert_eq!(fs::metadata(&exported_case).unwrap().len(), 38);

    let exported_notes_1 = case.export(&notes_txt, None).expect("export NOTES.TXT #1");
    let exported_notes_2 = case.export(&notes_txt, None).expect("export NOTES.TXT #2");
    assert_ne!(exported_notes_1, exported_notes_2);
    assert!(
        exported_notes_2
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("同名副本-")
    );

    // 8. Forensic findings: note + file hash + file compare + export_findings
    record_note(&mut case, &case_txt, "确认该文件包含测试案件核心说明。")
        .expect("record note");
    let hash_res = examine(&mut case, &case_txt, None, None).expect("file hash");
    assert_eq!(hash_res.operation, "FILE_HASH");
    assert_eq!(hash_res.result, "成功");
    assert_eq!(
        hash_res.details["sha256"].as_str(),
        Some("65760c5c042fa64abd0398d08186802d7eb3527d2d4ae7fa2fe2e1c83c2c8113")
    );

    let cmp_res =
        examine(&mut case, &case_txt, Some(&exported_case), None).expect("file compare");
    assert_eq!(cmp_res.operation, "FILE_COMPARE");
    assert_eq!(cmp_res.result, "一致");

    let current_records = case.check_audit().expect("check audit before findings export");
    let groups = group_findings(&current_records);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].records.len(), 3);

    let exp_findings = export_findings(&mut case, &groups).expect("export_findings");
    assert_eq!(exp_findings.exported_count, 1);
    assert!(exp_findings.failed.is_empty());
    assert!(exp_findings.summary_path.is_file());

    // 9. Content search: ASCII + Chinese UTF-8 with streaming callback verification
    let cancel = AtomicBool::new(false);
    let mut streamed_ascii: Vec<SearchHit> = Vec::new();
    let ascii_out = search_case(
        &mut case,
        &SearchOptions {
            query: "TraceDesk".to_string(),
            encoding: "UTF-8".to_string(),
            limit: None,
            selected: None,
        },
        &cancel,
        None,
        Some(&mut |batch| streamed_ascii.extend_from_slice(batch)),
        None,
    )
    .expect("ASCII search");
    assert_eq!(ascii_out.record.status, "完成");
    assert_eq!(ascii_out.record.hits.len(), 1);
    assert_eq!(ascii_out.record.hits[0].path, "README.TXT");
    assert_eq!(ascii_out.record.hits[0].file_byte, 0);
    assert_eq!(streamed_ascii, ascii_out.record.hits);
    assert!(ascii_out.report_path.is_file());

    let mut streamed_zh: Vec<SearchHit> = Vec::new();
    let zh_out = search_case(
        &mut case,
        &SearchOptions {
            query: "取证演示".to_string(),
            encoding: "UTF-8".to_string(),
            limit: None,
            selected: None,
        },
        &cancel,
        None,
        Some(&mut |batch| streamed_zh.extend_from_slice(batch)),
        None,
    )
    .expect("Chinese UTF-8 search");
    assert_eq!(zh_out.record.status, "完成");
    assert_eq!(zh_out.record.hits.len(), 1);
    assert_eq!(zh_out.record.hits[0].path, "NOTES.TXT");
    assert_eq!(streamed_zh, zh_out.record.hits);

    // 10. Timeline
    let tl = case.timeline().expect("timeline");
    assert_eq!(tl.len(), 18);

    // 11. Generate Markdown report & verify all 10 required sections
    let report_path = case.report(None).expect("generate report");
    let report_md = fs::read_to_string(&report_path).expect("read report md");
    for heading in [
        "# 电子数据取证报告",
        "## 案件信息",
        "## 原始证据与完整性",
        "## 文件清单摘要",
        "### 分区概览",
        "### 文件清单抽样（前 200 项）",
        "## 导出副本",
        "## 内容搜索记录",
        "## 文件取证发现",
        "## 审计日志摘要",
        "## 取证人员确认",
        "## 适用边界",
    ] {
        assert!(
            report_md.contains(heading),
            "report missing required heading: {heading}"
        );
    }

    // 12. Build review bundle ZIP + .zip.sha256
    let bundle = build_bundle(&mut case, &BuildBundleOptions::default(), None)
        .expect("build review bundle");
    assert!(bundle.bundle_path.is_file());
    assert!(bundle.sha256_path.is_file());
    assert_eq!(bundle.included_exports, 4);
    assert_eq!(bundle.included_searches, 2);
    assert_eq!(bundle.omitted_exports, 0);
    assert_eq!(bundle.omitted_searches, 0);

    let sha_file_content = fs::read_to_string(&bundle.sha256_path).expect("read .zip.sha256");
    let zip_name = bundle.bundle_path.file_name().unwrap().to_string_lossy();
    assert_eq!(sha_file_content, format!("{}  {zip_name}\n", bundle.sha256));

    // Verify `audit.head` on disk is exact 64 ASCII bytes with NO trailing newline.
    let head_bytes = fs::read(case.folder().join("audit.head")).expect("read audit.head");
    assert_eq!(head_bytes.len(), 64);
    assert!(!head_bytes.contains(&b'\n'));
    assert!(!head_bytes.contains(&b'\r'));

    let case_dir = case.folder().to_path_buf();
    case.close();

    // 13A. Native Rust `verify_bundle` verification
    let rust_verified =
        verify_bundle(&bundle.bundle_path, Some(&bundle.sha256)).expect("Rust verify_bundle");
    assert_eq!(rust_verified, 12); // report.md + 4 exports + 2 searches + audit.jsonl + audit.head + verify_bundle.py + manifest.json + 复核说明.txt

    // 13B. Optional cross-language verification with embedded standalone `verify_bundle.py`
    //      when local `.venv\Scripts\python.exe` and the script are present.
    if let (Some(python_exe), Some(verify_script)) = (
        find_python_executable(&paths.root),
        paths.verify_bundle_script(),
    ) {
        let output = Command::new(&python_exe)
            .arg(&verify_script)
            .arg(&bundle.bundle_path)
            .arg("--sha256")
            .arg(&bundle.sha256)
            .output()
            .expect("spawn python verify_bundle.py");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "Python verify_bundle.py failed!\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("核验通过：12 份材料及审计链。"),
            "unexpected verify_bundle.py stdout: {stdout}"
        );
    }

    // 13C. Bonus: Re-open our Rust-created case in Rust AND ensure full audit chain passes!
    let mut reopened = Case::open(&case_dir, None, AuditOrigin::Manual).expect("reopen Rust case");
    let final_records = reopened.check_audit().expect("reopen audit check");
    assert!(final_records.len() >= 15);
    assert_eq!(reopened.data().inventory.len(), 13);
    reopened.close();
}
