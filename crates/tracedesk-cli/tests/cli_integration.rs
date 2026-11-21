//! Integration tests for `tracedesk-cli`:
//! 1. `verify-bundle` on the Python golden baseline ZIP (`scratch/baseline/golden_case/demo_case`)
//! 2. `verify-bundle` tamper detection across all attack surfaces (external SHA-256, member bytes,
//!    audit chain, 64-byte `audit.head` newline injection, `report.md`, `manifest.json` exports,
//!    `searches/*.json`, and member set mismatch)
//! 3. `make-demo` pure-Rust FAT16 image generation (byte-for-byte parity + deleted file recovery)
//! 4. `run-demo` full closed-loop forensic workflow & self-verification

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tracedesk_cli::{
    EXPECTED_DEMO_DD_SHA256, EXPECTED_DEMO_VOLUME_DD_SHA256, create_demo_image_with_deleted,
};
use tracedesk_core::{AuditOrigin, Case, sha256_hex};
use tracedesk_engines::{TskCli, sha256_file};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const GOLDEN_CASE_DIR: &str = r"C:\Users\cymr1\.gemini\antigravity\brain\17680ca1-4084-4cc1-9fbe-b9bcc92744bb\scratch\baseline\golden_case\demo_case";
const GOLDEN_BUNDLE_NAME: &str = "report_c49fe3d534c9.zip";
const GOLDEN_BUNDLE_SHA256: &str =
    "a393ea20650f96e64a3423c569f403ab4b157c5b936e02645ecb02b7fb00ca0c";

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tracedesk-cli"))
}

/// Helper to read all members from an existing ZIP into an ordered map.
fn read_zip_members(zip_path: &Path) -> BTreeMap<String, Vec<u8>> {
    let file = File::open(zip_path).expect("open zip");
    let mut archive = ZipArchive::new(file).expect("parse zip");
    let mut map = BTreeMap::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).expect("zip entry");
        let name = entry.name().to_string();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).expect("read entry");
        map.insert(name, buf);
    }
    map
}

/// Write a map of members to a new ZIP file, optionally recalculating `SHA256SUMS.json`.
fn write_zip_members(
    dst_path: &Path,
    mut members: BTreeMap<String, Vec<u8>>,
    recompute_sums: bool,
) {
    if recompute_sums {
        let mut sums: BTreeMap<String, String> = BTreeMap::new();
        for (name, bytes) in &members {
            if name != "SHA256SUMS.json" {
                sums.insert(name.clone(), sha256_hex(bytes));
            }
        }
        let sums_bytes = serde_json::to_vec_pretty(&sums).expect("serialize sums");
        members.insert("SHA256SUMS.json".to_string(), sums_bytes);
    }

    let file = File::create(dst_path).expect("create zip");
    let mut writer = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for (name, bytes) in &members {
        writer.start_file(name, opts).expect("start_file");
        writer.write_all(bytes).expect("write_all");
    }
    writer.finish().expect("finish zip");
}

#[test]
fn verify_bundle_passes_golden_case_and_detects_all_tampering() {
    let golden_zip = Path::new(GOLDEN_CASE_DIR)
        .join("reports")
        .join(GOLDEN_BUNDLE_NAME);
    assert!(
        golden_zip.is_file(),
        "Golden baseline bundle missing: {}",
        golden_zip.display()
    );

    // 1. Pass with explicit `--sha256`
    let out = Command::new(cli_bin())
        .arg("verify-bundle")
        .arg(&golden_zip)
        .arg("--sha256")
        .arg(GOLDEN_BUNDLE_SHA256)
        .output()
        .expect("run verify-bundle");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "verify-bundle failed on golden zip: stdout={stdout}, stderr={stderr}"
    );
    assert_eq!(stdout.trim(), "核验通过：10 份材料及审计链。");

    // 2. Pass without `--sha256`
    let out_no_sha = Command::new(cli_bin())
        .arg("verify-bundle")
        .arg(&golden_zip)
        .output()
        .expect("run verify-bundle without sha256");
    assert!(out_no_sha.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out_no_sha.stdout).trim(),
        "核验通过：10 份材料及审计链。"
    );

    // 3. Reject wrong outer `--sha256`
    let out_bad_sha = Command::new(cli_bin())
        .arg("verify-bundle")
        .arg(&golden_zip)
        .arg("--sha256")
        .arg("0".repeat(64))
        .output()
        .expect("run verify-bundle bad sha256");
    assert!(!out_bad_sha.status.success());
    assert!(
        String::from_utf8_lossy(&out_bad_sha.stderr).contains("复核包外部 SHA-256 不匹配"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&out_bad_sha.stderr)
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let base_members = read_zip_members(&golden_zip);

    // 4. Tamper `report.md` without updating SHA256SUMS.json -> "成员摘要不匹配：report.md"
    {
        let mut m = base_members.clone();
        m.get_mut("report.md")
            .unwrap()
            .extend_from_slice(b"\nTAMPERED");
        let zip_path = tmp.path().join("tamper_report_raw.zip");
        write_zip_members(&zip_path, m, false);
        let res = Command::new(cli_bin())
            .arg("verify-bundle")
            .arg(&zip_path)
            .output()
            .unwrap();
        assert!(!res.status.success());
        assert!(
            String::from_utf8_lossy(&res.stderr).contains("成员摘要不匹配：report.md"),
            "stderr: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }

    // 5. Tamper `report.md` AND recompute SHA256SUMS.json -> caught by audit chain REPORT_GENERATE digest check!
    {
        let mut m = base_members.clone();
        m.get_mut("report.md")
            .unwrap()
            .extend_from_slice(b"\nFORGED_REPORT");
        let zip_path = tmp.path().join("tamper_report_resummed.zip");
        write_zip_members(&zip_path, m, true);
        let res = Command::new(cli_bin())
            .arg("verify-bundle")
            .arg(&zip_path)
            .output()
            .unwrap();
        assert!(!res.status.success());
        assert!(
            String::from_utf8_lossy(&res.stderr).contains("报告摘要不匹配"),
            "stderr: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }

    // 6. Tamper `audit.jsonl` AND recompute SHA256SUMS.json -> caught by audit hash chain check!
    {
        let mut m = base_members.clone();
        let audit_str = String::from_utf8(m["audit.jsonl"].clone()).unwrap();
        let tampered_audit = audit_str.replacen("基线取证员", "篡改取证员", 1);
        m.insert("audit.jsonl".to_string(), tampered_audit.into_bytes());
        let zip_path = tmp.path().join("tamper_audit_chain.zip");
        write_zip_members(&zip_path, m, true);
        let res = Command::new(cli_bin())
            .arg("verify-bundle")
            .arg(&zip_path)
            .output()
            .unwrap();
        assert!(!res.status.success());
        assert!(
            String::from_utf8_lossy(&res.stderr).contains("审计链不一致"),
            "stderr: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }

    // 7. Tamper `audit.head` by appending a trailing `\n` (65 bytes) AND recompute SHA256SUMS.json -> "审计链尾不匹配"
    {
        let mut m = base_members.clone();
        m.get_mut("audit.head").unwrap().push(b'\n');
        let zip_path = tmp.path().join("tamper_audit_head_newline.zip");
        write_zip_members(&zip_path, m, true);
        let res = Command::new(cli_bin())
            .arg("verify-bundle")
            .arg(&zip_path)
            .output()
            .unwrap();
        assert!(!res.status.success());
        assert!(
            String::from_utf8_lossy(&res.stderr).contains("审计链尾不匹配"),
            "stderr: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }

    // 8. Tamper `manifest.json` export size AND recompute SHA256SUMS.json -> "导出记录不匹配"
    {
        let mut m = base_members.clone();
        let mut manifest: Value = serde_json::from_slice(&m["manifest.json"]).unwrap();
        manifest["exports"][0]["size"] = Value::from(999_999u64);
        m.insert(
            "manifest.json".to_string(),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        );
        let zip_path = tmp.path().join("tamper_manifest_export.zip");
        write_zip_members(&zip_path, m, true);
        let res = Command::new(cli_bin())
            .arg("verify-bundle")
            .arg(&zip_path)
            .output()
            .unwrap();
        assert!(!res.status.success());
        assert!(
            String::from_utf8_lossy(&res.stderr).contains("导出记录不匹配"),
            "stderr: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }

    // 9. Tamper `searches/search_*.json` AND recompute SHA256SUMS.json -> "搜索记录不匹配"
    {
        let mut m = base_members.clone();
        let search_key = m
            .keys()
            .find(|k| k.starts_with("searches/"))
            .unwrap()
            .clone();
        m.get_mut(&search_key).unwrap().push(b'\n');
        let zip_path = tmp.path().join("tamper_search_resummed.zip");
        write_zip_members(&zip_path, m, true);
        let res = Command::new(cli_bin())
            .arg("verify-bundle")
            .arg(&zip_path)
            .output()
            .unwrap();
        assert!(!res.status.success());
        assert!(
            String::from_utf8_lossy(&res.stderr).contains("搜索记录不匹配"),
            "stderr: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }

    // 10. Add an unlisted member to ZIP without adding to SHA256SUMS.json -> "成员重复或与清单不一致"
    {
        let mut m = base_members;
        m.insert("extra_unlisted.txt".to_string(), b"rogue".to_vec());
        let zip_path = tmp.path().join("tamper_extra_member.zip");
        write_zip_members(&zip_path, m, false);
        let res = Command::new(cli_bin())
            .arg("verify-bundle")
            .arg(&zip_path)
            .output()
            .unwrap();
        assert!(!res.status.success());
        assert!(
            String::from_utf8_lossy(&res.stderr).contains("成员重复或与清单不一致"),
            "stderr: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }
}

#[test]
fn make_demo_and_run_demo_closed_loop_via_cli() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let evidence_dir = tmp.path().join("evidence");
    let cases_dir = tmp.path().join("cases");
    let logs_dir = tmp.path().join("logs");

    // 1. Run `make-demo --out-dir <evidence_dir>`
    let make_out = Command::new(cli_bin())
        .arg("make-demo")
        .arg("--out-dir")
        .arg(&evidence_dir)
        .output()
        .expect("run make-demo");
    let make_stdout = String::from_utf8_lossy(&make_out.stdout);
    let make_stderr = String::from_utf8_lossy(&make_out.stderr);
    assert!(
        make_out.status.success(),
        "make-demo failed: stdout={make_stdout}, stderr={make_stderr}"
    );
    assert!(make_stdout.contains("已生成："));

    let demo_dd = evidence_dir.join("demo.dd");
    let demo_vol = evidence_dir.join("demo_volume.dd");
    assert!(demo_dd.is_file());
    assert!(evidence_dir.join("demo.manifest.json").is_file());
    assert!(evidence_dir.join("demo.dd.sha256").is_file());
    assert!(demo_vol.is_file());
    assert!(evidence_dir.join("demo_volume.manifest.json").is_file());
    assert!(evidence_dir.join("demo_volume.dd.sha256").is_file());

    // Byte-for-byte SHA-256 parity with Python `scripts/make_demo.py`
    assert_eq!(
        sha256_file(&demo_dd, None, None).unwrap(),
        EXPECTED_DEMO_DD_SHA256
    );
    assert_eq!(
        sha256_file(&demo_vol, None, None).unwrap(),
        EXPECTED_DEMO_VOLUME_DD_SHA256
    );

    // Running `make-demo` a second time must preserve existing images without overwriting
    let make_again = Command::new(cli_bin())
        .arg("make-demo")
        .arg("--out-dir")
        .arg(&evidence_dir)
        .output()
        .expect("run make-demo second time");
    assert!(make_again.status.success());
    assert!(
        String::from_utf8_lossy(&make_again.stdout).contains("已存在，保留："),
        "expected preservation message"
    );

    // 2. Verify pure-Rust FAT16 image with deleted entry (`0xE5`) can be scanned and recovered by TSK
    let deleted_dd = evidence_dir.join("demo_deleted.dd");
    let del_manifest =
        create_demo_image_with_deleted(&deleted_dd, true).expect("create deleted demo image");
    assert!(deleted_dd.is_file());
    assert!(del_manifest.sha256_path.is_file());
    let tsk = TskCli::discover(None).expect("discover TSK");
    let del_entries = tsk
        .list_entries(&deleted_dd, 2048, true, None, "", None)
        .expect("list_entries on deleted_dd");
    let del_entry = del_entries
        .iter()
        .find(|e| e.deleted && e.path.ends_with("ELETED.TXT"))
        .expect("should find deleted DELETED.TXT entry");
    let mut recovered = Vec::new();
    tsk.stream_entry(&deleted_dd, del_entry, None, |chunk| {
        recovered.extend_from_slice(chunk);
        Ok(())
    })
    .expect("recover deleted entry via icat -r");
    assert_eq!(
        recovered,
        b"Deleted forensic artifact recoverable via TSK icat -r.\r\n"
    );

    // 3. Run `run-demo --cases-dir <cases_dir> --evidence <demo_dd>`
    let demo_out = Command::new(cli_bin())
        .arg("run-demo")
        .arg("--cases-dir")
        .arg(&cases_dir)
        .arg("--evidence")
        .arg(&demo_dd)
        .env("TRACEDESK_LOGS_DIR", &logs_dir)
        .output()
        .expect("run run-demo");
    let demo_stdout = String::from_utf8_lossy(&demo_out.stdout);
    let demo_stderr = String::from_utf8_lossy(&demo_out.stderr);
    assert!(
        demo_out.status.success(),
        "run-demo failed: stdout={demo_stdout}, stderr={demo_stderr}"
    );
    assert!(demo_stdout.contains("案件："));
    assert!(demo_stdout.contains("导出："));
    assert!(demo_stdout.contains("报告："));
    assert!(demo_stdout.contains("复核包："));
    assert!(demo_stdout.contains("核验通过：10 份材料及审计链。"));
    assert!(demo_stdout.contains("耗时明细："));

    // Verify `latest-demo.txt` marker was written and points to a valid case directory
    let marker_path = logs_dir.join("latest-demo.txt");
    assert!(marker_path.is_file(), "latest-demo.txt missing");
    let case_dir = PathBuf::from(fs::read_to_string(&marker_path).unwrap().trim());
    assert!(case_dir.is_dir(), "case_dir missing: {}", case_dir.display());

    // Open the generated case in Rust and verify all artifacts & audit chain
    let mut case = Case::open(&case_dir, None, AuditOrigin::Manual).expect("open demo case");
    assert_eq!(case.data().inventory.len(), 13);
    assert_eq!(case.data().exports.len(), 2);
    let records = case.check_audit().expect("verify demo audit chain");
    assert!(records.iter().any(|r| r.action == "FILE_NOTE"));
    assert!(records.iter().any(|r| r.action == "FILE_HASH"));
    assert!(records.iter().any(|r| r.action == "CONTENT_SEARCH"));
    assert!(records.iter().any(|r| r.action == "TIMELINE"));
    assert!(records.iter().any(|r| r.action == "REPORT_GENERATE"));
    assert!(records.iter().any(|r| r.action == "REVIEW_EXPORT"));
    case.close();

    // Find the review bundle ZIP in `<case_dir>/reports/` and verify via `verify-bundle` CLI
    let reports_dir = case_dir.join("reports");
    let zip_path = fs::read_dir(&reports_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().and_then(|s| s.to_str()) == Some("zip"))
        .expect("find review bundle zip");
    let sha_file = zip_path.with_extension("zip.sha256");
    let expected_sha = fs::read_to_string(&sha_file)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();

    let verify_out = Command::new(cli_bin())
        .arg("verify-bundle")
        .arg(&zip_path)
        .arg("--sha256")
        .arg(&expected_sha)
        .output()
        .expect("verify-bundle on run-demo zip");
    assert!(verify_out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&verify_out.stdout).trim(),
        "核验通过：10 份材料及审计链。"
    );
}

#[test]
fn cli_argument_parsing_and_help_version_commands() {
    let help_out = Command::new(cli_bin())
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(help_out.status.success());
    let help_stdout = String::from_utf8_lossy(&help_out.stdout);
    assert!(help_stdout.contains("verify-bundle"));
    assert!(help_stdout.contains("run-demo"));
    assert!(help_stdout.contains("make-demo"));
    assert!(help_stdout.contains("bench"));

    let ver_out = Command::new(cli_bin())
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(ver_out.status.success());
    assert!(
        String::from_utf8_lossy(&ver_out.stdout)
            .trim()
            .starts_with("tracedesk-cli ")
    );

    let unknown_out = Command::new(cli_bin())
        .arg("unknown-subcmd")
        .output()
        .expect("run unknown-subcmd");
    assert!(!unknown_out.status.success());
    assert!(String::from_utf8_lossy(&unknown_out.stderr).contains("未知子命令"));

    let missing_arg_out = Command::new(cli_bin())
        .arg("verify-bundle")
        .output()
        .expect("run verify-bundle without path");
    assert!(!missing_arg_out.status.success());
    assert!(String::from_utf8_lossy(&missing_arg_out.stderr).contains("缺少复核包"));
}

