//! Standalone review bundle verifier (`verify-bundle <zip_path> [--sha256 <hex64>]`),
//! 100% compatible with `scripts/verify_bundle.py`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use serde_json::Value;
use tracedesk_core::{CoreError, CoreResult, verify_bundle};
use zip::ZipArchive;

/// Verify a TraceDesk review bundle ZIP file and all embedded materials, audit chain,
/// `audit.head` (exact 64 ASCII bytes), `report.md`, `manifest.json` exports, and
/// `searches/*.json` digests against the audit chain.
///
/// Returns the number of verified material files in `SHA256SUMS.json`.
pub fn verify_bundle_strict(zip_path: &Path, expected_sha256: Option<&str>) -> CoreResult<usize> {
    if !zip_path.is_file() {
        return Err(CoreError::NotFound(format!(
            "复核包文件不存在：{}",
            zip_path.display()
        )));
    }

    // 1. Run core verification:
    //    - outer ZIP SHA-256 (if provided)
    //    - unique ZIP member names & exact set equality with SHA256SUMS.json + {"SHA256SUMS.json"}
    //    - per-member SHA-256 recomputation
    //    - full audit.jsonl canonical JSON SHA-256 hash chain from genesis 0^64
    //    - exact 64-byte audit.head (no newline strip) & manifest.json audit_head match
    //    - manifest.json exports member SHA-256 and uncompressed size match
    let count = verify_bundle(zip_path, expected_sha256)?;

    // 2. Additional cross-checks on report.md and searches/*.json against audit.jsonl & manifest.json.
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;

    let checks: BTreeMap<String, String> = {
        let mut entry = archive.by_name("SHA256SUMS.json").map_err(|_| {
            CoreError::IntegrityFailed("复核包缺少 SHA256SUMS.json".to_string())
        })?;
        let mut raw = String::new();
        entry.read_to_string(&mut raw)?;
        serde_json::from_str(&raw)?
    };

    if !checks.contains_key("report.md") {
        return Err(CoreError::IntegrityFailed(
            "复核包缺少取证报告 report.md".to_string(),
        ));
    }

    let manifest: Value = {
        let mut entry = archive.by_name("manifest.json")?;
        let mut raw = String::new();
        entry.read_to_string(&mut raw)?;
        serde_json::from_str(&raw)?
    };

    // Parse audit.jsonl records for latest REPORT_GENERATE and all CONTENT_SEARCH digests.
    let mut last_report_sha: Option<String> = None;
    let mut audit_searches: HashMap<String, String> = HashMap::new();
    {
        let entry = archive.by_name("audit.jsonl")?;
        let reader = BufReader::new(entry);
        for line_res in reader.lines() {
            let line = line_res?;
            let rec: Value = serde_json::from_str(&line)?;
            let action = rec.get("action").and_then(Value::as_str).unwrap_or("");
            let subject = rec.get("subject").and_then(Value::as_str).unwrap_or("");
            let sha = rec
                .get("details")
                .and_then(|d| d.get("sha256"))
                .and_then(Value::as_str);

            if action == "REPORT_GENERATE"
                && let Some(s) = sha
                && !s.is_empty()
            {
                last_report_sha = Some(s.to_string());
            } else if action == "CONTENT_SEARCH"
                && let Some(s) = sha
                && !s.is_empty()
                && !subject.is_empty()
            {
                audit_searches.insert(subject.to_string(), s.to_string());
            }
        }
    }

    if let Some(expected_report_sha) = last_report_sha
        && checks.get("report.md") != Some(&expected_report_sha)
    {
        return Err(CoreError::IntegrityFailed(
            "报告摘要不匹配：report.md 与审计链记录不一致".to_string(),
        ));
    }

    // Collect omitted search names from manifest.json.
    let mut omitted_search_names: HashSet<String> = HashSet::new();
    if let Some(omitted) = manifest.get("omitted_searches").and_then(Value::as_array) {
        for item in omitted {
            if let Some(name) = item.get("name").and_then(Value::as_str) {
                omitted_search_names.insert(name.to_string());
            }
        }
    }

    // Every `searches/<name>` member in the ZIP must match its CONTENT_SEARCH audit record digest.
    for (member, actual_sha) in &checks {
        if let Some(search_name) = member.strip_prefix("searches/") {
            match audit_searches.get(search_name) {
                Some(expected_sha) if expected_sha == actual_sha => {}
                _ => {
                    return Err(CoreError::IntegrityFailed(format!(
                        "搜索记录不匹配：{member}"
                    )));
                }
            }
        }
    }

    // Every CONTENT_SEARCH audit record with a sha256 must either be present in `searches/` or listed in `omitted_searches`.
    for (search_name, expected_sha) in &audit_searches {
        let member = format!("searches/{search_name}");
        if let Some(actual_sha) = checks.get(&member) {
            if actual_sha != expected_sha {
                return Err(CoreError::IntegrityFailed(format!(
                    "搜索记录不匹配：{member}"
                )));
            }
        } else if !omitted_search_names.contains(search_name) {
            return Err(CoreError::IntegrityFailed(format!(
                "搜索记录缺失且未在 omitted_searches 登记：{member}"
            )));
        }
    }

    Ok(count)
}

/// Run the `verify-bundle` CLI command and return the formatted success line.
pub fn run_verify_bundle_command(
    zip_path: &Path,
    expected_sha256: Option<&str>,
) -> CoreResult<String> {
    let count = verify_bundle_strict(zip_path, expected_sha256)?;
    Ok(format!("核验通过：{count} 份材料及审计链。"))
}
