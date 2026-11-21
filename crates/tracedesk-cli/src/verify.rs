//! 独立复核包核验器（`verify-bundle <zip_path> [--sha256 <hex64>]`），
//! 与 `scripts/verify_bundle.py` 100% 兼容。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use serde_json::Value;
use tracedesk_core::{CoreError, CoreResult, verify_bundle};
use zip::ZipArchive;

/// 核验 TraceDesk 复核包 ZIP 文件及其内嵌材料、审计链、
/// `audit.head`（严格 64 字节 ASCII）、`report.md`、`manifest.json` 导出记录，
/// 以及 `searches/*.json` 摘要与审计链的一致性。
///
/// 返回 `SHA256SUMS.json` 中通过核验的材料文件数量。
pub fn verify_bundle_strict(zip_path: &Path, expected_sha256: Option<&str>) -> CoreResult<usize> {
    if !zip_path.is_file() {
        return Err(CoreError::NotFound(format!(
            "复核包文件不存在：{}",
            zip_path.display()
        )));
    }

    // 1. 执行核心核验：
    //    - 外部 ZIP 文件的 SHA-256（若已提供）
    //    - ZIP 成员名唯一性，且成员集合与 SHA256SUMS.json + {"SHA256SUMS.json"} 完全一致
    //    - 逐成员重新计算 SHA-256 摘要
    //    - 从创世哈希 0^64 起校验 audit.jsonl 的完整规范 JSON SHA-256 哈希链
    //    - 校验严格 64 字节的 audit.head（不去除换行符）并与 manifest.json 中的 audit_head 比对
    //    - 校验 manifest.json 中导出成员的 SHA-256 与未压缩大小是否匹配
    let count = verify_bundle(zip_path, expected_sha256)?;

    // 2. 针对 report.md 与 searches/*.json 补充与 audit.jsonl 及 manifest.json 的交叉校验。
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

    // 解析 audit.jsonl 记录，提取最新一次 REPORT_GENERATE 及全部 CONTENT_SEARCH 摘要。
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

    // 从 manifest.json 中收集被省略的搜索记录名称。
    let mut omitted_search_names: HashSet<String> = HashSet::new();
    if let Some(omitted) = manifest.get("omitted_searches").and_then(Value::as_array) {
        for item in omitted {
            if let Some(name) = item.get("name").and_then(Value::as_str) {
                omitted_search_names.insert(name.to_string());
            }
        }
    }

    // ZIP 中的每个 `searches/<name>` 成员均须与对应的 CONTENT_SEARCH 审计记录摘要一致。
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

    // 每条包含 sha256 的 CONTENT_SEARCH 审计记录，必须存在于 `searches/` 中或已登记在 `omitted_searches` 中。
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

/// 运行 `verify-bundle` CLI 子命令，并返回格式化后的成功提示信息。
pub fn run_verify_bundle_command(
    zip_path: &Path,
    expected_sha256: Option<&str>,
) -> CoreResult<String> {
    let count = verify_bundle_strict(zip_path, expected_sha256)?;
    Ok(format!("核验通过：{count} 份材料及审计链。"))
}
