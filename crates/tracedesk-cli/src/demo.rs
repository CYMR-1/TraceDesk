//! 完整端到端取证演示流程（`run-demo [--cases-dir <dir>] [--evidence <path>]`），
//! 在对齐 `scripts/run_demo.py` 的基础上，涵盖发现记录、内容搜索、复核包构建、
//! 自我独立核验、`logs/latest-demo.txt` 更新及分阶段耗时统计。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracedesk_core::{
    AppPaths, AuditOrigin, BuildBundleOptions, Case, CoreError, CoreResult, SearchOptions,
    build_bundle, can_export, examine, record_note, search_case,
};
use tracedesk_engines::TskCli;

use crate::make_demo::create_demo_image;
use crate::verify::verify_bundle_strict;

/// [`run_demo_command`] 的分阶段耗时与总耗时（单位：毫秒）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DemoTimings {
    pub create_ms: f64,
    pub load_ms: f64,
    pub scan_ms: f64,
    pub verify_ms: f64,
    pub export_ms: f64,
    pub findings_ms: f64,
    pub search_ms: f64,
    pub timeline_ms: f64,
    pub report_ms: f64,
    pub bundle_ms: f64,
    pub verify_bundle_ms: f64,
    pub total_ms: f64,
}

/// [`run_demo_command`] 返回的完整输出摘要。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DemoRunSummary {
    pub case_folder: PathBuf,
    pub evidence_path: PathBuf,
    pub exported_path: PathBuf,
    pub report_path: PathBuf,
    pub bundle_path: PathBuf,
    pub bundle_sha256: String,
    pub verified_materials: usize,
    pub inventory_count: usize,
    pub timeline_events: usize,
    pub latest_demo_marker: PathBuf,
    pub timings: DemoTimings,
}

struct DemoStageOutcome {
    exported_path: PathBuf,
    report_path: PathBuf,
    bundle_path: PathBuf,
    bundle_sha256: String,
    inventory_count: usize,
    timeline_events: usize,
    load_ms: f64,
    scan_ms: f64,
    verify_ms: f64,
    export_ms: f64,
    findings_ms: f64,
    search_ms: f64,
    timeline_ms: f64,
    report_ms: f64,
    bundle_ms: f64,
}

#[inline]
fn round_ms(start: Instant) -> f64 {
    (start.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

/// 执行 `run-demo [--cases-dir <dir>] [--evidence <path>]` 演示流程。
pub fn run_demo_command(
    cases_dir: Option<&Path>,
    evidence: Option<&Path>,
) -> CoreResult<DemoRunSummary> {
    let paths = AppPaths::discover();
    let target_cases_dir = match cases_dir {
        Some(d) => d.to_path_buf(),
        None => paths.cases_dir.clone(),
    };
    let target_evidence = match evidence {
        Some(e) => {
            if !e.is_file() {
                return Err(CoreError::NotFound(format!(
                    "指定的证据镜像文件不存在：{}",
                    e.display()
                )));
            }
            e.to_path_buf()
        }
        None => {
            let default_ev = paths.evidence_dir.join("demo.dd");
            if !default_ev.exists() {
                create_demo_image(&default_ev, true)?;
            }
            default_ev
        }
    };

    let tsk = TskCli::discover(paths.find_tsk_bin().as_deref())?;
    let cancel = AtomicBool::new(false);
    let t_total = Instant::now();

    // 1. 建案
    let t = Instant::now();
    let mut case = Case::create(
        &target_cases_dir,
        "DEMO-2026-001",
        "演示取证人员",
        "自建 FAT16 测试镜像",
        None,
        None,
        AuditOrigin::Manual,
    )?;
    let create_ms = round_ms(t);

    let outcome = (|| -> CoreResult<DemoStageOutcome> {
        // 2. 载入镜像
        let t = Instant::now();
        case.load_image(&target_evidence, Some(&tsk), None, None)?;
        let load_ms = round_ms(t);

        // 3. 扫描全部分区
        let t = Instant::now();
        let entries = case.scan_partitions(Some(&tsk), None, None)?;
        let scan_ms = round_ms(t);

        // 4. 校验镜像完整性
        let t = Instant::now();
        if !case.verify_integrity(Some(&tsk), None, None)? {
            return Err(CoreError::IntegrityFailed("原镜像哈希不一致".to_string()));
        }
        let verify_ms = round_ms(t);

        // 5. 导出关键文件 (DOCS/CASE.TXT + NOTES.TXT)
        let t = Instant::now();
        let primary_entry = entries
            .iter()
            .find(|e| e.path == "DOCS/CASE.TXT")
            .or_else(|| entries.iter().find(|e| can_export(e)))
            .ok_or_else(|| CoreError::NotFound("镜像清单中未找到可导出的文件".to_string()))?
            .clone();
        let exported = case.export(&primary_entry, Some(&tsk))?;
        if let Some(notes_entry) = entries.iter().find(|e| e.path == "NOTES.TXT") {
            let _ = case.export(notes_entry, Some(&tsk))?;
        }
        let export_ms = round_ms(t);

        // 6. 记笔记 & 算哈希
        let t = Instant::now();
        record_note(
            &mut case,
            &primary_entry,
            "演示取证发现：确认嵌套目录案件说明文件与原始证据一致。",
        )?;
        examine(&mut case, &primary_entry, None, Some(&tsk))?;
        let findings_ms = round_ms(t);

        // 7. 内容搜索 (ASCII + UTF-8 中文)
        let t = Instant::now();
        search_case(
            &mut case,
            &SearchOptions {
                query: "TraceDesk".to_string(),
                encoding: "UTF-8".to_string(),
                limit: None,
                selected: None,
            },
            &cancel,
            None,
            None,
            Some(&tsk),
        )?;
        search_case(
            &mut case,
            &SearchOptions {
                query: "取证演示".to_string(),
                encoding: "UTF-8".to_string(),
                limit: None,
                selected: None,
            },
            &cancel,
            None,
            None,
            Some(&tsk),
        )?;
        let search_ms = round_ms(t);

        // 8. MACB 时间线
        let t = Instant::now();
        let timeline = case.timeline()?;
        let timeline_ms = round_ms(t);

        // 9. 生成报告
        let t = Instant::now();
        let report_path = case.report(Some(&tsk))?;
        let report_ms = round_ms(t);

        // 10. 生成复核包
        let t = Instant::now();
        let bundle = build_bundle(&mut case, &BuildBundleOptions::default(), Some(&tsk))?;
        let bundle_ms = round_ms(t);

        Ok(DemoStageOutcome {
            exported_path: exported,
            report_path,
            bundle_path: bundle.bundle_path,
            bundle_sha256: bundle.sha256,
            inventory_count: entries.len(),
            timeline_events: timeline.len(),
            load_ms,
            scan_ms,
            verify_ms,
            export_ms,
            findings_ms,
            search_ms,
            timeline_ms,
            report_ms,
            bundle_ms,
        })
    })();

    let case_folder = case.folder().to_path_buf();
    case.close();

    let DemoStageOutcome {
        exported_path,
        report_path,
        bundle_path,
        bundle_sha256,
        inventory_count,
        timeline_events,
        load_ms,
        scan_ms,
        verify_ms,
        export_ms,
        findings_ms,
        search_ms,
        timeline_ms,
        report_ms,
        bundle_ms,
    } = outcome?;

    // 11. 复核包自我独立验签
    let t = Instant::now();
    let verified_materials = verify_bundle_strict(&bundle_path, Some(&bundle_sha256))?;
    let verify_bundle_ms = round_ms(t);
    let total_ms = round_ms(t_total);

    // 12. 更新 latest-demo.txt：若显式指定了自定义 `--cases-dir` 且未设置 `TRACEDESK_LOGS_DIR`，
    //     将标记写入自定义案件目录内，避免污染仓库全局 `logs/latest-demo.txt`。
    let has_explicit_logs_env = std::env::var_os("TRACEDESK_LOGS_DIR")
        .is_some_and(|v| !v.is_empty());
    let marker_dir = if cases_dir.is_some() && !has_explicit_logs_env {
        target_cases_dir.clone()
    } else {
        paths.logs_dir.clone()
    };
    fs::create_dir_all(&marker_dir)?;
    let latest_demo_marker = marker_dir.join("latest-demo.txt");
    fs::write(&latest_demo_marker, case_folder.to_string_lossy().as_bytes())?;

    let timings = DemoTimings {
        create_ms,
        load_ms,
        scan_ms,
        verify_ms,
        export_ms,
        findings_ms,
        search_ms,
        timeline_ms,
        report_ms,
        bundle_ms,
        verify_bundle_ms,
        total_ms,
    };

    println!("案件： {}", case_folder.display());
    println!("导出： {}", exported_path.display());
    println!("报告： {}", report_path.display());
    println!("复核包： {}", bundle_path.display());
    println!("核验通过：{verified_materials} 份材料及审计链。");
    println!(
        "耗时明细：建案 {:.2} ms | 载入 {:.2} ms | 扫描 {:.2} ms | 校验 {:.2} ms | 导出 {:.2} ms | 发现 {:.2} ms | 搜索 {:.2} ms | 时间线 {:.2} ms | 报告 {:.2} ms | 复核包 {:.2} ms | 验签 {:.2} ms | 总耗时 {:.2} ms",
        timings.create_ms,
        timings.load_ms,
        timings.scan_ms,
        timings.verify_ms,
        timings.export_ms,
        timings.findings_ms,
        timings.search_ms,
        timings.timeline_ms,
        timings.report_ms,
        timings.bundle_ms,
        timings.verify_bundle_ms,
        timings.total_ms
    );

    Ok(DemoRunSummary {
        case_folder,
        evidence_path: target_evidence,
        exported_path,
        report_path,
        bundle_path,
        bundle_sha256,
        verified_materials,
        inventory_count,
        timeline_events,
        latest_demo_marker,
        timings,
    })
}
