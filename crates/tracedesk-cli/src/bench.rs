//! 原生 Rust 性能基准测试套件（`bench [--json-out <path>]`），
//! 采用与 `scratch/baseline/run_baseline.py` 完全一致的数据集规模与计算公式，
//! 并额外包含多核 EWF1（64 MiB）并行解码哈希与多核 AVX2 内容搜索吞吐量测试，
//! 同时自动对照 `python_bench.json` 计算加速比。

use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use adler2::adler32_slice;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracedesk_core::{
    AppPaths, AuditOrigin, BuildBundleOptions, Case, CoreError, CoreResult, SearchOptions,
    TimelineFilter, TimelineIndex, build_bundle, find_matches_in_reader, read_inventory_gz,
    search_case, write_inventory_gz,
};
use tracedesk_engines::ewf::{EWF1_MAGIC, hash_logical_ewf1_parallel};
use tracedesk_engines::{InventoryEntry, TskCli, map_fat_regions};

use crate::make_demo::create_demo_image;
use crate::verify::verify_bundle_strict;

const DEFAULT_PYTHON_BENCH_PATH: &str = r"C:\Users\cymr1\.gemini\antigravity\brain\17680ca1-4084-4cc1-9fbe-b9bcc92744bb\scratch\baseline\python_bench.json";

#[inline]
fn round2(val: f64) -> f64 {
    (val * 100.0).round() / 100.0
}

#[inline]
fn round3(val: f64) -> f64 {
    (val * 1000.0).round() / 1000.0
}

#[inline]
fn elapsed_ms(start: Instant) -> f64 {
    round2(start.elapsed().as_secs_f64() * 1000.0)
}

#[inline]
fn speedup(py_ms: f64, rust_ms: f64) -> f64 {
    if rust_ms <= 0.0001 {
        0.0
    } else {
        round2(py_ms / rust_ms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchEnvironment {
    pub rust_profile: String,
    pub platform: String,
    pub arch: String,
    pub cpu_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenSearchSummary {
    pub file: String,
    pub hits: usize,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenDemoTimings {
    pub create_ms: f64,
    pub load_ms: f64,
    pub scan_all_ms: f64,
    pub verify_ms: f64,
    pub export_2_files_ms: f64,
    pub search_ascii_ms: f64,
    pub search_utf8_zh_ms: f64,
    pub timeline_ms: f64,
    pub report_ms: f64,
    pub build_bundle_ms: f64,
    pub verify_bundle_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenDemoBench {
    pub image: String,
    pub image_bytes: u64,
    pub image_sha256: String,
    pub inventory_count: usize,
    pub exports: Vec<String>,
    pub search_ascii: GoldenSearchSummary,
    pub search_utf8_zh: GoldenSearchSummary,
    pub timeline_events: usize,
    pub report_file: String,
    pub bundle_file: String,
    pub bundle_sha256: String,
    pub verify_bundle_output: String,
    pub audit_count: usize,
    pub audit_head: String,
    pub timings: GoldenDemoTimings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryGzipBench {
    pub entry_count: usize,
    pub compresslevel: u32,
    pub gz_bytes: u64,
    pub write_ms: f64,
    pub read_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline400kBench {
    pub entry_count: usize,
    pub event_count: usize,
    pub build_sort_ms: f64,
    pub filter_options_ms: f64,
    pub option_counts: [usize; 3],
    pub matching_filtered_query_ms: f64,
    pub matching_filtered_query_hits: usize,
    pub matching_status_only_ms: f64,
    pub matching_status_only_hits: usize,
    pub matching_full_date_query_ms: f64,
    pub matching_full_date_query_hits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fat500kBench {
    pub clusters: usize,
    pub image_bytes: u64,
    pub non_sparse_ms: f64,
    pub non_sparse_free_bytes: u64,
    pub non_sparse_idle_bytes: u64,
    pub non_sparse_free_extents: usize,
    pub non_sparse_idle_extents: usize,
    pub all_zero_fast_path_ms: f64,
    pub all_zero_free_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Audit200Bench {
    pub appends: usize,
    pub total_records: usize,
    pub append_200_ms: f64,
    pub avg_per_append_ms: f64,
    pub check_audit_201_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreBenchmarks {
    pub inventory_100k_gzip: InventoryGzipBench,
    pub timeline_400k_macb: Timeline400kBench,
    pub fat_500k_clusters: Fat500kBench,
    pub audit_chain_200_writes: Audit200Bench,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EwfParallelBench {
    pub logical_bytes: u64,
    pub logical_mib: f64,
    pub physical_bytes: u64,
    pub segments: usize,
    pub chunks: usize,
    pub sha256: String,
    pub elapsed_ms: f64,
    pub throughput_mib_per_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Avx2SearchBench {
    pub logical_bytes: u64,
    pub logical_mib: f64,
    pub streams: usize,
    pub hits: usize,
    pub elapsed_ms: f64,
    pub throughput_mib_per_sec: f64,
    pub throughput_gib_per_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtraBenchmarks {
    pub ewf1_64mib_parallel_hash: EwfParallelBench,
    pub avx2_content_search_throughput: Avx2SearchBench,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricComparison {
    pub metric: String,
    pub python_ms: f64,
    pub rust_ms: f64,
    pub speedup_x: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustBenchReport {
    pub environment: BenchEnvironment,
    pub golden_demo_case: GoldenDemoBench,
    pub benchmarks: CoreBenchmarks,
    pub extra_benchmarks: ExtraBenchmarks,
    pub comparison_vs_python: Vec<MetricComparison>,
}

/// 生成与 `run_baseline.py::make_synthetic_entries` 完全一致的 100,000 条合成文件清单条目。
pub fn make_synthetic_entries(n: usize) -> Vec<InventoryEntry> {
    let base_ts: i64 = 1_788_249_600; // 基准时间戳 2026-09-01T08:00:00Z
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let deleted = i.is_multiple_of(10);
        let reallocated = deleted && i.is_multiple_of(20);
        let folder = format!("USERS/DEPT_{:02}/PROJ_{:03}", i % 50, i % 200);
        let name = if i.is_multiple_of(4) {
            format!("report_{:02}_{:06}.txt", i % 100, i)
        } else {
            format!("doc_{:06}.bin", i)
        };
        let t0 = base_ts + ((i as i64 * 17) % 2_500_000);
        entries.push(InventoryEntry {
            path: format!("{folder}/{name}"),
            inode: format!("{}-128-1", 1000 + i),
            offset: if !i.is_multiple_of(3) { 2048 } else { 206_848 },
            size: ((i as u64) * 97) % 1_048_576,
            mode: "r/rrwxrwxrwx".to_string(),
            directory: false,
            deleted,
            reallocated,
            atime: t0 + 60,
            mtime: t0,
            ctime: t0 + 120,
            crtime: t0 - 300,
            filesystem: "NTFS".to_string(),
            start_cluster_allocated: None,
            extents: None,
        });
    }
    entries
}

/// 1. 基准测试：100,000 条清单条目的 Gzip（`compresslevel=1`）写入与读取性能。
pub fn bench_inventory_gzip(entries: &[InventoryEntry]) -> CoreResult<InventoryGzipBench> {
    let tmp = tempfile::tempdir()?;
    let gz_path = tmp.path().join("inventory-bench.jsonl.gz");

    let t = Instant::now();
    write_inventory_gz(&gz_path, entries, None)?;
    let write_ms = elapsed_ms(t);
    let gz_bytes = fs::metadata(&gz_path)?.len();

    let t = Instant::now();
    let loaded = read_inventory_gz(&gz_path)?;
    let read_ms = elapsed_ms(t);
    if loaded.len() != entries.len() {
        return Err(CoreError::Other(format!(
            "inventory_100k_gzip 数量不匹配：{} vs {}",
            loaded.len(),
            entries.len()
        )));
    }

    Ok(InventoryGzipBench {
        entry_count: entries.len(),
        compresslevel: 1,
        gz_bytes,
        write_ms,
        read_ms,
    })
}

/// 2. 基准测试：400,000 条 MACB 时间线的构建排序、`filter_options` 提取与多条件筛选性能。
pub fn bench_timeline_400k(entries: Vec<InventoryEntry>) -> CoreResult<Timeline400kBench> {
    let entry_count = entries.len();
    let t = Instant::now();
    let tl = TimelineIndex::build(entries);
    let build_sort_ms = elapsed_ms(t);
    if tl.len() != entry_count * 4 {
        return Err(CoreError::Other(format!(
            "timeline_400k 事件数不匹配：{}",
            tl.len()
        )));
    }

    let t = Instant::now();
    let opts = tl.filter_options();
    let filter_options_ms = elapsed_ms(t);
    let option_counts = [opts.events.len(), opts.statuses.len(), opts.offsets.len()];

    let t = Instant::now();
    let hits_filtered = tl.matching(&TimelineFilter {
        query: "report_04".to_string(),
        event: Some("M 内容修改".to_string()),
        status: None,
        offset: None,
    })?;
    let matching_filtered_query_ms = elapsed_ms(t);

    let t = Instant::now();
    let hits_status = tl.matching(&TimelineFilter {
        query: String::new(),
        event: Some("B 创建".to_string()),
        status: Some("已删除".to_string()),
        offset: None,
    })?;
    let matching_status_only_ms = elapsed_ms(t);

    let t = Instant::now();
    let hits_full_query = tl.matching(&TimelineFilter {
        query: "2026-09".to_string(),
        event: None,
        status: None,
        offset: None,
    })?;
    let matching_full_date_query_ms = elapsed_ms(t);

    Ok(Timeline400kBench {
        entry_count,
        event_count: tl.len(),
        build_sort_ms,
        filter_options_ms,
        option_counts,
        matching_filtered_query_ms,
        matching_filtered_query_hits: hits_filtered.len(),
        matching_status_only_ms,
        matching_status_only_hits: hits_status.len(),
        matching_full_date_query_ms,
        matching_full_date_query_hits: hits_full_query.len(),
    })
}

/// 3. 基准测试：500,000 簇 FAT32 的非稀疏混合映射与全零快路径性能。
pub fn bench_fat_500k_clusters() -> CoreResult<Fat500kBench> {
    let clusters: usize = 500_000;
    let sector: usize = 512;
    let per_cluster: u8 = 1;
    let reserved: u16 = 32;
    let copies: u8 = 1;
    let fat_sectors: usize = ((clusters + 2) * 4).div_ceil(sector); // 3907 个扇区
    let total_sectors: usize = (reserved as usize) + (copies as usize) * fat_sectors + clusters;

    let mut boot = [0u8; 512];
    boot[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"BENCHFAT");
    // 按小端序写入 FAT32 引导扇区 BPB 字段（对应 struct.pack_into('<HBHBHH', ...)）
    boot[11..13].copy_from_slice(&(sector as u16).to_le_bytes());
    boot[13] = per_cluster;
    boot[14..16].copy_from_slice(&reserved.to_le_bytes());
    boot[16] = copies;
    boot[17..19].copy_from_slice(&0u16.to_le_bytes());
    boot[19..21].copy_from_slice(&0u16.to_le_bytes());
    boot[32..36].copy_from_slice(&(total_sectors as u32).to_le_bytes());
    boot[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
    boot[40..42].copy_from_slice(&0u16.to_le_bytes());
    boot[44..48].copy_from_slice(&2u32.to_le_bytes()); // 根目录起始簇号 = 2
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);
    let fsstat = "File System Type: FAT32\n";

    let tmp = tempfile::tempdir()?;
    let img = tmp.path().join("fat32_500k.img");

    let mut fat_mixed = vec![0u8; fat_sectors * sector];
    fat_mixed[0..4].copy_from_slice(&0x0fff_fff8u32.to_le_bytes());
    fat_mixed[4..8].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
    fat_mixed[8..12].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
    for c in 3..(clusters + 2) {
        let val: u32 = match c % 4 {
            0 => 0,
            1 => 0x0fff_ffff,
            2 => 0,
            _ => {
                if c + 1 < clusters + 2 {
                    (c + 1) as u32
                } else {
                    0x0fff_ffff
                }
            }
        };
        let off = c * 4;
        fat_mixed[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }

    {
        let mut f = File::create(&img)?;
        f.write_all(&boot)?;
        f.seek(SeekFrom::Start((reserved as u64) * (sector as u64)))?;
        f.write_all(&fat_mixed)?;
        f.set_len((total_sectors as u64) * (sector as u64))?;
        f.flush()?;
    }

    let t = Instant::now();
    let regions_mixed = map_fat_regions(&img, 0, fsstat, &mut [], None)?;
    let non_sparse_ms = elapsed_ms(t);

    // 重写 FAT 表以测试全零快路径
    let mut fat_zero = vec![0u8; fat_sectors * sector];
    fat_zero[0..4].copy_from_slice(&0x0fff_fff8u32.to_le_bytes());
    fat_zero[4..8].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
    fat_zero[8..12].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
    {
        let mut f = OpenOptions::new().read(true).write(true).open(&img)?;
        f.seek(SeekFrom::Start((reserved as u64) * (sector as u64)))?;
        f.write_all(&fat_zero)?;
        f.flush()?;
    }

    let t = Instant::now();
    let regions_zero = map_fat_regions(&img, 0, fsstat, &mut [], None)?;
    let all_zero_fast_path_ms = elapsed_ms(t);

    let non_sparse_free_bytes = regions_mixed[1].size;
    let non_sparse_idle_bytes = regions_mixed[2].size;
    let non_sparse_free_extents = regions_mixed[1]
        .extents
        .as_ref()
        .map(Vec::len)
        .unwrap_or(0);
    let non_sparse_idle_extents = regions_mixed[2]
        .extents
        .as_ref()
        .map(Vec::len)
        .unwrap_or(0);
    let all_zero_free_bytes = regions_zero[1].size;

    Ok(Fat500kBench {
        clusters,
        image_bytes: (total_sectors as u64) * (sector as u64),
        non_sparse_ms,
        non_sparse_free_bytes,
        non_sparse_idle_bytes,
        non_sparse_free_extents,
        non_sparse_idle_extents,
        all_zero_fast_path_ms,
        all_zero_free_bytes,
    })
}

/// 4. 基准测试：连续 200 次审计链追加写入与 201 条记录完整校验性能。
pub fn bench_audit_200() -> CoreResult<Audit200Bench> {
    let tmp = tempfile::tempdir()?;
    let mut case = Case::create(
        tmp.path(),
        "BENCH-AUDIT",
        "基准测试员",
        "200次审计链压测",
        None,
        None,
        AuditOrigin::Manual,
    )?;

    let t = Instant::now();
    for i in 0..200u64 {
        let mut details = Map::new();
        details.insert("idx".to_string(), Value::from(i));
        details.insert(
            "note".to_string(),
            Value::String("中文审计链基准写入测试".to_string()),
        );
        case.log("BENCH_EVENT", &format!("subject/{i:04}"), "成功", details)?;
    }
    let append_200_ms = elapsed_ms(t);

    let t = Instant::now();
    let records = case.check_audit()?;
    let check_audit_201_ms = elapsed_ms(t);
    case.close();

    if records.len() != 201 {
        return Err(CoreError::Other(format!(
            "audit_chain_200 记录数不匹配：{}",
            records.len()
        )));
    }

    Ok(Audit200Bench {
        appends: 200,
        total_records: 201,
        append_200_ms,
        avg_per_append_ms: round3(append_200_ms / 200.0),
        check_audit_201_ms,
    })
}

/// 5. 基准测试：对齐 `run_baseline.py::run_golden_demo_case` 的 `evidence/demo.dd` 端到端取证全流程。
pub fn bench_golden_demo_case() -> CoreResult<GoldenDemoBench> {
    let paths = AppPaths::discover();
    let mut image = paths.evidence_dir.join("demo.dd");
    let tmp_root = tempfile::tempdir()?;
    if !image.is_file() {
        image = tmp_root.path().join("demo.dd");
        create_demo_image(&image, true)?;
    }
    let image_bytes = fs::metadata(&image)?.len();
    let cases_root = tmp_root.path().join("cases");
    let tsk = TskCli::discover(paths.find_tsk_bin().as_deref())?;
    let cancel = AtomicBool::new(false);

    let t_total = Instant::now();

    let t = Instant::now();
    let mut case = Case::create(
        &cases_root,
        "GOLDEN-2026-001",
        "基线取证员",
        "demo.dd 黄金兼容性样本",
        Some("demo_case"),
        None,
        AuditOrigin::Manual,
    )?;
    let create_ms = elapsed_ms(t);

    let t = Instant::now();
    case.load_image(&image, Some(&tsk), None, None)?;
    let load_ms = elapsed_ms(t);

    let t = Instant::now();
    let entries = case.scan_partitions(Some(&tsk), None, None)?;
    let scan_all_ms = elapsed_ms(t);

    let t = Instant::now();
    let verified = case.verify_integrity(Some(&tsk), None, None)?;
    if !verified {
        return Err(CoreError::IntegrityFailed(
            "demo.dd verify_integrity() returned false".to_string(),
        ));
    }
    let verify_ms = elapsed_ms(t);

    let t = Instant::now();
    let doc_entry = entries
        .iter()
        .find(|e| e.path == "DOCS/CASE.TXT")
        .ok_or_else(|| CoreError::NotFound("缺少 DOCS/CASE.TXT".to_string()))?
        .clone();
    let notes_entry = entries
        .iter()
        .find(|e| e.path == "NOTES.TXT")
        .ok_or_else(|| CoreError::NotFound("缺少 NOTES.TXT".to_string()))?
        .clone();
    let exp_doc = case.export(&doc_entry, Some(&tsk))?;
    let exp_notes = case.export(&notes_entry, Some(&tsk))?;
    let export_2_files_ms = elapsed_ms(t);

    let t = Instant::now();
    let ascii_out = search_case(
        &mut case,
        &SearchOptions {
            query: "TraceDesk".to_string(),
            encoding: "utf-8".to_string(),
            limit: None,
            selected: None,
        },
        &cancel,
        None,
        None,
        Some(&tsk),
    )?;
    let search_ascii_ms = elapsed_ms(t);

    let t = Instant::now();
    let zh_out = search_case(
        &mut case,
        &SearchOptions {
            query: "取证演示".to_string(),
            encoding: "utf-8".to_string(),
            limit: None,
            selected: None,
        },
        &cancel,
        None,
        None,
        Some(&tsk),
    )?;
    let search_utf8_zh_ms = elapsed_ms(t);

    let t = Instant::now();
    let events = case.timeline()?;
    let timeline_ms = elapsed_ms(t);

    let t = Instant::now();
    let report_path = case.report(Some(&tsk))?;
    let report_ms = elapsed_ms(t);

    let t = Instant::now();
    let bundle = build_bundle(&mut case, &BuildBundleOptions::default(), Some(&tsk))?;
    let build_bundle_ms = elapsed_ms(t);

    let audit_records = case.check_audit()?;
    let audit_head = fs::read_to_string(case.folder().join("audit.head"))?;
    let evidence_sha = case
        .data()
        .evidence
        .as_ref()
        .and_then(|e| e.sha256.clone())
        .unwrap_or_default();
    case.close();

    let t = Instant::now();
    let verified_count = verify_bundle_strict(&bundle.bundle_path, Some(&bundle.sha256))?;
    let verify_bundle_ms = elapsed_ms(t);
    let total_ms = elapsed_ms(t_total);

    Ok(GoldenDemoBench {
        image: image.to_string_lossy().into_owned(),
        image_bytes,
        image_sha256: evidence_sha,
        inventory_count: entries.len(),
        exports: vec![
            exp_doc
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            exp_notes
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        ],
        search_ascii: GoldenSearchSummary {
            file: ascii_out.report_name,
            hits: ascii_out.record.hits.len(),
            status: ascii_out.record.status,
        },
        search_utf8_zh: GoldenSearchSummary {
            file: zh_out.report_name,
            hits: zh_out.record.hits.len(),
            status: zh_out.record.status,
        },
        timeline_events: events.len(),
        report_file: report_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        bundle_file: bundle
            .bundle_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        bundle_sha256: bundle.sha256,
        verify_bundle_output: format!("核验通过：{verified_count} 份材料及审计链。"),
        audit_count: audit_records.len(),
        audit_head,
        timings: GoldenDemoTimings {
            create_ms,
            load_ms,
            scan_all_ms,
            verify_ms,
            export_2_files_ms,
            search_ascii_ms,
            search_utf8_zh_ms,
            timeline_ms,
            report_ms,
            build_bundle_ms,
            verify_bundle_ms,
            total_ms,
        },
    })
}

fn write_ewf_section_desc(buf: &mut Vec<u8>, name: &str, next_offset: u64, section_size: u64) {
    let mut desc = [0u8; 76];
    let nb = name.as_bytes();
    desc[..nb.len()].copy_from_slice(nb);
    desc[16..24].copy_from_slice(&next_offset.to_le_bytes());
    desc[24..32].copy_from_slice(&section_size.to_le_bytes());
    let crc = adler32_slice(&desc[..72]);
    desc[72..76].copy_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&desc);
}

/// 6A. 基准测试：64 MiB 多分段 EWF1（4 个分段，2,048 个 32 KiB 块）多核并行解码与 SHA-256 计算性能。
pub fn bench_ewf1_64mib_parallel() -> CoreResult<EwfParallelBench> {
    let logical_bytes: usize = 64 * 1024 * 1024; // 67,108,864 字节
    let bytes_per_sector: u32 = 512;
    let sectors_per_chunk: u32 = 64;
    let chunk_size: usize = (bytes_per_sector * sectors_per_chunk) as usize; // 每块 32 KiB
    let total_chunks: usize = logical_bytes / chunk_size; // 共 2048 块
    let chunks_per_segment: usize = 512; // 4 个分段（.E01-.E04）
    let num_segments: usize = total_chunks / chunks_per_segment;

    // 预构造 16 种不同的 32 KiB 块模板（8 个压缩块、8 个未压缩块）并循环平铺至 2048 个块，
    // 既能快速构建 64 MiB EWF1 镜像，又能确保每个块都经过真实的 zlib 解压与 Adler-32 校验。
    let mut plain_templates: Vec<Vec<u8>> = Vec::with_capacity(16);
    let mut encoded_templates: Vec<(Vec<u8>, bool)> = Vec::with_capacity(16);
    for t_idx in 0..16usize {
        let mut plain = vec![0u8; chunk_size];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = ((i.wrapping_mul(31).wrapping_add(t_idx * 97)) ^ (i >> 5)) as u8;
        }
        let compressed = t_idx % 2 == 0;
        if compressed {
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(&plain)?;
            let z = enc.finish()?;
            encoded_templates.push((z, true));
        } else {
            let crc = adler32_slice(&plain);
            let mut raw_with_crc = Vec::with_capacity(chunk_size + 4);
            raw_with_crc.extend_from_slice(&plain);
            raw_with_crc.extend_from_slice(&crc.to_le_bytes());
            encoded_templates.push((raw_with_crc, false));
        }
        plain_templates.push(plain);
    }

    let mut vol_body = vec![0u8; 1052];
    vol_body[0] = 0x01;
    vol_body[4..8].copy_from_slice(&(total_chunks as u32).to_le_bytes());
    vol_body[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
    vol_body[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
    vol_body[16..24].copy_from_slice(&((logical_bytes / 512) as u64).to_le_bytes());
    vol_body[36] = 0x01;
    vol_body[52] = 0x01;
    let vol_crc = adler32_slice(&vol_body[..1048]);
    vol_body[1048..1052].copy_from_slice(&vol_crc.to_le_bytes());

    let tmp = tempfile::tempdir()?;
    let mut seg_paths = Vec::with_capacity(num_segments);
    let mut physical_bytes: u64 = 0;

    for seg in 0..num_segments {
        let seg_num = (seg + 1) as u16;
        let path = tmp.path().join(format!("bench64m.E{seg_num:02}"));
        let start_chunk = seg * chunks_per_segment;
        let end_chunk = (seg + 1) * chunks_per_segment;
        let is_last = seg + 1 == num_segments;

        let mut buf = Vec::with_capacity(18 * 1024 * 1024);
        buf.extend_from_slice(&EWF1_MAGIC);
        buf.push(0x01);
        buf.extend_from_slice(&seg_num.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());

        if seg == 0 {
            let vol_sec_size = (76 + vol_body.len()) as u64;
            let next = buf.len() as u64 + vol_sec_size;
            write_ewf_section_desc(&mut buf, "volume", next, vol_sec_size);
            buf.extend_from_slice(&vol_body);
        }

        let sectors_sec_offset = buf.len() as u64;
        let sectors_data_start = sectors_sec_offset + 76;
        let mut sectors_payload = Vec::with_capacity(chunks_per_segment * 24_000);
        let mut table_entries = Vec::with_capacity(chunks_per_segment);

        for c in start_chunk..end_chunk {
            let (ref payload, is_compressed) = encoded_templates[c % 16];
            let rel_off = sectors_data_start + sectors_payload.len() as u64;
            sectors_payload.extend_from_slice(payload);
            let entry = if is_compressed {
                (rel_off as u32) | 0x8000_0000
            } else {
                rel_off as u32
            };
            table_entries.push(entry);
        }

        let sectors_sec_size = (76 + sectors_payload.len()) as u64;
        let table_offset = sectors_sec_offset + sectors_sec_size;
        write_ewf_section_desc(&mut buf, "sectors", table_offset, sectors_sec_size);
        buf.extend_from_slice(&sectors_payload);

        let mut table_body = Vec::with_capacity(24 + table_entries.len() * 4 + 4);
        let mut thdr = [0u8; 24];
        thdr[0..4].copy_from_slice(&(table_entries.len() as u32).to_le_bytes());
        let thdr_crc = adler32_slice(&thdr[..20]);
        thdr[20..24].copy_from_slice(&thdr_crc.to_le_bytes());
        table_body.extend_from_slice(&thdr);
        let entries_start = table_body.len();
        for &e in &table_entries {
            table_body.extend_from_slice(&e.to_le_bytes());
        }
        let entries_crc = adler32_slice(&table_body[entries_start..]);
        table_body.extend_from_slice(&entries_crc.to_le_bytes());

        let table_sec_size = (76 + table_body.len()) as u64;
        let term_offset = table_offset + table_sec_size;
        write_ewf_section_desc(&mut buf, "table", term_offset, table_sec_size);
        buf.extend_from_slice(&table_body);

        let term_name = if is_last { "done" } else { "next" };
        let term_off = buf.len() as u64;
        write_ewf_section_desc(&mut buf, term_name, term_off, 76);

        fs::write(&path, &buf)?;
        physical_bytes += buf.len() as u64;
        seg_paths.push(path);
    }

    let e01 = &seg_paths[0];
    let t = Instant::now();
    let sha256 = hash_logical_ewf1_parallel(e01, logical_bytes as u64, None, None)?;
    let elapsed = elapsed_ms(t);
    let logical_mib = 64.0;
    let throughput_mib_per_sec = if elapsed > 0.0 {
        round2(logical_mib / (elapsed / 1000.0))
    } else {
        0.0
    };

    Ok(EwfParallelBench {
        logical_bytes: logical_bytes as u64,
        logical_mib,
        physical_bytes,
        segments: num_segments,
        chunks: total_chunks,
        sha256,
        elapsed_ms: elapsed,
        throughput_mib_per_sec,
    })
}

/// 6B. 基准测试：在 256 MiB 数据（32 × 8 MiB 流）上的多核 AVX2 SIMD 精确字节内容搜索吞吐量。
pub fn bench_avx2_content_search() -> CoreResult<Avx2SearchBench> {
    let stream_bytes: usize = 8 * 1024 * 1024; // 每条流 8 MiB
    let num_streams: usize = 32; // 总计 256 MiB
    let total_bytes: u64 = (stream_bytes * num_streams) as u64;
    let needle = b"TraceDesk-AVX2-Forensic-Marker";

    // 构造 8 MiB 缓冲区并写入 8 处标记（32 条流 × 8 = 总计 256 处命中）。
    let mut template = vec![b'A'; stream_bytes];
    for (i, b) in template.iter_mut().enumerate().step_by(64) {
        *b = b'0' + ((i / 64) % 10) as u8;
    }
    for k in 0..8usize {
        let pos = (k + 1) * 1_000_000;
        template[pos..pos + needle.len()].copy_from_slice(needle);
    }

    let t = Instant::now();
    let total_hits: usize = (0..num_streams)
        .into_par_iter()
        .map(|_| {
            let mut cursor = Cursor::new(template.as_slice());
            let hits = find_matches_in_reader(
                &mut cursor,
                stream_bytes as u64,
                needle,
                None,
                None,
                None,
            )
            .expect("AVX2 search");
            hits.len()
        })
        .sum();
    let elapsed = elapsed_ms(t);

    if total_hits != num_streams * 8 {
        return Err(CoreError::Other(format!(
            "AVX2 搜索命中数异常：{total_hits}"
        )));
    }

    let logical_mib = 256.0;
    let throughput_mib_per_sec = if elapsed > 0.0 {
        round2(logical_mib / (elapsed / 1000.0))
    } else {
        0.0
    };
    let throughput_gib_per_sec = round2(throughput_mib_per_sec / 1024.0);

    Ok(Avx2SearchBench {
        logical_bytes: total_bytes,
        logical_mib,
        streams: num_streams,
        hits: total_hits,
        elapsed_ms: elapsed,
        throughput_mib_per_sec,
        throughput_gib_per_sec,
    })
}

fn find_python_bench_path(json_out: Option<&Path>) -> Option<PathBuf> {
    if let Some(out) = json_out
        && let Some(parent) = out.parent()
    {
        let sibling = parent.join("python_bench.json");
        if sibling.is_file() {
            return Some(sibling);
        }
    }
    let default = PathBuf::from(DEFAULT_PYTHON_BENCH_PATH);
    if default.is_file() {
        return Some(default);
    }
    None
}

fn build_comparisons(
    py_json: &Value,
    golden: &GoldenDemoBench,
    benchmarks: &CoreBenchmarks,
) -> Vec<MetricComparison> {
    let mut rows = Vec::new();
    let mut add = |label: &str, py_val: Option<f64>, rust_ms: f64| {
        if let Some(py_ms) = py_val {
            rows.push(MetricComparison {
                metric: label.to_string(),
                python_ms: py_ms,
                rust_ms,
                speedup_x: speedup(py_ms, rust_ms),
            });
        }
    };

    let py_inv = py_json
        .get("benchmarks")
        .and_then(|b| b.get("inventory_100k_gzip"));
    add(
        "10万条清单 Gzip (level 1) 写入",
        py_inv.and_then(|v| v.get("write_ms")).and_then(Value::as_f64),
        benchmarks.inventory_100k_gzip.write_ms,
    );
    add(
        "10万条清单 Gzip (level 1) 读取",
        py_inv.and_then(|v| v.get("read_ms")).and_then(Value::as_f64),
        benchmarks.inventory_100k_gzip.read_ms,
    );

    let py_tl = py_json
        .get("benchmarks")
        .and_then(|b| b.get("timeline_400k_macb"));
    add(
        "40万条 MACB 时间线构建与排序",
        py_tl
            .and_then(|v| v.get("build_sort_ms"))
            .and_then(Value::as_f64),
        benchmarks.timeline_400k_macb.build_sort_ms,
    );
    add(
        "40万条 MACB 筛选项提取",
        py_tl
            .and_then(|v| v.get("filter_options_ms"))
            .and_then(Value::as_f64),
        benchmarks.timeline_400k_macb.filter_options_ms,
    );
    add(
        "40万条 MACB 事件+关键词筛选 (1,000 hits)",
        py_tl
            .and_then(|v| v.get("matching_filtered_query_ms"))
            .and_then(Value::as_f64),
        benchmarks.timeline_400k_macb.matching_filtered_query_ms,
    );
    add(
        "40万条 MACB 事件+状态筛选 (5,000 hits)",
        py_tl
            .and_then(|v| v.get("matching_status_only_ms"))
            .and_then(Value::as_f64),
        benchmarks.timeline_400k_macb.matching_status_only_ms,
    );
    add(
        "40万条 MACB 全量日期关键词扫描 (400,000 hits)",
        py_tl
            .and_then(|v| v.get("matching_full_date_query_ms"))
            .and_then(Value::as_f64),
        benchmarks.timeline_400k_macb.matching_full_date_query_ms,
    );

    let py_fat = py_json
        .get("benchmarks")
        .and_then(|b| b.get("fat_500k_clusters"));
    add(
        "50万簇 FAT32 非稀疏混合簇映射",
        py_fat
            .and_then(|v| v.get("non_sparse_ms"))
            .and_then(Value::as_f64),
        benchmarks.fat_500k_clusters.non_sparse_ms,
    );
    add(
        "50万簇 FAT32 全零快路径映射",
        py_fat
            .and_then(|v| v.get("all_zero_fast_path_ms"))
            .and_then(Value::as_f64),
        benchmarks.fat_500k_clusters.all_zero_fast_path_ms,
    );

    let py_audit = py_json
        .get("benchmarks")
        .and_then(|b| b.get("audit_chain_200_writes"));
    add(
        "连续 200 次审计链追加写入 (fsync)",
        py_audit
            .and_then(|v| v.get("append_200_ms"))
            .and_then(Value::as_f64),
        benchmarks.audit_chain_200_writes.append_200_ms,
    );
    add(
        "201 条审计链整链 SHA-256 校验",
        py_audit
            .and_then(|v| v.get("check_audit_201_ms"))
            .and_then(Value::as_f64),
        benchmarks.audit_chain_200_writes.check_audit_201_ms,
    );

    let py_demo = py_json
        .get("golden_demo_case")
        .and_then(|g| g.get("timings"));
    add(
        "demo.dd 端到端闭环总耗时",
        py_demo
            .and_then(|v| v.get("total_ms"))
            .and_then(Value::as_f64),
        golden.timings.total_ms,
    );
    add(
        "  ├─ demo.dd 载入镜像",
        py_demo
            .and_then(|v| v.get("load_ms"))
            .and_then(Value::as_f64),
        golden.timings.load_ms,
    );
    add(
        "  ├─ demo.dd 全分区扫描",
        py_demo
            .and_then(|v| v.get("scan_all_ms"))
            .and_then(Value::as_f64),
        golden.timings.scan_all_ms,
    );
    add(
        "  ├─ demo.dd 导出 2 份文件",
        py_demo
            .and_then(|v| v.get("export_2_files_ms"))
            .and_then(Value::as_f64),
        golden.timings.export_2_files_ms,
    );
    add(
        "  ├─ demo.dd ASCII 内容搜索",
        py_demo
            .and_then(|v| v.get("search_ascii_ms"))
            .and_then(Value::as_f64),
        golden.timings.search_ascii_ms,
    );
    add(
        "  ├─ demo.dd UTF-8 中文内容搜索",
        py_demo
            .and_then(|v| v.get("search_utf8_zh_ms"))
            .and_then(Value::as_f64),
        golden.timings.search_utf8_zh_ms,
    );
    add(
        "  ├─ demo.dd 时间线构建",
        py_demo
            .and_then(|v| v.get("timeline_ms"))
            .and_then(Value::as_f64),
        golden.timings.timeline_ms,
    );
    add(
        "  ├─ demo.dd 10章节报告生成",
        py_demo
            .and_then(|v| v.get("report_ms"))
            .and_then(Value::as_f64),
        golden.timings.report_ms,
    );
    add(
        "  ├─ demo.dd 复核包 ZIP 构建",
        py_demo
            .and_then(|v| v.get("build_bundle_ms"))
            .and_then(Value::as_f64),
        golden.timings.build_bundle_ms,
    );
    add(
        "  └─ demo.dd 复核包独立核验",
        py_demo
            .and_then(|v| v.get("verify_bundle_ms"))
            .and_then(Value::as_f64),
        golden.timings.verify_bundle_ms,
    );

    rows
}

/// 执行 `bench [--json-out <path>]` 子命令。
pub fn run_bench_command(json_out: Option<&Path>) -> CoreResult<RustBenchReport> {
    println!("[1/6] 正在执行真实 evidence/demo.dd 全流程闭环基准...");
    let golden = bench_golden_demo_case()?;
    println!(
        "  -> demo.dd 总耗时: {:.2} ms | {}",
        golden.timings.total_ms, golden.verify_bundle_output
    );

    println!("[2/6] 正在生成 100,000 条合成清单并测试 Gzip (level 1) 读写...");
    let entries = make_synthetic_entries(100_000);
    let inv_bench = bench_inventory_gzip(&entries)?;
    println!(
        "  -> 清单写入: {:.2} ms | 读取: {:.2} ms | 压缩大小: {} bytes",
        inv_bench.write_ms, inv_bench.read_ms, inv_bench.gz_bytes
    );

    println!("[3/6] 正在测试 400,000 条 MACB 时间线并行排序与多条件筛选...");
    let tl_bench = bench_timeline_400k(entries)?;
    println!(
        "  -> 构建排序: {:.2} ms | 筛选项: {:.2} ms | 事件+关键词: {:.2} ms | 全量日期扫描: {:.2} ms",
        tl_bench.build_sort_ms,
        tl_bench.filter_options_ms,
        tl_bench.matching_filtered_query_ms,
        tl_bench.matching_full_date_query_ms
    );

    println!("[4/6] 正在测试 500,000 簇 FAT32 非稀疏混合簇映射与全零快路径...");
    let fat_bench = bench_fat_500k_clusters()?;
    println!(
        "  -> 非稀疏混合簇: {:.2} ms | 全零快路径: {:.2} ms",
        fat_bench.non_sparse_ms, fat_bench.all_zero_fast_path_ms
    );

    println!("[5/6] 正在测试连续 200 次审计链追加写入与 201 条整链校验...");
    let audit_bench = bench_audit_200()?;
    println!(
        "  -> 200次追加: {:.2} ms (均值 {:.3} ms/次) | 201条整链校验: {:.2} ms",
        audit_bench.append_200_ms, audit_bench.avg_per_append_ms, audit_bench.check_audit_201_ms
    );

    println!("[6/6] 正在测试合成多段 EWF1 (64 MiB) 多核并行解码哈希 & 多核 AVX2 内容搜索吞吐量...");
    let ewf_bench = bench_ewf1_64mib_parallel()?;
    let avx2_bench = bench_avx2_content_search()?;
    println!(
        "  -> EWF1 64 MiB 并行解码哈希: {:.2} ms ({:.2} MiB/s) | AVX2 256 MiB 内容搜索: {:.2} ms ({:.2} MiB/s, {:.2} GiB/s)",
        ewf_bench.elapsed_ms,
        ewf_bench.throughput_mib_per_sec,
        avx2_bench.elapsed_ms,
        avx2_bench.throughput_mib_per_sec,
        avx2_bench.throughput_gib_per_sec
    );

    let benchmarks = CoreBenchmarks {
        inventory_100k_gzip: inv_bench,
        timeline_400k_macb: tl_bench,
        fat_500k_clusters: fat_bench,
        audit_chain_200_writes: audit_bench,
    };

    let comparison_vs_python = if let Some(py_path) = find_python_bench_path(json_out)
        && let Ok(raw) = fs::read_to_string(&py_path)
        && let Ok(py_json) = serde_json::from_str::<Value>(&raw)
    {
        build_comparisons(&py_json, &golden, &benchmarks)
    } else {
        Vec::new()
    };

    if !comparison_vs_python.is_empty() {
        println!("\n=== TraceDesk Rust vs Python 性能基准对比表 ===");
        println!("| 测试项 | Python 基线 (ms) | Rust 原生 (ms) | 加速比 (Speedup) |");
        println!("| --- | ---: | ---: | ---: |");
        for row in &comparison_vs_python {
            println!(
                "| {} | {:.2} | {:.2} | **{:.2}×** |",
                row.metric, row.python_ms, row.rust_ms, row.speedup_x
            );
        }
    }

    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let rust_profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
    .to_string();

    let report = RustBenchReport {
        environment: BenchEnvironment {
            rust_profile,
            platform: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_count,
        },
        golden_demo_case: golden,
        benchmarks,
        extra_benchmarks: ExtraBenchmarks {
            ewf1_64mib_parallel_hash: ewf_bench,
            avx2_content_search_throughput: avx2_bench,
        },
        comparison_vs_python,
    };

    if let Some(out_path) = json_out {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json_text = serde_json::to_string_pretty(&report)?;
        fs::write(out_path, json_text.as_bytes())?;
        println!("\n已保存 Rust 性能基准结果至: {}", out_path.display());
    }

    Ok(report)
}
