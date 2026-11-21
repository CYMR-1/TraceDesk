//! Performance regression & benchmark tests matching `scratch/baseline/python_bench.json`:
//! 1. 100,000 inventory entries gzip write & read (`compresslevel=1`)
//! 2. 400,000 MACB timeline events parallel sort + filter_options + multi-core parallel filter
//! 3. 200 sequential audit log appends + full chain verification of 201 records

use std::time::Instant;

use serde_json::{Map, Value};
use tracedesk_core::{
    AuditOrigin, Case, TimelineFilter, TimelineIndex, read_inventory_gz, write_inventory_gz,
};
use tracedesk_engines::InventoryEntry;

fn build_synthetic_100k_inventory() -> Vec<InventoryEntry> {
    let mut entries = Vec::with_capacity(100_000);
    for i in 0..100_000u64 {
        let deleted = i.is_multiple_of(20);
        let reallocated = i.is_multiple_of(100);
        let offset = if i.is_multiple_of(2) { 2048 } else { 204_800 };
        let base_ts = 1_788_220_800 + (i as i64 % 86_400);
        entries.push(InventoryEntry {
            path: format!("DIR_{:03}/SUB_{:02}/FILE_{:06}.txt", i % 100, i % 10, i),
            inode: (i + 10).to_string(),
            mode: "r/rrwxrwxrwx".to_string(),
            size: (i % 65_536) + 128,
            deleted,
            reallocated,
            atime: base_ts,
            mtime: base_ts + 60,
            ctime: base_ts + 120,
            crtime: base_ts + 180,
            directory: false,
            offset,
            filesystem: "NTFS".to_string(),
            start_cluster_allocated: None,
            extents: None,
        });
    }
    entries
}

#[test]
fn bench_inventory_100k_gzip_write_read() {
    let entries = build_synthetic_100k_inventory();
    let tmp = tempfile::tempdir().expect("tempdir");
    let gz_path = tmp.path().join("inventory-100k.jsonl.gz");

    let t0 = Instant::now();
    write_inventory_gz(&gz_path, &entries, None).expect("write 100k gz");
    let write_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let gz_bytes = std::fs::metadata(&gz_path).unwrap().len();

    let t1 = Instant::now();
    let loaded = read_inventory_gz(&gz_path).expect("read 100k gz");
    let read_ms = t1.elapsed().as_secs_f64() * 1000.0;

    assert_eq!(loaded.len(), 100_000);
    assert_eq!(loaded[0], entries[0]);
    assert_eq!(loaded[99_999], entries[99_999]);

    eprintln!(
        "[BENCH] inventory_100k_gzip: write={write_ms:.2} ms (Py: 523.44 ms), read={read_ms:.2} ms (Py: 372.27 ms), gz_bytes={gz_bytes}"
    );
}

#[test]
fn bench_timeline_400k_parallel_sort_and_filter() {
    let entries = build_synthetic_100k_inventory();

    let t0 = Instant::now();
    let timeline = TimelineIndex::build(entries);
    let build_sort_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(timeline.len(), 400_000);

    let t1 = Instant::now();
    let opts = timeline.filter_options();
    let opts_ms = t1.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(opts.events.len(), 4);
    assert_eq!(opts.statuses.len(), 3);
    assert_eq!(opts.offsets.len(), 2);

    // Filtered query (event=M, offset=2048, query="DIR_000")
    let t2 = Instant::now();
    let filtered = timeline
        .matching(&TimelineFilter {
            event: Some("M".to_string()),
            offset: Some(2048),
            query: "DIR_000".to_string(),
            ..Default::default()
        })
        .expect("filtered match");
    let filtered_ms = t2.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(filtered.len(), 1000);

    // Status-only filter (`已删除·重分配`: every 100th entry -> 1000 entries * 4 events = 4000)
    let t3 = Instant::now();
    let status_hits = timeline
        .matching(&TimelineFilter {
            status: Some("已删除·重分配".to_string()),
            ..Default::default()
        })
        .expect("status match");
    let status_ms = t3.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(status_hits.len(), 4000);

    // Full date query across all 400k events (matching `2026-09-01` or `2026-09-02` -> `"2026-09-"`)
    let t4 = Instant::now();
    let date_hits = timeline
        .matching(&TimelineFilter {
            query: "2026-09-".to_string(),
            ..Default::default()
        })
        .expect("date match");
    let date_ms = t4.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(date_hits.len(), 400_000);

    eprintln!(
        "[BENCH] timeline_400k_macb: build_sort={build_sort_ms:.2} ms (Py: 108.19 ms), \
         filter_options={opts_ms:.2} ms (Py: 36.90 ms), \
         filtered={filtered_ms:.2} ms (Py: 420.54 ms), \
         status_only={status_ms:.2} ms (Py: 142.48 ms), \
         full_date_query={date_ms:.2} ms (Py: 1861.81 ms)"
    );
}

#[test]
fn bench_audit_chain_200_appends() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut case = Case::create(
        tmp.path(),
        "BENCH-AUDIT-200",
        "性能测试员",
        "200 次审计链追加基准",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create");

    let t0 = Instant::now();
    for i in 1..=200u64 {
        let mut details = Map::new();
        details.insert("index".to_string(), Value::from(i));
        details.insert("note".to_string(), Value::String(format!("取证发现笔记 #{i}")));
        case.log("FILE_NOTE", &format!("DOCS/FILE_{i}.TXT"), "成功", details)
            .expect("append audit");
    }
    let append_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let t1 = Instant::now();
    let records = case.check_audit().expect("check 201 records");
    let verify_ms = t1.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(records.len(), 201);

    eprintln!(
        "[BENCH] audit_chain_200_writes: append_200={append_ms:.2} ms ({:.3} ms/append, Py: 8526.25 ms), check_audit_201={verify_ms:.2} ms (Py: 41.93 ms)",
        append_ms / 200.0
    );
}
