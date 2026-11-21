//! Core unit & behavioral tests for formatting, canonical JSON, audit chain tamper detection,
//! locking, legacy migration, coverage, browser index, cross-page GBK/UTF-16/image preview,
//! SIMD content search, and selective/tampered review bundles.

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;

use image::codecs::gif::GifEncoder;
use image::{Delay, Frame, ImageBuffer, ImageFormat, Rgba};
use serde_json::{Map, Value, json};
use tracedesk_core::{
    AppPaths, AuditOrigin, AuditRecord, BrowserFilter, BrowserIndex, BuildBundleOptions, Case,
    CoreError, PageWindow, PreviewEncoding, Provenance, StatusFilter, TREE_GROUP_SIZE,
    TREE_GROUP_THRESHOLD, TimelineFilter, TimelineIndex, assess_coverage, audit_origin,
    audit_origin_label, build_bundle, canonical_json, case_folder_name, compute_legacy_carry,
    decode_image_preview, display_timestamp, find_matches_in_reader, format_unix_east8_stack,
    normalize_event_filter, parse_pattern, preview_rows, preview_text, save_json_atomic,
    source_status, verify_bundle, windows_filename,
};
use tracedesk_engines::{InventoryEntry, PartitionInfo};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

fn make_entry(path: &str, offset: u64, inode: &str, size: u64, dir: bool, del: bool) -> InventoryEntry {
    InventoryEntry {
        path: path.to_string(),
        inode: inode.to_string(),
        mode: if dir {
            "d/drwxrwxrwx".to_string()
        } else {
            "r/rrwxrwxrwx".to_string()
        },
        size,
        deleted: del,
        reallocated: false,
        atime: 1_788_220_800,
        mtime: 1_788_249_900,
        ctime: 0,
        crtime: 1_788_249_900,
        directory: dir,
        offset,
        filesystem: "FAT16".to_string(),
        start_cluster_allocated: None,
        extents: None,
    }
}

fn find_python(root: &Path) -> PathBuf {
    for cand in [
        root.join(".venv").join("Scripts").join("python.exe"),
        PathBuf::from(r"C:\Users\cymr1\Desktop\qimo\TraceDesk\.venv\Scripts\python.exe"),
        PathBuf::from("python"),
    ] {
        if cand.is_file() {
            return cand;
        }
    }
    PathBuf::from("python")
}

#[test]
fn canonical_json_matches_python_byte_for_byte() {
    #[derive(serde::Serialize)]
    struct Unsorted {
        zebra: i64,
        alpha: String,
        nested: Nested,
        slash: String,
        ctrl: String,
        empty: Option<String>,
        flag: bool,
    }
    #[derive(serde::Serialize)]
    struct Nested {
        b_zh: String,
        a_list: Vec<Value>,
    }

    let payload = Unsorted {
        zebra: 42,
        alpha: "取证测试/路径".to_string(),
        nested: Nested {
            b_zh: "中文内容\n换行\t制表\"引号\\反斜杠".to_string(),
            a_list: vec![json!({"k2": 2, "k1": 1}), Value::Null, Value::Bool(false)],
        },
        slash: "a/b/c".to_string(),
        ctrl: "\x01\x08\x0c\r\n\t".to_string(),
        empty: None,
        flag: true,
    };

    let rust_canonical = canonical_json(&payload).expect("canonical_json");
    assert_eq!(
        rust_canonical,
        r#"{"alpha":"取证测试/路径","ctrl":"\u0001\b\f\r\n\t","empty":null,"flag":true,"nested":{"a_list":[{"k1":1,"k2":2},null,false],"b_zh":"中文内容\n换行\t制表\"引号\\反斜杠"},"slash":"a/b/c","zebra":42}"#
    );

    // Cross-check directly against Python json.dumps(..., ensure_ascii=False, sort_keys=True, separators=(',', ':')).
    let paths = AppPaths::discover();
    let py = find_python(&paths.root);
    let out = Command::new(&py)
        .args([
            "-X",
            "utf8",
            "-c",
            "import json, sys; v = json.loads(sys.stdin.read()); sys.stdout.write(json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(',', ':')))",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(rust_canonical.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run python canonical check");
    assert!(out.status.success());
    assert_eq!(out.stdout, rust_canonical.as_bytes());
}

#[test]
fn formatting_windows_filenames_and_stack_timestamps() {
    assert_eq!(windows_filename("a<b>c:d\"e/f\\g|h?i*j\x01", 255), "a_b_c_d_e_f_g_h_i_j_");
    assert_eq!(windows_filename("CON", 255), "_CON");
    assert_eq!(windows_filename("nul.txt", 255), "_nul.txt");
    assert_eq!(windows_filename("COM1 .log", 255), "_COM1 .log");
    assert_eq!(windows_filename("LPT¹.dat", 255), "_LPT¹.dat");
    assert_eq!(windows_filename("   ...  ", 255), "file");

    // Surrogate pair (emoji = 2 UTF-16 code units) must never be split.
    let emoji_name = "a😀b"; // 1 + 2 + 1 = 4 UTF-16 units
    assert_eq!(windows_filename(emoji_name, 2), "a");
    assert_eq!(windows_filename(emoji_name, 3), "a😀");

    // Overlong case folder name (>255 UTF-16 units) splits into <=84 units per field.
    let long = "案".repeat(120);
    let folder = case_folder_name(&long, &long, &long);
    assert!(folder.chars().map(char::len_utf16).sum::<usize>() <= 255);

    // Zero-alloc stack UTC+8 formatter matches chrono across edge dates & leap years.
    for ts in [
        1_i64,
        86_400,
        951_782_400,   // 2000-02-29 UTC
        1_709_164_800, // 2024-02-29 UTC
        1_788_249_900, // 2026-09-01
        2_147_483_647, // 2038-01-19
        4_102_444_800, // 2100-01-01
    ] {
        let fast = format_unix_east8_stack(ts).expect("valid range");
        let fast_str = std::str::from_utf8(&fast).unwrap();
        assert_eq!(fast_str, display_timestamp(ts, false));
    }
    assert_eq!(display_timestamp(0, true), "未记录");
    assert_eq!(display_timestamp(-5, false), "未记录");
}

#[test]
fn audit_head_no_newline_tamper_detection_and_legacy_origin() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut case = Case::create(
        tmp.path(),
        "AUDIT-001",
        "取证员A",
        "篡改测试",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create");
    case.log("FILE_FILTER", "*.txt", "成功", Map::new())
        .expect("log 2");

    // `audit.head` must be exact 64 ASCII bytes, no newline.
    let head_path = case.folder().join("audit.head");
    let raw_head = fs::read(&head_path).expect("read head");
    assert_eq!(raw_head.len(), 64);
    assert!(!raw_head.contains(&b'\n'));

    // Tamper `audit.head` -> detected both by `log` (via cache miss -> full check) and `check_audit`.
    fs::write(&head_path, "0".repeat(64)).expect("tamper head");
    let err = case.log("FILE_FILTER", "*", "成功", Map::new()).unwrap_err();
    assert!(matches!(err, CoreError::AuditTampered(_)));

    // Restore head, tamper `audit.jsonl` body with EQUAL byte length AND preserved mtime,
    // then call `case.log()` -> MUST detect tampering and return `AuditTampered`!
    fs::write(&head_path, &raw_head).expect("restore head");
    let audit_path = case.folder().join("audit.jsonl");
    let orig_content = fs::read_to_string(&audit_path).expect("read audit.jsonl");
    let orig_mtime = fs::metadata(&audit_path).unwrap().modified().unwrap();
    let same_len_tampered = orig_content.replace("*.txt", "*.doc");
    assert_eq!(same_len_tampered.len(), orig_content.len());
    {
        let f = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&audit_path)
            .unwrap();
        (&f).write_all(same_len_tampered.as_bytes()).unwrap();
        f.set_modified(orig_mtime).unwrap();
    }
    let err_same_len_log = case.log("FILE_FILTER", "*", "成功", Map::new()).unwrap_err();
    assert!(matches!(err_same_len_log, CoreError::AuditTampered(_)));
    let err2 = case.check_audit().unwrap_err();
    assert!(matches!(err2, CoreError::AuditTampered(_)));

    // Legacy origin derivation without `origin` field.
    let legacy_mcp = AuditRecord {
        seq: 1,
        timestamp: "2026-01-01T08:00:00+08:00".to_string(),
        actor: "AI 助手 (MCP)".to_string(),
        origin: None,
        action: "CASE_CREATE".to_string(),
        subject: "X".to_string(),
        result: "成功".to_string(),
        details: Map::new(),
        previous: "0".repeat(64),
        hash: "a".repeat(64),
    };
    assert_eq!(audit_origin(&legacy_mcp), AuditOrigin::Mcp);
    assert_eq!(audit_origin_label(&legacy_mcp), "MCP");

    let legacy_manual = AuditRecord {
        actor: "普通取证员".to_string(),
        ..legacy_mcp
    };
    assert_eq!(audit_origin(&legacy_manual), AuditOrigin::Manual);
    assert_eq!(audit_origin_label(&legacy_manual), "人工");
}

#[test]
fn case_lock_isolation_and_legacy_inline_inventory_migration() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut case1 = Case::create(
        tmp.path(),
        "LOCK-001",
        "取证员",
        "锁测试",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create case1");

    // Duplicate case folder name gets ` (2)`.
    let mut case_dup = Case::create(
        tmp.path(),
        "LOCK-001",
        "取证员",
        "锁测试",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create duplicate");
    assert!(case_dup.folder().file_name().unwrap().to_string_lossy().ends_with(" (2)"));
    case_dup.close();

    // Concurrent open on same case fails with Locked.
    let lock_err = Case::open(case1.folder(), None, AuditOrigin::Mcp).err().expect("should lock");
    assert!(lock_err.is_locked());

    // Evidence inside cases root must be rejected!
    let bad_img = tmp.path().join("inside.dd");
    fs::write(&bad_img, vec![0u8; 4096]).expect("write bad img");
    let iso_err = case1.load_image(&bad_img, None, None, None).unwrap_err();
    assert!(iso_err.to_string().contains("案件库目录之外"));

    // `.e02` outside cases root must be rejected with "请从首段 E01 打开".
    let outside = tempfile::tempdir().expect("outside dir");
    let e02 = outside.path().join("disk.E02");
    fs::write(&e02, vec![0u8; 4096]).expect("write e02");
    let e02_err = case1.load_image(&e02, None, None, None).unwrap_err();
    assert!(e02_err.to_string().contains("首段 E01"));

    // Simulate legacy inline inventory in `case.json` and confirm automatic migration on `Case::open`.
    let folder = case1.folder().to_path_buf();
    case1.close();

    let meta_path = folder.join("case.json");
    let mut raw: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    let sample_entry = make_entry("LEGACY.TXT", 2048, "10", 128, false, false);
    raw["inventory"] = serde_json::to_value(vec![sample_entry]).unwrap();
    raw.as_object_mut().unwrap().remove("inventory_file");
    raw.as_object_mut().unwrap().remove("inventory_count");
    save_json_atomic(&meta_path, &raw).expect("save legacy case.json");

    let mut migrated = Case::open(&folder, None, AuditOrigin::Manual).expect("migrate legacy");
    assert_eq!(migrated.data().inventory.len(), 1);
    assert_eq!(migrated.data().inventory[0].path, "LEGACY.TXT");
    migrated.close();

    let after: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert!(after.get("inventory_file").is_some());
    assert_eq!(after["inventory_count"], json!(1));
    assert!(after.get("inventory").is_none());
}

#[test]
fn coverage_boot_sector_ntfs_fat_and_provenance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let img = tmp.path().join("vol.dd");

    // Create a synthetic 2 MiB image with a valid NTFS boot sector at sector 0 claiming 4096 sectors (=2 MiB).
    let mut data = vec![0u8; 4096 * 512];
    data[3..11].copy_from_slice(b"NTFS    ");
    data[11..13].copy_from_slice(&512u16.to_le_bytes());
    data[40..48].copy_from_slice(&4096u64.to_le_bytes());
    data[510] = 0x55;
    data[511] = 0xAA;
    fs::write(&img, &data).expect("write vol");

    let parts = vec![PartitionInfo {
        offset: 0,
        description: "NTFS".to_string(),
    }];
    let cov = assess_coverage::<fn(u64) -> Option<Vec<u8>>>(&img, &parts, "", None, None)
        .expect("assess");
    assert_eq!(cov.volumes[0].filesystem, "NTFS");
    assert_eq!(cov.volumes[0].status, "声明范围已覆盖");
    assert_eq!(cov.volumes[0].missing_bytes, 0);

    // Claiming more sectors than image size -> `声明范围超出镜像`.
    data[40..48].copy_from_slice(&8192u64.to_le_bytes());
    fs::write(&img, &data).expect("write truncated vol");
    let cov_short = assess_coverage::<fn(u64) -> Option<Vec<u8>>>(&img, &parts, "", None, None)
        .expect("assess short");
    assert_eq!(cov_short.volumes[0].status, "声明范围超出镜像");
    assert_eq!(cov_short.volumes[0].missing_bytes, 4096 * 512);

    // Invalid expected_sha256 rejected.
    let bad_prov = Provenance {
        expected_sha256: "not-64-hex".to_string(),
        ..Default::default()
    };
    assert!(bad_prov.normalized_and_validated().is_err());

    let ev = tracedesk_core::EvidenceInfo {
        path: "x.dd".to_string(),
        size: 100,
        sha256: Some("a".repeat(64)),
        fixed_at: Some("2026-01-01T08:00:00+08:00".to_string()),
        partitions: vec![],
        layout: String::new(),
        format: None,
        large_image: None,
        opened_at: None,
        source_stamp: None,
        segments: None,
        provenance: Some(Provenance {
            expected_sha256: "b".repeat(64),
            ..Default::default()
        }),
        coverage: None,
    };
    assert_eq!(source_status(&ev), "警告：交付方摘要与本机固定值不一致");
}

#[test]
fn browser_index_virtual_ancestors_pagination_and_large_dir_grouping() {
    // Include deep file without explicit parent directory entry + 2100 files in one folder.
    let mut entries = vec![make_entry("DEEP/SUB/LEAF.TXT", 2048, "99999", 10, false, false)];
    for i in 0..(TREE_GROUP_THRESHOLD + 52) {
        entries.push(make_entry(
            &format!("BIG/file_{i:04}.txt"),
            2048,
            &(i + 10).to_string(),
            64,
            false,
            i % 10 == 0,
        ));
    }

    let index = BrowserIndex::build(&entries);
    // Synthesized virtual ancestors `DEEP`, `DEEP/SUB`, and `BIG` must exist in root branch.
    let root_page = index.tree_children(2048, "", None);
    assert!(!root_page.grouped);
    assert!(root_page.nodes.iter().any(|n| n.path == "DEEP" && n.entry_id.is_none()));
    assert!(root_page.nodes.iter().any(|n| n.path == "BIG" && n.entry_id.is_none()));

    // `BIG` has 2100 > 2048 children -> grouped by 256!
    let big_grouped = index.tree_children(2048, "BIG", None);
    assert!(big_grouped.grouped);
    assert_eq!(
        big_grouped.group_count,
        (TREE_GROUP_THRESHOLD + 52).div_ceil(TREE_GROUP_SIZE)
    );
    assert!(big_grouped.nodes[0].is_group);
    assert_eq!(big_grouped.nodes[0].label, "条目 1–256");

    // Expanding bucket 0 yields 256 concrete nodes.
    let bucket0 = index.tree_children(2048, "BIG", Some(0));
    assert!(!bucket0.grouped);
    assert_eq!(bucket0.nodes.len(), 256);

    // Filtered pagination: deleted only in `BIG`.
    let page = index.query_page(
        &BrowserFilter {
            scope_offset: Some(2048),
            scope_path: Some("BIG".to_string()),
            status: StatusFilter::Deleted,
            ..Default::default()
        },
        0,
        100,
    );
    assert_eq!(page.total, 210);
    assert_eq!(page.total_pages, 3);
    assert_eq!(page.entry_ids.len(), 100);
}

#[test]
fn preview_cross_page_gbk_gb18030_utf16_and_image_caps() {
    // 1. Cross-page GBK Chinese boundary: 4095 bytes of 'A' + GBK("中文测试")
    //    '中' = [0xD6, 0xD0] straddles byte 4095 (page 0) and byte 4096 (page 1)!
    let (gbk_zh, _, had_err) = encoding_rs::GBK.encode("中文测试");
    assert!(!had_err);
    let mut gbk_data = vec![b'A'; 4095];
    gbk_data.extend_from_slice(&gbk_zh);
    let size = gbk_data.len() as u64;

    let read_at = |off: u64, len: usize| -> tracedesk_core::CoreResult<Vec<u8>> {
        let s = (off as usize).min(gbk_data.len());
        let e = (s + len).min(gbk_data.len());
        Ok(gbk_data[s..e].to_vec())
    };

    // Page 0: bytes [0..4099)
    let win0 = PageWindow {
        bytes: read_at(0, 4096 + 3).unwrap(),
        carry: 0,
        encoding: PreviewEncoding::Gbk,
    };
    let text0 = preview_text(&win0, 0, size, PreviewEncoding::Gbk, 4096);
    assert!(text0.ends_with("AA中"), "page 0 should decode straddling '中'");

    // Page 1: start = 4096, compute_legacy_carry must detect carry = 1!
    let (carry1, _) =
        compute_legacy_carry(4096, PreviewEncoding::Gbk, None, read_at).expect("carry");
    assert_eq!(carry1, 1);
    let win1 = PageWindow {
        bytes: read_at(4093, 4096 + 6).unwrap(),
        carry: carry1,
        encoding: PreviewEncoding::Gbk,
    };
    let text1 = preview_text(&win1, 4096, size, PreviewEncoding::Gbk, 4096);
    assert_eq!(text1, "文测试", "page 1 must align cleanly after straddling '中'");

    // 2. Cross-page UTF-16LE surrogate pair: 2047 'A's (4094 bytes) + "😀" (4 bytes at 4094..4098) + "中"
    let full_str = format!("{}😀中", "A".repeat(2047));
    let u16_bytes: Vec<u8> = full_str
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let u16_size = u16_bytes.len() as u64;

    let u16_win0 = PageWindow {
        bytes: u16_bytes[0..(4096 + 3).min(u16_bytes.len())].to_vec(),
        carry: 0,
        encoding: PreviewEncoding::Utf16Le,
    };
    let u16_t0 = preview_text(&u16_win0, 0, u16_size, PreviewEncoding::Utf16Le, 4096);
    assert!(u16_t0.ends_with("A😀"));

    let u16_win1 = PageWindow {
        bytes: u16_bytes[4093..].to_vec(),
        carry: 0,
        encoding: PreviewEncoding::Utf16Le,
    };
    let u16_t1 = preview_text(&u16_win1, 4096, u16_size, PreviewEncoding::Utf16Le, 4096);
    assert_eq!(u16_t1, "中");

    // 3. HEX row formatting check.
    let hex = preview_rows(&u16_win1, 4096, u16_size, PreviewEncoding::Utf16Le, 4096);
    assert_eq!(hex.len(), 1);
    assert_eq!(hex[0].offset_hex, "00001000");

    // 4. Image preview: valid PNG, oversized dimension (>4096px downscale), animated GIF first frame, corrupt data.
    let img_entry = make_entry("PIC.PNG", 2048, "1", 1000, false, false);
    let mut small_png = Vec::new();
    let small_buf: ImageBuffer<Rgba<u8>, Vec<u8>> =
        ImageBuffer::from_pixel(32, 16, Rgba([38, 116, 196, 255]));
    small_buf
        .write_to(&mut Cursor::new(&mut small_png), ImageFormat::Png)
        .unwrap();
    let res_ok = decode_image_preview(&small_png, &img_entry, "");
    assert!(res_ok.ok);
    assert_eq!(res_ok.width, Some(32));
    assert_eq!(res_ok.height, Some(16));
    assert!(!res_ok.animated);
    assert!(res_ok.data_url.as_deref().unwrap().starts_with("data:image/png;base64,"));

    // Oversized width 5000 x 100 (500k pixels <= 40MP, > 4096px axis -> scaled to 4096 wide)
    let mut wide_png = Vec::new();
    let wide_buf: ImageBuffer<Rgba<u8>, Vec<u8>> =
        ImageBuffer::from_pixel(5000, 100, Rgba([20, 140, 80, 255]));
    wide_buf
        .write_to(&mut Cursor::new(&mut wide_png), ImageFormat::Png)
        .unwrap();
    let res_wide = decode_image_preview(&wide_png, &img_entry, "");
    assert!(res_wide.ok);
    assert_eq!(res_wide.width, Some(5000));
    assert_eq!(res_wide.display_width, Some(4096));

    // Multi-frame animated GIF -> `animated == true`, decodes first frame cleanly.
    let mut gif_bytes = Vec::new();
    {
        let mut enc = GifEncoder::new(&mut gif_bytes);
        let f1 = Frame::from_parts(
            ImageBuffer::from_pixel(8, 8, Rgba([255, 0, 0, 255])),
            0,
            0,
            Delay::from_numer_denom_ms(100, 1),
        );
        let f2 = Frame::from_parts(
            ImageBuffer::from_pixel(8, 8, Rgba([0, 255, 0, 255])),
            0,
            0,
            Delay::from_numer_denom_ms(100, 1),
        );
        enc.encode_frames([f1, f2]).unwrap();
    }
    let res_gif = decode_image_preview(&gif_bytes, &img_entry, "");
    assert!(res_gif.ok);
    assert!(res_gif.animated);

    // Corrupt image bytes rejected cleanly.
    let res_corrupt = decode_image_preview(b"not a valid image", &img_entry, "");
    assert!(!res_corrupt.ok);
    assert!(res_corrupt.error.unwrap().contains("损坏或格式不受支持"));

    // >32 MiB image rejected before decode.
    let huge_entry = make_entry("HUGE.PNG", 2048, "2", 33 * 1024 * 1024, false, false);
    let res_huge = decode_image_preview(&[], &huge_entry, "");
    assert!(!res_huge.ok);
    assert!(res_huge.error.unwrap().contains("32 MiB"));
}

#[test]
fn content_search_patterns_sliding_context_and_timeline_aliases() {
    assert_eq!(parse_pattern("AB CD", "HEX").unwrap(), vec![0xAB, 0xCD]);
    assert_eq!(parse_pattern("A", "UTF-16LE").unwrap(), vec![0x41, 0x00]);
    assert_eq!(parse_pattern("中", "GBK").unwrap(), vec![0xD6, 0xD0]);
    assert!(parse_pattern("", "UTF-8").is_err());
    assert!(parse_pattern(&"A".repeat(4097), "UTF-8").is_err());

    // Overlapping hits & exact 12-byte before/after hex context across boundaries.
    let mut payload = vec![b'x'; 20];
    payload.extend_from_slice(b"AAAA");
    payload.extend_from_slice(b"0123456789abcdef");
    let mut cursor = Cursor::new(&payload);
    let hits = find_matches_in_reader(&mut cursor, payload.len() as u64, b"AA", None, None, None)
        .expect("find matches");
    assert_eq!(hits.len(), 3); // offsets 20, 21, 22
    assert_eq!(hits[0].file_byte, 20);
    assert_eq!(hits[1].file_byte, 21);
    assert_eq!(hits[2].file_byte, 22);
    assert_eq!(hits[0].before.split(' ').count(), 12);
    assert_eq!(hits[0].after.split(' ').count(), 12);

    // Short-read stream (25 of 50 recorded bytes) with a hit in the trailing 12 bytes (19..23):
    // flushing the tail buffer with `push_chunk(&[], ...)` must preserve the hit!
    let finder = memchr::memmem::Finder::new(b"NOTE");
    let mut short_matcher =
        tracedesk_core::StreamMatcher::new(&finder, 4, 50, 0, 0, 50, None);
    let mut short_stream = vec![b'.'; 19];
    short_stream.extend_from_slice(b"NOTE!");
    short_stream.push(b'!'); // 25 bytes total; "NOTE" is at 19..23 (only 2 bytes after!)
    assert_eq!(short_stream.len(), 25);
    short_matcher.push_chunk(&short_stream, None).unwrap();
    // Before EOF flush, hit at 19..23 is held waiting for 12-byte after context.
    short_matcher.push_chunk(&[], None).unwrap();
    let short_hits = short_matcher.into_hits();
    assert_eq!(short_hits.len(), 1);
    assert_eq!(short_hits[0].file_byte, 19);
    assert_eq!(short_hits[0].after, "21 21");

    // Timeline event aliases M/A/C/B.
    assert_eq!(normalize_event_filter("M").unwrap(), "M 内容修改");
    assert_eq!(normalize_event_filter("a").unwrap(), "A 访问");
    assert_eq!(normalize_event_filter("C").unwrap(), "C 元数据变更");
    assert_eq!(normalize_event_filter("B").unwrap(), "B 创建");
    assert!(normalize_event_filter("Z").is_err());

    let tl = TimelineIndex::build(vec![make_entry("A.TXT", 2048, "1", 10, false, false)]);
    let m_hits = tl
        .matching(&TimelineFilter {
            event: Some("M".to_string()),
            query: "2026-09-01 16:05:00".to_string(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(m_hits.len(), 1);
    let page = tl
        .query_page(&TimelineFilter::default(), true, 0, 10)
        .unwrap();
    // Descending preserves 1-based global ascending sequence numbers!
    assert_eq!(page.items[0].number, 3);
    assert_eq!(page.items[2].number, 1);
}

#[test]
fn review_bundle_missing_material_handling_and_tamper_detection() {
    let paths = AppPaths::discover();
    let demo_dd = paths.evidence_dir.join("demo.dd");
    let tmp = tempfile::tempdir().expect("tempdir");

    let mut case = Case::create(
        tmp.path(),
        "REV-001",
        "复核员",
        "缺失材料与篡改测试",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create");
    case.load_image(&demo_dd, None, None, None).expect("load");
    let inv = case.scan_partitions(None, None, None).expect("scan");
    let f1 = inv.iter().find(|e| e.path == "README.TXT").unwrap().clone();
    let f2 = inv.iter().find(|e| e.path == "NOTES.TXT").unwrap().clone();
    let p1 = case.export(&f1, None).expect("export 1");
    let _p2 = case.export(&f2, None).expect("export 2");

    // Delete first exported file to simulate missing local copy.
    fs::remove_file(&p1).expect("delete exported copy");

    // Default (`skip_missing=false`) rejects missing selected export.
    let miss_err = build_bundle(&mut case, &BuildBundleOptions::default(), None).unwrap_err();
    assert!(matches!(miss_err, CoreError::MissingMaterials(_)));

    // `skip_missing=true` succeeds, omits export #1, appends instruction #7, and passes verify_bundle!
    let res = build_bundle(
        &mut case,
        &BuildBundleOptions {
            selected_export_indices: None,
            selected_search_indices: None,
            skip_missing: true,
        },
        None,
    )
    .expect("build with skip_missing");
    assert_eq!(res.included_exports, 1);
    assert_eq!(res.omitted_exports, 1);
    assert_eq!(res.missing_exports, 1);
    verify_bundle(&res.bundle_path, Some(&res.sha256)).expect("verify bundle with omitted");

    // Repack ZIP with tampered `report.md` -> `verify_bundle` MUST reject!
    let tampered_zip = tmp.path().join("tampered.zip");
    {
        let mut src_zip = ZipArchive::new(fs::File::open(&res.bundle_path).unwrap()).unwrap();
        let mut dst_zip = ZipWriter::new(fs::File::create(&tampered_zip).unwrap());
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for i in 0..src_zip.len() {
            let mut entry = src_zip.by_index(i).unwrap();
            let name = entry.name().to_string();
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf).unwrap();
            if name == "report.md" {
                buf.extend_from_slice(b"\nTAMPERED");
            }
            dst_zip.start_file(&name, opts).unwrap();
            dst_zip.write_all(&buf).unwrap();
        }
        dst_zip.finish().unwrap();
    }
    let tamper_err = verify_bundle(&tampered_zip, None).unwrap_err();
    assert!(tamper_err.to_string().contains("成员摘要不匹配"));

    // Wrong external SHA-256 rejected.
    let bad_sha = verify_bundle(&res.bundle_path, Some(&"0".repeat(64))).unwrap_err();
    assert!(bad_sha.to_string().contains("外部 SHA-256 不匹配"));

    // Verify `AppPaths` resolves tools & evidence cleanly.
    assert!(paths.find_tsk_bin().is_some());
    assert!(paths.verify_bundle_script().is_some());
    let _ = AtomicBool::new(false);
}
