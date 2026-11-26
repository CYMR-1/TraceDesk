//! 核心单元与行为测试：覆盖格式化、规范化 JSON、审计链篡改检测、
//! 文件锁、旧版清单迁移、卷覆盖范围、浏览索引、跨页 GBK/UTF-16/图片预览、
//! SIMD 内容搜索以及按需/篡改复核包校验。

use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;

#[cfg(feature = "image-preview")]
use image::codecs::gif::GifEncoder;
#[cfg(feature = "image-preview")]
use image::{Delay, Frame, ImageBuffer, ImageFormat, Rgba};
use serde_json::{Map, Value, json};
#[cfg(feature = "image-preview")]
use tracedesk_core::{decode_image_preview, preview_entry_image};
use tracedesk_core::{
    AppPaths, AuditOrigin, AuditRecord, BrowserFilter, BrowserIndex, BuildBundleOptions, Case,
    CoreError, ExportRecord, PageWindow, PreviewEncoding, PreviewSession, Provenance, StatusFilter,
    TREE_GROUP_SIZE, TREE_GROUP_THRESHOLD, TimelineFilter, TimelineIndex, assess_coverage,
    audit_mcp_user, audit_origin, audit_origin_label, build_bundle, canonical_json,
    case_folder_name, compute_legacy_carry, display_timestamp, find_matches_in_reader,
    findings_text, format_unix_east8_stack, inspect_bundle_exports, normalize_event_filter,
    numbered_export_filename, parse_pattern, preview_rows, preview_text, record_note,
    render_report, resolve_export_path, save_json_atomic, source_status, strip_trailing_version,
    utf16_unit_len, verify_audit_chain_at, verify_bundle, windows_filename,
};
use tracedesk_engines::{InventoryEntry, PartitionInfo, TskCli};
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

fn find_python(root: &Path) -> Option<PathBuf> {
    let cand = root.join(".venv").join("Scripts").join("python.exe");
    cand.is_file().then_some(cand)
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

    // 当本地存在 `.venv\Scripts\python.exe` 时，可选与 Python
    // json.dumps(..., ensure_ascii=False, sort_keys=True, separators=(',', ':')) 做交叉核对。
    let paths = AppPaths::discover();
    if let Some(py) = find_python(&paths.root) {
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
}

#[test]
fn formatting_windows_filenames_and_stack_timestamps() {
    assert_eq!(windows_filename("a<b>c:d\"e/f\\g|h?i*j\x01", 255), "a_b_c_d_e_f_g_h_i_j_");
    assert_eq!(windows_filename("CON", 255), "_CON");
    assert_eq!(windows_filename("nul.txt", 255), "_nul.txt");
    assert_eq!(windows_filename("COM1 .log", 255), "_COM1 .log");
    assert_eq!(windows_filename("LPT¹.dat", 255), "_LPT¹.dat");
    assert_eq!(windows_filename("   ...  ", 255), "file");

    // 代理对（emoji 占 2 个 UTF-16 代码单元）绝不能被拆分。
    let emoji_name = "a😀b"; // 1 + 2 + 1 = 4 个 UTF-16 代码单元
    assert_eq!(windows_filename(emoji_name, 2), "a");
    assert_eq!(windows_filename(emoji_name, 3), "a😀");

    // 默认案件目录名使用 `_` 连接编号、人员与对象，超长时（>255 个 UTF-16 单元）每个字段截断至 <=84 个单元。
    assert_eq!(case_folder_name("XCB", "GJR", "SDGFGH"), "XCB_GJR_SDGFGH");
    let long = "案".repeat(120);
    let folder = case_folder_name(&long, &long, &long);
    assert!(folder.chars().map(char::len_utf16).sum::<usize>() <= 255);
    assert_eq!(folder.matches('_').count(), 2);

    // 零分配栈上 UTC+8 格式化器在边界日期与闰年上与 chrono 结果一致。
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

    // `audit.head` 必须严格为 64 字节 ASCII，不含换行符。
    let head_path = case.folder().join("audit.head");
    let raw_head = fs::read(&head_path).expect("read head");
    assert_eq!(raw_head.len(), 64);
    assert!(!raw_head.contains(&b'\n'));

    // 篡改 `audit.head` -> `log`（缓存未命中触发全量检查）与 `check_audit` 均应检出。
    fs::write(&head_path, "0".repeat(64)).expect("tamper head");
    let err = case.log("FILE_FILTER", "*", "成功", Map::new()).unwrap_err();
    assert!(matches!(err, CoreError::AuditTampered(_)));

    // 恢复 head，保持字节长度与 mtime 不变地篡改 `audit.jsonl` 正文，
    // 再调用 `case.log()` -> 必须检出篡改并返回 `AuditTampered`！
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

    // 历史兼容：无 `origin` 与 `mcp_client` 字段时按 `actor` 推导来源及使用者。
    let legacy_mcp = AuditRecord {
        seq: 1,
        timestamp: "2026-01-01T08:00:00+08:00".to_string(),
        actor: "AI 助手 (MCP)".to_string(),
        origin: None,
        mcp_client: None,
        action: "CASE_CREATE".to_string(),
        subject: "X".to_string(),
        result: "成功".to_string(),
        details: Map::new(),
        previous: "0".repeat(64),
        hash: "a".repeat(64),
    };
    assert_eq!(audit_origin(&legacy_mcp), AuditOrigin::Mcp);
    assert_eq!(audit_mcp_user(&legacy_mcp).as_deref(), Some("AI 助手"));
    assert_eq!(audit_origin_label(&legacy_mcp), "MCP · AI 助手");

    // 泛化 MCP 标识（无具体使用者名）时保持展示为 "MCP"。
    let legacy_generic_mcp = AuditRecord {
        actor: "MCP".to_string(),
        origin: Some("mcp".to_string()),
        ..legacy_mcp.clone()
    };
    assert_eq!(audit_origin(&legacy_generic_mcp), AuditOrigin::Mcp);
    assert_eq!(audit_mcp_user(&legacy_generic_mcp), None);
    assert_eq!(audit_origin_label(&legacy_generic_mcp), "MCP");

    let legacy_manual = AuditRecord {
        actor: "普通取证员".to_string(),
        ..legacy_mcp
    };
    assert_eq!(audit_origin(&legacy_manual), AuditOrigin::Manual);
    assert_eq!(audit_mcp_user(&legacy_manual), None);
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

    // 重名案件目录自动追加 ` (2)` 后缀。
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

    // 并发打开同一案件应因锁冲突返回 Locked 错误。
    let lock_err = Case::open(case1.folder(), None, AuditOrigin::Mcp).err().expect("should lock");
    assert!(lock_err.is_locked());

    // 位于案件库根目录内部的镜像文件必须被拒绝。
    let bad_img = tmp.path().join("inside.dd");
    fs::write(&bad_img, vec![0u8; 4096]).expect("write bad img");
    let iso_err = case1.load_image(&bad_img, None, None, None).unwrap_err();
    assert!(iso_err.to_string().contains("案件库目录之外"));

    // 案件库外部的 `.e02` 分段文件必须被拒绝并提示“请从首段 E01 打开”。
    let outside = tempfile::tempdir().expect("outside dir");
    let e02 = outside.path().join("disk.E02");
    fs::write(&e02, vec![0u8; 4096]).expect("write e02");
    let e02_err = case1.load_image(&e02, None, None, None).unwrap_err();
    assert!(e02_err.to_string().contains("首段 E01"));

    // 模拟 `case.json` 中的旧版内联清单，验证 `Case::open` 会自动迁移为 `.jsonl.gz`。
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
    assert!(after.get("inventory_files").is_some());
    assert!(after.get("inventory_file").is_none());
    assert_eq!(after["inventory_count"], json!(1));
    assert!(after.get("inventory").is_none());
}

#[test]
fn coverage_boot_sector_ntfs_fat_and_provenance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let img = tmp.path().join("vol.dd");

    // 构造合成 2 MiB 镜像，扇区 0 包含有效 NTFS 引导扇区并声明 4096 扇区（=2 MiB）。
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

    // 声明扇区数超出镜像大小 -> `声明范围超出镜像`。
    data[40..48].copy_from_slice(&8192u64.to_le_bytes());
    fs::write(&img, &data).expect("write truncated vol");
    let cov_short = assess_coverage::<fn(u64) -> Option<Vec<u8>>>(&img, &parts, "", None, None)
        .expect("assess short");
    assert_eq!(cov_short.volumes[0].status, "声明范围超出镜像");
    assert_eq!(cov_short.volumes[0].missing_bytes, 4096 * 512);

    // 非法的 expected_sha256 应被拒绝。
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
    // 包含缺少显式父目录条目的深层文件，以及同一目录下的 2100 个文件。
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
    // 合成的虚拟祖先目录 `DEEP`、`DEEP/SUB` 与 `BIG` 必须出现在根分支中。
    let root_page = index.tree_children(2048, "", None);
    assert!(!root_page.grouped);
    assert!(root_page.nodes.iter().any(|n| n.path == "DEEP" && n.entry_id.is_none()));
    assert!(root_page.nodes.iter().any(|n| n.path == "BIG" && n.entry_id.is_none()));

    // `BIG` 含有 2100 > 2048 个子项 -> 按每桶 256 项分组。
    let big_grouped = index.tree_children(2048, "BIG", None);
    assert!(big_grouped.grouped);
    assert_eq!(
        big_grouped.group_count,
        (TREE_GROUP_THRESHOLD + 52).div_ceil(TREE_GROUP_SIZE)
    );
    assert!(big_grouped.nodes[0].is_group);
    assert_eq!(big_grouped.nodes[0].label, "条目 1–256");

    // 展开第 0 桶应返回 256 个实际节点。
    let bucket0 = index.tree_children(2048, "BIG", Some(0));
    assert!(!bucket0.grouped);
    assert_eq!(bucket0.nodes.len(), 256);

    // 筛选分页：仅查询 `BIG` 目录下的已删除条目。
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
    // 1. 跨页 GBK 中文边界：4095 字节 'A' + GBK("中文测试")
    //    '中' = [0xD6, 0xD0] 跨越第 0 页末尾字节 4095 与第 1 页起始字节 4096。
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

    // 第 0 页：字节范围 [0..4099)
    let win0 = PageWindow {
        bytes: read_at(0, 4096 + 3).unwrap(),
        carry: 0,
        encoding: PreviewEncoding::Gbk,
    };
    let text0 = preview_text(&win0, 0, size, PreviewEncoding::Gbk, 4096);
    assert!(text0.ends_with("AA中"), "page 0 should decode straddling '中'");

    // 第 1 页：start = 4096，compute_legacy_carry 必须检出 carry = 1。
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

    // 2. 跨页 UTF-16LE 代理对：2047 个 'A'（4094 字节）+ "😀"（4 字节位于 4094..4098）+ "中"
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

    // 3. HEX 行格式化检查。
    let hex = preview_rows(&u16_win1, 4096, u16_size, PreviewEncoding::Utf16Le, 4096);
    assert_eq!(hex.len(), 1);
    assert_eq!(hex[0].offset_hex, "00001000");

    // 4. 图片预览：有效 PNG、超大尺寸降采样（>4096px）、动图 GIF 首帧以及损坏数据拦截。
    #[cfg(feature = "image-preview")]
    {
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

        // 超宽尺寸 5000 x 100（50 万像素 <= 4000 万像素，单边 > 4096px -> 缩放至宽 4096）
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

        // 多帧动图 GIF -> `animated == true`，正常解码首帧。
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

        // 损坏图片字节应被明确拒绝。
        let res_corrupt = decode_image_preview(b"not a valid image", &img_entry, "");
        assert!(!res_corrupt.ok);
        assert!(res_corrupt.error.unwrap().contains("损坏或格式不受支持"));

        // 超过 32 MiB 的图片应在解码前直接拒绝。
        let huge_entry = make_entry("HUGE.PNG", 2048, "2", 33 * 1024 * 1024, false, false);
        let res_huge = decode_image_preview(&[], &huge_entry, "");
        assert!(!res_huge.ok);
        assert!(res_huge.error.unwrap().contains("32 MiB"));
    }
}

#[test]
fn content_search_patterns_sliding_context_and_timeline_aliases() {
    assert_eq!(parse_pattern("AB CD", "HEX").unwrap(), vec![0xAB, 0xCD]);
    assert_eq!(parse_pattern("A", "UTF-16LE").unwrap(), vec![0x41, 0x00]);
    assert_eq!(parse_pattern("中", "GBK").unwrap(), vec![0xD6, 0xD0]);
    assert!(parse_pattern("", "UTF-8").is_err());
    assert!(parse_pattern(&"A".repeat(4097), "UTF-8").is_err());

    // 跨边界的重叠命中与精确 12 字节前后 HEX 上下文。
    let mut payload = vec![b'x'; 20];
    payload.extend_from_slice(b"AAAA");
    payload.extend_from_slice(b"0123456789abcdef");
    let mut cursor = Cursor::new(&payload);
    let hits = find_matches_in_reader(&mut cursor, payload.len() as u64, b"AA", None, None, None)
        .expect("find matches");
    assert_eq!(hits.len(), 3); // 偏移 20、21、22
    assert_eq!(hits[0].file_byte, 20);
    assert_eq!(hits[1].file_byte, 21);
    assert_eq!(hits[2].file_byte, 22);
    assert_eq!(hits[0].before.split(' ').count(), 12);
    assert_eq!(hits[0].after.split(' ').count(), 12);

    // 短读流（记录 50 字节但仅读到 25 字节），且命中位于末尾 12 字节内（19..23）：
    // 调用 `push_chunk(&[], ...)` 冲刷尾缓冲必须保留该命中项。
    let finder = memchr::memmem::Finder::new(b"NOTE");
    let mut short_matcher =
        tracedesk_core::StreamMatcher::new(&finder, 4, 50, 0, 0, 50, None);
    let mut short_stream = vec![b'.'; 19];
    short_stream.extend_from_slice(b"NOTE!");
    short_stream.push(b'!'); // 总计 25 字节；"NOTE" 位于 19..23（其后仅剩 2 字节）
    assert_eq!(short_stream.len(), 25);
    short_matcher.push_chunk(&short_stream, None).unwrap();
    // EOF 冲刷前，位于 19..23 的命中项会暂存等待 12 字节后文上下文。
    short_matcher.push_chunk(&[], None).unwrap();
    let short_hits = short_matcher.into_hits();
    assert_eq!(short_hits.len(), 1);
    assert_eq!(short_hits[0].file_byte, 19);
    assert_eq!(short_hits[0].after, "21 21");

    // 时间线事件别名 M/A/C/B。
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
    // 倒序展示时仍保留从 1 开始的全局升序序号。
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

    // 删除首个导出文件以模拟本地副本缺失。
    fs::remove_file(&p1).expect("delete exported copy");

    // 默认选项（`skip_missing=false`）拒绝缺失已选导出文件的复核包构建。
    let miss_err = build_bundle(&mut case, &BuildBundleOptions::default(), None).unwrap_err();
    assert!(matches!(miss_err, CoreError::MissingMaterials(_)));

    // `skip_missing=true` 应构建成功，省略导出 #1、追加说明第 7 条并通过 verify_bundle 核验。
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

    // 重打包 ZIP 并篡改 `report.md` -> `verify_bundle` 必须拒绝！
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

    // 错误的外部 SHA-256 应被拒绝。
    let bad_sha = verify_bundle(&res.bundle_path, Some(&"0".repeat(64))).unwrap_err();
    assert!(bad_sha.to_string().contains("外部 SHA-256 不匹配"));

    // 验证 `AppPaths` 能正确定位工具与证据目录。
    assert!(paths.find_tsk_bin().is_some());
    assert!(paths.verify_bundle_script().is_some());
    let _ = AtomicBool::new(false);
}

#[test]
fn mcp_client_audit_chain_reporting_and_verify_bundle_compat() {
    let paths = AppPaths::discover();
    let demo_dd = paths.evidence_dir.join("demo.dd");
    assert!(demo_dd.is_file(), "缺少测试镜像 demo.dd");

    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    let folder = {
        let mut manual_case = Case::create(
            &cases_dir,
            "MCP-WHO-001",
            "张取证",
            "MCP来源标记测试",
            None,
            None,
            AuditOrigin::Manual,
        )
        .expect("创建人工案件");
        manual_case.load_image(&demo_dd, None, None, None).expect("载入镜像");
        manual_case
            .scan_partitions(None, None, None)
            .expect("扫描分区");
        let dir = manual_case.folder().to_path_buf();
        manual_case.close();
        dir
    };

    // 校验人工记录绝不写入 `mcp_client` 键，确保与历史人工记录字节级一致。
    let audit_before_mcp = fs::read_to_string(folder.join("audit.jsonl")).expect("读取人工审计链");
    assert!(
        !audit_before_mcp.contains("\"mcp_client\""),
        "人工操作记录不应包含 mcp_client 键：{audit_before_mcp}"
    );

    // 以 MCP 身份并携带使用者/客户端标识打开同一案件，记录取证发现并构建复核包。
    let bundle_res = {
        let mut mcp_case = Case::open_with_mcp_client(
            &folder,
            Some("张三"),
            AuditOrigin::Mcp,
            Some("张三 / Cursor 1.2"),
        )
        .expect("以 MCP 身份打开案件");
        assert_eq!(mcp_case.mcp_client(), Some("张三 / Cursor 1.2"));

        let target_entry = mcp_case
            .displayed_entries()
            .iter()
            .find(|e| e.path.ends_with("CASE.TXT") && !e.deleted)
            .cloned()
            .expect("定位 CASE.TXT");
        let note_rec = record_note(&mut mcp_case, &target_entry, "由 MCP 协同标记的关键发现")
            .expect("写入 MCP 取证笔记");
        // 磁盘原始记录保留传入值，展示归一化去除末尾版本号数字（不影响既有审计链）。
        assert_eq!(note_rec.mcp_client.as_deref(), Some("张三 / Cursor 1.2"));
        assert_eq!(audit_mcp_user(&note_rec).as_deref(), Some("张三 / Cursor"));
        assert_eq!(audit_origin_label(&note_rec), "MCP · 张三 / Cursor");

        // 校验纯文本取证发现与 Markdown 报告均展示去除版本号后的 “MCP · 张三 / Cursor”。
        let records = mcp_case.check_audit().expect("核验含 mcp_client 的审计链");
        let plain = findings_text(&records);
        assert!(plain.contains("[MCP · 张三 / Cursor]"), "findings_text={plain}");

        let report_md = render_report(mcp_case.data(), &records, "通过：测试校验");
        assert!(
            report_md.contains("| MCP · 张三 / Cursor |"),
            "报告审计日志摘要应包含归一化后的 MCP 使用者：{report_md}"
        );
        assert!(
            report_md.contains("[MCP · 张三 / Cursor]"),
            "报告文件取证发现应包含归一化后的 MCP 使用者：{report_md}"
        );

        let bundle = build_bundle(&mut mcp_case, &BuildBundleOptions::default(), None)
            .expect("生成含 mcp_client 审计记录的复核包");
        mcp_case.close();
        bundle
    };

    // 原生 Rust 核验复核包与审计哈希链必须 100% 通过。
    let verified = verify_bundle(&bundle_res.bundle_path, Some(&bundle_res.sha256))
        .expect("Rust verify_bundle 验签通过");
    assert!(verified >= 5);

    // 独立核验磁盘审计链可反序列化全部历史人工记录 + 新 MCP 记录。
    let disk_records = verify_audit_chain_at(&folder).expect("磁盘审计链验签通过");
    assert!(disk_records.iter().any(|r| r.origin.as_deref() == Some("manual") && r.mcp_client.is_none()));
    assert!(
        disk_records
            .iter()
            .any(|r| r.mcp_client.as_deref() == Some("张三 / Cursor 1.2"))
    );

    // 若本机存在 Python 3，则同步用内嵌 `verify_bundle.py` 进行跨语言验签。
    let py_script = tmp.path().join("verify_bundle.py");
    fs::write(&py_script, tracedesk_core::EMBEDDED_VERIFY_BUNDLE_PY).expect("写出 verify_bundle.py");
    for py_bin in ["python", "python3"] {
        if let Ok(output) = std::process::Command::new(py_bin)
            .arg(&py_script)
            .arg(&bundle_res.bundle_path)
            .arg("--sha256")
            .arg(&bundle_res.sha256)
            .output()
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("核验通过"), "verify_bundle.py 输出异常：{stdout}");
            break;
        }
    }
}

#[test]
fn strip_trailing_version_and_legacy_audit_chain_compat() {
    // 1. 校验各类常见与边界格式的去尾版本号规则。
    assert_eq!(strip_trailing_version("workbuddy 1.0"), "workbuddy");
    assert_eq!(strip_trailing_version("Antigravity 1.0"), "Antigravity");
    assert_eq!(strip_trailing_version("Cursor 1.2.3"), "Cursor");
    assert_eq!(strip_trailing_version("claude-code v2.1"), "claude-code");
    assert_eq!(strip_trailing_version("claude-code V2.1.0"), "claude-code");
    assert_eq!(strip_trailing_version("ForensicBot/3.0"), "ForensicBot");
    assert_eq!(
        strip_trailing_version("WorkBuddy HTTP / workbuddy-http-forensics 1.0"),
        "WorkBuddy HTTP / workbuddy-http-forensics"
    );
    assert_eq!(
        strip_trailing_version("王五 / ForensicBot/3.0"),
        "王五 / ForensicBot"
    );
    assert_eq!(strip_trailing_version("张三 / Cursor 1.2"), "张三 / Cursor");
    assert_eq!(strip_trailing_version("workbuddy 1.0.0-beta.1"), "workbuddy");
    // 纯数字名称与去除后为空的段必须保留原段，且连字符命名不误删。
    assert_eq!(strip_trailing_version("12345"), "12345");
    assert_eq!(strip_trailing_version("1.0"), "1.0");
    assert_eq!(strip_trailing_version("/3.0"), "/3.0");
    assert_eq!(strip_trailing_version("GPT-4"), "GPT-4");
    assert_eq!(strip_trailing_version("本地 MCP 客户端"), "本地 MCP 客户端");
    assert_eq!(strip_trailing_version("   "), "");

    // 2. 模拟历史案件磁盘 `audit.jsonl` 中存在带版本号的旧记录 + 不带版本号的新记录，
    //    验证展示标签自动去尾版本号合并，同时磁盘原文未被修改且哈希链 100% 校验通过。
    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    let folder = {
        let mut legacy_case = Case::create_with_mcp_client(
            &cases_dir,
            "LEG-VER-001",
            "张取证",
            "历史版本号兼容测试",
            None,
            Some("张取证"),
            AuditOrigin::Mcp,
            Some("workbuddy 1.0"),
        )
        .expect("创建历史 MCP 案件");
        legacy_case
            .log_with_mcp_client(
                "FILE_NOTE",
                "DOCS/CASE.TXT",
                "成功",
                Map::new(),
                Some("WorkBuddy HTTP / workbuddy-http-forensics 1.0"),
            )
            .expect("追加历史复合来源记录");
        legacy_case
            .log_with_mcp_client(
                "FILE_NOTE",
                "DOCS/CASE.TXT",
                "成功",
                Map::new(),
                Some("workbuddy"),
            )
            .expect("追加新版无版本号记录");
        let dir = legacy_case.folder().to_path_buf();
        legacy_case.close();
        dir
    };

    // 磁盘 audit.jsonl 原文保持不变，绝不改写历史记录，且完整 SHA-256 哈希链 100% 通过。
    let raw_disk = fs::read_to_string(folder.join("audit.jsonl")).expect("读取磁盘 audit.jsonl");
    assert!(raw_disk.contains("\"workbuddy 1.0\""));
    assert!(raw_disk.contains("\"WorkBuddy HTTP / workbuddy-http-forensics 1.0\""));

    let verified = verify_audit_chain_at(&folder).expect("历史含版本号审计链必须 100% 验签通过");
    assert_eq!(verified.len(), 3);
    assert_eq!(audit_mcp_user(&verified[0]).as_deref(), Some("workbuddy"));
    assert_eq!(audit_origin_label(&verified[0]), "MCP · workbuddy");
    assert_eq!(
        audit_mcp_user(&verified[1]).as_deref(),
        Some("WorkBuddy HTTP / workbuddy-http-forensics")
    );
    assert_eq!(
        audit_origin_label(&verified[1]),
        "MCP · WorkBuddy HTTP / workbuddy-http-forensics"
    );
    assert_eq!(audit_mcp_user(&verified[2]).as_deref(), Some("workbuddy"));
    assert_eq!(audit_origin_label(&verified[2]), "MCP · workbuddy");
}

#[test]
fn stream_matcher_small_initial_chunks_find_match_at_offset_zero() {
    let payload = b"NEEDLE_AT_ZERO_followed_by_more_bytes_1234567890_end";
    let needle = b"NEEDLE";
    let finder = memchr::memmem::Finder::new(needle);

    // 逐 1 字节投喂：首块长度远小于 needle_len + CONTEXT_BYTES，不得跳过偏移 0。
    let mut m1 = tracedesk_core::StreamMatcher::new(
        &finder,
        needle.len(),
        payload.len() as u64,
        0,
        0,
        payload.len() as u64,
        None,
    );
    for chunk in payload.chunks(1) {
        m1.push_chunk(chunk, None).expect("1-byte chunk");
    }
    let hits1 = m1.into_hits();
    assert_eq!(hits1.len(), 1);
    assert_eq!(hits1[0].file_byte, 0);
    assert_eq!(hits1[0].before, "");
    assert_eq!(
        hits1[0].after,
        tracedesk_core::hex_spaced_lower(&payload[needle.len()..needle.len() + 12])
    );

    // 投喂恰好等于 CONTEXT_BYTES（12 字节）的首块：search_end == 0 < needle_len，不得跳过偏移 0。
    let mut m12 = tracedesk_core::StreamMatcher::new(
        &finder,
        needle.len(),
        payload.len() as u64,
        0,
        0,
        payload.len() as u64,
        None,
    );
    m12.push_chunk(&payload[..12], None).expect("12-byte head");
    m12.push_chunk(&payload[12..], None).expect("tail");
    let hits12 = m12.into_hits();
    assert_eq!(hits12.len(), 1);
    assert_eq!(hits12[0].file_byte, 0);
}

#[test]
fn windows_filename_rechecks_reserved_name_after_truncation_and_report_handles_none_evidence() {
    // "CONSOLE" 截断为 3 个 UTF-16 单元后会变成保留设备名 "CON"，必须二次净化。
    let sanitized = windows_filename("CONSOLE", 3);
    assert_ne!(sanitized.to_ascii_uppercase(), "CON");
    assert!(sanitized.starts_with('_'));

    // render_report 在未加载镜像（evidence: None）时不应 panic。
    let data = tracedesk_core::CaseData {
        id: "id-none".to_string(),
        number: "NO-EV-001".to_string(),
        examiner: "测试员".to_string(),
        target: "空证据".to_string(),
        created: "2026-11-25T16:00:00+08:00".to_string(),
        evidence: None,
        inventory: Vec::new(),
        exports: Vec::new(),
        partition_scans: None,
        offset: None,
        fsstat: None,
        index_verification: None,
        verification: None,
    };
    let md = render_report(&data, &[], "无证据兜底");
    assert!(md.contains("NO-EV-001"));
}

#[test]
fn numbered_export_filename_rules_and_duplicate_export_review_bundle() {
    // 1. 单元测试 `numbered_export_filename`：覆盖常规、无扩展名、多点扩展名、隐藏文件与超长截断。
    assert_eq!(numbered_export_filename("NOTES.TXT", 0), "NOTES.TXT");
    assert_eq!(numbered_export_filename("NOTES.TXT", 1), "NOTES(1).TXT");
    assert_eq!(numbered_export_filename("NOTES.TXT", 2), "NOTES(2).TXT");
    assert_eq!(numbered_export_filename("README", 0), "README");
    assert_eq!(numbered_export_filename("README", 1), "README(1)");
    assert_eq!(numbered_export_filename("README", 2), "README(2)");
    assert_eq!(numbered_export_filename("archive.tar.gz", 1), "archive.tar(1).gz");
    assert_eq!(numbered_export_filename(".gitignore", 0), ".gitignore");
    assert_eq!(numbered_export_filename(".gitignore", 1), ".gitignore(1)");
    assert_eq!(numbered_export_filename(".env.local", 1), ".env(1).local");

    // 超长文件名（255 UTF-16 码元）：追加序号后严格 <= 255 码元，优先保留扩展名与序号后缀。
    let long_with_ext = format!("{}.docx", "长".repeat(250));
    assert_eq!(utf16_unit_len(&long_with_ext), 255);
    let long_1 = numbered_export_filename(&long_with_ext, 1);
    let long_10 = numbered_export_filename(&long_with_ext, 10);
    assert_eq!(utf16_unit_len(&long_1), 255);
    assert_eq!(utf16_unit_len(&long_10), 255);
    assert!(long_1.ends_with("(1).docx"));
    assert!(long_10.ends_with("(10).docx"));

    // 超长截断边界出现尾部空格/点时必须自动裁剪。
    let long_space_dot = format!("{} .  tail.txt", "b".repeat(245));
    let trimmed_1 = numbered_export_filename(&long_space_dot, 1);
    assert!(utf16_unit_len(&trimmed_1) <= 255);
    assert_eq!(trimmed_1, format!("{}(1).txt", "b".repeat(245)));

    // 截断后恰好落入 Windows 保留设备名（"CONSOLE" 截断为 3 单元变成 "CON"）不得命中保留名。
    let long_ext_reserved = format!("CONSOLE.{}", "x".repeat(248)); // 7 + 1 + 248 = 256
    let safe_reserved = numbered_export_filename(&long_ext_reserved, 1);
    assert!(utf16_unit_len(&safe_reserved) <= 255);
    assert!(safe_reserved.starts_with("_CO(1)."));

    // 2. 端到端验证连续三次导出同一文件：在 exports/ 下生成 NOTES.TXT、NOTES(1).TXT、NOTES(2).TXT，
    //    不创建任何 `同名副本-*` 子目录，且复核包定位与核验全部通过。
    let paths = AppPaths::discover();
    let demo_dd = paths.evidence_dir.join("demo.dd");
    assert!(demo_dd.is_file(), "缺少测试镜像 demo.dd");

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut case = Case::create(
        tmp.path(),
        "DUP-EXP-001",
        "测试取证员",
        "同名序号导出与复核包定位测试",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create case");
    case.load_image(&demo_dd, None, None, None).expect("load demo.dd");
    let inv = case.scan_partitions(None, None, None).expect("scan partitions");
    let notes = inv
        .iter()
        .find(|e| e.path == "NOTES.TXT")
        .expect("NOTES.TXT")
        .clone();

    let p0 = case.export(&notes, None).expect("export #1");
    let p1 = case.export(&notes, None).expect("export #2");
    let p2 = case.export(&notes, None).expect("export #3");

    let exports_dir = case.folder().join("exports");
    assert_eq!(p0.file_name().and_then(|s| s.to_str()), Some("NOTES.TXT"));
    assert_eq!(p1.file_name().and_then(|s| s.to_str()), Some("NOTES(1).TXT"));
    assert_eq!(p2.file_name().and_then(|s| s.to_str()), Some("NOTES(2).TXT"));
    assert_eq!(p0.parent(), Some(exports_dir.as_path()));
    assert_eq!(p1.parent(), Some(exports_dir.as_path()));
    assert_eq!(p2.parent(), Some(exports_dir.as_path()));

    // 确认 exports/ 目录下不存在任何子目录（不再产生 `同名副本-*` 文件夹）。
    let subdirs: Vec<_> = fs::read_dir(&exports_dir)
        .expect("read exports dir")
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .collect();
    assert!(subdirs.is_empty(), "不应创建任何子目录：{subdirs:?}");

    // 确认三份副本内容均完整保留、互不覆盖。
    let bytes0 = fs::read(&p0).expect("read p0");
    let bytes1 = fs::read(&p1).expect("read p1");
    let bytes2 = fs::read(&p2).expect("read p2");
    assert_eq!(bytes0, bytes1);
    assert_eq!(bytes1, bytes2);

    // 确认 `inspect_bundle_exports` 与 `resolve_export_path` 能准确定位带序号副本。
    let rows = inspect_bundle_exports(&case).expect("inspect bundle exports");
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r.exists));
    assert_eq!(rows[0].relative, "NOTES.TXT");
    assert_eq!(rows[1].relative, "NOTES(1).TXT");
    assert_eq!(rows[2].relative, "NOTES(2).TXT");

    // 确认即使案件记录中的路径前缀来自其他目录，仍能定位新版序号文件与历史 `同名副本-*` 文件。
    let moved_numbered = ExportRecord {
        path: r"D:\old_location\case_x\exports\NOTES(1).TXT".to_string(),
        ..case.data().exports[1].clone()
    };
    let (resolved_num, rel_num) =
        resolve_export_path(&case, &moved_numbered).expect("resolve moved numbered export");
    assert_eq!(rel_num, PathBuf::from("NOTES(1).TXT"));
    assert!(resolved_num.is_file());

    let legacy_dir = exports_dir.join("同名副本-legacy99");
    fs::create_dir(&legacy_dir).expect("create legacy dup dir");
    let legacy_file = legacy_dir.join("NOTES.TXT");
    fs::write(&legacy_file, &bytes0).expect("write legacy dup file");
    let legacy_rec = ExportRecord {
        path: r"D:\old_location\case_x\exports\同名副本-legacy99\NOTES.TXT".to_string(),
        ..case.data().exports[0].clone()
    };
    let (resolved_legacy, rel_legacy) =
        resolve_export_path(&case, &legacy_rec).expect("resolve legacy subdir export");
    assert_eq!(rel_legacy, PathBuf::from("同名副本-legacy99").join("NOTES.TXT"));
    assert!(resolved_legacy.is_file());

    // 构建复核包并用原生 `verify_bundle` 全量核验。
    let bundle = build_bundle(&mut case, &BuildBundleOptions::default(), None)
        .expect("build review bundle with numbered exports");
    assert_eq!(bundle.included_exports, 3);
    assert_eq!(bundle.omitted_exports, 0);
    verify_bundle(&bundle.bundle_path, Some(&bundle.sha256))
        .expect("verify review bundle with numbered exports");
    case.close();
}

/// 构造最小合成 NTFS 镜像辅助函数：写入引导扇区、$MFT 与若干测试 MFT 记录（含常规、已删除、压缩与 PNG）。
fn build_synthetic_ntfs_preview_image(
    active_text: &[u8],
    deleted_payload: &[u8],
    png_bytes: &[u8],
) -> Vec<u8> {
    fn encode_run(len: u64, lcn: u64) -> Vec<u8> {
        let len_b = len.to_le_bytes();
        let mut ln = 8;
        while ln > 1 && len_b[ln - 1] == 0 {
            ln -= 1;
        }
        let lcn_b = (lcn as i64).to_le_bytes();
        let mut on = 8;
        while on > 1 && lcn_b[on - 1] == 0 && (lcn_b[on - 2] & 0x80) == 0 {
            on -= 1;
        }
        let mut out = vec![((on as u8) << 4) | (ln as u8)];
        out.extend_from_slice(&len_b[..ln]);
        out.extend_from_slice(&lcn_b[..on]);
        out
    }

    fn resident_data(attr_id: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let val_off = 24usize;
        let total_len = (val_off + payload.len() + 7) & !7;
        let mut buf = vec![0u8; total_len];
        buf[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        buf[4..8].copy_from_slice(&(total_len as u32).to_le_bytes());
        buf[8] = 0; // 常驻属性
        buf[12..14].copy_from_slice(&flags.to_le_bytes());
        buf[14..16].copy_from_slice(&attr_id.to_le_bytes());
        buf[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        buf[20..22].copy_from_slice(&(val_off as u16).to_le_bytes());
        buf[val_off..val_off + payload.len()].copy_from_slice(payload);
        buf
    }

    fn non_resident_data(
        attr_id: u16,
        flags: u16,
        data_size: u64,
        cluster_count: u64,
        lcn: u64,
    ) -> Vec<u8> {
        let runlist = encode_run(cluster_count, lcn);
        let run_off = 64usize;
        let total_len = (run_off + runlist.len() + 1 + 7) & !7;
        let mut buf = vec![0u8; total_len];
        buf[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        buf[4..8].copy_from_slice(&(total_len as u32).to_le_bytes());
        buf[8] = 1; // 非常驻属性
        buf[12..14].copy_from_slice(&flags.to_le_bytes());
        buf[14..16].copy_from_slice(&attr_id.to_le_bytes());
        buf[16..24].copy_from_slice(&0u64.to_le_bytes()); // lowest_vcn
        buf[24..32].copy_from_slice(&(cluster_count.saturating_sub(1)).to_le_bytes()); // highest_vcn
        buf[32..34].copy_from_slice(&(run_off as u16).to_le_bytes());
        buf[40..48].copy_from_slice(&data_size.to_le_bytes());
        buf[48..56].copy_from_slice(&data_size.to_le_bytes());
        buf[56..64].copy_from_slice(&data_size.to_le_bytes());
        buf[run_off..run_off + runlist.len()].copy_from_slice(&runlist);
        buf[run_off + runlist.len()] = 0x00;
        buf
    }

    fn build_mft(in_use: bool, attrs: &[Vec<u8>]) -> [u8; 1024] {
        let mut rec = [0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&48u16.to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        rec[20..22].copy_from_slice(&56u16.to_le_bytes());
        rec[22..24].copy_from_slice(&(u16::from(in_use)).to_le_bytes());
        rec[28..32].copy_from_slice(&1024u32.to_le_bytes());
        let mut pos = 56usize;
        for a in attrs {
            rec[pos..pos + a.len()].copy_from_slice(a);
            pos += a.len();
        }
        rec[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        pos += 4;
        rec[24..28].copy_from_slice(&(pos as u32).to_le_bytes());
        // 写入有效 NTFS USA 修复序列
        let usn = [0x21u8, 0x43u8];
        let o0 = [rec[510], rec[511]];
        let o1 = [rec[1022], rec[1023]];
        rec[48..50].copy_from_slice(&usn);
        rec[50..52].copy_from_slice(&o0);
        rec[52..54].copy_from_slice(&o1);
        rec[510..512].copy_from_slice(&usn);
        rec[1022..1024].copy_from_slice(&usn);
        rec
    }

    let part_offset: u64 = 64;
    let part_base = (part_offset * 512) as usize;
    let cluster_size = 4096usize;
    let total_clusters = 32usize;
    let mft_lcn: u64 = 4;
    let mut img = vec![0u8; part_base + total_clusters * cluster_size];

    // NTFS 引导扇区
    let boot = &mut img[part_base..part_base + 512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = 8; // 8 扇区/簇 = 4096 字节
    boot[40..48].copy_from_slice(&((total_clusters * 8) as u64).to_le_bytes());
    boot[48..56].copy_from_slice(&mft_lcn.to_le_bytes());
    boot[64] = (-10i8) as u8; // 1024 字节 MFT 记录
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);

    let write_mft = |buf: &mut [u8], idx: usize, rec: &[u8; 1024]| {
        let off = part_base + (mft_lcn as usize) * cluster_size + idx * 1024;
        buf[off..off + 1024].copy_from_slice(rec);
    };

    // 记录 0：$MFT（占用 LCN 4..8，共 4 簇 = 16 条 MFT 记录）
    write_mft(
        &mut img,
        0,
        &build_mft(true, &[non_resident_data(1, 0, 4 * cluster_size as u64, 4, mft_lcn)]),
    );
    // 记录 5：现存小体积常驻文本文件
    write_mft(&mut img, 5, &build_mft(true, &[resident_data(1, 0, active_text)]));
    // 记录 6：已删除非常驻 NTFS 文件（存放于 LCN 10..12）
    let del_clusters = deleted_payload.len().div_ceil(cluster_size) as u64;
    let del_off = part_base + 10 * cluster_size;
    img[del_off..del_off + deleted_payload.len()].copy_from_slice(deleted_payload);
    write_mft(
        &mut img,
        6,
        &build_mft(
            false,
            &[non_resident_data(1, 0, deleted_payload.len() as u64, del_clusters, 10)],
        ),
    );
    // 记录 7：现存小 PNG 图片（非常驻，存放于 LCN 14）
    let png_clusters = png_bytes.len().div_ceil(cluster_size).max(1) as u64;
    let png_off = part_base + 14 * cluster_size;
    img[png_off..png_off + png_bytes.len()].copy_from_slice(png_bytes);
    write_mft(
        &mut img,
        7,
        &build_mft(
            true,
            &[non_resident_data(1, 0, png_bytes.len() as u64, png_clusters, 14)],
        ),
    );
    // 记录 8：带压缩标志（0x0001）的 NTFS 文件，必须触发回退至路由 3
    write_mft(
        &mut img,
        8,
        &build_mft(true, &[non_resident_data(1, 0x0001, 4096, 1, 16)]),
    );

    img
}

#[test]
fn preview_direct_volume_routing_for_small_and_deleted_ntfs_plus_route3_truncation_cap() {
    let paths = AppPaths::discover();
    let demo_dd = paths.evidence_dir.join("demo.dd");
    assert!(demo_dd.is_file(), "缺少测试镜像 demo.dd");
    let tsk = TskCli::discover(None).expect("发现内置 TSK");

    let tmp = tempfile::tempdir().expect("tempdir");
    // 构造一个不含任何 TSK 可执行文件的目录：若成功打开会话，则证明 100% 走了进程内直读而非 icat。
    let empty_bin = tmp.path().join("no_tsk_bin");
    fs::create_dir(&empty_bin).expect("create empty_bin");
    let broken_tsk = TskCli::from_bin_dir(empty_bin);

    // 1. 小体积常规 FAT 文件（< 8 MiB）现在应直接命中路由 2（VolumeReader），零 icat 子进程。
    let demo_entries = tsk
        .list_entries(&demo_dd, 2048, true, None, "", None)
        .expect("list demo.dd");
    let readme = demo_entries
        .iter()
        .find(|e| e.path == "README.TXT" && !e.deleted)
        .expect("README.TXT")
        .clone();
    assert!(readme.size < 8 * 1024 * 1024);

    let mut fat_sess =
        PreviewSession::open(&demo_dd, &readme, Some(&broken_tsk)).expect("小 FAT 文件直读应成功");
    assert_eq!(fat_sess.backend_name(), "volume");
    assert!(!fat_sess.is_truncated());
    assert_eq!(fat_sess.readable_size(), readme.size);
    let fat_page = fat_sess
        .read_page(0, 4096, PreviewEncoding::Utf8)
        .expect("read fat page");
    assert!(!fat_page.truncated);
    assert!(fat_page.text.contains("TraceDesk"));
    // 未截断时序列化 JSON 不应额外输出 `truncated` 键，保持对外结构完全兼容。
    let fat_page_json = serde_json::to_value(&fat_page).expect("serialize page");
    assert!(fat_page_json.get("truncated").is_none());

    // 2. 0 字节空文件走 empty 路由，无需打开卷读取器或调用 icat。
    let zero_entry = make_entry("EMPTY.TXT", 2048, "99", 0, false, false);
    let mut zero_sess =
        PreviewSession::open(&demo_dd, &zero_entry, Some(&broken_tsk)).expect("空文件预览应成功");
    assert_eq!(zero_sess.backend_name(), "empty");
    assert!(!zero_sess.is_truncated());
    assert_eq!(zero_sess.readable_size(), 0);
    let zero_page = zero_sess
        .read_page(0, 4096, PreviewEncoding::Utf8)
        .expect("read zero page");
    assert_eq!(zero_page.total_pages, 1);
    assert!(zero_page.text.is_empty());

    // 3. 合成 NTFS 镜像：普通小文件、已删除非常驻 NTFS 文件与小 PNG 均优先命中路由 2 直读；
    //    带压缩标志的 NTFS 文件则自动失败并无缝回退至路由 3。
    let active_text = b"NTFS active resident small file for direct preview!";
    let mut deleted_payload = Vec::with_capacity(5000);
    for i in 0..5000usize {
        deleted_payload.push(b'A' + (i % 26) as u8);
    }
    #[cfg(feature = "image-preview")]
    let png_bytes = {
        let mut out = Vec::new();
        let buf: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_pixel(12, 8, Rgba([40, 120, 210, 255]));
        buf.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    };
    #[cfg(not(feature = "image-preview"))]
    let png_bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    let ntfs_img_path = tmp.path().join("synthetic_ntfs.dd");
    fs::write(
        &ntfs_img_path,
        build_synthetic_ntfs_preview_image(active_text, &deleted_payload, &png_bytes),
    )
    .expect("write synthetic ntfs");

    let ntfs_active = InventoryEntry {
        filesystem: "NTFS".to_string(),
        ..make_entry("ACTIVE.TXT", 64, "5-128-1", active_text.len() as u64, false, false)
    };
    let mut active_sess = PreviewSession::open(&ntfs_img_path, &ntfs_active, Some(&broken_tsk))
        .expect("NTFS 常驻小文件应命中直读");
    assert_eq!(active_sess.backend_name(), "volume");
    assert_eq!(
        active_sess.read_at(0, active_text.len()).unwrap(),
        active_text
    );

    let ntfs_deleted = InventoryEntry {
        mode: "-/r---------".to_string(),
        filesystem: "NTFS".to_string(),
        ..make_entry(
            "DELETED_NTFS.TXT",
            64,
            "6-128-1",
            deleted_payload.len() as u64,
            false,
            true,
        )
    };
    let mut del_ntfs_sess = PreviewSession::open(&ntfs_img_path, &ntfs_deleted, Some(&broken_tsk))
        .expect("已删除 NTFS 文件应命中 VolumeReader 直读");
    assert_eq!(del_ntfs_sess.backend_name(), "volume");
    assert!(!del_ntfs_sess.is_truncated());
    assert_eq!(
        del_ntfs_sess.read_at(0, deleted_payload.len()).unwrap(),
        deleted_payload
    );

    #[cfg(feature = "image-preview")]
    {
        let ntfs_png = InventoryEntry {
            filesystem: "NTFS".to_string(),
            ..make_entry("TINY.PNG", 64, "7-128-1", png_bytes.len() as u64, false, false)
        };
        let img_res = preview_entry_image(&ntfs_img_path, &ntfs_png, Some(&broken_tsk))
            .expect("NTFS PNG 走路由 2 直读图片预览应成功");
        assert!(img_res.ok);
        assert_eq!(img_res.width, Some(12));
        assert_eq!(img_res.height, Some(8));

        // 超过 32 MiB 的图片预览应在触发路由 3 icat 之前提前返回超限提示。
        let huge_png = InventoryEntry {
            filesystem: "NTFS".to_string(),
            ..make_entry("HUGE.PNG", 64, "8-128-1", 40 * 1024 * 1024, false, false)
        };
        let huge_res = preview_entry_image(&ntfs_img_path, &huge_png, Some(&broken_tsk))
            .expect("超大图片应提前返回超限结果而不调用 icat");
        assert!(!huge_res.ok);
        assert!(huge_res.error.unwrap().contains("32 MiB"));
    }

    // 压缩 NTFS 文件无法直读，应回退到路由 3（因使用 broken_tsk 会返回 TskNotFound，证明回退生效）。
    let ntfs_compressed = InventoryEntry {
        filesystem: "NTFS".to_string(),
        ..make_entry("COMPRESSED.BIN", 64, "8-128-1", 4096, false, false)
    };
    let fallback_err = PreviewSession::open(&ntfs_img_path, &ntfs_compressed, Some(&broken_tsk))
        .err()
        .expect("压缩 NTFS 文件应回退至路由 3 并因缺少 icat 返回错误");
    assert!(
        fallback_err.to_string().contains("icat") || fallback_err.to_string().contains("Sleuth Kit"),
        "unexpected error: {fallback_err}"
    );

    // 4. 路由 3（`icat` 写 `%TEMP%`）回退与安全截断上限保护：
    //    复制 demo.dd 并伪造一个已删除 FAT 条目（VolumeReader 对已删除 FAT 必然回退至路由 3）。
    let mutated_fat = tmp.path().join("demo_deleted_preview.dd");
    fs::copy(&demo_dd, &mutated_fat).expect("copy demo.dd");
    let volume_base = 2048u64 * 512;
    let root_dir = volume_base + (1 + 2 * 64) * 512;
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&mutated_fat)
            .unwrap();
        let mut rec = [0u8; 32];
        f.seek(SeekFrom::Start(root_dir)).unwrap();
        f.read_exact(&mut rec).unwrap();
        rec[0] = 0xE5;
        f.seek(SeekFrom::Start(root_dir + 5 * 32)).unwrap();
        f.write_all(&rec).unwrap();
    }

    let del_entries = tsk
        .list_entries(&mutated_fat, 2048, true, None, "", None)
        .expect("list mutated_fat");
    let del_readme = del_entries
        .iter()
        .find(|e| e.deleted && e.path.ends_with("EADME.TXT") && e.size == readme.size)
        .expect("deleted README.TXT")
        .clone();

    let expected_bytes = fat_sess.read_at(0, readme.size as usize).unwrap();

    // 4a. 缓存上限 >= 文件大小：走路由 3 且不截断。
    let mut full_cached =
        PreviewSession::open_with_cache_limit(&mutated_fat, &del_readme, Some(&tsk), del_readme.size)
            .expect("路由 3 精确等于上限时应完整读取");
    assert_eq!(full_cached.backend_name(), "icat_cache");
    assert!(!full_cached.is_truncated());
    assert_eq!(full_cached.readable_size(), del_readme.size);
    assert_eq!(
        full_cached.read_at(0, del_readme.size as usize).unwrap(),
        expected_bytes
    );

    // 4b. 缓存上限 < 文件大小（模拟 GB 级大文件触发 64 MiB 保护）：流式截断并标注截断状态。
    let cap: u64 = 32;
    let mut capped =
        PreviewSession::open_with_cache_limit(&mutated_fat, &del_readme, Some(&tsk), cap)
            .expect("路由 3 触发安全上限时应优雅截断而非报错");
    assert_eq!(capped.backend_name(), "icat_cache");
    assert!(capped.is_truncated());
    assert_eq!(capped.readable_size(), cap);
    assert!(capped.read_note().contains("截断"));
    assert_eq!(capped.read_at(0, 128).unwrap(), &expected_bytes[..cap as usize]);

    let capped_page = capped
        .read_page(0, 4096, PreviewEncoding::Utf8)
        .expect("read capped page");
    assert!(capped_page.truncated);
    assert_eq!(capped_page.readable_size, cap);
    assert_eq!(capped_page.recorded_size, del_readme.size);
    assert!(capped_page.read_note.contains("截断"));
    let capped_json = serde_json::to_value(&capped_page).expect("serialize capped page");
    assert_eq!(capped_json.get("truncated"), Some(&json!(true)));
}

#[test]
fn audit_head_atomic_sync_and_case_json_bak_generation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut case = Case::create(
        tmp.path(),
        "BAK-001",
        "取证员B",
        "原子刷盘与容灾备份测试",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create case");

    let case_dir = case.folder().to_path_buf();
    let case_json = case_dir.join("case.json");
    let case_bak = case_dir.join("case.json.bak");
    // 首次新建案件时 `case.json` 之前不存在，因此尚未生成 `.bak`。
    assert!(!case_bak.exists());
    let first_case_json = fs::read_to_string(&case_json).expect("read first case.json");

    // 再次保存 `case.json`：必须在覆盖前原子生成包含上一版有效内容的 `case.json.bak`。
    case.save(false, None).expect("second save");
    assert!(case_bak.is_file(), "覆盖 case.json 后应自动生成 case.json.bak");
    let bak_content = fs::read_to_string(&case_bak).expect("read case.json.bak");
    assert_eq!(bak_content, first_case_json);

    // 连续写入足够多的审计记录（使 `audit.jsonl` 超过 64 KiB 块边界），
    // 验证流式 `audit_fast_check` 与 `write_bytes_atomic_sync` 均稳定且无临时文件残留。
    let pad = "X".repeat(2048);
    for i in 0..45u64 {
        let mut details = Map::new();
        details.insert("idx".to_string(), json!(i));
        details.insert("payload".to_string(), json!(pad));
        case.log("FILE_FILTER", "*.log", "成功", details)
            .expect("log large audit entry");
    }
    let audit_len = fs::metadata(case_dir.join("audit.jsonl")).unwrap().len();
    assert!(
        audit_len > 64 * 1024,
        "audit.jsonl 应超过 64 KiB 以覆盖多块流式 SHA-256 校验（当前 {audit_len} 字节）"
    );

    let raw_head = fs::read(case_dir.join("audit.head")).expect("read audit.head");
    assert_eq!(raw_head.len(), 64);
    assert!(!raw_head.contains(&b'\n'));
    assert!(!raw_head.contains(&b'\r'));

    // 目录中不应残留任何 `.tmp` / `.head.tmp` / `.bak.tmp` 临时文件。
    for entry in fs::read_dir(&case_dir).expect("read case dir") {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            !name.ends_with(".tmp"),
            "案件目录不应残留临时文件：{name}"
        );
    }

    let records = case.check_audit().expect("verify full audit chain");
    assert_eq!(records.len(), 46);
    case.close();
}

#[test]
fn legacy_single_file_inventory_case_opens_and_migrates_cleanly() {
    use tracedesk_core::write_inventory_gz;

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut case = Case::create(
        tmp.path(),
        "LEGACY-GZ-001",
        "取证员C",
        "旧版单文件清单兼容测试",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create case");
    let folder = case.folder().to_path_buf();
    case.close();

    // 构造旧版单文件 `inventory-<32hex>.jsonl.gz` 与对应的 `case.json`。
    let legacy_name = "inventory-0123456789abcdef0123456789abcdef.jsonl.gz";
    let entries = vec![
        make_entry("A.TXT", 2048, "10", 64, false, false),
        make_entry("B.TXT", 40960, "20", 128, false, false),
    ];
    write_inventory_gz(&folder.join(legacy_name), &entries, None).expect("write legacy gz");

    let meta_path = folder.join("case.json");
    let mut raw: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    let obj = raw.as_object_mut().unwrap();
    obj.remove("inventory");
    obj.remove("inventory_files");
    obj.insert("inventory_file".to_string(), json!(legacy_name));
    obj.insert("inventory_count".to_string(), json!(2));
    save_json_atomic(&meta_path, &raw).expect("save legacy single-file case.json");

    // 1. 打开旧版单文件案件：100% 兼容且不破坏旧文件。
    let mut reopened = Case::open(&folder, None, AuditOrigin::Manual).expect("open legacy case");
    assert_eq!(reopened.data().inventory.len(), 2);
    assert_eq!(reopened.data().inventory[0].path, "A.TXT");
    assert_eq!(reopened.data().inventory[1].path, "B.TXT");
    let legacy_key = reopened.inventory_cache_key();
    assert_eq!(legacy_key.len(), 16);

    // 仅保存元数据时仍保留旧版单文件引用。
    reopened.save(false, None).expect("save metadata only");
    assert!(folder.join(legacy_name).is_file());
    let mid_doc: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert_eq!(mid_doc["inventory_file"], json!(legacy_name));

    // 2. 触发全量清单重写：升级为分分区 `inventory_files` 并自动清理旧单文件。
    reopened.save(true, None).expect("migrate to partitioned");
    assert!(
        !folder.join(legacy_name).exists(),
        "迁移为分分区清单后应清理旧单文件"
    );
    assert_eq!(reopened.inventory_files().len(), 2);
    assert!(reopened.inventory_files().contains_key(&2048));
    assert!(reopened.inventory_files().contains_key(&40960));
    let new_key = reopened.inventory_cache_key();
    assert_ne!(legacy_key, new_key);
    reopened.close();

    // 3. 重新打开分分区案件（触发 rayon 并行解压），清单与指纹完全一致。
    let mut reopened2 = Case::open(&folder, None, AuditOrigin::Manual).expect("reopen partitioned");
    assert_eq!(reopened2.data().inventory, entries);
    assert_eq!(reopened2.inventory_cache_key(), new_key);
    reopened2.close();
}

#[test]
fn partitioned_inventory_single_partition_scan_preserves_untouched_partition_file_and_mtime() {
    use std::time::{Duration, SystemTime};
    use tracedesk_core::write_inventory_gz;

    let paths = AppPaths::discover();
    let demo_dd = paths.evidence_dir.join("demo.dd");
    assert!(demo_dd.is_file(), "demo.dd missing at {}", demo_dd.display());

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut case = Case::create(
        tmp.path(),
        "PART-INC-001",
        "取证员D",
        "单分区增量扫描不重压未变更分区测试",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create case");
    case.load_image(&demo_dd, None, None, None)
        .expect("load demo.dd");
    let scanned = case
        .scan_partitions(None, None, None)
        .expect("initial scan_partitions");
    assert_eq!(scanned.len(), 13);
    assert_eq!(case.inventory_files().len(), 1);
    let orig_p2048_file = case.inventory_files()[&2048].clone();
    let folder = case.folder().to_path_buf();
    case.close();

    // 在 `case.json` 中注入一个已存在的第二分区清单文件（offset = 99999），模拟多分区已扫描案件，
    // 并将其 mtime 设为 60 秒前以精确验证增量扫描不会重写或触碰该分区文件。
    let untouched_offset: u64 = 99999;
    let untouched_name = "inventory-p99999-abcdef0123456789abcdef0123456789.jsonl.gz";
    let untouched_entries = vec![
        make_entry("PART2/ALPHA.TXT", untouched_offset, "501", 42, false, false),
        make_entry("PART2/BETA.TXT", untouched_offset, "502", 84, false, false),
    ];
    let untouched_path = folder.join(untouched_name);
    write_inventory_gz(&untouched_path, &untouched_entries, None).expect("write part2 gz");
    let past_mtime = SystemTime::now() - Duration::from_secs(60);
    {
        let f = OpenOptions::new().write(true).open(&untouched_path).unwrap();
        f.set_modified(past_mtime).unwrap();
    }
    let expected_untouched_mtime = fs::metadata(&untouched_path).unwrap().modified().unwrap();

    let meta_path = folder.join("case.json");
    let mut doc: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    doc["inventory_files"][untouched_offset.to_string()] = json!(untouched_name);
    doc["inventory_count"] = json!(15);
    doc["partition_scans"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "offset": untouched_offset,
            "status": "ready",
            "count": 2
        }));
    save_json_atomic(&meta_path, &doc).expect("save 2-partition case.json");

    // 重新打开：rayon 并行加载 2 个分区共 15 条记录，且按 offset 升序拼接。
    let mut case2 = Case::open(&folder, None, AuditOrigin::Manual).expect("open 2-part case");
    assert_eq!(case2.data().inventory.len(), 15);
    assert_eq!(case2.inventory_files().len(), 2);
    assert_eq!(case2.inventory_files()[&2048], orig_p2048_file);
    assert_eq!(case2.inventory_files()[&untouched_offset], untouched_name);

    // 仅增量扫描分区 2048：
    // - 分区 2048 应写出新的 `.jsonl.gz` 并删除旧的 `orig_p2048_file`；
    // - 未变更分区 99999 的文件名、mtime 与全部条目必须保持 100% 不变！
    let rescan = case2.scan_partition(2048, None, None).expect("scan_partition 2048");
    assert_eq!(rescan.len(), 13);
    assert_eq!(case2.data().inventory.len(), 15);
    let new_p2048_file = case2.inventory_files()[&2048].clone();
    assert_ne!(new_p2048_file, orig_p2048_file);
    assert!(!folder.join(&orig_p2048_file).exists(), "旧 2048 分区文件应被清理");
    assert!(folder.join(&new_p2048_file).is_file());

    assert_eq!(case2.inventory_files()[&untouched_offset], untouched_name);
    let actual_untouched_mtime = fs::metadata(&untouched_path).unwrap().modified().unwrap();
    assert_eq!(
        actual_untouched_mtime, expected_untouched_mtime,
        "未变更分区的 .jsonl.gz 文件 mtime 必须保持不变"
    );
    let expected_inventory = case2.data().inventory.clone();
    let expected_cache_key = case2.inventory_cache_key();
    case2.close();

    // 再次重开验证并行加载完整一致。
    let mut case3 = Case::open(&folder, None, AuditOrigin::Manual).expect("reopen after inc scan");
    assert_eq!(case3.data().inventory, expected_inventory);
    assert_eq!(case3.inventory_cache_key(), expected_cache_key);
    case3.close();

    // 路径穿越防御：篡改 `inventory_files` 指向父目录文件时必须被 `CorruptCase` 拦截。
    let mut bad_doc: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    bad_doc["inventory_files"]["2048"] = json!("../escape.jsonl.gz");
    save_json_atomic(&meta_path, &bad_doc).expect("write traversal case.json");
    let err = Case::open(&folder, None, AuditOrigin::Manual).err().expect("reject traversal");
    assert!(matches!(err, CoreError::CorruptCase(_)));
}

#[test]
fn rebind_image_path_enforces_sha256_and_restores_all_operations() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tracedesk_core::action_title;

    let paths = AppPaths::discover();
    let demo_dd = paths.evidence_dir.join("demo.dd");
    assert!(demo_dd.is_file(), "demo.dd missing at {}", demo_dd.display());

    let cases_root = tempfile::tempdir().expect("cases root");
    let external_dir = tempfile::tempdir().expect("external evidence dir");

    let mut case = Case::create(
        cases_root.path(),
        "REBIND-001",
        "取证员E",
        "重绑源镜像强制 SHA-256 校验测试",
        None,
        None,
        AuditOrigin::Manual,
    )
    .expect("create case");
    assert!(!case.evidence_exists());
    // 未加载镜像时调用重绑必须返回 InvalidInput。
    assert!(matches!(
        case.rebind_image_path(&demo_dd, None, None),
        Err(CoreError::InvalidInput(_))
    ));

    // 拷贝一份作为原始加载镜像，以便后续模拟原路径失效/移动。
    let orig_img = external_dir.path().join("original_demo.dd");
    fs::copy(&demo_dd, &orig_img).expect("copy orig demo");
    case.load_image(&orig_img, None, None, None)
        .expect("load original image");
    assert!(case.evidence_exists());
    let orig_sha = case
        .data()
        .evidence
        .as_ref()
        .and_then(|e| e.sha256.clone())
        .expect("fixed sha256");
    let inventory = case
        .scan_partitions(None, None, None)
        .expect("scan partitions");
    let readme = inventory
        .iter()
        .find(|e| e.path == "README.TXT" && !e.deleted)
        .expect("README.TXT")
        .clone();
    let orig_bound_path = case.image_path().expect("orig path");

    // 1. 案件库内部路径必须被隔离边界拒绝。
    let inside_img = cases_root.path().join("inside_copy.dd");
    fs::copy(&demo_dd, &inside_img).expect("copy inside");
    assert!(matches!(
        case.rebind_image_path(&inside_img, None, None),
        Err(CoreError::InvalidInput(_))
    ));
    assert_eq!(case.image_path().unwrap(), orig_bound_path);

    // 2. 同大小但内容被篡改 1 字节的镜像：必须返回 IntegrityFailed，写入失败审计且绝不修改原路径！
    let tampered_img = external_dir.path().join("tampered_demo.dd");
    let mut tampered_bytes = fs::read(&demo_dd).expect("read demo.dd");
    tampered_bytes[4096] ^= 0xFF;
    fs::write(&tampered_img, &tampered_bytes).expect("write tampered");

    let err_tampered = case
        .rebind_image_path(&tampered_img, None, None)
        .expect_err("tampered image must be rejected");
    assert!(
        matches!(err_tampered, CoreError::IntegrityFailed(_)),
        "expected IntegrityFailed, got: {err_tampered:?}"
    );
    assert_eq!(
        case.image_path().unwrap(),
        orig_bound_path,
        "校验失败绝不能修改原镜像路径"
    );

    // 3. 不同大小的镜像：同样必须返回 IntegrityFailed 且不修改原路径。
    let different_size_img = external_dir.path().join("small_other.dd");
    fs::write(&different_size_img, vec![0u8; 4096]).expect("write other");
    assert!(matches!(
        case.rebind_image_path(&different_size_img, None, None),
        Err(CoreError::IntegrityFailed(_))
    ));
    assert_eq!(case.image_path().unwrap(), orig_bound_path);

    // 验证失败审计已落盘且操作标题已注册。
    assert_eq!(action_title("IMAGE_REBIND"), "重绑源镜像路径");
    let records_after_fail = case.check_audit().expect("check audit after fail");
    let fail_rebinds: Vec<_> = records_after_fail
        .iter()
        .filter(|r| r.action == "IMAGE_REBIND" && r.result == "失败")
        .collect();
    assert_eq!(fail_rebinds.len(), 2);

    // 4. 模拟原镜像被移动到新路径（关闭释放句柄后移动，再重新打开检查 evidence_exists == false）。
    let case_dir = case.folder().to_path_buf();
    case.close();
    let moved_img = external_dir.path().join("relocated").join("moved_demo.dd");
    fs::create_dir_all(moved_img.parent().unwrap()).expect("mkdir relocated");
    fs::rename(&orig_img, &moved_img).expect("move orig_img");

    let mut reopened = Case::open(&case_dir, None, AuditOrigin::Manual).expect("reopen case");
    assert!(
        !reopened.evidence_exists(),
        "原镜像已移动后 evidence_exists 应返回 false"
    );

    // 5. 合法重绑到新路径：验证进度回调、返回值、审计记录以及后续校验/预览/导出全部正常！
    let max_seen = AtomicU64::new(0);
    let progress_cb = |done: u64, _total: u64| {
        max_seen.fetch_max(done, Ordering::Relaxed);
    };
    let rebind_res = reopened
        .rebind_image_path(&moved_img, None, Some(&progress_cb))
        .expect("rebind to valid moved image");
    assert_eq!(rebind_res.sha256, orig_sha);
    assert!(rebind_res.verified);
    assert_eq!(rebind_res.segment_count, 1);
    assert_eq!(rebind_res.old_image, orig_bound_path.to_string_lossy());
    assert!(rebind_res.new_image.ends_with("moved_demo.dd"));
    assert!(max_seen.load(Ordering::Relaxed) > 0, "应触发流式哈希进度回调");
    assert!(reopened.evidence_exists());
    assert!(reopened.is_session_verified());

    // 重绑后：完整性校验、预览、导出均应正常工作。
    assert!(
        reopened
            .verify_integrity(None, None, None)
            .expect("verify after rebind")
    );
    let new_img_path = reopened.image_path().expect("new image path");
    let mut sess = PreviewSession::open(&new_img_path, &readme, None).expect("preview after rebind");
    let page = sess
        .read_page(0, 4096, PreviewEncoding::Utf8)
        .expect("read preview page");
    assert!(page.text.contains("TraceDesk"));
    drop(sess);

    let exported = reopened.export(&readme, None).expect("export after rebind");
    assert!(exported.is_file());

    // 审计链包含 IMAGE_REBIND 成功记录且携带关键字段。
    let final_records = reopened.check_audit().expect("final audit check");
    let ok_rebind = final_records
        .iter()
        .find(|r| r.action == "IMAGE_REBIND" && r.result == "成功")
        .expect("IMAGE_REBIND success record");
    assert_eq!(ok_rebind.details["sha256"], json!(orig_sha));
    assert_eq!(ok_rebind.details["verified"], json!(true));
    assert_eq!(
        ok_rebind.details["old_image"],
        json!(orig_bound_path.to_string_lossy())
    );
    assert_eq!(ok_rebind.details["new_image"], json!(rebind_res.new_image));
    reopened.close();

    // 重新打开后持久化路径保持有效。
    let mut reopened2 = Case::open(&case_dir, None, AuditOrigin::Manual).expect("reopen after rebind");
    assert!(reopened2.evidence_exists());
    assert_eq!(
        reopened2.image_path().unwrap().to_string_lossy(),
        rebind_res.new_image
    );
    reopened2.check_audit().expect("reopen audit check");
    reopened2.close();
}
