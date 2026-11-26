use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use tracedesk_engines::tsk::{
    decode_fls_line, parse_bodyfile_line, parse_fls_bodyfile_reader, parse_mmls_output,
};
use tracedesk_engines::{
    EngineError, EntryReadPlan, TskCli, TskCommand, VolumeReader, decode_acp_strict,
    map_fat_regions, sha256_file,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[derive(Deserialize)]
struct DemoManifest {
    image_sha256: String,
    files: HashMap<String, ManifestFile>,
}

#[derive(Deserialize)]
struct ManifestFile {
    size: u64,
    sha256: String,
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn test_tsk_whitelist_and_parsers() {
    for ok_cmd in ["mmls", "fsstat", "fls", "icat", "img_stat", "img_cat"] {
        assert!(TskCommand::parse_whitelisted(ok_cmd).is_ok());
    }
    for bad_cmd in ["cmd", "powershell", "tsk_recover", "istat", "sh", ""] {
        let err = TskCommand::parse_whitelisted(bad_cmd).unwrap_err();
        assert!(matches!(err, EngineError::TskCommandDenied(_)));
    }

    // 必须同时兼容识别 DOS（`000:000`）与 GPT（`000`）槽位格式。
    for slot in ["000", "000:000"] {
        let sample = format!(
            "000: Meta 0000000000 0000000033 0000000034 Table\n\
             001: ------- 0000000034 0000002047 0000002014 Unallocated\n\
             002: {slot} 0000002048 0000018431 0000016384 FAT16\n\
             003: 000:001 0000018432 0000020000 0000001569 Extended (0x05)\n"
        );
        let parts = parse_mmls_output(&sample);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].offset, 2048);
        assert_eq!(parts[0].description, "FAT16");
    }

    // bodyfile 解析器测试：路径含竖线、deleted 与 deleted-realloc 区分，以及文件名本身以 " (deleted)" 结尾的普通文件。
    let normal = parse_bodyfile_line(
        "0|/DIR/a|b (deleted)|15|r/rrwxrwxrwx|0|0|128|1|2|3|4",
        2048,
        false,
    )
    .unwrap();
    assert_eq!(normal.path, "DIR/a|b (deleted)");
    assert!(!normal.deleted);
    assert!(!normal.reallocated);
    assert_eq!(normal.size, 128);

    let del = parse_bodyfile_line(
        "0|/OLD.TXT (deleted)|20|r/rrwxrwxrwx|0|0|50|0|0|0|0",
        2048,
        true,
    )
    .unwrap();
    assert_eq!(del.path, "OLD.TXT");
    assert!(del.deleted);
    assert!(!del.reallocated);

    let realloc = parse_bodyfile_line(
        "0|/REUSED.TXT (deleted-realloc)|21|-/rrwxrwxrwx|0|0|64|0|0|0|0",
        2048,
        true,
    )
    .unwrap();
    assert_eq!(realloc.path, "REUSED.TXT");
    assert!(realloc.deleted);
    assert!(realloc.reallocated);
}

#[test]
fn test_demo_dd_full_pipeline_and_volume_reader_parity() {
    let root = repo_root();
    let demo = root.join("evidence").join("demo.dd");
    let manifest: DemoManifest = serde_json::from_str(
        &fs::read_to_string(root.join("evidence").join("demo.manifest.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(sha256_file(&demo, None, None).unwrap(), manifest.image_sha256);

    let tsk = TskCli::discover(None).expect("discover bundled TSK");
    assert!(!tsk.version().unwrap().is_empty());

    // 1. 分区探测（inspect）
    let (layout, partitions) = tsk.inspect(&demo).expect("inspect demo.dd");
    assert!(layout.contains("DOS Partition Table"));
    assert_eq!(partitions.len(), 1);
    assert_eq!(partitions[0].offset, 2048);
    assert!(partitions[0].description.contains("FAT16"));

    // 2. fsstat 与 fsstat_to_file 校验
    let fsstat_full = tsk.fsstat(&demo, 2048, false).expect("fsstat full");
    assert!(fsstat_full.contains("File System Type: FAT16"));
    let fsstat_type = tsk.fsstat(&demo, 2048, true).expect("fsstat type");
    assert_eq!(fsstat_type.trim().to_ascii_uppercase(), "FAT16");

    let tmp = tempfile::tempdir().unwrap();
    let fsstat_file = tmp.path().join("fsstat.txt");
    tsk.fsstat_to_file(&demo, 2048, &fsstat_file).unwrap();
    assert_eq!(fs::read_to_string(&fsstat_file).unwrap(), fsstat_full);

    // 3. list_entries（并发执行 -u 与 -d）
    let mut entries = tsk
        .list_entries(&demo, 2048, true, None, "", None)
        .expect("list_entries");
    assert_eq!(entries.len(), 10);

    // 校验 README.TXT 的 UTC mtime 与黄金基线一致（2026-09-01 08:05 UTC）。
    let readme = entries.iter().find(|e| e.path == "README.TXT").unwrap();
    assert_eq!(readme.mtime, 1788249900);

    // 校验带 dir_inode 与 prefix_path 的单目录列举。
    let docs_dir = entries.iter().find(|e| e.path == "DOCS").unwrap();
    assert!(docs_dir.directory);
    let docs_children = tsk
        .list_entries(&demo, 2048, false, Some(&docs_dir.inode), "DOCS", None)
        .expect("list DOCS");
    assert!(docs_children.iter().any(|e| e.path == "DOCS/CASE.TXT"));

    // 预先取消的 list_entries 应立即返回 Cancelled。
    let cancel = AtomicBool::new(true);
    assert!(
        tsk.list_entries(&demo, 2048, true, None, "", Some(&cancel))
            .unwrap_err()
            .is_cancelled()
    );

    // 4. map_fat_regions 结果与黄金用例逐字节一致。
    let regions = map_fat_regions(&demo, 2048, &fsstat_full, &mut entries, None)
        .expect("map_fat_regions");
    assert_eq!(regions.len(), 3);
    assert_eq!(regions[0].path, "(根目录)");
    assert_eq!(regions[0].inode, "2");
    assert_eq!(regions[0].size, 16_384);
    assert_eq!(regions[1].path, "空余空间（未分配簇）");
    assert_eq!(regions[1].size, 8_302_080);
    assert_eq!(regions[1].extents, Some(vec![(1_135_104, 8_302_080)]));
    assert_eq!(regions[2].path, "闲置空间（已分配未关联簇）");
    assert_eq!(regions[2].size, 0);
    assert_eq!(regions[2].extents, Some(vec![]));

    // 5. 校验清单中每个文件经由 export_file、stream_entry 和 VolumeReader 读取的逐字节一致性。
    let mut volume = VolumeReader::open(&demo).expect("VolumeReader::open");
    for (rel_path, expected) in &manifest.files {
        let entry = entries
            .iter()
            .find(|e| &e.path == rel_path)
            .unwrap_or_else(|| panic!("missing manifest entry {rel_path}"));
        assert_eq!(entry.size, expected.size);

        // export_file 导出校验
        let exported = tmp.path().join(rel_path.replace('/', "_"));
        tsk.export_file(&demo, entry.offset, &entry.inode, entry.size, &exported)
            .unwrap();
        assert_eq!(sha256_file(&exported, None, None).unwrap(), expected.sha256);

        // stream_entry 流式读取校验
        let mut streamed = Vec::new();
        let (written, note) = tsk
            .stream_entry(&demo, entry, None, |chunk| {
                streamed.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(written, expected.size);
        assert!(note.is_empty());
        assert_eq!(sha256_hex(&streamed), expected.sha256);

        // VolumeReader 的 plan_entry 与全量读取校验
        match volume.plan_entry(entry, b"TraceDesk") {
            EntryReadPlan::Direct {
                intervals,
                total_size,
            } => {
                assert_eq!(total_size, expected.size);
                assert_eq!(intervals.len(), 1);
                assert_eq!(intervals[0].start, 0);
                assert_eq!(intervals[0].end, expected.size);
            }
            EntryReadPlan::FallbackToIcat => panic!("expected Direct plan for {rel_path}"),
        }

        let direct = volume
            .read_entry_at(entry, 0, entry.size as usize)
            .expect("VolumeReader full read");
        assert_eq!(direct, streamed, "byte mismatch for {rel_path}");

        // 跨簇边界的随机切片读取（尤其是 PAYLOAD.BIN：1536 字节 = 3 簇）
        if entry.size > 20 {
            let start = entry.size / 3;
            let len = ((entry.size - start) / 2).max(1) as usize;
            let slice = volume
                .read_entry_at(entry, start, len)
                .expect("VolumeReader slice read");
            assert_eq!(slice, &streamed[start as usize..start as usize + len]);
        }
    }
}

#[test]
fn test_unpartitioned_demo_volume_fallback_offset_zero() {
    let vol = repo_root().join("evidence").join("demo_volume.dd");
    assert!(vol.is_file());
    let tsk = TskCli::discover(None).unwrap();
    let (layout, parts) = tsk.inspect(&vol).expect("inspect demo_volume.dd");
    assert!(layout.contains("偏移 0"));
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].offset, 0);

    let entries = tsk.list_entries(&vol, 0, true, None, "", None).unwrap();
    assert!(entries.iter().any(|e| e.path == "DOCS/CASE.TXT"));
}

#[test]
fn test_deleted_fat_entries_and_idle_clusters() {
    let root = repo_root();
    let demo = root.join("evidence").join("demo.dd");
    let manifest: DemoManifest = serde_json::from_str(
        &fs::read_to_string(root.join("evidence").join("demo.manifest.json")).unwrap(),
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let mutated = tmp.path().join("demo_deleted.dd");
    fs::copy(&demo, &mutated).unwrap();

    // 对照 tests/core/test_workflow.py::test_deleted_records_and_fat_regions 构造测试镜像
    let volume_base = 2048u64 * 512;
    let root_dir = volume_base + (1 + 2 * 64) * 512;
    let data_base = root_dir + 32 * 512;
    {
        let mut f = OpenOptions::new().read(true).write(true).open(&mutated).unwrap();
        let mut rec = [0u8; 32];
        f.seek(SeekFrom::Start(root_dir)).unwrap();
        f.read_exact(&mut rec).unwrap();
        rec[0] = 0xe5;

        let mut empty = rec;
        empty[26..32].fill(0);

        f.seek(SeekFrom::Start(root_dir + 5 * 32)).unwrap();
        f.write_all(&empty).unwrap();
        f.write_all(&rec).unwrap();

        for fat in [1u64, 65u64] {
            f.seek(SeekFrom::Start(volume_base + fat * 512 + 20 * 2)).unwrap();
            f.write_all(&[0xff, 0xff]).unwrap();
        }
    }

    let tsk = TskCli::discover(None).unwrap();
    let fsstat = tsk.fsstat(&mutated, 2048, false).unwrap();
    let mut entries = tsk.list_entries(&mutated, 2048, true, None, "", None).unwrap();

    // 校验严格顺序：所有现存条目（-u）必须排在所有已删除条目（-d）之前。
    let first_del = entries.iter().position(|e| e.deleted).expect("has deleted");
    assert!(entries[..first_del].iter().all(|e| !e.deleted));
    assert!(entries[first_del..].iter().all(|e| e.deleted));

    let regions = map_fat_regions(&mutated, 2048, &fsstat, &mut entries, None).unwrap();

    let deleted: Vec<_> = entries
        .iter()
        .filter(|e| e.deleted && e.path.ends_with("EADME.TXT"))
        .collect();
    assert_eq!(deleted.len(), 2);
    assert_eq!(deleted[0].start_cluster_allocated, None);
    assert_eq!(deleted[1].start_cluster_allocated, Some(true));

    // 在 VolumeReader 中，FAT 已删除条目必须回退至 icat。
    let mut vol = VolumeReader::open(&mutated).unwrap();
    assert_eq!(
        vol.plan_entry(deleted[1], b"TraceDesk"),
        EntryReadPlan::FallbackToIcat
    );

    // 通过 stream_entry 恢复的数据应与 README.TXT 的 SHA-256 一致（0 字节空文件返回 0 字节）。
    let (n0, _) = tsk.stream_entry(&mutated, deleted[0], None, |_| Ok(())).unwrap();
    assert_eq!(n0, 0);

    let mut recovered = Vec::new();
    let (n1, _) = tsk
        .stream_entry(&mutated, deleted[1], None, |b| {
            recovered.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(n1, manifest.files["README.TXT"].size);
    assert_eq!(sha256_hex(&recovered), manifest.files["README.TXT"].sha256);

    // 校验闲置空间与空余空间区间与预期磁盘偏移完全一致。
    let idle = regions
        .iter()
        .find(|r| r.path == "闲置空间（已分配未关联簇）")
        .unwrap();
    assert_eq!(idle.extents, Some(vec![(data_base + 18 * 512, 512)]));

    let free = regions
        .iter()
        .find(|r| r.path == "空余空间（未分配簇）")
        .unwrap();
    let free_extents = free.extents.as_ref().unwrap();
    assert_eq!(free_extents.len(), 2);
    assert_eq!(free.size, free_extents.iter().map(|(_, l)| *l).sum::<u64>());
}

#[test]
fn test_tsk_bin_dir_normalization_and_no_stray_dest_on_missing_tool() {
    // 发现到的 bin_dir 必须始终为绝对路径，且不含 Windows `\\?\` 原义前缀。
    let discovered = TskCli::discover(None).expect("discover TSK");
    assert!(discovered.bin_dir().is_absolute());
    assert!(
        !discovered
            .bin_dir()
            .to_string_lossy()
            .starts_with(r"\\?\")
    );

    // 当工具缺失时，`fsstat_to_file` 与 `export_file` 必须在创建 `dest` 之前失败。
    let tmp = tempfile::tempdir().unwrap();
    let empty_bin = tmp.path().join("empty_bin");
    fs::create_dir(&empty_bin).unwrap();
    let broken_tsk = TskCli::from_bin_dir(empty_bin);
    let demo = repo_root().join("evidence").join("demo.dd");

    let fsstat_dest = tmp.path().join("should_not_exist_fsstat.txt");
    assert!(broken_tsk.fsstat_to_file(&demo, 2048, &fsstat_dest).is_err());
    assert!(
        !fsstat_dest.exists(),
        "fsstat_to_file must not leave a 0-byte dest file when executable is missing"
    );

    let export_dest = tmp.path().join("should_not_exist_export.bin");
    assert!(
        broken_tsk
            .export_file(&demo, 2048, "3", 65, &export_dest)
            .is_err()
    );
    assert!(
        !export_dest.exists(),
        "export_file must not leave a 0-byte dest file when executable is missing"
    );
}

#[test]
fn test_fls_utf8_multilingual_emoji_decoding_and_malformed_line_tolerance() {
    // 1. 纯 ASCII 与 UTF-8 中文/日文/韩文/Emoji 文件名均应走零拷贝 UTF-8 快速路径，不触发有损解码。
    let utf8_samples = [
        "0|/证据材料/涉案报告_2026.docx|101-128-1|r/rrwxrwxrwx|0|0|2048|1700000000|1700000001|1700000002|1700000003",
        "0|/証拠フォルダ/テスト文書_日本語.txt|102-128-1|r/rrwxrwxrwx|0|0|512|1700000010|1700000011|1700000012|1700000013",
        "0|/증거자료/보고서_한국어.pdf|103-128-1|r/rrwxrwxrwx|0|0|4096|1700000020|1700000021|1700000022|1700000023",
        "0|/现场📸/🔥证据😀|含竖线.png|104-128-1|r/rrwxrwxrwx|0|0|8192|1700000030|1700000031|1700000032|1700000033",
    ];

    for line in &utf8_samples {
        let (decoded, used_lossy) = decode_fls_line(line.as_bytes());
        assert!(matches!(decoded, Cow::Borrowed(_)));
        assert!(!used_lossy);
        assert_eq!(decoded.as_ref(), *line);
    }

    // 2. 严格单行解析器 `parse_bodyfile_line` 必须保持原有边界校验：畸形行应返回 Err。
    assert!(parse_bodyfile_line("corrupted_no_pipes", 2048, false).is_err());
    assert!(
        parse_bodyfile_line(
            "0|/BAD_SIZE.TXT|105|r/r|0|0|not_a_num|0|0|0|0",
            2048,
            false
        )
        .is_err()
    );
    assert!(
        parse_bodyfile_line(
            "0|/BAD_TIME.TXT|106|r/r|0|0|10|abc|0|0|0",
            2048,
            false
        )
        .is_err()
    );

    // 3. 构造混合流：包含 UTF-8 多语种/Emoji 正常行、空行、多种格式异常行、非法字节序列行。
    let mut raw_stream: Vec<u8> = Vec::new();
    raw_stream.extend_from_slice(utf8_samples[0].as_bytes());
    raw_stream.extend_from_slice(b"\r\n");
    // 空行（应静默跳过，不计入异常行）
    raw_stream.extend_from_slice(b"\r\n");
    // 异常行 #1：字段数不足
    raw_stream.extend_from_slice(b"0|/BROKEN/MISSING_FIELDS|12|r/r\n");
    // UTF-8 日文行
    raw_stream.extend_from_slice(utf8_samples[1].as_bytes());
    raw_stream.push(b'\n');
    // 异常行 #2：文件大小非数字
    raw_stream.extend_from_slice(b"0|/BAD_SIZE.TXT|105|r/r|0|0|NaN|0|0|0|0\n");
    // UTF-8 韩文行
    raw_stream.extend_from_slice(utf8_samples[2].as_bytes());
    raw_stream.push(b'\n');
    // 异常行 #3：时间戳非整数
    raw_stream.extend_from_slice(b"0|/BAD_TS.TXT|106|r/r|0|0|10|0|bad|0|0\n");
    // UTF-8 Emoji + 含竖线文件名行
    raw_stream.extend_from_slice(utf8_samples[3].as_bytes());
    raw_stream.push(b'\n');

    // 非 UTF-8 原始字节行：在支持 CP_ACP 严格解码（如 CP936 GBK）时回退严格解码，
    // 在无效字节序列（如 0xFF 0xFE）时降级单行有损解码且不中断整盘解析。
    let mut non_utf8_line: Vec<u8> = Vec::new();
    non_utf8_line.extend_from_slice(b"0|/RAW_");
    non_utf8_line.extend_from_slice(&[0xFF, 0xFE]);
    non_utf8_line.extend_from_slice(b".bin|107|r/rrwxrwxrwx|0|0|77|1|2|3|4");
    let expect_lossy = decode_acp_strict(&non_utf8_line).is_err();
    raw_stream.extend_from_slice(&non_utf8_line);
    raw_stream.push(b'\n');

    let mut cursor = Cursor::new(raw_stream);
    let summary =
        parse_fls_bodyfile_reader(&mut cursor, 2048, false, None).expect("容错流式解析不应失败");

    assert_eq!(summary.skipped_lines, 3, "应精确跳过 3 条格式异常行");
    assert_eq!(
        summary.lossy_decoded_lines,
        usize::from(expect_lossy),
        "无效编码行是否触发有损降级应与当前系统代码页行为一致"
    );
    assert_eq!(summary.entries.len(), 5, "所有有效条目必须完整保留");
    assert_eq!(summary.entries[0].path, "证据材料/涉案报告_2026.docx");
    assert_eq!(summary.entries[1].path, "証拠フォルダ/テスト文書_日本語.txt");
    assert_eq!(summary.entries[2].path, "증거자료/보고서_한국어.pdf");
    assert_eq!(summary.entries[3].path, "现场📸/🔥证据😀|含竖线.png");
    assert_eq!(summary.entries[4].inode, "107");
    assert_eq!(summary.entries[4].size, 77);
    assert!(summary.entries[4].path.starts_with("RAW_"));
    assert!(summary.entries[4].path.ends_with(".bin"));

    // 4. 在 CP936/GBK（中文 Windows）下验证非 UTF-8 的合法 GBK 字节回退到 CP_ACP 严格解码。
    let gbk_line: Vec<u8> = b"0|/\xD6\xD0\xCE\xC4.txt|108|r/rrwxrwxrwx|0|0|12|1|2|3|4".to_vec();
    assert!(std::str::from_utf8(&gbk_line).is_err());
    if let Ok(expected_acp) = decode_acp_strict(&gbk_line) {
        let (decoded, used_lossy) = decode_fls_line(&gbk_line);
        assert!(!used_lossy, "合法 CP_ACP 字节不应触发有损降级");
        assert_eq!(decoded.as_ref(), expected_acp);
    }

    // 5. 协作式取消标志生效时应立即返回 Cancelled。
    let cancel = AtomicBool::new(true);
    let mut cancel_cursor = Cursor::new(utf8_samples[0].as_bytes());
    let err = parse_fls_bodyfile_reader(&mut cancel_cursor, 2048, false, Some(&cancel))
        .unwrap_err();
    assert!(err.is_cancelled());
}
