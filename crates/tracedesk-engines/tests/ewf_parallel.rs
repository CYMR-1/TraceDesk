use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

use adler2::adler32_slice;
use flate2::Compression;
use flate2::write::ZlibEncoder;

use tracedesk_engines::ewf::{
    self, EWF1_MAGIC, EwfIndex, EwfMediaReader, acquisition_info, discover_segments,
    hash_logical_ewf1_parallel, hash_logical_stream, hash_physical_segments,
};
use tracedesk_engines::{
    EngineError, EntryReadPlan, MediaReader, TskCli, VolumeReader, open_media, sha256_file,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn write_section_desc(buf: &mut Vec<u8>, name: &str, next_offset: u64, section_size: u64) {
    let mut desc = [0u8; 76];
    let nb = name.as_bytes();
    desc[..nb.len()].copy_from_slice(nb);
    desc[16..24].copy_from_slice(&next_offset.to_le_bytes());
    desc[24..32].copy_from_slice(&section_size.to_le_bytes());
    let crc = adler32_slice(&desc[..72]);
    desc[72..76].copy_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&desc);
}

fn make_volume_body(
    chunk_count: u32,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    sector_count: u64,
) -> Vec<u8> {
    let mut body = vec![0u8; 1052];
    body[0] = 0x01; // 固定磁盘介质类型
    body[4..8].copy_from_slice(&chunk_count.to_le_bytes());
    body[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
    body[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
    body[16..24].copy_from_slice(&sector_count.to_le_bytes());
    body[36] = 0x01; // 镜像介质标志
    body[52] = 0x01; // 快速压缩级别
    let crc = adler32_slice(&body[..1048]);
    body[1048..1052].copy_from_slice(&crc.to_le_bytes());
    body
}

fn make_header_body() -> Vec<u8> {
    let text = "1\nmain\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\n\t\t\t\t\t1.0\tWindows\t0\t0\t0\n\n";
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(text.as_bytes()).unwrap();
    enc.finish().unwrap()
}

/// 从 `raw` 构建真正的、兼容 libewf 的多分段 EWF1 镜像（`.E01`、`.E02` 等）。
/// 交替写入压缩块（zlib）与非压缩块（原始数据 + 小端 Adler-32），以覆盖两条解码路径。
fn build_ewf1_segments(
    dir: &Path,
    stem: &str,
    raw: &[u8],
    chunks_per_segment: usize,
    corrupt_primary_table_in_seg0: bool,
) -> Vec<PathBuf> {
    let bytes_per_sector: u32 = 512;
    let sectors_per_chunk: u32 = 64;
    let chunk_size = (bytes_per_sector * sectors_per_chunk) as usize; // 32768 字节
    assert_eq!(raw.len() % bytes_per_sector as usize, 0);
    let sector_count = (raw.len() / bytes_per_sector as usize) as u64;
    let total_chunks = raw.len().div_ceil(chunk_size);
    let vol_body = make_volume_body(
        total_chunks as u32,
        sectors_per_chunk,
        bytes_per_sector,
        sector_count,
    );
    let hdr_body = make_header_body();

    let num_segments = total_chunks.div_ceil(chunks_per_segment);
    let mut paths = Vec::with_capacity(num_segments);

    for seg in 0..num_segments {
        let seg_num = (seg + 1) as u16;
        let path = dir.join(format!("{stem}.E{seg_num:02}"));
        let start_chunk = seg * chunks_per_segment;
        let end_chunk = ((seg + 1) * chunks_per_segment).min(total_chunks);
        let is_last = seg + 1 == num_segments;

        let mut buf = Vec::new();
        // 13 字节 EWF1 文件头。
        buf.extend_from_slice(&EWF1_MAGIC);
        buf.push(0x01);
        buf.extend_from_slice(&seg_num.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());

        if seg == 0 {
            // header 节
            let hdr_sec_size = (76 + hdr_body.len()) as u64;
            let next = buf.len() as u64 + hdr_sec_size;
            write_section_desc(&mut buf, "header", next, hdr_sec_size);
            buf.extend_from_slice(&hdr_body);

            // volume 节
            let vol_sec_size = (76 + vol_body.len()) as u64;
            let next = buf.len() as u64 + vol_sec_size;
            write_section_desc(&mut buf, "volume", next, vol_sec_size);
            buf.extend_from_slice(&vol_body);
        }

        // 编码当前分段内的数据块。
        let sectors_sec_offset = buf.len() as u64;
        let sectors_data_start = sectors_sec_offset + 76;
        let mut sectors_payload = Vec::new();
        let mut table_entries = Vec::with_capacity(end_chunk - start_chunk);

        for c in start_chunk..end_chunk {
            let chunk_start = c * chunk_size;
            let chunk_end = (chunk_start + chunk_size).min(raw.len());
            let mut plain = vec![0u8; chunk_size];
            plain[..chunk_end - chunk_start].copy_from_slice(&raw[chunk_start..chunk_end]);

            let rel_off = sectors_data_start + sectors_payload.len() as u64;
            assert!(rel_off < 0x8000_0000);

            // 交替编码：偶数块使用 zlib 压缩，奇数块保持非压缩并附带小端 Adler-32。
            if c % 2 == 0 {
                let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
                enc.write_all(&plain).unwrap();
                let z = enc.finish().unwrap();
                sectors_payload.extend_from_slice(&z);
                table_entries.push((rel_off as u32) | 0x8000_0000);
            } else {
                let crc = adler32_slice(&plain);
                sectors_payload.extend_from_slice(&plain);
                sectors_payload.extend_from_slice(&crc.to_le_bytes());
                table_entries.push(rel_off as u32);
            }
        }

        let sectors_sec_size = (76 + sectors_payload.len()) as u64;
        let table_offset = sectors_sec_offset + sectors_sec_size;
        write_section_desc(&mut buf, "sectors", table_offset, sectors_sec_size);
        buf.extend_from_slice(&sectors_payload);

        // 构建 table 节体（24 字节头 + N*4 条目 + 4 字节尾部 Adler-32）。
        let mut table_body = Vec::with_capacity(24 + table_entries.len() * 4 + 4);
        let mut thdr = [0u8; 24];
        thdr[0..4].copy_from_slice(&(table_entries.len() as u32).to_le_bytes());
        // base_offset 设为 0
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
        let table2_offset = table_offset + table_sec_size;
        write_section_desc(&mut buf, "table", table2_offset, table_sec_size);
        if corrupt_primary_table_in_seg0 && seg == 0 {
            let mut bad_table = table_body.clone();
            let last = bad_table.len() - 1;
            bad_table[last] ^= 0xff; // 破坏尾部校验和
            buf.extend_from_slice(&bad_table);
        } else {
            buf.extend_from_slice(&table_body);
        }

        // table2 备份节
        let end_sec_offset = table2_offset + table_sec_size;
        write_section_desc(&mut buf, "table2", end_sec_offset, table_sec_size);
        buf.extend_from_slice(&table_body);

        // next / done 终止节（遵循 EWF1 规范，next_offset 指向自身）
        let term_name = if is_last { "done" } else { "next" };
        let term_off = buf.len() as u64;
        write_section_desc(&mut buf, term_name, term_off, 76);

        let mut f = File::create(&path).unwrap();
        f.write_all(&buf).unwrap();
        paths.push(path);
    }

    paths
}

#[test]
fn test_ewf_segment_discovery_and_acquisition_info() {
    let tmp = tempfile::tempdir().unwrap();
    let e01 = tmp.path().join("disk.E01");
    let e02 = tmp.path().join("disk.E02");
    fs::write(&e01, b"stub1").unwrap();
    fs::write(&e02, b"stub2").unwrap();
    // 同目录随附的文本文件必须被忽略。
    fs::write(tmp.path().join("disk.TXT"), b"notes").unwrap();

    let segs = discover_segments(&e01).unwrap();
    assert_eq!(segs.len(), 2);
    assert_eq!(segs[0].file_name().unwrap(), "disk.E01");
    assert_eq!(segs[1].file_name().unwrap(), "disk.E02");

    // 必须拒绝非首段 `.E02`。
    let err = discover_segments(&e02).unwrap_err();
    assert!(matches!(err, EngineError::InvalidArgument(_)));

    // 必须拒绝缺失中间分段的情况。
    fs::remove_file(&e02).unwrap();
    fs::write(tmp.path().join("disk.E03"), b"stub3").unwrap();
    let err = discover_segments(&e01).unwrap_err();
    assert!(matches!(err, EngineError::Ewf(_)));

    // `.E99` 之后的字母续段（`.EAA`）：测试无效文件头检测及有效魔数接受。
    let tmp_alpha = tempfile::tempdir().unwrap();
    for i in 1..=99 {
        fs::write(tmp_alpha.path().join(format!("big.E{i:02}")), b"seg").unwrap();
    }
    let eaa = tmp_alpha.path().join("big.EAA");
    fs::write(&eaa, b"NOT_EVF1_MAGIC").unwrap();
    let err = discover_segments(&tmp_alpha.path().join("big.E01")).unwrap_err();
    assert!(err.to_string().contains("字母续段"));

    fs::write(&eaa, EWF1_MAGIC).unwrap();
    let segs100 = discover_segments(&tmp_alpha.path().join("big.E01")).unwrap();
    assert_eq!(segs100.len(), 100);
    assert_eq!(segs100[99].file_name().unwrap(), "big.EAA");

    // Guymager `.info` 解析测试
    let info_path = e01.with_extension("info");
    fs::write(
        &info_path,
        "GUYMAGER ACQUISITION INFO FILE\n\
         Version              : 0.8.13-2\n\
         Acquisition started  : 2026-11-21 10:00:00 (UTC)\n\
         SHA256 hash          : 83029884B25C65F5CD8E94415C9A4E6A60F762459130CF96EAC1E626890C70E8\n",
    )
    .unwrap();
    let info = acquisition_info(&e01);
    assert_eq!(
        info.get("expected_sha256").map(String::as_str),
        Some("83029884b25c65f5cd8e94415c9a4e6a60f762459130cf96eac1e626890c70e8")
    );
    assert_eq!(info.get("tool").map(String::as_str), Some("Guymager 0.8.13-2"));
    assert!(info.get("acquired").unwrap().contains("2026-11-21 10:00:00"));
    assert!(info.get("source").unwrap().contains("disk.info"));
}

#[test]
fn test_ewf1_parallel_decode_random_read_and_tsk_interop() {
    let demo_path = repo_root().join("evidence").join("demo.dd");
    let raw = fs::read(&demo_path).expect("read demo.dd");
    let expected_sha = sha256_file(&demo_path, None, None).unwrap();

    let tmp = tempfile::tempdir().unwrap();
    // 288 个 32 KiB 块切分为 3 个分段（每段 96 块），混排压缩块与非压缩块。
    let segs = build_ewf1_segments(tmp.path(), "demo_ewf", &raw, 96, false);
    assert_eq!(segs.len(), 3);
    let e01 = &segs[0];

    // 1. 验证官方 Sleuth Kit（libewf.dll）可正常识别我们构造的 EWF1 镜像。
    let tsk = TskCli::discover(None).expect("discover TSK");
    let (tsk_logical_size, tsk_sector_size) = tsk.img_stat_ewf(e01).expect("img_stat_ewf");
    assert_eq!(tsk_logical_size, raw.len() as u64);
    assert_eq!(tsk_sector_size, 512);

    let sector0 = tsk.read_ewf_sector(e01, 0).expect("read_ewf_sector 0");
    assert_eq!(sector0, &raw[..512]);

    let sector2048 = tsk.read_ewf_sector(e01, 2048).expect("read_ewf_sector 2048");
    assert_eq!(sector2048, &raw[2048 * 512..2049 * 512]);

    let (_, parts) = tsk.inspect(e01).expect("inspect e01");
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].offset, 2048);

    // 2. 并行计算物理分段哈希，并严格保持原始分段顺序。
    let phys_progress = AtomicU64::new(0);
    let total_phys: u64 = segs.iter().map(|p| fs::metadata(p).unwrap().len()).sum();
    let phys_cb = |done: u64, total: u64| {
        assert_eq!(total, total_phys);
        phys_progress.store(done, Ordering::Relaxed);
    };
    let digests = hash_physical_segments(&segs, None, Some(&phys_cb)).unwrap();
    assert_eq!(digests.len(), 3);
    for (i, d) in digests.iter().enumerate() {
        assert_eq!(d.name, segs[i].file_name().unwrap().to_str().unwrap());
        assert_eq!(d.sha256, sha256_file(&segs[i], None, None).unwrap());
    }
    assert_eq!(phys_progress.load(Ordering::Relaxed), total_phys);

    // 3. 纯 Rust 多核并行计算 EWF1 逻辑流 SHA-256。
    let log_progress = AtomicU64::new(0);
    let log_cb = |done: u64, total: u64| {
        assert_eq!(total, raw.len() as u64);
        log_progress.store(done, Ordering::Relaxed);
    };
    let parallel_sha =
        hash_logical_ewf1_parallel(e01, raw.len() as u64, None, Some(&log_cb)).unwrap();
    assert_eq!(parallel_sha, expected_sha);
    assert_eq!(log_progress.load(Ordering::Relaxed), raw.len() as u64);

    let stream_sha = hash_logical_stream(&tsk, e01, raw.len() as u64, None, None).unwrap();
    assert_eq!(stream_sha, expected_sha);

    // 取消信号必须直接向上传播，不得回退到 img_cat。
    let cancel = AtomicBool::new(true);
    assert!(
        hash_logical_stream(&tsk, e01, raw.len() as u64, Some(&cancel), None)
            .unwrap_err()
            .is_cancelled()
    );

    // 4. 线程安全 EwfMediaReader 跨块与跨分段并发随机读取测试。
    let media: Arc<dyn MediaReader> = open_media(e01).expect("open_media EWF1");
    assert_eq!(media.media_size(), raw.len() as u64);

    let raw_arc = Arc::new(raw);
    let mut handles = Vec::new();
    for t in 0..8usize {
        let m = Arc::clone(&media);
        let r = Arc::clone(&raw_arc);
        handles.push(thread::spawn(move || {
            let offsets = [
                0usize,
                32_760,           // 跨越第 0 块 -> 第 1 块（压缩块 -> 非压缩块）
                96 * 32_768 - 17, // 跨越分段 .E01 -> .E02
                192 * 32_768 - 9, // 跨越分段 .E02 -> .E03
                2048 * 512 + t * 4093,
                r.len() - 1024,
            ];
            for off in offsets {
                let len = (4096 + t * 137).min(r.len() - off);
                let mut buf = vec![0u8; len];
                m.read_exact_at(off as u64, &mut buf).unwrap();
                assert_eq!(buf, &r[off..off + len]);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // 5. 基于 EWF1 的 VolumeReader 读取 FAT16 文件，结果与 TSK icat 完全一致。
    let entries = tsk.list_entries(e01, 2048, true, None, "", None).unwrap();
    let mut volume = VolumeReader::open(e01).expect("VolumeReader over EWF1");
    for name in ["README.TXT", "PAYLOAD.BIN", "DOCS/CASE.TXT"] {
        let entry = entries.iter().find(|e| e.path == name).unwrap();
        assert!(matches!(
            volume.plan_entry(entry, b"TraceDesk"),
            EntryReadPlan::Direct { .. }
        ));
        let direct = volume
            .read_entry_at(entry, 0, entry.size as usize)
            .unwrap();
        let mut from_icat = Vec::new();
        tsk.stream_entry(e01, entry, None, |b| {
            from_icat.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(direct, from_icat, "EWF1 VolumeReader mismatch on {name}");
    }
}

#[test]
fn test_ewf1_table2_recovery_and_corruption_detection() {
    let raw: Vec<u8> = (0usize..(128 * 1024))
        .map(|i| (i.wrapping_mul(31) & 0xff) as u8)
        .collect();
    let tmp = tempfile::tempdir().unwrap();

    // 破坏 0 号分段中主 `table` 的校验和；解析器必须能通过 `table2` 透明恢复。
    let segs = build_ewf1_segments(tmp.path(), "backup", &raw, 2, true);
    let idx = EwfIndex::open(&segs[0]).expect("recover via table2");
    assert_eq!(idx.chunks.len(), 4);

    let reader = EwfMediaReader::open(&segs[0]).unwrap();
    let mut out = vec![0u8; raw.len()];
    reader.read_exact_at(0, &mut out).unwrap();
    assert_eq!(out, raw);

    // 破坏一个非压缩块载荷 -> 必须检出 Adler-32 校验不匹配。
    let bad_chunk_loc = idx.chunks[1]; // 第 1 块为非压缩块
    assert!(!bad_chunk_loc.compressed);
    let seg_path = &segs[bad_chunk_loc.segment_idx as usize];
    let mut seg_bytes = fs::read(seg_path).unwrap();
    seg_bytes[bad_chunk_loc.file_offset as usize] ^= 0x55;
    fs::write(seg_path, &seg_bytes).unwrap();

    let err = ewf::hash_logical_ewf1_parallel(&segs[0], raw.len() as u64, None, None).unwrap_err();
    assert!(matches!(err, EngineError::Ewf(_)));
}

#[test]
fn test_ewf_hash_logical_stream_auto_fallback_to_img_cat() {
    let demo_path = repo_root().join("evidence").join("demo.dd");
    let raw = fs::read(&demo_path).unwrap();
    let expected_sha = sha256_file(&demo_path, None, None).unwrap();

    // 构造一个在 `done` 前插入自定义节的合法 EWF1：libewf 会忽略未知节，
    // 而严格的纯 Rust EWF1 解析器会拒绝未知节类型并回退到 `img_cat`。
    let tmp = tempfile::tempdir().unwrap();
    let segs = build_ewf1_segments(tmp.path(), "fallback", &raw, 512, false);
    let e01 = &segs[0];
    let mut data = fs::read(e01).unwrap();
    let done_off = data.len() - 76;
    data.truncate(done_off);
    let custom_next = (done_off + 76) as u64;
    write_section_desc(&mut data, "custom", custom_next, 76);
    let new_done_off = data.len() as u64;
    write_section_desc(&mut data, "done", new_done_off, 76);
    fs::write(e01, &data).unwrap();

    // 严格的纯 Rust EWF1 解析器必须拒绝未知节类型。
    assert!(EwfIndex::open(e01).is_err());

    // `hash_logical_stream` 必须透明回退至 `TskCli::img_cat` 并得到一致的 SHA-256。
    let tsk = TskCli::discover(None).unwrap();
    let fallback_sha = hash_logical_stream(&tsk, e01, raw.len() as u64, None, None).unwrap();
    assert_eq!(fallback_sha, expected_sha);
}
