use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::Instant;

use tracedesk_engines::{
    ByteInterval, EntryReadPlan, InventoryEntry, MediaReader, VolumeReader, map_fat_regions,
};

/// 用于确定性合成 NTFS 测试的内存版 MediaReader。
struct MemoryMedia(Vec<u8>);

impl MediaReader for MemoryMedia {
    fn media_size(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> tracedesk_engines::EngineResult<()> {
        let start = offset as usize;
        let end = start + buf.len();
        if end > self.0.len() {
            return Err(tracedesk_engines::EngineError::RandomRead("out of bounds".into()));
        }
        buf.copy_from_slice(&self.0[start..end]);
        Ok(())
    }
}

#[test]
fn test_fat32_500k_clusters_performance_and_accuracy() {
    // 复现 scratch/baseline/run_baseline.py 中的 500,000 簇非稀疏 FAT32 基准测试
    // （Python 基线：11,563 ms；Rust 要求：< 500 ms）。
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("fat32_500k.dd");

    let clusters: u64 = 500_000;
    let sector_size: u64 = 512;
    let reserved: u64 = 32;
    let copies: u64 = 1;
    let fat_sectors: u64 = ((clusters + 2) * 4).div_ceil(sector_size);
    let data_sector: u64 = reserved + copies * fat_sectors;
    let total_sectors: u64 = data_sector + clusters;
    let total_bytes: u64 = total_sectors * sector_size;

    // 构建 FAT32 引导扇区。
    let mut boot = [0u8; 512];
    boot[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    boot[11..13].copy_from_slice(&(sector_size as u16).to_le_bytes());
    boot[13] = 1; // 每簇 1 个扇区
    boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    boot[16] = copies as u8;
    boot[32..36].copy_from_slice(&(total_sectors as u32).to_le_bytes());
    boot[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
    boot[44..48].copy_from_slice(&2u32.to_le_bytes()); // 根目录起始簇 root_cluster = 2
    boot[82..90].copy_from_slice(b"FAT32   ");
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);

    // 填充 500,000 条非稀疏混合 FAT32 表项：
    // - 簇 2：根目录（EOC）
    // - 簇 3..=1002（1000 个簇）：由 inode 3 持有的现存文件簇链
    // - 其余簇 1003..500002 按交替模式排布：
    //   每 3n 为空余（0），每 3n+1 为闲置 EOC（0x0fffffff），每 3n+2 为空余（0），
    //   并在簇 2000 处放置一个坏簇标记（0x0ffffff7）。
    let mut fat = vec![0u8; (fat_sectors * sector_size) as usize];
    let set_fat = |fat: &mut [u8], c: u64, val: u32| {
        let off = (c as usize) * 4;
        fat[off..off + 4].copy_from_slice(&val.to_le_bytes());
    };
    set_fat(&mut fat, 0, 0x0fff_fff8);
    set_fat(&mut fat, 1, 0x0fff_ffff);
    set_fat(&mut fat, 2, 0x0fff_ffff); // 根目录簇 2
    for c in 3..1002 {
        set_fat(&mut fat, c, (c + 1) as u32);
    }
    set_fat(&mut fat, 1002, 0x0fff_ffff);

    let mut expected_free_clusters: u64 = 0;
    let mut expected_idle_clusters: u64 = 0;
    for c in 1003..(clusters + 2) {
        if c == 2000 {
            set_fat(&mut fat, c, 0x0fff_fff7); // 坏簇 -> 既不计入空余也不计入闲置
        } else if c % 3 == 1 {
            set_fat(&mut fat, c, 0x0fff_ffff); // 已分配但未关联 -> 闲置
            expected_idle_clusters += 1;
        } else {
            set_fat(&mut fat, c, 0); // 空余
            expected_free_clusters += 1;
        }
    }

    // 在簇 2 写入根目录项（槽位 0 = inode 3，槽位 1 = inode 4）。
    let mut dir_sector = [0u8; 512];
    // 槽位 0：起始于簇 3 的现存文件
    dir_sector[0..11].copy_from_slice(b"ACTIVE  BIN");
    dir_sector[11] = 0x20;
    dir_sector[26..28].copy_from_slice(&3u16.to_le_bytes());
    dir_sector[28..32].copy_from_slice(&(1000 * 512u32).to_le_bytes());
    // 槽位 1：指向已分配簇 1006 的已删除文件（1006 % 3 == 1 -> 已分配）
    dir_sector[32] = 0xe5;
    dir_sector[33..43].copy_from_slice(b"ELETED BIN");
    dir_sector[43] = 0x20;
    dir_sector[58..60].copy_from_slice(&1006u16.to_le_bytes());
    dir_sector[60..64].copy_from_slice(&512u32.to_le_bytes());

    {
        let mut f = File::create(&img_path).unwrap();
        f.set_len(total_bytes).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&boot).unwrap();
        f.seek(SeekFrom::Start(reserved * sector_size)).unwrap();
        f.write_all(&fat).unwrap();
        f.seek(SeekFrom::Start(data_sector * sector_size)).unwrap();
        f.write_all(&dir_sector).unwrap();
        f.flush().unwrap();
    }

    let mut entries = vec![
        InventoryEntry {
            path: "ACTIVE.BIN".to_string(),
            inode: "3".to_string(),
            mode: "r/rrwxrwxrwx".to_string(),
            size: 1000 * 512,
            deleted: false,
            reallocated: false,
            atime: 0,
            mtime: 0,
            ctime: 0,
            crtime: 0,
            directory: false,
            offset: 0,
            filesystem: "FAT32".to_string(),
            start_cluster_allocated: None,
            extents: None,
        },
        InventoryEntry {
            path: "_ELETED.BIN".to_string(),
            inode: "4".to_string(),
            mode: "r/rrwxrwxrwx".to_string(),
            size: 512,
            deleted: true,
            reallocated: false,
            atime: 0,
            mtime: 0,
            ctime: 0,
            crtime: 0,
            directory: false,
            offset: 0,
            filesystem: "FAT32".to_string(),
            start_cluster_allocated: None,
            extents: None,
        },
    ];

    let fsstat = "File System Type: FAT32\n";
    let t0 = Instant::now();
    let regions = map_fat_regions(&img_path, 0, fsstat, &mut entries, None).unwrap();
    let elapsed = t0.elapsed();

    eprintln!(
        "[bench] 500k non-sparse FAT32 map_fat_regions elapsed: {:.2} ms",
        elapsed.as_secs_f64() * 1000.0
    );
    assert!(
        elapsed.as_millis() < 500,
        "500k FAT32 mapping took {} ms, expected < 500 ms",
        elapsed.as_millis()
    );

    assert_eq!(entries[1].start_cluster_allocated, Some(true));
    assert_eq!(regions[0].path, "(根目录)");
    assert_eq!(regions[0].size, 512);
    assert_eq!(regions[1].path, "空余空间（未分配簇）");
    assert_eq!(regions[1].size, expected_free_clusters * 512);
    assert_eq!(regions[2].path, "闲置空间（已分配未关联簇）");
    assert_eq!(regions[2].size, expected_idle_clusters * 512);
}

// ============================================================================
// 合成 NTFS 构建器与原生 VolumeReader 测试
// ============================================================================

fn encode_data_run(len: u64, lcn_delta: Option<i64>) -> Vec<u8> {
    let mut len_bytes = Vec::new();
    let mut v = len;
    while v > 0 {
        len_bytes.push((v & 0xff) as u8);
        v >>= 8;
    }
    if len_bytes.is_empty() {
        len_bytes.push(0);
    }

    let off_bytes = match lcn_delta {
        None => Vec::new(),
        Some(delta) => {
            let full = delta.to_le_bytes();
            let mut n = 8;
            while n > 1 {
                let sign_bit = (full[n - 2] & 0x80) != 0;
                if (delta >= 0 && full[n - 1] == 0x00 && !sign_bit)
                    || (delta < 0 && full[n - 1] == 0xff && sign_bit)
                {
                    n -= 1;
                } else {
                    break;
                }
            }
            full[..n].to_vec()
        }
    };

    let header = ((off_bytes.len() as u8) << 4) | (len_bytes.len() as u8);
    let mut out = vec![header];
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(&off_bytes);
    out
}

fn make_resident_attr(
    attr_type: u32,
    attr_id: u16,
    flags: u16,
    name: &str,
    payload: &[u8],
) -> Vec<u8> {
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    let name_offset = 24usize;
    let val_offset = (name_offset + name_utf16.len() * 2 + 7) & !7;
    let total_len = (val_offset + payload.len() + 7) & !7;
    let mut buf = vec![0u8; total_len];
    buf[0..4].copy_from_slice(&attr_type.to_le_bytes());
    buf[4..8].copy_from_slice(&(total_len as u32).to_le_bytes());
    buf[8] = 0; // 常驻属性
    buf[9] = name_utf16.len() as u8;
    buf[10..12].copy_from_slice(&(name_offset as u16).to_le_bytes());
    buf[12..14].copy_from_slice(&flags.to_le_bytes());
    buf[14..16].copy_from_slice(&attr_id.to_le_bytes());
    buf[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    buf[20..22].copy_from_slice(&(val_offset as u16).to_le_bytes());
    for (i, u) in name_utf16.iter().enumerate() {
        buf[name_offset + i * 2..name_offset + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    buf[val_offset..val_offset + payload.len()].copy_from_slice(payload);
    buf
}

#[allow(clippy::too_many_arguments)]
fn make_non_resident_attr(
    attr_type: u32,
    attr_id: u16,
    flags: u16,
    name: &str,
    lowest_vcn: u64,
    highest_vcn: u64,
    data_size: u64,
    initialized_size: u64,
    runlist: &[u8],
) -> Vec<u8> {
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    let name_offset = 64usize;
    let run_offset = (name_offset + name_utf16.len() * 2 + 7) & !7;
    let total_len = (run_offset + runlist.len() + 1 + 7) & !7; // +1 为 0x00 终止字节
    let mut buf = vec![0u8; total_len];
    buf[0..4].copy_from_slice(&attr_type.to_le_bytes());
    buf[4..8].copy_from_slice(&(total_len as u32).to_le_bytes());
    buf[8] = 1; // 非常驻属性
    buf[9] = name_utf16.len() as u8;
    buf[10..12].copy_from_slice(&(name_offset as u16).to_le_bytes());
    buf[12..14].copy_from_slice(&flags.to_le_bytes());
    buf[14..16].copy_from_slice(&attr_id.to_le_bytes());
    buf[16..24].copy_from_slice(&lowest_vcn.to_le_bytes());
    buf[24..32].copy_from_slice(&highest_vcn.to_le_bytes());
    buf[32..34].copy_from_slice(&(run_offset as u16).to_le_bytes());
    buf[40..48].copy_from_slice(&data_size.to_le_bytes());
    buf[48..56].copy_from_slice(&data_size.to_le_bytes());
    buf[56..64].copy_from_slice(&initialized_size.to_le_bytes());
    for (i, u) in name_utf16.iter().enumerate() {
        buf[name_offset + i * 2..name_offset + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    buf[run_offset..run_offset + runlist.len()].copy_from_slice(runlist);
    buf[run_offset + runlist.len()] = 0x00;
    buf
}

fn build_mft_record(in_use: bool, base_ref: u64, attrs: &[Vec<u8>]) -> [u8; 1024] {
    let mut rec = [0u8; 1024];
    rec[0..4].copy_from_slice(b"FILE");
    let usa_offset: u16 = 48;
    let usa_count: u16 = 3; // 1 个 USN + 2 个扇区（1024 / 512）
    let first_attr: u16 = 56;
    rec[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    rec[6..8].copy_from_slice(&usa_count.to_le_bytes());
    rec[20..22].copy_from_slice(&first_attr.to_le_bytes());
    rec[22..24].copy_from_slice(&(if in_use { 1u16 } else { 0u16 }).to_le_bytes());
    rec[28..32].copy_from_slice(&1024u32.to_le_bytes());
    rec[32..40].copy_from_slice(&base_ref.to_le_bytes());

    let mut pos = first_attr as usize;
    for a in attrs {
        rec[pos..pos + a.len()].copy_from_slice(a);
        pos += a.len();
    }
    rec[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    pos += 4;
    rec[24..28].copy_from_slice(&(pos as u32).to_le_bytes());

    // 在偏移 510..512 与 1022..1024 处写入真实的 NTFS USA 修复项。
    let usn = [0x34u8, 0x12u8];
    let orig0 = [rec[510], rec[511]];
    let orig1 = [rec[1022], rec[1023]];
    rec[48..50].copy_from_slice(&usn);
    rec[50..52].copy_from_slice(&orig0);
    rec[52..54].copy_from_slice(&orig1);
    rec[510..512].copy_from_slice(&usn);
    rec[1022..1024].copy_from_slice(&usn);
    rec
}

fn make_attr_list_entry(
    attr_type: u32,
    starting_vcn: u64,
    mft_record: u64,
    attr_id: u16,
    name: &str,
) -> Vec<u8> {
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    let rec_len = (26 + name_utf16.len() * 2 + 7) & !7;
    let mut e = vec![0u8; rec_len];
    e[0..4].copy_from_slice(&attr_type.to_le_bytes());
    e[4..6].copy_from_slice(&(rec_len as u16).to_le_bytes());
    e[6] = name_utf16.len() as u8;
    e[7] = 26;
    e[8..16].copy_from_slice(&starting_vcn.to_le_bytes());
    e[16..24].copy_from_slice(&mft_record.to_le_bytes());
    e[24..26].copy_from_slice(&attr_id.to_le_bytes());
    for (i, u) in name_utf16.iter().enumerate() {
        e[26 + i * 2..26 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    e
}

fn ntfs_entry(inode: &str, size: u64, deleted: bool) -> InventoryEntry {
    InventoryEntry {
        path: format!("FILE_{inode}.DAT"),
        inode: inode.to_string(),
        mode: if deleted { "-/r---------" } else { "r/r---------" }.to_string(),
        size,
        deleted,
        reallocated: false,
        atime: 0,
        mtime: 0,
        ctime: 0,
        crtime: 0,
        directory: false,
        offset: 64, // 分区起始于第 64 扇区
        filesystem: "NTFS".to_string(),
        start_cluster_allocated: None,
        extents: None,
    }
}

#[test]
fn test_native_ntfs_volume_reader_all_features_and_fallbacks() {
    let part_offset: u64 = 64;
    let part_base = (part_offset * 512) as usize;
    let cluster_size = 4096usize;
    let total_clusters = 64usize;
    let mut img = vec![0u8; part_base + total_clusters * cluster_size];

    // 在分区起始处写入 NTFS 引导扇区。
    let mft_lcn: u64 = 4; // MFT 占用簇 4..12（8 簇 = 32 KiB = 32 条 MFT 记录）
    {
        let boot = &mut img[part_base..part_base + 512];
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 8; // 8 扇区 * 512 = 4096 字节/簇
        boot[40..48].copy_from_slice(&((total_clusters * 8) as u64).to_le_bytes());
        boot[48..56].copy_from_slice(&mft_lcn.to_le_bytes());
        boot[64] = (-10i8) as u8; // 2^10 = 1024 字节 MFT 记录
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
    }

    let write_cluster = |img: &mut [u8], lcn: usize, data: &[u8]| {
        let off = part_base + lcn * cluster_size;
        img[off..off + data.len()].copy_from_slice(data);
    };
    let write_mft = |img: &mut [u8], idx: usize, rec: &[u8; 1024]| {
        let off = part_base + (mft_lcn as usize) * cluster_size + idx * 1024;
        img[off..off + 1024].copy_from_slice(rec);
    };

    // 记录 0：从 LCN 4 起覆盖 8 个簇（32 条记录）的 $MFT。
    let mft_runs = encode_data_run(8, Some(mft_lcn as i64));
    let mft0 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0,
            "",
            0,
            7,
            (8 * cluster_size) as u64,
            (8 * cluster_size) as u64,
            &mft_runs,
        )],
    );
    write_mft(&mut img, 0, &mft0);

    // 记录 10：常驻 $DATA（默认匿名流 id=1）+ 命名 ADS 流（`secret`，id=2）。
    let res_payload = b"Hello resident NTFS file!";
    let ads_payload = b"Hidden ADS stream payload!";
    let rec10 = build_mft_record(
        true,
        0,
        &[
            make_resident_attr(0x80, 1, 0, "", res_payload),
            make_resident_attr(0x80, 2, 0, "secret", ads_payload),
        ],
    );
    write_mft(&mut img, 10, &rec10);

    // 记录 11：非常驻碎片文件，先位于 LCN 20（1 簇），再跳至 LCN 15（负增量 -5，1 簇）。
    let frag_a: Vec<u8> = (0..cluster_size).map(|i| (i & 0xff) as u8).collect();
    let frag_b: Vec<u8> = (0..cluster_size).map(|i| ((i * 7 + 3) & 0xff) as u8).collect();
    write_cluster(&mut img, 20, &frag_a);
    write_cluster(&mut img, 15, &frag_b);
    let mut frag_runs = encode_data_run(1, Some(20));
    frag_runs.extend_from_slice(&encode_data_run(1, Some(-5)));
    let frag_size = (cluster_size + 1234) as u64;
    let rec11 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0,
            "",
            0,
            1,
            frag_size,
            frag_size,
            &frag_runs,
        )],
    );
    write_mft(&mut img, 11, &rec11);

    // 记录 12：稀疏文件 [稀疏 10 簇，真实数据 2 簇 @ LCN 22..24，稀疏 10 簇] = 22 * 4096 字节。
    let sparse_mid_a = vec![0xAAu8; cluster_size];
    let sparse_mid_b = vec![0xBBu8; cluster_size];
    write_cluster(&mut img, 22, &sparse_mid_a);
    write_cluster(&mut img, 23, &sparse_mid_b);
    let mut sparse_runs = encode_data_run(10, None);
    sparse_runs.extend_from_slice(&encode_data_run(2, Some(22)));
    sparse_runs.extend_from_slice(&encode_data_run(10, None));
    let sparse_size = (22 * cluster_size) as u64;
    let rec12 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0x8000, // 稀疏标志（SPARSE）
            "",
            0,
            21,
            sparse_size,
            sparse_size,
            &sparse_runs,
        )],
    );
    write_mft(&mut img, 12, &rec12);

    // 记录 13：全稀疏文件（10 个稀疏簇）。
    let all_sparse_runs = encode_data_run(10, None);
    let rec13 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0x8000,
            "",
            0,
            9,
            (10 * cluster_size) as u64,
            (10 * cluster_size) as u64,
            &all_sparse_runs,
        )],
    );
    write_mft(&mut img, 13, &rec13);

    // 记录 14：已删除 MFT 记录（in_use = false），其非常驻簇 @ LCN 25 数据完好。
    let deleted_payload = b"Deleted NTFS content still intact on disk!";
    write_cluster(&mut img, 25, deleted_payload);
    let del_runs = encode_data_run(1, Some(25));
    let rec14 = build_mft_record(
        false, // 未使用（已删除）
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0,
            "",
            0,
            0,
            deleted_payload.len() as u64,
            deleted_payload.len() as u64,
            &del_runs,
        )],
    );
    write_mft(&mut img, 14, &rec14);

    // 记录 15：压缩属性（标志 0x0001）-> 必须返回 FallbackToIcat。
    let rec15 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0x0001,
            "",
            0,
            0,
            4096,
            4096,
            &encode_data_run(1, Some(26)),
        )],
    );
    write_mft(&mut img, 15, &rec15);

    // 记录 16：加密属性（标志 0x4000）-> 必须返回 FallbackToIcat。
    let rec16 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0x4000,
            "",
            0,
            0,
            4096,
            4096,
            &encode_data_run(1, Some(27)),
        )],
    );
    write_mft(&mut img, 16, &rec16);

    // 记录 17：runlist 为空的非常驻属性（`$BadClus:$Bad` 场景）-> 必须返回 FallbackToIcat。
    let rec17 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(0x80, 1, 0, "", 0, 0, 8192, 8192, &[])],
    );
    write_mft(&mut img, 17, &rec17);

    // 记录 19 + 扩展记录 20：`$ATTRIBUTE_LIST` 将 `$DATA` 拆分到基础与扩展 MFT 记录。
    let ext_c0 = vec![0x11u8; cluster_size];
    let ext_c1 = vec![0x22u8; cluster_size];
    write_cluster(&mut img, 30, &ext_c0);
    write_cluster(&mut img, 31, &ext_c1);
    let mut al_bytes = make_attr_list_entry(0x80, 0, 19, 1, "");
    al_bytes.extend_from_slice(&make_attr_list_entry(0x80, 1, 20, 4, ""));
    let rec19 = build_mft_record(
        true,
        0,
        &[
            make_resident_attr(0x20, 0, 0, "", &al_bytes),
            make_non_resident_attr(
                0x80,
                1,
                0,
                "",
                0,
                0,
                (2 * cluster_size) as u64,
                (2 * cluster_size) as u64,
                &encode_data_run(1, Some(30)),
            ),
        ],
    );
    let rec20 = build_mft_record(
        true,
        19, // 基础记录号 base_mft_record == 19
        &[make_non_resident_attr(
            0x80,
            4,
            0,
            "",
            1,
            1,
            0,
            0,
            &encode_data_run(1, Some(31)),
        )],
    );
    write_mft(&mut img, 19, &rec19);
    write_mft(&mut img, 20, &rec20);

    // 记录 21：initialized_size（2000）< data_size（4096）-> 尾部字节必须读作 0。
    let mut init_cluster = vec![0x5Au8; cluster_size];
    init_cluster[..2000].fill(0x77);
    write_cluster(&mut img, 32, &init_cluster);
    let rec21 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0,
            "",
            0,
            0,
            4096,
            2000,
            &encode_data_run(1, Some(32)),
        )],
    );
    write_mft(&mut img, 21, &rec21);

    // 记录 22 + 23：`$ATTRIBUTE_LIST` 的基础 MFT 在 VCN 0 处声明了完整 `data_size`（2 簇），
    // 但扩展 MFT 23 的 `base_ref` 不匹配（99 != 22）-> 必须返回 FallbackToIcat（严禁回退到基础记录的运行段）。
    let mut al22 = make_attr_list_entry(0x80, 0, 22, 1, "");
    al22.extend_from_slice(&make_attr_list_entry(0x80, 1, 23, 4, ""));
    let rec22 = build_mft_record(
        true,
        0,
        &[
            make_resident_attr(0x20, 0, 0, "", &al22),
            make_non_resident_attr(
                0x80,
                1,
                0,
                "",
                0,
                0,
                (2 * cluster_size) as u64,
                (2 * cluster_size) as u64,
                &encode_data_run(1, Some(33)),
            ),
        ],
    );
    let rec23 = build_mft_record(
        true,
        99, // base_mft_record 不匹配
        &[make_non_resident_attr(
            0x80,
            4,
            0,
            "",
            1,
            1,
            0,
            0,
            &encode_data_run(1, Some(34)),
        )],
    );
    write_mft(&mut img, 22, &rec22);
    write_mft(&mut img, 23, &rec23);

    // 记录 24 + 25：`$ATTRIBUTE_LIST` 基础 MFT 未压缩但扩展 MFT 已压缩 -> 必须返回 FallbackToIcat。
    let mut al24 = make_attr_list_entry(0x80, 0, 24, 1, "");
    al24.extend_from_slice(&make_attr_list_entry(0x80, 1, 25, 4, ""));
    let rec24 = build_mft_record(
        true,
        0,
        &[
            make_resident_attr(0x20, 0, 0, "", &al24),
            make_non_resident_attr(
                0x80,
                1,
                0,
                "",
                0,
                0,
                (2 * cluster_size) as u64,
                (2 * cluster_size) as u64,
                &encode_data_run(1, Some(35)),
            ),
        ],
    );
    let rec25 = build_mft_record(
        true,
        24,
        &[make_non_resident_attr(
            0x80,
            4,
            0x0001, // 压缩的扩展属性段
            "",
            1,
            1,
            0,
            0,
            &encode_data_run(1, Some(36)),
        )],
    );
    write_mft(&mut img, 24, &rec24);
    write_mft(&mut img, 25, &rec25);

    // 记录 26：单记录运行段截断（1 簇 = 4096 字节 < initialized_size 8192）-> 必须返回 FallbackToIcat。
    let rec26 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0,
            "",
            0,
            0,
            (2 * cluster_size) as u64,
            (2 * cluster_size) as u64,
            &encode_data_run(1, Some(37)),
        )],
    );
    write_mft(&mut img, 26, &rec26);

    // 记录 27 + 28：`$ATTRIBUTE_LIST` 存在 VCN 空洞（基础 VCN 0、扩展 VCN 2、缺失 VCN 1）-> 必须返回 FallbackToIcat。
    let mut al27 = make_attr_list_entry(0x80, 0, 27, 1, "");
    al27.extend_from_slice(&make_attr_list_entry(0x80, 2, 28, 4, ""));
    let rec27 = build_mft_record(
        true,
        0,
        &[
            make_resident_attr(0x20, 0, 0, "", &al27),
            make_non_resident_attr(
                0x80,
                1,
                0,
                "",
                0,
                0,
                (3 * cluster_size) as u64,
                (3 * cluster_size) as u64,
                &encode_data_run(1, Some(38)),
            ),
        ],
    );
    let rec28 = build_mft_record(
        true,
        27,
        &[make_non_resident_attr(
            0x80,
            4,
            0,
            "",
            2,
            2,
            0,
            0,
            &encode_data_run(1, Some(39)),
        )],
    );
    write_mft(&mut img, 27, &rec27);
    write_mft(&mut img, 28, &rec28);

    // 记录 29 + 30：`$ATTRIBUTE_LIST` 存在重叠 VCN（基础 VCN 0..=1，扩展 VCN 1..=2）-> 必须返回 FallbackToIcat。
    let mut al29 = make_attr_list_entry(0x80, 0, 29, 1, "");
    al29.extend_from_slice(&make_attr_list_entry(0x80, 1, 30, 4, ""));
    let rec29 = build_mft_record(
        true,
        0,
        &[
            make_resident_attr(0x20, 0, 0, "", &al29),
            make_non_resident_attr(
                0x80,
                1,
                0,
                "",
                0,
                1,
                (3 * cluster_size) as u64,
                (3 * cluster_size) as u64,
                &encode_data_run(2, Some(40)),
            ),
        ],
    );
    let rec30 = build_mft_record(
        true,
        29,
        &[make_non_resident_attr(
            0x80,
            4,
            0,
            "",
            1,
            2,
            0,
            0,
            &encode_data_run(2, Some(42)),
        )],
    );
    write_mft(&mut img, 29, &rec29);
    write_mft(&mut img, 30, &rec30);

    // 记录 31：highest_vcn 不匹配（仅 1 个簇的运行段但 highest_vcn = 5）-> 必须返回 FallbackToIcat。
    let rec31 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0,
            "",
            0,
            5,
            cluster_size as u64,
            cluster_size as u64,
            &encode_data_run(1, Some(44)),
        )],
    );
    write_mft(&mut img, 31, &rec31);

    // 执行 VolumeReader 断言校验。
    let media: Arc<dyn MediaReader> = Arc::new(MemoryMedia(img));
    let mut vol = VolumeReader::open_with_media(media);

    // 1. 常驻默认流与 ADS 流读取校验。
    let e10 = ntfs_entry("10-128-1", res_payload.len() as u64, false);
    assert_eq!(
        vol.plan_entry(&e10, b"NTFS"),
        EntryReadPlan::Direct {
            intervals: vec![ByteInterval {
                start: 0,
                end: res_payload.len() as u64
            }],
            total_size: res_payload.len() as u64
        }
    );
    assert_eq!(
        vol.read_entry_at(&e10, 0, res_payload.len()).unwrap(),
        res_payload
    );

    let e10_ads = ntfs_entry("10-128-2", ads_payload.len() as u64, false);
    assert_eq!(
        vol.read_entry_at(&e10_ads, 0, ads_payload.len()).unwrap(),
        ads_payload
    );

    // 2. 含负 LCN 增量的碎片文件读取校验。
    let e11 = ntfs_entry("11-128-1", frag_size, false);
    let read11 = vol.read_entry_at(&e11, 0, frag_size as usize).unwrap();
    assert_eq!(&read11[..cluster_size], &frag_a[..]);
    assert_eq!(&read11[cluster_size..], &frag_b[..1234]);
    // 跨簇边界切片读取。
    let cross = vol.read_entry_at(&e11, (cluster_size - 16) as u64, 32).unwrap();
    assert_eq!(&cross[..16], &frag_a[cluster_size - 16..]);
    assert_eq!(&cross[16..], &frag_b[..16]);

    // 3. 稀疏区间规划校验（对齐 test_review.py::test_sparse_intervals_boundary_and_guards）。
    let e12 = ntfs_entry("12-128-1", sparse_size, false);
    assert_eq!(
        vol.plan_entry(&e12, b"\x00ABC"),
        EntryReadPlan::Direct {
            intervals: vec![ByteInterval {
                start: (10 * cluster_size - 3) as u64,
                end: (12 * cluster_size) as u64
            }],
            total_size: sparse_size
        }
    );
    // 全零检索目标不得跳过稀疏区域。
    assert_eq!(
        vol.plan_entry(&e12, b"\x00\x00"),
        EntryReadPlan::Direct {
            intervals: vec![ByteInterval {
                start: 0,
                end: sparse_size
            }],
            total_size: sparse_size
        }
    );
    // 跨越“稀疏 -> 真实 -> 稀疏”读取应精确产生“零字节 + 载荷 + 零字节”。
    let span = vol
        .read_entry_at(&e12, (10 * cluster_size - 8) as u64, 2 * cluster_size + 16)
        .unwrap();
    assert!(span[..8].iter().all(|&b| b == 0));
    assert!(span[8..8 + cluster_size].iter().all(|&b| b == 0xAA));
    assert!(span[8 + cluster_size..8 + 2 * cluster_size].iter().all(|&b| b == 0xBB));
    assert!(span[8 + 2 * cluster_size..].iter().all(|&b| b == 0));

    // 4. 全稀疏文件配合非零检索目标时返回空区间列表。
    let e13 = ntfs_entry("13-128-1", (10 * cluster_size) as u64, false);
    assert_eq!(
        vol.plan_entry(&e13, b"ab"),
        EntryReadPlan::Direct {
            intervals: vec![],
            total_size: (10 * cluster_size) as u64
        }
    );

    // 5. 已删除 NTFS MFT 记录的直接随机读取校验。
    let e14 = ntfs_entry("14-128-1", deleted_payload.len() as u64, true);
    assert!(matches!(
        vol.plan_entry(&e14, b"Deleted"),
        EntryReadPlan::Direct { .. }
    ));
    assert_eq!(
        vol.read_entry_at(&e14, 0, deleted_payload.len()).unwrap(),
        deleted_payload
    );

    // 6. 压缩、加密以及空运行段属性必须返回 FallbackToIcat。
    assert_eq!(
        vol.plan_entry(&ntfs_entry("15-128-1", 4096, false), b"ab"),
        EntryReadPlan::FallbackToIcat
    );
    assert_eq!(
        vol.plan_entry(&ntfs_entry("16-128-1", 4096, false), b"ab"),
        EntryReadPlan::FallbackToIcat
    );
    assert_eq!(
        vol.plan_entry(&ntfs_entry("17-128-1", 8192, false), b"ab"),
        EntryReadPlan::FallbackToIcat
    );

    // 7. 跨扩展 MFT 记录 20 的 `$ATTRIBUTE_LIST` 读取校验。
    let e19 = ntfs_entry("19-128-1", (2 * cluster_size) as u64, false);
    let read19 = vol.read_entry_at(&e19, 0, 2 * cluster_size).unwrap();
    assert!(read19[..cluster_size].iter().all(|&b| b == 0x11));
    assert!(read19[cluster_size..].iter().all(|&b| b == 0x22));

    // 8. initialized_size < data_size 时尾部补零并收缩非稀疏扫描区间。
    let e21 = ntfs_entry("21-128-1", 4096, false);
    assert_eq!(
        vol.plan_entry(&e21, b"ab"),
        EntryReadPlan::Direct {
            intervals: vec![ByteInterval { start: 0, end: 2000 }],
            total_size: 4096
        }
    );
    let read21 = vol.read_entry_at(&e21, 0, 4096).unwrap();
    assert!(read21[..2000].iter().all(|&b| b == 0x77));
    assert!(read21[2000..].iter().all(|&b| b == 0x00));

    // 9. `$ATTRIBUTE_LIST` 失败或 runlist 畸形时必须返回 FallbackToIcat（严禁返回残缺的 Direct）。
    assert_eq!(
        vol.plan_entry(&ntfs_entry("22-128-1", (2 * cluster_size) as u64, false), b"ab"),
        EntryReadPlan::FallbackToIcat,
        "$ATTRIBUTE_LIST mismatched base_ref must fall back to icat"
    );
    assert_eq!(
        vol.plan_entry(&ntfs_entry("24-128-1", (2 * cluster_size) as u64, false), b"ab"),
        EntryReadPlan::FallbackToIcat,
        "$ATTRIBUTE_LIST compressed extension must fall back to icat"
    );
    assert_eq!(
        vol.plan_entry(&ntfs_entry("26-128-1", (2 * cluster_size) as u64, false), b"ab"),
        EntryReadPlan::FallbackToIcat,
        "truncated non-resident runs must fall back to icat"
    );
    assert_eq!(
        vol.plan_entry(&ntfs_entry("27-128-1", (3 * cluster_size) as u64, false), b"ab"),
        EntryReadPlan::FallbackToIcat,
        "VCN gap in $ATTRIBUTE_LIST runs must fall back to icat"
    );
    assert_eq!(
        vol.plan_entry(&ntfs_entry("29-128-1", (3 * cluster_size) as u64, false), b"ab"),
        EntryReadPlan::FallbackToIcat,
        "overlapping VCN runs must fall back to icat"
    );
    assert_eq!(
        vol.plan_entry(&ntfs_entry("31-128-1", cluster_size as u64, false), b"ab"),
        EntryReadPlan::FallbackToIcat,
        "highest_vcn mismatch must fall back to icat"
    );
}

#[test]
fn test_ntfs_64k_cluster_0x80_and_malformed_cpmr_0x80_and_fat_deleted_dash_r() {
    // 1. 构造标准 64 KiB 簇（boot[13] = 0x80 = 128 扇区/簇）的合成 NTFS 卷，验证不 panic 且精确读取。
    let cluster_size = 65_536usize;
    let mft_lcn = 2u64;
    let total_clusters = 8usize;
    let mut img = vec![0u8; total_clusters * cluster_size];

    img[3..11].copy_from_slice(b"NTFS    ");
    img[11..13].copy_from_slice(&512u16.to_le_bytes());
    img[13] = 0x80; // 128 扇区/簇 = 64 KiB 簇（过去强制转 i8 取反会触发 -128 溢出 panic）
    img[48..56].copy_from_slice(&mft_lcn.to_le_bytes());
    img[64] = (-10i8) as u8; // MFT 记录 1024 字节
    img[510] = 0x55;
    img[511] = 0xAA;

    let write_mft = |disk: &mut [u8], idx: usize, rec: &[u8]| {
        let off = (mft_lcn as usize) * cluster_size + idx * 1024;
        disk[off..off + 1024].copy_from_slice(rec);
    };

    let mft0 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0,
            "",
            0,
            0,
            (16 * 1024) as u64,
            (16 * 1024) as u64,
            &encode_data_run(1, Some(mft_lcn as i64)),
        )],
    );
    write_mft(&mut img, 0, &mft0);

    // 在 LCN 4 写入测试数据，验证 64 KiB 簇偏移计算精确无误。
    let payload = b"NTFS_64K_CLUSTER_OK_0x80";
    let data_lcn = 4usize;
    img[data_lcn * cluster_size..data_lcn * cluster_size + payload.len()].copy_from_slice(payload);
    let rec5 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(
            0x80,
            1,
            0,
            "",
            0,
            0,
            payload.len() as u64,
            payload.len() as u64,
            &encode_data_run(1, Some(data_lcn as i64)),
        )],
    );
    write_mft(&mut img, 5, &rec5);

    let media64k: Arc<dyn MediaReader> = Arc::new(MemoryMedia(img.clone()));
    let mut vol64k = VolumeReader::open_with_media(media64k);
    let mut e5 = ntfs_entry("5-128-1", payload.len() as u64, false);
    e5.offset = 0;
    assert!(matches!(
        vol64k.plan_entry(&e5, b"64K"),
        EntryReadPlan::Direct { .. }
    ));
    let mut buf = vec![0u8; payload.len()];
    vol64k.read_entry_into(&e5, 0, &mut buf).expect("read 64K NTFS");
    assert_eq!(&buf, payload);

    // 2. 畸形 boot[64] = 0x80（i8::MIN = -128）：必须平滑回退 FallbackToIcat，严禁 panic。
    let mut bad_boot = img;
    bad_boot[64] = 0x80;
    let media_bad: Arc<dyn MediaReader> = Arc::new(MemoryMedia(bad_boot));
    let mut vol_bad = VolumeReader::open_with_media(media_bad);
    assert_eq!(vol_bad.plan_entry(&e5, b"64K"), EntryReadPlan::FallbackToIcat);

    // 3. 验证 FAT 已删除且 mode 为 `-/r...` 的条目在起始簇被占用时能被正确标注 start_cluster_allocated。
    let tmp = tempfile::tempdir().expect("tempdir");
    let fat_path = tmp.path().join("fat16_del_dash_r.img");
    let sector_size = 512usize;
    let reserved = 1usize;
    let fat_sectors = 1usize;
    let root_entries = 16usize;
    let root_sectors = (root_entries * 32) / sector_size;
    let data_clusters = 32usize;
    let total_sectors = reserved + fat_sectors + root_sectors + data_clusters;
    let mut fat_img = vec![0u8; total_sectors * sector_size];
    fat_img[0] = 0xEB;
    fat_img[1] = 0x3C;
    fat_img[2] = 0x90;
    fat_img[11..13].copy_from_slice(&(sector_size as u16).to_le_bytes());
    fat_img[13] = 1; // 每簇 1 扇区
    fat_img[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    fat_img[16] = 1; // 1 份 FAT
    fat_img[17..19].copy_from_slice(&(root_entries as u16).to_le_bytes());
    fat_img[19..21].copy_from_slice(&(total_sectors as u16).to_le_bytes());
    fat_img[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
    fat_img[54..62].copy_from_slice(b"FAT12   ");
    fat_img[510] = 0x55;
    fat_img[511] = 0xAA;
    // 在 FAT12 表中将簇 3 标记为已占用（EOC = 0xFFF）。
    // 簇 3 在 FAT12 的偏移为 (3 * 3) / 2 = 4，奇数簇占高 12 位。
    let fat_off = reserved * sector_size;
    fat_img[fat_off + 4] = 0xF0;
    fat_img[fat_off + 5] = 0xFF;
    // 在根目录槽位 0（TSK inode = 3）写入已删除文件目录项，起始簇指向簇 3。
    let root_off = (reserved + fat_sectors) * sector_size;
    fat_img[root_off] = 0xE5;
    fat_img[root_off + 1..root_off + 11].copy_from_slice(b"ELFILE TXT");
    fat_img[root_off + 11] = 0x20;
    fat_img[root_off + 26..root_off + 28].copy_from_slice(&3u16.to_le_bytes());
    fat_img[root_off + 28..root_off + 32].copy_from_slice(&64u32.to_le_bytes());
    std::fs::write(&fat_path, &fat_img).expect("write fat img");

    let mut entries = vec![InventoryEntry {
        path: "DELFILE.TXT".to_string(),
        inode: "3".to_string(),
        mode: "-/r---------".to_string(),
        size: 64,
        deleted: true,
        reallocated: false,
        atime: 0,
        mtime: 0,
        ctime: 0,
        crtime: 0,
        directory: false,
        offset: 0,
        filesystem: "FAT12".to_string(),
        start_cluster_allocated: None,
        extents: None,
    }];
    let regions = map_fat_regions(
        &fat_path,
        0,
        "File System Type: FAT12\n",
        &mut entries,
        None,
    )
    .expect("map_fat_regions");
    assert_eq!(regions.len(), 3);
    assert_eq!(
        entries[0].start_cluster_allocated,
        Some(true),
        "已删除且 mode 为 -/r 的 FAT 条目在起始簇被占用时必须标注 start_cluster_allocated=Some(true)"
    );
}
