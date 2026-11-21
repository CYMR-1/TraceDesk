use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::Instant;

use tracedesk_engines::{
    ByteInterval, EntryReadPlan, InventoryEntry, MediaReader, VolumeReader, map_fat_regions,
};

/// In-memory MediaReader for deterministic synthetic NTFS tests.
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
    // Replicates scratch/baseline/run_baseline.py 500,000-cluster non-sparse FAT32 benchmark
    // (Python baseline: 11,563 ms; Rust requirement: < 500 ms).
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

    // Build FAT32 boot sector.
    let mut boot = [0u8; 512];
    boot[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    boot[11..13].copy_from_slice(&(sector_size as u16).to_le_bytes());
    boot[13] = 1; // 1 sector per cluster
    boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    boot[16] = copies as u8;
    boot[32..36].copy_from_slice(&(total_sectors as u32).to_le_bytes());
    boot[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
    boot[44..48].copy_from_slice(&2u32.to_le_bytes()); // root_cluster = 2
    boot[82..90].copy_from_slice(b"FAT32   ");
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);

    // Populate 500,000 non-sparse mixed FAT32 entries:
    // - cluster 2: root directory (EOC)
    // - clusters 3..=1002 (1000 clusters): active file chain owned by inode 3
    // - remaining clusters 1003..500002: alternating pattern:
    //   every 3rd cluster is free (0), every 3rd+1 is idle EOC (0x0fffffff), every 3rd+2 is free (0),
    //   plus one bad cluster (0x0ffffff7) at cluster 2000.
    let mut fat = vec![0u8; (fat_sectors * sector_size) as usize];
    let set_fat = |fat: &mut [u8], c: u64, val: u32| {
        let off = (c as usize) * 4;
        fat[off..off + 4].copy_from_slice(&val.to_le_bytes());
    };
    set_fat(&mut fat, 0, 0x0fff_fff8);
    set_fat(&mut fat, 1, 0x0fff_ffff);
    set_fat(&mut fat, 2, 0x0fff_ffff); // root dir cluster 2
    for c in 3..1002 {
        set_fat(&mut fat, c, (c + 1) as u32);
    }
    set_fat(&mut fat, 1002, 0x0fff_ffff);

    let mut expected_free_clusters: u64 = 0;
    let mut expected_idle_clusters: u64 = 0;
    for c in 1003..(clusters + 2) {
        if c == 2000 {
            set_fat(&mut fat, c, 0x0fff_fff7); // bad cluster -> neither free nor idle
        } else if c % 3 == 1 {
            set_fat(&mut fat, c, 0x0fff_ffff); // allocated but unreferenced -> idle
            expected_idle_clusters += 1;
        } else {
            set_fat(&mut fat, c, 0); // free
            expected_free_clusters += 1;
        }
    }

    // Write root directory entries at cluster 2 (slot 0 = inode 3, slot 1 = inode 4).
    let mut dir_sector = [0u8; 512];
    // Slot 0: active file starting at cluster 3
    dir_sector[0..11].copy_from_slice(b"ACTIVE  BIN");
    dir_sector[11] = 0x20;
    dir_sector[26..28].copy_from_slice(&3u16.to_le_bytes());
    dir_sector[28..32].copy_from_slice(&(1000 * 512u32).to_le_bytes());
    // Slot 1: deleted file pointing to allocated cluster 1003 (or 1006, where 1006 % 3 == 1 -> allocated!)
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
// Synthetic NTFS Builder & Native VolumeReader Tests
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
    buf[8] = 0; // resident
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
    let total_len = (run_offset + runlist.len() + 1 + 7) & !7; // +1 for 0x00 terminator
    let mut buf = vec![0u8; total_len];
    buf[0..4].copy_from_slice(&attr_type.to_le_bytes());
    buf[4..8].copy_from_slice(&(total_len as u32).to_le_bytes());
    buf[8] = 1; // non-resident
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
    let usa_count: u16 = 3; // 1 USN + 2 sectors (1024 / 512)
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

    // Apply real NTFS USA fixups at offsets 510..512 and 1022..1024.
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
        offset: 64, // partition starts at sector 64
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

    // Write NTFS boot sector at partition base.
    let mft_lcn: u64 = 4; // MFT occupies clusters 4..12 (8 clusters = 32 KiB = 32 MFT records)
    {
        let boot = &mut img[part_base..part_base + 512];
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 8; // 8 sectors * 512 = 4096 bytes/cluster
        boot[40..48].copy_from_slice(&((total_clusters * 8) as u64).to_le_bytes());
        boot[48..56].copy_from_slice(&mft_lcn.to_le_bytes());
        boot[64] = (-10i8) as u8; // 2^10 = 1024-byte MFT records
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

    // Record 0: $MFT covering 8 clusters (32 records) starting at LCN 4.
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

    // Record 10: Resident $DATA (default unnamed id=1) + Named ADS stream (`secret`, id=2).
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

    // Record 11: Non-resident fragmented file across LCN 20 (1 cluster) then LCN 15 (negative delta -5, 1 cluster).
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

    // Record 12: Sparse file [sparse 10 clusters, real 2 clusters @ LCN 22..24, sparse 10 clusters] = 22 * 4096 bytes.
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
            0x8000, // SPARSE
            "",
            0,
            21,
            sparse_size,
            sparse_size,
            &sparse_runs,
        )],
    );
    write_mft(&mut img, 12, &rec12);

    // Record 13: All-sparse file (10 sparse clusters).
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

    // Record 14: DELETED MFT record (in_use = false) with intact non-resident cluster @ LCN 25.
    let deleted_payload = b"Deleted NTFS content still intact on disk!";
    write_cluster(&mut img, 25, deleted_payload);
    let del_runs = encode_data_run(1, Some(25));
    let rec14 = build_mft_record(
        false, // NOT IN USE (deleted)
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

    // Record 15: Compressed attribute (flag 0x0001) -> MUST FallbackToIcat.
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

    // Record 16: Encrypted attribute (flag 0x4000) -> MUST FallbackToIcat.
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

    // Record 17: Non-resident with empty runlist ($BadClus:$Bad case) -> MUST FallbackToIcat.
    let rec17 = build_mft_record(
        true,
        0,
        &[make_non_resident_attr(0x80, 1, 0, "", 0, 0, 8192, 8192, &[])],
    );
    write_mft(&mut img, 17, &rec17);

    // Record 19 + Extension Record 20: $ATTRIBUTE_LIST splitting $DATA across base + extension MFT.
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
        19, // base_mft_record == 19
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

    // Record 21: initialized_size (2000) < data_size (4096) -> trailing bytes must read as zero.
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

    // Record 22 + 23: $ATTRIBUTE_LIST whose base MFT has full `data_size` (2 clusters) at VCN 0,
    // but extension MFT 23 has mismatched `base_ref` (99 != 22) -> MUST FallbackToIcat (never fall back to base runs!).
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
        99, // mismatched base_mft_record!
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

    // Record 24 + 25: $ATTRIBUTE_LIST with uncompressed base MFT, but compressed extension MFT -> MUST FallbackToIcat.
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
            0x0001, // COMPRESSED extension!
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

    // Record 26: Single-record truncated runs (1 cluster = 4096 bytes < initialized_size 8192) -> MUST FallbackToIcat.
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

    // Record 27 + 28: $ATTRIBUTE_LIST with a VCN gap (base VCN 0, extension VCN 2, missing VCN 1) -> MUST FallbackToIcat.
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

    // Record 29 + 30: $ATTRIBUTE_LIST with overlapping VCNs (base VCN 0..=1, extension VCN 1..=2) -> MUST FallbackToIcat.
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

    // Record 31: highest_vcn mismatch (1 cluster run but highest_vcn = 5) -> MUST FallbackToIcat.
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

    // Run VolumeReader assertions!
    let media: Arc<dyn MediaReader> = Arc::new(MemoryMedia(img));
    let mut vol = VolumeReader::open_with_media(media);

    // 1. Resident default + ADS stream.
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

    // 2. Fragmented file with negative LCN delta.
    let e11 = ntfs_entry("11-128-1", frag_size, false);
    let read11 = vol.read_entry_at(&e11, 0, frag_size as usize).unwrap();
    assert_eq!(&read11[..cluster_size], &frag_a[..]);
    assert_eq!(&read11[cluster_size..], &frag_b[..1234]);
    // Cross-boundary slice read.
    let cross = vol.read_entry_at(&e11, (cluster_size - 16) as u64, 32).unwrap();
    assert_eq!(&cross[..16], &frag_a[cluster_size - 16..]);
    assert_eq!(&cross[16..], &frag_b[..16]);

    // 3. Sparse interval planning matches test_review.py::test_sparse_intervals_boundary_and_guards!
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
    // All-zero needle must NOT skip sparse regions.
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
    // Reading across sparse -> real -> sparse produces exact zeros + payload + zeros.
    let span = vol
        .read_entry_at(&e12, (10 * cluster_size - 8) as u64, 2 * cluster_size + 16)
        .unwrap();
    assert!(span[..8].iter().all(|&b| b == 0));
    assert!(span[8..8 + cluster_size].iter().all(|&b| b == 0xAA));
    assert!(span[8 + cluster_size..8 + 2 * cluster_size].iter().all(|&b| b == 0xBB));
    assert!(span[8 + 2 * cluster_size..].iter().all(|&b| b == 0));

    // 4. All-sparse file with non-zero needle yields empty intervals.
    let e13 = ntfs_entry("13-128-1", (10 * cluster_size) as u64, false);
    assert_eq!(
        vol.plan_entry(&e13, b"ab"),
        EntryReadPlan::Direct {
            intervals: vec![],
            total_size: (10 * cluster_size) as u64
        }
    );

    // 5. Deleted NTFS MFT record direct random read!
    let e14 = ntfs_entry("14-128-1", deleted_payload.len() as u64, true);
    assert!(matches!(
        vol.plan_entry(&e14, b"Deleted"),
        EntryReadPlan::Direct { .. }
    ));
    assert_eq!(
        vol.read_entry_at(&e14, 0, deleted_payload.len()).unwrap(),
        deleted_payload
    );

    // 6. Compressed, encrypted, and empty-run attributes MUST return FallbackToIcat.
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

    // 7. $ATTRIBUTE_LIST spanning extension MFT record 20.
    let e19 = ntfs_entry("19-128-1", (2 * cluster_size) as u64, false);
    let read19 = vol.read_entry_at(&e19, 0, 2 * cluster_size).unwrap();
    assert!(read19[..cluster_size].iter().all(|&b| b == 0x11));
    assert!(read19[cluster_size..].iter().all(|&b| b == 0x22));

    // 8. initialized_size < data_size zeroes tail & shrinks non-sparse interval.
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

    // 9. $ATTRIBUTE_LIST failure / malformed runlist MUST return FallbackToIcat (never partial Direct).
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
