use std::collections::HashSet;
use std::fs::File;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};

use lru::LruCache;
use memmap2::MmapOptions;
use regex::Regex;

use crate::error::{EngineError, EngineResult};
use crate::media::{MediaReader, file_read_exact_at};
use crate::types::InventoryEntry;

static FSSTAT_FAT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^File System Type: FAT(12|16|32)\s*$").expect("valid fat fsstat regex")
});

const FAT_PAGE_SIZE: usize = 64 * 1024;
const FAT_PAGE_CACHE_CAP: usize = 64; // 4 MiB bounded cache for random reads

#[inline]
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Parsed FAT12/16/32 boot parameter block geometry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FatGeometry {
    pub bits: u8,
    pub base: u64,
    pub sector: u64,
    pub cluster_size: u64,
    pub root_sectors: u64,
    pub directory_sector: u64,
    pub data_sector: u64,
    pub total_sectors: u64,
    pub clusters: u64,
    pub table_start: u64,
    pub table_length: u64,
    pub root_cluster: u32,
}

impl FatGeometry {
    fn parse(boot: &[u8; 512], base: u64, media_size: u64, forced_bits: Option<u8>) -> EngineResult<Self> {
        let sector = read_u16_le(boot, 11) as u64;
        let per_cluster = boot[13] as u64;
        let reserved = read_u16_le(boot, 14) as u64;
        let copies = boot[16] as u64;
        let root_items = read_u16_le(boot, 17) as u64;
        let total16 = read_u16_le(boot, 19) as u64;
        let fat16 = read_u16_le(boot, 22) as u64;
        let total32 = read_u32_le(boot, 32) as u64;
        let fat32 = read_u32_le(boot, 36) as u64;

        let fat_sectors = if fat16 != 0 { fat16 } else { fat32 };
        let total_sectors = if total16 != 0 { total16 } else { total32 };

        if !matches!(sector, 512 | 1024 | 2048 | 4096)
            || !matches!(per_cluster, 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128)
        {
            return Err(EngineError::Fat("FAT 扇区或簇大小无效".to_string()));
        }

        let root_sectors = (root_items * 32).div_ceil(sector);
        let fat_area = copies
            .checked_mul(fat_sectors)
            .ok_or_else(|| EngineError::Fat("FAT 分配表区域溢出".to_string()))?;
        let directory_sector = reserved
            .checked_add(fat_area)
            .ok_or_else(|| EngineError::Fat("FAT 目录偏移溢出".to_string()))?;
        let data_sector = directory_sector
            .checked_add(root_sectors)
            .ok_or_else(|| EngineError::Fat("FAT 数据区偏移溢出".to_string()))?;

        if total_sectors < data_sector {
            return Err(EngineError::Fat("FAT 布局超出镜像或分配表边界".to_string()));
        }
        let clusters = (total_sectors - data_sector) / per_cluster;
        let bits = match forced_bits {
            Some(b) => b,
            None => {
                if clusters < 4085 {
                    12
                } else if clusters < 65525 {
                    16
                } else {
                    32
                }
            }
        };

        let table_length = ((clusters + 2) * (bits as u64)).div_ceil(8);
        let fat_bytes = fat_sectors
            .checked_mul(sector)
            .ok_or_else(|| EngineError::Fat("FAT 分配表字节长度溢出".to_string()))?;
        let vol_end = total_sectors
            .checked_mul(sector)
            .and_then(|v| base.checked_add(v))
            .ok_or_else(|| EngineError::Fat("FAT 卷结束偏移溢出".to_string()))?;

        if clusters == 0 || reserved == 0 || copies == 0 || table_length > fat_bytes || vol_end > media_size {
            return Err(EngineError::Fat("FAT 布局超出镜像或分配表边界".to_string()));
        }

        let mut table_start = base + reserved * sector;
        if bits == 32 {
            let flags = read_u16_le(boot, 40);
            if (flags & 0x80) != 0 {
                let active = (flags & 0x0f) as u64;
                if active >= copies {
                    return Err(EngineError::Fat("FAT 活动分配表编号无效".to_string()));
                }
                table_start = table_start
                    .checked_add(active * fat_bytes)
                    .ok_or_else(|| EngineError::Fat("FAT 活动表偏移溢出".to_string()))?;
            }
        }

        let root_cluster = if bits == 32 { read_u32_le(boot, 44) } else { 0 };
        let cluster_size = per_cluster * sector;

        Ok(Self {
            bits,
            base,
            sector,
            cluster_size,
            root_sectors,
            directory_sector,
            data_sector,
            total_sectors,
            clusters,
            table_start,
            table_length,
            root_cluster,
        })
    }

    #[inline]
    pub fn max_dir_slots(&self) -> u64 {
        (self.total_sectors - self.directory_sector) * self.sector / 32
    }

    #[inline]
    pub fn dir_entry_offset(&self, slot: u64) -> u64 {
        self.base + self.directory_sector * self.sector + slot * 32
    }

    #[inline]
    pub fn cluster_disk_offset(&self, cluster: u64) -> u64 {
        self.base + self.data_sector * self.sector + (cluster - 2) * self.cluster_size
    }

    #[inline]
    pub fn reserved_value(&self) -> u32 {
        match self.bits {
            12 => 0xff0,
            16 => 0xfff0,
            _ => 0x0fff_fff0,
        }
    }

    #[inline]
    pub fn eoc_min(&self) -> u32 {
        match self.bits {
            12 => 0xff8,
            16 => 0xfff8,
            _ => 0x0fff_fff8,
        }
    }
}

#[inline]
fn next_cluster_slice(table: &[u8], bits: u8, cluster: u64) -> u32 {
    match bits {
        32 => {
            let off = (cluster as usize) * 4;
            u32::from_le_bytes([table[off], table[off + 1], table[off + 2], table[off + 3]])
                & 0x0fff_ffff
        }
        16 => {
            let off = (cluster as usize) * 2;
            u16::from_le_bytes([table[off], table[off + 1]]) as u32
        }
        _ => {
            let off = ((cluster as usize) * 3) / 2;
            let val = u16::from_le_bytes([table[off], table[off + 1]]);
            (if (cluster & 1) != 0 { val >> 4 } else { val } & 0xfff) as u32
        }
    }
}

/// Compact 64-bit word bitset for tracking owned clusters with minimal cache footprint.
struct ClusterBitset {
    words: Vec<u64>,
}

impl ClusterBitset {
    fn new(limit: usize) -> Self {
        Self {
            words: vec![0u64; limit.div_ceil(64)],
        }
    }

    #[inline]
    fn test(&self, bit: usize) -> bool {
        (self.words[bit >> 6] & (1u64 << (bit & 63))) != 0
    }

    /// Sets `bit` and returns `true` if it was newly set (`false` if already set).
    #[inline]
    fn set(&mut self, bit: usize) -> bool {
        let word = &mut self.words[bit >> 6];
        let mask = 1u64 << (bit & 63);
        if (*word & mask) != 0 {
            false
        } else {
            *word |= mask;
            true
        }
    }
}

#[inline]
fn push_extent(ranges: &mut Vec<(u64, u64)>, start: u64, length: u64) {
    if length == 0 {
        return;
    }
    if let Some(last) = ranges.last_mut()
        && last.0 + last.1 == start
    {
        last.1 += length;
        return;
    }
    ranges.push((start, length));
}

/// Map FAT12/16/32 root directory, unallocated clusters (`空余空间（未分配簇）`), and
/// allocated-but-unreferenced clusters (`闲置空间（已分配未关联簇）`) into read-only region
/// entries, while annotating deleted FAT entries whose start cluster is currently allocated.
///
/// 100% behaviorally aligned with `forensic/engines/fat.py::fat_regions` at native Rust speed.
pub fn map_fat_regions(
    image: &Path,
    offset: u64,
    fsstat: &str,
    entries: &mut [InventoryEntry],
    cancel: Option<&AtomicBool>,
) -> EngineResult<Vec<InventoryEntry>> {
    let Some(caps) = FSSTAT_FAT_RE.captures(fsstat) else {
        return Ok(Vec::new());
    };
    let bits: u8 = caps[1]
        .parse()
        .map_err(|_| EngineError::Fat("无法识别 FAT 位数".to_string()))?;

    let base = offset
        .checked_mul(512)
        .ok_or_else(|| EngineError::Fat("分区偏移溢出".to_string()))?;

    let file = File::open(image)?;
    let file_size = file.metadata()?.len();
    if base.saturating_add(512) > file_size {
        return Err(EngineError::Fat("无法完整读取 FAT 引导扇区".to_string()));
    }
    let mut boot = [0u8; 512];
    file_read_exact_at(&file, base, &mut boot)
        .map_err(|_| EngineError::Fat("无法完整读取 FAT 引导扇区".to_string()))?;

    let geom = FatGeometry::parse(&boot, base, file_size, Some(bits))?;

    let table_len_usize = usize::try_from(geom.table_length)
        .map_err(|_| EngineError::Fat("FAT 分配表超过寻址空间".to_string()))?;

    // Map the active FAT read-only (memmap2 aligns allocation granularity internally).
    let mmap = unsafe {
        MmapOptions::new()
            .offset(geom.table_start)
            .len(table_len_usize)
            .map(&file)?
    };
    let table: &[u8] = &mmap;

    let cluster_limit = geom.clusters + 2;
    let mut owned = ClusterBitset::new(cluster_limit as usize);

    let claim = |mut cluster: u64, owned: &mut ClusterBitset| -> EngineResult<u64> {
        let mut count: u64 = 0;
        while (2..cluster_limit).contains(&cluster) {
            if count.is_multiple_of(65536)
                && cancel.is_some_and(|c| c.load(Ordering::Relaxed))
            {
                return Err(EngineError::Cancelled("已取消建立索引".to_string()));
            }
            if !owned.set(cluster as usize) {
                break;
            }
            count += 1;
            cluster = next_cluster_slice(table, bits, cluster) as u64;
        }
        Ok(count)
    };

    let root_size = if bits == 32 {
        claim(geom.root_cluster as u64, &mut owned)? * geom.cluster_size
    } else {
        geom.root_sectors * geom.sector
    };

    let max_slots = geom.max_dir_slots();
    let mut record = [0u8; 32];

    for (index, entry) in entries.iter_mut().enumerate() {
        if index.is_multiple_of(1024) && cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled("已取消建立索引".to_string()));
        }
        if !(entry.mode.starts_with("r/") || entry.mode.starts_with("d/")) {
            continue;
        }
        let inode_num = entry
            .inode
            .parse::<u64>()
            .map_err(|_| EngineError::Fat(format!("无效的 FAT inode：{}", entry.inode)))?;
        let slot = inode_num
            .checked_sub(3)
            .ok_or_else(|| EngineError::Fat("FAT 目录项超出分区边界".to_string()))?;
        if slot >= max_slots {
            return Err(EngineError::Fat("FAT 目录项超出分区边界".to_string()));
        }
        file_read_exact_at(&file, geom.dir_entry_offset(slot), &mut record)
            .map_err(|_| EngineError::Fat("无法完整读取 FAT 目录项".to_string()))?;

        if (record[11] & 0x08) != 0 {
            continue;
        }
        let mut first = read_u16_le(&record, 26) as u64;
        if bits == 32 {
            first |= ((read_u16_le(&record, 20) & 0x0fff) as u64) << 16;
        }
        if entry.deleted {
            if (2..cluster_limit).contains(&first) && next_cluster_slice(table, bits, first) != 0 {
                entry.start_cluster_allocated = Some(true);
            }
        } else {
            claim(first, &mut owned)?;
        }
    }

    let mut free: Vec<(u64, u64)> = Vec::new();
    let mut idle: Vec<(u64, u64)> = Vec::new();
    let reserved_value = geom.reserved_value();
    let reserved_end = reserved_value + 8;
    let data_base = geom.base + geom.data_sector * geom.sector;
    let csize = geom.cluster_size;

    const BLOCK_CLUSTERS: u64 = 16_384;
    let mut first = 2u64;
    while first < cluster_limit {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled("已取消建立索引".to_string()));
        }
        let end = (first + BLOCK_CLUSTERS).min(cluster_limit);
        if bits == 32 || bits == 16 {
            let width = (bits / 8) as usize;
            let slice = &table[(first as usize) * width..(end as usize) * width];
            // Fast vectorized all-zero block check for sparse FAT volumes.
            if slice.iter().all(|&b| b == 0) {
                let start = data_base + (first - 2) * csize;
                let len = (end - first) * csize;
                push_extent(&mut free, start, len);
                first = end;
                continue;
            }
        }

        // Run-length coalesced inner scan to keep register pressure & vector pushes minimal.
        let mut run_kind: u8 = 0; // 0=none, 1=free, 2=idle
        let mut run_start_cluster: u64 = 0;
        let mut run_count: u64 = 0;

        let flush_run = |kind: u8,
                         start_c: u64,
                         cnt: u64,
                         free: &mut Vec<(u64, u64)>,
                         idle: &mut Vec<(u64, u64)>| {
            if cnt == 0 || kind == 0 {
                return;
            }
            let start = data_base + (start_c - 2) * csize;
            let len = cnt * csize;
            if kind == 1 {
                push_extent(free, start, len);
            } else {
                push_extent(idle, start, len);
            }
        };

        if bits == 32 {
            let slice = &table[(first as usize) * 4..(end as usize) * 4];
            for (i, &chunk4) in slice.as_chunks::<4>().0.iter().enumerate() {
                let cluster = first + i as u64;
                let val = u32::from_le_bytes(chunk4) & 0x0fff_ffff;
                let kind = if val == 0 {
                    1u8
                } else if val != 1
                    && !(reserved_value..reserved_end).contains(&val)
                    && !owned.test(cluster as usize)
                {
                    2u8
                } else {
                    0u8
                };
                if kind == run_kind && kind != 0 {
                    run_count += 1;
                } else {
                    flush_run(run_kind, run_start_cluster, run_count, &mut free, &mut idle);
                    run_kind = kind;
                    run_start_cluster = cluster;
                    run_count = u64::from(kind != 0);
                }
            }
        } else if bits == 16 {
            let slice = &table[(first as usize) * 2..(end as usize) * 2];
            for (i, &chunk2) in slice.as_chunks::<2>().0.iter().enumerate() {
                let cluster = first + i as u64;
                let val = u16::from_le_bytes(chunk2) as u32;
                let kind = if val == 0 {
                    1u8
                } else if val != 1
                    && !(reserved_value..reserved_end).contains(&val)
                    && !owned.test(cluster as usize)
                {
                    2u8
                } else {
                    0u8
                };
                if kind == run_kind && kind != 0 {
                    run_count += 1;
                } else {
                    flush_run(run_kind, run_start_cluster, run_count, &mut free, &mut idle);
                    run_kind = kind;
                    run_start_cluster = cluster;
                    run_count = u64::from(kind != 0);
                }
            }
        } else {
            for cluster in first..end {
                let val = next_cluster_slice(table, 12, cluster);
                let kind = if val == 0 {
                    1u8
                } else if val != 1
                    && !(reserved_value..reserved_end).contains(&val)
                    && !owned.test(cluster as usize)
                {
                    2u8
                } else {
                    0u8
                };
                if kind == run_kind && kind != 0 {
                    run_count += 1;
                } else {
                    flush_run(run_kind, run_start_cluster, run_count, &mut free, &mut idle);
                    run_kind = kind;
                    run_start_cluster = cluster;
                    run_count = u64::from(kind != 0);
                }
            }
        }
        flush_run(run_kind, run_start_cluster, run_count, &mut free, &mut idle);

        first = end;
    }

    let free_size: u64 = free.iter().map(|(_, len)| *len).sum();
    let idle_size: u64 = idle.iter().map(|(_, len)| *len).sum();

    let make_region = |path: &str, inode: &str, size: u64, extents: Option<Vec<(u64, u64)>>| {
        InventoryEntry {
            path: path.to_string(),
            inode: inode.to_string(),
            mode: "v/v---------".to_string(),
            size,
            deleted: false,
            reallocated: false,
            atime: 0,
            mtime: 0,
            ctime: 0,
            crtime: 0,
            directory: false,
            offset,
            filesystem: String::new(),
            start_cluster_allocated: None,
            extents,
        }
    };

    Ok(vec![
        make_region("(根目录)", "2", root_size, None),
        make_region("空余空间（未分配簇）", "", free_size, Some(free)),
        make_region("闲置空间（已分配未关联簇）", "", idle_size, Some(idle)),
    ])
}

/// Coalesced physical disk extent `(disk_byte_offset, byte_len)` for a FAT file.
#[derive(Debug, Clone)]
pub(crate) struct FatFileRuns {
    pub size: u64,
    /// `(logical_start, disk_offset, byte_len)` sorted by `logical_start`.
    pub extents: Vec<(u64, u64, u64)>,
}

/// Read-only random-access FAT12/16/32 volume reader operating over any [`MediaReader`] (RAW or EWF1).
pub(crate) struct FatVolume {
    media: Arc<dyn MediaReader>,
    geom: FatGeometry,
    fat_pages: LruCache<u64, Vec<u8>>,
}

impl FatVolume {
    pub fn open(media: Arc<dyn MediaReader>, partition_offset: u64) -> EngineResult<Self> {
        let base = partition_offset
            .checked_mul(512)
            .ok_or_else(|| EngineError::Fat("FAT 分区偏移溢出".to_string()))?;
        let mut boot = [0u8; 512];
        media.read_exact_at(base, &mut boot)?;
        if boot[510..512] != [0x55, 0xaa] {
            return Err(EngineError::Fat("无效的 FAT 引导签名".to_string()));
        }
        // Verify FAT signature or valid BPB (note: some valid FAT images leave label blank,
        // so we check OEM/signature hints and geometry consistency).
        if &boot[3..11] == b"NTFS    " {
            return Err(EngineError::Fat("分区为 NTFS 而非 FAT".to_string()));
        }
        let has_fat_label = matches!(&boot[54..62], b"FAT12   " | b"FAT16   " | b"FAT     ")
            || &boot[82..90] == b"FAT32   ";
        if !has_fat_label && !(boot[0] == 0xeb || boot[0] == 0xe9) {
            return Err(EngineError::Fat("未识别为 FAT 引导扇区".to_string()));
        }
        let geom = FatGeometry::parse(&boot, base, media.media_size(), None)?;
        Ok(Self {
            media,
            geom,
            fat_pages: LruCache::new(NonZeroUsize::new(FAT_PAGE_CACHE_CAP).expect("non-zero")),
        })
    }

    fn read_fat_bytes(&mut self, table_rel_offset: u64, out: &mut [u8]) -> EngineResult<()> {
        let mut rel = table_rel_offset;
        let mut pos = 0usize;
        while pos < out.len() {
            let page_idx = rel / (FAT_PAGE_SIZE as u64);
            let in_page = (rel % (FAT_PAGE_SIZE as u64)) as usize;
            if !self.fat_pages.contains(&page_idx) {
                let page_rel_start = page_idx * (FAT_PAGE_SIZE as u64);
                let page_len = (self.geom.table_length.saturating_sub(page_rel_start))
                    .min(FAT_PAGE_SIZE as u64) as usize;
                let mut page = vec![0u8; page_len];
                self.media
                    .read_exact_at(self.geom.table_start + page_rel_start, &mut page)?;
                self.fat_pages.put(page_idx, page);
            }
            let page = self.fat_pages.get(&page_idx).expect("just inserted");
            let avail = page.len().saturating_sub(in_page);
            if avail == 0 {
                return Err(EngineError::Fat("读取 FAT 分配表越界".to_string()));
            }
            let take = avail.min(out.len() - pos);
            out[pos..pos + take].copy_from_slice(&page[in_page..in_page + take]);
            rel += take as u64;
            pos += take;
        }
        Ok(())
    }

    fn next_cluster(&mut self, cluster: u64) -> EngineResult<u32> {
        match self.geom.bits {
            32 => {
                let mut b = [0u8; 4];
                self.read_fat_bytes(cluster * 4, &mut b)?;
                Ok(u32::from_le_bytes(b) & 0x0fff_ffff)
            }
            16 => {
                let mut b = [0u8; 2];
                self.read_fat_bytes(cluster * 2, &mut b)?;
                Ok(u16::from_le_bytes(b) as u32)
            }
            _ => {
                let mut b = [0u8; 2];
                self.read_fat_bytes((cluster * 3) / 2, &mut b)?;
                let val = u16::from_le_bytes(b);
                Ok((if (cluster & 1) != 0 { val >> 4 } else { val } & 0xfff) as u32)
            }
        }
    }

    /// Resolve cluster chain for a non-deleted regular FAT file.
    pub fn resolve_regular_file(&mut self, inode_num: u64, expected_size: u64) -> EngineResult<FatFileRuns> {
        let slot = inode_num
            .checked_sub(3)
            .ok_or_else(|| EngineError::Fat("FAT 目录项 inode 越界".to_string()))?;
        if slot >= self.geom.max_dir_slots() {
            return Err(EngineError::Fat("FAT 目录项超出分区边界".to_string()));
        }
        let mut record = [0u8; 32];
        self.media
            .read_exact_at(self.geom.dir_entry_offset(slot), &mut record)?;

        if record[0] == 0x00 || record[0] == 0xe5 {
            return Err(EngineError::Fat("FAT 目录项已删除或为空".to_string()));
        }
        if (record[11] & 0x18) != 0 {
            return Err(EngineError::Fat("FAT 目录项非普通文件".to_string()));
        }
        let file_size = read_u32_le(&record, 28) as u64;
        if file_size != expected_size {
            return Err(EngineError::Fat("文件或属性长度与清单不符".to_string()));
        }
        if expected_size == 0 {
            return Ok(FatFileRuns {
                size: 0,
                extents: Vec::new(),
            });
        }

        let mut cluster = read_u16_le(&record, 26) as u64;
        if self.geom.bits == 32 {
            cluster |= ((read_u16_le(&record, 20) & 0x0fff) as u64) << 16;
        }

        let cluster_limit = self.geom.clusters + 2;
        let needed_clusters = expected_size.div_ceil(self.geom.cluster_size);
        let eoc_min = self.geom.eoc_min();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut extents: Vec<(u64, u64, u64)> = Vec::new();
        let mut logical_pos: u64 = 0;

        for step in 0..needed_clusters {
            if !(2..cluster_limit).contains(&cluster) || !visited.insert(cluster) {
                return Err(EngineError::Fat("FAT 簇链中断或存在环形簇".to_string()));
            }
            let disk_off = self.geom.cluster_disk_offset(cluster);
            let chunk_len = (expected_size - logical_pos).min(self.geom.cluster_size);
            if let Some(last) = extents.last_mut()
                && last.1 + last.2 == disk_off
            {
                last.2 += chunk_len;
            } else {
                extents.push((logical_pos, disk_off, chunk_len));
            }
            logical_pos += chunk_len;

            if step + 1 < needed_clusters {
                let next = self.next_cluster(cluster)?;
                if next >= eoc_min || (next as u64) < 2 || (next as u64) >= cluster_limit {
                    return Err(EngineError::Fat("FAT 簇链长度短于文件声明大小".to_string()));
                }
                cluster = next as u64;
            }
        }

        Ok(FatFileRuns {
            size: expected_size,
            extents,
        })
    }

    /// Read exact bytes from a resolved FAT file using binary search over coalesced extents.
    pub fn read_file_at(
        &self,
        runs: &FatFileRuns,
        file_offset: u64,
        buf: &mut [u8],
    ) -> EngineResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = file_offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| EngineError::RandomRead("FAT 读取偏移溢出".to_string()))?;
        if end > runs.size {
            return Err(EngineError::RandomRead("原始文件内容短读".to_string()));
        }

        let mut pos = file_offset;
        let mut out_pos = 0usize;
        let mut idx = runs
            .extents
            .partition_point(|&(log_start, _, len)| log_start + len <= pos);

        while out_pos < buf.len() {
            let &(log_start, disk_off, ext_len) = runs
                .extents
                .get(idx)
                .ok_or_else(|| EngineError::RandomRead("FAT 区间定位越界".to_string()))?;
            let in_ext = pos - log_start;
            let take = ((ext_len - in_ext) as usize).min(buf.len() - out_pos);
            self.media
                .read_exact_at(disk_off + in_ext, &mut buf[out_pos..out_pos + take])?;
            pos += take as u64;
            out_pos += take;
            idx += 1;
        }
        Ok(())
    }
}
