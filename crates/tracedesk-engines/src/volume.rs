use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use lru::LruCache;

use crate::error::{EngineError, EngineResult};
use crate::fat::{FatFileRuns, FatVolume};
use crate::media::{MediaReader, open_media};
use crate::ntfs::{NtfsEntryData, NtfsVolume};
use crate::types::{ByteInterval, EntryReadPlan, InventoryEntry};

const ENTRY_CACHE_CAP: usize = 256;

enum CachedPartition {
    Ntfs(Arc<NtfsVolume>),
    Fat(FatVolume),
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EntryCacheKey {
    offset: u64,
    inode: String,
    size: u64,
    deleted: bool,
}

#[derive(Debug, Clone)]
enum ResolvedEntry {
    Ntfs(NtfsEntryData),
    Fat(FatFileRuns),
}

/// 进程内 64 位卷与文件随机读取器，支持基于 RAW 和 EWF1 介质的 NTFS（含稀疏运行段跳过
/// 及已删除 MFT 记录）与 FAT12/16/32（未删除的常规文件）。对于不支持、已压缩或已加密的属性
/// 以及已删除的 FAT 条目，均返回 [`EntryReadPlan::FallbackToIcat`]。
pub struct VolumeReader {
    media: Arc<dyn MediaReader>,
    partitions: HashMap<u64, CachedPartition>,
    entry_cache: LruCache<EntryCacheKey, Arc<ResolvedEntry>>,
}

impl VolumeReader {
    /// 打开 RAW 或 EWF1 镜像并初始化新的 [`VolumeReader`]。
    pub fn open(image: &Path) -> EngineResult<Self> {
        let media = open_media(image)?;
        Ok(Self::open_with_media(media))
    }

    /// 基于已有的线程安全 [`MediaReader`] 构造 [`VolumeReader`]。
    pub fn open_with_media(media: Arc<dyn MediaReader>) -> Self {
        Self {
            media,
            partitions: HashMap::new(),
            entry_cache: LruCache::new(NonZeroUsize::new(ENTRY_CACHE_CAP).expect("non-zero")),
        }
    }

    /// 派生一个工作线程专用的 [`VolumeReader`]：共享底层介质句柄及已解析的只读
    /// `Arc<NtfsVolume>` 元数据，避免每个工作线程和滚动窗口重复解析引导扇区与 `$MFT`。
    pub fn fork_worker(&self) -> Self {
        let mut partitions = HashMap::with_capacity(self.partitions.len());
        for (&offset, part) in &self.partitions {
            match part {
                CachedPartition::Ntfs(ntfs) => {
                    partitions.insert(offset, CachedPartition::Ntfs(Arc::clone(ntfs)));
                }
                CachedPartition::Unsupported => {
                    partitions.insert(offset, CachedPartition::Unsupported);
                }
                CachedPartition::Fat(_) => {}
            }
        }
        Self {
            media: Arc::clone(&self.media),
            partitions,
            entry_cache: LruCache::new(NonZeroUsize::new(ENTRY_CACHE_CAP).expect("non-zero")),
        }
    }

    /// 预先探测并缓存指定偏移处的分区元数据，供后续并行工作线程通过 [`Self::fork_worker`] 复用。
    pub fn prime_partition(&mut self, offset: u64) {
        let _ = self.ensure_partition(offset);
    }

    /// 返回底层 [`MediaReader`] 的引用。
    pub fn media(&self) -> &Arc<dyn MediaReader> {
        &self.media
    }

    fn ensure_partition(&mut self, offset: u64) -> &mut CachedPartition {
        if !self.partitions.contains_key(&offset) {
            let part = self.detect_partition(offset);
            self.partitions.insert(offset, part);
        }
        self.partitions.get_mut(&offset).expect("just inserted")
    }

    fn detect_partition(&self, offset: u64) -> CachedPartition {
        let Some(base) = offset.checked_mul(512) else {
            return CachedPartition::Unsupported;
        };
        let mut boot = [0u8; 512];
        if self.media.read_exact_at(base, &mut boot).is_err() {
            return CachedPartition::Unsupported;
        }
        if &boot[3..11] == b"NTFS    "
            && let Ok(ntfs) = NtfsVolume::open(Arc::clone(&self.media), offset)
        {
            return CachedPartition::Ntfs(Arc::new(ntfs));
        }
        if let Ok(fat) = FatVolume::open(Arc::clone(&self.media), offset) {
            return CachedPartition::Fat(fat);
        }
        CachedPartition::Unsupported
    }

    fn resolve_entry(&mut self, entry: &InventoryEntry) -> EngineResult<Arc<ResolvedEntry>> {
        if entry.directory || entry.extents.is_some() {
            return Err(EngineError::RandomRead("目录或空间区域不支持文件随机读".to_string()));
        }
        if !entry.deleted && !entry.mode.starts_with("r/") {
            return Err(EngineError::RandomRead("此记录需要 icat 恢复读取".to_string()));
        }
        if entry.deleted && !(entry.mode.starts_with("r/") || entry.mode.starts_with("-/r")) {
            return Err(EngineError::RandomRead("此删除记录不支持直接读取".to_string()));
        }

        let (ino_num, attr_type, attr_id) = parse_inode(&entry.inode)
            .ok_or_else(|| EngineError::RandomRead("无法定位文件属性".to_string()))?;

        let key = EntryCacheKey {
            offset: entry.offset,
            inode: entry.inode.clone(),
            size: entry.size,
            deleted: entry.deleted,
        };
        if let Some(cached) = self.entry_cache.get(&key) {
            return Ok(Arc::clone(cached));
        }

        let part = self.ensure_partition(entry.offset);
        let resolved = Arc::new(match part {
            CachedPartition::Ntfs(ntfs) => {
                let data = ntfs.resolve_entry(ino_num, attr_type, attr_id, entry.size)?;
                ResolvedEntry::Ntfs(data)
            }
            CachedPartition::Fat(fat) => {
                // 已删除的 FAT 记录始终回退到 `icat -r`。
                if entry.deleted || attr_type.is_some() {
                    return Err(EngineError::RandomRead(
                        "FAT 删除记录需回退 icat 恢复读取".to_string(),
                    ));
                }
                let runs = fat.resolve_regular_file(ino_num, entry.size)?;
                ResolvedEntry::Fat(runs)
            }
            CachedPartition::Unsupported => {
                return Err(EngineError::RandomRead(
                    "当前分区文件系统不支持进程内随机读，需回退 icat".to_string(),
                ));
            }
        });

        self.entry_cache.put(key, Arc::clone(&resolved));
        Ok(resolved)
    }

    /// 检查条目属性并计算需要扫描的非稀疏字节区间。
    ///
    /// 若遇到已压缩/已加密/异常的 NTFS 属性、空运行段的 NTFS 属性、FAT 已删除记录
    /// 或不受支持的文件系统，则返回 [`EntryReadPlan::FallbackToIcat`]。
    pub fn plan_entry(&mut self, entry: &InventoryEntry, needle: &[u8]) -> EntryReadPlan {
        let Ok(resolved) = self.resolve_entry(entry) else {
            return EntryReadPlan::FallbackToIcat;
        };
        match resolved.as_ref() {
            ResolvedEntry::Ntfs(data) => {
                let intervals = data.non_sparse_intervals(needle);
                EntryReadPlan::Direct {
                    intervals,
                    total_size: entry.size,
                }
            }
            ResolvedEntry::Fat(_) => {
                let intervals = if entry.size == 0 {
                    Vec::new()
                } else {
                    vec![ByteInterval {
                        start: 0,
                        end: entry.size,
                    }]
                };
                EntryReadPlan::Direct {
                    intervals,
                    total_size: entry.size,
                }
            }
        }
    }

    /// 从 `entry` 的 `file_offset` 处精确读取并填充至调用方提供的缓冲区 `buf`（避免每块重复分配）。
    pub fn read_entry_into(
        &mut self,
        entry: &InventoryEntry,
        file_offset: u64,
        buf: &mut [u8],
    ) -> EngineResult<()> {
        let resolved = self.resolve_entry(entry)?;
        if buf.is_empty() {
            if file_offset > entry.size {
                return Err(EngineError::RandomRead("读取偏移超出文件长度".to_string()));
            }
            return Ok(());
        }
        let part = self.ensure_partition(entry.offset);
        match (part, resolved.as_ref()) {
            (CachedPartition::Ntfs(ntfs), ResolvedEntry::Ntfs(data)) => {
                ntfs.read_entry_data_at(data, file_offset, buf)?;
            }
            (CachedPartition::Fat(fat), ResolvedEntry::Fat(runs)) => {
                fat.read_file_at(runs, file_offset, buf)?;
            }
            _ => {
                return Err(EngineError::RandomRead("分区与缓存条目类型不一致".to_string()));
            }
        }
        Ok(())
    }

    /// 从 `entry` 的 `file_offset` 处精确读取 `len` 字节。
    pub fn read_entry_at(
        &mut self,
        entry: &InventoryEntry,
        file_offset: u64,
        len: usize,
    ) -> EngineResult<Vec<u8>> {
        if len == 0 {
            self.read_entry_into(entry, file_offset, &mut [])?;
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; len];
        self.read_entry_into(entry, file_offset, &mut buf)?;
        Ok(buf)
    }
}

/// 解析 TSK inode 格式：`<mft_or_ino>` 或 `<mft>-<attr_type>-<attr_id>`。
pub(crate) fn parse_inode(inode: &str) -> Option<(u64, Option<u32>, Option<u16>)> {
    let mut parts = inode.split('-');
    let first = parts.next()?.parse::<u64>().ok()?;
    let second = match parts.next() {
        None => return Some((first, None, None)),
        Some(s) => s.parse::<u32>().ok()?,
    };
    let third = parts.next()?.parse::<u16>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((first, Some(second), Some(third)))
}
