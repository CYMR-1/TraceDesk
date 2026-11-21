use std::collections::HashSet;
use std::sync::Arc;

use crate::error::{EngineError, EngineResult};
use crate::media::MediaReader;
use crate::types::ByteInterval;

const ATTR_TYPE_ATTRIBUTE_LIST: u32 = 0x20;
const ATTR_TYPE_DATA: u32 = 0x80;
const ATTR_TYPE_END: u32 = 0xFFFF_FFFF;

const ATTR_FLAG_COMPRESSED: u16 = 0x0001;
const ATTR_FLAG_ENCRYPTED: u16 = 0x4000;
#[allow(dead_code)]
const ATTR_FLAG_SPARSE: u16 = 0x8000;

#[inline]
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Single contiguous cluster run in a non-resident NTFS attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NtfsDataRun {
    pub vcn: u64,
    pub len_clusters: u64,
    /// `Some(lcn)` for allocated on-disk clusters, `None` for sparse (zero-filled) runs.
    pub lcn: Option<u64>,
}

/// Resolved NTFS file/attribute payload ready for fast random reads & sparse-interval planning.
#[derive(Debug, Clone)]
pub(crate) enum NtfsEntryData {
    Resident {
        bytes: Vec<u8>,
    },
    NonResident {
        data_size: u64,
        initialized_size: u64,
        cluster_size: u64,
        runs: Vec<NtfsDataRun>,
    },
}

impl NtfsEntryData {
    pub fn size(&self) -> u64 {
        match self {
            Self::Resident { bytes } => bytes.len() as u64,
            Self::NonResident { data_size, .. } => *data_size,
        }
    }

    /// Compute non-sparse scan intervals matching `forensic/core/search_worker.py::_non_sparse_intervals`.
    ///
    /// - Resident attributes always return `[0, size)`.
    /// - When `needle` is empty or all zero bytes, sparse regions are NOT skipped (`[0, size)`).
    /// - Non-sparse runs are extended backward by `needle.len().saturating_sub(1)` bytes so
    ///   cross-boundary matches starting in the trailing zeroes before a run are never missed.
    pub fn non_sparse_intervals(&self, needle: &[u8]) -> Vec<ByteInterval> {
        let size = self.size();
        if size == 0 {
            return Vec::new();
        }
        match self {
            Self::Resident { .. } => vec![ByteInterval { start: 0, end: size }],
            Self::NonResident {
                data_size,
                initialized_size,
                cluster_size,
                runs,
            } => {
                let all_zero_needle = needle.is_empty() || needle.iter().all(|&b| b == 0);
                let has_sparse = runs.iter().any(|r| r.lcn.is_none()) || *initialized_size < *data_size;
                if all_zero_needle || !has_sparse {
                    return vec![ByteInterval {
                        start: 0,
                        end: *data_size,
                    }];
                }

                let overlap = needle.len().saturating_sub(1) as u64;
                let valid_end = (*initialized_size).min(*data_size);
                let mut intervals: Vec<ByteInterval> = Vec::new();

                for run in runs {
                    if run.lcn.is_none() {
                        continue;
                    }
                    let Some(run_start) = run.vcn.checked_mul(*cluster_size) else {
                        continue;
                    };
                    let Some(run_end_raw) = run
                        .vcn
                        .checked_add(run.len_clusters)
                        .and_then(|v| v.checked_mul(*cluster_size))
                    else {
                        continue;
                    };
                    let h_lo = run_start.saturating_sub(overlap);
                    let h_hi = run_end_raw.min(valid_end);
                    if h_lo >= h_hi {
                        continue;
                    }
                    if let Some(last) = intervals.last_mut()
                        && h_lo <= last.end
                    {
                        last.end = last.end.max(h_hi);
                    } else {
                        intervals.push(ByteInterval {
                            start: h_lo,
                            end: h_hi,
                        });
                    }
                }
                intervals
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedAttribute {
    attr_type: u32,
    attr_id: u16,
    attr_flags: u16,
    name_utf16: Vec<u16>,
    body: ParsedAttrBody,
}

#[derive(Debug, Clone)]
enum ParsedAttrBody {
    Resident(Vec<u8>),
    NonResident {
        lowest_vcn: u64,
        data_size: u64,
        initialized_size: u64,
        compression_unit: u16,
        runs: Vec<NtfsDataRun>,
    },
}

#[derive(Debug, Clone)]
struct AttrListEntry {
    attr_type: u32,
    attr_id: u16,
    starting_vcn: u64,
    mft_record: u64,
    name_utf16: Vec<u16>,
}

/// Native read-only NTFS volume reader supporting MFT fixups, `$ATTRIBUTE_LIST`,
/// non-resident multi-run & sparse data streams, and deleted (unallocated) MFT records.
pub(crate) struct NtfsVolume {
    media: Arc<dyn MediaReader>,
    partition_base: u64,
    cluster_size: u64,
    mft_record_size: usize,
    mft_runs: Vec<NtfsDataRun>,
    mft_size: u64,
}

impl NtfsVolume {
    pub fn open(media: Arc<dyn MediaReader>, partition_offset: u64) -> EngineResult<Self> {
        let partition_base = partition_offset
            .checked_mul(512)
            .ok_or_else(|| EngineError::Ntfs("NTFS 分区偏移溢出".to_string()))?;
        let mut boot = [0u8; 512];
        media.read_exact_at(partition_base, &mut boot)?;
        if &boot[3..11] != b"NTFS    " || boot[510..512] != [0x55, 0xaa] {
            return Err(EngineError::Ntfs("不是有效的 NTFS 引导扇区".to_string()));
        }

        let bytes_per_sector = read_u16_le(&boot, 11) as u64;
        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return Err(EngineError::Ntfs("NTFS 扇区大小无效".to_string()));
        }
        let spc_raw = boot[13] as i8;
        let sectors_per_cluster = if spc_raw > 0 {
            spc_raw as u64
        } else if spc_raw < 0 && (-spc_raw) <= 24 {
            1u64 << ((-spc_raw) as u32)
        } else {
            return Err(EngineError::Ntfs("NTFS 每簇扇区数无效".to_string()));
        };
        let cluster_size = bytes_per_sector
            .checked_mul(sectors_per_cluster)
            .ok_or_else(|| EngineError::Ntfs("NTFS 簇大小溢出".to_string()))?;

        let mft_lcn = read_u64_le(&boot, 48);
        let cpmr = boot[64] as i8;
        let mft_record_size = if cpmr > 0 {
            (cpmr as u64)
                .checked_mul(cluster_size)
                .and_then(|v| usize::try_from(v).ok())
        } else if cpmr < 0 && (-cpmr) <= 16 {
            Some(1usize << ((-cpmr) as u32))
        } else {
            None
        }
        .ok_or_else(|| EngineError::Ntfs("NTFS MFT 记录大小无效".to_string()))?;

        if !(512..=65536).contains(&mft_record_size)
            || !mft_record_size.is_multiple_of(512)
        {
            return Err(EngineError::Ntfs(format!(
                "NTFS MFT 记录大小不受支持：{mft_record_size}"
            )));
        }

        // Bootstrap by reading MFT record 0 ($MFT) directly from `mft_lcn`.
        let mft0_disk_off = partition_base
            .checked_add(
                mft_lcn
                    .checked_mul(cluster_size)
                    .ok_or_else(|| EngineError::Ntfs("NTFS $MFT 偏移溢出".to_string()))?,
            )
            .ok_or_else(|| EngineError::Ntfs("NTFS $MFT 偏移溢出".to_string()))?;

        let mut mft0 = vec![0u8; mft_record_size];
        media.read_exact_at(mft0_disk_off, &mut mft0)?;
        apply_usa_fixup(&mut mft0)?;

        let attrs0 = parse_record_attributes(&mft0)?;
        // First locate $MFT's initial $DATA attribute in record 0.
        let mut initial_runs: Option<(Vec<NtfsDataRun>, u64)> = None;
        for attr in &attrs0 {
            if attr.attr_type == ATTR_TYPE_DATA
                && attr.name_utf16.is_empty()
                && let ParsedAttrBody::NonResident {
                    data_size, runs, ..
                } = &attr.body
            {
                initial_runs = Some((runs.clone(), *data_size));
                break;
            }
        }

        let (mft_runs, mft_size) = match initial_runs {
            Some(v) => v,
            None => {
                // Rare case: $MFT's $DATA lives exclusively in an $ATTRIBUTE_LIST extension record
                // located near the beginning of $MFT. Bootstrap a small provisional single-run map.
                let provisional_clusters = 16u64;
                let temp = Self {
                    media: Arc::clone(&media),
                    partition_base,
                    cluster_size,
                    mft_record_size,
                    mft_runs: vec![NtfsDataRun {
                        vcn: 0,
                        len_clusters: provisional_clusters,
                        lcn: Some(mft_lcn),
                    }],
                    mft_size: provisional_clusters * cluster_size,
                };
                match temp.resolve_from_record_0_attr_list(&attrs0)? {
                    NtfsEntryData::NonResident {
                        data_size, runs, ..
                    } => (runs, data_size),
                    _ => return Err(EngineError::Ntfs("无法定位 $MFT 的 $DATA 区间".to_string())),
                }
            }
        };

        let mut volume = Self {
            media,
            partition_base,
            cluster_size,
            mft_record_size,
            mft_runs,
            mft_size,
        };

        // If $MFT itself has an $ATTRIBUTE_LIST, collect all $DATA extents across extension records.
        if attrs0.iter().any(|a| a.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
            && let Ok(NtfsEntryData::NonResident {
                data_size, runs, ..
            }) = volume.resolve_from_record_0_attr_list(&attrs0)
            && !runs.is_empty()
        {
            volume.mft_runs = runs;
            volume.mft_size = data_size;
        }

        Ok(volume)
    }

    fn resolve_from_record_0_attr_list(
        &self,
        attrs0: &[ParsedAttribute],
    ) -> EngineResult<NtfsEntryData> {
        self.resolve_via_attribute_list(0, attrs0, Some(ATTR_TYPE_DATA), None)
    }

    fn read_mft_record(&self, mft_num: u64) -> EngineResult<Vec<u8>> {
        let v_off = mft_num
            .checked_mul(self.mft_record_size as u64)
            .ok_or_else(|| EngineError::Ntfs("MFT 记录号溢出".to_string()))?;
        if v_off
            .checked_add(self.mft_record_size as u64)
            .is_none_or(|end| end > self.mft_size)
        {
            return Err(EngineError::Ntfs(format!("MFT 记录 {mft_num} 超出 $MFT 范围")));
        }

        let mut buf = vec![0u8; self.mft_record_size];
        self.read_from_runs(&self.mft_runs, self.mft_size, v_off, &mut buf, true)?;
        apply_usa_fixup(&mut buf)?;
        Ok(buf)
    }

    fn read_from_runs(
        &self,
        runs: &[NtfsDataRun],
        initialized_size: u64,
        file_offset: u64,
        buf: &mut [u8],
        reject_sparse: bool,
    ) -> EngineResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let mut pos = file_offset;
        let mut out_pos = 0usize;

        while out_pos < buf.len() {
            if pos >= initialized_size {
                if reject_sparse {
                    return Err(EngineError::Ntfs("读取偏移超出有效初始化长度".to_string()));
                }
                buf[out_pos..].fill(0);
                break;
            }
            let remaining_valid = (initialized_size - pos) as usize;
            let want = (buf.len() - out_pos).min(remaining_valid);
            let target_vcn = pos / self.cluster_size;
            let in_cluster = pos % self.cluster_size;

            let run_idx = runs.partition_point(|r| r.vcn + r.len_clusters <= target_vcn);
            let run = runs
                .get(run_idx)
                .filter(|r| target_vcn >= r.vcn && target_vcn < r.vcn + r.len_clusters)
                .ok_or_else(|| EngineError::Ntfs(format!("缺少 VCN {target_vcn} 对应的数据区间")))?;

            let run_byte_off = (target_vcn - run.vcn) * self.cluster_size + in_cluster;
            let run_total_bytes = run
                .len_clusters
                .checked_mul(self.cluster_size)
                .ok_or_else(|| EngineError::Ntfs("数据区间字节长度溢出".to_string()))?;
            let avail = (run_total_bytes - run_byte_off) as usize;
            let take = want.min(avail);

            match run.lcn {
                Some(lcn) => {
                    let disk_off = self
                        .partition_base
                        .checked_add(
                            lcn.checked_mul(self.cluster_size)
                                .and_then(|v| v.checked_add(run_byte_off))
                                .ok_or_else(|| EngineError::Ntfs("NTFS 物理偏移溢出".to_string()))?,
                        )
                        .ok_or_else(|| EngineError::Ntfs("NTFS 物理偏移溢出".to_string()))?;
                    self.media
                        .read_exact_at(disk_off, &mut buf[out_pos..out_pos + take])?;
                }
                None => {
                    if reject_sparse {
                        return Err(EngineError::Ntfs("MFT 记录落在稀疏区间内".to_string()));
                    }
                    buf[out_pos..out_pos + take].fill(0);
                }
            }

            pos += take as u64;
            out_pos += take;
        }
        Ok(())
    }

    /// Resolve an MFT entry's data attribute (active or deleted MFT record).
    ///
    /// Returns `Err` for compressed, encrypted, missing, size-mismatched, or empty-run attributes
    /// so `VolumeReader` cleanly falls back to `icat`.
    pub fn resolve_entry(
        &self,
        mft_num: u64,
        attr_type: Option<u32>,
        attr_id: Option<u16>,
        expected_size: u64,
    ) -> EngineResult<NtfsEntryData> {
        let record = self.read_mft_record(mft_num)?;
        let attrs = parse_record_attributes(&record)?;

        let data = if attrs.iter().any(|a| a.attr_type == ATTR_TYPE_ATTRIBUTE_LIST) {
            match self.resolve_via_attribute_list(mft_num, &attrs, attr_type, attr_id) {
                Ok(d) => d,
                Err(_) => self.resolve_direct_attributes(&attrs, attr_type, attr_id)?,
            }
        } else {
            self.resolve_direct_attributes(&attrs, attr_type, attr_id)?
        };

        if data.size() != expected_size {
            return Err(EngineError::Ntfs(format!(
                "NTFS 属性长度与清单不符：实际 {}，清单 {}",
                data.size(),
                expected_size
            )));
        }
        Ok(data)
    }

    fn resolve_direct_attributes(
        &self,
        attrs: &[ParsedAttribute],
        target_type: Option<u32>,
        target_id: Option<u16>,
    ) -> EngineResult<NtfsEntryData> {
        let wanted_type = target_type.unwrap_or(ATTR_TYPE_DATA);
        let matched = attrs.iter().find(|a| {
            if a.attr_type != wanted_type {
                return false;
            }
            match target_id {
                Some(id) => a.attr_id == id,
                None => a.name_utf16.is_empty(),
            }
        });
        let attr = matched.ok_or_else(|| EngineError::Ntfs("未找到目标 NTFS 属性".to_string()))?;
        self.attr_to_entry_data(attr)
    }

    fn attr_to_entry_data(&self, attr: &ParsedAttribute) -> EngineResult<NtfsEntryData> {
        if (attr.attr_flags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_ENCRYPTED)) != 0 {
            return Err(EngineError::Ntfs(
                "压缩或加密 NTFS 属性需回退 icat".to_string(),
            ));
        }
        match &attr.body {
            ParsedAttrBody::Resident(bytes) => Ok(NtfsEntryData::Resident {
                bytes: bytes.clone(),
            }),
            ParsedAttrBody::NonResident {
                lowest_vcn,
                data_size,
                initialized_size,
                compression_unit,
                runs,
            } => {
                if *lowest_vcn != 0 || (*compression_unit != 0 && (attr.attr_flags & ATTR_FLAG_COMPRESSED) != 0) {
                    return Err(EngineError::Ntfs("非首段或压缩属性需回退 icat".to_string()));
                }
                if runs.is_empty() {
                    return Err(EngineError::Ntfs("非常驻属性无数据区间，回退 icat".to_string()));
                }
                Ok(NtfsEntryData::NonResident {
                    data_size: *data_size,
                    initialized_size: *initialized_size,
                    cluster_size: self.cluster_size,
                    runs: runs.clone(),
                })
            }
        }
    }

    fn resolve_via_attribute_list(
        &self,
        base_mft_num: u64,
        base_attrs: &[ParsedAttribute],
        target_type: Option<u32>,
        target_id: Option<u16>,
    ) -> EngineResult<NtfsEntryData> {
        let list_attr = base_attrs
            .iter()
            .find(|a| a.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
            .ok_or_else(|| EngineError::Ntfs("缺少 $ATTRIBUTE_LIST".to_string()))?;

        let list_bytes = match &list_attr.body {
            ParsedAttrBody::Resident(b) => b.clone(),
            ParsedAttrBody::NonResident {
                data_size,
                initialized_size,
                runs,
                ..
            } => {
                if *data_size > 16 * 1024 * 1024 {
                    return Err(EngineError::Ntfs("$ATTRIBUTE_LIST 异常过大".to_string()));
                }
                let mut buf = vec![0u8; *data_size as usize];
                self.read_from_runs(runs, *initialized_size, 0, &mut buf, false)?;
                buf
            }
        };

        let entries = parse_attribute_list(&list_bytes)?;
        let wanted_type = target_type.unwrap_or(ATTR_TYPE_DATA);

        // Locate the base extent (`starting_vcn == 0`) matching `(wanted_type, target_id or unnamed)`.
        let base_entry = entries
            .iter()
            .find(|e| {
                e.attr_type == wanted_type
                    && e.starting_vcn == 0
                    && match target_id {
                        Some(id) => e.attr_id == id,
                        None => e.name_utf16.is_empty(),
                    }
            })
            .ok_or_else(|| EngineError::Ntfs("$ATTRIBUTE_LIST 中未找到目标属性".to_string()))?;

        let target_name = &base_entry.name_utf16;
        let mut extents: Vec<&AttrListEntry> = entries
            .iter()
            .filter(|e| e.attr_type == wanted_type && &e.name_utf16 == target_name)
            .collect();
        extents.sort_by_key(|e| e.starting_vcn);

        let mut merged_runs: Vec<NtfsDataRun> = Vec::new();
        let mut data_size: Option<u64> = None;
        let mut initialized_size: Option<u64> = None;
        let mut seen_records: HashSet<u64> = HashSet::new();
        let mut loaded_records: Vec<(u64, Vec<ParsedAttribute>)> = Vec::new();

        for ext in &extents {
            if seen_records.insert(ext.mft_record) {
                if ext.mft_record == base_mft_num {
                    loaded_records.push((base_mft_num, base_attrs.to_vec()));
                } else {
                    let rec_bytes = self.read_mft_record(ext.mft_record)?;
                    let base_ref = read_u64_le(&rec_bytes, 32) & 0x0000_FFFF_FFFF_FFFF;
                    if base_ref != base_mft_num {
                        return Err(EngineError::Ntfs(
                            "扩展 MFT 记录基础引用不匹配，回退 icat".to_string(),
                        ));
                    }
                    let rec_attrs = parse_record_attributes(&rec_bytes)?;
                    loaded_records.push((ext.mft_record, rec_attrs));
                }
            }
        }

        for ext in extents {
            let (_, rec_attrs) = loaded_records
                .iter()
                .find(|(num, _)| *num == ext.mft_record)
                .ok_or_else(|| EngineError::Ntfs("扩展记录缺失".to_string()))?;

            let attr = rec_attrs
                .iter()
                .find(|a| {
                    a.attr_type == ext.attr_type
                        && a.attr_id == ext.attr_id
                        && a.name_utf16 == ext.name_utf16
                })
                .ok_or_else(|| EngineError::Ntfs("扩展 MFT 中未找到对应属性段".to_string()))?;

            if (attr.attr_flags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_ENCRYPTED)) != 0 {
                return Err(EngineError::Ntfs(
                    "压缩或加密 NTFS 属性需回退 icat".to_string(),
                ));
            }
            match &attr.body {
                ParsedAttrBody::Resident(bytes) => {
                    return Ok(NtfsEntryData::Resident {
                        bytes: bytes.clone(),
                    });
                }
                ParsedAttrBody::NonResident {
                    lowest_vcn,
                    data_size: ds,
                    initialized_size: is,
                    runs,
                    ..
                } => {
                    if *lowest_vcn == 0 {
                        data_size = Some(*ds);
                        initialized_size = Some(*is);
                    }
                    merged_runs.extend_from_slice(runs);
                }
            }
        }

        merged_runs.sort_by_key(|r| r.vcn);
        let ds = data_size.ok_or_else(|| EngineError::Ntfs("缺少起始 VCN 0 属性段".to_string()))?;
        let is = initialized_size.unwrap_or(ds);
        if merged_runs.is_empty() {
            return Err(EngineError::Ntfs("非常驻属性无数据区间，回退 icat".to_string()));
        }

        Ok(NtfsEntryData::NonResident {
            data_size: ds,
            initialized_size: is,
            cluster_size: self.cluster_size,
            runs: merged_runs,
        })
    }

    /// Read exact bytes from a resolved [`NtfsEntryData`] at `file_offset`.
    pub fn read_entry_data_at(
        &self,
        data: &NtfsEntryData,
        file_offset: u64,
        buf: &mut [u8],
    ) -> EngineResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = file_offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| EngineError::RandomRead("NTFS 读取偏移溢出".to_string()))?;
        if end > data.size() {
            return Err(EngineError::RandomRead("原始文件内容短读".to_string()));
        }

        match data {
            NtfsEntryData::Resident { bytes } => {
                let start = file_offset as usize;
                buf.copy_from_slice(&bytes[start..start + buf.len()]);
                Ok(())
            }
            NtfsEntryData::NonResident {
                initialized_size,
                runs,
                ..
            } => self.read_from_runs(runs, *initialized_size, file_offset, buf, false),
        }
    }
}

/// Apply NTFS Update Sequence Array (USA) fixups to a raw MFT record buffer.
fn apply_usa_fixup(record: &mut [u8]) -> EngineResult<()> {
    if record.len() < 48 || &record[0..4] != b"FILE" {
        return Err(EngineError::Ntfs("无效的 MFT 记录魔数".to_string()));
    }
    let usa_offset = read_u16_le(record, 4) as usize;
    let usa_count = read_u16_le(record, 6) as usize;
    if usa_count < 1 || usa_offset + usa_count * 2 > record.len() {
        return Err(EngineError::Ntfs("MFT USA 修复数组越界".to_string()));
    }
    let usn = [record[usa_offset], record[usa_offset + 1]];
    let sectors = record.len() / 512;
    if usa_count - 1 < sectors {
        return Err(EngineError::Ntfs("MFT USA 扇区修复项不足".to_string()));
    }
    for i in 1..=sectors {
        let sector_end = i * 512 - 2;
        if record[sector_end] != usn[0] || record[sector_end + 1] != usn[1] {
            return Err(EngineError::Ntfs("MFT USA 更新序列号校验失败".to_string()));
        }
        record[sector_end] = record[usa_offset + i * 2];
        record[sector_end + 1] = record[usa_offset + i * 2 + 1];
    }
    Ok(())
}

/// Parse all attributes inside a fixed-up MFT record.
fn parse_record_attributes(record: &[u8]) -> EngineResult<Vec<ParsedAttribute>> {
    let first_attr = read_u16_le(record, 20) as usize;
    let used_size = (read_u32_le(record, 24) as usize).min(record.len());
    if first_attr < 42 || first_attr >= used_size {
        return Err(EngineError::Ntfs("MFT 首个属性偏移无效".to_string()));
    }

    let mut attrs = Vec::new();
    let mut pos = first_attr;
    while pos + 8 <= used_size {
        let attr_type = read_u32_le(record, pos);
        if attr_type == ATTR_TYPE_END {
            break;
        }
        let attr_len = read_u32_le(record, pos + 4) as usize;
        if attr_len < 16 || pos + attr_len > used_size {
            return Err(EngineError::Ntfs("MFT 属性长度越界".to_string()));
        }
        let non_resident = record[pos + 8] != 0;
        let name_len = record[pos + 9] as usize;
        let name_offset = read_u16_le(record, pos + 10) as usize;
        let attr_flags = read_u16_le(record, pos + 12);
        let attr_id = read_u16_le(record, pos + 14);

        let mut name_utf16 = Vec::with_capacity(name_len);
        if name_len > 0 {
            let name_end = name_offset + name_len * 2;
            if name_end > attr_len {
                return Err(EngineError::Ntfs("MFT 属性名称越界".to_string()));
            }
            for i in 0..name_len {
                name_utf16.push(read_u16_le(record, pos + name_offset + i * 2));
            }
        }

        let body = if !non_resident {
            if attr_len < 24 {
                return Err(EngineError::Ntfs("常驻属性头过短".to_string()));
            }
            let value_len = read_u32_le(record, pos + 16) as usize;
            let value_offset = read_u16_le(record, pos + 20) as usize;
            if value_offset + value_len > attr_len {
                return Err(EngineError::Ntfs("常驻属性数据越界".to_string()));
            }
            ParsedAttrBody::Resident(
                record[pos + value_offset..pos + value_offset + value_len].to_vec(),
            )
        } else {
            if attr_len < 64 {
                return Err(EngineError::Ntfs("非常驻属性头过短".to_string()));
            }
            let lowest_vcn = read_u64_le(record, pos + 16);
            let runlist_offset = read_u16_le(record, pos + 32) as usize;
            let compression_unit = read_u16_le(record, pos + 34);
            let data_size = read_u64_le(record, pos + 48);
            let initialized_size = read_u64_le(record, pos + 56);
            if runlist_offset > attr_len {
                return Err(EngineError::Ntfs("非常驻属性 runlist 偏移越界".to_string()));
            }
            let runs = parse_data_runs(&record[pos + runlist_offset..pos + attr_len], lowest_vcn)?;
            ParsedAttrBody::NonResident {
                lowest_vcn,
                data_size,
                initialized_size,
                compression_unit,
                runs,
            }
        };

        attrs.push(ParsedAttribute {
            attr_type,
            attr_id,
            attr_flags,
            name_utf16,
            body,
        });
        pos += attr_len;
    }

    Ok(attrs)
}

/// Decode NTFS runlist bytes into a list of [`NtfsDataRun`] entries.
fn parse_data_runs(bytes: &[u8], lowest_vcn: u64) -> EngineResult<Vec<NtfsDataRun>> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut cur_vcn = lowest_vcn;
    let mut cur_lcn: i64 = 0;

    while pos < bytes.len() {
        let header = bytes[pos];
        if header == 0 {
            break;
        }
        pos += 1;
        let len_size = (header & 0x0f) as usize;
        let off_size = ((header >> 4) & 0x0f) as usize;
        if len_size == 0 || len_size > 8 || off_size > 8 || pos + len_size + off_size > bytes.len()
        {
            return Err(EngineError::Ntfs("NTFS data run 编码无效".to_string()));
        }

        let mut run_len: u64 = 0;
        for i in 0..len_size {
            run_len |= (bytes[pos + i] as u64) << (i * 8);
        }
        pos += len_size;

        let lcn = if off_size == 0 {
            None
        } else {
            let mut delta: i64 = 0;
            for i in 0..off_size {
                delta |= (bytes[pos + i] as i64) << (i * 8);
            }
            // Sign-extend if top bit of the last byte is set.
            if off_size < 8 && (bytes[pos + off_size - 1] & 0x80) != 0 {
                delta |= !0i64 << (off_size * 8);
            }
            pos += off_size;
            cur_lcn = cur_lcn
                .checked_add(delta)
                .ok_or_else(|| EngineError::Ntfs("NTFS LCN 累加溢出".to_string()))?;
            if cur_lcn < 0 {
                return Err(EngineError::Ntfs("NTFS LCN 出现负值".to_string()));
            }
            Some(cur_lcn as u64)
        };

        if run_len > 0 {
            runs.push(NtfsDataRun {
                vcn: cur_vcn,
                len_clusters: run_len,
                lcn,
            });
            cur_vcn = cur_vcn
                .checked_add(run_len)
                .ok_or_else(|| EngineError::Ntfs("NTFS VCN 累加溢出".to_string()))?;
        }
    }

    Ok(runs)
}

fn parse_attribute_list(bytes: &[u8]) -> EngineResult<Vec<AttrListEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos + 26 <= bytes.len() {
        let attr_type = read_u32_le(bytes, pos);
        let rec_len = read_u16_le(bytes, pos + 4) as usize;
        if rec_len < 26 || pos + rec_len > bytes.len() {
            return Err(EngineError::Ntfs("$ATTRIBUTE_LIST 项长度越界".to_string()));
        }
        let name_len = bytes[pos + 6] as usize;
        let name_offset = bytes[pos + 7] as usize;
        let starting_vcn = read_u64_le(bytes, pos + 8);
        let mft_ref = read_u64_le(bytes, pos + 16);
        let mft_record = mft_ref & 0x0000_FFFF_FFFF_FFFF;
        let attr_id = read_u16_le(bytes, pos + 24);

        let mut name_utf16 = Vec::with_capacity(name_len);
        if name_len > 0 {
            if name_offset + name_len * 2 > rec_len {
                return Err(EngineError::Ntfs("$ATTRIBUTE_LIST 属性名越界".to_string()));
            }
            for i in 0..name_len {
                name_utf16.push(read_u16_le(bytes, pos + name_offset + i * 2));
            }
        }

        entries.push(AttrListEntry {
            attr_type,
            attr_id,
            starting_vcn,
            mft_record,
            name_utf16,
        });
        pos += rec_len;
    }
    Ok(entries)
}
