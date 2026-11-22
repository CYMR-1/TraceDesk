//! 基于 `rayon` 多核并行排序与过滤的紧凑 `u64` MACB 时间线索引
//! （对应 `core-contract.md` §3.6，与 `forensic/core/timeline.py` 保持一致）。

use std::collections::BTreeSet;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracedesk_engines::{InventoryEntry, entry_status};

use crate::error::{CoreError, CoreResult};
use crate::formatting::{display_timestamp, format_unix_east8_stack};

/// 有序 MACB 时间戳字段及其对应的中文标签。
pub const TIMELINE_FIELDS: [(&str, &str); 4] = [
    ("mtime", "M 内容修改"),
    ("atime", "A 访问"),
    ("ctime", "C 元数据变更"),
    ("crtime", "B 创建"),
];

/// 规范化事件筛选字符串，支持完整中文标签或 `M`/`A`/`C`/`B` 简写别名。
pub fn normalize_event_filter(event: &str) -> CoreResult<&'static str> {
    let trimmed = event.trim();
    match trimmed.to_ascii_uppercase().as_str() {
        "M" => return Ok(TIMELINE_FIELDS[0].1),
        "A" => return Ok(TIMELINE_FIELDS[1].1),
        "C" => return Ok(TIMELINE_FIELDS[2].1),
        "B" => return Ok(TIMELINE_FIELDS[3].1),
        _ => {}
    }
    for &(_, label) in &TIMELINE_FIELDS {
        if trimmed == label {
            return Ok(label);
        }
    }
    Err(CoreError::InvalidInput(format!(
        "无效的时间线事件筛选：{event}。可选：M / A / C / B 或 M 内容修改, A 访问, C 元数据变更, B 创建"
    )))
}

#[inline]
fn entry_field_timestamp(entry: &InventoryEntry, field_idx: usize) -> i64 {
    match field_idx {
        0 => entry.mtime,
        1 => entry.atime,
        2 => entry.ctime,
        3 => entry.crtime,
        _ => 0,
    }
}

/// 零堆分配的 ASCII 大小写不敏感子串匹配检查。
#[inline]
fn contains_ascii_icase(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if needle_lower.len() > haystack.len() {
        return false;
    }
    let first = needle_lower[0];
    let limit = haystack.len() - needle_lower.len();
    for i in 0..=limit {
        if haystack[i].to_ascii_lowercase() == first {
            let mut matched = true;
            for j in 1..needle_lower.len() {
                if haystack[i + j].to_ascii_lowercase() != needle_lower[j] {
                    matched = false;
                    break;
                }
            }
            if matched {
                return true;
            }
        }
    }
    false
}

/// 单条物化的时间线事件行，保留从 1 开始的全局升序序号。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineRow {
    /// 未筛选时间线中从 1 开始的原始升序位置（`original_index + 1`）。
    pub number: usize,
    /// 格式化后的 UTC+8 ISO-8601 时间戳。
    pub time: String,
    /// 中文 MACB 事件标签（例如 `"M 内容修改"`）。
    pub event: String,
    pub path: String,
    pub inode: String,
    pub offset: u64,
    pub status: String,
}

/// 从时间线底层条目提取的去重可用筛选选项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineFilterOptions {
    pub events: Vec<String>,
    pub statuses: Vec<String>,
    pub offsets: Vec<String>,
}

/// [`TimelineIndex::matching`] 与 [`TimelineIndex::query_page`] 使用的筛选条件。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimelineFilter {
    pub query: String,
    /// 完整中文标签或 `M`/`A`/`C`/`B` 别名。
    pub event: Option<String>,
    pub status: Option<String>,
    pub offset: Option<u64>,
}

/// 分页时间线查询响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelinePage {
    pub total: usize,
    pub total_events: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    pub items: Vec<TimelineRow>,
}

/// 基于清单快照构建的紧凑 `u64` 编码 MACB 时间线索引。
#[derive(Debug, Clone)]
pub struct TimelineIndex {
    entries: Vec<InventoryEntry>,
    /// 按 Unix 时间戳升序排列的紧凑索引（`entry_idx * 4 + field_idx`）。
    positions: Vec<u64>,
}

impl TimelineIndex {
    /// 从 `entries` 构建并并行排序紧凑 MACB 时间线（跳过 `<= 0` 的时间戳）。
    pub fn build(entries: Vec<InventoryEntry>) -> Self {
        let mut positions = Vec::with_capacity(entries.len().saturating_mul(3));
        for (idx, entry) in entries.iter().enumerate() {
            let base = (idx as u64) * 4;
            if entry.mtime > 0 {
                positions.push(base);
            }
            if entry.atime > 0 {
                positions.push(base + 1);
            }
            if entry.ctime > 0 {
                positions.push(base + 2);
            }
            if entry.crtime > 0 {
                positions.push(base + 3);
            }
        }
        // 按 Unix 时间戳执行稳定的多核并行升序排序。
        positions.par_sort_by_key(|&pos| {
            entry_field_timestamp(&entries[(pos / 4) as usize], (pos % 4) as usize)
        });
        Self { entries, positions }
    }

    /// 时间线中的 MACB 事件总数。
    #[inline]
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// 当时间线不包含任何事件时返回 `true`。
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    /// 原始紧凑 `positions` 切片（`entry_idx * 4 + field_idx`）。
    pub fn positions(&self) -> &[u64] {
        &self.positions
    }

    /// 底层条目切片。
    pub fn entries(&self) -> &[InventoryEntry] {
        &self.entries
    }

    /// 按从 0 开始的 `original_index` 物化单条 [`TimelineRow`]（`number` 从 1 开始）。
    pub fn get(&self, original_index: usize) -> Option<TimelineRow> {
        let pos = *self.positions.get(original_index)?;
        let entry = &self.entries[(pos / 4) as usize];
        let field_idx = (pos % 4) as usize;
        let ts = entry_field_timestamp(entry, field_idx);
        Some(TimelineRow {
            number: original_index + 1,
            time: display_timestamp(ts, false),
            event: TIMELINE_FIELDS[field_idx].1.to_string(),
            path: entry.path.clone(),
            inode: entry.inode.clone(),
            offset: entry.offset,
            status: entry_status(entry).to_string(),
        })
    }

    /// 按升序物化全部时间线行。
    pub fn to_vec(&self) -> Vec<TimelineRow> {
        (0..self.positions.len())
            .filter_map(|i| self.get(i))
            .collect()
    }

    /// 计算可用的筛选下拉选项（`events`、`statuses`、`offsets`）。
    pub fn filter_options(&self) -> TimelineFilterOptions {
        let mut seen_fields = [false; 4];
        let mut statuses: BTreeSet<&'static str> = BTreeSet::new();
        let mut offsets: BTreeSet<u64> = BTreeSet::new();

        for entry in &self.entries {
            let mut has_time = false;
            if entry.mtime > 0 {
                seen_fields[0] = true;
                has_time = true;
            }
            if entry.atime > 0 {
                seen_fields[1] = true;
                has_time = true;
            }
            if entry.ctime > 0 {
                seen_fields[2] = true;
                has_time = true;
            }
            if entry.crtime > 0 {
                seen_fields[3] = true;
                has_time = true;
            }
            if has_time {
                statuses.insert(entry_status(entry));
                offsets.insert(entry.offset);
            }
        }

        let events = TIMELINE_FIELDS
            .iter()
            .enumerate()
            .filter(|&(i, _)| seen_fields[i])
            .map(|(_, &(_, label))| label.to_string())
            .collect();
        let statuses = statuses.into_iter().map(str::to_string).collect();
        let offsets = offsets.into_iter().map(|o| o.to_string()).collect();
        TimelineFilterOptions {
            events,
            statuses,
            offsets,
        }
    }

    /// 多核并行过滤，按升序返回 `self.positions` 中匹配的从 0 开始索引列表。
    pub fn matching(&self, filter: &TimelineFilter) -> CoreResult<Vec<usize>> {
        let event_field_idx: Option<usize> = match filter.event.as_deref() {
            Some(ev) if !ev.trim().is_empty() => {
                let normalized = normalize_event_filter(ev)?;
                TIMELINE_FIELDS
                    .iter()
                    .position(|&(_, label)| label == normalized)
            }
            _ => None,
        };
        let status_filter = filter
            .status
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let offset_filter = filter.offset;
        let query_trimmed = filter.query.trim();
        let has_query = !query_trimmed.is_empty();
        let query_is_ascii = query_trimmed.is_ascii();
        let query_lower = query_trimmed.to_lowercase();
        let query_ascii_bytes = query_lower.as_bytes();

        // 快速路径：无任何筛选条件时直接返回 0..len 全部索引。
        if event_field_idx.is_none()
            && status_filter.is_none()
            && offset_filter.is_none()
            && !has_query
        {
            return Ok((0..self.positions.len()).collect());
        }

        let entries = &self.entries;
        let hits: Vec<usize> = self
            .positions
            .par_iter()
            .enumerate()
            .filter_map(|(index, &pos)| {
                let field_idx = (pos % 4) as usize;
                if let Some(expected_field) = event_field_idx
                    && field_idx != expected_field
                {
                    return None;
                }
                let entry = &entries[(pos / 4) as usize];
                if let Some(expected_offset) = offset_filter
                    && entry.offset != expected_offset
                {
                    return None;
                }
                let status = entry_status(entry);
                if let Some(expected_status) = status_filter
                    && status != expected_status
                {
                    return None;
                }
                if has_query {
                    let label = TIMELINE_FIELDS[field_idx].1;
                    let ts = entry_field_timestamp(entry, field_idx);
                    if query_is_ascii {
                        let mut matched = contains_ascii_icase(
                            entry.path.as_bytes(),
                            query_ascii_bytes,
                        ) || contains_ascii_icase(
                            entry.inode.as_bytes(),
                            query_ascii_bytes,
                        ) || contains_ascii_icase(
                            label.as_bytes(),
                            query_ascii_bytes,
                        );
                        if !matched {
                            // 在栈上格式化分区偏移，避免堆分配。
                            let mut off_buf = [0u8; 20];
                            let off_slice = format_u64_stack(entry.offset, &mut off_buf);
                            if contains_ascii_icase(off_slice, query_ascii_bytes) {
                                matched = true;
                            }
                        }
                        if !matched {
                            if let Some(mut ts_buf) = format_unix_east8_stack(ts) {
                                if contains_ascii_icase(&ts_buf, query_ascii_bytes) {
                                    matched = true;
                                } else {
                                    ts_buf[10] = b' ';
                                    if contains_ascii_icase(&ts_buf, query_ascii_bytes) {
                                        matched = true;
                                    }
                                }
                            } else {
                                let formatted = display_timestamp(ts, false);
                                if contains_ascii_icase(formatted.as_bytes(), query_ascii_bytes)
                                    || contains_ascii_icase(
                                        formatted.replace('T', " ").as_bytes(),
                                        query_ascii_bytes,
                                    )
                                {
                                    matched = true;
                                }
                            }
                        }
                        if !matched {
                            return None;
                        }
                    } else {
                        let formatted = display_timestamp(ts, false);
                        let matched = entry.path.to_lowercase().contains(&query_lower)
                            || entry.inode.to_lowercase().contains(&query_lower)
                            || entry.offset.to_string().contains(&query_lower)
                            || label.to_lowercase().contains(&query_lower)
                            || status.to_lowercase().contains(&query_lower)
                            || formatted.to_lowercase().contains(&query_lower)
                            || formatted
                                .replace('T', " ")
                                .to_lowercase()
                                .contains(&query_lower);
                        if !matched {
                            return None;
                        }
                    }
                }
                Some(index)
            })
            .collect();

        Ok(hits)
    }

    /// 执行带筛选、可选倒序的分页时间线查询，并保留从 1 开始的全局原始序号。
    pub fn query_page(
        &self,
        filter: &TimelineFilter,
        descending: bool,
        page: usize,
        page_size: usize,
    ) -> CoreResult<TimelinePage> {
        let matched = self.matching(filter)?;
        let total = matched.len();
        let ps = page_size.max(1);
        let total_pages = if total == 0 { 1 } else { total.div_ceil(ps) };
        let clamped_page = page.min(total_pages - 1);
        let start = clamped_page * ps;
        let end = (start + ps).min(total);

        let mut items = Vec::with_capacity(end.saturating_sub(start));
        if start < total {
            if descending {
                for i in start..end {
                    let orig_idx = matched[total - 1 - i];
                    if let Some(row) = self.get(orig_idx) {
                        items.push(row);
                    }
                }
            } else {
                for &orig_idx in &matched[start..end] {
                    if let Some(row) = self.get(orig_idx) {
                        items.push(row);
                    }
                }
            }
        }

        Ok(TimelinePage {
            total,
            total_events: self.positions.len(),
            page: clamped_page,
            page_size: ps,
            total_pages,
            items,
        })
    }
}

#[inline]
fn format_u64_stack(mut val: u64, buf: &mut [u8; 20]) -> &[u8] {
    if val == 0 {
        buf[19] = b'0';
        return &buf[19..20];
    }
    let mut i = 20usize;
    while val > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    &buf[i..20]
}
