//! Compact `u64` MACB timeline index with multi-core `rayon` parallel sorting & filtering
//! (`core-contract.md` §3.6, matching `forensic/core/timeline.py`).

use std::collections::BTreeSet;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracedesk_engines::{InventoryEntry, entry_status};

use crate::error::{CoreError, CoreResult};
use crate::formatting::{display_timestamp, format_unix_east8_stack};

/// Ordered MACB timestamp fields and their Chinese labels.
pub const TIMELINE_FIELDS: [(&str, &str); 4] = [
    ("mtime", "M 内容修改"),
    ("atime", "A 访问"),
    ("ctime", "C 元数据变更"),
    ("crtime", "B 创建"),
];

/// Normalize an event filter string accepting either full Chinese labels or `M`/`A`/`C`/`B` aliases.
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

/// ASCII case-insensitive substring check without heap allocations.
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

/// Single materialized timeline event row, preserving the 1-based global ascending sequence number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineRow {
    /// 1-based original ascending position in the unfiltered timeline (`original_index + 1`).
    pub number: usize,
    /// Formatted UTC+8 ISO-8601 timestamp.
    pub time: String,
    /// Chinese MACB event label (e.g. `"M 内容修改"`).
    pub event: String,
    pub path: String,
    pub inode: String,
    pub offset: u64,
    pub status: String,
}

/// Distinct available filter options derived from the timeline's underlying entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineFilterOptions {
    pub events: Vec<String>,
    pub statuses: Vec<String>,
    pub offsets: Vec<String>,
}

/// Filter criteria for [`TimelineIndex::matching`] and [`TimelineIndex::query_page`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimelineFilter {
    pub query: String,
    /// Full Chinese label or `M`/`A`/`C`/`B` alias.
    pub event: Option<String>,
    pub status: Option<String>,
    pub offset: Option<u64>,
}

/// Paginated timeline response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelinePage {
    pub total: usize,
    pub total_events: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    pub items: Vec<TimelineRow>,
}

/// Compact `u64`-encoded MACB timeline index over an inventory snapshot.
#[derive(Debug, Clone)]
pub struct TimelineIndex {
    entries: Vec<InventoryEntry>,
    /// Compact `entry_idx * 4 + field_idx` indices sorted ascending by Unix timestamp.
    positions: Vec<u64>,
}

impl TimelineIndex {
    /// Build and parallel-sort the compact MACB timeline from `entries` (skipping timestamps `<= 0`).
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
        // Stable multi-core parallel sort ascending by Unix timestamp.
        positions.par_sort_by_key(|&pos| {
            entry_field_timestamp(&entries[(pos / 4) as usize], (pos % 4) as usize)
        });
        Self { entries, positions }
    }

    /// Total number of MACB events in the timeline.
    #[inline]
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// Returns `true` if the timeline contains zero events.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    /// Raw compact `positions` slice (`entry_idx * 4 + field_idx`).
    pub fn positions(&self) -> &[u64] {
        &self.positions
    }

    /// Underlying entries slice.
    pub fn entries(&self) -> &[InventoryEntry] {
        &self.entries
    }

    /// Materialize a single [`TimelineRow`] at 0-based `original_index` (with 1-based `number`).
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

    /// Materialize all timeline rows in ascending order.
    pub fn to_vec(&self) -> Vec<TimelineRow> {
        (0..self.positions.len())
            .filter_map(|i| self.get(i))
            .collect()
    }

    /// Compute available filter dropdown options (`events`, `statuses`, `offsets`).
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

    /// Multi-core parallel filter returning matching 0-based indices into `self.positions`
    /// in ascending order.
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

        // Fast path: no filter at all -> all indices 0..len.
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
                            // Format partition offset on stack without heap allocation.
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

    /// Execute a filtered, optionally reversed, paginated timeline query while preserving
    /// 1-based global original sequence numbers.
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
