//! Canonical inventory sorting, lazy directory tree indexing (with synthesized virtual
//! ancestor directories), pagination (100/page), large-directory grouping (>2048 by 256),
//! and multi-condition filtering (`core-contract.md` §3.5).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use tracedesk_engines::{InventoryEntry, entry_name, entry_status};

/// Default page size for paginated file listings.
pub const DEFAULT_PAGE_SIZE: usize = 100;
/// Threshold above which UI switches to paginated & lazy tree rendering.
pub const PAGING_THRESHOLD: usize = 1000;
/// Directory child count threshold above which tree children are grouped into buckets.
pub const TREE_GROUP_THRESHOLD: usize = 2048;
/// Number of children per bucket when a directory exceeds [`TREE_GROUP_THRESHOLD`].
pub const TREE_GROUP_SIZE: usize = 256;

/// Trim leading/trailing slashes from an in-image path.
#[inline]
pub fn normalize_scope_path(path: &str) -> String {
    path.replace('\\', "/").trim_matches('/').to_string()
}

/// Parent directory portion of a slash-separated path (equivalent to Python `path.rpartition('/')[0]`).
#[inline]
pub fn parent_dir(trimmed_path: &str) -> &str {
    trimmed_path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("")
}

/// Leaf name portion of a slash-separated path.
#[inline]
pub fn leaf_name(trimmed_path: &str) -> &str {
    trimmed_path
        .rsplit_once('/')
        .map(|(_, name)| name)
        .unwrap_or(trimmed_path)
}

/// Canonical sort comparator matching `forensic/core/browser_index.py::prepare`
/// and `core-contract.md` §3.5:
/// `(offset, path.matches('/').count(), mode.to_ascii_lowercase().starts_with("v/"), !directory, path, deleted)`.
pub fn cmp_canonical(a: &InventoryEntry, b: &InventoryEntry) -> std::cmp::Ordering {
    let a_depth = a.path.matches('/').count();
    let b_depth = b.path.matches('/').count();
    let a_sys = a.mode.len() >= 2 && a.mode.as_bytes()[..2].eq_ignore_ascii_case(b"v/");
    let b_sys = b.mode.len() >= 2 && b.mode.as_bytes()[..2].eq_ignore_ascii_case(b"v/");
    (
        a.offset,
        a_depth,
        a_sys,
        !a.directory,
        a.path.as_str(),
        a.deleted,
    )
        .cmp(&(
            b.offset,
            b_depth,
            b_sys,
            !b.directory,
            b.path.as_str(),
            b.deleted,
        ))
}

/// A single item inside a directory branch of the navigation tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeBranchItem {
    /// Normalized path (trimmed of leading/trailing `/`).
    pub path: String,
    /// Index into [`BrowserIndex::ordered`], or `None` for synthesized virtual ancestor folders.
    pub entry_index: Option<usize>,
}

/// Serializable node descriptor returned by lazy tree expansion (`get_tree_children`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeNodeDto {
    pub label: String,
    pub path: String,
    pub offset: u64,
    pub entry_id: Option<usize>,
    pub directory: bool,
    pub has_children: bool,
    pub is_group: bool,
    pub group_index: Option<usize>,
    pub deleted: bool,
    pub mode: String,
    pub inode: String,
}

/// Response for lazy tree expansion of `(offset, scope_path)` with optional bucket `group_index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeChildrenPage {
    pub nodes: Vec<TreeNodeDto>,
    pub grouped: bool,
    pub group_count: usize,
    pub total_children: usize,
}

/// Entry status filter mode for file browser and MCP queries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusFilter {
    #[default]
    All,
    /// Desktop browser "现存文件": non-deleted, non-directory, non-system (`v/` / `V/`).
    ActiveFile,
    /// MCP "active": `entry_status(entry) == "现存"`.
    ActiveStatus,
    /// Deleted records (`deleted == true`).
    Deleted,
    /// System regions and virtual directories (`mode` starts with `v/` or `V/`).
    System,
}

/// Multi-condition query filter for [`BrowserIndex::query_page`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrowserFilter {
    pub scope_offset: Option<u64>,
    /// Exact parent directory scope (matching desktop directory navigation).
    pub scope_path: Option<String>,
    /// Recursive path prefix scope (matching MCP `path_prefix`).
    pub path_prefix: Option<String>,
    pub suffix: String,
    pub keyword: String,
    pub status: StatusFilter,
    pub files_only: bool,
}

/// A single paginated query result referencing entries in [`BrowserIndex::ordered`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserPage {
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    pub entry_ids: Vec<usize>,
}

/// Located position of an entry within its parent directory scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryLocation {
    pub scope_offset: u64,
    pub scope_path: String,
    pub page: usize,
    pub index_in_page: usize,
}

/// Pre-indexed view over a case's inventory supporting fast directory lookup,
/// lazy tree expansion, large-directory grouping, and paginated multi-condition filtering.
#[derive(Debug, Clone, Default)]
pub struct BrowserIndex {
    ordered: Vec<InventoryEntry>,
    branches: HashMap<(u64, String), Vec<TreeBranchItem>>,
    children: HashMap<(u64, String), Vec<usize>>,
}

impl BrowserIndex {
    /// Build a [`BrowserIndex`] from an unsorted slice of [`InventoryEntry`] records.
    pub fn build(entries: &[InventoryEntry]) -> Self {
        let mut ordered = entries.to_vec();
        ordered.sort_by(cmp_canonical);

        let mut directories: HashSet<(u64, String)> = HashSet::new();
        for row in &ordered {
            if row.directory {
                directories.insert((row.offset, row.path.trim_matches('/').to_string()));
            }
        }

        let mut branches: HashMap<(u64, String), Vec<TreeBranchItem>> = HashMap::new();
        let mut children: HashMap<(u64, String), Vec<usize>> = HashMap::new();

        for (idx, row) in ordered.iter().enumerate() {
            let offset = row.offset;
            let trimmed = row.path.trim_matches('/');
            let mut parent = parent_dir(trimmed).to_string();

            children.entry((offset, parent.clone())).or_default().push(idx);
            branches
                .entry((offset, parent.clone()))
                .or_default()
                .push(TreeBranchItem {
                    path: trimmed.to_string(),
                    entry_index: Some(idx),
                });

            while !parent.is_empty() && !directories.contains(&(offset, parent.clone())) {
                directories.insert((offset, parent.clone()));
                let ancestor = parent_dir(&parent).to_string();
                branches
                    .entry((offset, ancestor.clone()))
                    .or_default()
                    .push(TreeBranchItem {
                        path: parent,
                        entry_index: None,
                    });
                parent = ancestor;
            }
        }

        Self {
            ordered,
            branches,
            children,
        }
    }

    /// Canonically ordered entries; indices in this slice serve as stable `entry_id` handles.
    pub fn ordered(&self) -> &[InventoryEntry] {
        &self.ordered
    }

    /// Look up an entry by its `entry_id` (index into [`Self::ordered`]).
    pub fn get(&self, entry_id: usize) -> Option<&InventoryEntry> {
        self.ordered.get(entry_id)
    }

    /// Whether the inventory size exceeds [`PAGING_THRESHOLD`].
    pub fn should_paginate(&self) -> bool {
        self.ordered.len() > PAGING_THRESHOLD
    }

    /// Raw branch items under `(offset, scope_path)` (including virtual ancestor folders).
    pub fn branch_items(&self, offset: u64, scope_path: &str) -> &[TreeBranchItem] {
        let key = (offset, normalize_scope_path(scope_path));
        self.branches.get(&key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Direct concrete child entry IDs under `(offset, scope_path)`.
    pub fn direct_children(&self, offset: u64, scope_path: &str) -> &[usize] {
        let key = (offset, normalize_scope_path(scope_path));
        self.children.get(&key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Lazily expand tree children for `(offset, scope_path)`.
    ///
    /// When a directory contains more than [`TREE_GROUP_THRESHOLD`] (2048) children and
    /// `group_index` is `None`, returns synthetic bucket nodes of [`TREE_GROUP_SIZE`] (256) items each.
    /// Passing `group_index = Some(g)` returns the concrete nodes in bucket `g`.
    pub fn tree_children(
        &self,
        offset: u64,
        scope_path: &str,
        group_index: Option<usize>,
    ) -> TreeChildrenPage {
        let norm_scope = normalize_scope_path(scope_path);
        let items = self.branch_items(offset, &norm_scope);
        let total_children = items.len();

        if total_children > TREE_GROUP_THRESHOLD && group_index.is_none() {
            let group_count = total_children.div_ceil(TREE_GROUP_SIZE);
            let mut nodes = Vec::with_capacity(group_count);
            for g in 0..group_count {
                let start = g * TREE_GROUP_SIZE;
                let end = (start + TREE_GROUP_SIZE).min(total_children);
                nodes.push(TreeNodeDto {
                    label: format!("条目 {}–{}", start + 1, end),
                    path: norm_scope.clone(),
                    offset,
                    entry_id: None,
                    directory: true,
                    has_children: true,
                    is_group: true,
                    group_index: Some(g),
                    deleted: false,
                    mode: String::new(),
                    inode: String::new(),
                });
            }
            return TreeChildrenPage {
                nodes,
                grouped: true,
                group_count,
                total_children,
            };
        }

        let slice = if let Some(g) = group_index {
            let start = g.saturating_mul(TREE_GROUP_SIZE);
            if start >= total_children {
                &items[0..0]
            } else {
                let end = (start + TREE_GROUP_SIZE).min(total_children);
                &items[start..end]
            }
        } else {
            items
        };

        let mut nodes = Vec::with_capacity(slice.len());
        for item in slice {
            let dto = match item.entry_index {
                Some(idx) => {
                    let row = &self.ordered[idx];
                    let mut name = entry_name(row);
                    if name.is_empty() {
                        name = "/".to_string();
                    }
                    if row.deleted {
                        let ino = if row.inode.is_empty() {
                            "—"
                        } else {
                            &row.inode
                        };
                        name.push_str(&format!("  [已删除 · {ino}]"));
                    }
                    let has_children =
                        row.directory && self.branches.contains_key(&(offset, item.path.clone()));
                    TreeNodeDto {
                        label: name,
                        path: item.path.clone(),
                        offset,
                        entry_id: Some(idx),
                        directory: row.directory,
                        has_children,
                        is_group: false,
                        group_index: None,
                        deleted: row.deleted,
                        mode: row.mode.clone(),
                        inode: row.inode.clone(),
                    }
                }
                None => {
                    let name = leaf_name(&item.path);
                    let has_children = self.branches.contains_key(&(offset, item.path.clone()));
                    TreeNodeDto {
                        label: if name.is_empty() {
                            "/".to_string()
                        } else {
                            name.to_string()
                        },
                        path: item.path.clone(),
                        offset,
                        entry_id: None,
                        directory: true,
                        has_children,
                        is_group: false,
                        group_index: None,
                        deleted: false,
                        mode: "V/V---------".to_string(),
                        inode: String::new(),
                    }
                }
            };
            nodes.push(dto);
        }

        TreeChildrenPage {
            nodes,
            grouped: false,
            group_count: 0,
            total_children,
        }
    }

    /// Filter entries according to [`BrowserFilter`] and return the requested 0-based page.
    pub fn query_page(
        &self,
        filter: &BrowserFilter,
        page: usize,
        page_size: usize,
    ) -> BrowserPage {
        let effective_page_size = page_size.max(1);
        let suffix_clean = {
            let s = filter.suffix.trim().to_lowercase();
            if !s.is_empty() && !s.starts_with('.') {
                format!(".{s}")
            } else {
                s
            }
        };
        let keyword_clean = filter.keyword.trim().to_lowercase();
        let prefix_clean = filter
            .path_prefix
            .as_deref()
            .map(normalize_scope_path)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase());

        let scope_path_norm = filter.scope_path.as_deref().map(normalize_scope_path);

        let candidate_ids: Vec<usize> =
            if let (Some(off), Some(sp)) = (filter.scope_offset, &scope_path_norm) {
                self.direct_children(off, sp).to_vec()
            } else {
                (0..self.ordered.len()).collect()
            };

        let matched: Vec<usize> = candidate_ids
            .into_iter()
            .filter(|&idx| {
                let row = &self.ordered[idx];
                if let Some(off) = filter.scope_offset
                    && row.offset != off
                {
                    return false;
                }
                if let Some(ref sp) = scope_path_norm
                    && parent_dir(row.path.trim_matches('/')) != sp.as_str()
                {
                    return false;
                }
                if filter.files_only && (row.directory || row.mode.starts_with("V/")) {
                    return false;
                }
                match filter.status {
                    StatusFilter::All => {}
                    StatusFilter::ActiveFile => {
                        if row.deleted
                            || row.directory
                            || (row.mode.len() >= 2
                                && row.mode.as_bytes()[..2].eq_ignore_ascii_case(b"v/"))
                        {
                            return false;
                        }
                    }
                    StatusFilter::ActiveStatus => {
                        if entry_status(row) != "现存" {
                            return false;
                        }
                    }
                    StatusFilter::Deleted => {
                        if !row.deleted {
                            return false;
                        }
                    }
                    StatusFilter::System => {
                        if !(row.mode.starts_with("v/") || row.mode.starts_with("V/")) {
                            return false;
                        }
                    }
                }
                if let Some(ref pfx) = prefix_clean {
                    let row_norm = normalize_scope_path(&row.path).to_lowercase();
                    if row_norm != *pfx && !row_norm.starts_with(&format!("{pfx}/")) {
                        return false;
                    }
                }
                if !suffix_clean.is_empty() && !row.path.to_lowercase().ends_with(&suffix_clean) {
                    return false;
                }
                if !keyword_clean.is_empty() {
                    let path_lc = row.path.to_lowercase();
                    let name_lc = entry_name(row).to_lowercase();
                    if !path_lc.contains(&keyword_clean) && !name_lc.contains(&keyword_clean) {
                        return false;
                    }
                }
                true
            })
            .collect();

        let total = matched.len();
        let total_pages = if total == 0 {
            1
        } else {
            total.div_ceil(effective_page_size)
        };
        let clamped_page = page.min(total_pages - 1);
        let start = clamped_page * effective_page_size;
        let end = (start + effective_page_size).min(total);
        let entry_ids = if start < total {
            matched[start..end].to_vec()
        } else {
            Vec::new()
        };

        BrowserPage {
            total,
            page: clamped_page,
            page_size: effective_page_size,
            total_pages,
            entry_ids,
        }
    }

    /// Locate an entry's parent directory scope and page coordinates.
    pub fn locate_entry(&self, entry_id: usize, page_size: usize) -> Option<EntryLocation> {
        let row = self.ordered.get(entry_id)?;
        let scope_path = parent_dir(row.path.trim_matches('/')).to_string();
        let siblings = self.direct_children(row.offset, &scope_path);
        let pos = siblings.iter().position(|&id| id == entry_id)?;
        let ps = page_size.max(1);
        Some(EntryLocation {
            scope_offset: row.offset,
            scope_path,
            page: pos / ps,
            index_in_page: pos % ps,
        })
    }
}
