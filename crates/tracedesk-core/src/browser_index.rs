//! 规范清单排序、延迟目录树索引（含合成的虚拟祖先目录）、分页（100 条/页）、
//! 大目录分桶（超过 2048 项按 256 项分组）与多条件过滤（对应 `core-contract.md` §3.5）。

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use tracedesk_engines::{InventoryEntry, entry_name, entry_status};

/// 分页文件列表的默认每页条数。
pub const DEFAULT_PAGE_SIZE: usize = 100;
/// UI 切换为分页与延迟树渲染的条目数阈值。
pub const PAGING_THRESHOLD: usize = 1000;
/// 目录子项数量超过该阈值时，树子节点将按桶分组展示。
pub const TREE_GROUP_THRESHOLD: usize = 2048;
/// 当目录子项超过 [`TREE_GROUP_THRESHOLD`] 时，每个分桶包含的子项数量。
pub const TREE_GROUP_SIZE: usize = 256;

/// 去除镜像内路径的首尾斜杠并将反斜杠统一转换为正斜杠。
#[inline]
pub fn normalize_scope_path(path: &str) -> String {
    path.replace('\\', "/").trim_matches('/').to_string()
}

/// 获取斜杠分隔路径的父目录部分（等价于 Python `path.rpartition('/')[0]`）。
#[inline]
pub fn parent_dir(trimmed_path: &str) -> &str {
    trimmed_path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("")
}

/// 获取斜杠分隔路径的末级名称部分。
#[inline]
pub fn leaf_name(trimmed_path: &str) -> &str {
    trimmed_path
        .rsplit_once('/')
        .map(|(_, name)| name)
        .unwrap_or(trimmed_path)
}

/// 规范排序比较器，与 `forensic/core/browser_index.py::prepare`
/// 及 `core-contract.md` §3.5 保持一致：
/// `(offset, path.matches('/').count(), mode.to_ascii_lowercase().starts_with("v/"), !directory, path, deleted)`。
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

/// 导航树某个目录分支下的单个项目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeBranchItem {
    /// 归一化路径（已去除首尾 `/`）。
    pub path: String,
    /// 在 [`BrowserIndex::ordered`] 中的索引；若为合成的虚拟祖先目录则为 `None`。
    pub entry_index: Option<usize>,
}

/// 延迟展开目录树（`get_tree_children`）返回的可序列化节点描述。
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

/// 针对 `(offset, scope_path)` 及可选分桶索引 `group_index` 的延迟树展开响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeChildrenPage {
    pub nodes: Vec<TreeNodeDto>,
    pub grouped: bool,
    pub group_count: usize,
    pub total_children: usize,
}

/// 文件浏览器与 MCP 查询使用的条目状态筛选模式。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusFilter {
    #[default]
    All,
    /// 桌面浏览器“现存文件”：未删除、非目录、非系统区域（`v/` / `V/`）。
    ActiveFile,
    /// MCP 的 `"active"`：`entry_status(entry) == "现存"`。
    ActiveStatus,
    /// 已删除记录（`deleted == true`）。
    Deleted,
    /// 系统区域与虚拟目录（`mode` 以 `v/` 或 `V/` 开头）。
    System,
}

/// [`BrowserIndex::query_page`] 使用的多条件查询过滤器。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrowserFilter {
    pub scope_offset: Option<u64>,
    /// 精确父目录范围（对应桌面端目录导航）。
    pub scope_path: Option<String>,
    /// 递归路径前缀范围（对应 MCP `path_prefix`）。
    pub path_prefix: Option<String>,
    pub suffix: String,
    pub keyword: String,
    pub status: StatusFilter,
    pub files_only: bool,
}

/// 单页查询结果，引用 [`BrowserIndex::ordered`] 中的条目索引。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserPage {
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    pub entry_ids: Vec<usize>,
}

/// 条目在其父目录范围中的定位坐标。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryLocation {
    pub scope_offset: u64,
    pub scope_path: String,
    pub page: usize,
    pub index_in_page: usize,
}

/// 针对案件清单的预索引视图，支持快速目录查找、
/// 延迟树展开、大目录分桶以及分页多条件过滤。
#[derive(Debug, Clone, Default)]
pub struct BrowserIndex {
    ordered: Vec<InventoryEntry>,
    branches: HashMap<(u64, String), Vec<TreeBranchItem>>,
    children: HashMap<(u64, String), Vec<usize>>,
}

impl BrowserIndex {
    /// 从未排序的 [`InventoryEntry`] 记录切片构建 [`BrowserIndex`]。
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

    /// 规范排序后的条目切片；该切片中的下标即稳定的 `entry_id` 句柄。
    pub fn ordered(&self) -> &[InventoryEntry] {
        &self.ordered
    }

    /// 根据 `entry_id`（[`Self::ordered`] 中的下标）查找对应条目。
    pub fn get(&self, entry_id: usize) -> Option<&InventoryEntry> {
        self.ordered.get(entry_id)
    }

    /// 清单条目数是否超过 [`PAGING_THRESHOLD`]。
    pub fn should_paginate(&self) -> bool {
        self.ordered.len() > PAGING_THRESHOLD
    }

    /// 获取 `(offset, scope_path)` 下的原始分支条目（含虚拟祖先目录）。
    pub fn branch_items(&self, offset: u64, scope_path: &str) -> &[TreeBranchItem] {
        let key = (offset, normalize_scope_path(scope_path));
        self.branches.get(&key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// 获取 `(offset, scope_path)` 下的直接实际子条目 ID 列表。
    pub fn direct_children(&self, offset: u64, scope_path: &str) -> &[usize] {
        let key = (offset, normalize_scope_path(scope_path));
        self.children.get(&key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// 延迟展开 `(offset, scope_path)` 的目录树子节点。
    ///
    /// 当目录包含超过 [`TREE_GROUP_THRESHOLD`]（2048）个子项且 `group_index` 为 `None` 时，
    /// 返回每桶 [`TREE_GROUP_SIZE`]（256）项的合成桶节点；
    /// 传入 `group_index = Some(g)` 时返回第 `g` 个分桶中的实际节点。
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

    /// 按 [`BrowserFilter`] 筛选条目并返回请求的从 0 开始的页数据。
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

    /// 定位条目所属的父目录范围及分页坐标。
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
