/**
 * 模块 1：文件浏览页 (files + export + file_tools 右键菜单)
 * - 左侧懒加载目录树（镜像 → 分区 → / 根目录 → 目录/文件/256 分组）
 * - 右上筛选栏 + 面包屑 + 9 列文件列表 + 分页器（>1000 项分页，每页 100 项，双击跳页）
 * - 右下内容预览（文本 9 编码 / 图片 / 十六进制）+ 导出所选文件按钮
 * - 右键菜单：导出所选文件 / 记录取证发现 / 计算哈希值（SHA-256）/ 校验一致性… / 单文件检索内容…
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { tauriApi } from '../api/tauri';
import { ContextMenu, type ContextMenuItem } from '../components/ContextMenu';
import { EntryIcon, inferEntryIconKind, UiIcon } from '../components/Icons';
import { Pagination } from '../components/Pagination';
import { PreviewPane } from '../components/PreviewPane';
import { SplitPane } from '../components/SplitPane';
import { VirtualTable, type VirtualColumn } from '../components/VirtualTable';
import { canExportEntry, type FeatureRegistry } from '../features/registry';
import type { CaseSnapshot, EntryView, TreeNodeDto } from '../types/ipc';
import { assetUrl, formatBytes, formatError } from '../utils/assets';

const PAGE_SIZE = 100;
const PAGING_THRESHOLD = 1000;

interface TreeBranchState {
  loaded: boolean;
  loading: boolean;
  children: TreeNodeDto[];
}

interface FileBrowserModuleProps {
  snapshot: CaseSnapshot | null;
  registry: FeatureRegistry;
  busy: boolean;
  scanningPartitions: boolean;
  selectedEntry: EntryView | null;
  onSelectEntry: (entry: EntryView | null) => void;
  onDetailChange: (detail: string) => void;
  onScanPartitions: () => void;
  onCancelScan: () => void;
  onBrowseDirectory: (offset: number, inode: string | null, path: string) => Promise<EntryView[] | null>;
  onExportEntry: (entry: EntryView) => void;
  onRecordNote: (entry: EntryView) => void;
  onHashEntry: (entry: EntryView) => void;
  onCompareEntry: (entry: EntryView) => void;
  onSearchInFile: (entry: EntryView) => void;
}

export const FileBrowserModule: React.FC<FileBrowserModuleProps> = ({
  snapshot,
  registry,
  busy,
  scanningPartitions,
  selectedEntry,
  onSelectEntry,
  onDetailChange,
  onScanPartitions,
  onCancelScan,
  onBrowseDirectory,
  onExportEntry,
  onRecordNote,
  onHashEntry,
  onCompareEntry,
  onSearchInFile,
}) => {
  const [scopeOffset, setScopeOffset] = useState<number | null>(null);
  const [scopePath, setScopePath] = useState<string | null>(null);
  const [suffix, setSuffix] = useState('');
  const [keyword, setKeyword] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'deleted'>('all');
  const [appliedSuffix, setAppliedSuffix] = useState('');
  const [appliedKeyword, setAppliedKeyword] = useState('');
  const [filterSeq, setFilterSeq] = useState(0);
  const pendingLogFilterRef = useRef(false);

  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [items, setItems] = useState<EntryView[]>([]);
  const [loadingList, setLoadingList] = useState(false);

  // 左侧懒加载目录树状态
  const [expandedIds, setExpandedIds] = useState<Set<string>>(() => new Set(['__image__']));
  const [selectedTreeId, setSelectedTreeId] = useState<string>('__image__');
  const [branches, setBranches] = useState<Record<string, TreeBranchState>>({});
  const [ancestors, setAncestors] = useState<Record<string, string | null>>({});

  // 右键菜单状态
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; entry: EntryView } | null>(null);

  const evidence = snapshot?.evidence ?? null;
  const isLargeImage = Boolean(evidence && (evidence.largeImage ?? evidence.large_image));
  const isQuickMode = Boolean(snapshot?.browsingDirectories);
  const partitions = evidence?.partitions ?? [];
  const scanMap = useMemo(() => {
    const map = new Map<number, { status: string; count?: number; error?: string }>();
    for (const s of snapshot?.partitionScans ?? []) {
      map.set(s.offset, s);
    }
    return map;
  }, [snapshot?.partitionScans]);

  const imageName = useMemo(() => {
    if (!evidence?.path) return '尚未加载镜像';
    const parts = evidence.path.split(/[\\/]/);
    return parts[parts.length - 1] || evidence.path;
  }, [evidence?.path]);

  // 案件或镜像结构变更时才重置目录树与范围（切换标签或记笔记/导出不清空展开状态与筛选）
  const partitionScansSummary = useMemo(
    () =>
      (snapshot?.partitionScans ?? [])
        .map((s) => `${s.offset}:${s.status}:${s.count ?? ''}`)
        .join(','),
    [snapshot?.partitionScans]
  );
  const caseIdentity = `${snapshot?.id ?? ''}|${evidence?.path ?? ''}|${snapshot?.inventoryCount ?? 0}|${snapshot?.browsingDirectories ? 'q' : 'f'}|${partitionScansSummary}`;
  const prevIdentityRef = useRef('');

  const loadTreeBranch = useCallback(
    async (branchKey: string, offset: number, path: string, groupIndex?: number) => {
      setBranches((prev) => {
        if (prev[branchKey]?.loading) return prev;
        return {
          ...prev,
          [branchKey]: { loaded: prev[branchKey]?.loaded ?? false, loading: true, children: prev[branchKey]?.children ?? [] },
        };
      });
      try {
        const res = await tauriApi.getTreeChildren({
          offset,
          scopePath: path,
          groupIndex,
        });
        setBranches((prev) => ({
          ...prev,
          [branchKey]: { loaded: true, loading: false, children: res.nodes },
        }));
      } catch {
        setBranches((prev) => ({
          ...prev,
          [branchKey]: { loaded: true, loading: false, children: [] },
        }));
      }
    },
    []
  );

  useEffect(() => {
    if (prevIdentityRef.current === caseIdentity) return;
    prevIdentityRef.current = caseIdentity;

    setBranches({});
    setScopeOffset(null);
    setScopePath(null);
    setSuffix('');
    setKeyword('');
    setAppliedSuffix('');
    setAppliedKeyword('');
    setStatusFilter('all');
    setPage(0);
    setSelectedTreeId('__image__');

    const initialExpanded = new Set<string>(['__image__']);
    for (const part of partitions) {
      initialExpanded.add(`part:${part.offset}`);
      const scan = scanMap.get(part.offset);
      if (scan?.status !== 'error') {
        const rootKey = `dir:${part.offset}:`;
        initialExpanded.add(rootKey);
        if (evidence) {
          void loadTreeBranch(rootKey, part.offset, '');
        }
      }
    }
    setExpandedIds(initialExpanded);
  }, [caseIdentity, partitions, scanMap, evidence, loadTreeBranch]);

  // 记录大镜像快速浏览时的父目录 inode 路径
  useEffect(() => {
    if (snapshot?.quickLocation) {
      const { offset, inode, path } = snapshot.quickLocation;
      setAncestors((prev) => ({ ...prev, [`${offset}:${path}`]: inode }));
    }
  }, [snapshot?.quickLocation]);

  // 查询当前分页文件列表（一次性消费 pendingLogFilterRef，避免翻页/切目录重复写 FILE_FILTER 审计记录）
  const fetchFilesPage = useCallback(
    async (targetPage: number) => {
      const shouldLogFilter = pendingLogFilterRef.current;
      pendingLogFilterRef.current = false;
      if (!snapshot || !evidence) {
        setItems([]);
        setTotal(0);
        setTotalPages(1);
        return;
      }
      setLoadingList(true);
      try {
        const res = await tauriApi.queryFilesPage({
          scopeOffset: isQuickMode ? snapshot.quickLocation?.offset ?? scopeOffset : scopeOffset,
          scopePath: isQuickMode ? snapshot.quickLocation?.path ?? '' : scopePath,
          suffix: appliedSuffix,
          keyword: appliedKeyword,
          status: statusFilter,
          page: targetPage,
          pageSize: PAGE_SIZE,
          logFilter: shouldLogFilter,
        });
        setItems(res.items);
        setTotal(res.total);
        setPage(res.page);
        setTotalPages(Math.max(1, res.totalPages));
        if (selectedEntry && !res.items.some((i) => i.entryId === selectedEntry.entryId)) {
          onSelectEntry(null);
        }
      } catch (err) {
        onDetailChange(`读取文件列表失败：${formatError(err)}`);
        setItems([]);
        setTotal(0);
        setTotalPages(1);
      } finally {
        setLoadingList(false);
      }
    },
    [
      snapshot,
      evidence,
      isQuickMode,
      scopeOffset,
      scopePath,
      appliedSuffix,
      appliedKeyword,
      statusFilter,
      selectedEntry,
      onSelectEntry,
      onDetailChange,
    ]
  );

  useEffect(() => {
    void fetchFilesPage(page);
  }, [
    snapshot?.id,
    snapshot?.inventoryCount,
    snapshot?.quickLocation?.offset,
    snapshot?.quickLocation?.path,
    evidence?.path,
    partitionScansSummary,
    scopeOffset,
    scopePath,
    appliedSuffix,
    appliedKeyword,
    statusFilter,
    page,
    filterSeq,
  ]);

  const handleApplyFilter = () => {
    pendingLogFilterRef.current = true;
    setAppliedSuffix(suffix);
    setAppliedKeyword(keyword);
    setPage(0);
    setFilterSeq((n) => n + 1);
  };

  const handleResetFilter = () => {
    pendingLogFilterRef.current = false;
    setSuffix('');
    setKeyword('');
    setAppliedSuffix('');
    setAppliedKeyword('');
    setStatusFilter('all');
    setPage(0);
    setFilterSeq((n) => n + 1);
  };

  const toggleTreeExpand = (nodeId: string, offset?: number, path?: string, groupIndex?: number) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
        if (offset !== undefined && path !== undefined && !branches[nodeId]?.loaded) {
          void loadTreeBranch(nodeId, offset, path, groupIndex);
        }
      }
      return next;
    });
  };

  const handleExpandAll = () => {
    const next = new Set<string>(['__image__']);
    for (const p of partitions) {
      next.add(`part:${p.offset}`);
      const rootKey = `dir:${p.offset}:`;
      next.add(rootKey);
      if (!branches[rootKey]?.loaded) {
        void loadTreeBranch(rootKey, p.offset, '');
      }
    }
    for (const [key, branch] of Object.entries(branches)) {
      next.add(key);
      for (const child of branch.children) {
        if (child.kind === 'directory' && child.offset !== undefined && child.scopePath !== undefined) {
          const ck = `dir:${child.offset}:${child.scopePath}`;
          next.add(ck);
          if (!branches[ck]?.loaded) {
            void loadTreeBranch(ck, child.offset, child.scopePath);
          }
        }
      }
    }
    setExpandedIds(next);
  };

  const handleCollapseAll = () => {
    setExpandedIds(new Set(['__image__']));
  };

  const handleParentDirectory = () => {
    if (!snapshot?.quickLocation) return;
    const { offset, path } = snapshot.quickLocation;
    const idx = path.lastIndexOf('/');
    const parent = idx >= 0 ? path.slice(0, idx) : '';
    const parentInode = ancestors[`${offset}:${parent}`] ?? null;
    void onBrowseDirectory(offset, parentInode, parent);
  };

  const handleSelectRow = useCallback(
    (entry: EntryView) => {
      onSelectEntry(entry);
      onDetailChange(
        `${entry.path}  ·  ${entry.status}  ·  inode ${entry.inode || '—'}  ·  ${entry.size} 字节  ·  分区偏移 ${entry.offset}`
      );
    },
    [onSelectEntry, onDetailChange]
  );

  const handleDoubleClickRow = useCallback(
    (entry: EntryView) => {
      if (!entry.directory) return;
      const cleanPath = entry.path.replace(/^\/+|\/+$/g, '');
      if (isQuickMode) {
        void onBrowseDirectory(entry.offset, entry.inode || null, cleanPath);
        return;
      }
      setScopeOffset(entry.offset);
      setScopePath(cleanPath);
      setSelectedTreeId(`dir:${entry.offset}:${cleanPath}`);
      setPage(0);
      onSelectEntry(null);
      handleResetFilter();
    },
    [isQuickMode, onBrowseDirectory, onSelectEntry]
  );

  const handleTreeNodeClick = async (node: TreeNodeDto, nodeId: string) => {
    setSelectedTreeId(nodeId);
    if (node.kind === 'image') {
      setScopeOffset(null);
      setScopePath(null);
      setPage(0);
      onSelectEntry(null);
      onDetailChange('双击右侧目录进入；选择文件查看内容。');
      return;
    }
    if (node.kind === 'partition' && node.offset !== undefined) {
      const scan = scanMap.get(node.offset);
      if (scan?.status === 'error') {
        onDetailChange(`此分区无法读取：${scan.error || '未知错误'}`);
        onSelectEntry(null);
        return;
      }
      if (isQuickMode) {
        void onBrowseDirectory(node.offset, null, '');
        return;
      }
      setScopeOffset(node.offset);
      setScopePath(null);
      setPage(0);
      onSelectEntry(null);
      return;
    }
    if ((node.kind === 'root' || node.kind === 'directory') && node.offset !== undefined) {
      const targetPath = (node.scopePath ?? '').replace(/^\/+|\/+$/g, '');
      if (isQuickMode) {
        void onBrowseDirectory(node.offset, node.inode ?? null, targetPath);
        return;
      }
      setScopeOffset(node.offset);
      setScopePath(targetPath);
      setPage(0);
      onSelectEntry(null);
      if (!expandedIds.has(nodeId)) {
        toggleTreeExpand(nodeId, node.offset, targetPath);
      }
      return;
    }
    if (node.kind === 'group' && node.offset !== undefined) {
      toggleTreeExpand(nodeId, node.offset, node.scopePath ?? '', node.groupIndex);
      return;
    }
    if (node.kind === 'file' && node.entryId) {
      try {
        const loc = await tauriApi.locateFileInScope({ entryId: node.entryId });
        setScopeOffset(loc.scopeOffset);
        setScopePath(loc.scopePath);
        setSuffix('');
        setKeyword('');
        setAppliedSuffix('');
        setAppliedKeyword('');
        setStatusFilter('all');
        setPage(loc.page);
        const pageRes = await tauriApi.queryFilesPage({
          scopeOffset: loc.scopeOffset,
          scopePath: loc.scopePath,
          suffix: '',
          keyword: '',
          status: 'all',
          page: loc.page,
          pageSize: PAGE_SIZE,
        });
        setItems(pageRes.items);
        setTotal(pageRes.total);
        setTotalPages(Math.max(1, pageRes.totalPages));
        const found = pageRes.items.find((e) => e.entryId === node.entryId) ?? pageRes.items[loc.indexInPage];
        if (found) {
          handleSelectRow(found);
        }
      } catch {
        // 忽略定位失败
      }
    }
  };

  // 递归渲染左侧目录树
  const renderTreeChildren = (nodes: TreeNodeDto[], depth: number): React.ReactNode =>
    nodes.map((node) => {
      const nodeId =
        node.kind === 'directory'
          ? `dir:${node.offset}:${node.scopePath ?? ''}`
          : node.kind === 'group'
            ? `grp:${node.offset}:${node.scopePath ?? ''}:${node.groupIndex ?? 0}`
            : node.id;
      const expanded = expandedIds.has(nodeId);
      const branch = branches[nodeId];
      const isSelected = selectedTreeId === nodeId;

      return (
        <React.Fragment key={nodeId}>
          <div
            className={`td-tree-row ${isSelected ? 'td-tree-row--selected' : ''}`}
            style={{ paddingLeft: 6 + depth * 14 }}
            title={node.tooltip ?? node.label}
            onClick={() => void handleTreeNodeClick(node, nodeId)}
            onContextMenu={(e) => {
              if (node.kind === 'file' && node.entryId) {
                e.preventDefault();
                const existing = items.find((item) => item.entryId === node.entryId);
                if (existing) {
                  handleSelectRow(existing);
                  setContextMenu({ x: e.clientX, y: e.clientY, entry: existing });
                }
              }
            }}
          >
            {node.hasChildren ? (
              <button
                type="button"
                className="td-tree-toggle"
                onClick={(e) => {
                  e.stopPropagation();
                  toggleTreeExpand(nodeId, node.offset, node.scopePath ?? '', node.groupIndex);
                }}
                aria-label={expanded ? '折叠' : '展开'}
              >
                <img
                  src={assetUrl(expanded ? 'assets/branch-open.svg' : 'assets/branch-closed.svg')}
                  alt=""
                />
              </button>
            ) : (
              <span style={{ width: 18, flexShrink: 0 }} />
            )}
            <span className="td-tree-icon">
              <EntryIcon kind={node.iconKind || (node.kind === 'file' ? 'file' : 'folder')} size={15} />
            </span>
            <span className={`td-tree-label ${node.deleted ? 'td-tree-label--deleted' : ''}`}>
              {node.label}
            </span>
          </div>
          {node.hasChildren && expanded && (
            <>
              {branch?.loading && (
                <div
                  className="td-tree-row td-muted-text"
                  style={{ paddingLeft: 24 + (depth + 1) * 14, fontSize: 11.5 }}
                >
                  正在加载…
                </div>
              )}
              {branch?.loaded && renderTreeChildren(branch.children, depth + 1)}
            </>
          )}
        </React.Fragment>
      );
    });

  // 文件列表 9 列定义
  const fileColumns = useMemo<VirtualColumn<EntryView>[]>(
    () => [
      {
        key: 'name',
        label: '文件名称 / 镜像内路径',
        width: 280,
        minWidth: 160,
        getText: (e) => e.name || '/',
        getTooltip: (e) => `${e.path}\n分区偏移 ${e.offset} 扇区`,
        renderCell: (e) => (
          <>
            <EntryIcon kind={inferEntryIconKind(e)} size={15} />
            <span className="td-vtable-cell-text">{e.name || '/'}</span>
          </>
        ),
      },
      {
        key: 'status',
        label: '状态',
        width: 118,
        minWidth: 84,
        pill: true,
        getText: (e) => e.status,
      },
      {
        key: 'size',
        label: '字节数',
        width: 118,
        minWidth: 76,
        align: 'center',
        mono: true,
        getText: (e) => formatBytes(e.size),
      },
      {
        key: 'inode',
        label: 'inode',
        width: 112,
        minWidth: 70,
        align: 'center',
        mono: true,
        getText: (e) => e.inode || '—',
      },
      {
        key: 'mtime',
        label: 'M 修改 (UTC+8)',
        width: 162,
        minWidth: 120,
        mono: true,
        getText: (e) => e.mtime || '—',
      },
      {
        key: 'atime',
        label: 'A 访问 (UTC+8)',
        width: 162,
        minWidth: 120,
        mono: true,
        getText: (e) => e.atime || '—',
      },
      {
        key: 'ctime',
        label: 'C 变更 (UTC+8)',
        width: 162,
        minWidth: 120,
        mono: true,
        tooltip: 'C 为元数据变更时间。FAT 不保存此时间；创建时间请查看 B 列。',
        getText: (e) => e.ctime || '—',
      },
      {
        key: 'crtime',
        label: 'B 创建 (UTC+8)',
        width: 162,
        minWidth: 120,
        mono: true,
        getText: (e) => e.crtime || '—',
      },
      {
        key: 'offset',
        label: '分区偏移（扇区）',
        width: 132,
        minWidth: 96,
        mono: true,
        subtle: true,
        getText: (e) => String(e.offset),
      },
    ],
    []
  );

  // 右键菜单构造（遵循 FeatureRegistry 装配清单）
  const contextMenuItems = useMemo<ContextMenuItem[]>(() => {
    if (!contextMenu || busy) return [];
    const { entry } = contextMenu;
    if (entry.directory) return [];
    const previewActions = registry.actionsAt('preview');
    const menuActions = registry.actionsAt('file_menu');
    const all = [...previewActions, ...menuActions].filter(
      (action) => !action.acceptsEntry || action.acceptsEntry(entry)
    );
    return all.map((action) => ({
      key: action.key,
      label: action.title,
      onClick: () => {
        if (action.key === 'export') onExportEntry(entry);
        else if (action.key === 'file_note') onRecordNote(entry);
        else if (action.key === 'file_hash') onHashEntry(entry);
        else if (action.key === 'compare_file') onCompareEntry(entry);
        else if (action.key === 'search_in_file') onSearchInFile(entry);
      },
    }));
  }, [
    contextMenu,
    busy,
    registry,
    onExportEntry,
    onRecordNote,
    onHashEntry,
    onCompareEntry,
    onSearchInFile,
  ]);

  const showQuickParent = Boolean(isQuickMode && snapshot?.quickLocation?.path);
  const showNavContext = Boolean(isLargeImage || showQuickParent);

  const breadcrumbText = useMemo(() => {
    if (!evidence) return '加载镜像后自动展示所有分区';
    if (isQuickMode) {
      const loc = snapshot?.quickLocation;
      return loc ? `${imageName}  /  分区 ${loc.offset}  /  ${loc.path || '/'}` : `${imageName}  /  选择分区`;
    }
    const partLabel = scopeOffset === null ? '所有分区' : `分区偏移 ${scopeOffset}`;
    const pathLabel = scopePath === null ? '全部条目（含子目录）' : `/${scopePath}`;
    return `${imageName}  /  ${partLabel}  /  ${pathLabel}`;
  }, [evidence, isQuickMode, snapshot?.quickLocation, imageName, scopeOffset, scopePath]);

  const inventoryTotal = snapshot?.inventoryCount ?? total;
  const showPagination = total > PAGING_THRESHOLD || totalPages > 1;
  const resultCountText = isQuickMode
    ? `当前目录 ${inventoryTotal} 项 · 匹配 ${total} 项`
    : `当前范围 ${total} 项 · 完整清单 ${inventoryTotal} 项 · 时间 UTC+8`;

  const treeFooterText = !evidence
    ? '尚未读取文件树'
    : isQuickMode
      ? '按目录读取 · 全案搜索和时间线可使用完整文件索引'
      : `${partitions.length} 个分区 · 完整清单 ${inventoryTotal} 项\n${
          inventoryTotal > PAGING_THRESHOLD ? '展开目录可查看全部子项' : '含目录、删除记录与系统区域'
        }`;

  const canExportSelected = Boolean(
    !busy && selectedEntry && canExportEntry(selectedEntry) && registry.hasFeature('export')
  );

  const leftNavPane = (
    <div className="td-nav-panel">
      <div className="td-nav-header">
        <div className="td-section-title">数据源 / 完整文件树</div>
        <div className="td-nav-header-btns">
          <button
            type="button"
            className="td-btn td-btn--compact"
            disabled={busy || !evidence}
            onClick={handleExpandAll}
          >
            <UiIcon name="expand" size={12} color="var(--text-secondary)" />
            全部展开
          </button>
          <button
            type="button"
            className="td-btn td-btn--compact"
            disabled={busy || !evidence}
            onClick={handleCollapseAll}
          >
            <UiIcon name="collapse" size={12} color="var(--text-secondary)" />
            全部折叠
          </button>
        </div>
      </div>

      {showNavContext && (
        <div className="td-nav-context">
          {showQuickParent && (
            <button
              type="button"
              className="td-btn td-btn--soft"
              disabled={busy}
              onClick={handleParentDirectory}
            >
              <UiIcon name="folder_up" size={14} color="var(--accent-soft-text)" />
              返回上级目录
            </button>
          )}
          {isLargeImage && (
            <button
              type="button"
              className={`td-btn ${scanningPartitions ? 'td-btn--warning' : 'td-btn--soft'}`}
              disabled={busy && !scanningPartitions}
              onClick={() => (scanningPartitions ? onCancelScan() : onScanPartitions())}
            >
              <UiIcon
                name={scanningPartitions ? 'warning' : 'index'}
                size={14}
                color={scanningPartitions ? 'var(--warn-fg)' : 'var(--accent-soft-text)'}
              />
              {scanningPartitions
                ? '取消建立索引'
                : isQuickMode
                  ? '建立完整文件索引'
                  : '重新建立文件索引'}
            </button>
          )}
        </div>
      )}

      <div className="td-nav-tree" role="tree" aria-label="数据源文件树">
        <div
          className={`td-tree-row ${selectedTreeId === '__image__' ? 'td-tree-row--selected' : ''}`}
          style={{ paddingLeft: 6 }}
          title={evidence?.path ?? '尚未加载镜像'}
          onClick={() =>
            void handleTreeNodeClick(
              {
                id: '__image__',
                label: imageName,
                kind: 'image',
                iconKind: 'disk',
                hasChildren: partitions.length > 0,
              },
              '__image__'
            )
          }
        >
          {partitions.length > 0 ? (
            <button
              type="button"
              className="td-tree-toggle"
              onClick={(e) => {
                e.stopPropagation();
                toggleTreeExpand('__image__');
              }}
            >
              <img
                src={assetUrl(
                  expandedIds.has('__image__') ? 'assets/branch-open.svg' : 'assets/branch-closed.svg'
                )}
                alt=""
              />
            </button>
          ) : (
            <span style={{ width: 18, flexShrink: 0 }} />
          )}
          <span className="td-tree-icon">
            <EntryIcon kind="disk" size={15} />
          </span>
          <span className="td-tree-label">{imageName}</span>
        </div>

        {expandedIds.has('__image__') &&
          partitions.map((part, idx) => {
            const partId = `part:${part.offset}`;
            const rootId = `dir:${part.offset}:`;
            const scan = scanMap.get(part.offset);
            const stateLabel =
              scan?.status === 'ready'
                ? `已读取 ${scan.count ?? 0} 项`
                : scan?.status === 'error'
                  ? '无法读取'
                  : '待读取';
            const partExpanded = expandedIds.has(partId);
            const rootExpanded = expandedIds.has(rootId);
            const rootBranch = branches[rootId];

            return (
              <React.Fragment key={partId}>
                <div
                  className={`td-tree-row ${selectedTreeId === partId ? 'td-tree-row--selected' : ''}`}
                  style={{ paddingLeft: 20 }}
                  title={`${part.description}\n偏移 ${part.offset} 扇区\n${scan?.error || stateLabel}`}
                  onClick={() =>
                    void handleTreeNodeClick(
                      {
                        id: partId,
                        label: `分区 ${idx + 1} · 偏移 ${part.offset} · ${stateLabel}`,
                        kind: 'partition',
                        iconKind: 'disk',
                        offset: part.offset,
                        hasChildren: scan?.status !== 'error',
                      },
                      partId
                    )
                  }
                >
                  {scan?.status !== 'error' ? (
                    <button
                      type="button"
                      className="td-tree-toggle"
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleTreeExpand(partId);
                      }}
                    >
                      <img
                        src={assetUrl(partExpanded ? 'assets/branch-open.svg' : 'assets/branch-closed.svg')}
                        alt=""
                      />
                    </button>
                  ) : (
                    <span style={{ width: 18, flexShrink: 0 }} />
                  )}
                  <span className="td-tree-icon">
                    <EntryIcon kind="disk" size={15} />
                  </span>
                  <span className="td-tree-label">
                    分区 {idx + 1} · 偏移 {part.offset} · {stateLabel}
                  </span>
                </div>

                {partExpanded && scan?.status !== 'error' && (
                  <>
                    <div
                      className={`td-tree-row ${selectedTreeId === rootId ? 'td-tree-row--selected' : ''}`}
                      style={{ paddingLeft: 34 }}
                      title={`分区偏移 ${part.offset} / 根目录`}
                      onClick={() =>
                        void handleTreeNodeClick(
                          {
                            id: rootId,
                            label: '/ 根目录',
                            kind: 'root',
                            iconKind: 'folder',
                            offset: part.offset,
                            scopePath: '',
                            hasChildren: true,
                          },
                          rootId
                        )
                      }
                    >
                      <button
                        type="button"
                        className="td-tree-toggle"
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleTreeExpand(rootId, part.offset, '');
                        }}
                      >
                        <img
                          src={assetUrl(rootExpanded ? 'assets/branch-open.svg' : 'assets/branch-closed.svg')}
                          alt=""
                        />
                      </button>
                      <span className="td-tree-icon">
                        <EntryIcon kind="folder" size={15} />
                      </span>
                      <span className="td-tree-label">/ 根目录</span>
                    </div>

                    {rootExpanded && (
                      <>
                        {rootBranch?.loading && (
                          <div className="td-tree-row td-muted-text" style={{ paddingLeft: 66, fontSize: 11.5 }}>
                            正在加载…
                          </div>
                        )}
                        {rootBranch?.loaded && renderTreeChildren(rootBranch.children, 3)}
                      </>
                    )}
                  </>
                )}
              </React.Fragment>
            );
          })}
      </div>

      <div className="td-nav-footer">{treeFooterText}</div>
    </div>
  );

  const rightTopResults = (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--surface-bg)' }}>
      <div className="td-filter-bar">
        <input
          type="text"
          className="td-input td-mono"
          style={{ width: 118 }}
          placeholder="后缀，如 .txt"
          aria-label="文件后缀"
          value={suffix}
          disabled={busy || !evidence}
          onChange={(e) => setSuffix(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') handleApplyFilter();
          }}
        />
        <div className="td-search-box">
          <span className="td-search-box-icon">
            <UiIcon name="search" size={14} color="var(--text-muted)" />
          </span>
          <input
            type="text"
            className="td-input"
            placeholder="当前目录内的路径关键词"
            aria-label="路径关键词"
            value={keyword}
            disabled={busy || !evidence}
            onChange={(e) => setKeyword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleApplyFilter();
            }}
          />
          {keyword && (
            <button
              type="button"
              className="td-search-clear"
              onClick={() => setKeyword('')}
              aria-label="清空关键词"
            >
              ×
            </button>
          )}
        </div>
        <select
          className="td-select"
          style={{ minWidth: 108 }}
          aria-label="文件状态"
          value={statusFilter}
          disabled={busy || !evidence}
          onChange={(e) => {
            setStatusFilter(e.target.value as 'all' | 'active' | 'deleted');
            setPage(0);
          }}
        >
          <option value="all">全部状态</option>
          <option value="active">现存文件</option>
          <option value="deleted">已删除</option>
        </select>
        <button
          type="button"
          className="td-btn td-btn--soft"
          disabled={busy || !evidence}
          onClick={handleApplyFilter}
        >
          筛选
        </button>
        <button
          type="button"
          className="td-btn"
          disabled={busy || !evidence}
          onClick={handleResetFilter}
        >
          重置
        </button>
      </div>

      <div className="td-breadcrumb-bar" title={breadcrumbText}>
        {breadcrumbText}
      </div>

      <VirtualTable
        rows={items}
        columns={fileColumns}
        rowKey={(e) => e.entryId}
        selectedKey={selectedEntry?.entryId ?? null}
        onSelectRow={(entry) => handleSelectRow(entry)}
        onDoubleClickRow={(entry) => handleDoubleClickRow(entry)}
        onContextMenuRow={(e, entry) => {
          if (!entry.directory) {
            setContextMenu({ x: e.clientX, y: e.clientY, entry });
          }
        }}
        emptyText={
          !snapshot
            ? '尚未打开案件。请先新建或打开案件。'
            : !evidence
              ? '尚未加载镜像。请点击右上角「加载镜像」选择 RAW 或 .E01 首段。'
              : loadingList
                ? '正在读取文件列表…'
                : '当前范围没有匹配项'
        }
      />

      <div className="td-table-footer">
        <span className="td-result-count">{resultCountText}</span>
        {showPagination && (
          <Pagination
            page={page}
            totalPages={totalPages}
            disabled={busy || loadingList}
            onPageChange={(nextPage) => setPage(nextPage)}
          />
        )}
      </div>
    </div>
  );

  const rightBottomPreview = (
    <div className="td-preview-panel">
      <div className="td-pane-header">
        <span className="td-section-title">内容预览</span>
        {registry.hasFeature('export') && (
          <button
            type="button"
            className="td-btn td-btn--soft"
            style={{ height: 28, minHeight: 28 }}
            disabled={!canExportSelected}
            onClick={() => selectedEntry && onExportEntry(selectedEntry)}
          >
            <UiIcon name="export" size={14} color={canExportSelected ? 'var(--accent-soft-text)' : 'var(--text-disabled)'} />
            导出所选文件
          </button>
        )}
      </div>
      <PreviewPane
        entry={selectedEntry}
        emptyMessage={items.length === 0 && evidence ? '没有匹配项' : '请选择文件'}
      />
    </div>
  );

  return (
    <div className="td-panel">
      <SplitPane
        direction="horizontal"
        initialSize={276}
        minFirst={220}
        minSecond={480}
        first={leftNavPane}
        second={
          <SplitPane
            direction="vertical"
            initialSize={0.58}
            minFirst={140}
            minSecond={160}
            first={rightTopResults}
            second={rightBottomPreview}
          />
        }
      />

      {contextMenu && contextMenuItems.length > 0 && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          items={contextMenuItems}
          onClose={() => setContextMenu(null)}
        />
      )}
    </div>
  );
};
