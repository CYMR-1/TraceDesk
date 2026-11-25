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
  error?: string | null;
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

const FileBrowserModuleInner: React.FC<FileBrowserModuleProps> = ({
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

  // 异步竞态与去重守卫：按案件代次隔离树分支回写，按递增序号隔离分页列表响应
  const caseGenRef = useRef(0);
  const filesReqSeqRef = useRef(0);
  const loadingBranchesRef = useRef<Set<string>>(new Set());
  const selectedEntryRef = useRef<EntryView | null>(selectedEntry);
  selectedEntryRef.current = selectedEntry;
  /** 点击左侧树中的文件时登记待选中条目，待统一分页查询返回后自动高亮，避免并发双发 queryFilesPage */
  const pendingSelectRef = useRef<{ entryId: string; fallbackIndex?: number } | null>(null);
  const lastQuickLocKeyRef = useRef<string>('');

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

  // 案件或镜像结构变更时才重置目录树与范围（切换标签或记笔记/导出不清空展开状态与筛选）。
  // 注意：大镜像按需模式下 inventoryCount 随当前浏览目录动态变化，不纳入 identity 以免切换目录时误清空左侧树缓存。
  const partitionScansSummary = useMemo(
    () =>
      (snapshot?.partitionScans ?? [])
        .map((s) => `${s.offset}:${s.status}:${s.count ?? ''}`)
        .join(','),
    [snapshot?.partitionScans]
  );
  const stableInventoryKey = snapshot?.browsingDirectories ? 'quick' : String(snapshot?.inventoryCount ?? 0);
  const caseIdentity = `${snapshot?.id ?? ''}|${evidence?.path ?? ''}|${stableInventoryKey}|${snapshot?.browsingDirectories ? 'q' : 'f'}|${partitionScansSummary}`;
  const prevIdentityRef = useRef('');

  const loadTreeBranch = useCallback(
    async (
      branchKey: string,
      offset: number,
      path: string,
      inode?: string | null,
      groupIndex?: number
    ) => {
      const gen = caseGenRef.current;
      const inflightKey = `${gen}|${branchKey}`;
      // 同步检查在途集合，防止双击或快速重复展开触发重复 getTreeChildren IPC
      if (loadingBranchesRef.current.has(inflightKey)) {
        return;
      }
      loadingBranchesRef.current.add(inflightKey);
      setBranches((prev) => ({
        ...prev,
        [branchKey]: {
          loaded: prev[branchKey]?.loaded ?? false,
          loading: true,
          children: prev[branchKey]?.children ?? [],
          error: null,
        },
      }));
      try {
        const res = await tauriApi.getTreeChildren({
          offset,
          scopePath: path,
          inode: inode ?? null,
          groupIndex,
        });
        if (gen !== caseGenRef.current) return;
        setBranches((prev) => ({
          ...prev,
          [branchKey]: {
            loaded: true,
            loading: false,
            children: res.nodes,
            error: null,
          },
        }));
      } catch (err) {
        if (gen !== caseGenRef.current) return;
        const msg = formatError(err);
        // 失败时不将 loaded 标记为 true，允许用户查看柔和错误提示并点击重试，而非永久缓存为空目录。
        setBranches((prev) => ({
          ...prev,
          [branchKey]: {
            loaded: false,
            loading: false,
            children: [],
            error: msg,
          },
        }));
        onDetailChange(`读取目录失败：${msg}`);
      } finally {
        loadingBranchesRef.current.delete(inflightKey);
      }
    },
    [onDetailChange]
  );

  useEffect(() => {
    if (prevIdentityRef.current === caseIdentity) return;
    prevIdentityRef.current = caseIdentity;
    caseGenRef.current += 1;
    filesReqSeqRef.current += 1;
    loadingBranchesRef.current.clear();
    pendingSelectRef.current = null;
    lastQuickLocKeyRef.current = '';

    setBranches({});
    setAncestors({});
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
      // 大镜像按需模式下不盲目自动展开所有分区的 / 根目录，保持默认折叠态（> 箭头）等待用户按需点击读取；
      // 全量扫描模式下则照常自动展开可读分区的根目录。
      if (!isQuickMode && scan?.status !== 'error') {
        const rootKey = `dir:${part.offset}:`;
        initialExpanded.add(rootKey);
        if (evidence) {
          void loadTreeBranch(rootKey, part.offset, '', null);
        }
      }
    }
    setExpandedIds(initialExpanded);
  }, [caseIdentity, isQuickMode, partitions, scanMap, evidence, loadTreeBranch]);

  // 记录大镜像快速浏览时的父目录 inode 路径，并在目录切换时重置页号为 0 避免沿用旧目录页码
  useEffect(() => {
    if (snapshot?.quickLocation) {
      const { offset, inode, path } = snapshot.quickLocation;
      setAncestors((prev) => ({ ...prev, [`${offset}:${path}`]: inode }));
      const locKey = `${offset}:${path}`;
      if (lastQuickLocKeyRef.current !== locKey) {
        lastQuickLocKeyRef.current = locKey;
        setPage(0);
      }
    } else {
      lastQuickLocKeyRef.current = '';
    }
  }, [snapshot?.quickLocation]);

  const handleSelectRow = useCallback(
    (entry: EntryView) => {
      onSelectEntry(entry);
      onDetailChange(
        `${entry.path}  ·  ${entry.status}  ·  inode ${entry.inode || '—'}  ·  ${entry.size} 字节  ·  分区偏移 ${entry.offset}`
      );
    },
    [onSelectEntry, onDetailChange]
  );

  const quickLocOffset = snapshot?.quickLocation?.offset ?? null;
  const quickLocPath = snapshot?.quickLocation?.path ?? null;
  const hasSnapshot = Boolean(snapshot);
  const hasEvidence = Boolean(evidence);

  // 查询当前分页文件列表（递增序号防过期覆盖，一次性消费 pendingLogFilterRef 避免重复记审计）
  const fetchFilesPage = useCallback(
    async (targetPage: number) => {
      const seq = ++filesReqSeqRef.current;
      const shouldLogFilter = pendingLogFilterRef.current;
      pendingLogFilterRef.current = false;
      if (!hasSnapshot || !hasEvidence) {
        setItems([]);
        setTotal(0);
        setTotalPages(1);
        setLoadingList(false);
        return;
      }
      setLoadingList(true);
      try {
        const res = await tauriApi.queryFilesPage({
          scopeOffset: isQuickMode ? quickLocOffset ?? scopeOffset : scopeOffset,
          scopePath: isQuickMode ? quickLocPath ?? '' : scopePath,
          suffix: appliedSuffix,
          keyword: appliedKeyword,
          status: statusFilter,
          page: targetPage,
          pageSize: PAGE_SIZE,
          logFilter: shouldLogFilter,
        });
        if (seq !== filesReqSeqRef.current) return;
        setItems(res.items);
        setTotal(res.total);
        setPage(res.page);
        setTotalPages(Math.max(1, res.totalPages));

        // 优先处理来自左侧树文件点击的待选中条目，避免与当前分页查询竞态清空选中态
        const pendingSel = pendingSelectRef.current;
        if (pendingSel) {
          pendingSelectRef.current = null;
          const found =
            res.items.find((i) => i.entryId === pendingSel.entryId) ??
            (pendingSel.fallbackIndex !== undefined ? res.items[pendingSel.fallbackIndex] : undefined);
          if (found) {
            handleSelectRow(found);
            return;
          }
        }
        const curSelected = selectedEntryRef.current;
        if (curSelected && !res.items.some((i) => i.entryId === curSelected.entryId)) {
          onSelectEntry(null);
        }
      } catch (err) {
        if (seq !== filesReqSeqRef.current) return;
        onDetailChange(`读取文件列表失败：${formatError(err)}`);
        setItems([]);
        setTotal(0);
        setTotalPages(1);
      } finally {
        if (seq === filesReqSeqRef.current) {
          setLoadingList(false);
        }
      }
    },
    [
      hasSnapshot,
      hasEvidence,
      snapshot?.id,
      snapshot?.inventoryCount,
      evidence?.path,
      partitionScansSummary,
      isQuickMode,
      quickLocOffset,
      quickLocPath,
      scopeOffset,
      scopePath,
      appliedSuffix,
      appliedKeyword,
      statusFilter,
      handleSelectRow,
      onSelectEntry,
      onDetailChange,
    ]
  );

  useEffect(() => {
    void fetchFilesPage(page);
  }, [fetchFilesPage, page, filterSeq]);

  const handleApplyFilter = useCallback(() => {
    pendingLogFilterRef.current = true;
    setAppliedSuffix(suffix);
    setAppliedKeyword(keyword);
    setPage(0);
    setFilterSeq((n) => n + 1);
  }, [suffix, keyword]);

  const handleResetFilter = useCallback(() => {
    pendingLogFilterRef.current = false;
    setSuffix('');
    setKeyword('');
    setAppliedSuffix('');
    setAppliedKeyword('');
    setStatusFilter('all');
    setPage(0);
    setFilterSeq((n) => n + 1);
  }, []);

  const toggleTreeExpand = (
    nodeId: string,
    offset?: number,
    path?: string,
    inode?: string | null,
    groupIndex?: number
  ) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
        if (offset !== undefined && path !== undefined && !branches[nodeId]?.loaded) {
          void loadTreeBranch(nodeId, offset, path, inode, groupIndex);
        }
      }
      return next;
    });
  };

  const handleExpandAll = () => {
    const next = new Set<string>(['__image__']);
    for (const p of partitions) {
      const scan = scanMap.get(p.offset);
      if (scan?.status === 'error') continue;
      next.add(`part:${p.offset}`);
      const rootKey = `dir:${p.offset}:`;
      next.add(rootKey);
      if (!branches[rootKey]?.loaded && !branches[rootKey]?.loading) {
        void loadTreeBranch(rootKey, p.offset, '', null);
      }
    }
    for (const [key, branch] of Object.entries(branches)) {
      if (!branch.loaded) continue;
      next.add(key);
      for (const child of branch.children) {
        if (child.kind === 'directory' && child.offset !== undefined && child.scopePath !== undefined) {
          const ck = `dir:${child.offset}:${child.scopePath}`;
          if (isQuickMode) {
            // 大镜像按需模式下仅展开已加载的子目录节点，避免递归触发大量 fls 读盘。
            if (branches[ck]?.loaded) {
              next.add(ck);
            }
          } else {
            next.add(ck);
            if (!branches[ck]?.loaded && !branches[ck]?.loading) {
              void loadTreeBranch(ck, child.offset, child.scopePath, child.inode ?? null);
            }
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

  const handleDoubleClickRow = useCallback(
    (entry: EntryView) => {
      if (!entry.directory) return;
      const cleanPath = entry.path.replace(/^\/+|\/+$/g, '');
      if (isQuickMode) {
        const dirInode = entry.inode || null;
        const dirKey = `dir:${entry.offset}:${cleanPath}`;
        const gen = caseGenRef.current;
        setAncestors((prev) => ({ ...prev, [`${entry.offset}:${cleanPath}`]: dirInode }));
        setPage(0);
        void (async () => {
          const entries = await onBrowseDirectory(entry.offset, dirInode, cleanPath);
          if (gen !== caseGenRef.current) return;
          if (entries) {
            setSelectedTreeId(dirKey);
            setExpandedIds((prev) => {
              const next = new Set(prev);
              next.add(`part:${entry.offset}`);
              next.add(`dir:${entry.offset}:`);
              next.add(dirKey);
              return next;
            });
            void loadTreeBranch(dirKey, entry.offset, cleanPath, dirInode);
          }
        })();
        return;
      }
      setScopeOffset(entry.offset);
      setScopePath(cleanPath);
      setSelectedTreeId(`dir:${entry.offset}:${cleanPath}`);
      setPage(0);
      onSelectEntry(null);
      handleResetFilter();
    },
    [isQuickMode, onBrowseDirectory, onSelectEntry, loadTreeBranch, handleResetFilter]
  );

  const handleTreeNodeClick = async (
    node: TreeNodeDto,
    nodeId: string,
    parentPath = '',
    parentInode: string | null = null
  ) => {
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
        const rootId = `dir:${node.offset}:`;
        const gen = caseGenRef.current;
        const entries = await onBrowseDirectory(node.offset, null, '');
        if (gen !== caseGenRef.current) return;
        if (entries) {
          setExpandedIds((prev) => {
            const next = new Set(prev);
            next.add(nodeId);
            next.add(rootId);
            return next;
          });
          // 后端 browse_directory 已写入分支缓存，同步刷新并展开左侧根目录树，保持左右一致。
          void loadTreeBranch(rootId, node.offset, '', null);
        }
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
        const targetInode = node.inode ?? null;
        const gen = caseGenRef.current;
        setAncestors((prev) => ({ ...prev, [`${node.offset}:${targetPath}`]: targetInode }));
        const entries = await onBrowseDirectory(node.offset, targetInode, targetPath);
        if (gen !== caseGenRef.current) return;
        if (entries) {
          setExpandedIds((prev) => {
            const next = new Set(prev);
            next.add(nodeId);
            return next;
          });
          // 同步将该目录返回的条目刷新并展开到左侧文件树分支，避免左右视图割裂。
          void loadTreeBranch(nodeId, node.offset, targetPath, targetInode);
        }
        return;
      }
      setScopeOffset(node.offset);
      setScopePath(targetPath);
      setPage(0);
      onSelectEntry(null);
      if (!expandedIds.has(nodeId)) {
        toggleTreeExpand(nodeId, node.offset, targetPath, node.inode ?? null);
      }
      return;
    }
    if (node.kind === 'group' && node.offset !== undefined) {
      toggleTreeExpand(nodeId, node.offset, node.scopePath ?? '', null, node.groupIndex);
      return;
    }
    if (node.kind === 'file' && node.entryId) {
      const gen = caseGenRef.current;
      // 大镜像按需模式下：若所点文件不在当前右侧目录中，先按需切入其父目录并登记待选中条目，待统一分页刷新后高亮。
      if (isQuickMode && node.offset !== undefined) {
        const curLoc = snapshot?.quickLocation;
        const cleanParent = parentPath.replace(/^\/+|\/+$/g, '');
        const alreadyInParent =
          curLoc?.offset === node.offset && (curLoc.path ?? '').replace(/^\/+|\/+$/g, '') === cleanParent;
        if (!alreadyInParent) {
          setPage(0);
          pendingSelectRef.current = { entryId: node.entryId };
          const browsed = await onBrowseDirectory(node.offset, parentInode, cleanParent);
          if (gen !== caseGenRef.current) return;
          if (!browsed) {
            // 浏览失败或被并发锁拒绝时及时清空待选标记，避免泄漏到后续分页查询
            pendingSelectRef.current = null;
            return;
          }
          const matched =
            browsed.find((e) => e.entryId === node.entryId) ??
            browsed.find(
              (e) =>
                !e.directory &&
                e.inode === (node.inode ?? '') &&
                Boolean(e.deleted) === Boolean(node.deleted)
            );
          if (matched) {
            pendingSelectRef.current = { entryId: matched.entryId };
            handleSelectRow(matched);
          } else {
            pendingSelectRef.current = null;
          }
          return;
        }
      }
      try {
        const loc = await tauriApi.locateFileInScope({ entryId: node.entryId });
        if (gen !== caseGenRef.current) return;
        // 登记待选中条目并统一交由状态变更触发单次 fetchFilesPage，避免并发双发 queryFilesPage 竞态
        pendingSelectRef.current = { entryId: node.entryId, fallbackIndex: loc.indexInPage };
        setScopeOffset(loc.scopeOffset);
        setScopePath(loc.scopePath);
        setSuffix('');
        setKeyword('');
        setAppliedSuffix('');
        setAppliedKeyword('');
        setStatusFilter('all');
        setPage(loc.page);
        setFilterSeq((n) => n + 1);
      } catch {
        // 忽略定位失败
      }
    }
  };

  // 递归渲染左侧目录树
  const renderTreeChildren = (
    nodes: TreeNodeDto[],
    depth: number,
    parentPath: string,
    parentInode: string | null
  ): React.ReactNode =>
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
      const nextParentPath = node.kind === 'directory' ? (node.scopePath ?? '') : parentPath;
      const nextParentInode = node.kind === 'directory' ? (node.inode ?? null) : parentInode;

      return (
        <React.Fragment key={nodeId}>
          <div
            className={`td-tree-row ${isSelected ? 'td-tree-row--selected' : ''}`}
            style={{ paddingLeft: 6 + depth * 14 }}
            title={node.tooltip ?? node.label}
            onClick={() => void handleTreeNodeClick(node, nodeId, parentPath, parentInode)}
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
                  toggleTreeExpand(
                    nodeId,
                    node.offset,
                    node.scopePath ?? '',
                    node.kind === 'directory' ? (node.inode ?? null) : null,
                    node.groupIndex
                  );
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
                  正在读取目录…
                </div>
              )}
              {branch?.error && !branch.loading && (
                <div
                  className="td-tree-row td-tree-error-row"
                  style={{ paddingLeft: 24 + (depth + 1) * 14 }}
                  title={branch.error}
                  onClick={(e) => {
                    e.stopPropagation();
                    if (node.offset !== undefined) {
                      void loadTreeBranch(
                        nodeId,
                        node.offset,
                        node.scopePath ?? '',
                        node.kind === 'directory' ? (node.inode ?? null) : null,
                        node.groupIndex
                      );
                    }
                  }}
                >
                  <span>读取失败：{branch.error}</span>
                  <span className="td-tree-retry-link">点击重试</span>
                </div>
              )}
              {branch?.loaded && !branch.loading && branch.children.length === 0 && (
                <div
                  className="td-tree-row td-muted-text"
                  style={{ paddingLeft: 24 + (depth + 1) * 14, fontSize: 11.5 }}
                >
                  （空目录）
                </div>
              )}
              {branch?.loaded &&
                branch.children.length > 0 &&
                renderTreeChildren(branch.children, depth + 1, nextParentPath, nextParentInode)}
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
            const partExpanded = expandedIds.has(partId);
            const rootExpanded = expandedIds.has(rootId);
            const rootBranch = branches[rootId];
            const stateLabel =
              scan?.status === 'ready'
                ? `已读取 ${scan.count ?? 0} 项`
                : scan?.status === 'error'
                  ? '无法读取'
                  : isQuickMode && rootBranch?.error
                    ? '无法读取'
                    : isQuickMode && rootBranch?.loaded
                      ? `已展开 ${rootBranch.children.length} 项`
                      : '待读取';

            return (
              <React.Fragment key={partId}>
                <div
                  className={`td-tree-row ${selectedTreeId === partId ? 'td-tree-row--selected' : ''}`}
                  style={{ paddingLeft: 20 }}
                  title={`${part.description}\n偏移 ${part.offset} 扇区\n${scan?.error || rootBranch?.error || stateLabel}`}
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
                      title={
                        isQuickMode
                          ? `分区偏移 ${part.offset} / 根目录（点击展开按需读取）`
                          : `分区偏移 ${part.offset} / 根目录`
                      }
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
                          toggleTreeExpand(rootId, part.offset, '', null);
                        }}
                        aria-label={rootExpanded ? '折叠根目录' : '展开根目录'}
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
                      {isQuickMode && !rootBranch?.loaded && !rootBranch?.loading && !rootBranch?.error && (
                        <span className="td-tree-hint">点击展开按需读取</span>
                      )}
                    </div>

                    {rootExpanded && (
                      <>
                        {rootBranch?.loading && (
                          <div className="td-tree-row td-muted-text" style={{ paddingLeft: 66, fontSize: 11.5 }}>
                            正在读取目录…
                          </div>
                        )}
                        {rootBranch?.error && !rootBranch.loading && (
                          <div
                            className="td-tree-row td-tree-error-row"
                            style={{ paddingLeft: 66 }}
                            title={rootBranch.error}
                            onClick={(e) => {
                              e.stopPropagation();
                              void loadTreeBranch(rootId, part.offset, '', null);
                            }}
                          >
                            <span>读取失败：{rootBranch.error}</span>
                            <span className="td-tree-retry-link">点击重试</span>
                          </div>
                        )}
                        {rootBranch?.loaded && !rootBranch.loading && rootBranch.children.length === 0 && (
                          <div className="td-tree-row td-muted-text" style={{ paddingLeft: 66, fontSize: 11.5 }}>
                            （空目录）
                          </div>
                        )}
                        {rootBranch?.loaded &&
                          rootBranch.children.length > 0 &&
                          renderTreeChildren(rootBranch.children, 3, '', null)}
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

export const FileBrowserModule = React.memo(FileBrowserModuleInner);
