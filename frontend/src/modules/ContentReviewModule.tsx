/**
 * 模块 6：内容搜索与复核页 (review)
 * - 支持 UTF-8 / UTF-16LE / GBK / HEX 精确搜索，全案或单文件范围，实时流式推送
 * - 使用 rAF 合并缓冲 + 虚拟滚动 VirtualTable，流畅承载 10 万+ 实时命中，彻底消除卡顿
 * - 搜索期间即可三态全选、下拉筛选分区偏移、双击弹出十六进制精准定位弹窗、排除误报或批量保存为取证发现
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { tauriApi, tauriEvents } from '../api/tauri';
import { UiIcon } from '../components/Icons';
import { VirtualTable, type VirtualColumn } from '../components/VirtualTable';
import { HexHitPreviewDialog } from '../components/dialogs/HexHitPreviewDialog';
import type { CheckState } from '../components/FilterHeader';
import {
  SEARCH_ENCODINGS,
  type CaseSnapshot,
  type EntryView,
  type SearchEncoding,
  type SearchFinishedEvent,
  type SearchHitDto,
  type SearchProgressEvent,
} from '../types/ipc';
import { formatError } from '../utils/assets';

interface ContentReviewModuleProps {
  snapshot: CaseSnapshot | null;
  selectedBrowserEntry: EntryView | null;
  /** 从文件浏览右键触发“单文件检索内容”时的信号 */
  singleFileRequestToken: number;
  busy: boolean;
  onSearchingChange: (searching: boolean) => void;
  onSnapshotUpdated: (snapshot: CaseSnapshot) => void;
  onAlert: (title: string, message: string, tone?: 'info' | 'warning' | 'error') => void;
}

const DEFAULT_HINT = '搜索当前清单中的普通文件及删除记录，不含未分配空间。双击命中定位原始字节。';

export const ContentReviewModule: React.FC<ContentReviewModuleProps> = ({
  snapshot,
  selectedBrowserEntry,
  singleFileRequestToken,
  busy,
  onSearchingChange,
  onSnapshotUpdated,
  onAlert,
}) => {
  const [query, setQuery] = useState('');
  const [encoding, setEncoding] = useState<SearchEncoding>('UTF-8');
  const [scope, setScope] = useState<'all' | 'selected'>('all');

  const [searching, setSearching] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [searchId, setSearchId] = useState<string | null>(null);
  const [needleHex, setNeedleHex] = useState('');
  const [activeEncoding, setActiveEncoding] = useState<SearchEncoding>('UTF-8');
  const [progress, setProgress] = useState<SearchProgressEvent | null>(null);
  const [finishedInfo, setFinishedInfo] = useState<SearchFinishedEvent | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [hits, setHits] = useState<SearchHitDto[]>([]);
  const [excludedSet, setExcludedSet] = useState<Set<number>>(() => new Set());
  const [checkedSet, setCheckedSet] = useState<Set<number>>(() => new Set());
  const [selectedHitIndex, setSelectedHitIndex] = useState<number | null>(null);
  const [activeFilters, setActiveFilters] = useState<Record<string, string[]>>({});
  const [previewHit, setPreviewHit] = useState<SearchHitDto | null>(null);
  const [savingBookmarks, setSavingBookmarks] = useState(false);

  const queryInputRef = useRef<HTMLInputElement>(null);
  const activeSearchIdRef = useRef<string | null>(null);
  const pendingHitsRef = useRef<SearchHitDto[]>([]);
  const rafRef = useRef<number | null>(null);
  const prevCaseIdRef = useRef<string>('');

  // 从文件浏览右键触发单文件搜索
  useEffect(() => {
    if (singleFileRequestToken > 0) {
      setScope('selected');
      queryInputRef.current?.focus();
    }
  }, [singleFileRequestToken]);

  // 案件切换时重置
  useEffect(() => {
    const cid = snapshot?.id ?? '';
    if (prevCaseIdRef.current !== cid) {
      prevCaseIdRef.current = cid;
      if (activeSearchIdRef.current) {
        void tauriApi.cancelContentSearch({ searchId: activeSearchIdRef.current }).catch(() => {});
      }
      activeSearchIdRef.current = null;
      pendingHitsRef.current = [];
      setSearching(false);
      setCancelling(false);
      onSearchingChange(false);
      setSearchId(null);
      setHits([]);
      setExcludedSet(new Set());
      setCheckedSet(new Set());
      setSelectedHitIndex(null);
      setActiveFilters({});
      setProgress(null);
      setFinishedInfo(null);
      setNotice(null);
    }
  }, [snapshot?.id, onSearchingChange]);

  const flushPendingHits = useCallback(() => {
    rafRef.current = null;
    if (pendingHitsRef.current.length === 0) return;
    const chunk = pendingHitsRef.current;
    pendingHitsRef.current = [];
    setHits((prev) => (prev.length === 0 ? chunk : prev.concat(chunk)));
  }, []);

  // 订阅 Rust 流式推送事件
  useEffect(() => {
    let mounted = true;
    const unlisteners: (() => void)[] = [];

    const setup = async () => {
      const u1 = await tauriEvents.onSearchHits((ev) => {
        if (!mounted || ev.searchId !== activeSearchIdRef.current || ev.hits.length === 0) return;
        pendingHitsRef.current.push(...ev.hits);
        if (rafRef.current === null) {
          rafRef.current = window.requestAnimationFrame(flushPendingHits);
        }
      });
      const u2 = await tauriEvents.onSearchProgress((ev) => {
        if (!mounted || ev.searchId !== activeSearchIdRef.current) return;
        setProgress(ev);
      });
      const u3 = await tauriEvents.onSearchFinished((ev) => {
        if (!mounted || ev.searchId !== activeSearchIdRef.current) return;
        if (rafRef.current !== null) {
          window.cancelAnimationFrame(rafRef.current);
          rafRef.current = null;
        }
        flushPendingHits();
        setSearching(false);
        setCancelling(false);
        onSearchingChange(false);
        setFinishedInfo(ev);
        if (ev.snapshot) {
          onSnapshotUpdated(ev.snapshot);
        }
      });
      unlisteners.push(u1, u2, u3);
    };

    void setup();
    return () => {
      mounted = false;
      if (rafRef.current !== null) {
        window.cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
      for (const u of unlisteners) u();
    };
  }, [flushPendingHits, onSearchingChange, onSnapshotUpdated]);

  // 未排除的命中
  const retainedHits = useMemo(() => {
    if (excludedSet.size === 0) return hits;
    return hits.filter((h) => !excludedSet.has(h.hitIndex));
  }, [hits, excludedSet]);

  // 分区偏移筛选选项
  const offsetOptions = useMemo(() => {
    const set = new Set<number>();
    for (const h of retainedHits) {
      set.add(h.offset);
    }
    return Array.from(set)
      .sort((a, b) => a - b)
      .map(String);
  }, [retainedHits]);

  // 当前可见命中（已应用分区偏移表头筛选）
  const visibleHits = useMemo(() => {
    const offsetFilter = activeFilters.offset ?? [];
    if (offsetFilter.length === 0) return retainedHits;
    const allow = new Set(offsetFilter);
    return retainedHits.filter((h) => allow.has(String(h.offset)));
  }, [retainedHits, activeFilters.offset]);

  const visibleCheckedCount = useMemo(() => {
    let count = 0;
    for (const h of visibleHits) {
      if (checkedSet.has(h.hitIndex)) count += 1;
    }
    return count;
  }, [visibleHits, checkedSet]);

  const checkState: CheckState =
    visibleHits.length === 0 || visibleCheckedCount === 0
      ? 'unchecked'
      : visibleCheckedCount === visibleHits.length
        ? 'checked'
        : 'indeterminate';

  const handleToggleCheckAll = useCallback(
    (checked: boolean) => {
      setCheckedSet((prev) => {
        const next = new Set(prev);
        for (const h of visibleHits) {
          if (checked) next.add(h.hitIndex);
          else next.delete(h.hitIndex);
        }
        return next;
      });
    },
    [visibleHits]
  );

  const handleStartOrCancel = async () => {
    if (searching) {
      if (activeSearchIdRef.current) {
        setCancelling(true);
        try {
          await tauriApi.cancelContentSearch({ searchId: activeSearchIdRef.current });
        } catch {
          setCancelling(false);
        }
      }
      return;
    }

    if (!snapshot) {
      onAlert('提示', '请先新建或打开案件。', 'info');
      return;
    }
    if (!snapshot.evidence) {
      onAlert('提示', '请先加载镜像。', 'info');
      return;
    }
    if (!query.trim()) {
      onAlert('搜索条件无效', '请输入要搜索的文字或十六进制字节。', 'warning');
      return;
    }
    if (scope === 'selected' && (!selectedBrowserEntry || selectedBrowserEntry.directory)) {
      onAlert('提示', '请先在「文件浏览」中选中一个文件。', 'info');
      return;
    }

    pendingHitsRef.current = [];
    setHits([]);
    setExcludedSet(new Set());
    setCheckedSet(new Set());
    setSelectedHitIndex(null);
    setActiveFilters({});
    setProgress(null);
    setFinishedInfo(null);
    setNotice(null);

    try {
      const res = await tauriApi.startContentSearch({
        query: query.trim(),
        encoding,
        selectedEntryId: scope === 'selected' ? selectedBrowserEntry?.entryId ?? null : null,
      });
      activeSearchIdRef.current = res.searchId;
      setSearchId(res.searchId);
      setNeedleHex(res.needleHex);
      setActiveEncoding(encoding);
      setSearching(true);
      setCancelling(false);
      onSearchingChange(true);
    } catch (err) {
      onAlert('搜索条件无效', formatError(err), 'warning');
    }
  };

  const getTargetIndices = (): number[] => {
    const checked = visibleHits
      .filter((h) => checkedSet.has(h.hitIndex))
      .map((h) => h.hitIndex);
    if (checked.length > 0) return checked;
    if (selectedHitIndex !== null && visibleHits.some((h) => h.hitIndex === selectedHitIndex)) {
      return [selectedHitIndex];
    }
    return [];
  };

  const handleExcludeSelected = () => {
    const targets = getTargetIndices();
    if (targets.length === 0) return;
    setExcludedSet((prev) => {
      const next = new Set(prev);
      for (const idx of targets) next.add(idx);
      return next;
    });
    setCheckedSet((prev) => {
      const next = new Set(prev);
      for (const idx of targets) next.delete(idx);
      return next;
    });
    const remaining = Math.max(0, retainedHits.length - targets.length);
    setNotice(`已从本次搜索中排除 ${targets.length} 项，当前保留 ${remaining} 项。`);
  };

  const handleBookmarkSelected = async () => {
    const targets = getTargetIndices();
    if (targets.length === 0 || !searchId) return;
    setSavingBookmarks(true);
    try {
      const res = await tauriApi.bookmarkSearchHits({
        searchId,
        hitIndices: targets,
      });
      onSnapshotUpdated(res.snapshot);
      setNotice(`已保存 ${res.savedCount} 条命中，可在「取证发现」中查看。`);
    } catch (err) {
      onAlert('保存命中记录失败', formatError(err), 'error');
    } finally {
      setSavingBookmarks(false);
    }
  };

  const columns = useMemo<VirtualColumn<SearchHitDto>[]>(
    () => [
      {
        key: 'check',
        label: '',
        width: 72,
        checkable: true,
        checkLabel: '全选',
        tooltip: '全选 / 取消全选',
      },
      {
        key: 'seq',
        label: '序号',
        width: 68,
        align: 'center',
        mono: true,
        getText: (_row, idx) => String(idx + 1),
      },
      {
        key: 'pos',
        label: '文件内字节偏移',
        width: 124,
        mono: true,
        getText: (r) => String(r.pos),
      },
      {
        key: 'offset',
        label: '分区偏移',
        width: 112,
        mono: true,
        filterable: true,
        tooltip: '单击下拉筛选分区偏移',
        getText: (r) => String(r.offset),
      },
      {
        key: 'inode',
        label: 'inode',
        width: 90,
        mono: true,
        getText: (r) => r.inode || '—',
      },
      {
        key: 'path',
        label: '镜像内路径',
        width: 280,
        getText: (r) => r.path,
      },
      {
        key: 'beforeHex',
        label: '前文 HEX',
        width: 240,
        mono: true,
        subtle: true,
        getText: (r) => r.beforeHex,
      },
      {
        key: 'afterHex',
        label: '后文 HEX',
        width: 240,
        mono: true,
        subtle: true,
        getText: (r) => r.afterHex,
      },
    ],
    []
  );

  const statusSummary = useMemo(() => {
    const excludedCount = excludedSet.size;
    const shownCount = retainedHits.length;

    if (searching) {
      const hitText = `已命中 ${shownCount} 条` + (excludedCount ? `（已排除 ${excludedCount} 条）` : '');
      let progText = `正在后台搜索… · ${hitText} · 可随时勾选、预览、排除或保存`;
      if (progress) {
        if (progress.total > 0) {
          const pct = Math.floor((100 * progress.done) / progress.total);
          progText = `正在${progress.stage} · ${pct}%（${progress.done.toLocaleString()}/${progress.total.toLocaleString()}） · ${hitText} · 可随时勾选、预览、排除或保存`;
        } else {
          progText = `正在${progress.stage}… · ${hitText}`;
        }
      }
      return notice ? `${notice}  |  ${progText}` : progText;
    }

    if (finishedInfo) {
      if (finishedInfo.error) {
        return `搜索失败：${finishedInfo.error}`;
      }
      const excludedNote = excludedCount ? `（已排除 ${excludedCount} 条，当前保留 ${shownCount} 条）` : '';
      const base =
        `${finishedInfo.status ?? '已完成'} · 已处理 ${finishedInfo.visited ?? 0}/${finishedInfo.eligible ?? 0} 项 · ` +
        `命中 ${hits.length} 条${excludedNote} · 读取失败 ${finishedInfo.errorsCount ?? 0} 项。` +
        `${finishedInfo.verification ? finishedInfo.verification + '。' : ''}` +
        `${finishedInfo.reportName ? `清单及失败明细：reports/${finishedInfo.reportName}` : ''}`;
      return notice ? `${notice}  |  ${base}` : base;
    }

    return notice || DEFAULT_HINT;
  }, [searching, progress, finishedInfo, hits.length, retainedHits.length, excludedSet.size, notice]);

  const percent =
    searching && progress && progress.total > 0
      ? Math.min(100, Math.round((100 * progress.done) / progress.total))
      : null;

  return (
    <div className="td-panel">
      <div className="td-panel-top-bar">
        <div className="td-search-box">
          <span className="td-search-box-icon">
            <UiIcon name="search" size={14} color="var(--text-muted)" />
          </span>
          <input
            ref={queryInputRef}
            type="text"
            className="td-input"
            placeholder="输入文字或十六进制字节；搜索文件内容（如演示镜像 HEX: 6E 6F 74 65）"
            value={query}
            disabled={searching}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !searching) {
                void handleStartOrCancel();
              }
            }}
          />
          {query && !searching && (
            <button type="button" className="td-search-clear" onClick={() => setQuery('')}>
              ×
            </button>
          )}
        </div>

        <select
          className="td-select td-mono"
          style={{ minWidth: 96 }}
          aria-label="搜索编码"
          value={encoding}
          disabled={searching}
          onChange={(e) => setEncoding(e.target.value as SearchEncoding)}
        >
          {SEARCH_ENCODINGS.map((enc) => (
            <option key={enc} value={enc}>
              {enc}
            </option>
          ))}
        </select>

        <select
          className="td-select"
          style={{ minWidth: 158 }}
          aria-label="搜索范围"
          value={scope}
          disabled={searching}
          onChange={(e) => setScope(e.target.value as 'all' | 'selected')}
        >
          <option value="all">全部文件</option>
          <option value="selected">
            {selectedBrowserEntry && !selectedBrowserEntry.directory
              ? `选中文件：${selectedBrowserEntry.name}`
              : '文件浏览中选中的文件'}
          </option>
        </select>

        <button
          type="button"
          className={`td-btn ${searching ? 'td-btn--warning' : 'td-btn--accent'}`}
          disabled={cancelling || (!searching && busy)}
          onClick={() => void handleStartOrCancel()}
        >
          {cancelling ? '正在取消…' : searching ? '取消搜索' : '搜索'}
        </button>

        <div className="td-toolbar-divider" />

        <button
          type="button"
          className="td-btn"
          title="在本次搜索中排除勾选（或当前选中）的命中"
          disabled={visibleHits.length === 0}
          onClick={handleExcludeSelected}
        >
          {visibleCheckedCount > 0 ? `排除所选项 (${visibleCheckedCount})` : '排除所选项'}
        </button>

        <button
          type="button"
          className="td-btn td-btn--soft"
          title="将勾选（或当前选中）的命中保存为取证发现"
          disabled={visibleHits.length === 0 || savingBookmarks || !searchId}
          onClick={() => void handleBookmarkSelected()}
        >
          {savingBookmarks
            ? '正在保存…'
            : visibleCheckedCount > 0
              ? `保存为取证发现 (${visibleCheckedCount})`
              : '保存为取证发现'}
        </button>
      </div>

      <div className="td-panel-sub-bar">
        <span className="td-muted-text" style={{ flex: 1, fontSize: 12, userSelect: 'text' }}>
          {statusSummary}
        </span>
        {searching && (
          <div className="td-progress-track" aria-label="内容搜索进度">
            <div
              className={`td-progress-fill ${percent === null ? 'td-progress-fill--indeterminate' : ''}`}
              style={percent !== null ? { width: `${percent}%` } : undefined}
            />
          </div>
        )}
      </div>

      <VirtualTable
        rows={visibleHits}
        columns={columns}
        rowKey={(r) => r.hitIndex}
        selectedKey={selectedHitIndex}
        checkState={checkState}
        onToggleCheckAll={handleToggleCheckAll}
        isRowChecked={(r) => checkedSet.has(r.hitIndex)}
        onToggleRowCheck={(row, checked) => {
          setCheckedSet((prev) => {
            const next = new Set(prev);
            if (checked) next.add(row.hitIndex);
            else next.delete(row.hitIndex);
            return next;
          });
        }}
        filterOptions={{ offset: offsetOptions }}
        activeFilters={activeFilters}
        onFilterChange={(colKey, vals) =>
          setActiveFilters((prev) => ({ ...prev, [colKey]: vals }))
        }
        onSelectRow={(r) => setSelectedHitIndex(r.hitIndex)}
        onDoubleClickRow={(r, _idx, colKey) => {
          if (colKey === 'check') return;
          setPreviewHit(r);
        }}
        emptyText={
          searching
            ? '正在扫描文件内容，命中将实时流式呈现…'
            : finishedInfo
              ? '未检索到匹配字节'
              : '输入关键字或十六进制字节并点击「搜索」，支持十万级流式虚拟滚动浏览'
        }
      />

      {previewHit && (
        <HexHitPreviewDialog
          hit={previewHit}
          encoding={activeEncoding}
          needleHex={needleHex}
          onClose={() => setPreviewHit(null)}
        />
      )}
    </div>
  );
};
