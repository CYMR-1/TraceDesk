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

export interface ContentSearchLiveState {
  searching: boolean;
  searchId: string | null;
  stageText: string;
  percent: number | null;
  hitCount: number;
}

interface ContentReviewModuleProps {
  snapshot: CaseSnapshot | null;
  selectedBrowserEntry: EntryView | null;
  /** 从文件浏览右键触发“单文件检索内容”时的信号 */
  singleFileRequestToken: number;
  busy: boolean;
  onSearchingChange: (searching: boolean) => void;
  /** 将后台内容搜索实时状态同步给主工作台底栏进度条与标签微点 */
  onSearchLiveStateChange?: (state: ContentSearchLiveState) => void;
  onSnapshotUpdated: (snapshot: CaseSnapshot) => void;
  onAlert: (title: string, message: string, tone?: 'info' | 'warning' | 'error') => void;
}

const DEFAULT_HINT = '搜索当前清单中的普通文件及删除记录，不含未分配空间。双击命中定位原始字节。';
/** 高频流式命中时的批量合入节流窗口（毫秒），减少十万级命中下的数组反复拷贝 */
const HIT_FLUSH_INTERVAL_MS = 80;

const ContentReviewModuleInner: React.FC<ContentReviewModuleProps> = ({
  snapshot,
  selectedBrowserEntry,
  singleFileRequestToken,
  busy,
  onSearchingChange,
  onSearchLiveStateChange,
  onSnapshotUpdated,
  onAlert,
}) => {
  const [query, setQuery] = useState('');
  const [encoding, setEncoding] = useState<SearchEncoding>('UTF-8');
  const [scope, setScope] = useState<'all' | 'selected'>('all');

  const [starting, setStarting] = useState(false);
  const [searching, setSearching] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [searchId, setSearchId] = useState<string | null>(null);
  const [needleHex, setNeedleHex] = useState('');
  const [activeEncoding, setActiveEncoding] = useState<SearchEncoding>('UTF-8');
  const [progress, setProgress] = useState<SearchProgressEvent | null>(null);
  const [finishedInfo, setFinishedInfo] = useState<SearchFinishedEvent | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // 历史搜索记录回放与命中二次筛查状态
  const [selectedHistoryReport, setSelectedHistoryReport] = useState('');
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [pathFilter, setPathFilter] = useState('');
  const [deletedFilter, setDeletedFilter] = useState<'all' | 'active' | 'deleted'>('all');

  const [hits, setHits] = useState<SearchHitDto[]>([]);
  const [offsetOptions, setOffsetOptions] = useState<string[]>([]);
  const [excludedSet, setExcludedSet] = useState<Set<number>>(() => new Set());
  const [checkedSet, setCheckedSet] = useState<Set<number>>(() => new Set());
  const [selectedHitIndex, setSelectedHitIndex] = useState<number | null>(null);
  const [activeFilters, setActiveFilters] = useState<Record<string, string[]>>({});
  const [previewHit, setPreviewHit] = useState<SearchHitDto | null>(null);
  const [savingBookmarks, setSavingBookmarks] = useState(false);

  const queryInputRef = useRef<HTMLInputElement>(null);
  const activeSearchIdRef = useRef<string | null>(null);
  /** 防止 Rust 极速扫描在 startContentSearch invoke 返回前就发出 hits/progress/finished 事件造成丢失 */
  const startingSearchRef = useRef(false);
  /** 案件切换或新搜索启动时递增代次，用于隔离已过期/已取消的 startContentSearch 异步返回 */
  const searchGenRef = useRef(0);
  const earlyBufferRef = useRef<
    Map<
      string,
      {
        hits: SearchHitDto[];
        progress: SearchProgressEvent | null;
        finished: SearchFinishedEvent | null;
      }
    >
  >(new Map());
  const pendingHitsRef = useRef<SearchHitDto[]>([]);
  const flushTimerRef = useRef<number | null>(null);
  const rafRef = useRef<number | null>(null);
  /** 增量维护已出现的分区偏移集合，避免十万级命中每帧 O(N) 重扫全部命中提取筛选项 */
  const seenOffsetsRef = useRef<Set<number>>(new Set());
  const prevCaseIdRef = useRef<string>('');

  const cancelScheduledFlush = useCallback(() => {
    if (flushTimerRef.current !== null) {
      window.clearTimeout(flushTimerRef.current);
      flushTimerRef.current = null;
    }
    if (rafRef.current !== null) {
      window.cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
  }, []);

  // 从文件浏览右键触发单文件搜索
  useEffect(() => {
    if (singleFileRequestToken > 0) {
      setScope('selected');
      queryInputRef.current?.focus();
    }
  }, [singleFileRequestToken]);

  // 案件切换时彻底重置搜索态、定时器和打开中的十六进制定位弹窗
  useEffect(() => {
    const cid = snapshot?.id ?? '';
    if (prevCaseIdRef.current !== cid) {
      prevCaseIdRef.current = cid;
      searchGenRef.current += 1;
      cancelScheduledFlush();
      if (activeSearchIdRef.current) {
        void tauriApi.cancelContentSearch({ searchId: activeSearchIdRef.current }).catch(() => {});
      }
      activeSearchIdRef.current = null;
      startingSearchRef.current = false;
      earlyBufferRef.current.clear();
      pendingHitsRef.current = [];
      seenOffsetsRef.current.clear();
      setStarting(false);
      setSearching(false);
      setCancelling(false);
      onSearchingChange(false);
      setSearchId(null);
      setScope('all');
      setHits([]);
      setOffsetOptions([]);
      setExcludedSet(new Set());
      setCheckedSet(new Set());
      setSelectedHitIndex(null);
      setActiveFilters({});
      setPreviewHit(null);
      setProgress(null);
      setFinishedInfo(null);
      setNotice(null);
      setSelectedHistoryReport('');
      setLoadingHistory(false);
      setPathFilter('');
      setDeletedFilter('all');
    }
  }, [snapshot?.id, onSearchingChange, cancelScheduledFlush]);

  const flushPendingHits = useCallback(() => {
    flushTimerRef.current = null;
    rafRef.current = null;
    if (pendingHitsRef.current.length === 0) return;
    const chunk = pendingHitsRef.current;
    pendingHitsRef.current = [];

    // 增量检测新增的分区偏移，仅在出现新分区时更新表头筛选项
    let hasNewOffset = false;
    for (let i = 0; i < chunk.length; i += 1) {
      const off = chunk[i].offset;
      if (!seenOffsetsRef.current.has(off)) {
        seenOffsetsRef.current.add(off);
        hasNewOffset = true;
      }
    }
    if (hasNewOffset) {
      setOffsetOptions(
        Array.from(seenOffsetsRef.current)
          .sort((a, b) => a - b)
          .map(String)
      );
    }

    setHits((prev) => (prev.length === 0 ? chunk : prev.concat(chunk)));
  }, []);

  const scheduleHitFlush = useCallback(() => {
    if (flushTimerRef.current !== null || rafRef.current !== null) return;
    // 首屏低延迟尽快呈现，已有大量命中时按 80ms 合并批次，显著降低数组拼接次数
    flushTimerRef.current = window.setTimeout(() => {
      flushTimerRef.current = null;
      rafRef.current = window.requestAnimationFrame(flushPendingHits);
    }, HIT_FLUSH_INTERVAL_MS);
  }, [flushPendingHits]);

  const applyFinishedEvent = useCallback(
    (ev: SearchFinishedEvent) => {
      cancelScheduledFlush();
      flushPendingHits();
      setStarting(false);
      setSearching(false);
      setCancelling(false);
      onSearchingChange(false);
      setFinishedInfo(ev);
      if (ev.reportName) {
        setSelectedHistoryReport(ev.reportName);
      }
      if (ev.snapshot) {
        onSnapshotUpdated(ev.snapshot);
      }
    },
    [cancelScheduledFlush, flushPendingHits, onSearchingChange, onSnapshotUpdated]
  );

  // 订阅 Rust 流式推送事件（支持早到事件缓冲回放，并在 StrictMode/卸载时立即释放晚到 unlistener）
  useEffect(() => {
    let mounted = true;
    const unlisteners: (() => void)[] = [];

    const ensureEarlyBucket = (id: string) => {
      let bucket = earlyBufferRef.current.get(id);
      if (!bucket) {
        bucket = { hits: [], progress: null, finished: null };
        earlyBufferRef.current.set(id, bucket);
      }
      return bucket;
    };

    const registerSafe = async (promise: Promise<() => void>) => {
      try {
        const unlisten = await promise;
        if (!mounted) {
          unlisten();
        } else {
          unlisteners.push(unlisten);
        }
      } catch {
        // 忽略单通道订阅异常，防止阻断其余事件注册
      }
    };

    void Promise.all([
      registerSafe(
        tauriEvents.onSearchHits((ev) => {
          if (!mounted || ev.hits.length === 0) return;
          if (ev.searchId === activeSearchIdRef.current) {
            pendingHitsRef.current.push(...ev.hits);
            scheduleHitFlush();
          } else if (startingSearchRef.current) {
            ensureEarlyBucket(ev.searchId).hits.push(...ev.hits);
          }
        })
      ),
      registerSafe(
        tauriEvents.onSearchProgress((ev) => {
          if (!mounted) return;
          if (ev.searchId === activeSearchIdRef.current) {
            setProgress(ev);
          } else if (startingSearchRef.current) {
            ensureEarlyBucket(ev.searchId).progress = ev;
          }
        })
      ),
      registerSafe(
        tauriEvents.onSearchFinished((ev) => {
          if (!mounted) return;
          if (ev.searchId === activeSearchIdRef.current) {
            applyFinishedEvent(ev);
          } else if (startingSearchRef.current) {
            ensureEarlyBucket(ev.searchId).finished = ev;
          }
        })
      ),
    ]);

    return () => {
      mounted = false;
      cancelScheduledFlush();
      for (const u of unlisteners) u();
      unlisteners.length = 0;
    };
  }, [scheduleHitFlush, cancelScheduledFlush, applyFinishedEvent]);

  // 未排除的命中
  const retainedHits = useMemo(() => {
    if (excludedSet.size === 0) return hits;
    return hits.filter((h) => !excludedSet.has(h.hitIndex));
  }, [hits, excludedSet]);

  // 当存在排除项时，按需根据保留命中收缩分区偏移选项；无排除项时直接复用增量维护的 offsetOptions
  const effectiveOffsetOptions = useMemo(() => {
    if (excludedSet.size === 0) return offsetOptions;
    const set = new Set<number>();
    for (const h of retainedHits) {
      set.add(h.offset);
    }
    return Array.from(set)
      .sort((a, b) => a - b)
      .map(String);
  }, [excludedSet.size, offsetOptions, retainedHits]);

  // 当前可见命中（依次应用分区偏移表头筛选、路径关键词过滤与已删除状态筛选）
  const visibleHits = useMemo(() => {
    const offsetFilter = activeFilters.offset ?? [];
    const allowOffsets = offsetFilter.length > 0 ? new Set(offsetFilter) : null;
    const kw = pathFilter.trim().toLowerCase();
    if (!allowOffsets && !kw && deletedFilter === 'all') {
      return retainedHits;
    }
    return retainedHits.filter((h) => {
      if (allowOffsets && !allowOffsets.has(String(h.offset))) return false;
      if (deletedFilter === 'deleted' && !h.deleted) return false;
      if (deletedFilter === 'active' && Boolean(h.deleted)) return false;
      if (kw && !h.path.toLowerCase().includes(kw)) return false;
      return true;
    });
  }, [retainedHits, activeFilters.offset, pathFilter, deletedFilter]);

  const visibleCheckedCount = useMemo(() => {
    // 未勾选任何命中时 O(1) 短路返回，避免流式增长期间每批全表遍历
    if (checkedSet.size === 0) return 0;
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
    if (starting) return;
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

    const gen = ++searchGenRef.current;
    cancelScheduledFlush();
    activeSearchIdRef.current = null;
    earlyBufferRef.current.clear();
    startingSearchRef.current = true;
    pendingHitsRef.current = [];
    seenOffsetsRef.current.clear();
    setStarting(true);
    setHits([]);
    setOffsetOptions([]);
    setExcludedSet(new Set());
    setCheckedSet(new Set());
    setSelectedHitIndex(null);
    setActiveFilters({});
    setProgress(null);
    setFinishedInfo(null);
    setNotice(null);
    setSelectedHistoryReport('');
    setPathFilter('');
    setDeletedFilter('all');

    try {
      const res = await tauriApi.startContentSearch({
        query: query.trim(),
        encoding,
        selectedEntryId: scope === 'selected' ? selectedBrowserEntry?.entryId ?? null : null,
      });
      // 若在启动等待期间发生了案件切换或重置，立即取消该过期后端搜索并放弃回写
      if (gen !== searchGenRef.current) {
        void tauriApi.cancelContentSearch({ searchId: res.searchId }).catch(() => {});
        return;
      }
      activeSearchIdRef.current = res.searchId;
      startingSearchRef.current = false;
      setStarting(false);
      setSearchId(res.searchId);
      setNeedleHex(res.needleHex);
      setActiveEncoding(encoding);

      const early = earlyBufferRef.current.get(res.searchId);
      earlyBufferRef.current.clear();

      if (early?.hits.length) {
        pendingHitsRef.current.push(...early.hits);
        flushPendingHits();
      }
      if (early?.progress) {
        setProgress(early.progress);
      }
      if (early?.finished) {
        applyFinishedEvent(early.finished);
      } else {
        setSearching(true);
        setCancelling(false);
        onSearchingChange(true);
      }
    } catch (err) {
      if (gen !== searchGenRef.current) return;
      startingSearchRef.current = false;
      setStarting(false);
      earlyBufferRef.current.clear();
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

  /** 恢复所有已排除的命中项 */
  const handleRestoreExcluded = () => {
    const count = excludedSet.size;
    if (count === 0) return;
    setExcludedSet(new Set());
    setNotice(`已恢复 ${count} 条已排除的命中项。`);
  };

  /** 回放选中的历史内容搜索记录（reports/search_*.json） */
  const handleLoadHistoryRecord = async (reportName: string) => {
    setSelectedHistoryReport(reportName);
    if (!reportName) return;
    if (starting || searching) {
      onAlert('提示', '请先等待或取消当前正在进行的内容搜索，再回放历史记录。', 'info');
      return;
    }
    const meta = (snapshot?.searchRecords ?? []).find((r) => r.reportName === reportName);
    setLoadingHistory(true);
    setNotice(null);
    try {
      const loadedHits = await tauriApi.loadSearchRecord({ reportName });
      const offsets = Array.from(new Set(loadedHits.map((h) => h.offset)))
        .sort((a, b) => a - b)
        .map(String);
      seenOffsetsRef.current = new Set(loadedHits.map((h) => h.offset));
      setHits(loadedHits);
      setOffsetOptions(offsets);
      setExcludedSet(new Set());
      setCheckedSet(new Set());
      setSelectedHitIndex(null);
      setActiveFilters({});
      setPathFilter('');
      setDeletedFilter('all');
      setPreviewHit(null);
      setProgress(null);

      // 绑定后端已注册的 replay:<reportName> 会话，回放命中亦可直接保存为取证发现
      const replaySid = `replay:${reportName}`;
      activeSearchIdRef.current = replaySid;
      setSearchId(replaySid);
      if (meta) {
        setQuery(meta.query);
        const enc = (SEARCH_ENCODINGS.includes(meta.encoding as SearchEncoding)
          ? meta.encoding
          : 'UTF-8') as SearchEncoding;
        setEncoding(enc);
        setActiveEncoding(enc);
        setNeedleHex(meta.query);
        setFinishedInfo({
          searchId: replaySid,
          status: `历史回放（${meta.status}）`,
          visited: meta.visited,
          eligible: meta.eligible,
          totalHits: loadedHits.length,
          errorsCount: meta.failed,
          verification: `记录时间 ${meta.time}`,
          reportName: meta.reportName,
        });
      } else {
        setFinishedInfo({
          searchId: replaySid,
          status: '历史回放',
          visited: loadedHits.length,
          eligible: loadedHits.length,
          totalHits: loadedHits.length,
          errorsCount: 0,
          reportName,
        });
      }
      setNotice(`已加载历史搜索记录 reports/${reportName}（共 ${loadedHits.length} 条命中）。`);
    } catch (err) {
      onAlert('加载历史搜索记录失败', formatError(err), 'error');
    } finally {
      setLoadingHistory(false);
    }
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

  // 将后台内容搜索实时进度同步给主工作台底栏与标签微点，切页后仍可随时观察与取消
  useEffect(() => {
    if (!onSearchLiveStateChange) return;
    if (!searching) {
      onSearchLiveStateChange({
        searching: false,
        searchId: null,
        stageText: '',
        percent: null,
        hitCount: 0,
      });
      return;
    }
    const stageText =
      progress && progress.total > 0 && percent !== null
        ? `后台内容搜索 · ${progress.stage} ${percent}% · 已命中 ${retainedHits.length} 条`
        : progress
          ? `后台内容搜索 · ${progress.stage}… · 已命中 ${retainedHits.length} 条`
          : `后台内容搜索中 · 已命中 ${retainedHits.length} 条`;
    onSearchLiveStateChange({
      searching: true,
      searchId: activeSearchIdRef.current ?? searchId,
      stageText,
      percent,
      hitCount: retainedHits.length,
    });
  }, [onSearchLiveStateChange, searching, searchId, progress, percent, retainedHits.length]);

  const historyRecords = snapshot?.searchRecords ?? [];

  const tableFilterOptions = useMemo(
    () => ({ offset: effectiveOffsetOptions }),
    [effectiveOffsetOptions]
  );

  const hitRowKey = useCallback((r: SearchHitDto) => r.hitIndex, []);
  const isHitRowChecked = useCallback((r: SearchHitDto) => checkedSet.has(r.hitIndex), [checkedSet]);
  const handleToggleHitCheck = useCallback((row: SearchHitDto, checked: boolean) => {
    setCheckedSet((prev) => {
      const next = new Set(prev);
      if (checked) next.add(row.hitIndex);
      else next.delete(row.hitIndex);
      return next;
    });
  }, []);
  const handleFilterChange = useCallback((colKey: string, vals: string[]) => {
    setActiveFilters((prev) => ({ ...prev, [colKey]: vals }));
  }, []);
  const handleSelectHitRow = useCallback((r: SearchHitDto) => {
    setSelectedHitIndex(r.hitIndex);
  }, []);
  const handleDoubleClickHitRow = useCallback((r: SearchHitDto, _idx: number, colKey: string) => {
    if (colKey === 'check') return;
    setPreviewHit(r);
  }, []);

  const isBusySearching = starting || searching;

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
            disabled={isBusySearching}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !isBusySearching) {
                void handleStartOrCancel();
              }
            }}
          />
          {query && !isBusySearching && (
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
          disabled={isBusySearching}
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
          disabled={isBusySearching}
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
          disabled={starting || cancelling || (!searching && busy)}
          onClick={() => void handleStartOrCancel()}
        >
          {starting ? '正在启动…' : cancelling ? '正在取消…' : searching ? '取消搜索' : '搜索'}
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

        {excludedSet.size > 0 && (
          <button
            type="button"
            className="td-btn"
            title="恢复全部已排除的命中项"
            onClick={handleRestoreExcluded}
          >
            恢复已排除项 ({excludedSet.size})
          </button>
        )}

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

      {/* 历史搜索回放 + 命中结果二次筛查工具条 */}
      <div className="td-panel-sub-bar td-review-secondary-bar">
        <select
          className="td-select"
          style={{ minWidth: 210, maxWidth: 320 }}
          aria-label="历史搜索记录回放"
          value={selectedHistoryReport}
          disabled={isBusySearching || loadingHistory || !snapshot || historyRecords.length === 0}
          onChange={(e) => void handleLoadHistoryRecord(e.target.value)}
        >
          <option value="">
            {loadingHistory
              ? '正在加载历史搜索记录…'
              : historyRecords.length > 0
                ? `历史搜索记录回放 (${historyRecords.length} 条)`
                : '暂无历史搜索记录'}
          </option>
          {historyRecords.map((rec) => (
            <option key={rec.reportName} value={rec.reportName}>
              {`${rec.query || '(空)'} [${rec.encoding}] · ${rec.hits} 命中 · ${rec.time}`}
            </option>
          ))}
        </select>

        <div className="td-toolbar-divider" />

        <div className="td-search-box" style={{ maxWidth: 260 }}>
          <span className="td-search-box-icon">
            <UiIcon name="search" size={13} color="var(--text-muted)" />
          </span>
          <input
            type="text"
            className="td-input"
            style={{ height: 28, minHeight: 28, fontSize: 12 }}
            placeholder="二次筛查：按路径关键词过滤命中"
            aria-label="命中路径关键词过滤"
            value={pathFilter}
            disabled={hits.length === 0}
            onChange={(e) => setPathFilter(e.target.value)}
          />
          {pathFilter && (
            <button
              type="button"
              className="td-search-clear"
              aria-label="清空路径过滤"
              onClick={() => setPathFilter('')}
            >
              ×
            </button>
          )}
        </div>

        <select
          className="td-select"
          style={{ minWidth: 112, height: 28, minHeight: 28, fontSize: 12 }}
          aria-label="命中文件删除状态筛选"
          value={deletedFilter}
          disabled={hits.length === 0}
          onChange={(e) => setDeletedFilter(e.target.value as 'all' | 'active' | 'deleted')}
        >
          <option value="all">全部状态</option>
          <option value="active">仅现存文件</option>
          <option value="deleted">仅已删除</option>
        </select>

        {(pathFilter || deletedFilter !== 'all') && (
          <span className="td-muted-text" style={{ fontSize: 11.5, whiteSpace: 'nowrap' }}>
            筛查显示 {visibleHits.length}/{retainedHits.length} 条
          </span>
        )}
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
        rowKey={hitRowKey}
        selectedKey={selectedHitIndex}
        checkState={checkState}
        onToggleCheckAll={handleToggleCheckAll}
        isRowChecked={isHitRowChecked}
        onToggleRowCheck={handleToggleHitCheck}
        filterOptions={tableFilterOptions}
        activeFilters={activeFilters}
        onFilterChange={handleFilterChange}
        onSelectRow={handleSelectHitRow}
        onDoubleClickRow={handleDoubleClickHitRow}
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

export const ContentReviewModule = React.memo(ContentReviewModuleInner);
