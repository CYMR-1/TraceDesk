/**
 * 模块 4：MACB 时间线页 (timeline)
 * - 支持大清单按需「生成时间线」、每页 100 条分页与双击页码跳转
 * - 支持事件/状态/分区偏移表头下拉筛选、序号/时间正倒序排序与回车关键词搜索
 * - 双击下方展开事件详情 DossierView
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { tauriApi } from '../api/tauri';
import { DossierView } from '../components/DossierView';
import { UiIcon } from '../components/Icons';
import { Pagination } from '../components/Pagination';
import { SplitPane } from '../components/SplitPane';
import { VirtualTable, type VirtualColumn } from '../components/VirtualTable';
import type { CaseSnapshot, LocateEntryRequest, TimelineRowDto } from '../types/ipc';
import { formatError } from '../utils/assets';

const PAGE_SIZE = 100;
const LARGE_INVENTORY_THRESHOLD = 1000;

interface TimelineModuleProps {
  snapshot: CaseSnapshot | null;
  busy: boolean;
  /** 跨模块一键跳转定位原文件回调 */
  onLocateEntry?: (req: LocateEntryRequest) => void;
}

const TimelineModuleInner: React.FC<TimelineModuleProps> = ({ snapshot, busy, onLocateEntry }) => {
  const [built, setBuilt] = useState(false);
  const [building, setBuilding] = useState(false);
  const [hint, setHint] = useState('尚未打开案件');
  const [filterOptions, setFilterOptions] = useState<Record<string, string[]>>({
    event: [],
    status: [],
    offset: [],
  });
  const [activeFilters, setActiveFilters] = useState<Record<string, string[]>>({});
  const [searchInput, setSearchInput] = useState('');
  const [appliedQuery, setAppliedQuery] = useState('');
  const [sortColumn, setSortColumn] = useState<'seq' | 'time'>('seq');
  const [sortDescending, setSortDescending] = useState(false);

  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [totalEvents, setTotalEvents] = useState(0);
  const [rows, setRows] = useState<TimelineRowDto[]>([]);
  const [selectedNum, setSelectedNum] = useState<number | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const lastCaseKeyRef = useRef('');
  // 使用代次与请求序号隔离旧案件或过期分页响应，避免竞态覆盖当前视图
  const buildGenRef = useRef(0);
  const pageReqSeqRef = useRef(0);
  const caseKey = `${snapshot?.id ?? ''}|${snapshot?.evidence?.path ?? ''}|${snapshot?.inventoryCount ?? 0}|${snapshot?.browsingDirectories ? 'q' : 'f'}`;

  const needsManualBuild = Boolean(
    snapshot &&
      !snapshot.browsingDirectories &&
      snapshot.inventoryCount > LARGE_INVENTORY_THRESHOLD &&
      !built
  );

  const handleBuildTimeline = useCallback(async () => {
    if (!snapshot) return;
    const gen = ++buildGenRef.current;
    setBuilding(true);
    try {
      const res = await tauriApi.buildTimeline();
      if (gen !== buildGenRef.current) return;
      setHint(res.hint);
      setTotalEvents(res.total);
      setFilterOptions({
        event: res.filterOptions.events,
        status: res.filterOptions.statuses,
        offset: res.filterOptions.offsets,
      });
      setBuilt(true);
      setPage(0);
    } catch (err) {
      if (gen !== buildGenRef.current) return;
      setHint(`生成时间线失败：${formatError(err)}`);
    } finally {
      if (gen === buildGenRef.current) {
        setBuilding(false);
      }
    }
  }, [snapshot]);

  // 案件切换时重置状态，小清单自动构建时间线
  useEffect(() => {
    if (lastCaseKeyRef.current === caseKey) return;
    lastCaseKeyRef.current = caseKey;
    buildGenRef.current += 1;
    pageReqSeqRef.current += 1;

    setBuilding(false);
    setSearchInput('');
    setAppliedQuery('');
    setActiveFilters({});
    setPage(0);
    setTotalPages(1);
    setRows([]);
    setSelectedNum(null);
    setDetailOpen(false);
    setBuilt(false);
    setFilterOptions({ event: [], status: [], offset: [] });

    if (!snapshot) {
      setHint('尚未打开案件');
      setTotalEvents(0);
      return;
    }
    if (snapshot.browsingDirectories) {
      setHint('请先在文件浏览中建立完整文件索引以生成全案时间线。');
      setTotalEvents(0);
      return;
    }
    if (!snapshot.evidence) {
      setHint('请先加载镜像以生成 MACB 时间线。');
      setTotalEvents(0);
      return;
    }
    if (snapshot.inventoryCount > LARGE_INVENTORY_THRESHOLD) {
      setHint('大清单 · 点击「生成时间线」，在后台整理事件。');
      setTotalEvents(0);
      return;
    }
    void handleBuildTimeline();
  }, [caseKey, snapshot, handleBuildTimeline]);

  // 查询时间线分页（单值筛选与后端分页总数 100% 一致）
  const fetchPage = useCallback(async () => {
    if (!snapshot || !built) return;
    const seq = ++pageReqSeqRef.current;
    try {
      const res = await tauriApi.queryTimelinePage({
        query: appliedQuery,
        event: activeFilters.event?.[0] ?? null,
        status: activeFilters.status?.[0] ?? null,
        offset: activeFilters.offset?.[0] ?? null,
        sortColumn,
        descending: sortDescending,
        page,
        pageSize: PAGE_SIZE,
      });
      if (seq !== pageReqSeqRef.current) return;
      setRows(res.items);
      setTotalEvents(res.totalEvents);
      setTotalPages(Math.max(1, res.totalPages));
    } catch (err) {
      if (seq !== pageReqSeqRef.current) return;
      setHint(`查询时间线失败：${formatError(err)}`);
    }
  }, [snapshot, built, appliedQuery, activeFilters, sortColumn, sortDescending, page]);

  useEffect(() => {
    void fetchPage();
  }, [fetchPage]);

  const handleCloseDetail = useCallback(() => {
    setDetailOpen(false);
  }, []);

  const selectedRow = useMemo(
    () => rows.find((r) => r.number === selectedNum) ?? null,
    [rows, selectedNum]
  );

  const columns = useMemo<VirtualColumn<TimelineRowDto>[]>(
    () => [
      { key: 'seq', label: '序号', width: 78, mono: true, sortable: true, getText: (r) => String(r.number) },
      { key: 'time', label: '时间（UTC+8）', width: 178, mono: true, sortable: true, getText: (r) => r.time },
      { key: 'event', label: '事件', width: 148, pill: true, filterable: true, filterMode: 'single', getText: (r) => r.event },
      { key: 'status', label: '状态', width: 128, pill: true, filterable: true, filterMode: 'single', getText: (r) => r.status },
      { key: 'offset', label: '分区偏移', width: 115, mono: true, filterable: true, filterMode: 'single', getText: (r) => String(r.offset) },
      { key: 'inode', label: 'inode', width: 100, mono: true, getText: (r) => r.inode || '—' },
      { key: 'path', label: '镜像内路径', width: 320, getText: (r) => r.path },
    ],
    []
  );

  const topStatusLabel =
    built && totalEvents > 0
      ? `MAC/B 时间线·UTC+8·当前 ${selectedNum ?? '—'}/${totalEvents}`
      : hint;

  return (
    <div className="td-panel">
      <div className="td-panel-top-bar">
        <span
          className="td-section-title"
          style={{ flex: 1, fontSize: 12.5, color: 'var(--text-secondary)' }}
          title={hint}
        >
          {topStatusLabel}
        </span>

        {needsManualBuild && (
          <button
            type="button"
            className="td-btn td-btn--soft"
            disabled={busy || building}
            onClick={() => void handleBuildTimeline()}
          >
            {building ? '正在整理时间线…' : '生成时间线'}
          </button>
        )}

        {selectedRow && onLocateEntry && (
          <button
            type="button"
            className="td-btn td-btn--soft td-btn--compact"
            disabled={busy}
            title="跳转到「文件浏览」定位当前选中时间线事件对应的原文件"
            onClick={() =>
              onLocateEntry({
                offset: selectedRow.offset,
                inode: selectedRow.inode,
                path: selectedRow.path,
                deleted: selectedRow.status.includes('已删除'),
              })
            }
          >
            <UiIcon name="locate" size={12} color="var(--accent-soft-text)" />
            定位原文件
          </button>
        )}

        <Pagination
          page={page}
          totalPages={totalPages}
          disabled={!built || building}
          onPageChange={(nextPage) => setPage(nextPage)}
        />
      </div>

      <div className="td-panel-sub-bar">
        <div className="td-search-box">
          <span className="td-search-box-icon">
            <UiIcon name="search" size={14} color="var(--text-muted)" />
          </span>
          <input
            type="text"
            className="td-input"
            placeholder="输入时间、事件、路径、状态或分区，按回车搜索"
            value={searchInput}
            disabled={!built}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                setAppliedQuery(searchInput.trim());
                setPage(0);
              }
            }}
          />
          {searchInput && (
            <button
              type="button"
              className="td-search-clear"
              onClick={() => {
                setSearchInput('');
                setAppliedQuery('');
                setPage(0);
              }}
            >
              ×
            </button>
          )}
        </div>
      </div>

      <SplitPane
        direction="vertical"
        initialSize={0.65}
        minFirst={160}
        minSecond={140}
        secondHidden={!detailOpen}
        first={
          <VirtualTable
            rows={rows}
            columns={columns}
            rowKey={(r) => r.number}
            selectedKey={selectedNum}
            filterOptions={filterOptions}
            activeFilters={activeFilters}
            onFilterChange={(colKey, vals) => {
              setActiveFilters((prev) => ({ ...prev, [colKey]: vals }));
              setPage(0);
            }}
            sortColumn={sortColumn}
            sortDescending={sortDescending}
            onSortRequest={(colKey) => {
              if (colKey !== 'seq' && colKey !== 'time') return;
              if (sortColumn === colKey) {
                setSortDescending((prev) => !prev);
              } else {
                setSortColumn(colKey);
                setSortDescending(false);
              }
              setPage(0);
            }}
            onSelectRow={(r) => setSelectedNum(r.number)}
            onDoubleClickRow={(r) => {
              setSelectedNum(r.number);
              setDetailOpen(true);
            }}
            emptyText={building ? '正在后台生成时间线…' : hint}
          />
        }
        second={
          selectedRow ? (
            <DossierView
              title={selectedRow.path}
              subtitle="文件系统时间 · UTC+8"
              headerActions={
                onLocateEntry ? (
                  <button
                    type="button"
                    className="td-btn td-btn--soft td-btn--compact"
                    disabled={busy}
                    title="跳转到「文件浏览」定位此时间线事件对应的原文件"
                    onClick={() =>
                      onLocateEntry({
                        offset: selectedRow.offset,
                        inode: selectedRow.inode,
                        path: selectedRow.path,
                        deleted: selectedRow.status.includes('已删除'),
                      })
                    }
                  >
                    <UiIcon name="locate" size={12} color="var(--accent-soft-text)" />
                    定位原文件
                  </button>
                ) : undefined
              }
              sections={[
                {
                  title: '事件详情',
                  rows: [
                    ['时间', selectedRow.time],
                    ['事件', selectedRow.event],
                    ['状态', selectedRow.status],
                    ['分区偏移（扇区）', String(selectedRow.offset)],
                    ['inode', selectedRow.inode || '—'],
                    ['路径', selectedRow.path],
                  ],
                },
              ]}
              onClose={handleCloseDetail}
            />
          ) : (
            <DossierView
              title="选择一条记录查看详情"
              subtitle={`当前页显示 ${rows.length} 条`}
              sections={[]}
              onClose={handleCloseDetail}
            />
          )
        }
      />
    </div>
  );
};

export const TimelineModule = React.memo(TimelineModuleInner);
