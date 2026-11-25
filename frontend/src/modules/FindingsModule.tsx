/**
 * 模块 3：取证发现页 (file_tools)
 * - 按文件归组展示笔记、摘要与副本比对记录，保留操作中文名映射 (FINDING_OPERATIONS)
 * - 表头下拉筛选（状态、分区偏移）与正倒序排序（序号、最近记录）
 * - 双击展开下方 DossierView 详情，支持一键导出当前可见分组
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { tauriApi } from '../api/tauri';
import { DossierView, type DossierSection } from '../components/DossierView';
import { UiIcon } from '../components/Icons';
import { SplitPane } from '../components/SplitPane';
import { VirtualTable, type VirtualColumn } from '../components/VirtualTable';
import { FINDING_OPERATIONS } from '../features/registry';
import type { CaseSnapshot, FindingGroupDto } from '../types/ipc';
import { formatError } from '../utils/assets';

interface FindingsModuleProps {
  snapshot: CaseSnapshot | null;
  busy: boolean;
  refreshToken: number;
  onExportFindings: (groupKeys: string[]) => void;
}

const DETAIL_FIELD_LABELS: readonly [string, string][] = [
  ['note', '笔记'],
  ['size', '读取字节数'],
  ['recorded_size', '目录记录字节数'],
  ['sha256', '读取内容 SHA-256'],
  ['comparison', '对照文件'],
  ['comparison_sha256', '对照 SHA-256'],
  ['source_note', '来源状态'],
  ['read_note', '读取说明'],
  ['source_verification', '操作时的完整性状态'],
  ['error', '错误'],
];

const FindingsModuleInner: React.FC<FindingsModuleProps> = ({
  snapshot,
  busy,
  refreshToken,
  onExportFindings,
}) => {
  const [keyword, setKeyword] = useState('');
  // 对搜索关键词做防抖处理，避免逐字输入高频触发后端 IPC 查询与审计扫描
  const [debouncedKeyword, setDebouncedKeyword] = useState('');
  const [activeFilters, setActiveFilters] = useState<Record<string, string[]>>({});
  const [filterOptions, setFilterOptions] = useState<Record<string, string[]>>({ status: [], offset: [] });
  const [sortColumn, setSortColumn] = useState<'seq' | 'latest'>('latest');
  const [sortDescending, setSortDescending] = useState(false);
  const [statusText, setStatusText] = useState('尚未打开案件');
  const [groups, setGroups] = useState<FindingGroupDto[]>([]);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const reqSeqRef = useRef(0);
  const prevCaseIdRef = useRef<string>(snapshot?.id ?? '');

  // 案件切换或关闭时重置本地筛选、搜索词与详情展开态，避免旧案件条件残留
  useEffect(() => {
    const cid = snapshot?.id ?? '';
    if (prevCaseIdRef.current !== cid) {
      prevCaseIdRef.current = cid;
      reqSeqRef.current += 1;
      setKeyword('');
      setDebouncedKeyword('');
      setActiveFilters({});
      setSelectedKey(null);
      setDetailOpen(false);
    }
  }, [snapshot?.id]);

  // 200ms 防抖同步搜索词；清空时立即生效
  useEffect(() => {
    const trimmed = keyword.trim();
    if (!trimmed) {
      setDebouncedKeyword('');
      return undefined;
    }
    const timer = window.setTimeout(() => {
      setDebouncedKeyword(trimmed);
    }, 200);
    return () => window.clearTimeout(timer);
  }, [keyword]);

  const loadFindings = useCallback(async () => {
    const seq = ++reqSeqRef.current;
    if (!snapshot) {
      setStatusText('尚未打开案件');
      setGroups([]);
      setFilterOptions({ status: [], offset: [] });
      setDetailOpen(false);
      return;
    }
    try {
      const res = await tauriApi.listFindings({
        status: activeFilters.status?.[0] ?? null,
        offset: activeFilters.offset?.[0] ?? null,
        keyword: debouncedKeyword,
        sortColumn,
        descending: sortDescending,
      });
      if (seq !== reqSeqRef.current) return;
      setStatusText(res.statusText);
      setFilterOptions({
        status: res.filterOptions.statuses,
        offset: res.filterOptions.offsets,
      });
      setGroups(res.groups);
    } catch (err) {
      if (seq !== reqSeqRef.current) return;
      setStatusText(`读取取证发现失败：${formatError(err)}`);
      setGroups([]);
    }
  }, [snapshot, debouncedKeyword, activeFilters, sortColumn, sortDescending]);

  useEffect(() => {
    void loadFindings();
  }, [loadFindings, refreshToken]);

  const handleCloseDetail = useCallback(() => {
    setDetailOpen(false);
  }, []);

  const selectedGroup = useMemo(
    () => groups.find((g) => g.groupKey === selectedKey) ?? null,
    [groups, selectedKey]
  );

  const columns = useMemo<VirtualColumn<FindingGroupDto>[]>(
    () => [
      { key: 'seq', label: '序号', width: 68, mono: true, sortable: true, getText: (g) => String(g.seq) },
      { key: 'subject', label: '镜像内路径', width: 340, getText: (g) => g.subject },
      {
        key: 'status',
        label: '状态',
        width: 118,
        pill: true,
        filterable: true,
        filterMode: 'single',
        getText: (g) => g.status,
      },
      {
        key: 'offset',
        label: '分区偏移',
        width: 115,
        mono: true,
        filterable: true,
        filterMode: 'single',
        getText: (g) => String(g.offset),
      },
      { key: 'inode', label: 'inode', width: 100, mono: true, getText: (g) => g.inode || '—' },
      { key: 'count', label: '记录数', width: 82, mono: true, getText: (g) => String(g.count) },
      {
        key: 'latest',
        label: '最近记录（UTC+8）',
        width: 174,
        mono: true,
        sortable: true,
        getText: (g) => g.latestTime,
      },
    ],
    []
  );

  const detailSections = useMemo<DossierSection[]>(() => {
    if (!selectedGroup) return [];
    const list: DossierSection[] = [
      {
        title: '证据来源',
        rows: [
          ['分区偏移（扇区）', String(selectedGroup.offset)],
          ['inode', selectedGroup.inode || '—'],
          ['镜像 SHA-256', selectedGroup.imageSha256 || '记录时待固定'],
        ],
      },
    ];
    for (const rec of [...selectedGroup.records].reverse()) {
      const originLabel = rec.originLabel ?? (rec.origin === 'mcp' ? 'MCP' : '人工');
      const opName = rec.actionTitle ?? FINDING_OPERATIONS[rec.action] ?? rec.action;
      const rows: [string, unknown][] = [
        ['时间', rec.timestamp],
        ['操作来源', originLabel],
      ];
      if (rec.mcpUser) {
        rows.push(['MCP 使用者', rec.mcpUser]);
      }
      rows.push(
        ['操作人员', rec.actor],
        ['结果', rec.result]
      );
      for (const [fieldKey, label] of DETAIL_FIELD_LABELS) {
        const val = rec.details?.[fieldKey];
        if (val !== undefined && val !== null && val !== '') {
          rows.push([label, val]);
        }
      }
      list.push({
        title: `#${rec.seq} · ${opName}`,
        rows,
      });
    }
    return list;
  }, [selectedGroup]);

  return (
    <div className="td-panel">
      <div className="td-panel-top-bar">
        <span className="td-section-title" style={{ flex: 1 }}>
          {statusText}
        </span>
        <button
          type="button"
          className="td-btn td-btn--soft"
          disabled={busy || !snapshot?.evidence || groups.length === 0}
          onClick={() => onExportFindings(groups.map((g) => g.groupKey))}
        >
          <UiIcon name="export" size={14} color={groups.length > 0 ? 'var(--accent-soft-text)' : 'var(--text-disabled)'} />
          一键导出
        </button>
      </div>

      <div className="td-panel-sub-bar">
        <div className="td-search-box">
          <span className="td-search-box-icon">
            <UiIcon name="search" size={14} color="var(--text-muted)" />
          </span>
          <input
            type="text"
            className="td-input"
            placeholder="搜索文件、笔记、摘要、人员或比对结果"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                setDebouncedKeyword(keyword.trim());
              }
            }}
          />
          {keyword && (
            <button
              type="button"
              className="td-search-clear"
              onClick={() => {
                setKeyword('');
                setDebouncedKeyword('');
              }}
            >
              ×
            </button>
          )}
        </div>
      </div>

      <SplitPane
        direction="vertical"
        initialSize={0.42}
        minFirst={140}
        minSecond={160}
        secondHidden={!detailOpen}
        first={
          <VirtualTable
            rows={groups}
            columns={columns}
            rowKey={(g) => g.groupKey}
            selectedKey={selectedKey}
            filterOptions={filterOptions}
            activeFilters={activeFilters}
            onFilterChange={(colKey, vals) =>
              setActiveFilters((prev) => ({ ...prev, [colKey]: vals }))
            }
            sortColumn={sortColumn}
            sortDescending={sortDescending}
            onSortRequest={(colKey) => {
              if (colKey !== 'seq' && colKey !== 'latest') return;
              if (sortColumn === colKey) {
                setSortDescending((prev) => !prev);
              } else {
                setSortColumn(colKey);
                setSortDescending(false);
              }
            }}
            onSelectRow={(g) => setSelectedKey(g.groupKey)}
            onDoubleClickRow={(g) => {
              setSelectedKey(g.groupKey);
              setDetailOpen(true);
            }}
            emptyText={
              snapshot
                ? '尚无取证发现 · 在文件浏览预览区点击「记为取证发现」或右键文件可记录笔记、计算摘要或比对副本'
                : '尚未打开案件'
            }
          />
        }
        second={
          selectedGroup ? (
            <DossierView
              title={selectedGroup.subject}
              subtitle="取证记录 · 笔记 / 摘要 / 副本比对"
              sections={detailSections}
              onClose={handleCloseDetail}
            />
          ) : (
            <DossierView
              title="选择一条记录查看详情"
              subtitle={`当前显示 ${groups.length} 条`}
              sections={[]}
              onClose={handleCloseDetail}
            />
          )
        }
      />
    </div>
  );
};

export const FindingsModule = React.memo(FindingsModuleInner);
