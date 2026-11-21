/**
 * 模块 5：审计日志页 (audit)
 * - 顶栏：SHA-256 哈希链校验结论 + 人工/MCP 操作统计
 * - 实时搜索框 + 7 列虚拟滚动表格（序号默认倒序、时间正倒序，来源/操作人员/操作/结果表头下拉筛选）
 * - 双击下方展开分栏详情（操作详情、操作参数与结果、前序/当前 SHA-256 哈希）
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { tauriApi } from '../api/tauri';
import { DossierView, type DossierSection } from '../components/DossierView';
import { UiIcon } from '../components/Icons';
import { SplitPane } from '../components/SplitPane';
import { VirtualTable, type VirtualColumn } from '../components/VirtualTable';
import { AUDIT_ACTION_TITLES } from '../features/registry';
import type { AuditRecordDto, CaseSnapshot } from '../types/ipc';
import { formatError } from '../utils/assets';

interface AuditLogModuleProps {
  snapshot: CaseSnapshot | null;
  refreshToken: number;
}

const AUDIT_DETAIL_LABELS: Record<string, string> = {
  note: '笔记',
  error: '错误',
  sha256: 'SHA-256',
  offset: '分区偏移（扇区）',
  size: '字节数',
  count: '数量',
  keyword: '关键词',
  actual: '实测摘要',
};

export const AuditLogModule: React.FC<AuditLogModuleProps> = ({ snapshot, refreshToken }) => {
  const [query, setQuery] = useState('');
  const [activeFilters, setActiveFilters] = useState<Record<string, string[]>>({});
  const [filterOptions, setFilterOptions] = useState<Record<string, string[]>>({
    origin: [],
    actor: [],
    action: [],
    result: [],
  });
  const [sortColumn, setSortColumn] = useState<'seq' | 'time'>('seq');
  const [sortDescending, setSortDescending] = useState(true);
  const [statusText, setStatusText] = useState('尚未打开案件');
  const [valid, setValid] = useState(true);
  const [records, setRecords] = useState<AuditRecordDto[]>([]);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const loadAudit = useCallback(async () => {
    if (!snapshot) {
      setStatusText('尚未打开案件');
      setValid(true);
      setRecords([]);
      setFilterOptions({ origin: [], actor: [], action: [], result: [] });
      setDetailOpen(false);
      return;
    }
    try {
      const originSel = activeFilters.origin ?? [];
      const actorSel = activeFilters.actor ?? [];
      const actionSel = activeFilters.action ?? [];
      const resultSel = activeFilters.result ?? [];
      const res = await tauriApi.listAuditLog({
        query: query.trim(),
        origin: originSel.length === 1 ? originSel[0] : null,
        actor: actorSel.length === 1 ? actorSel[0] : null,
        action: actionSel.length === 1 ? actionSel[0] : null,
        result: resultSel.length === 1 ? resultSel[0] : null,
        sortColumn,
        descending: sortDescending,
      });
      setValid(res.valid);
      setStatusText(res.statusText);
      setFilterOptions({
        origin: res.filterOptions.origins,
        actor: res.filterOptions.actors,
        action: res.filterOptions.actions,
        result: res.filterOptions.results,
      });
      const multiFiltered = res.records.filter((r) => {
        const originText = r.originLabel || (r.origin === 'mcp' ? 'MCP' : '人工');
        const actionText = r.actionTitle || AUDIT_ACTION_TITLES[r.action] || r.action;
        if (originSel.length > 1 && !originSel.includes(originText)) return false;
        if (actorSel.length > 1 && !actorSel.includes(r.actor)) return false;
        if (actionSel.length > 1 && !actionSel.includes(actionText)) return false;
        if (resultSel.length > 1 && !resultSel.includes(r.result)) return false;
        return true;
      });
      setRecords(multiFiltered);
    } catch (err) {
      setValid(false);
      setStatusText(`日志校验失败：${formatError(err)}`);
      setRecords([]);
    }
  }, [snapshot, query, activeFilters, sortColumn, sortDescending]);

  useEffect(() => {
    void loadAudit();
  }, [loadAudit, refreshToken]);

  const selectedRecord = useMemo(
    () => records.find((r) => r.seq === selectedSeq) ?? null,
    [records, selectedSeq]
  );

  const columns = useMemo<VirtualColumn<AuditRecordDto>[]>(
    () => [
      { key: 'seq', label: '序号', width: 68, mono: true, sortable: true, getText: (r) => String(r.seq) },
      { key: 'time', label: '时间（UTC+8）', width: 168, mono: true, sortable: true, getText: (r) => r.timestamp },
      {
        key: 'origin',
        label: '来源',
        width: 96,
        pill: true,
        filterable: true,
        getText: (r) => r.originLabel || (r.origin === 'mcp' ? 'MCP' : '人工'),
      },
      { key: 'actor', label: '操作人员', width: 132, filterable: true, getText: (r) => r.actor },
      {
        key: 'action',
        label: '操作',
        width: 150,
        filterable: true,
        getText: (r) => r.actionTitle || AUDIT_ACTION_TITLES[r.action] || r.action,
      },
      { key: 'result', label: '结果', width: 112, pill: true, filterable: true, getText: (r) => r.result },
      { key: 'subject', label: '对象', width: 320, getText: (r) => r.subject },
    ],
    []
  );

  const detailSections = useMemo<DossierSection[]>(() => {
    if (!selectedRecord) return [];
    const originLabel = selectedRecord.originLabel || (selectedRecord.origin === 'mcp' ? 'MCP' : '人工');
    const sections: DossierSection[] = [
      {
        title: '操作详情',
        rows: [
          ['时间（UTC+8）', selectedRecord.timestamp],
          ['操作来源', originLabel],
          ['操作人员', selectedRecord.actor],
          ['对象', selectedRecord.subject],
          ['结果', selectedRecord.result],
          ['操作代码', selectedRecord.action],
        ],
      },
    ];
    const detailEntries = Object.entries(selectedRecord.details || {});
    if (detailEntries.length > 0) {
      sections.push({
        title: '操作参数与结果',
        rows: detailEntries.map(([k, v]) => [
          AUDIT_DETAIL_LABELS[k] ?? k,
          typeof v === 'string' ? v : JSON.stringify(v),
        ]),
      });
    }
    sections.push({
      title: '审计链',
      rows: [
        ['上一条记录哈希', selectedRecord.previous],
        ['本条记录哈希', selectedRecord.hash],
      ],
    });
    return sections;
  }, [selectedRecord]);

  return (
    <div className="td-panel">
      <div className="td-panel-top-bar">
        <span
          className="td-section-title"
          style={{
            flex: 1,
            color: !valid ? 'var(--danger-fg)' : 'var(--text-primary)',
          }}
        >
          {statusText}
        </span>
      </div>

      <div className="td-panel-sub-bar">
        <div className="td-search-box">
          <span className="td-search-box-icon">
            <UiIcon name="search" size={14} color="var(--text-muted)" />
          </span>
          <input
            type="text"
            className="td-input"
            placeholder="搜索来源（人工/MCP）、操作、人员、对象或结果"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {query && (
            <button type="button" className="td-search-clear" onClick={() => setQuery('')}>
              ×
            </button>
          )}
        </div>
      </div>

      <SplitPane
        direction="vertical"
        initialSize={0.62}
        minFirst={160}
        minSecond={160}
        secondHidden={!detailOpen}
        first={
          <VirtualTable
            rows={records}
            columns={columns}
            rowKey={(r) => r.seq}
            selectedKey={selectedSeq}
            filterOptions={filterOptions}
            activeFilters={activeFilters}
            onFilterChange={(colKey, vals) =>
              setActiveFilters((prev) => ({ ...prev, [colKey]: vals }))
            }
            sortColumn={sortColumn}
            sortDescending={sortDescending}
            onSortRequest={(colKey) => {
              if (colKey !== 'seq' && colKey !== 'time') return;
              if (sortColumn === colKey) {
                setSortDescending((prev) => !prev);
              } else {
                setSortColumn(colKey);
                setSortDescending(true);
              }
            }}
            onSelectRow={(r) => setSelectedSeq(r.seq)}
            onDoubleClickRow={(r) => {
              setSelectedSeq(r.seq);
              setDetailOpen(true);
            }}
            emptyText={snapshot ? '没有匹配的审计记录' : '尚未打开案件'}
          />
        }
        second={
          selectedRecord ? (
            <DossierView
              title={`#${selectedRecord.seq} · [${selectedRecord.originLabel || (selectedRecord.origin === 'mcp' ? 'MCP' : '人工')}] ${selectedRecord.actionTitle || AUDIT_ACTION_TITLES[selectedRecord.action] || selectedRecord.action}`}
              subtitle="审计日志 · UTC+8"
              sections={detailSections}
            />
          ) : (
            <DossierView title="选择一条记录查看详情" subtitle={`当前显示 ${records.length} 条`} sections={[]} />
          )
        }
      />
    </div>
  );
};
