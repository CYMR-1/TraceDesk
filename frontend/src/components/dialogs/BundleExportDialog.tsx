/**
 * 复核包材料选择与缺失核查弹窗 (BundleExportDialog 1:1)
 */
import React, { useMemo, useState } from 'react';
import type { BundleExportRow, BundleMaterialsResponse, BundleSearchRow } from '../../types/ipc';
import { copyToClipboard, formatBytes } from '../../utils/assets';
import { UiIcon } from '../Icons';
import { VirtualTable, type VirtualColumn } from '../VirtualTable';
import { Modal } from './Modal';

interface BundleExportDialogProps {
  materials: BundleMaterialsResponse;
  onConfirm: (selectedExportIndices: number[], selectedSearchIndices: number[]) => void;
  onClose: () => void;
}

export const BundleExportDialog: React.FC<BundleExportDialogProps> = ({
  materials,
  onConfirm,
  onClose,
}) => {
  const availableExports = useMemo(() => materials.exports.filter((r) => r.exists), [materials.exports]);
  const missingExports = useMemo(() => materials.exports.filter((r) => !r.exists), [materials.exports]);
  const availableSearches = useMemo(() => materials.searches.filter((r) => r.exists), [materials.searches]);
  const missingSearches = useMemo(() => materials.searches.filter((r) => !r.exists), [materials.searches]);

  const [tab, setTab] = useState<'exports' | 'searches'>('exports');
  const [selectedExportIds, setSelectedExportIds] = useState<Set<number>>(
    () => new Set(availableExports.map((r) => r.index))
  );
  const [selectedSearchIds, setSelectedSearchIds] = useState<Set<number>>(
    () => new Set(availableSearches.map((r) => r.index))
  );
  const [onlyMissingExports, setOnlyMissingExports] = useState(false);
  const [onlyMissingSearches, setOnlyMissingSearches] = useState(false);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);

  const hasMissing = missingExports.length > 0 || missingSearches.length > 0;

  const displayedExports = useMemo(
    () => (onlyMissingExports ? missingExports : materials.exports),
    [onlyMissingExports, missingExports, materials.exports]
  );

  const displayedSearches = useMemo(
    () => (onlyMissingSearches ? missingSearches : materials.searches),
    [onlyMissingSearches, missingSearches, materials.searches]
  );

  const exportColumns = useMemo<VirtualColumn<BundleExportRow>[]>(
    () => [
      { key: 'check', label: '', width: 38, checkable: true, checkLabel: '' },
      { key: 'index', label: '序号', width: 54, align: 'center', mono: true, getText: (r) => String(r.index) },
      {
        key: 'status',
        label: '副本状态',
        width: 84,
        align: 'center',
        pill: true,
        getText: (r) => (r.exists ? '正常' : '缺失'),
        getTooltip: (r) => (r.exists ? '文件存在' : r.missingReason || '文件缺失'),
      },
      {
        key: 'displayPath',
        label: '本地副本路径',
        width: 210,
        mono: true,
        getText: (r) => r.displayPath,
        getTooltip: (r) => (r.exists ? r.displayPath : r.missingReason || r.displayPath),
      },
      { key: 'source', label: '镜像内路径', width: 220, getText: (r) => r.source },
      {
        key: 'size',
        label: '字节数',
        width: 108,
        align: 'right',
        mono: true,
        getText: (r) => formatBytes(r.size),
      },
      {
        key: 'time',
        label: '导出时间（UTC+8）',
        width: 164,
        mono: true,
        subtle: true,
        getText: (r) => r.time || '未记录',
      },
    ],
    []
  );

  const searchColumns = useMemo<VirtualColumn<BundleSearchRow>[]>(
    () => [
      { key: 'check', label: '', width: 38, checkable: true, checkLabel: '' },
      { key: 'index', label: '序号', width: 50, align: 'center', mono: true, getText: (r) => String(r.index) },
      {
        key: 'status',
        label: '文件状态',
        width: 80,
        align: 'center',
        pill: true,
        getText: (r) => (r.exists ? '正常' : '缺失'),
        getTooltip: (r) => (r.exists ? '文件存在' : r.missingReason || '文件缺失'),
      },
      {
        key: 'displayPath',
        label: '本地记录路径',
        width: 200,
        mono: true,
        getText: (r) => r.displayPath,
        getTooltip: (r) => (r.exists ? r.displayPath : r.missingReason || r.displayPath),
      },
      { key: 'query', label: '搜索内容', width: 190, getText: (r) => r.query },
      { key: 'encoding', label: '编码', width: 74, mono: true, getText: (r) => r.encoding },
      { key: 'hits', label: '命中数', width: 64, align: 'right', mono: true, getText: (r) => String(r.hits) },
      {
        key: 'time',
        label: '搜索时间（UTC+8）',
        width: 162,
        mono: true,
        subtle: true,
        getText: (r) => r.time || '未记录',
      },
    ],
    []
  );

  const missingParts: string[] = [];
  if (missingExports.length > 0) missingParts.push(`${missingExports.length} 条历史导出副本`);
  if (missingSearches.length > 0) missingParts.push(`${missingSearches.length} 条历史内容搜索记录`);

  const summaryParts = [
    `导出副本 ${selectedExportIds.size}/${availableExports.length}` +
      (missingExports.length ? `（缺失 ${missingExports.length}）` : ''),
  ];
  if (materials.searches.length > 0) {
    summaryParts.push(
      `搜索记录 ${selectedSearchIds.size}/${availableSearches.length}` +
        (missingSearches.length ? `（缺失 ${missingSearches.length}）` : '')
    );
  }

  const tabTitle = (name: string, available: number, missing: number) =>
    missing > 0 ? `${name}（可用 ${available} · 缺失 ${missing}）` : `${name}（${available}）`;

  const handleCopyMissing = async () => {
    const ok = await copyToClipboard(materials.missingText);
    if (ok) {
      setCopyNotice('已复制缺失材料清单到剪贴板');
      window.setTimeout(() => setCopyNotice(null), 2500);
    }
  };

  return (
    <Modal
      title="导出复核包 · 选择纳入材料"
      width={920}
      height={640}
      onClose={onClose}
      footer={
        <>
          <span className="td-muted-text" style={{ fontSize: 12 }}>
            {copyNotice ?? `已选：${summaryParts.join('  ·  ')}`}
          </span>
          <div className="td-modal-footer-spacer" />
          {hasMissing && (
            <button type="button" className="td-btn" onClick={() => void handleCopyMissing()}>
              <UiIcon name="copy" size={14} color="var(--text-secondary)" />
              复制缺失清单
            </button>
          )}
          <button type="button" className="td-btn" onClick={onClose}>
            取消
          </button>
          <button
            type="button"
            className="td-btn td-btn--accent"
            onClick={() => {
              onConfirm(
                Array.from(selectedExportIds).sort((a, b) => a - b),
                Array.from(selectedSearchIds).sort((a, b) => a - b)
              );
              onClose();
            }}
          >
            生成复核包
          </button>
        </>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%' }}>
        {hasMissing ? (
          <div className="td-banner td-banner--warning">
            <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
              <UiIcon name="warning" size={18} color="var(--warn-fg)" />
              <div style={{ fontWeight: 600 }}>
                检测到 {missingParts.join(' 与 ')} 在本地目录中缺失（可能已被手动清理或被安全软件隔离）。
                缺失项已标红且不可勾选；您可以自由勾选现存材料继续生成复核包，未纳入项会如实记入 manifest.json：
              </div>
            </div>
            <pre
              className="td-code-block"
              style={{
                maxHeight: 112,
                background: '#FFFDF8',
                color: 'var(--warn-fg)',
                borderColor: 'var(--warn-border)',
              }}
            >
              {materials.missingText}
            </pre>
          </div>
        ) : (
          <div className="td-banner td-banner--ok">
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <UiIcon name="check_shield" size={18} color="var(--ok-fg)" />
              <span>
                全部历史导出副本（{availableExports.length} 条）与内容搜索记录（{availableSearches.length} 条）均完整存在。
                默认全部勾选，您可自由取消不需要打入复核包的条目。
              </span>
            </div>
          </div>
        )}

        <div className="td-dialog-tabs">
          <div className="td-dialog-tab-bar" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={tab === 'exports'}
              className={`td-dialog-tab ${tab === 'exports' ? 'td-dialog-tab--active' : ''}`}
              onClick={() => setTab('exports')}
            >
              {tabTitle('导出副本', availableExports.length, missingExports.length)}
            </button>
            {materials.searches.length > 0 && (
              <button
                type="button"
                role="tab"
                aria-selected={tab === 'searches'}
                className={`td-dialog-tab ${tab === 'searches' ? 'td-dialog-tab--active' : ''}`}
                onClick={() => setTab('searches')}
              >
                {tabTitle('内容搜索记录', availableSearches.length, missingSearches.length)}
              </button>
            )}
          </div>

          <div className="td-dialog-tab-pane">
            {tab === 'exports' ? (
              <>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <button
                    type="button"
                    className="td-btn td-btn--soft"
                    onClick={() => setSelectedExportIds(new Set(availableExports.map((r) => r.index)))}
                  >
                    全选可用副本
                  </button>
                  <button
                    type="button"
                    className="td-btn"
                    onClick={() => setSelectedExportIds(new Set())}
                  >
                    全不选
                  </button>
                  {missingExports.length > 0 && (
                    <button
                      type="button"
                      className="td-btn"
                      onClick={() => setOnlyMissingExports((prev) => !prev)}
                    >
                      {onlyMissingExports ? '显示全部' : `仅看缺失项 (${missingExports.length})`}
                    </button>
                  )}
                </div>
                <div style={{ flex: 1, minHeight: 0, border: '1px solid var(--border-subtle)', borderRadius: 4, display: 'flex' }}>
                  <VirtualTable
                    rows={displayedExports}
                    columns={exportColumns}
                    rowKey={(r) => r.index}
                    isRowDisabled={(r) => !r.exists}
                    isRowChecked={(r) => r.exists && selectedExportIds.has(r.index)}
                    checkState={
                      availableExports.length === 0 || selectedExportIds.size === 0
                        ? 'unchecked'
                        : selectedExportIds.size === availableExports.length
                          ? 'checked'
                          : 'indeterminate'
                    }
                    onToggleCheckAll={(checked) =>
                      setSelectedExportIds(
                        checked ? new Set(availableExports.map((r) => r.index)) : new Set()
                      )
                    }
                    onToggleRowCheck={(row, checked) => {
                      if (!row.exists) return;
                      setSelectedExportIds((prev) => {
                        const next = new Set(prev);
                        if (checked) next.add(row.index);
                        else next.delete(row.index);
                        return next;
                      });
                    }}
                    emptyText="无导出副本记录"
                  />
                </div>
              </>
            ) : (
              <>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <button
                    type="button"
                    className="td-btn td-btn--soft"
                    onClick={() => setSelectedSearchIds(new Set(availableSearches.map((r) => r.index)))}
                  >
                    全选可用记录
                  </button>
                  <button
                    type="button"
                    className="td-btn"
                    onClick={() => setSelectedSearchIds(new Set())}
                  >
                    全不选
                  </button>
                  {missingSearches.length > 0 && (
                    <button
                      type="button"
                      className="td-btn"
                      onClick={() => setOnlyMissingSearches((prev) => !prev)}
                    >
                      {onlyMissingSearches ? '显示全部' : `仅看缺失项 (${missingSearches.length})`}
                    </button>
                  )}
                </div>
                <div style={{ flex: 1, minHeight: 0, border: '1px solid var(--border-subtle)', borderRadius: 4, display: 'flex' }}>
                  <VirtualTable
                    rows={displayedSearches}
                    columns={searchColumns}
                    rowKey={(r) => r.index}
                    isRowDisabled={(r) => !r.exists}
                    isRowChecked={(r) => r.exists && selectedSearchIds.has(r.index)}
                    checkState={
                      availableSearches.length === 0 || selectedSearchIds.size === 0
                        ? 'unchecked'
                        : selectedSearchIds.size === availableSearches.length
                          ? 'checked'
                          : 'indeterminate'
                    }
                    onToggleCheckAll={(checked) =>
                      setSelectedSearchIds(
                        checked ? new Set(availableSearches.map((r) => r.index)) : new Set()
                      )
                    }
                    onToggleRowCheck={(row, checked) => {
                      if (!row.exists) return;
                      setSelectedSearchIds((prev) => {
                        const next = new Set(prev);
                        if (checked) next.add(row.index);
                        else next.delete(row.index);
                        return next;
                      });
                    }}
                    emptyText="无内容搜索记录"
                  />
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </Modal>
  );
};
