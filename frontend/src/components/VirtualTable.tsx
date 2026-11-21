/**
 * 高性能虚拟滚动表格 (VirtualTable)：
 * 专门承载万级/十万级内容搜索实时流式命中、MACB 时间线、审计日志与取证发现；
 * 仅渲染可视区域 + 12 行缓冲区，集成 FilterHeader、2.5px 晴空蓝选中导轨、语义胶囊、等宽列与行复选框。
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { FilterHeader, TriStateCheckbox, type CheckState, type FilterColumnSpec } from './FilterHeader';
import { isMutedPlaceholder, SemanticPill } from './SemanticPill';

export interface VirtualColumn<T> extends FilterColumnSpec {
  mono?: boolean;
  subtle?: boolean;
  pill?: boolean;
  renderCell?: (row: T, rowIndex: number) => React.ReactNode;
  getText?: (row: T, rowIndex: number) => string;
  getTooltip?: (row: T, rowIndex: number) => string | undefined;
}

interface VirtualTableProps<T> {
  rows: readonly T[];
  columns: VirtualColumn<T>[];
  rowKey: (row: T, index: number) => string | number;
  rowHeight?: number;
  overscan?: number;
  selectedKey?: string | number | null;
  onSelectRow?: (row: T, index: number) => void;
  onDoubleClickRow?: (row: T, index: number, columnKey: string) => void;
  onContextMenuRow?: (e: React.MouseEvent, row: T, index: number) => void;
  isRowDisabled?: (row: T) => boolean;
  isRowChecked?: (row: T) => boolean;
  onToggleRowCheck?: (row: T, checked: boolean) => void;
  checkState?: CheckState;
  onToggleCheckAll?: (checked: boolean) => void;
  filterOptions?: Record<string, string[]>;
  activeFilters?: Record<string, string[]>;
  onFilterChange?: (columnKey: string, values: string[]) => void;
  sortColumn?: string | null;
  sortDescending?: boolean;
  onSortRequest?: (columnKey: string) => void;
  emptyText?: string;
  /** 可选外部滚动定位索引 */
  scrollToIndex?: number | null;
}

export function VirtualTable<T>({
  rows,
  columns,
  rowKey,
  rowHeight = 28,
  overscan = 12,
  selectedKey = null,
  onSelectRow,
  onDoubleClickRow,
  onContextMenuRow,
  isRowDisabled,
  isRowChecked,
  onToggleRowCheck,
  checkState = 'unchecked',
  onToggleCheckAll,
  filterOptions,
  activeFilters,
  onFilterChange,
  sortColumn,
  sortDescending,
  onSortRequest,
  emptyText = '暂无记录',
  scrollToIndex = null,
}: VirtualTableProps<T>) {
  const scrollerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(420);
  const [colWidths, setColWidths] = useState<number[]>(() => columns.map((c) => c.width));

  useEffect(() => {
    setColWidths((prev) =>
      columns.map((c, idx) => (idx < prev.length ? prev[idx] : c.width))
    );
  }, [columns.length]);

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    const update = () => setViewportHeight(el.clientHeight || 420);
    update();
    if (typeof ResizeObserver !== 'undefined') {
      const obs = new ResizeObserver(update);
      obs.observe(el);
      return () => obs.disconnect();
    }
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, []);

  useEffect(() => {
    if (scrollToIndex == null || scrollToIndex < 0 || !scrollerRef.current) return;
    const el = scrollerRef.current;
    const targetTop = scrollToIndex * rowHeight;
    const headerHeight = 32;
    const visibleTop = el.scrollTop;
    const visibleBottom = visibleTop + el.clientHeight - headerHeight;
    if (targetTop < visibleTop) {
      el.scrollTop = targetTop;
    } else if (targetTop + rowHeight > visibleBottom) {
      el.scrollTop = Math.max(0, targetTop + rowHeight - (el.clientHeight - headerHeight));
    }
  }, [scrollToIndex, rowHeight]);

  const handleResizeColumn = useCallback((index: number, width: number) => {
    setColWidths((prev) => {
      const next = [...prev];
      next[index] = width;
      return next;
    });
  }, []);

  const totalWidth = useMemo(
    () => colWidths.reduce((sum, w) => sum + w, 0),
    [colWidths]
  );

  const totalHeight = rows.length * rowHeight;

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    const maxScroll = Math.max(0, totalHeight - Math.max(0, viewportHeight - 32));
    if (el.scrollTop > maxScroll) {
      el.scrollTop = maxScroll;
      setScrollTop(maxScroll);
    }
  }, [totalHeight, viewportHeight]);

  const startIndex = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const visibleCount = Math.ceil(viewportHeight / rowHeight) + overscan * 2;
  const endIndex = Math.min(rows.length, startIndex + visibleCount);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (rows.length === 0 || !onSelectRow) return;
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const currentIndex = rows.findIndex((r, idx) => rowKey(r, idx) === selectedKey);
    const nextIndex =
      e.key === 'ArrowDown'
        ? Math.min(rows.length - 1, currentIndex + 1)
        : Math.max(0, currentIndex <= 0 ? 0 : currentIndex - 1);
    const target = rows[nextIndex];
    if (target) {
      onSelectRow(target, nextIndex);
      const el = scrollerRef.current;
      if (el) {
        const y = nextIndex * rowHeight;
        if (y < el.scrollTop) el.scrollTop = y;
        else if (y + rowHeight > el.scrollTop + el.clientHeight - 32) {
          el.scrollTop = Math.max(0, y + rowHeight - (el.clientHeight - 32));
        }
      }
    }
  };

  return (
    <div className="td-vtable" tabIndex={0} onKeyDown={handleKeyDown}>
      <div
        ref={scrollerRef}
        className="td-vtable-scroller"
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        <div style={{ minWidth: totalWidth, width: '100%' }}>
          <FilterHeader
            columns={columns}
            columnWidths={colWidths}
            onResizeColumn={handleResizeColumn}
            checkState={checkState}
            onToggleCheckAll={onToggleCheckAll}
            filterOptions={filterOptions}
            activeFilters={activeFilters}
            onFilterChange={onFilterChange}
            sortColumn={sortColumn}
            sortDescending={sortDescending}
            onSortRequest={onSortRequest}
          />
          {rows.length === 0 ? (
            <div className="td-vtable-empty">{emptyText}</div>
          ) : (
            <div className="td-vtable-body" style={{ height: totalHeight }}>
              {rows.slice(startIndex, endIndex).map((row, sliceIdx) => {
                const index = startIndex + sliceIdx;
                const key = rowKey(row, index);
                const selected = selectedKey !== null && key === selectedKey;
                const disabled = isRowDisabled?.(row) ?? false;
                const checked = isRowChecked?.(row) ?? false;

                return (
                  <div
                    key={key}
                    role="row"
                    aria-selected={selected}
                    style={{ top: index * rowHeight, height: rowHeight }}
                    className={[
                      'td-vtable-row',
                      index % 2 === 1 ? 'td-vtable-row--alt' : '',
                      selected ? 'td-vtable-row--selected' : '',
                      disabled ? 'td-vtable-row--disabled' : '',
                    ]
                      .filter(Boolean)
                      .join(' ')}
                    onClick={() => onSelectRow?.(row, index)}
                    onContextMenu={(e) => {
                      if (onContextMenuRow) {
                        e.preventDefault();
                        onSelectRow?.(row, index);
                        onContextMenuRow(e, row, index);
                      }
                    }}
                  >
                    {columns.map((col, colIdx) => {
                      const width = colWidths[colIdx] ?? col.width;
                      const rawText = col.getText ? col.getText(row, index) : '';
                      const tooltip = col.getTooltip ? col.getTooltip(row, index) : rawText || undefined;
                      const alignClass =
                        col.align === 'center'
                          ? 'td-vtable-cell--center'
                          : col.align === 'right'
                            ? 'td-vtable-cell--right'
                            : '';

                      let content: React.ReactNode;
                      if (col.checkable) {
                        content = (
                          <TriStateCheckbox
                            state={checked ? 'checked' : 'unchecked'}
                            disabled={disabled}
                            onChange={(nextChecked) => onToggleRowCheck?.(row, nextChecked)}
                          />
                        );
                      } else if (col.renderCell) {
                        content = col.renderCell(row, index);
                      } else if (col.pill) {
                        content = <SemanticPill text={rawText} title={tooltip} />;
                      } else {
                        const muted = !selected && isMutedPlaceholder(rawText);
                        const subtle = !selected && !muted && Boolean(col.subtle);
                        content = (
                          <span
                            className={[
                              'td-vtable-cell-text',
                              col.mono ? 'td-mono' : '',
                              muted ? 'td-muted-text' : '',
                              subtle ? 'td-subtle-text' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                          >
                            {rawText}
                          </span>
                        );
                      }

                      return (
                        <div
                          key={col.key}
                          role="gridcell"
                          title={col.checkable ? undefined : tooltip}
                          style={{
                            width,
                            flexGrow: colIdx === columns.length - 1 ? 1 : 0,
                          }}
                          className={`td-vtable-cell ${alignClass}`}
                          onDoubleClick={() => onDoubleClickRow?.(row, index, col.key)}
                        >
                          {content}
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
