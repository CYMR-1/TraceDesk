/**
 * 统一取证表头组件 (FilterHeader)：
 * - 支持首列三态复选框（未选 / 半选 / 全选）与“全选”字样；
 * - 支持表头下拉多选筛选（含“全部”清空项与多选勾选，激活态 #E5F1FE + 2px 晴空蓝底边）；
 * - 支持指定列正/倒序排序指示与悬停提示；
 * - 支持列宽拖拽调整。
 */
import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';

export type CheckState = 'unchecked' | 'indeterminate' | 'checked';

export interface FilterColumnSpec {
  key: string;
  label: string;
  width: number;
  minWidth?: number;
  align?: 'left' | 'center' | 'right';
  tooltip?: string;
  checkable?: boolean;
  checkLabel?: string;
  filterable?: boolean;
  /** 单选或多选筛选（默认 multi 支持多选勾选，点击“全部”可清除） */
  filterMode?: 'multi' | 'single';
  sortable?: boolean;
}

interface FilterHeaderProps {
  columns: FilterColumnSpec[];
  columnWidths: number[];
  onResizeColumn?: (index: number, width: number) => void;
  checkState?: CheckState;
  onToggleCheckAll?: (checked: boolean) => void;
  filterOptions?: Record<string, string[]>;
  activeFilters?: Record<string, string[]>;
  onFilterChange?: (columnKey: string, selectedValues: string[]) => void;
  sortColumn?: string | null;
  sortDescending?: boolean;
  onSortRequest?: (columnKey: string) => void;
}

export const TriStateCheckbox: React.FC<{
  state: CheckState;
  disabled?: boolean;
  onChange?: (checked: boolean) => void;
  ariaLabel?: string;
}> = ({ state, disabled = false, onChange, ariaLabel }) => (
  <button
    type="button"
    role="checkbox"
    aria-checked={state === 'indeterminate' ? 'mixed' : state === 'checked'}
    aria-label={ariaLabel}
    disabled={disabled}
    className={`td-checkbox ${state === 'checked' ? 'td-checkbox--checked' : ''} ${state === 'indeterminate' ? 'td-checkbox--indeterminate' : ''}`}
    onClick={(e) => {
      e.stopPropagation();
      if (!disabled) {
        onChange?.(state !== 'checked');
      }
    }}
  >
    {state === 'checked' && (
      <svg width="11" height="11" viewBox="0 0 12 12" aria-hidden="true">
        <path
          d="M2.2 6.2 4.8 8.8 9.8 3.3"
          fill="none"
          stroke="#FFFFFF"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    )}
    {state === 'indeterminate' && (
      <svg width="11" height="11" viewBox="0 0 12 12" aria-hidden="true">
        <line
          x1="2.6"
          y1="6"
          x2="9.4"
          y2="6"
          stroke="#FFFFFF"
          strokeWidth="1.9"
          strokeLinecap="round"
        />
      </svg>
    )}
  </button>
);

export const FilterHeader: React.FC<FilterHeaderProps> = ({
  columns,
  columnWidths,
  onResizeColumn,
  checkState = 'unchecked',
  onToggleCheckAll,
  filterOptions = {},
  activeFilters = {},
  onFilterChange,
  sortColumn = null,
  sortDescending = false,
  onSortRequest,
}) => {
  const [openMenu, setOpenMenu] = useState<{
    columnKey: string;
    mode: 'multi' | 'single';
    x: number;
    y: number;
    minWidth: number;
  } | null>(null);
  const [hoveredCol, setHoveredCol] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [menuPos, setMenuPos] = useState<{ left: number; top: number }>({ left: 0, top: 0 });

  useLayoutEffect(() => {
    if (!openMenu) return;
    const el = menuRef.current;
    if (!el) {
      setMenuPos({ left: openMenu.x, top: openMenu.y });
      return;
    }
    const rect = el.getBoundingClientRect();
    const left = Math.min(openMenu.x, Math.max(8, window.innerWidth - rect.width - 8));
    const top = Math.min(openMenu.y, Math.max(8, window.innerHeight - rect.height - 8));
    setMenuPos({ left, top });
  }, [openMenu]);

  useEffect(() => {
    if (!openMenu) return;
    const onDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpenMenu(null);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpenMenu(null);
    };
    window.addEventListener('mousedown', onDown, true);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('mousedown', onDown, true);
      window.removeEventListener('keydown', onKey);
    };
  }, [openMenu]);

  const startResize = (e: React.MouseEvent, index: number, minWidth: number) => {
    e.stopPropagation();
    e.preventDefault();
    const startX = e.clientX;
    const startW = columnWidths[index] ?? columns[index].width;

    const onMove = (moveEvent: MouseEvent) => {
      const next = Math.max(minWidth, startW + (moveEvent.clientX - startX));
      onResizeColumn?.(index, next);
    };
    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };

  const openOptions = openMenu ? filterOptions[openMenu.columnKey] ?? [] : [];
  const openSelected = openMenu ? activeFilters[openMenu.columnKey] ?? [] : [];

  const toggleOption = (option: string) => {
    if (!openMenu) return;
    if (openMenu.mode === 'single') {
      const next = openSelected.length === 1 && openSelected[0] === option ? [] : [option];
      onFilterChange?.(openMenu.columnKey, next);
      setOpenMenu(null);
      return;
    }
    const set = new Set(openSelected);
    if (set.has(option)) {
      set.delete(option);
    } else {
      set.add(option);
    }
    onFilterChange?.(openMenu.columnKey, Array.from(set));
  };

  return (
    <>
      <div className="td-vtable-header" role="row">
        {columns.map((col, idx) => {
          const width = columnWidths[idx] ?? col.width;
          const selected = activeFilters[col.key] ?? [];
          const isFiltered = Boolean(col.filterable && selected.length > 0);
          const isSorted = Boolean(col.sortable && sortColumn === col.key);
          const isInteractive = Boolean(col.checkable || col.filterable || col.sortable);
          const isHovered = hoveredCol === col.key;

          const displayLabel = isFiltered
            ? selected.length === 1
              ? `${col.label}：${selected[0]}`
              : `${col.label} (${selected.length})`
            : col.label;

          const alignClass =
            col.align === 'center'
              ? 'td-header-cell--center'
              : col.align === 'right'
                ? 'td-header-cell--right'
                : '';

          return (
            <div
              key={col.key}
              role="columnheader"
              style={{ width, minWidth: col.minWidth ?? 44 }}
              title={col.tooltip ?? (col.filterable ? '单击下拉筛选' : col.sortable ? '单击切换正序/倒序' : col.label)}
              className={[
                'td-header-cell',
                alignClass,
                isInteractive ? 'td-header-cell--interactive' : '',
                isFiltered ? 'td-header-cell--filtered' : '',
                isSorted ? 'td-header-cell--sorted' : '',
              ]
                .filter(Boolean)
                .join(' ')}
              onMouseEnter={() => setHoveredCol(col.key)}
              onMouseLeave={() => setHoveredCol(null)}
              onClick={(e) => {
                if (col.checkable) {
                  onToggleCheckAll?.(checkState !== 'checked');
                  return;
                }
                if (col.filterable) {
                  const rect = e.currentTarget.getBoundingClientRect();
                  setOpenMenu((prev) =>
                    prev?.columnKey === col.key
                      ? null
                      : {
                          columnKey: col.key,
                          mode: col.filterMode ?? 'multi',
                          x: rect.left,
                          y: rect.bottom + 1,
                          minWidth: Math.max(148, rect.width),
                        }
                  );
                  return;
                }
                if (col.sortable) {
                  onSortRequest?.(col.key);
                }
              }}
            >
              {col.checkable ? (
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <TriStateCheckbox
                    state={checkState}
                    onChange={(checked) => onToggleCheckAll?.(checked)}
                    ariaLabel={col.checkLabel ?? '全选'}
                  />
                  {col.checkLabel && <span>{col.checkLabel}</span>}
                </div>
              ) : (
                <>
                  <span className="td-header-cell-label">{displayLabel}</span>
                  {col.filterable && (
                    <span className="td-header-indicator" aria-hidden="true">
                      {isFiltered ? (
                        <svg width="10" height="10" viewBox="0 0 10 10">
                          <polygon points="1.5,3 8.5,3 5,7.4" fill="var(--accent)" />
                        </svg>
                      ) : (
                        <svg width="10" height="10" viewBox="0 0 10 10">
                          <path
                            d="M1.8 3.5 5 6.8 8.2 3.5"
                            fill="none"
                            stroke={isHovered ? 'var(--accent)' : 'var(--text-muted)'}
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          />
                        </svg>
                      )}
                    </span>
                  )}
                  {col.sortable && (
                    <span className="td-header-indicator" aria-hidden="true">
                      {isSorted ? (
                        <svg width="10" height="10" viewBox="0 0 10 10">
                          {sortDescending ? (
                            <path
                              d="M1.8 3.4 5 6.8 8.2 3.4"
                              fill="none"
                              stroke="var(--accent)"
                              strokeWidth="1.6"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                            />
                          ) : (
                            <path
                              d="M1.8 6.6 5 3.2 8.2 6.6"
                              fill="none"
                              stroke="var(--accent)"
                              strokeWidth="1.6"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                            />
                          )}
                        </svg>
                      ) : isHovered ? (
                        <svg width="10" height="12" viewBox="0 0 10 12">
                          <path
                            d="M2.4 4.6 5 2 7.6 4.6"
                            fill="none"
                            stroke="var(--text-muted)"
                            strokeWidth="1.3"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          />
                          <path
                            d="M2.4 7.4 5 10 7.6 7.4"
                            fill="none"
                            stroke="var(--text-muted)"
                            strokeWidth="1.3"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          />
                        </svg>
                      ) : null}
                    </span>
                  )}
                </>
              )}
              {onResizeColumn && !col.checkable && (
                <div
                  className="td-col-resizer"
                  onMouseDown={(e) => startResize(e, idx, col.minWidth ?? 44)}
                  onClick={(e) => e.stopPropagation()}
                />
              )}
            </div>
          );
        })}
      </div>

      {openMenu && (
        <div
          ref={menuRef}
          className="td-menu"
          style={{ left: menuPos.left, top: menuPos.top, minWidth: openMenu.minWidth }}
          role="menu"
        >
          <button
            type="button"
            className={`td-menu-item ${openSelected.length === 0 ? 'td-menu-item--active' : ''}`}
            onClick={() => {
              onFilterChange?.(openMenu.columnKey, []);
              setOpenMenu(null);
            }}
          >
            <TriStateCheckbox state={openSelected.length === 0 ? 'checked' : 'unchecked'} />
            <span>全部</span>
          </button>
          <div className="td-menu-sep" />
          {openOptions.length === 0 ? (
            <button type="button" className="td-menu-item" disabled>
              （暂无可选项）
            </button>
          ) : (
            openOptions.map((option) => {
              const checked = openSelected.includes(option);
              return (
                <button
                  key={option}
                  type="button"
                  className={`td-menu-item ${checked ? 'td-menu-item--active' : ''}`}
                  onClick={() => toggleOption(option)}
                >
                  <TriStateCheckbox state={checked ? 'checked' : 'unchecked'} />
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{option}</span>
                </button>
              );
            })
          )}
          {openMenu.mode === 'multi' && openSelected.length > 0 && (
            <>
              <div className="td-menu-sep" />
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '2px 6px' }}>
                <button
                  type="button"
                  className="td-btn td-btn--compact"
                  onClick={() => {
                    onFilterChange?.(openMenu.columnKey, []);
                    setOpenMenu(null);
                  }}
                >
                  清除筛选
                </button>
                <button
                  type="button"
                  className="td-btn td-btn--compact"
                  onClick={() => setOpenMenu(null)}
                >
                  完成
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </>
  );
};
