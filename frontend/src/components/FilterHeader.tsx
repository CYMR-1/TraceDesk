/**
 * 统一取证表头组件 (FilterHeader)：
 * - 支持首列三态复选框（未选 / 半选 / 全选）与“全选”字样；
 * - 支持表头下拉筛选（区分单选菜单与多选复选框两种视觉交互，激活态 #E5F1FE + 2px 晴空蓝底边）；
 * - 针对“来源”列提供顶层基础项（全部 / 人工 / MCP（全部））与“按具体 MCP 调用方筛选”分层展示；
 * - 候选项超过 6 项时自动显示顶部紧凑搜索框，支持单行省略与完整悬停提示；
 * - 支持指定列正/倒序排序指示与列宽拖拽调整。
 */
import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { resolvePillVariant, type PillVariant } from './SemanticPill';

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
  /** 下拉选项语义分组形态（origin 表示“来源”列：基础来源 + 具体 MCP 调用方分层） */
  filterVariant?: 'default' | 'origin';
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

/** 筛选菜单下拉项的解析模型 */
interface ParsedFilterOption {
  /** 实际回传给业务/后端的原始值 */
  value: string;
  /** 下拉菜单中展示的主文案 */
  displayLabel: string;
  /** 悬停完整提示文案 */
  tooltip: string;
  /** 是否属于具体 MCP 调用方子项（如 MCP · WorkBuddy ...） */
  isSpecificMcp: boolean;
  /** 左侧状态指示点语义色 */
  dotTone: 'manual' | 'mcp' | PillVariant;
}

const SEARCH_THRESHOLD = 6;
const MCP_CALLER_PREFIX_RE = /^MCP\s*[·•]\s*(.+)$/i;

/** 判断某列是否启用“来源”分层筛选样式 */
function isOriginColumn(col: Pick<FilterColumnSpec, 'key' | 'filterVariant'>): boolean {
  return col.filterVariant === 'origin' || col.key === 'origin';
}

/** 格式化表头激活筛选值展示文案（保持 MCP 原始回传值不变） */
function formatHeaderFilterValue(
  col: Pick<FilterColumnSpec, 'key' | 'filterVariant'>,
  value: string
): string {
  if (isOriginColumn(col) && value.trim().toUpperCase() === 'MCP') {
    return 'MCP（全部）';
  }
  return value;
}

/** 解析单个下拉筛选选项的展示标签、MCP 分组属性与状态点色彩 */
function parseFilterOption(option: string, originColumn: boolean): ParsedFilterOption {
  const trimmed = option.trim();
  if (originColumn) {
    if (trimmed === '人工') {
      return {
        value: option,
        displayLabel: '人工',
        tooltip: '人工操作（桌面端界面交互）',
        isSpecificMcp: false,
        dotTone: 'manual',
      };
    }
    if (trimmed.toUpperCase() === 'MCP') {
      return {
        value: option,
        displayLabel: 'MCP（全部）',
        tooltip: '全部 MCP 调用方（含所有已观测客户端）',
        isSpecificMcp: false,
        dotTone: 'mcp',
      };
    }
    const mcpMatch = trimmed.match(MCP_CALLER_PREFIX_RE);
    if (mcpMatch) {
      const callerName = mcpMatch[1].trim() || trimmed;
      return {
        value: option,
        displayLabel: callerName,
        tooltip: option,
        isSpecificMcp: true,
        dotTone: 'mcp',
      };
    }
  }

  const semanticVariant = resolvePillVariant(trimmed, 'neutral') ?? 'neutral';
  return {
    value: option,
    displayLabel: option,
    tooltip: option,
    isSpecificMcp: false,
    dotTone: semanticVariant,
  };
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

/** 多选下拉项内纯视觉圆角复选框（避免在 button 内部嵌套 button） */
const FilterCheckboxVisual: React.FC<{ checked: boolean }> = ({ checked }) => (
  <span
    aria-hidden="true"
    className={`td-filter-checkbox ${checked ? 'td-filter-checkbox--checked' : ''}`}
  >
    {checked && (
      <svg width="10" height="10" viewBox="0 0 12 12">
        <path
          d="M2.2 6.2 4.8 8.8 9.8 3.3"
          fill="none"
          stroke="#FFFFFF"
          strokeWidth="1.9"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    )}
  </span>
);

/** 单选下拉项右侧晴空蓝选中对勾 */
const SingleCheckMark: React.FC = () => (
  <span className="td-filter-check-mark" aria-hidden="true">
    <svg width="13" height="13" viewBox="0 0 14 14">
      <path
        d="M2.6 7.3 5.6 10.3 11.4 4.1"
        fill="none"
        stroke="#2563EB"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  </span>
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
    label: string;
    mode: 'multi' | 'single';
    originGrouped: boolean;
    x: number;
    y: number;
    minWidth: number;
  } | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [hoveredCol, setHoveredCol] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [menuPos, setMenuPos] = useState<{ left: number; top: number }>({ left: 0, top: 0 });

  const openOptions = useMemo(
    () => (openMenu ? filterOptions[openMenu.columnKey] ?? [] : []),
    [openMenu, filterOptions]
  );
  const openSelected = useMemo(
    () => (openMenu ? activeFilters[openMenu.columnKey] ?? [] : []),
    [openMenu, activeFilters]
  );
  const showSearch = openOptions.length > SEARCH_THRESHOLD;

  // 切换列或关闭弹层时清空搜索词
  useEffect(() => {
    setSearchQuery('');
  }, [openMenu?.columnKey]);

  // 超过 6 个选项展示搜索框时，弹层打开后自动聚焦搜索输入
  useEffect(() => {
    if (openMenu && showSearch) {
      const raf = window.requestAnimationFrame(() => {
        searchInputRef.current?.focus();
      });
      return () => window.cancelAnimationFrame(raf);
    }
    return undefined;
  }, [openMenu, showSearch]);

  // 根据实际渲染尺寸避让视口左右/底部边界
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
  }, [openMenu, openOptions.length, searchQuery]);

  useEffect(() => {
    if (!openMenu) return;
    const onDown = (e: MouseEvent) => {
      const target = e.target as HTMLElement | null;
      if (menuRef.current && menuRef.current.contains(target)) {
        return;
      }
      // 点击当前已展开列的表头触发区时，交由 onClick 完成收起，避免先关后开闪烁
      const triggerEl = target?.closest?.('[data-filter-trigger]');
      if (triggerEl?.getAttribute('data-filter-trigger') === openMenu.columnKey) {
        return;
      }
      setOpenMenu(null);
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

  // 解析选项并应用顶部快捷搜索过滤；若为“来源”列则拆分为基础项与具体 MCP 调用方两组
  const { primaryOptions, specificMcpOptions } = useMemo(() => {
    const isOrigin = Boolean(openMenu?.originGrouped);
    const parsed = openOptions.map((opt) => parseFilterOption(opt, isOrigin));
    const kw = searchQuery.trim().toLowerCase();
    const filtered = kw
      ? parsed.filter(
          (item) =>
            item.value.toLowerCase().includes(kw) ||
            item.displayLabel.toLowerCase().includes(kw)
        )
      : parsed;

    if (!isOrigin) {
      return { primaryOptions: filtered, specificMcpOptions: [] as ParsedFilterOption[] };
    }

    const base: ParsedFilterOption[] = [];
    const specific: ParsedFilterOption[] = [];
    for (const item of filtered) {
      if (item.isSpecificMcp) {
        specific.push(item);
      } else {
        base.push(item);
      }
    }
    return { primaryOptions: base, specificMcpOptions: specific };
  }, [openMenu?.originGrouped, openOptions, searchQuery]);

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

  const renderOptionButton = (item: ParsedFilterOption) => {
    if (!openMenu) return null;
    const checked = openSelected.includes(item.value);
    const isSingle = openMenu.mode === 'single';

    return (
      <button
        key={item.value}
        type="button"
        role={isSingle ? 'menuitemradio' : 'menuitemcheckbox'}
        aria-checked={checked}
        title={item.tooltip}
        className={`td-filter-item ${isSingle ? 'td-filter-item--single' : 'td-filter-item--multi'} ${
          checked ? 'td-filter-item--active' : ''
        }`}
        onClick={() => toggleOption(item.value)}
      >
        {isSingle ? (
          item.isSpecificMcp ? (
            <span className="td-filter-mcp-badge" aria-hidden="true">
              MCP
            </span>
          ) : (
            <span
              className={`td-filter-dot td-filter-dot--${item.dotTone}`}
              aria-hidden="true"
            />
          )
        ) : (
          <FilterCheckboxVisual checked={checked} />
        )}
        <span className="td-filter-item-text">{item.displayLabel}</span>
        {isSingle && checked && <SingleCheckMark />}
      </button>
    );
  };

  const isAllSelected = openSelected.length === 0;
  const totalVisibleOptions = primaryOptions.length + specificMcpOptions.length;

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
          const isMenuOpen = openMenu?.columnKey === col.key;

          const displayLabel = isFiltered
            ? selected.length === 1
              ? `${col.label}：${formatHeaderFilterValue(col, selected[0])}`
              : `${col.label} (${selected.length})`
            : col.label;

          const headerTooltip = isFiltered
            ? `${col.label}：${selected.map((v) => formatHeaderFilterValue(col, v)).join('、')}（单击更改筛选）`
            : col.tooltip ??
              (col.filterable ? '单击下拉筛选' : col.sortable ? '单击切换正序/倒序' : col.label);

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
              data-filter-trigger={col.filterable ? col.key : undefined}
              style={{ width, minWidth: col.minWidth ?? 44 }}
              title={headerTooltip}
              className={[
                'td-header-cell',
                alignClass,
                isInteractive ? 'td-header-cell--interactive' : '',
                isFiltered ? 'td-header-cell--filtered' : '',
                isSorted ? 'td-header-cell--sorted' : '',
                isMenuOpen ? 'td-header-cell--open' : '',
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
                          label: col.label,
                          mode: col.filterMode ?? 'multi',
                          originGrouped: isOriginColumn(col),
                          x: rect.left,
                          y: rect.bottom + 3,
                          minWidth: Math.min(380, Math.max(224, Math.ceil(rect.width))),
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
                            stroke={isHovered || isMenuOpen ? 'var(--accent)' : 'var(--text-muted)'}
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
          className="td-filter-menu"
          style={{ left: menuPos.left, top: menuPos.top, minWidth: openMenu.minWidth }}
          role="menu"
          aria-label={`按${openMenu.label}筛选`}
        >
          {/* 候选项超过 6 项时自动显示顶部紧凑快捷搜索框 */}
          {showSearch && (
            <div className="td-filter-search-wrap">
              <span className="td-filter-search-icon" aria-hidden="true">
                <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
                  <circle cx="7.2" cy="7.2" r="4.6" stroke="currentColor" strokeWidth="1.5" />
                  <path
                    d="M10.7 10.7 13.8 13.8"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                  />
                </svg>
              </span>
              <input
                ref={searchInputRef}
                type="text"
                className="td-filter-search-input"
                placeholder={`搜索${openMenu.label}选项…`}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              {searchQuery && (
                <button
                  type="button"
                  className="td-filter-search-clear"
                  aria-label="清空选项搜索"
                  onClick={() => setSearchQuery('')}
                >
                  ×
                </button>
              )}
            </div>
          )}

          {/* 选项滚动列表区 */}
          <div className="td-filter-menu-list">
            {/* 顶层“全部”清除筛选项（搜索过滤中不抢占空间） */}
            {!searchQuery.trim() && (
              <>
                <button
                  type="button"
                  role={openMenu.mode === 'single' ? 'menuitemradio' : 'menuitemcheckbox'}
                  aria-checked={isAllSelected}
                  title={`显示全部${openMenu.label}`}
                  className={`td-filter-item ${
                    openMenu.mode === 'single' ? 'td-filter-item--single' : 'td-filter-item--multi'
                  } ${isAllSelected ? 'td-filter-item--active' : ''}`}
                  onClick={() => {
                    onFilterChange?.(openMenu.columnKey, []);
                    setOpenMenu(null);
                  }}
                >
                  {openMenu.mode === 'single' ? (
                    <span className="td-filter-dot td-filter-dot--all" aria-hidden="true" />
                  ) : (
                    <FilterCheckboxVisual checked={isAllSelected} />
                  )}
                  <span className="td-filter-item-text">全部</span>
                  {openMenu.mode === 'single' && isAllSelected && <SingleCheckMark />}
                </button>
                <div className="td-filter-sep" />
              </>
            )}

            {openOptions.length === 0 ? (
              <div className="td-filter-empty">（暂无可选项）</div>
            ) : totalVisibleOptions === 0 ? (
              <div className="td-filter-empty">
                <span>未找到匹配「{searchQuery.trim()}」的选项</span>
                <button
                  type="button"
                  className="td-filter-empty-reset"
                  onClick={() => setSearchQuery('')}
                >
                  清空搜索
                </button>
              </div>
            ) : (
              <>
                {primaryOptions.map(renderOptionButton)}
                {specificMcpOptions.length > 0 && (
                  <>
                    {primaryOptions.length > 0 && <div className="td-filter-sep" />}
                    <div className="td-filter-group-label">按具体 MCP 调用方筛选</div>
                    {specificMcpOptions.map(renderOptionButton)}
                  </>
                )}
              </>
            )}
          </div>

          {/* 多选模式底部已选统计与快捷重置栏 */}
          {openMenu.mode === 'multi' && (
            <div className="td-filter-footer">
              <span
                className={`td-filter-footer-count ${
                  openSelected.length > 0 ? 'td-filter-footer-count--active' : ''
                }`}
              >
                {openSelected.length > 0 ? `已选 ${openSelected.length} 项` : '未筛选（全部）'}
              </span>
              <div className="td-filter-footer-actions">
                <button
                  type="button"
                  className="td-btn td-btn--compact"
                  disabled={openSelected.length === 0}
                  onClick={() => {
                    onFilterChange?.(openMenu.columnKey, []);
                  }}
                >
                  重置
                </button>
                <button
                  type="button"
                  className="td-btn td-btn--compact td-btn--soft"
                  onClick={() => setOpenMenu(null)}
                >
                  完成
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </>
  );
};
