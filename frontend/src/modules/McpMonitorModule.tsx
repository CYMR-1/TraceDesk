/**
 * 模块 7：MCP 实时监控主工作区 (mcp)
 * - 顶部控制与状态条：本地 Streamable HTTP 启停、活跃客户端胶囊、桌面与 MCP 实时协同提示条、刷新/清空
 * - 四项紧凑遥测指标卡：总调用/执行中、成功率与平均耗时、活跃客户端、只读 vs 受控写入
 * - 三合一子视图：
 *   ① 实时操作流（默认）：筛选栏 + 左右可拖拽分栏（时间线步骤流 + 单步详情透视面板）
 *   ② 接入配置：stdio（推荐）与 Streamable HTTP 配置 JSON 与一键复制
 *   ③ 工具清单与调用统计：关联展示全部 19 项工具的累计调用、失败与平均耗时
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { tauriApi } from '../api/tauri';
import { UiIcon } from '../components/Icons';
import { SemanticPill } from '../components/SemanticPill';
import { SplitPane } from '../components/SplitPane';
import { VirtualTable, type VirtualColumn } from '../components/VirtualTable';
import type {
  CaseSnapshot,
  McpActivityPhase,
  McpActivityRecord,
  McpActivityStats,
  McpStatus,
  McpTransportKind,
  ToolCatalogItem,
} from '../types/ipc';
import { copyToClipboard, formatError } from '../utils/assets';
import {
  formatActivityShortTime,
  formatDurationMs,
  formatPhaseLabel,
  formatPrettyJson,
  formatTransportLabel,
  stripTrailingVersion,
} from '../utils/mcpActivity';

interface McpMonitorModuleProps {
  snapshot: CaseSnapshot | null;
  mcpStatus: McpStatus | null;
  activities: McpActivityRecord[];
  stats: McpActivityStats;
  onStatusChange: (next: McpStatus) => void;
  onRefreshAll: () => Promise<void>;
  onClearActivities: () => Promise<void>;
  onJumpToAudit: () => void;
  onRefreshCurrentCase: () => Promise<void>;
}

type SubViewKey = 'stream' | 'config' | 'tools';
type StatusFilter = 'all' | McpActivityPhase;
type ModeFilter = 'all' | 'readonly' | 'write';
type TransportFilter = 'all' | McpTransportKind;

/** 携带实时统计指标的工具目录行 */
interface ToolRowWithStats extends ToolCatalogItem {
  calls: number;
  failures: number;
  avgDurationMs: number;
}

export const McpMonitorModule: React.FC<McpMonitorModuleProps> = ({
  snapshot,
  mcpStatus,
  activities,
  stats,
  onStatusChange,
  onRefreshAll,
  onClearActivities,
  onJumpToAudit,
  onRefreshCurrentCase,
}) => {
  const [subView, setSubView] = useState<SubViewKey>('stream');
  const [port, setPort] = useState<number>(mcpStatus?.port ?? 8765);
  const [portInput, setPortInput] = useState<string>(String(mcpStatus?.port ?? 8765));
  const [actionBusy, setActionBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string>('');

  // 实时操作流筛选状态
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [modeFilter, setModeFilter] = useState<ModeFilter>('all');
  const [clientFilter, setClientFilter] = useState<string>('all');
  const [transportFilter, setTransportFilter] = useState<TransportFilter>('all');
  const [keyword, setKeyword] = useState<string>('');
  const [autoSelectLatest, setAutoSelectLatest] = useState<boolean>(true);
  const [selectedCallId, setSelectedCallId] = useState<string | null>(null);

  // 工具清单筛选状态
  const [toolKeyword, setToolKeyword] = useState<string>('');
  const [toolModeFilter, setToolModeFilter] = useState<ModeFilter>('all');

  const feedbackTimerRef = useRef<number | null>(null);
  const prevTopCallIdRef = useRef<string | null>(null);

  /** 短暂展示操作反馈文案 */
  const showFeedback = useCallback((text: string) => {
    setFeedback(text);
    if (feedbackTimerRef.current !== null) {
      window.clearTimeout(feedbackTimerRef.current);
    }
    feedbackTimerRef.current = window.setTimeout(() => {
      setFeedback('');
      feedbackTimerRef.current = null;
    }, 3200);
  }, []);

  useEffect(() => {
    return () => {
      if (feedbackTimerRef.current !== null) {
        window.clearTimeout(feedbackTimerRef.current);
      }
    };
  }, []);

  // 服务运行中时同步真实监听端口
  useEffect(() => {
    if (mcpStatus?.running) {
      setPort(mcpStatus.port);
      setPortInput(String(mcpStatus.port));
    }
  }, [mcpStatus?.running, mcpStatus?.port]);

  // 归一化后的活跃客户端名称（温和去尾版本号并去重）
  const normalizedActiveClients = useMemo(() => {
    const set = new Set<string>();
    for (const raw of stats.activeClients) {
      const clean = stripTrailingVersion(raw);
      if (clean) set.add(clean);
    }
    return Array.from(set);
  }, [stats.activeClients]);

  // 动态提取所有出现过的客户端名称用于筛选下拉（与活跃客户端保持同一去尾版本口径）
  const knownClients = useMemo(() => {
    const set = new Set<string>(normalizedActiveClients);
    for (const item of activities) {
      const clean = stripTrailingVersion(item.client);
      if (clean) set.add(clean);
    }
    return Array.from(set);
  }, [activities, normalizedActiveClients]);

  // 过滤后的实时操作流列表
  const filteredActivities = useMemo(() => {
    const kw = keyword.trim().toLowerCase();
    return activities.filter((item) => {
      if (statusFilter !== 'all' && item.phase !== statusFilter) return false;
      if (modeFilter === 'readonly' && !item.readOnly) return false;
      if (modeFilter === 'write' && item.readOnly) return false;
      const cleanClient = stripTrailingVersion(item.client);
      if (clientFilter !== 'all' && cleanClient !== clientFilter) return false;
      if (transportFilter !== 'all' && item.transport !== transportFilter) return false;
      if (kw) {
        const hay = [
          item.toolTitle,
          item.toolName ?? '',
          item.method,
          item.category,
          cleanClient,
          item.sessionId ?? '',
          item.caseNumber ?? '',
          item.caseDir ?? '',
          item.paramsSummary,
          item.resultSummary,
          item.error ?? '',
        ]
          .join(' ')
          .toLowerCase();
        if (!hay.includes(kw)) return false;
      }
      return true;
    });
  }, [activities, statusFilter, modeFilter, clientFilter, transportFilter, keyword]);

  // 仅当有新步骤到达且开启“自动选中最新”时，自动高亮最新步骤；若列表首次出现数据且未选中也默认选中首条
  useEffect(() => {
    const topCallId = activities[0]?.callId ?? null;
    const hasNewHead = topCallId !== null && topCallId !== prevTopCallIdRef.current;
    prevTopCallIdRef.current = topCallId;

    if (hasNewHead && autoSelectLatest) {
      const topInFiltered = filteredActivities.find((a) => a.callId === topCallId);
      setSelectedCallId(topInFiltered ? topCallId : filteredActivities[0]?.callId ?? topCallId);
      return;
    }

    if (selectedCallId === null && filteredActivities.length > 0) {
      setSelectedCallId(filteredActivities[0].callId);
    } else if (
      selectedCallId !== null &&
      filteredActivities.length > 0 &&
      !filteredActivities.some((a) => a.callId === selectedCallId)
    ) {
      setSelectedCallId(filteredActivities[0].callId);
    }
  }, [activities, filteredActivities, autoSelectLatest, selectedCallId]);

  const selectedActivity = useMemo(
    () =>
      filteredActivities.find((a) => a.callId === selectedCallId) ??
      activities.find((a) => a.callId === selectedCallId) ??
      null,
    [filteredActivities, activities, selectedCallId]
  );

  // 当前正在执行的工具列表（用于指标卡提示）
  const runningActivities = useMemo(
    () => activities.filter((a) => a.phase === 'started'),
    [activities]
  );

  // 成功率计算（仅针对已结束调用）
  const finishedCount = stats.succeededCalls + stats.failedCalls;
  const successRateText =
    finishedCount > 0 ? `${((stats.succeededCalls * 100) / finishedCount).toFixed(1)}%` : '—';
  const totalRwCount = stats.readOnlyCalls + stats.writeCalls;
  const readRatioPct = totalRwCount > 0 ? Math.round((stats.readOnlyCalls * 100) / totalRwCount) : 0;

  // 端口输入处理
  const handlePortInputChange = (raw: string) => {
    setPortInput(raw);
    const parsed = Number.parseInt(raw, 10);
    if (!Number.isNaN(parsed) && parsed >= 1024 && parsed <= 65535) {
      setPort(parsed);
      if (!mcpStatus?.running) {
        void tauriApi
          .getMcpStatus({ port: parsed })
          .then(onStatusChange)
          .catch(() => {
            // 输入过程忽略偶发查询错误
          });
      }
    }
  };

  const handlePortBlur = () => {
    const parsed = Number.parseInt(portInput, 10);
    const clamped = Number.isNaN(parsed) ? 8765 : Math.max(1024, Math.min(65535, parsed));
    setPort(clamped);
    setPortInput(String(clamped));
    if (!mcpStatus?.running) {
      void tauriApi
        .getMcpStatus({ port: clamped })
        .then(onStatusChange)
        .catch(() => {
          // 忽略预览端口同步失败
        });
    }
  };

  // 启动或停止本地 Streamable HTTP 服务
  const handleToggleHttp = async () => {
    setActionBusy(true);
    setErrorMsg(null);
    try {
      if (mcpStatus?.running) {
        const next = await tauriApi.stopMcpHttp();
        onStatusChange(next);
        showFeedback('本地 HTTP MCP 服务已停止');
      } else {
        const next = await tauriApi.startMcpHttp({ port });
        onStatusChange(next);
        showFeedback(`本地 HTTP MCP 服务已启动：${next.url}`);
      }
    } catch (err) {
      setErrorMsg(`MCP 服务操作失败：${formatError(err)}`);
    } finally {
      setActionBusy(false);
    }
  };

  // 手动刷新状态与操作流
  const handleManualRefresh = async () => {
    setRefreshing(true);
    setErrorMsg(null);
    try {
      await onRefreshAll();
      showFeedback('已同步最新 MCP 服务状态与实时操作流');
    } catch (err) {
      setErrorMsg(`刷新监控流失败：${formatError(err)}`);
    } finally {
      setRefreshing(false);
    }
  };

  // 清空监控流
  const handleClearStream = async () => {
    setActionBusy(true);
    setErrorMsg(null);
    try {
      await onClearActivities();
      setSelectedCallId(null);
      showFeedback('已清空实时监控流');
    } catch (err) {
      setErrorMsg(`清空监控流失败：${formatError(err)}`);
    } finally {
      setActionBusy(false);
    }
  };

  // 通用复制到剪贴板
  const handleCopy = async (text: string, label: string) => {
    const ok = await copyToClipboard(text);
    showFeedback(ok ? `已复制${label}` : '复制失败，请手动选中复制');
  };

  // 重置实时操作流筛选
  const handleResetFilters = () => {
    setStatusFilter('all');
    setModeFilter('all');
    setClientFilter('all');
    setTransportFilter('all');
    setKeyword('');
  };

  // 关联实时调用统计的 19 项工具清单
  const tools = mcpStatus?.tools ?? [];
  const toolRows = useMemo<ToolRowWithStats[]>(() => {
    const kw = toolKeyword.trim().toLowerCase();
    return tools
      .map((tool) => {
        const st = stats.toolStats[tool.name];
        return {
          ...tool,
          calls: st?.calls ?? 0,
          failures: st?.failures ?? 0,
          avgDurationMs: st?.avgDurationMs ?? 0,
        };
      })
      .filter((t) => {
        if (toolModeFilter === 'readonly' && !t.readOnly) return false;
        if (toolModeFilter === 'write' && t.readOnly) return false;
        if (kw) {
          const hay = `${t.title ?? ''} ${t.name} ${t.category} ${t.summary}`.toLowerCase();
          if (!hay.includes(kw)) return false;
        }
        return true;
      });
  }, [tools, stats.toolStats, toolKeyword, toolModeFilter]);

  const toolColumns = useMemo<VirtualColumn<ToolRowWithStats>[]>(
    () => [
      {
        key: 'title',
        label: '工具中文名',
        width: 146,
        getText: (t) => t.title || t.name,
      },
      {
        key: 'name',
        label: '原始工具名',
        width: 224,
        mono: true,
        getText: (t) => t.name,
      },
      {
        key: 'category',
        label: '分类',
        width: 102,
        getText: (t) => t.category,
      },
      {
        key: 'mode',
        label: '模式',
        width: 164,
        pill: true,
        getText: (t) => (t.readOnly ? '只读' : '受控写入（记入审计链）'),
      },
      {
        key: 'calls',
        label: '累计调用',
        width: 82,
        align: 'right',
        mono: true,
        getText: (t) => String(t.calls),
      },
      {
        key: 'failures',
        label: '失败次数',
        width: 82,
        align: 'right',
        mono: true,
        getText: (t) => String(t.failures),
        renderCell: (t) => (
          <span
            className="td-mono"
            style={{
              color: t.failures > 0 ? 'var(--danger-fg)' : 'var(--text-muted)',
              fontWeight: t.failures > 0 ? 700 : 400,
            }}
          >
            {t.failures}
          </span>
        ),
      },
      {
        key: 'avgDuration',
        label: '平均耗时',
        width: 92,
        align: 'right',
        mono: true,
        getText: (t) => (t.calls > 0 ? formatDurationMs(t.avgDurationMs) : '—'),
      },
      {
        key: 'summary',
        label: '功能说明',
        width: 320,
        getText: (t) => t.summary,
      },
    ],
    []
  );

  const running = Boolean(mcpStatus?.running);
  const activeCaseNumber = snapshot?.number ?? mcpStatus?.activeCaseNumber ?? null;
  const formattedParams = useMemo(
    () => (selectedActivity ? formatPrettyJson(selectedActivity.paramsJson) : ''),
    [selectedActivity]
  );
  const formattedResponse = useMemo(
    () => (selectedActivity?.responsePreview ? formatPrettyJson(selectedActivity.responsePreview) : ''),
    [selectedActivity]
  );

  const hasActiveFilter =
    statusFilter !== 'all' ||
    modeFilter !== 'all' ||
    clientFilter !== 'all' ||
    transportFilter !== 'all' ||
    keyword.trim().length > 0;

  return (
    <div className="td-panel">
      {/* 1. 顶部控制与状态条 */}
      <div className="td-mcp-control-bar">
        <div className="td-mcp-control-left">
          <div
            className={`td-mcp-service-badge ${
              running ? 'td-mcp-service-badge--running' : 'td-mcp-service-badge--stopped'
            }`}
          >
            <span className={`td-mcp-dot ${running ? 'td-mcp-dot--online' : 'td-mcp-dot--idle'}`} />
            <span>
              {running
                ? `本地 HTTP 运行中 · ${mcpStatus?.url}`
                : '本地 HTTP 未启动（stdio 客户端可按需直接拉起）'}
            </span>
          </div>

          {normalizedActiveClients.length > 0 && (
            <div className="td-mcp-clients-wrap" aria-label="活跃调用客户端">
              <span className="td-muted-text" style={{ fontSize: 11.5 }}>
                活跃客户端：
              </span>
              {normalizedActiveClients.map((clientName) => {
                const isSelected = clientFilter === clientName && subView === 'stream';
                return (
                  <button
                    key={clientName}
                    type="button"
                    className={`td-mcp-client-chip ${isSelected ? 'td-mcp-client-chip--active' : ''}`}
                    title={isSelected ? '点击取消按此客户端筛选' : `点击在操作流中筛选「${clientName}」`}
                    onClick={() => {
                      setSubView('stream');
                      setClientFilter((prev) => (prev === clientName ? 'all' : clientName));
                    }}
                  >
                    MCP · {clientName}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="td-mcp-control-right">
          <label
            htmlFor="td-mcp-monitor-port"
            style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)' }}
          >
            <span>端口</span>
            <input
              id="td-mcp-monitor-port"
              type="number"
              min={1024}
              max={65535}
              className="td-input td-mono"
              style={{ width: 82 }}
              disabled={running || actionBusy}
              value={portInput}
              onChange={(e) => handlePortInputChange(e.target.value)}
              onBlur={handlePortBlur}
            />
          </label>

          <button
            type="button"
            className={`td-btn ${running ? 'td-btn--soft' : 'td-btn--accent'}`}
            disabled={actionBusy}
            onClick={() => void handleToggleHttp()}
          >
            {running ? '停止 HTTP 服务' : '启动 HTTP 服务'}
          </button>

          <div className="td-toolbar-divider" />

          <button
            type="button"
            className="td-btn"
            disabled={refreshing || actionBusy}
            onClick={() => void handleManualRefresh()}
            title="重新拉取 MCP 服务状态与实时操作流"
          >
            <UiIcon name="refresh" size={14} color="var(--text-secondary)" />
            刷新
          </button>

          <button
            type="button"
            className="td-btn"
            disabled={actionBusy || activities.length === 0}
            onClick={() => void handleClearStream()}
            title="清空当前监控面板中的所有历史步骤记录"
          >
            <UiIcon name="trash" size={14} color="var(--text-secondary)" />
            清空监控流
          </button>
        </div>
      </div>

      {/* 桌面与 MCP 实时协同提示条（仅写入瞬间加短锁，外部 stdio/HTTP 可直接操作并热刷新） */}
      {activeCaseNumber && (
        <div className="td-mcp-collab-strip">
          <span className="td-mcp-dot td-mcp-dot--online" />
          <span style={{ flex: 1 }}>
            桌面与 MCP 实时协同已就绪：案件「{activeCaseNumber}」采用仅写入瞬间短锁，外部 stdio 与 HTTP 客户端可直接操作并实时同步界面
          </span>
          <button
            type="button"
            className="td-btn td-btn--compact"
            disabled={refreshing || actionBusy}
            onClick={() => void onRefreshCurrentCase()}
            title="立即同步当前案件快照与审计日志"
          >
            <UiIcon name="refresh" size={12} color="#0F766E" />
            立即同步
          </button>
        </div>
      )}

      {/* 错误反馈条 */}
      {errorMsg && (
        <div className="td-mcp-error-strip">
          <span>{errorMsg}</span>
          <button
            type="button"
            className="td-btn td-btn--compact"
            onClick={() => setErrorMsg(null)}
          >
            关闭
          </button>
        </div>
      )}

      {/* 2. 四项紧凑遥测指标卡 */}
      <div className="td-mcp-metrics-grid">
        <div
          className={`td-mcp-metric-card ${
            stats.runningCalls > 0 ? 'td-mcp-metric-card--running' : ''
          }`}
        >
          <div className="td-mcp-metric-head">
            <span>总调用 / 执行中</span>
            {stats.runningCalls > 0 ? (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 5,
                  color: '#1D4ED8',
                  fontWeight: 600,
                }}
              >
                <span className="td-mcp-dot td-mcp-dot--running" />
                执行中 {stats.runningCalls}
              </span>
            ) : (
              <span>空闲</span>
            )}
          </div>
          <div className="td-mcp-metric-value-row">
            <span className="td-mcp-metric-value">{stats.totalCalls}</span>
            <span className="td-mcp-metric-sub" title={runningActivities[0]?.toolTitle}>
              {runningActivities.length > 0
                ? `正在执行：${runningActivities[0].toolTitle}`
                : '实时监听桌面与外部通道'}
            </span>
          </div>
        </div>

        <div className="td-mcp-metric-card">
          <div className="td-mcp-metric-head">
            <span>成功率与平均耗时</span>
            <span className="td-mono" style={{ color: 'var(--text-secondary)' }}>
              均 {finishedCount > 0 ? formatDurationMs(stats.avgDurationMs) : '—'}
            </span>
          </div>
          <div className="td-mcp-metric-value-row">
            <span
              className="td-mcp-metric-value"
              style={{
                color:
                  stats.failedCalls > 0 && finishedCount > 0
                    ? stats.succeededCalls === 0
                      ? 'var(--danger-fg)'
                      : 'var(--text-primary)'
                    : finishedCount > 0
                      ? 'var(--ok-fg)'
                      : 'var(--text-primary)',
              }}
            >
              {successRateText}
            </span>
            <span className="td-mcp-metric-sub">
              成功 {stats.succeededCalls} · 失败 {stats.failedCalls}
            </span>
          </div>
        </div>

        <div className="td-mcp-metric-card">
          <div className="td-mcp-metric-head">
            <span>活跃客户端</span>
            <span>{normalizedActiveClients.length > 0 ? '已观测接入' : '待连接'}</span>
          </div>
          <div className="td-mcp-metric-value-row">
            <span className="td-mcp-metric-value">{normalizedActiveClients.length}</span>
            <span
              className="td-mcp-metric-sub"
              title={normalizedActiveClients.join(' · ') || '等待客户端连接'}
            >
              {normalizedActiveClients.length > 0
                ? normalizedActiveClients.join(' · ')
                : '等待 MCP 客户端调用'}
            </span>
          </div>
        </div>

        <div className="td-mcp-metric-card">
          <div className="td-mcp-metric-head">
            <span>只读查询 vs 受控写入</span>
            <span>写入记入审计链</span>
          </div>
          <div className="td-mcp-metric-value-row">
            <span className="td-mcp-metric-value">
              <span style={{ color: 'var(--ok-fg)' }}>{stats.readOnlyCalls}</span>
              <span style={{ color: 'var(--text-disabled)', margin: '0 4px', fontWeight: 400 }}>/</span>
              <span style={{ color: 'var(--warn-fg)' }}>{stats.writeCalls}</span>
            </span>
            <span className="td-mcp-metric-sub">
              只读 {stats.readOnlyCalls} · 受控写入 {stats.writeCalls}
            </span>
          </div>
          <div className="td-mcp-ratio-bar" aria-hidden="true">
            <div className="td-mcp-ratio-read" style={{ width: `${readRatioPct}%` }} />
            <div
              className="td-mcp-ratio-write"
              style={{ width: `${totalRwCount > 0 ? 100 - readRatioPct : 0}%` }}
            />
          </div>
        </div>
      </div>

      {/* 3. 三合一子视图切换栏 */}
      <div className="td-mcp-subnav">
        <div className="td-mcp-subnav-tabs" role="tablist" aria-label="MCP 监控子视图">
          <button
            type="button"
            role="tab"
            aria-selected={subView === 'stream'}
            className={`td-mcp-subnav-tab ${subView === 'stream' ? 'td-mcp-subnav-tab--active' : ''}`}
            onClick={() => setSubView('stream')}
          >
            <UiIcon
              name="activity"
              size={14}
              color={subView === 'stream' ? '#2563EB' : 'var(--text-muted)'}
            />
            实时操作流
            <span className="td-mcp-subnav-count">{activities.length}</span>
            {stats.runningCalls > 0 && <span className="td-mcp-dot td-mcp-dot--running" />}
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={subView === 'config'}
            className={`td-mcp-subnav-tab ${subView === 'config' ? 'td-mcp-subnav-tab--active' : ''}`}
            onClick={() => setSubView('config')}
          >
            <UiIcon
              name="settings"
              size={14}
              color={subView === 'config' ? '#2563EB' : 'var(--text-muted)'}
            />
            接入配置
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={subView === 'tools'}
            className={`td-mcp-subnav-tab ${subView === 'tools' ? 'td-mcp-subnav-tab--active' : ''}`}
            onClick={() => setSubView('tools')}
          >
            <UiIcon
              name="list"
              size={14}
              color={subView === 'tools' ? '#2563EB' : 'var(--text-muted)'}
            />
            工具清单与统计
            <span className="td-mcp-subnav-count">{tools.length || 19}</span>
          </button>
        </div>

        {feedback && <span className="td-mcp-feedback">{feedback}</span>}
      </div>

      {/* ---------- 子视图 ①：实时操作流（核心体验） ---------- */}
      {subView === 'stream' && (
        <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
          {/* 顶部筛选栏 */}
          <div className="td-mcp-filter-bar">
            <div className="td-segmented" role="group" aria-label="按执行状态筛选">
              {(
                [
                  ['all', '全部'],
                  ['started', '执行中'],
                  ['completed', '成功'],
                  ['failed', '失败'],
                ] as const
              ).map(([val, label]) => (
                <button
                  key={val}
                  type="button"
                  className={`td-segmented-btn ${statusFilter === val ? 'td-segmented-btn--active' : ''}`}
                  onClick={() => setStatusFilter(val)}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="td-segmented" role="group" aria-label="按读写模式筛选">
              {(
                [
                  ['all', '全部模式'],
                  ['readonly', '只读'],
                  ['write', '受控写入'],
                ] as const
              ).map(([val, label]) => (
                <button
                  key={val}
                  type="button"
                  className={`td-segmented-btn ${modeFilter === val ? 'td-segmented-btn--active' : ''}`}
                  onClick={() => setModeFilter(val)}
                >
                  {label}
                </button>
              ))}
            </div>

            <select
              className="td-select"
              style={{ minHeight: 26, fontSize: 12, paddingTop: 2, paddingBottom: 2 }}
              aria-label="按调用客户端筛选"
              value={clientFilter}
              onChange={(e) => setClientFilter(e.target.value)}
            >
              <option value="all">全部客户端</option>
              {knownClients.map((c) => (
                <option key={c} value={c}>
                  MCP · {c}
                </option>
              ))}
            </select>

            <select
              className="td-select"
              style={{ minHeight: 26, fontSize: 12, paddingTop: 2, paddingBottom: 2 }}
              aria-label="按传输方式筛选"
              value={transportFilter}
              onChange={(e) => setTransportFilter(e.target.value as TransportFilter)}
            >
              <option value="all">全部传输方式</option>
              <option value="desktop-http">桌面 HTTP (desktop-http)</option>
              <option value="stdio">stdio 通道</option>
              <option value="streamable-http">独立 HTTP (streamable-http)</option>
            </select>

            <div className="td-search-box" style={{ minWidth: 180 }}>
              <span className="td-search-box-icon">
                <UiIcon name="search" size={13} color="var(--text-muted)" />
              </span>
              <input
                type="text"
                className="td-input"
                style={{ minHeight: 26, fontSize: 12 }}
                placeholder="筛选工具名、参数、结果、案件号或错误信息…"
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
              />
              {keyword && (
                <button
                  type="button"
                  className="td-search-clear"
                  aria-label="清空搜索关键词"
                  onClick={() => setKeyword('')}
                >
                  ×
                </button>
              )}
            </div>

            <label className="td-mcp-toggle-label" title="有新调用到达时自动高亮并展示其详情">
              <input
                type="checkbox"
                checked={autoSelectLatest}
                onChange={(e) => setAutoSelectLatest(e.target.checked)}
              />
              自动选中最新
            </label>
          </div>

          {/* 左右可拖拽分栏：左栏（58%）实时步骤时间线 + 右栏（42%）单步操作详情透视面板 */}
          <div style={{ flex: 1, minHeight: 0, display: 'flex' }}>
            <SplitPane
              direction="horizontal"
              initialSize={0.58}
              minFirst={380}
              minSecond={320}
              first={
                <div className="td-mcp-stream-pane">
                  <div className="td-pane-header">
                    <span className="td-section-title" style={{ fontSize: 12.5 }}>
                      实时步骤时间线
                    </span>
                    <span className="td-muted-text" style={{ fontSize: 11.5 }}>
                      {hasActiveFilter
                        ? `匹配 ${filteredActivities.length} / 共 ${activities.length} 步`
                        : `共 ${activities.length} 步 · 最新在前`}
                    </span>
                  </div>

                  {filteredActivities.length === 0 ? (
                    activities.length === 0 ? (
                      <div className="td-mcp-empty-state">
                        <div className="td-mcp-empty-icon">
                          <UiIcon name="mcp" size={22} color="#2563EB" />
                        </div>
                        <div className="td-mcp-empty-title">暂无 MCP 实时调用记录</div>
                        <div className="td-mcp-empty-desc">
                          无论是连接桌面内置 Streamable HTTP 服务，还是由 Claude Desktop、Cursor、Antigravity 等外部客户端通过{' '}
                          <code className="td-mono">stdio</code> 拉起，每一步调用参数、执行耗时与返回结果都会自动实时呈现在这里。
                        </div>
                        <div style={{ display: 'flex', gap: 8, marginTop: 6, flexWrap: 'wrap', justifyContent: 'center' }}>
                          <button
                            type="button"
                            className="td-btn td-btn--accent"
                            onClick={() => setSubView('config')}
                          >
                            <UiIcon name="settings" size={14} color="#FFFFFF" />
                            前往接入配置
                          </button>
                          {!running && (
                            <button
                              type="button"
                              className="td-btn td-btn--soft"
                              disabled={actionBusy}
                              onClick={() => void handleToggleHttp()}
                            >
                              启动本地 HTTP 服务
                            </button>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="td-mcp-empty-state">
                        <div className="td-mcp-empty-title">没有匹配当前筛选条件的调用记录</div>
                        <div className="td-mcp-empty-desc">
                          已隐藏 {activities.length} 条记录，请调整状态、客户端、传输方式或关键词筛选条件。
                        </div>
                        <button type="button" className="td-btn td-btn--soft" onClick={handleResetFilters}>
                          重置全部筛选条件
                        </button>
                      </div>
                    )
                  ) : (
                    <div className="td-mcp-stream-list" role="listbox" aria-label="MCP 实时步骤时间线">
                      {filteredActivities.map((item) => {
                        const isSelected = selectedActivity?.callId === item.callId;
                        const isRunning = item.phase === 'started';
                        const isFailed = item.phase === 'failed';
                        return (
                          <div
                            key={item.callId}
                            role="option"
                            aria-selected={isSelected}
                            className={`td-mcp-step-row ${
                              isSelected ? 'td-mcp-step-row--selected' : ''
                            } ${isRunning ? 'td-mcp-step-row--running' : ''}`}
                            onClick={() => setSelectedCallId(item.callId)}
                          >
                            {/* 左侧状态指示轨与语义图标 */}
                            <div className="td-mcp-step-rail" aria-hidden="true">
                              {isRunning ? (
                                <span className="td-mcp-spinner" />
                              ) : isFailed ? (
                                <UiIcon
                                  name="x_circle"
                                  size={16}
                                  color="var(--danger-fg)"
                                  fill="var(--danger-bg)"
                                />
                              ) : (
                                <UiIcon
                                  name="check_circle"
                                  size={16}
                                  color="var(--ok-fg)"
                                  fill="var(--ok-bg)"
                                />
                              )}
                              <div className="td-mcp-step-rail-line" />
                            </div>

                            {/* 步骤内容主体 */}
                            <div className="td-mcp-step-main">
                              <div className="td-mcp-step-top">
                                <span className="td-mcp-step-time" title={item.timestamp}>
                                  {formatActivityShortTime(item.timestamp)}
                                </span>
                                <span className="td-mcp-step-title" title={item.toolTitle}>
                                  {item.toolTitle}
                                </span>
                                {item.toolName && (
                                  <span className="td-mcp-step-rawname" title={item.toolName}>
                                    {item.toolName}
                                  </span>
                                )}
                                <span
                                  className={`td-mcp-step-duration ${
                                    isRunning
                                      ? 'td-mcp-step-duration--running'
                                      : isFailed
                                        ? 'td-mcp-step-duration--failed'
                                        : ''
                                  }`}
                                >
                                  {isRunning ? '执行中…' : formatDurationMs(item.durationMs)}
                                </span>
                              </div>

                              <div className="td-mcp-step-meta">
                                <SemanticPill
                                  text={`MCP · ${stripTrailingVersion(item.client) || '未知客户端'}`}
                                  fallback="system"
                                />
                                <SemanticPill
                                  text={formatTransportLabel(item.transport)}
                                  fallback="neutral"
                                />
                                <SemanticPill
                                  text={item.readOnly ? '只读' : '受控写入'}
                                  fallback={item.readOnly ? 'ok' : 'warn'}
                                />
                                {item.caseNumber && (
                                  <span
                                    className="td-pill td-pill--neutral td-mono"
                                    title={item.caseDir ?? item.caseNumber}
                                  >
                                    {item.caseNumber}
                                  </span>
                                )}
                                {item.paramsSummary && (
                                  <span className="td-mcp-step-params" title={item.paramsSummary}>
                                    {item.paramsSummary}
                                  </span>
                                )}
                              </div>

                              {(isFailed && item.error) || item.resultSummary ? (
                                <div
                                  className={`td-mcp-step-outcome ${
                                    isFailed ? 'td-mcp-step-outcome--error' : ''
                                  }`}
                                  title={isFailed && item.error ? item.error : item.resultSummary}
                                >
                                  {isFailed && item.error
                                    ? `错误：${item.error}`
                                    : item.resultSummary}
                                </div>
                              ) : null}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              }
              second={
                <div className="td-mcp-detail-pane">
                  <div className="td-pane-header">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                      <span
                        className="td-section-title"
                        style={{
                          fontSize: 12.5,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {selectedActivity ? selectedActivity.toolTitle : '单步操作详情透视'}
                      </span>
                      {selectedActivity && (
                        <SemanticPill
                          text={formatPhaseLabel(selectedActivity.phase)}
                          fallback={
                            selectedActivity.phase === 'failed'
                              ? 'danger'
                              : selectedActivity.phase === 'started'
                                ? 'accent'
                                : 'ok'
                          }
                        />
                      )}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                      <button
                        type="button"
                        className="td-btn td-btn--compact"
                        onClick={onJumpToAudit}
                        title="切换到「审计日志」标签页核验链上记录"
                      >
                        跳转审计日志
                        <UiIcon name="arrow_right" size={12} color="currentColor" />
                      </button>
                      <button
                        type="button"
                        className="td-btn td-btn--compact"
                        disabled={!snapshot}
                        onClick={() => void onRefreshCurrentCase()}
                        title="重新读取当前打开案件的最新快照与审计链"
                      >
                        <UiIcon name="refresh" size={12} color="currentColor" />
                        刷新当前案件
                      </button>
                    </div>
                  </div>

                  {!selectedActivity ? (
                    <div className="td-mcp-empty-state">
                      <UiIcon name="document_preview" size={28} color="var(--text-disabled)" />
                      <div className="td-mcp-empty-title">选择左侧步骤查看完整调用透视</div>
                      <div className="td-mcp-empty-desc">
                        点击时间线中的任意一条 MCP 操作，可查看完整元信息、原始调用参数 JSON 与返回结果或报错详情。
                      </div>
                    </div>
                  ) : (
                    <div className="td-mcp-detail-scroll">
                      {/* 元信息卡片 */}
                      <div className="td-mcp-detail-card">
                        <div className="td-mcp-block-header">
                          <span className="td-mcp-block-title">调用元信息</span>
                          <span className="td-mono td-muted-text" style={{ fontSize: 11 }}>
                            callId: {selectedActivity.callId}
                          </span>
                        </div>
                        <div className="td-mcp-meta-grid">
                          <div className="td-mcp-meta-item">
                            <span className="td-mcp-meta-label">调用时间（UTC+8）</span>
                            <span className="td-mcp-meta-val td-mono">{selectedActivity.timestamp}</span>
                          </div>
                          <div className="td-mcp-meta-item">
                            <span className="td-mcp-meta-label">执行状态与耗时</span>
                            <span className="td-mcp-meta-val" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <SemanticPill text={formatPhaseLabel(selectedActivity.phase)} />
                              <span className="td-mono">
                                {selectedActivity.phase === 'started'
                                  ? '进行中…'
                                  : formatDurationMs(selectedActivity.durationMs)}
                              </span>
                            </span>
                          </div>
                          <div className="td-mcp-meta-item">
                            <span className="td-mcp-meta-label">调用客户端</span>
                            <span className="td-mcp-meta-val">
                              <SemanticPill
                                text={`MCP · ${stripTrailingVersion(selectedActivity.client) || '未知客户端'}`}
                                fallback="system"
                              />
                            </span>
                          </div>
                          <div className="td-mcp-meta-item">
                            <span className="td-mcp-meta-label">传输方式与模式</span>
                            <span className="td-mcp-meta-val" style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                              <SemanticPill text={formatTransportLabel(selectedActivity.transport)} />
                              <SemanticPill
                                text={selectedActivity.readOnly ? '只读' : '受控写入'}
                                fallback={selectedActivity.readOnly ? 'ok' : 'warn'}
                              />
                            </span>
                          </div>
                          <div className="td-mcp-meta-item">
                            <span className="td-mcp-meta-label">工具名称 / RPC 方法</span>
                            <span className="td-mcp-meta-val td-mono">
                              {selectedActivity.toolName || selectedActivity.method}
                              {selectedActivity.toolName && selectedActivity.method
                                ? ` (${selectedActivity.method})`
                                : ''}
                            </span>
                          </div>
                          <div className="td-mcp-meta-item">
                            <span className="td-mcp-meta-label">会话 ID</span>
                            <span className="td-mcp-meta-val td-mono">
                              {selectedActivity.sessionId || '—'}
                            </span>
                          </div>
                          <div className="td-mcp-meta-item td-mcp-meta-item--full">
                            <span className="td-mcp-meta-label">目标案件</span>
                            <span className="td-mcp-meta-val td-mono">
                              {selectedActivity.caseNumber ? `[${selectedActivity.caseNumber}] ` : ''}
                              {selectedActivity.caseDir || '未限定特定案件（全局操作）'}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* 调用参数 JSON 代码块 */}
                      <div className="td-mcp-detail-card">
                        <div className="td-mcp-block-header">
                          <span className="td-mcp-block-title">调用参数（JSON）</span>
                          <button
                            type="button"
                            className="td-btn td-btn--compact"
                            disabled={!formattedParams}
                            onClick={() => void handleCopy(formattedParams, '调用参数 JSON')}
                          >
                            <UiIcon name="copy" size={12} color="currentColor" />
                            复制 JSON
                          </button>
                        </div>
                        <pre className="td-mcp-json-block">
                          {formattedParams || '{}'}
                        </pre>
                      </div>

                      {/* 返回结果 / 报错详情预览区 */}
                      <div className="td-mcp-detail-card">
                        <div className="td-mcp-block-header">
                          <span className="td-mcp-block-title">
                            {selectedActivity.phase === 'failed'
                              ? '错误详情与诊断信息'
                              : '返回结果预览'}
                          </span>
                          {(selectedActivity.error || formattedResponse || selectedActivity.resultSummary) && (
                            <button
                              type="button"
                              className="td-btn td-btn--compact"
                              onClick={() =>
                                void handleCopy(
                                  selectedActivity.error ||
                                    formattedResponse ||
                                    selectedActivity.resultSummary,
                                  selectedActivity.phase === 'failed' ? '错误详情' : '返回结果'
                                )
                              }
                            >
                              <UiIcon name="copy" size={12} color="currentColor" />
                              复制内容
                            </button>
                          )}
                        </div>

                        {selectedActivity.phase === 'started' && (
                          <div className="td-mcp-running-box">
                            <span className="td-mcp-spinner" />
                            <span>该工具正在执行中，完成后将自动原位刷新耗时与返回预览…</span>
                          </div>
                        )}

                        {selectedActivity.resultSummary && (
                          <div
                            style={{
                              fontSize: 12.5,
                              color:
                                selectedActivity.phase === 'failed'
                                  ? 'var(--danger-fg)'
                                  : 'var(--text-primary)',
                              fontWeight: 500,
                              lineHeight: 1.5,
                            }}
                          >
                            {selectedActivity.resultSummary}
                          </div>
                        )}

                        {selectedActivity.error && (
                          <div className="td-mcp-error-box">{selectedActivity.error}</div>
                        )}

                        {formattedResponse && (
                          <pre className="td-mcp-json-block">{formattedResponse}</pre>
                        )}

                        {selectedActivity.phase !== 'started' &&
                          !selectedActivity.error &&
                          !formattedResponse &&
                          !selectedActivity.resultSummary && (
                            <div className="td-muted-text" style={{ fontSize: 12 }}>
                              无附加返回正文预览。
                            </div>
                          )}
                      </div>
                    </div>
                  )}
                </div>
              }
            />
          </div>
        </div>
      )}

      {/* ---------- 子视图 ②：接入配置 ---------- */}
      {subView === 'config' && (
        <div className="td-mcp-config-scroll">
          <div className="td-mcp-config-notice">
            <UiIcon name="activity" size={15} color="#2563EB" />
            <span>
              <strong>实时过程监控已自动启用：</strong>
              无论外部客户端采用 <code className="td-mono">stdio</code> 还是{' '}
              <code className="td-mono">Streamable HTTP</code> 接入 TraceDesk MCP，每一步工具调用均会实时同步至「实时操作流」面板。
            </span>
          </div>

          <div className="td-mcp-config-grid">
            {/* stdio 接入卡片 */}
            <section className="td-mcp-config-card">
              <div className="td-mcp-config-card-head">
                <span className="td-mcp-config-card-title">stdio 接入配置</span>
                <SemanticPill text="推荐" fallback="ok" />
              </div>
              <div className="td-mcp-config-card-desc">
                推荐用于 Claude Desktop、Cursor、Antigravity 等本地 MCP 客户端。客户端按需以子进程方式拉起，无需常驻本地端口，且自动同步操作遥测到桌面端。
              </div>
              <pre className="td-code-block" style={{ flex: 1, minHeight: 190 }}>
                {mcpStatus?.stdioConfigJson ?? '正在载入 stdio 配置…'}
              </pre>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="td-btn td-btn--soft"
                  disabled={!mcpStatus}
                  onClick={() =>
                    mcpStatus && void handleCopy(mcpStatus.stdioConfigJson, ' stdio 配置 JSON')
                  }
                >
                  <UiIcon name="copy" size={14} color="var(--accent-soft-text)" />
                  复制配置 JSON
                </button>
                <button
                  type="button"
                  className="td-btn"
                  disabled={!mcpStatus}
                  onClick={() =>
                    mcpStatus && void handleCopy(mcpStatus.stdioCli, ' stdio 启动命令')
                  }
                >
                  复制启动命令
                </button>
              </div>
            </section>

            {/* Streamable HTTP 接入卡片 */}
            <section className="td-mcp-config-card">
              <div className="td-mcp-config-card-head">
                <span className="td-mcp-config-card-title">Streamable HTTP 接入配置</span>
                <SemanticPill text={running ? '运行中' : '未启动'} />
              </div>
              <div className="td-mcp-config-card-desc">
                适用于支持远程/本地 Streamable HTTP 协议的客户端。服务仅监听{' '}
                <code className="td-mono">127.0.0.1</code> 本机回环并启用 DNS 重绑定防护；在顶部点击「启动 HTTP 服务」即可接入。
              </div>
              <pre className="td-code-block" style={{ flex: 1, minHeight: 190 }}>
                {mcpStatus?.httpConfigJson ?? '正在载入 HTTP 配置…'}
              </pre>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="td-btn td-btn--soft"
                  disabled={!mcpStatus}
                  onClick={() =>
                    mcpStatus && void handleCopy(mcpStatus.httpConfigJson, ' HTTP 配置 JSON')
                  }
                >
                  <UiIcon name="copy" size={14} color="var(--accent-soft-text)" />
                  复制配置 JSON
                </button>
                <button
                  type="button"
                  className="td-btn"
                  disabled={!mcpStatus}
                  onClick={() =>
                    mcpStatus && void handleCopy(mcpStatus.url, '本地 HTTP 服务地址')
                  }
                >
                  复制服务地址
                </button>
                <button
                  type="button"
                  className="td-btn"
                  disabled={!mcpStatus}
                  onClick={() =>
                    mcpStatus && void handleCopy(mcpStatus.httpCli, ' HTTP 启动命令')
                  }
                >
                  复制启动命令
                </button>
              </div>
            </section>
          </div>
        </div>
      )}

      {/* ---------- 子视图 ③：工具清单（19 项）与调用统计 ---------- */}
      {subView === 'tools' && (
        <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
          <div className="td-mcp-filter-bar">
            <div className="td-segmented" role="group" aria-label="按工具模式筛选">
              {(
                [
                  ['all', `全部工具 (${tools.length || 19})`],
                  ['readonly', '只读查询'],
                  ['write', '受控写入'],
                ] as const
              ).map(([val, label]) => (
                <button
                  key={val}
                  type="button"
                  className={`td-segmented-btn ${toolModeFilter === val ? 'td-segmented-btn--active' : ''}`}
                  onClick={() => setToolModeFilter(val)}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="td-search-box" style={{ maxWidth: 340 }}>
              <span className="td-search-box-icon">
                <UiIcon name="search" size={13} color="var(--text-muted)" />
              </span>
              <input
                type="text"
                className="td-input"
                style={{ minHeight: 26, fontSize: 12 }}
                placeholder="搜索工具中文名、原始名、分类或功能说明…"
                value={toolKeyword}
                onChange={(e) => setToolKeyword(e.target.value)}
              />
              {toolKeyword && (
                <button
                  type="button"
                  className="td-search-clear"
                  aria-label="清空工具搜索"
                  onClick={() => setToolKeyword('')}
                >
                  ×
                </button>
              )}
            </div>

            <span className="td-muted-text" style={{ fontSize: 11.5, marginLeft: 'auto' }}>
              双击工具行可在「实时操作流」中筛选该工具的调用记录
            </span>
          </div>

          <div style={{ flex: 1, minHeight: 0, display: 'flex' }}>
            <VirtualTable
              rows={toolRows}
              columns={toolColumns}
              rowKey={(t) => t.name}
              onDoubleClickRow={(tool) => {
                setKeyword(tool.name);
                setSubView('stream');
                showFeedback(`已筛选工具「${tool.title || tool.name}」的实时调用记录`);
              }}
              emptyText="没有匹配的 MCP 工具"
            />
          </div>
        </div>
      )}
    </div>
  );
};
