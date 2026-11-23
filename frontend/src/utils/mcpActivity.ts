/**
 * MCP 实时活动流合并、统计计算与格式化工具函数
 * 用于前端收到 mcp:activity 实时事件后原位更新 started 记录并重算汇总指标，
 * 以及统一传输通道名称、耗时、毫秒时间戳和 JSON 预览的展示格式。
 */

import type {
  McpActivityPhase,
  McpActivityRecord,
  McpActivityStats,
  McpToolStat,
  McpTransportKind,
} from '../types/ipc';

/** 空统计初始值 */
export const EMPTY_MCP_ACTIVITY_STATS: McpActivityStats = {
  totalCalls: 0,
  runningCalls: 0,
  succeededCalls: 0,
  failedCalls: 0,
  readOnlyCalls: 0,
  writeCalls: 0,
  avgDurationMs: 0,
  activeClients: [],
  toolStats: {},
};

/** 传输方式展示文案映射 */
export const MCP_TRANSPORT_LABELS: Record<McpTransportKind, string> = {
  'desktop-http': '桌面 HTTP',
  'streamable-http': '独立 HTTP',
  stdio: 'stdio',
};

/** 操作阶段展示文案映射 */
export const MCP_PHASE_LABELS: Record<McpActivityPhase, string> = {
  started: '执行中',
  completed: '成功',
  failed: '失败',
};

/**
 * 将实时推送的 MCP 活动事件按 callId 合并到现有列表：
 * - 若已存在同 callId 条目，则原位更新（优先保留已有非空参数与上下文）；
 * - 若不存在，则插入列表顶部并限制最大缓存条数。
 */
export function mergeMcpActivityRecord(
  prev: readonly McpActivityRecord[],
  incoming: McpActivityRecord,
  maxItems = 500
): McpActivityRecord[] {
  const index = prev.findIndex((item) => item.callId === incoming.callId);
  if (index >= 0) {
    const existing = prev[index];
    const merged: McpActivityRecord = {
      ...existing,
      ...incoming,
      // 保留首次启动时已携带而完成事件可能省略的上下文字段
      sessionId: incoming.sessionId ?? existing.sessionId ?? null,
      toolName: incoming.toolName ?? existing.toolName ?? null,
      toolTitle: incoming.toolTitle || existing.toolTitle,
      category: incoming.category || existing.category,
      caseDir: incoming.caseDir ?? existing.caseDir ?? null,
      caseNumber: incoming.caseNumber ?? existing.caseNumber ?? null,
      paramsSummary: incoming.paramsSummary || existing.paramsSummary,
      paramsJson: incoming.paramsJson || existing.paramsJson,
      resultSummary: incoming.resultSummary || existing.resultSummary,
      responsePreview: incoming.responsePreview ?? existing.responsePreview ?? null,
      error: incoming.error ?? (incoming.phase === 'completed' ? null : existing.error ?? null),
    };
    const next = [...prev];
    next[index] = merged;
    return next;
  }
  return [incoming, ...prev].slice(0, maxItems);
}

/**
 * 基于当前活动列表实时重算汇总指标与分工具统计
 */
export function computeMcpActivityStats(
  activities: readonly McpActivityRecord[]
): McpActivityStats {
  let runningCalls = 0;
  let succeededCalls = 0;
  let failedCalls = 0;
  let readOnlyCalls = 0;
  let writeCalls = 0;
  let totalDuration = 0;
  let durationCount = 0;

  const clientSet = new Set<string>();
  const toolBuckets = new Map<
    string,
    { calls: number; failures: number; durationSum: number; durationSamples: number }
  >();

  for (const item of activities) {
    if (item.phase === 'started') {
      runningCalls += 1;
    } else if (item.phase === 'completed') {
      succeededCalls += 1;
    } else if (item.phase === 'failed') {
      failedCalls += 1;
    }

    if (item.readOnly) {
      readOnlyCalls += 1;
    } else {
      writeCalls += 1;
    }

    const client = item.client?.trim();
    if (client) {
      clientSet.add(client);
    }

    const dur = typeof item.durationMs === 'number' && Number.isFinite(item.durationMs) ? item.durationMs : null;
    if (dur !== null && item.phase !== 'started') {
      totalDuration += dur;
      durationCount += 1;
    }

    const toolKey = item.toolName?.trim();
    if (toolKey) {
      let bucket = toolBuckets.get(toolKey);
      if (!bucket) {
        bucket = { calls: 0, failures: 0, durationSum: 0, durationSamples: 0 };
        toolBuckets.set(toolKey, bucket);
      }
      bucket.calls += 1;
      if (item.phase === 'failed') {
        bucket.failures += 1;
      }
      if (dur !== null && item.phase !== 'started') {
        bucket.durationSum += dur;
        bucket.durationSamples += 1;
      }
    }
  }

  const toolStats: Record<string, McpToolStat> = {};
  for (const [toolName, bucket] of toolBuckets.entries()) {
    toolStats[toolName] = {
      toolName,
      calls: bucket.calls,
      failures: bucket.failures,
      avgDurationMs:
        bucket.durationSamples > 0 ? Math.round(bucket.durationSum / bucket.durationSamples) : 0,
    };
  }

  return {
    totalCalls: activities.length,
    runningCalls,
    succeededCalls,
    failedCalls,
    readOnlyCalls,
    writeCalls,
    avgDurationMs: durationCount > 0 ? Math.round(totalDuration / durationCount) : 0,
    activeClients: Array.from(clientSet),
    toolStats,
  };
}

/** 规范化本地路径以跨大小写和斜杠比对案件目录 */
export function normalizeCaseDirForCompare(dir: string | null | undefined): string {
  if (!dir) return '';
  return dir.trim().replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
}

/** 将时间戳提取为精确到毫秒的紧凑时间部分（如 09:42:18.342） */
export function formatActivityShortTime(timestamp: string): string {
  const raw = (timestamp || '').trim();
  if (!raw) return '--:--:--.---';
  const match = raw.match(/(\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)/);
  if (match) {
    const t = match[1];
    if (t.includes('.')) {
      const [hms, ms] = t.split('.');
      return `${hms}.${ms.padEnd(3, '0').slice(0, 3)}`;
    }
    return `${t}.000`;
  }
  return raw;
}

/** 格式化调用耗时（毫秒 / 秒） */
export function formatDurationMs(durationMs: number | null | undefined): string {
  if (durationMs === null || durationMs === undefined || !Number.isFinite(durationMs)) {
    return '—';
  }
  if (durationMs < 1000) {
    return `${Math.round(durationMs)} ms`;
  }
  return `${(durationMs / 1000).toFixed(2)} s`;
}

/** 将文本尝试按 JSON 格式化，解析失败则原样返回 */
export function formatPrettyJson(raw: string | null | undefined): string {
  const text = (raw ?? '').trim();
  if (!text) return '';
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

/** 获取传输方式的中文展示标签 */
export function formatTransportLabel(transport: McpTransportKind | string): string {
  return MCP_TRANSPORT_LABELS[transport as McpTransportKind] ?? transport;
}

/** 获取操作阶段的中文展示标签 */
export function formatPhaseLabel(phase: McpActivityPhase | string): string {
  return MCP_PHASE_LABELS[phase as McpActivityPhase] ?? phase;
}
