/**
 * MCP 实时活动流合并、统计计算与格式化工具函数
 * 用于前端收到 mcp:activity 实时事件后原位更新 started 记录并重算汇总指标，
 * 以及统一传输通道名称、耗时、毫秒时间戳和 JSON 预览的展示格式。
 */

import type {
  McpActivityPhase,
  McpActivityRecord,
  McpActivitySnapshot,
  McpActivityStats,
  McpToolStat,
  McpTransportKind,
} from '../types/ipc';

/** 匹配 MCP 客户端/来源名称分段末尾的版本号数字（如 " 1.0"、" 1.2.3"、" v2.1"、"/3.0"） */
const TRAILING_VERSION_RE =
  /(?:(?:\s+|\/)[vV]?\d+(?:\.\d+)*(?:-(?:alpha|beta|rc|dev|pre|preview|snapshot)(?:[._-]?\d+)*)?)+$/i;

/**
 * 去除 MCP 客户端/来源名称各段末尾的版本号数字，用于展示与筛选合并对齐：
 * - "workbuddy 1.0" -> "workbuddy"
 * - "WorkBuddy HTTP / workbuddy-http-forensics 1.0" -> "WorkBuddy HTTP / workbuddy-http-forensics"
 * - "ForensicBot/3.0" -> "ForensicBot"
 * 若某段去除后为空则保留原段，避免误删纯数字名称。
 */
export function stripTrailingVersion(raw: string | null | undefined): string {
  const trimmed = (raw ?? '').trim();
  if (!trimmed) return '';
  const segments = trimmed
    .split(' / ')
    .map((seg) => {
      const clean = seg.trim();
      if (!clean) return '';
      const stripped = clean.replace(TRAILING_VERSION_RE, '').trimEnd();
      return stripped || clean;
    })
    .filter((seg) => seg.length > 0);
  return segments.length > 0 ? segments.join(' / ') : trimmed;
}

/** 规范化单条 MCP 活动记录的 client 展示字段（温和去尾版本号） */
export function normalizeMcpActivityRecord(record: McpActivityRecord): McpActivityRecord {
  const cleanClient = stripTrailingVersion(record.client);
  if (cleanClient === record.client) {
    return record;
  }
  return {
    ...record,
    client: cleanClient,
  };
}

/** 规范化 MCP 活动快照中的活动列表与活跃客户端列表 */
export function normalizeMcpActivitySnapshot(snapshot: McpActivitySnapshot): McpActivitySnapshot {
  const activities = snapshot.activities.map(normalizeMcpActivityRecord);
  const clientSet = new Set<string>();
  for (const name of snapshot.stats.activeClients) {
    const clean = stripTrailingVersion(name);
    if (clean) clientSet.add(clean);
  }
  return {
    activities,
    stats: {
      ...snapshot.stats,
      activeClients: Array.from(clientSet),
    },
  };
}

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

/** 合并同 callId 的旧记录与新记录，优先保留首次启动时的非空上下文字段 */
function mergeSingleActivity(
  existing: McpActivityRecord,
  incoming: McpActivityRecord
): McpActivityRecord {
  return {
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
    error:
      incoming.error ??
      (incoming.phase === 'completed' ? null : existing.error ?? null),
  };
}

/**
 * 将实时推送的单条 MCP 活动事件按 callId 合并到现有列表：
 * - 若已存在同 callId 条目，则原位更新（优先保留已有非空参数与上下文）；
 * - 若不存在，则插入列表顶部并限制最大缓存条数。
 */
export function mergeMcpActivityRecord(
  prev: readonly McpActivityRecord[],
  incoming: McpActivityRecord,
  maxItems = 500
): McpActivityRecord[] {
  return mergeMcpActivityBatch(prev, [incoming], maxItems);
}

/**
 * 批量合并多条实时推送的 MCP 活动事件（O(N + K) 单趟索引合并，避免高频突发事件下的 O(N * K) 复制）：
 * - 已存在的 callId 原位更新；
 * - 新增的 callId 按到达顺序前置到列表顶部（最新在前），超出 maxItems 时截断尾部。
 */
export function mergeMcpActivityBatch(
  prev: readonly McpActivityRecord[],
  incomingList: readonly McpActivityRecord[],
  maxItems = 500
): McpActivityRecord[] {
  if (incomingList.length === 0) {
    return prev as McpActivityRecord[];
  }

  // 建立已有条目的 callId -> 数组下标映射，避免每条事件线性扫描
  const existingIndexByCallId = new Map<string, number>();
  for (let i = 0; i < prev.length; i += 1) {
    existingIndexByCallId.set(prev[i].callId, i);
  }

  let updatedExisting: McpActivityRecord[] | null = null;
  // 新到达且不在 prev 中的条目，按到达顺序合并去重后再倒序前置到顶部
  const addedOrder: McpActivityRecord[] = [];
  const addedIndexByCallId = new Map<string, number>();

  for (const raw of incomingList) {
    const normalized = normalizeMcpActivityRecord(raw);
    const existingIdx = existingIndexByCallId.get(normalized.callId);
    if (existingIdx !== undefined) {
      if (!updatedExisting) {
        updatedExisting = [...prev];
      }
      updatedExisting[existingIdx] = mergeSingleActivity(updatedExisting[existingIdx], normalized);
      continue;
    }

    const addedIdx = addedIndexByCallId.get(normalized.callId);
    if (addedIdx !== undefined) {
      addedOrder[addedIdx] = mergeSingleActivity(addedOrder[addedIdx], normalized);
    } else {
      addedIndexByCallId.set(normalized.callId, addedOrder.length);
      addedOrder.push(normalized);
    }
  }

  const baseList = updatedExisting ?? prev;
  if (addedOrder.length === 0) {
    return updatedExisting ?? (prev as McpActivityRecord[]);
  }

  // 后到达的新记录位于最顶部（最新在前）
  const prepended: McpActivityRecord[] = [];
  for (let i = addedOrder.length - 1; i >= 0; i -= 1) {
    prepended.push(addedOrder[i]);
  }
  return prepended.concat(baseList).slice(0, maxItems);
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

    // 入队时已对 client 完成去尾版本规范化，此处直接复用清洗后字段避免重复正则匹配
    const client = item.client.trim();
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
