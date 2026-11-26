/**
 * TraceDesk 可装配功能模块注册表 (对齐 forensic/features/config.py, catalog.py, api.py)
 * 默认启用全部 11 个模块，保留严格顺序、依赖声明、按钮位置与页面标签顺序。
 */

import type { EntryView } from '../types/ipc';

export type FeatureKey =
  | 'cases'
  | 'evidence'
  | 'files'
  | 'export'
  | 'file_tools'
  | 'report'
  | 'timeline'
  | 'audit'
  | 'help'
  | 'mcp'
  | 'review';

export type ActionLocation = 'brand' | 'header' | 'evidence' | 'preview' | 'file_menu';

export type ActionRole = 'default' | 'accent' | 'soft' | 'ghost' | 'pager' | 'warning';

export type PanelKey = 'files' | 'info' | 'findings' | 'timeview' | 'audit' | 'review' | 'mcp';

export interface FeatureActionSpec {
  key: string;
  title: string;
  location: ActionLocation;
  role?: ActionRole;
  icon?: string;
  /** 右键菜单或预览栏按钮针对当前选中文件是否可用 */
  acceptsEntry?: (entry: EntryView) => boolean;
}

export interface FeaturePanelSpec {
  key: PanelKey;
  title: string;
}

export interface FeatureDefinition {
  key: FeatureKey;
  requires: readonly FeatureKey[];
  actions: readonly FeatureActionSpec[];
  panels: readonly FeaturePanelSpec[];
}

/** 默认启用的全部 11 个功能模块及严格装配顺序 */
export const ENABLED_FEATURES: readonly FeatureKey[] = [
  'cases',
  'evidence',
  'files',
  'export',
  'file_tools',
  'report',
  'timeline',
  'audit',
  'help',
  'mcp',
  'review',
] as const;

export const REQUIRED_FEATURES: readonly FeatureKey[] = ['cases', 'evidence', 'files'] as const;

export function canExportEntry(entry: EntryView): boolean {
  if (entry.canExport !== undefined) {
    return entry.canExport;
  }
  return !entry.directory && (entry.mode.startsWith('r/') || (entry.deleted && entry.mode.startsWith('-/r')));
}

/** 旧版操作中文名映射 (对齐 forensic/core/findings.py) */
export const FINDING_OPERATIONS: Readonly<Record<string, string>> = {
  FILE_NOTE: '取证笔记',
  FILE_HASH: '计算摘要',
  FILE_COMPARE: '比对副本',
};

export const AUDIT_ACTION_TITLES: Readonly<Record<string, string>> = {
  CONTENT_SEARCH: '搜索文件内容',
  SOURCE_REGISTER: '登记证据来源',
  REVIEW_EXPORT: '生成复核包',
  CASE_CREATE: '新建案件',
  CASE_OPEN: '打开案件',
  IMAGE_LOAD_BEGIN: '开始载入镜像',
  IMAGE_LOAD: '载入镜像',
  HASH_FIXED: '固定镜像摘要',
  HASH_VERIFY: '校验镜像完整性',
  FILE_BROWSE: '读取分区文件',
  PARTITIONS_SCAN: '扫描所有分区',
  FILE_FILTER: '筛选文件',
  FILE_EXPORT: '导出文件',
  TIMELINE: '生成时间线',
  REPORT_GENERATE: '生成报告',
  REPORT_HTML: '生成 HTML 报告',
  HTML_REPORT_GENERATE: '生成 HTML 报告',
  MAGIC_SCAN: '魔数伪装检测',
  FILE_NOTE: '记录取证发现',
  FILE_COMPARE: '比对文件副本',
  FILE_HASH: '计算文件摘要',
  FINDINGS_EXPORT: '导出取证发现',
};

export const SOURCE_FIELD_LABELS: readonly { key: 'evidenceId' | 'source' | 'acquired' | 'tool' | 'expectedSha256'; label: string; placeholder: string; mono?: boolean }[] = [
  { key: 'evidenceId', label: '证据编号', placeholder: '例如：EVID-01' },
  { key: 'source', label: '来源 / 交付方', placeholder: '例如：移交单位或扣押清单编号' },
  { key: 'acquired', label: '采集时间与时区', placeholder: '例如：2026-01-12 10:30 UTC+8' },
  { key: 'tool', label: '采集工具与版本', placeholder: '例如：FTK Imager 4.7 / ddrescue' },
  { key: 'expectedSha256', label: '交付方 SHA-256', placeholder: '64 位十六进制 SHA-256 摘要（可选）', mono: true },
] as const;

const FEATURE_CATALOG: Record<FeatureKey, FeatureDefinition> = {
  cases: {
    key: 'cases',
    requires: [],
    actions: [
      { key: 'new_case', title: '新建案件', location: 'header', icon: 'case_new' },
      { key: 'open_case', title: '打开案件', location: 'header', icon: 'case_open' },
    ],
    panels: [],
  },
  evidence: {
    key: 'evidence',
    requires: ['cases'],
    actions: [
      { key: 'load', title: '加载镜像', location: 'evidence', role: 'accent', icon: 'import_disk' },
      { key: 'verify', title: '校验完整性', location: 'evidence', icon: 'verify' },
    ],
    panels: [{ key: 'info', title: '镜像与文件系统' }],
  },
  files: {
    key: 'files',
    requires: ['cases', 'evidence'],
    actions: [],
    panels: [{ key: 'files', title: '文件浏览' }],
  },
  export: {
    key: 'export',
    requires: ['files'],
    actions: [
      {
        key: 'export',
        title: '导出所选文件',
        location: 'preview',
        role: 'soft',
        icon: 'export',
        acceptsEntry: canExportEntry,
      },
    ],
    panels: [],
  },
  file_tools: {
    key: 'file_tools',
    requires: ['files'],
    actions: [
      { key: 'file_note', title: '记录取证发现', location: 'file_menu', icon: 'note', acceptsEntry: canExportEntry },
      { key: 'file_hash', title: '计算哈希值（SHA-256）', location: 'file_menu', acceptsEntry: canExportEntry },
      { key: 'compare_file', title: '校验一致性…', location: 'file_menu', acceptsEntry: canExportEntry },
    ],
    panels: [{ key: 'findings', title: '取证发现' }],
  },
  report: {
    key: 'report',
    requires: ['cases'],
    actions: [
      { key: 'report', title: '生成 Markdown 报告', location: 'header', role: 'soft', icon: 'report' },
    ],
    panels: [],
  },
  timeline: {
    key: 'timeline',
    requires: ['cases'],
    actions: [],
    panels: [{ key: 'timeview', title: 'MACB 时间线' }],
  },
  audit: {
    key: 'audit',
    requires: ['cases'],
    actions: [],
    panels: [{ key: 'audit', title: '审计日志' }],
  },
  help: {
    key: 'help',
    requires: [],
    actions: [
      { key: 'help', title: '操作说明', location: 'brand', role: 'pager', icon: 'help' },
    ],
    panels: [],
  },
  mcp: {
    key: 'mcp',
    requires: [],
    actions: [
      { key: 'mcp', title: 'MCP 服务', location: 'brand', role: 'pager', icon: 'mcp' },
    ],
    panels: [{ key: 'mcp', title: 'MCP 实时监控' }],
  },
  review: {
    key: 'review',
    requires: ['evidence', 'files'],
    actions: [
      { key: 'export_bundle', title: '导出复核包', location: 'header', role: 'accent', icon: 'bundle' },
      { key: 'search_in_file', title: '单文件检索内容…', location: 'file_menu', acceptsEntry: canExportEntry },
    ],
    panels: [{ key: 'review', title: '内容搜索与复核' }],
  },
};

export interface FeatureRegistry {
  readonly enabledKeys: readonly FeatureKey[];
  readonly features: readonly FeatureDefinition[];
  readonly actions: Readonly<Record<string, FeatureActionSpec>>;
  readonly panels: readonly FeaturePanelSpec[];
  hasFeature(key: FeatureKey): boolean;
  actionsAt(location: ActionLocation): FeatureActionSpec[];
}

/** 校验依赖并按顺序装配工作台功能模块；保留六大主工作区标签严格顺序 */
export function createFeatureRegistry(enabled: readonly FeatureKey[] = ENABLED_FEATURES): FeatureRegistry {
  const keySet = new Set<FeatureKey>();
  for (const key of enabled) {
    if (keySet.has(key)) {
      throw new Error(`功能标识重复：${key}`);
    }
    if (!(key in FEATURE_CATALOG)) {
      throw new Error(`未知功能：${key}`);
    }
    keySet.add(key);
  }

  const missingRequired = REQUIRED_FEATURES.filter((req) => !keySet.has(req));
  if (missingRequired.length > 0) {
    throw new Error(`缺少工作台基础功能：${missingRequired.join(', ')}`);
  }

  const features = enabled.map((key) => FEATURE_CATALOG[key]);
  const actions: Record<string, FeatureActionSpec> = {};
  const panelMap = new Map<PanelKey, FeaturePanelSpec>();

  for (const feature of features) {
    const missingDeps = feature.requires.filter((dep) => !keySet.has(dep));
    if (missingDeps.length > 0) {
      throw new Error(`功能 ${feature.key} 缺少依赖：${missingDeps.join(', ')}`);
    }
    for (const action of feature.actions) {
      if (action.key in actions) {
        throw new Error(`命令标识重复：${action.key}`);
      }
      actions[action.key] = action;
    }
    for (const panel of feature.panels) {
      if (panelMap.has(panel.key)) {
        throw new Error(`页面标识重复：${panel.key}`);
      }
      panelMap.set(panel.key, panel);
    }
  }

  // 严格保证主工作区标签顺序：文件浏览 → 镜像与文件系统 → 取证发现 → MACB 时间线 → 审计日志 → 内容搜索与复核 → MCP 实时监控
  const strictPanelOrder: PanelKey[] = ['files', 'info', 'findings', 'timeview', 'audit', 'review', 'mcp'];
  const orderedPanels = strictPanelOrder
    .map((key) => panelMap.get(key))
    .filter((p): p is FeaturePanelSpec => p !== undefined);

  return {
    enabledKeys: enabled,
    features,
    actions,
    panels: orderedPanels,
    hasFeature: (key) => keySet.has(key),
    actionsAt: (location) => Object.values(actions).filter((action) => action.location === location),
  };
}
