/**
 * TraceDesk 桌面端主工作台骨架 (5 层纵向架构 + 11 个可装配功能模块)
 */
import React, { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { isTauriRuntime, tauriApi, tauriEvents } from './api/tauri';
import { BrandLogo, UiIcon } from './components/Icons';
import { AlertDialog, type AlertDialogState } from './components/dialogs/AlertDialog';
import { BundleExportDialog } from './components/dialogs/BundleExportDialog';
import { BusyTaskDialog } from './components/dialogs/BusyTaskDialog';
import { ExamineResultDialog } from './components/dialogs/ExamineResultDialog';
import { ExportResultDialog, type ExportResultInfo } from './components/dialogs/ExportResultDialog';
import { FindingNoteDialog } from './components/dialogs/FindingNoteDialog';
import { NewCaseDialog } from './components/dialogs/NewCaseDialog';
import { OpenCaseDialog } from './components/dialogs/OpenCaseDialog';
import { RegisterSourceDialog } from './components/dialogs/RegisterSourceDialog';
import { VerifyBundleDialog } from './components/dialogs/VerifyBundleDialog';
import { createFeatureRegistry, ENABLED_FEATURES, type PanelKey } from './features/registry';
import { AuditLogModule } from './modules/AuditLogModule';
import { ContentReviewModule, type ContentSearchLiveState } from './modules/ContentReviewModule';
import { EvidenceInfoModule } from './modules/EvidenceInfoModule';
import { FileBrowserModule } from './modules/FileBrowserModule';
import { FindingsModule } from './modules/FindingsModule';
import { McpMonitorModule } from './modules/McpMonitorModule';
import { TimelineModule } from './modules/TimelineModule';
import type {
  AppPaths,
  BundleMaterialsResponse,
  CaseSnapshot,
  EntryView,
  ExamineFileResponse,
  LocateEntryRequest,
  McpActivityRecord,
  McpStatus,
  RecentCaseDto,
} from './types/ipc';
import { extractPathLeafName, formatCaseTimestamp, formatError } from './utils/assets';
import {
  computeMcpActivityStats,
  mergeMcpActivityBatch,
  normalizeCaseDirForCompare,
  normalizeMcpActivitySnapshot,
  stripTrailingVersion,
} from './utils/mcpActivity';

// 仅在点击“操作说明”时按需懒加载图文引导模块，缩减桌面端首屏主包体积
const HelpGuideDialog = React.lazy(() =>
  import('./modules/HelpGuideDialog').then((mod) => ({ default: mod.HelpGuideDialog }))
);

const DEFAULT_STATUS = '就绪 · 应用层只读 · 本地处理 · UTC+8';
const DEFAULT_DETAIL = '选择目录定位文件；拖动分隔条调整树、列表和内容区域。';
const DEFAULT_WINDOW_TITLE = 'TraceDesk — 电子数据取证工作台';
const RAW_IMAGE_EXTENSIONS = ['dd', 'raw', 'img', 'ima', 'bin', 'dsk', 'image', 'flp', 'vfd', 'E01', 'e01'];
const IMAGE_DROP_EXT_SET = new Set(RAW_IMAGE_EXTENSIONS.map((ext) => ext.toLowerCase()));

/** 标准取证闭环四步速览（用于未开案欢迎工作台侧栏） */
const WORKFLOW_STEPS = [
  {
    step: '1',
    title: '建案与镜像固定',
    desc: '初始化隔离案件目录，只读载入镜像并固定整盘 SHA-256 基线',
  },
  {
    step: '2',
    title: '浏览预览与魔数检测',
    desc: '支持文本、HEX 与图片预览，自动识别扩展名伪装文件',
  },
  {
    step: '3',
    title: '搜索、时间线与发现',
    desc: '多编码流式检索、MACB 时间线分析与结构化取证笔录',
  },
  {
    step: '4',
    title: '双报告与复核包核验',
    desc: '输出 Markdown / HTML 报告及防篡改复核包并支持离线验真',
  },
] as const;

/** 未开案欢迎工作台核心特性微标签 */
const WORKBENCH_CAPABILITIES = ['只读防护', 'SHA-256 审计链', 'EWF / RAW', 'MCP 协同'] as const;

/** 判断拖放路径是否为 case.json 案件元数据文件 */
function isCaseJsonDrop(filePath: string): boolean {
  return extractPathLeafName(filePath).toLowerCase() === 'case.json';
}

/** 判断拖放路径是否为受支持的证据镜像格式（.dd/.raw/.img/.e01 等） */
function isSupportedImageDrop(filePath: string): boolean {
  const base = extractPathLeafName(filePath);
  const dotIdx = base.lastIndexOf('.');
  if (dotIdx <= 0) return false;
  return IMAGE_DROP_EXT_SET.has(base.slice(dotIdx + 1).toLowerCase());
}

/** 将秒数格式化为简洁的中文时长（用于哈希校验已耗时与预计剩余时间 ETA） */
function formatDurationZh(totalSeconds: number): string {
  const safe = Math.max(0, Math.round(totalSeconds));
  if (safe < 60) {
    return `${safe}秒`;
  }
  const hours = Math.floor(safe / 3600);
  const minutes = Math.floor((safe % 3600) / 60);
  const seconds = safe % 60;
  if (hours > 0) {
    return `${hours}小时${String(minutes).padStart(2, '0')}分`;
  }
  return `${minutes}分${String(seconds).padStart(2, '0')}秒`;
}

export const App: React.FC = () => {
  const registry = useMemo(() => createFeatureRegistry(ENABLED_FEATURES), []);
  const inTauri = useMemo(() => isTauriRuntime(), []);

  const [appPaths, setAppPaths] = useState<AppPaths>({
    rootDir: '',
    casesDir: '',
    evidenceDir: '',
  });
  const [snapshot, setSnapshot] = useState<CaseSnapshot | null>(null);
  const [activeTab, setActiveTab] = useState<PanelKey>('files');
  const [selectedEntry, setSelectedEntry] = useState<EntryView | null>(null);
  const [detailText, setDetailText] = useState(DEFAULT_DETAIL);
  const [statusText, setStatusText] = useState(DEFAULT_STATUS);
  const [busy, setBusy] = useState(false);
  const [activeTaskLabel, setActiveTaskLabel] = useState<string | null>(null);
  const [taskStageText, setTaskStageText] = useState('');
  const [progressPercent, setProgressPercent] = useState<number | null>(null);
  const [scanningPartitions, setScanningPartitions] = useState(false);
  const [hashingImage, setHashingImage] = useState(false);
  const [contentSearching, setContentSearching] = useState(false);
  const [searchLiveState, setSearchLiveState] = useState<ContentSearchLiveState>({
    searching: false,
    searchId: null,
    stageText: '',
    percent: null,
    hitCount: 0,
  });
  const [cancellingActiveTask, setCancellingActiveTask] = useState(false);
  const [recentCases, setRecentCases] = useState<RecentCaseDto[]>([]);
  const [loadingRecentCases, setLoadingRecentCases] = useState(false);
  const [dragOverActive, setDragOverActive] = useState(false);
  const [refreshToken, setRefreshToken] = useState(0);
  const [singleFileSearchToken, setSingleFileSearchToken] = useState(0);

  // 全局 MCP 服务状态与实时监控流（汇总指标从活动列表纯派生，消除状态更新器内嵌套 setState）
  const [mcpStatus, setMcpStatus] = useState<McpStatus | null>(null);
  const [mcpActivities, setMcpActivities] = useState<McpActivityRecord[]>([]);
  const mcpStats = useMemo(() => computeMcpActivityStats(mcpActivities), [mcpActivities]);

  // 弹窗状态
  const [newCaseOpen, setNewCaseOpen] = useState(false);
  const [openCaseOpen, setOpenCaseOpen] = useState(false);
  const [registerSourceOpen, setRegisterSourceOpen] = useState(false);
  const [verifyBundleOpen, setVerifyBundleOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  // 顶部「生成报告」瓷白下拉菜单开关与外部点击监测容器
  const [reportMenuOpen, setReportMenuOpen] = useState(false);
  const reportMenuRef = useRef<HTMLDivElement | null>(null);
  const [noteTarget, setNoteTarget] = useState<{ entry: EntryView; initialNote?: string } | null>(null);
  const [examineResult, setExamineResult] = useState<ExamineFileResponse | null>(null);
  const [exportResult, setExportResult] = useState<ExportResultInfo | null>(null);
  const [bundleMaterials, setBundleMaterials] = useState<BundleMaterialsResponse | null>(null);
  const [busyDialogReason, setBusyDialogReason] = useState<string | null>(null);
  const [alertState, setAlertState] = useState<AlertDialogState | null>(null);
  // 跨模块“一键跳转定位原文件”统一状态
  const [locateTarget, setLocateTarget] = useState<LocateEntryRequest | null>(null);
  const locateSeqRef = useRef(0);

  const busyRef = useRef(false);
  const hashingImageRef = useRef(false);
  const contentSearchingRef = useRef(false);
  const activeSearchIdRef = useRef<string | null>(null);
  const hashStartedAtRef = useRef<number | null>(null);
  const backgroundBusyRef = useRef(false);
  const inspectingBundleRef = useRef(false);
  const clearPendingProgressRef = useRef<() => void>(() => {});
  const snapshotRef = useRef<CaseSnapshot | null>(null);
  const mcpStatusRef = useRef<McpStatus | null>(null);
  const openCaseByPathRef = useRef<(casePath: string) => Promise<void>>(async () => {});
  const loadImageByPathRef = useRef<(imagePath: string) => Promise<void>>(async () => {});
  mcpStatusRef.current = mcpStatus;

  // 同步更新并发锁与快照引用，避免链式任务在 React 异步重渲染前读到陈旧状态
  const setBusyState = useCallback((next: boolean) => {
    busyRef.current = next;
    setBusy(next);
  }, []);

  const setHashingImageState = useCallback((next: boolean) => {
    hashingImageRef.current = next;
    backgroundBusyRef.current = next || contentSearchingRef.current;
    setHashingImage(next);
  }, []);

  const setContentSearchingState = useCallback((next: boolean) => {
    contentSearchingRef.current = next;
    backgroundBusyRef.current = hashingImageRef.current || next;
    setContentSearching(next);
    if (!next) {
      activeSearchIdRef.current = null;
    }
  }, []);

  const handleSearchLiveStateChange = useCallback((next: ContentSearchLiveState) => {
    activeSearchIdRef.current = next.searching ? next.searchId : null;
    setSearchLiveState(next);
  }, []);

  /** 刷新案件库中的最近案件列表（供空态欢迎页与打开案件弹窗复用） */
  const refreshRecentCases = useCallback(async () => {
    setLoadingRecentCases(true);
    try {
      const list = await tauriApi.listRecentCases();
      setRecentCases(list);
    } catch {
      // 忽略最近案件刷新异常
    } finally {
      setLoadingRecentCases(false);
    }
  }, []);

  const setSnapshotState = useCallback((next: CaseSnapshot | null) => {
    snapshotRef.current = next;
    setSnapshot(next);
  }, []);

  const showAlert = useCallback(
    (title: string, message: string, tone: AlertDialogState['tone'] = 'info') => {
      setAlertState({ title, message, tone });
    },
    []
  );

  // 打开实时任务进度弹窗，清晰展示当前正在运行的任务与进度
  const openBusyDialog = useCallback((reason: string) => {
    setBusyDialogReason(reason);
  }, []);

  const bumpRefresh = useCallback(() => {
    setRefreshToken((n) => n + 1);
  }, []);

  const applySnapshot = useCallback(
    (next: CaseSnapshot | null) => {
      setSnapshotState(next);
      setRefreshToken((n) => n + 1);
    },
    [setSnapshotState]
  );

  /** 拉取最新 MCP 服务状态与实时监控流快照（与后端 500 条环形队列容量对齐，避免统计跳变） */
  const refreshMcpTelemetry = useCallback(async () => {
    const [statusRes, actRes] = await Promise.all([
      tauriApi.getMcpStatus(),
      tauriApi.listMcpActivities({ limit: 500 }),
    ]);
    const normalized = normalizeMcpActivitySnapshot(actRes);
    setMcpStatus(statusRes);
    setMcpActivities(normalized.activities);
  }, []);

  /** 清空 MCP 实时操作流 */
  const handleClearMcpActivities = useCallback(async () => {
    await tauriApi.clearMcpActivities();
    setMcpActivities([]);
  }, []);

  /** 温和刷新当前打开的案件快照与审计日志（不折叠文件树、不丢失当前选中文件） */
  const refreshCurrentCaseGently = useCallback(
    async (notice?: string) => {
      try {
        const latest = await tauriApi.getCaseSnapshot();
        if (latest) {
          setSnapshotState(latest);
        }
        setRefreshToken((n) => n + 1);
        if (notice) {
          setStatusText(notice);
        }
      } catch {
        // 忽略温和刷新过程中的偶发读取异常
      }
    },
    [setSnapshotState]
  );

  // 启动时读取路径、当前案件快照、最近案件列表与 MCP 实时状态
  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const [paths, snap] = await Promise.all([
          tauriApi.getAppPaths(),
          tauriApi.getCaseSnapshot(),
        ]);
        if (!active) return;
        setAppPaths(paths);
        if (snap) {
          setSnapshotState(snap);
        }
      } catch {
        // 忽略初始化读取失败
      }

      if (active) {
        void refreshRecentCases();
      }

      try {
        const [statusRes, actRes] = await Promise.all([
          tauriApi.getMcpStatus(),
          tauriApi.listMcpActivities({ limit: 500 }),
        ]);
        if (!active) return;
        const normalized = normalizeMcpActivitySnapshot(actRes);
        setMcpStatus(statusRes);
        setMcpActivities(normalized.activities);
      } catch {
        // 忽略初始化 MCP 监控读取失败
      }
    })();
    return () => {
      active = false;
    };
  }, [setSnapshotState, refreshRecentCases]);

  // 打开/切换/关闭案件或载入镜像时动态更新原生窗口标题（同时同步浏览器页签标题）
  useEffect(() => {
    const title = !snapshot
      ? DEFAULT_WINDOW_TITLE
      : snapshot.evidence?.path
        ? `TraceDesk — ${snapshot.number} (${extractPathLeafName(snapshot.evidence.path)})`
        : `TraceDesk — ${snapshot.number}`;
    document.title = title;
    if (!inTauri) return;
    let active = true;
    void import('@tauri-apps/api/window')
      .then(({ getCurrentWindow }) => {
        if (!active) return;
        return getCurrentWindow().setTitle(title);
      })
      .catch(() => {
        // 忽略窗口标题设置异常
      });
    return () => {
      active = false;
    };
  }, [inTauri, snapshot?.number, snapshot?.evidence?.path]);

  // 订阅 Tauri 2 原生窗口文件拖拽事件：支持拖入 case.json 打开案件，或已开案时拖入镜像文件加载
  useEffect(() => {
    if (!inTauri) return;
    let mounted = true;
    let unlisten: (() => void) | undefined;
    void (async () => {
      try {
        const { getCurrentWindow } = await import('@tauri-apps/api/window');
        const fn = await getCurrentWindow().onDragDropEvent((event) => {
          if (!mounted) return;
          const payload = event.payload;
          if (payload.type === 'enter' || payload.type === 'over') {
            setDragOverActive(true);
            return;
          }
          if (payload.type === 'leave') {
            setDragOverActive(false);
            return;
          }
          if (payload.type === 'drop') {
            setDragOverActive(false);
            const paths = payload.paths ?? [];
            if (paths.length === 0) return;

            const caseJson = paths.find((p) => isCaseJsonDrop(p));
            if (caseJson) {
              void openCaseByPathRef.current(caseJson);
              return;
            }
            const imageFile = paths.find((p) => isSupportedImageDrop(p));
            if (imageFile) {
              if (!snapshotRef.current) {
                showAlert('提示', '请先新建或打开案件，再拖入证据镜像文件（.dd / .raw / .img / .e01）。', 'info');
                return;
              }
              void loadImageByPathRef.current(imageFile);
              return;
            }
            showAlert(
              '不支持的文件类型',
              '请拖入案件元数据 case.json 打开案件，或在已开案状态下拖入 .dd / .raw / .img / .e01 镜像文件。',
              'warning'
            );
          }
        });
        if (!mounted) {
          fn();
        } else {
          unlisten = fn;
        }
      } catch {
        // 忽略非桌面窗口环境
      }
    })();
    return () => {
      mounted = false;
      setDragOverActive(false);
      unlisten?.();
    };
  }, [inTauri, showAlert]);

  // 顶部「生成报告」下拉菜单：支持点击外部区域与 Esc 键关闭
  useEffect(() => {
    if (!reportMenuOpen) return;
    const handleOutsideClick = (event: MouseEvent) => {
      if (reportMenuRef.current && !reportMenuRef.current.contains(event.target as Node)) {
        setReportMenuOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setReportMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [reportMenuOpen]);

  // 案件关闭或进入忙碌状态时自动收起报告下拉菜单
  useEffect(() => {
    if (!snapshot || busy) {
      setReportMenuOpen(false);
    }
  }, [snapshot, busy]);

  // 订阅后台任务、大镜像哈希进度与 MCP 实时遥测事件（含 StrictMode/卸载防泄漏与 rAF 合批节流）
  useEffect(() => {
    let mounted = true;
    const unlisteners: (() => void)[] = [];

    // 高频进度事件合批缓存，每帧最多提交一次状态更新并去重相同文案/百分比
    let progressRafId: number | null = null;
    let pendingProgress: { pct: number | null; text: string } | null = null;
    let lastProgressPct: number | null | undefined = undefined;
    let lastProgressText = '';

    const scheduleProgressUpdate = (pct: number | null, text: string) => {
      pendingProgress = { pct, text };
      if (progressRafId !== null) return;
      progressRafId = window.requestAnimationFrame(() => {
        progressRafId = null;
        if (!mounted || !pendingProgress) return;
        const { pct: nextPct, text: nextText } = pendingProgress;
        pendingProgress = null;
        if (nextPct !== lastProgressPct) {
          lastProgressPct = nextPct;
          setProgressPercent(nextPct);
        }
        if (nextText !== lastProgressText) {
          lastProgressText = nextText;
          setStatusText(nextText);
          setTaskStageText(nextText);
        }
      });
    };

    const clearPendingProgress = () => {
      if (progressRafId !== null) {
        window.cancelAnimationFrame(progressRafId);
        progressRafId = null;
      }
      pendingProgress = null;
      lastProgressPct = undefined;
      lastProgressText = '';
    };
    // 暴露给 runTask 与大镜像校验启停边界，防止已排队的进度 rAF 覆盖任务结束状态或误吞重复任务进度
    clearPendingProgressRef.current = clearPendingProgress;

    // MCP 实时活动事件按帧合批合并，避免跨进程尾随突发数十条事件触发连续全树重绘
    let mcpRafId: number | null = null;
    let pendingMcpRecords: McpActivityRecord[] = [];
    const scheduleMcpFlush = () => {
      if (mcpRafId !== null) return;
      mcpRafId = window.requestAnimationFrame(() => {
        mcpRafId = null;
        if (!mounted || pendingMcpRecords.length === 0) return;
        const batch = pendingMcpRecords;
        pendingMcpRecords = [];
        setMcpActivities((prev) => mergeMcpActivityBatch(prev, batch, 500));
      });
    };

    const registerSafe = async (promise: Promise<() => void>) => {
      try {
        const unlisten = await promise;
        if (!mounted) {
          // 若组件在 listen() Promise 解析前已卸载，立即释放底层监听防泄漏
          unlisten();
        } else {
          unlisteners.push(unlisten);
        }
      } catch {
        // 忽略单通道订阅异常
      }
    };

    void Promise.all([
      registerSafe(
        tauriEvents.onTaskProgress((ev) => {
          if (!mounted) return;
          if (ev.total > 0) {
            const pct = Math.min(100, Math.floor((100 * ev.done) / ev.total));
            scheduleProgressUpdate(pct, `${ev.stage} · ${pct}%`);
          } else {
            scheduleProgressUpdate(null, `${ev.stage}…`);
          }
        })
      ),
      registerSafe(
        tauriEvents.onHashProgress((ev) => {
          if (!mounted) return;
          if (hashStartedAtRef.current === null) {
            hashStartedAtRef.current = Date.now();
          }
          const pct = ev.total > 0 ? Math.min(100, Math.floor((100 * ev.done) / ev.total)) : 0;
          const elapsedSec = Math.max(0, (Date.now() - hashStartedAtRef.current) / 1000);
          let etaPart = '';
          if (ev.total > ev.done && ev.rateMiBs > 0.01) {
            const remainingMiB = (ev.total - ev.done) / (1024 * 1024);
            const etaSec = remainingMiB / ev.rateMiBs;
            etaPart = ` · 预计剩余 ${formatDurationZh(etaSec)}`;
          }
          scheduleProgressUpdate(
            pct,
            `后台读取整镜像 · ${pct}% · ${Math.round(ev.rateMiBs)} MiB/s · 已耗时 ${formatDurationZh(elapsedSec)}${etaPart}`
          );
        })
      ),
      registerSafe(
        tauriEvents.onHashFinished((ev) => {
          if (!mounted) return;
          hashStartedAtRef.current = null;
          clearPendingProgress();
          setHashingImageState(false);
          setProgressPercent(null);
          setTaskStageText('');
          if (ev.snapshot) {
            applySnapshot(ev.snapshot);
          }
          if (ev.cancelled) {
            setStatusText('已取消校验');
          } else if (ev.error) {
            setStatusText('校验失败');
            showAlert('校验失败', ev.error, 'error');
          } else if (ev.ok) {
            setStatusText(ev.initialFixed ? '已完成整镜像 SHA-256 固定' : '完整性校验通过');
          } else {
            setStatusText('完整性校验不匹配');
            showAlert('完整性校验', '本次读取与案件固定值不一致，请核查原始镜像！', 'error');
          }
        })
      ),
      // 实时批量合并 MCP 单步操作事件（汇总指标通过 useMemo 自动重算）
      registerSafe(
        tauriEvents.onMcpActivity((record) => {
          if (!mounted) return;
          pendingMcpRecords.push(record);
          scheduleMcpFlush();
        })
      ),
      // 当 MCP 对当前打开的案件执行受控写入后，温和刷新快照与审计日志（不折叠文件树）
      registerSafe(
        tauriEvents.onMcpCaseUpdated((ev) => {
          if (!mounted) return;
          const currentDir = normalizeCaseDirForCompare(snapshotRef.current?.caseDir);
          const updatedDir = normalizeCaseDirForCompare(ev.caseDir);
          if (currentDir && updatedDir && currentDir === updatedDir) {
            const matchedTool = mcpStatusRef.current?.tools?.find((t) => t.name === ev.toolName);
            const displayTool = matchedTool?.title || ev.toolName;
            const cleanClient = stripTrailingVersion(ev.client);
            const clientLabel = cleanClient ? `MCP（${cleanClient}）` : 'MCP';
            void refreshCurrentCaseGently(`${clientLabel}完成「${displayTool}」，已自动刷新案件与审计日志`);
          }
        })
      ),
    ]);

    return () => {
      mounted = false;
      clearPendingProgress();
      clearPendingProgressRef.current = () => {};
      if (mcpRafId !== null) {
        window.cancelAnimationFrame(mcpRafId);
        mcpRafId = null;
      }
      pendingMcpRecords = [];
      for (const u of unlisteners) u();
      unlisteners.length = 0;
    };
  }, [applySnapshot, refreshCurrentCaseGently, setHashingImageState, showAlert]);

  // 主窗口关闭守卫（仅 Tauri 桌面端；增加 mounted 守卫防止 StrictMode 双挂载残留重复关闭监听）
  useEffect(() => {
    if (!inTauri) return;
    let mounted = true;
    let unlisten: (() => void) | undefined;
    void (async () => {
      try {
        const { getCurrentWindow } = await import('@tauri-apps/api/window');
        const fn = await getCurrentWindow().onCloseRequested(async (event) => {
          if (!mounted) return;
          if (busyRef.current || backgroundBusyRef.current) {
            event.preventDefault();
            openBusyDialog('存在正在运行的后台任务或内容搜索，请先取消或等待完成后再关闭窗口。');
            return;
          }
          try {
            const check = await tauriApi.checkBusyBeforeClose();
            if (check.busy) {
              event.preventDefault();
              showAlert('正在处理', check.reason || '后台任务尚未结束，请稍后关闭窗口。', 'warning');
            }
          } catch {
            // 忽略守卫查询异常
          }
        });
        if (!mounted) {
          fn();
        } else {
          unlisten = fn;
        }
      } catch {
        // 忽略非窗口环境
      }
    })();
    return () => {
      mounted = false;
      unlisten?.();
    };
  }, [inTauri, openBusyDialog, showAlert]);

  // 统一任务执行包装：同步维护 busyRef 与 busy，避免链式任务或快速连点误触发并发锁
  const runTask = useCallback(
    async <T,>(
      label: string,
      work: () => Promise<T>,
      options?: {
        requiresCase?: boolean;
        blocksBackground?: boolean;
        onSuccess?: (val: T) => void | Promise<void>;
      }
    ): Promise<T | null> => {
      const requiresCase = options?.requiresCase ?? true;
      const blocksBackground = options?.blocksBackground ?? !requiresCase;
      if (blocksBackground && backgroundBusyRef.current) {
        openBusyDialog('切换案件前请先取消后台校验或内容搜索，或等待完成。');
        return null;
      }
      if (busyRef.current) {
        openBusyDialog('请等待当前任务完成后再继续操作。');
        return null;
      }
      if (requiresCase && !snapshotRef.current) {
        showAlert('提示', '请先新建或打开案件。', 'info');
        return null;
      }

      clearPendingProgressRef.current();
      setBusyState(true);
      setActiveTaskLabel(label);
      setTaskStageText(`${label}…`);
      setProgressPercent(null);
      setStatusText(`${label}…`);
      let result: T;
      try {
        result = await work();
      } catch (err) {
        clearPendingProgressRef.current();
        setBusyState(false);
        setActiveTaskLabel(null);
        setTaskStageText('');
        setProgressPercent(null);
        setStatusText(`${label}失败`);
        showAlert(`${label}失败`, formatError(err), 'error');
        return null;
      }

      // work() 完成后先清理在途进度帧并同步释放并发锁，再执行 onSuccess 或返回给链式后续任务
      clearPendingProgressRef.current();
      setBusyState(false);
      setActiveTaskLabel(null);
      setTaskStageText('');
      setProgressPercent(null);
      setStatusText(DEFAULT_STATUS);
      await options?.onSuccess?.(result);
      return result;
    },
    [openBusyDialog, setBusyState, showAlert]
  );

  // 加载镜像或打开案件后，按镜像大小自动扫描分区或浏览首个可读根目录
  const resumePartitions = useCallback(
    async (snap: CaseSnapshot) => {
      const ev = snap.evidence;
      if (!ev) return;
      const isLarge = Boolean(ev.largeImage ?? ev.large_image);
      if (isLarge && snap.browsingDirectories) {
        if (ev.partitions.length === 0) return;
        const res = await runTask(
          '读取分区根目录',
          async () => {
            const failures: string[] = [];
            for (const part of ev.partitions) {
              try {
                return await tauriApi.browseDirectory({ offset: part.offset, inode: null, path: '' });
              } catch (err) {
                failures.push(`偏移 ${part.offset}：${formatError(err)}`);
              }
            }
            throw new Error('无法读取根目录：' + failures.join('；'));
          },
          { requiresCase: true }
        );
        if (res) {
          applySnapshot(res.snapshot);
        }
      } else if (!isLarge && snap.needsPartitionScan) {
        setScanningPartitions(true);
        try {
          const res = await runTask('读取所有分区与文件树', () => tauriApi.scanAllPartitions(), {
            requiresCase: true,
          });
          if (res) {
            if (res.completed) {
              applySnapshot(res.snapshot);
            } else {
              setDetailText('已取消建立索引，保留原有浏览结果。');
            }
          }
        } finally {
          setScanningPartitions(false);
        }
      }
    },
    [runTask, applySnapshot]
  );

  const handleCaseReplaced = useCallback(
    async (next: CaseSnapshot | null) => {
      setSelectedEntry(null);
      setLocateTarget(null);
      setDetailText(DEFAULT_DETAIL);
      setStatusText(DEFAULT_STATUS);
      applySnapshot(next);
      // 成功新建或打开案件后默认进入文件浏览主工作台（避免停留在未开案 MCP 独立页）
      if (next) {
        setActiveTab('files');
      }
      void refreshRecentCases();
      if (next) {
        await resumePartitions(next);
      }
    },
    [applySnapshot, resumePartitions, refreshRecentCases]
  );

  // 案件与镜像动作
  const handleNewCase = () => {
    if (backgroundBusyRef.current) {
      openBusyDialog('切换案件前请先取消后台校验或内容搜索，或等待完成。');
      return;
    }
    if (busyRef.current) {
      openBusyDialog('请等待当前任务完成后再新建案件。');
      return;
    }
    setNewCaseOpen(true);
  };

  /** 通过指定路径直接打开案件（供欢迎空态卡片、拖拽 case.json 复用） */
  const openCaseByPath = useCallback(
    async (casePath: string) => {
      if (backgroundBusyRef.current) {
        openBusyDialog('切换案件前请先取消后台校验或内容搜索，或等待完成。');
        return;
      }
      if (busyRef.current) {
        openBusyDialog('请等待当前任务完成后再打开案件。');
        return;
      }
      const snap = await runTask('打开案件并读取清单', () => tauriApi.openCase({ casePath }), {
        requiresCase: false,
        blocksBackground: true,
      });
      if (snap) {
        await handleCaseReplaced(snap);
      }
    },
    [handleCaseReplaced, openBusyDialog, runTask]
  );
  openCaseByPathRef.current = openCaseByPath;

  const handleOpenCase = () => {
    if (backgroundBusyRef.current) {
      openBusyDialog('切换案件前请先取消后台校验或内容搜索，或等待完成。');
      return;
    }
    if (busyRef.current) {
      openBusyDialog('请等待当前任务完成后再打开案件。');
      return;
    }
    // 统一打开含最近案件列表卡片与“浏览本地 case.json…”按钮的弹窗
    setOpenCaseOpen(true);
  };

  /** 关闭当前打开的案件并返回空态欢迎页 */
  const handleCloseCase = useCallback(async () => {
    if (!snapshotRef.current) return;
    if (backgroundBusyRef.current) {
      openBusyDialog('关闭案件前请先取消后台校验或内容搜索，或等待完成。');
      return;
    }
    if (busyRef.current) {
      openBusyDialog('请等待当前任务完成后再关闭案件。');
      return;
    }
    const res = await runTask('关闭当前案件', () => tauriApi.closeCase(), {
      requiresCase: true,
      blocksBackground: true,
    });
    if (res?.closed) {
      await handleCaseReplaced(null);
      setActiveTab('files');
      setStatusText('已关闭当前案件');
    }
  }, [handleCaseReplaced, openBusyDialog, runTask]);

  /** 通过指定路径加载镜像（供选择文件与拖拽镜像文件复用） */
  const loadImageByPath = useCallback(
    async (imagePath: string) => {
      if (!snapshotRef.current) {
        showAlert('提示', '请先新建或打开案件。', 'info');
        return;
      }
      if (backgroundBusyRef.current) {
        openBusyDialog('加载新镜像前请先取消后台完整性校验或内容搜索，或等待完成。');
        return;
      }
      if (busyRef.current) {
        openBusyDialog('请等待当前任务完成后再加载镜像。');
        return;
      }
      const snap = await runTask(
        '打开镜像并识别分区',
        () => tauriApi.loadImage({ imagePath }),
        { requiresCase: true, blocksBackground: true }
      );
      if (snap) {
        setSelectedEntry(null);
        applySnapshot(snap);
        await resumePartitions(snap);
      }
    },
    [applySnapshot, openBusyDialog, resumePartitions, runTask, showAlert]
  );
  loadImageByPathRef.current = loadImageByPath;

  const handleLoadImage = async () => {
    if (!snapshotRef.current) {
      showAlert('提示', '请先新建或打开案件。', 'info');
      return;
    }
    if (backgroundBusyRef.current) {
      openBusyDialog('加载新镜像前请先取消后台完整性校验或内容搜索，或等待完成。');
      return;
    }
    if (busyRef.current) {
      openBusyDialog('请等待当前任务完成后再加载镜像。');
      return;
    }
    let imagePath: string | null = null;
    if (inTauri) {
      imagePath = await tauriApi.pickFile({
        title: '选择 RAW 镜像或 E01 首段',
        defaultPath: appPaths.evidenceDir || undefined,
        filters: [{ name: 'RAW 或 EWF 首段', extensions: RAW_IMAGE_EXTENSIONS }],
      });
      if (!imagePath) return;
    } else {
      imagePath = 'C:\\TraceDesk\\evidence\\demo.dd';
    }
    await loadImageByPath(imagePath);
  };

  const handleVerifyIntegrity = async () => {
    if (hashingImageRef.current) {
      try {
        await tauriApi.cancelVerifyIntegrity();
        setStatusText('正在取消校验…');
      } catch {
        // 忽略
      }
      return;
    }
    const currentSnap = snapshotRef.current;
    if (!currentSnap) {
      showAlert('提示', '请先新建或打开案件。', 'info');
      return;
    }
    if (!currentSnap.evidence) {
      showAlert('提示', '请先加载镜像。', 'info');
      return;
    }
    const isLarge = Boolean(currentSnap.evidence.largeImage ?? currentSnap.evidence.large_image);
    if (isLarge) {
      if (busyRef.current) {
        openBusyDialog('请等待当前任务完成后再启动完整性校验。');
        return;
      }
      clearPendingProgressRef.current();
      hashStartedAtRef.current = Date.now();
      setHashingImageState(true);
      setStatusText('后台读取整镜像 · 可继续浏览');
      setTaskStageText('后台读取整镜像 · 可继续浏览');
      try {
        await tauriApi.verifyIntegrity();
      } catch (err) {
        hashStartedAtRef.current = null;
        clearPendingProgressRef.current();
        setHashingImageState(false);
        setProgressPercent(null);
        setTaskStageText('');
        setStatusText('校验失败');
        showAlert('校验失败', formatError(err), 'error');
      }
      return;
    }
    const res = await runTask('流式校验 SHA-256', () => tauriApi.verifyIntegrity());
    if (res) {
      applySnapshot(res.snapshot);
      showAlert(
        '完整性校验',
        res.ok
          ? res.initialFixed
            ? '已完成整镜像 SHA-256 首次固定。'
            : '通过：与初始固定值一致。'
          : '失败：原始镜像已发生变化！',
        res.ok ? 'ok' : 'error'
      );
    }
  };

  const handleScanAllPartitions = useCallback(async () => {
    if (!snapshotRef.current?.evidence) return;
    if (busyRef.current) {
      openBusyDialog('请等待当前任务完成后再扫描分区。');
      return;
    }
    setScanningPartitions(true);
    try {
      const res = await runTask('读取所有分区与文件树', () => tauriApi.scanAllPartitions());
      if (res) {
        if (res.completed) {
          applySnapshot(res.snapshot);
        } else {
          setDetailText('已取消建立索引，保留原有浏览结果。');
        }
      }
    } finally {
      setScanningPartitions(false);
    }
  }, [applySnapshot, openBusyDialog, runTask]);

  const handleScanPartition = useCallback(
    async (offset: number) => {
      if (!snapshotRef.current?.evidence) return;
      if (busyRef.current) {
        openBusyDialog('请等待当前任务完成后再索引分区。');
        return;
      }
      setScanningPartitions(true);
      try {
        const res = await runTask(`索引分区（偏移 ${offset}）`, () =>
          tauriApi.scanPartition({ offset })
        );
        if (res) {
          if (res.completed) {
            applySnapshot(res.snapshot);
            setDetailText(`已完成分区偏移 ${offset} 扇区的文件索引。`);
          } else {
            setDetailText(`已取消分区偏移 ${offset} 扇区的索引。`);
          }
        }
      } finally {
        setScanningPartitions(false);
      }
    },
    [applySnapshot, openBusyDialog, runTask]
  );

  const handleCancelScan = useCallback(async () => {
    try {
      await tauriApi.cancelScanPartitions();
      setStatusText('正在取消建立索引…');
    } catch {
      // 忽略
    }
  }, []);

  /** 按当前活跃任务类型统一发起取消请求（前台长任务 / 后台大镜像哈希 / 后台内容搜索） */
  const handleCancelActiveTask = useCallback(async () => {
    if (cancellingActiveTask) return;
    setCancellingActiveTask(true);
    try {
      const jobs: Promise<unknown>[] = [];
      if (busyRef.current) {
        jobs.push(tauriApi.cancelTask());
      }
      if (hashingImageRef.current) {
        jobs.push(tauriApi.cancelVerifyIntegrity());
      }
      if (contentSearchingRef.current && activeSearchIdRef.current) {
        jobs.push(tauriApi.cancelContentSearch({ searchId: activeSearchIdRef.current }));
      }
      if (jobs.length > 0) {
        setStatusText('正在请求取消当前任务…');
        await Promise.allSettled(jobs);
      }
    } finally {
      setCancellingActiveTask(false);
    }
  }, [cancellingActiveTask]);

  const handleBrowseDirectory = useCallback(
    async (offset: number, inode: string | null, path: string): Promise<EntryView[] | null> => {
      const res = await runTask(`读取目录 /${path}`, () =>
        tauriApi.browseDirectory({ offset, inode, path })
      );
      if (res) {
        setSelectedEntry(null);
        applySnapshot(res.snapshot);
        return res.entries;
      }
      return null;
    },
    [runTask, applySnapshot]
  );

  const handleExportEntry = useCallback(
    async (entry: EntryView) => {
      await runTask('校验并导出证据副本', () => tauriApi.exportFile({ entryId: entry.entryId }), {
        onSuccess: (res) => {
          applySnapshot(res.snapshot);
          // 保留原文件条目，便于导出成功弹窗一键打开“记录取证发现”
          setExportResult({
            title: res.title || '导出成功',
            path: res.path,
            note: res.note,
            entry,
          });
        },
      });
    },
    [applySnapshot, runTask]
  );

  const handleHashEntry = useCallback(
    async (entry: EntryView) => {
      await runTask('计算文件 SHA-256', () => tauriApi.examineFile({ entryId: entry.entryId }), {
        onSuccess: (res) => {
          applySnapshot(res.snapshot);
          setExamineResult(res);
        },
      });
    },
    [applySnapshot, runTask]
  );

  const handleCompareEntry = useCallback(
    async (entry: EntryView) => {
      if (busyRef.current) {
        openBusyDialog('请等待当前任务完成后再校验文件一致性。');
        return;
      }
      const currentSnap = snapshotRef.current;
      let comparisonPath: string | null = null;
      if (inTauri) {
        comparisonPath = await tauriApi.pickFile({
          title: '选择与镜像内文件比较的本地副本',
          defaultPath: currentSnap ? `${currentSnap.caseDir}\\exports` : undefined,
        });
        if (!comparisonPath) return;
      } else {
        comparisonPath = `${currentSnap?.caseDir ?? 'C:\\TraceDesk\\cases\\DEMO-01'}\\exports\\${entry.name}`;
      }
      await runTask(
        '校验文件一致性',
        () => tauriApi.examineFile({ entryId: entry.entryId, comparisonPath: comparisonPath! }),
        {
          onSuccess: (res) => {
            applySnapshot(res.snapshot);
            setExamineResult(res);
          },
        }
      );
    },
    [applySnapshot, inTauri, openBusyDialog, runTask]
  );

  const handleSearchInFile = useCallback((entry: EntryView) => {
    setSelectedEntry(entry);
    setActiveTab('review');
    setSingleFileSearchToken((n) => n + 1);
  }, []);

  const handleExportFsstat = useCallback(
    async (offset: number) => {
      await runTask('读取完整文件系统详情', () => tauriApi.exportFsstat({ offset }), {
        onSuccess: (res) => {
          setExportResult({
            title: '文件系统详情已导出',
            path: res.path,
          });
        },
      });
    },
    [runTask]
  );

  const handleExportFindings = useCallback(
    async (groupKeys: string[]) => {
      if (groupKeys.length === 0) {
        showAlert('提示', '当前没有可导出的取证发现。', 'info');
        return;
      }
      await runTask('一键导出取证发现', () => tauriApi.exportFindings({ groupKeys }), {
        onSuccess: (res) => {
          applySnapshot(res.snapshot);
          setExportResult({
            title: '取证发现已导出',
            path: res.summaryPath,
            note: res.note,
          });
        },
      });
    },
    [applySnapshot, runTask, showAlert]
  );

  const handleGenerateReport = async () => {
    await runTask('校验并生成 Markdown 报告', () => tauriApi.generateReport(), {
      onSuccess: (res) => {
        applySnapshot(res.snapshot);
        setExportResult({
          title: 'Markdown 报告已生成',
          path: res.path,
        });
      },
    });
  };

  /** 生成离线自包含 HTML 取证报告并展示路径、SHA-256 与大小 */
  const handleGenerateHtmlReport = async () => {
    await runTask('校验并生成 HTML 报告', () => tauriApi.generateHtmlReport(), {
      onSuccess: (res) => {
        void refreshCurrentCaseGently('已生成离线 HTML 报告并写入审计链');
        setExportResult({
          title: 'HTML 报告已生成',
          path: res.path,
          sha256: res.sha256,
          bytes: res.bytes,
          generatedAt: res.generatedAt,
          note: '离线自包含单文件 HTML 报告，可在无网环境下直接使用浏览器打开审阅与打印。',
        });
      },
    });
  };

  const handleExportBundle = async () => {
    const currentSnap = snapshotRef.current;
    if (!currentSnap) {
      showAlert('提示', '请先新建或打开案件。', 'info');
      return;
    }
    if (!currentSnap.evidence) {
      showAlert('提示', '请先加载镜像。', 'info');
      return;
    }
    if (busyRef.current || inspectingBundleRef.current) {
      openBusyDialog('请等待当前任务完成后再生成复核包。');
      return;
    }
    inspectingBundleRef.current = true;
    try {
      const mat = await tauriApi.inspectBundleMaterials();
      if (mat.exports.length > 0 || mat.searches.length > 0) {
        setBundleMaterials(mat);
      } else {
        await runBuildBundle();
      }
    } catch (err) {
      showAlert('检查复核包材料失败', formatError(err), 'error');
    } finally {
      inspectingBundleRef.current = false;
    }
  };

  // 为记忆化子模块提供稳定的回调引用，防止进度或遥测更新破坏 React.memo
  const handleScanPartitionsClick = useCallback(() => {
    void handleScanAllPartitions();
  }, [handleScanAllPartitions]);

  const handleScanPartitionClick = useCallback(
    (offset: number) => {
      void handleScanPartition(offset);
    },
    [handleScanPartition]
  );

  const handleCancelScanClick = useCallback(() => {
    void handleCancelScan();
  }, [handleCancelScan]);

  const handleExportEntryClick = useCallback(
    (entry: EntryView) => {
      void handleExportEntry(entry);
    },
    [handleExportEntry]
  );

  const handleRecordNoteClick = useCallback((entry: EntryView, initialNote?: string) => {
    setNoteTarget({ entry, initialNote });
  }, []);

  /** 跨模块“一键跳转定位原文件”统一入口：切至文件浏览模块并驱动目标定位与 HEX 高亮 */
  const handleLocateEntry = useCallback((req: LocateEntryRequest) => {
    const nextId = ++locateSeqRef.current;
    setLocateTarget({
      ...req,
      requestId: nextId,
    });
    setActiveTab('files');
  }, []);

  const handleHashEntryClick = useCallback(
    (entry: EntryView) => {
      void handleHashEntry(entry);
    },
    [handleHashEntry]
  );

  const handleCompareEntryClick = useCallback(
    (entry: EntryView) => {
      void handleCompareEntry(entry);
    },
    [handleCompareEntry]
  );

  const handleOpenRegisterSource = useCallback(() => {
    setRegisterSourceOpen(true);
  }, []);

  const handleExportFsstatClick = useCallback(
    (offset: number) => {
      void handleExportFsstat(offset);
    },
    [handleExportFsstat]
  );

  const handleExportFindingsClick = useCallback(
    (groupKeys: string[]) => {
      void handleExportFindings(groupKeys);
    },
    [handleExportFindings]
  );

  const handleJumpToAudit = useCallback(() => {
    setActiveTab('audit');
    bumpRefresh();
  }, [bumpRefresh]);

  const handleRefreshCurrentCaseManual = useCallback(
    () => refreshCurrentCaseGently('已手动刷新当前案件快照与审计日志'),
    [refreshCurrentCaseGently]
  );

  const runBuildBundle = async (selectedExportIndices?: number[], selectedSearchIndices?: number[]) => {
    await runTask(
      '校验并生成复核包',
      () =>
        tauriApi.buildReviewBundle({
          selectedExportIndices,
          selectedSearchIndices,
        }),
      {
        onSuccess: (res) => {
          applySnapshot(res.snapshot);
          setExportResult({
            title: '复核包已生成',
            path: res.path,
          });
        },
      }
    );
  };

  // 分发顶部按钮命令
  const invokeAction = (key: string) => {
    switch (key) {
      case 'help':
        setHelpOpen(true);
        break;
      case 'mcp':
        setActiveTab('mcp');
        break;
      case 'new_case':
        handleNewCase();
        break;
      case 'open_case':
        void handleOpenCase();
        break;
      case 'report':
        void handleGenerateReport();
        break;
      case 'export_bundle':
        void handleExportBundle();
        break;
      case 'load':
        void handleLoadImage();
        break;
      case 'verify':
        void handleVerifyIntegrity();
        break;
      default:
        break;
    }
  };

  const brandActions = registry.actionsAt('brand');
  const brandActionMap = useMemo(
    () => new Map(brandActions.map((act) => [act.key, act])),
    [brandActions]
  );
  const helpAction = brandActionMap.get('help');
  const mcpAction = brandActionMap.get('mcp');
  const headerActions = registry.actionsAt('header');
  const headerActionMap = useMemo(
    () => new Map(headerActions.map((act) => [act.key, act])),
    [headerActions]
  );
  const newCaseAction = headerActionMap.get('new_case');
  const openCaseAction = headerActionMap.get('open_case');
  const reportAction = headerActionMap.get('report');
  const exportBundleAction = headerActionMap.get('export_bundle');
  const evidenceActions = registry.actionsAt('evidence');
  const fileNoteAction = registry.actions.file_note;
  const hasFileNoteFeature = Boolean(registry.hasFeature('file_tools') && fileNoteAction);

  // 视图形态判定：未开案全屏欢迎首页 / 未开案 MCP 独立监控页 / 已开案三段式工作台
  const isWelcomeLaunchpad = !snapshot && activeTab !== 'mcp';
  const isStandaloneMcp = !snapshot && activeTab === 'mcp';

  const custodyState = snapshot?.custodyState ?? 'idle';
  const showProgressBar = busy || hashingImage || contentSearching;

  // 当仅存在后台内容搜索时，底栏进度条与文案同步显示后台内容搜索进度
  const effectiveProgressPercent =
    busy || hashingImage ? progressPercent : contentSearching ? searchLiveState.percent : null;
  const footerStatusText =
    !busy && !hashingImage && contentSearching
      ? searchLiveState.stageText || '正在后台搜索文件内容…'
      : statusText;

  // 未开案时为底栏左侧提供贴合当前视图的简洁提示文案
  const footerDetailText = useMemo(() => {
    if (snapshot) return detailText;
    if (detailText !== DEFAULT_DETAIL) return detailText;
    if (isStandaloneMcp) {
      return 'MCP 实时监控模式 · 随时可通过右上角新建或打开案件进入取证工作台。';
    }
    return inTauri
      ? '选择最近案件、点击快捷入口，或直接将 case.json 拖入窗口快速开始。'
      : '浏览器只读演示预览模式 · 可新建/打开演示案件、体验离线复核包核验与 MCP 监控。';
  }, [snapshot, detailText, isStandaloneMcp, inTauri]);

  // 聚合当前活跃的前台与后台任务名称，供实时任务进度弹窗清晰展示
  const activeTaskNames = useMemo(() => {
    const names: string[] = [];
    if (activeTaskLabel) {
      names.push(activeTaskLabel);
    }
    if (hashingImage) {
      names.push('校验镜像完整性');
    }
    if (contentSearching) {
      names.push('搜索文件内容');
    }
    return names;
  }, [activeTaskLabel, hashingImage, contentSearching]);

  const busyDialogStageText = useMemo(() => {
    if (taskStageText) return taskStageText;
    if (hashingImage) return '后台读取整镜像 · 可继续浏览';
    if (contentSearching) return searchLiveState.stageText || '正在流式检索镜像文件内容…';
    return statusText;
  }, [taskStageText, hashingImage, contentSearching, searchLiveState.stageText, statusText]);

  // 当前正在执行中的 MCP 工具信息（用于顶栏和底栏实时状态指示）
  const activeRunningMcp = useMemo(
    () => mcpActivities.find((item) => item.phase === 'started') ?? null,
    [mcpActivities]
  );
  const mcpRunningCalls = mcpStats.runningCalls;
  const mcpHttpRunning = Boolean(mcpStatus?.running);
  const mcpLiveLabel = useMemo(() => {
    if (mcpRunningCalls > 0) {
      const toolTitle = activeRunningMcp?.toolTitle || '正在调用工具';
      return mcpRunningCalls > 1
        ? `MCP 执行中 · ${toolTitle} (+${mcpRunningCalls - 1})`
        : `MCP 执行中 · ${toolTitle}`;
    }
    if (mcpHttpRunning) {
      return 'MCP 运行中';
    }
    return 'MCP 服务';
  }, [mcpRunningCalls, activeRunningMcp, mcpHttpRunning]);

  return (
    <div className="td-workbench">
      {/* 未开案进入「MCP 实时监控」时的专属简洁顶栏（隐藏禁用态报告/复核包/镜像控件与空模块标签） */}
      {isStandaloneMcp && (
        <header className="td-header td-header--standalone-mcp">
          <button
            type="button"
            className="td-btn td-hdr-back-btn"
            title="返回 TraceDesk 欢迎首页"
            onClick={() => setActiveTab('files')}
          >
            <UiIcon name="arrow_left" size={14} color="var(--accent-soft-text)" />
            <span>返回首页</span>
          </button>

          <div className="td-header-divider" />

          <div className="td-header-brand">
            <BrandLogo size={26} className="td-header-logo td-header-logo--compact" />
            <span className="td-header-title">TraceDesk</span>
            <div className="td-header-divider" />
            <span className="td-header-page-title">MCP 实时监控</span>
            {!inTauri && (
              <span className="td-header-demo-tag" title="当前运行在纯浏览器环境，采用内置只读演示数据">
                演示预览
              </span>
            )}
          </div>

          <div className="td-header-spacer" />

          <div className="td-hdr-actions">
            {helpAction && (
              <button
                type="button"
                className="td-btn td-hdr-btn--ghost"
                title="查看 TraceDesk 操作说明与取证指南"
                onClick={() => invokeAction('help')}
              >
                <UiIcon name={helpAction.icon || 'help'} size={14} color="var(--header-muted)" />
                <span>{helpAction.title}</span>
              </button>
            )}

            {(newCaseAction || openCaseAction) && (
              <>
                {helpAction && <div className="td-header-divider td-header-divider--cmd" />}
                <div className="td-hdr-segmented" role="group" aria-label="案件管理">
                  {newCaseAction && (
                    <button
                      type="button"
                      data-action-key="new_case"
                      disabled={busy}
                      className="td-hdr-seg-btn"
                      title="新建隔离取证案件目录"
                      onClick={() => invokeAction('new_case')}
                    >
                      <UiIcon
                        name={newCaseAction.icon || 'case_new'}
                        size={14}
                        color={busy ? 'var(--text-disabled)' : 'var(--header-icon)'}
                      />
                      <span>{newCaseAction.title}</span>
                    </button>
                  )}
                  {openCaseAction && (
                    <button
                      type="button"
                      data-action-key="open_case"
                      disabled={busy}
                      className="td-hdr-seg-btn"
                      title="打开已有取证案件"
                      onClick={() => invokeAction('open_case')}
                    >
                      <UiIcon
                        name={openCaseAction.icon || 'case_open'}
                        size={14}
                        color={busy ? 'var(--text-disabled)' : 'var(--header-icon)'}
                      />
                      <span>{openCaseAction.title}</span>
                    </button>
                  )}
                </div>
              </>
            )}

            <button
              type="button"
              data-action-key="verify_bundle"
              className="td-btn td-hdr-btn td-hdr-btn--verify"
              title="离线核验复核包 ZIP 完整性、审计哈希链与逐成员防篡改摘要"
              onClick={() => setVerifyBundleOpen(true)}
            >
              <UiIcon name="check_shield" size={14} color="var(--accent-soft-text)" />
              <span>核验复核包</span>
            </button>
          </div>
        </header>
      )}

      {/* 已打开案件时渲染完整三段式工作台顶栏：命令带 + 保管状态条 + 模块导航标签带 */}
      {snapshot && (
        <>
          {/* 1. 顶部 48px 明净瓷白命令带 */}
          <header className="td-header">
            <div className="td-header-brand">
              <BrandLogo size={28} className="td-header-logo" />
              <span className="td-header-title">TraceDesk</span>
              <div className="td-header-divider" />
              <span className="td-header-subtitle">电子数据取证工作台</span>
              {!inTauri && (
                <span className="td-header-demo-tag" title="当前运行在纯浏览器环境，采用内置只读演示数据">
                  演示预览
                </span>
              )}
            </div>

            {brandActions.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 4 }}>
                {brandActions.map((act) => {
                  if (act.key === 'mcp') {
                    const isRunningNow = mcpRunningCalls > 0;
                    const stateClass = isRunningNow
                      ? 'td-hdr-mcp-btn--running'
                      : mcpHttpRunning
                        ? 'td-hdr-mcp-btn--online'
                        : 'td-hdr-btn--ghost';
                    const activeClass = activeTab === 'mcp' ? 'td-hdr-mcp-btn--active' : '';
                    return (
                      <button
                        key={act.key}
                        type="button"
                        className={`td-btn td-hdr-mcp-btn ${stateClass} ${activeClass}`}
                        title={
                          isRunningNow
                            ? `${mcpLiveLabel}（点击切换到 MCP 实时监控）`
                            : mcpHttpRunning
                              ? `本地 MCP HTTP 服务运行中：${mcpStatus?.url}（点击打开实时监控）`
                              : '切换到 MCP 实时监控与服务配置'
                        }
                        onClick={() => invokeAction(act.key)}
                      >
                        {isRunningNow ? (
                          <span className="td-mcp-dot td-mcp-dot--running" />
                        ) : mcpHttpRunning ? (
                          <span className="td-mcp-dot td-mcp-dot--online" />
                        ) : (
                          act.icon && <UiIcon name={act.icon} size={14} color="var(--header-muted)" />
                        )}
                        <span className="td-hdr-mcp-label">{mcpLiveLabel}</span>
                      </button>
                    );
                  }
                  return (
                    <button
                      key={act.key}
                      type="button"
                      className="td-btn td-hdr-btn--ghost"
                      onClick={() => invokeAction(act.key)}
                    >
                      {act.icon && <UiIcon name={act.icon} size={14} color="var(--header-muted)" />}
                      {act.title}
                    </button>
                  );
                })}
              </div>
            )}

            <div className="td-header-spacer" />

            <div className="td-hdr-actions">
              {/* 案件管理分段控件组：新建案件 / 打开案件 / 关闭 */}
              {(newCaseAction || openCaseAction || snapshot) && (
                <div className="td-hdr-segmented" role="group" aria-label="案件管理">
                  {newCaseAction && (
                    <button
                      type="button"
                      data-action-key="new_case"
                      disabled={busy}
                      className="td-hdr-seg-btn"
                      title="新建隔离取证案件目录"
                      onClick={() => invokeAction('new_case')}
                    >
                      <UiIcon
                        name={newCaseAction.icon || 'case_new'}
                        size={14}
                        color={busy ? 'var(--text-disabled)' : 'var(--header-icon)'}
                      />
                      <span>{newCaseAction.title}</span>
                    </button>
                  )}
                  {openCaseAction && (
                    <button
                      type="button"
                      data-action-key="open_case"
                      disabled={busy}
                      className="td-hdr-seg-btn"
                      title="打开已有取证案件"
                      onClick={() => invokeAction('open_case')}
                    >
                      <UiIcon
                        name={openCaseAction.icon || 'case_open'}
                        size={14}
                        color={busy ? 'var(--text-disabled)' : 'var(--header-icon)'}
                      />
                      <span>{openCaseAction.title}</span>
                    </button>
                  )}
                  <button
                    type="button"
                    data-action-key="close_case"
                    disabled={busy}
                    className="td-hdr-seg-btn td-hdr-seg-btn--danger"
                    title="关闭当前打开的案件并返回欢迎首页"
                    onClick={() => void handleCloseCase()}
                  >
                    <UiIcon name="x_circle" size={14} />
                    <span>关闭</span>
                  </button>
                </div>
              )}

              {/* 报告输出下拉菜单：合并 Markdown 与离线 HTML 两种报告格式 */}
              {reportAction && (
                <>
                  <div className="td-header-divider td-header-divider--cmd" />
                  <div className="td-hdr-dropdown" ref={reportMenuRef}>
                    <button
                      type="button"
                      data-action-key="report_menu"
                      disabled={busy}
                      aria-haspopup="menu"
                      aria-expanded={reportMenuOpen}
                      className={`td-btn td-hdr-btn td-hdr-dropdown-trigger ${reportMenuOpen ? 'td-hdr-dropdown-trigger--open' : ''}`}
                      title="选择导出 Markdown 或离线单文件 HTML 取证报告"
                      onClick={() => setReportMenuOpen((prev) => !prev)}
                    >
                      <UiIcon
                        name="report"
                        size={14}
                        color={busy ? 'var(--text-disabled)' : 'var(--header-icon)'}
                      />
                      <span>生成报告</span>
                      <UiIcon
                        name="chevron_down"
                        size={12}
                        className="td-hdr-dropdown-caret"
                        color={busy ? 'var(--text-disabled)' : 'var(--header-muted)'}
                      />
                    </button>

                    {reportMenuOpen && !busy && (
                      <div className="td-hdr-dropdown-menu" role="menu" aria-label="选择取证报告格式">
                        <button
                          type="button"
                          role="menuitem"
                          data-action-key="report"
                          className="td-hdr-dropdown-item"
                          onClick={() => {
                            setReportMenuOpen(false);
                            void handleGenerateReport();
                          }}
                        >
                          <span className="td-hdr-dropdown-icon">
                            <UiIcon name="report" size={15} color="var(--accent)" />
                          </span>
                          <span className="td-hdr-dropdown-body">
                            <span className="td-hdr-dropdown-title-row">
                              <span className="td-hdr-dropdown-title">Markdown 报告</span>
                              <span className="td-hdr-dropdown-ext td-mono">.md</span>
                            </span>
                            <span className="td-hdr-dropdown-desc">
                              结构化分节文本，便于归档与二次编辑
                            </span>
                          </span>
                        </button>

                        <button
                          type="button"
                          role="menuitem"
                          data-action-key="html_report"
                          className="td-hdr-dropdown-item"
                          onClick={() => {
                            setReportMenuOpen(false);
                            void handleGenerateHtmlReport();
                          }}
                        >
                          <span className="td-hdr-dropdown-icon">
                            <UiIcon name="html_report" size={15} color="var(--accent)" />
                          </span>
                          <span className="td-hdr-dropdown-body">
                            <span className="td-hdr-dropdown-title-row">
                              <span className="td-hdr-dropdown-title">离线 HTML 报告</span>
                              <span className="td-hdr-dropdown-ext td-mono">.html</span>
                            </span>
                            <span className="td-hdr-dropdown-desc">
                              单文件自包含排版，支持无网浏览器审阅打印
                            </span>
                          </span>
                        </button>
                      </div>
                    )}
                  </div>
                </>
              )}

              {/* 复核包操作组：晴空蓝主焦点「导出复核包」+ 浅蓝描边「核验复核包」 */}
              <div className="td-header-divider td-header-divider--cmd" />
              <div className="td-hdr-bundle-group">
                {exportBundleAction && (
                  <button
                    type="button"
                    data-action-key="export_bundle"
                    disabled={busy}
                    className="td-btn td-hdr-btn--primary"
                    title="打包案件报告、导出副本、搜索记录、审计链与 SHA256SUMS 复核包"
                    onClick={() => invokeAction('export_bundle')}
                  >
                    <UiIcon
                      name={exportBundleAction.icon || 'bundle'}
                      size={14}
                      color={busy ? 'var(--header-primary-disabled-fg)' : '#FFFFFF'}
                    />
                    <span>{exportBundleAction.title}</span>
                  </button>
                )}
                <button
                  type="button"
                  data-action-key="verify_bundle"
                  className="td-btn td-hdr-btn td-hdr-btn--verify"
                  title="离线核验复核包 ZIP 完整性、审计哈希链与逐成员防篡改摘要（未打开案件同样可用）"
                  onClick={() => setVerifyBundleOpen(true)}
                >
                  <UiIcon name="check_shield" size={14} color="var(--accent-soft-text)" />
                  <span>核验复核包</span>
                </button>
              </div>
            </div>
          </header>

          {/* 2. 案件与证据保管状态条（单行左右排布 + 3px 左侧语义指示边框） */}
          <section className="td-custody-bar" data-state={custodyState} aria-label="案件保管状态">
            <div className="td-custody-lines">
              <div className="td-custody-line td-custody-primary" title={snapshot.summaryLine1}>
                {snapshot.summaryLine1}
              </div>
              {snapshot.summaryLine2 && (
                <div className="td-custody-line td-custody-secondary" title={snapshot.summaryLine2}>
                  <span className="td-custody-dot" aria-hidden="true" />
                  <span className="td-custody-secondary-text">{snapshot.summaryLine2}</span>
                </div>
              )}
            </div>
          </section>

          {/* 3. 模块导航标签带（38px，薄雾浅蓝 #EFF4F9） */}
          <nav className="td-tab-strip" aria-label="功能模块导航">
            <div className="td-tab-list" role="tablist">
              {registry.panels.map((panel) => {
                const isActive = activeTab === panel.key;
                return (
                  <button
                    key={panel.key}
                    type="button"
                    role="tab"
                    aria-selected={isActive}
                    className={`td-module-tab ${isActive ? 'td-module-tab--active' : ''}`}
                    onClick={() => {
                      setActiveTab(panel.key);
                      if (panel.key === 'findings' || panel.key === 'audit') {
                        bumpRefresh();
                      }
                    }}
                  >
                    {panel.title}
                    {panel.key === 'review' && contentSearching && (
                      <span className="td-tab-badge" title="后台内容搜索正在运行">
                        <span className="td-mcp-dot td-mcp-dot--running" style={{ width: 6, height: 6 }} />
                        搜索中
                      </span>
                    )}
                    {panel.key === 'mcp' && mcpRunningCalls > 0 && (
                      <span className="td-tab-badge">
                        <span className="td-mcp-dot td-mcp-dot--running" style={{ width: 6, height: 6 }} />
                        {mcpRunningCalls}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            <div className="td-tab-actions">
              {evidenceActions.map((act) => {
                const isVerify = act.key === 'verify';
                const isLoad = act.key === 'load';
                const verifyWarning = isVerify && hashingImage;
                const disabled = isVerify
                  ? !hashingImage && (busy || !snapshot.evidence)
                  : busy;

                const btnClass = verifyWarning
                  ? 'td-btn td-btn--warning'
                  : isLoad
                    ? 'td-btn td-btn--accent'
                    : 'td-btn';

                const iconName = verifyWarning ? 'warning' : act.icon;
                const iconColor = verifyWarning
                  ? 'var(--warn-fg)'
                  : isLoad
                    ? disabled
                      ? 'var(--header-primary-disabled-fg)'
                      : '#FFFFFF'
                    : disabled
                      ? 'var(--text-disabled)'
                      : 'var(--text-secondary)';

                return (
                  <button
                    key={act.key}
                    type="button"
                    className={btnClass}
                    disabled={disabled}
                    onClick={() => invokeAction(act.key)}
                  >
                    {iconName && <UiIcon name={iconName} size={14} color={iconColor} />}
                    {verifyWarning ? '取消校验' : act.title}
                  </button>
                );
              })}
            </div>
          </nav>
        </>
      )}

      {/* 4. 纯白证据工作区 / 全屏欢迎首页 */}
      <main className="td-workspace">
        {/* 未开案时以全屏瓷白晴空蓝启动台铺满窗口（集成操作说明与 MCP 实时状态入口） */}
        {isWelcomeLaunchpad && (
          <div className="td-welcome-empty">
            <div className="td-welcome-canvas">
              {/* 顶部品牌头区与右上角轻量工具入口 */}
              <div className="td-welcome-masthead">
                <div className="td-welcome-masthead-top">
                  <div className="td-welcome-brand">
                    <div className="td-welcome-emblem">
                      <BrandLogo size={36} />
                    </div>
                    <div className="td-welcome-hero-text">
                      <div className="td-welcome-title-row">
                        <h1 className="td-welcome-title">TraceDesk 电子数据取证工作台</h1>
                        {!inTauri && (
                          <span
                            className="td-header-demo-tag"
                            title="当前运行在纯浏览器环境，采用内置只读演示数据"
                          >
                            演示预览
                          </span>
                        )}
                      </div>
                      <p className="td-welcome-subtitle">
                        面向本地证据镜像的无损只读勘验、流式内容检索与防篡改交付工作台
                      </p>
                    </div>
                  </div>

                  {/* 顶部精致集成工具角：操作说明 + MCP 实时监控 */}
                  {(helpAction || mcpAction) && (
                    <div className="td-welcome-utilities" role="toolbar" aria-label="工作台辅助功能">
                      {helpAction && (
                        <button
                          type="button"
                          className="td-welcome-tool-btn"
                          title="查看 TraceDesk 操作说明与标准取证流程"
                          onClick={() => invokeAction('help')}
                        >
                          <UiIcon name={helpAction.icon || 'help'} size={14} color="var(--header-icon)" />
                          <span>{helpAction.title}</span>
                        </button>
                      )}
                      {mcpAction && (() => {
                        const isRunningNow = mcpRunningCalls > 0;
                        const mcpStateClass = isRunningNow
                          ? 'td-welcome-mcp-btn--running'
                          : mcpHttpRunning
                            ? 'td-welcome-mcp-btn--online'
                            : '';
                        return (
                          <button
                            type="button"
                            className={`td-welcome-tool-btn td-welcome-mcp-btn ${mcpStateClass}`}
                            title={
                              isRunningNow
                                ? `${mcpLiveLabel}（点击进入 MCP 实时监控）`
                                : mcpHttpRunning
                                  ? `本地 MCP HTTP 服务运行中：${mcpStatus?.url}（点击进入实时监控）`
                                  : '打开 MCP 实时监控与服务接入配置'
                            }
                            onClick={() => invokeAction('mcp')}
                          >
                            {isRunningNow ? (
                              <span className="td-mcp-dot td-mcp-dot--running" />
                            ) : mcpHttpRunning ? (
                              <span className="td-mcp-dot td-mcp-dot--online" />
                            ) : (
                              <UiIcon name={mcpAction.icon || 'mcp'} size={14} color="var(--header-icon)" />
                            )}
                            <span className="td-welcome-mcp-label">{mcpLiveLabel}</span>
                          </button>
                        );
                      })()}
                    </div>
                  )}
                </div>

                {/* 核心特性微标签行 */}
                <div className="td-welcome-specs" aria-label="工作台核心能力">
                  {WORKBENCH_CAPABILITIES.map((cap) => (
                    <span key={cap} className="td-welcome-spec-chip">
                      {cap}
                    </span>
                  ))}
                </div>
              </div>

              {/* 三张高质感快捷操作瓷砖：新建案件 / 打开已有案件 / 离线核验复核包 */}
              <div className="td-welcome-tiles" role="group" aria-label="快速开始">
                <button
                  type="button"
                  className="td-welcome-tile td-welcome-tile--primary"
                  disabled={busy}
                  onClick={handleNewCase}
                >
                  <span className="td-welcome-tile-badge td-welcome-tile-badge--primary">
                    <UiIcon name="case_new" size={18} color="#FFFFFF" />
                  </span>
                  <span className="td-welcome-tile-body">
                    <span className="td-welcome-tile-title">新建案件</span>
                    <span className="td-welcome-tile-desc">创建隔离案件目录与审计链起点</span>
                  </span>
                  <UiIcon
                    name="arrow_right"
                    size={15}
                    className="td-welcome-tile-arrow"
                    color="var(--accent)"
                  />
                </button>

                <button
                  type="button"
                  className="td-welcome-tile"
                  disabled={busy}
                  onClick={handleOpenCase}
                >
                  <span className="td-welcome-tile-badge">
                    <UiIcon name="case_open" size={18} color="var(--accent)" />
                  </span>
                  <span className="td-welcome-tile-body">
                    <span className="td-welcome-tile-title">打开已有案件</span>
                    <span className="td-welcome-tile-desc">浏览本地 case.json 或恢复历史勘验</span>
                  </span>
                  <UiIcon
                    name="arrow_right"
                    size={15}
                    className="td-welcome-tile-arrow"
                    color="var(--text-muted)"
                  />
                </button>

                <button
                  type="button"
                  className="td-welcome-tile"
                  onClick={() => setVerifyBundleOpen(true)}
                >
                  <span className="td-welcome-tile-badge">
                    <UiIcon name="check_shield" size={18} color="var(--accent)" />
                  </span>
                  <span className="td-welcome-tile-body">
                    <span className="td-welcome-tile-title">离线核验复核包</span>
                    <span className="td-welcome-tile-desc">校验复核包 ZIP 完整性与审计链</span>
                  </span>
                  <UiIcon
                    name="arrow_right"
                    size={15}
                    className="td-welcome-tile-arrow"
                    color="var(--text-muted)"
                  />
                </button>
              </div>

              {/* 主体平衡双栏：左侧最近案件档案列表 + 右侧快捷拖放/点击打开区与标准取证闭环 */}
              <div className="td-welcome-split">
                <section className="td-welcome-panel td-welcome-recent-panel" aria-label="最近案件">
                  <div className="td-welcome-panel-head">
                    <div className="td-welcome-panel-title-group">
                      <h2 className="td-welcome-panel-title">最近案件</h2>
                      <span className="td-welcome-count-badge td-mono">{recentCases.length}</span>
                    </div>
                    <button
                      type="button"
                      className="td-btn td-btn--compact"
                      disabled={loadingRecentCases || busy}
                      onClick={() => void refreshRecentCases()}
                    >
                      <UiIcon name="refresh" size={12} color="var(--text-secondary)" />
                      {loadingRecentCases ? '正在刷新…' : '刷新列表'}
                    </button>
                  </div>

                  {recentCases.length > 0 ? (
                    <>
                      <div className="td-welcome-case-list">
                        {recentCases.map((item) => {
                          const formattedTime = formatCaseTimestamp(item.created);
                          const leafDir = extractPathLeafName(item.folder);
                          return (
                            <button
                              key={item.folder}
                              type="button"
                              className="td-welcome-case-card"
                              disabled={busy}
                              onClick={() => void openCaseByPath(item.folder)}
                              title={`点击打开案件：${item.folder}`}
                            >
                              <div className="td-welcome-case-top">
                                <span className="td-welcome-case-id td-mono">
                                  {item.number || item.name}
                                </span>
                                <span
                                  className={`td-recent-badge ${item.hasEvidence ? 'td-recent-badge--ready' : 'td-recent-badge--empty'}`}
                                >
                                  {item.hasEvidence
                                    ? `已载入镜像 · ${item.inventoryCount.toLocaleString()} 项`
                                    : '待载入镜像'}
                                </span>
                              </div>

                              <div className="td-welcome-case-meta">
                                <span className="td-welcome-meta-item">
                                  <span className="td-welcome-meta-key">对象</span>
                                  <span className="td-welcome-meta-val">{item.target || '—'}</span>
                                </span>
                                <span className="td-welcome-meta-sep" aria-hidden="true" />
                                <span className="td-welcome-meta-item">
                                  <span className="td-welcome-meta-key">取证人员</span>
                                  <span className="td-welcome-meta-val">{item.examiner || '—'}</span>
                                </span>
                                {item.exportsCount > 0 && (
                                  <>
                                    <span className="td-welcome-meta-sep" aria-hidden="true" />
                                    <span className="td-welcome-meta-item">
                                      <span className="td-welcome-meta-key">已导出</span>
                                      <span className="td-welcome-meta-val">{item.exportsCount} 份</span>
                                    </span>
                                  </>
                                )}
                              </div>

                              <div className="td-welcome-case-foot">
                                <span className="td-welcome-case-dir" title={item.folder}>
                                  <UiIcon name="case_open" size={12} color="var(--text-muted)" />
                                  <span className="td-mono">{leafDir}</span>
                                </span>
                                {formattedTime && (
                                  <span className="td-welcome-case-time" title={item.created}>
                                    <UiIcon name="clock" size={12} color="var(--text-muted)" />
                                    <span className="td-mono">{formattedTime}</span>
                                  </span>
                                )}
                              </div>
                            </button>
                          );
                        })}
                      </div>
                      <div className="td-welcome-panel-foot">
                        点击任意案件卡片即可恢复工作区；也可通过上方「打开已有案件」定位磁盘任意位置的 case.json。
                      </div>
                    </>
                  ) : (
                    <div className="td-welcome-case-empty">
                      <span className="td-welcome-empty-icon">
                        <UiIcon name="case_open" size={22} color="var(--accent)" />
                      </span>
                      <div className="td-welcome-empty-title">
                        {loadingRecentCases ? '正在扫描案件库目录…' : '案件库中尚无历史案件'}
                      </div>
                      <div className="td-welcome-empty-desc">
                        {loadingRecentCases
                          ? '请稍候，正在读取本地案件索引清单。'
                          : '点击上方「新建案件」开始首次勘验，或直接将本地 case.json 拖入窗口快速打开。'}
                      </div>
                    </div>
                  )}
                </section>

                <aside className="td-welcome-aside" aria-label="文件拖放与标准取证流程">
                  {/* 可点击与拖放双模式虚线引导区 */}
                  <button
                    type="button"
                    className="td-welcome-dropzone"
                    disabled={busy}
                    title="点击选择本地 case.json 打开案件，或直接拖入窗口"
                    onClick={handleOpenCase}
                  >
                    <div className="td-welcome-dropzone-head">
                      <span className="td-welcome-dropzone-icon">
                        <UiIcon name="import_disk" size={17} color="var(--accent)" />
                      </span>
                      <div className="td-welcome-dropzone-copy">
                        <div className="td-welcome-dropzone-title-row">
                          <span className="td-welcome-dropzone-title">拖入文件快速打开</span>
                          <span className="td-welcome-dropzone-hint">点击选择</span>
                        </div>
                        <div className="td-welcome-dropzone-desc">
                          {inTauri
                            ? '将 case.json 拖入窗口或点击此处打开案件；开案后拖入镜像文件自动识别分区。'
                            : '点击此处打开演示案件；桌面端支持将 case.json 或磁盘镜像直接拖入窗口。'}
                        </div>
                      </div>
                    </div>
                    <div className="td-welcome-format-pills">
                      <span className="td-welcome-fmt-pill td-welcome-fmt-pill--case td-mono">
                        case.json
                      </span>
                      <span className="td-welcome-fmt-pill td-mono">.e01</span>
                      <span className="td-welcome-fmt-pill td-mono">.dd</span>
                      <span className="td-welcome-fmt-pill td-mono">.raw</span>
                      <span className="td-welcome-fmt-pill td-mono">.img</span>
                    </div>
                  </button>

                  {/* 四步标准取证闭环速览 */}
                  <div className="td-welcome-panel td-welcome-workflow">
                    <div className="td-welcome-panel-head td-welcome-panel-head--compact">
                      <h2 className="td-welcome-panel-title">标准取证闭环</h2>
                      <span className="td-welcome-tz-badge td-mono">UTC+8</span>
                    </div>
                    <ol className="td-welcome-steps">
                      {WORKFLOW_STEPS.map((item) => (
                        <li key={item.step} className="td-welcome-step">
                          <span className="td-welcome-step-num td-mono" aria-hidden="true">
                            {item.step}
                          </span>
                          <div className="td-welcome-step-body">
                            <div className="td-welcome-step-title">{item.title}</div>
                            <div className="td-welcome-step-desc">{item.desc}</div>
                          </div>
                        </li>
                      ))}
                    </ol>
                  </div>
                </aside>
              </div>
            </div>
          </div>
        )}

        {/* 文件浏览与内容搜索保持挂载，避免切换标签时丢失文件树或后台流式搜索结果 */}
        <div
          style={{
            display: snapshot && activeTab === 'files' ? 'flex' : 'none',
            flex: 1,
            minHeight: 0,
            flexDirection: 'column',
          }}
        >
          <FileBrowserModule
            snapshot={snapshot}
            registry={registry}
            busy={busy}
            scanningPartitions={scanningPartitions}
            selectedEntry={selectedEntry}
            locateTarget={locateTarget}
            onSelectEntry={setSelectedEntry}
            onDetailChange={setDetailText}
            onScanPartitions={handleScanPartitionsClick}
            onScanPartition={handleScanPartitionClick}
            onCancelScan={handleCancelScanClick}
            onBrowseDirectory={handleBrowseDirectory}
            onExportEntry={handleExportEntryClick}
            onRecordNote={handleRecordNoteClick}
            onHashEntry={handleHashEntryClick}
            onCompareEntry={handleCompareEntryClick}
            onSearchInFile={handleSearchInFile}
          />
        </div>

        {snapshot && activeTab === 'info' && (
          <EvidenceInfoModule
            snapshot={snapshot}
            busy={busy}
            onRegisterSource={handleOpenRegisterSource}
            onExportFsstat={handleExportFsstatClick}
            onScanPartition={handleScanPartitionClick}
          />
        )}

        {snapshot && activeTab === 'findings' && (
          <FindingsModule
            snapshot={snapshot}
            busy={busy}
            refreshToken={refreshToken}
            onExportFindings={handleExportFindingsClick}
            onLocateEntry={handleLocateEntry}
          />
        )}

        {registry.hasFeature('timeline') && (
          <div
            style={{
              display: snapshot && activeTab === 'timeview' ? 'flex' : 'none',
              flex: 1,
              minHeight: 0,
              flexDirection: 'column',
            }}
          >
            <TimelineModule snapshot={snapshot} busy={busy} onLocateEntry={handleLocateEntry} />
          </div>
        )}

        {snapshot && activeTab === 'audit' && (
          <AuditLogModule snapshot={snapshot} refreshToken={refreshToken} />
        )}

        {registry.hasFeature('review') && (
          <div
            style={{
              display: snapshot && activeTab === 'review' ? 'flex' : 'none',
              flex: 1,
              minHeight: 0,
              flexDirection: 'column',
            }}
          >
            <ContentReviewModule
              snapshot={snapshot}
              selectedBrowserEntry={selectedEntry}
              singleFileRequestToken={singleFileSearchToken}
              busy={busy}
              onSearchingChange={setContentSearchingState}
              onSearchLiveStateChange={handleSearchLiveStateChange}
              onSnapshotUpdated={applySnapshot}
              onLocateEntry={handleLocateEntry}
              onAlert={showAlert}
            />
          </div>
        )}

        {registry.hasFeature('mcp') && (
          <div
            style={{
              display: activeTab === 'mcp' ? 'flex' : 'none',
              flex: 1,
              minHeight: 0,
              flexDirection: 'column',
            }}
          >
            <McpMonitorModule
              isActive={activeTab === 'mcp'}
              snapshot={snapshot}
              mcpStatus={mcpStatus}
              activities={mcpActivities}
              stats={mcpStats}
              onStatusChange={setMcpStatus}
              onRefreshAll={refreshMcpTelemetry}
              onClearActivities={handleClearMcpActivities}
              onJumpToAudit={handleJumpToAudit}
              onRefreshCurrentCase={handleRefreshCurrentCaseManual}
            />
          </div>
        )}
      </main>

      {/* 5. 底部只读状态与进度遥测栏（28px） */}
      <footer className="td-footer">
        <span className="td-footer-detail" title={footerDetailText}>
          {footerDetailText}
        </span>
        {mcpRunningCalls > 0 && (
          <button
            type="button"
            className="td-footer-mcp-pill"
            title={`${mcpLiveLabel}（点击查看实时操作流）`}
            onClick={() => setActiveTab('mcp')}
          >
            <span className="td-mcp-dot td-mcp-dot--running" style={{ width: 7, height: 7 }} />
            <span className="td-footer-mcp-pill-text">{mcpLiveLabel}</span>
          </button>
        )}
        <div className="td-footer-divider" />
        <span
          className={`td-footer-status ${!busy && !hashingImage && contentSearching ? 'td-footer-status--clickable' : ''}`}
          title={
            !busy && !hashingImage && contentSearching
              ? '点击切换到「内容搜索与复核」页查看实时命中'
              : footerStatusText
          }
          onClick={() => {
            if (!busy && !hashingImage && contentSearching) {
              setActiveTab('review');
            }
          }}
        >
          {footerStatusText}
        </span>
        {showProgressBar && (
          <div className="td-footer-progress-group">
            <div className="td-progress-track" aria-label="任务进度">
              <div
                className={`td-progress-fill ${effectiveProgressPercent === null ? 'td-progress-fill--indeterminate' : ''}`}
                style={
                  effectiveProgressPercent !== null
                    ? { width: `${effectiveProgressPercent}%` }
                    : undefined
                }
              />
            </div>
            <button
              type="button"
              className="td-footer-cancel-btn"
              disabled={cancellingActiveTask}
              title="取消当前正在执行的任务"
              onClick={() => void handleCancelActiveTask()}
            >
              {cancellingActiveTask ? '取消中…' : '取消'}
            </button>
          </div>
        )}
      </footer>

      {/* 原生文件拖放柔和提示遮罩 */}
      {dragOverActive && (
        <div className="td-drop-overlay" aria-live="polite">
          <div className="td-drop-card">
            <UiIcon name="import_disk" size={34} color="var(--accent)" />
            <div className="td-drop-title">松开鼠标以导入文件</div>
            <div className="td-drop-desc">
              {snapshot
                ? '拖入 case.json 可切换案件；拖入 .dd / .raw / .img / .e01 可为当前案件加载证据镜像。'
                : '拖入案件目录中的 case.json 即可直接打开已有案件。'}
            </div>
          </div>
        </div>
      )}

      {/* ---------- 公共业务弹窗 ---------- */}
      {newCaseOpen && (
        <NewCaseDialog
          defaultCasesDir={appPaths.casesDir || 'C:\\TraceDesk\\cases'}
          onCreated={(snap) => void handleCaseReplaced(snap)}
          onClose={() => setNewCaseOpen(false)}
        />
      )}

      {openCaseOpen && (
        <OpenCaseDialog
          defaultCasesDir={appPaths.casesDir || 'C:\\TraceDesk\\cases'}
          initialRecentCases={recentCases}
          onOpened={(snap) => void handleCaseReplaced(snap)}
          onClose={() => setOpenCaseOpen(false)}
        />
      )}

      {registerSourceOpen && (
        <RegisterSourceDialog
          initialProvenance={snapshot?.evidence?.provenance}
          onSaved={(snap) => {
            applySnapshot(snap);
            setStatusText('已更新证据来源与交付方摘要');
          }}
          onClose={() => setRegisterSourceOpen(false)}
        />
      )}

      {noteTarget && (
        <FindingNoteDialog
          entry={noteTarget.entry}
          initialNote={noteTarget.initialNote}
          onSaved={(snap) => {
            applySnapshot(snap);
            setStatusText('已记录取证发现并写入审计链');
          }}
          onClose={() => setNoteTarget(null)}
        />
      )}

      {examineResult && (
        <ExamineResultDialog data={examineResult} onClose={() => setExamineResult(null)} />
      )}

      {exportResult && (
        <ExportResultDialog
          title={exportResult.title}
          path={exportResult.path}
          note={exportResult.note}
          sha256={exportResult.sha256}
          bytes={exportResult.bytes}
          generatedAt={exportResult.generatedAt}
          entry={exportResult.entry}
          noteIcon={fileNoteAction?.icon ?? 'note'}
          onRecordNote={
            hasFileNoteFeature && exportResult.entry
              ? (entry) => {
                  // 关闭导出成功弹窗并立即打开该文件的取证发现笔记弹窗
                  setExportResult(null);
                  setNoteTarget({ entry });
                }
              : undefined
          }
          onClose={() => setExportResult(null)}
        />
      )}

      {verifyBundleOpen && (
        <VerifyBundleDialog
          defaultDir={snapshot ? `${snapshot.caseDir}\\reports` : appPaths.casesDir || undefined}
          onClose={() => setVerifyBundleOpen(false)}
        />
      )}

      {bundleMaterials && (
        <BundleExportDialog
          materials={bundleMaterials}
          onConfirm={(exportIds, searchIds) => void runBuildBundle(exportIds, searchIds)}
          onClose={() => setBundleMaterials(null)}
        />
      )}

      {helpOpen && (
        <Suspense fallback={null}>
          <HelpGuideDialog onClose={() => setHelpOpen(false)} />
        </Suspense>
      )}

      {busyDialogReason && (
        <BusyTaskDialog
          reason={busyDialogReason}
          taskNames={activeTaskNames}
          stageText={busyDialogStageText}
          progressPercent={effectiveProgressPercent}
          onCancelTasks={() => void handleCancelActiveTask()}
          cancelling={cancellingActiveTask}
          onClose={() => setBusyDialogReason(null)}
        />
      )}

      {alertState && (
        <AlertDialog
          title={alertState.title}
          message={alertState.message}
          tone={alertState.tone}
          onClose={() => setAlertState(null)}
        />
      )}
    </div>
  );
};

export default App;
