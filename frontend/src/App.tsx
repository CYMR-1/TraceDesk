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
import { createFeatureRegistry, ENABLED_FEATURES, type PanelKey } from './features/registry';
import { AuditLogModule } from './modules/AuditLogModule';
import { ContentReviewModule } from './modules/ContentReviewModule';
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
  McpActivityRecord,
  McpStatus,
} from './types/ipc';
import { formatError } from './utils/assets';
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
const DELIVERABLE_KEYS = new Set(['report', 'export_bundle']);
const RAW_IMAGE_EXTENSIONS = ['dd', 'raw', 'img', 'ima', 'bin', 'dsk', 'image', 'flp', 'vfd', 'E01', 'e01'];

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
  const [helpOpen, setHelpOpen] = useState(false);
  const [noteTarget, setNoteTarget] = useState<EntryView | null>(null);
  const [examineResult, setExamineResult] = useState<ExamineFileResponse | null>(null);
  const [exportResult, setExportResult] = useState<ExportResultInfo | null>(null);
  const [bundleMaterials, setBundleMaterials] = useState<BundleMaterialsResponse | null>(null);
  const [busyDialogReason, setBusyDialogReason] = useState<string | null>(null);
  const [alertState, setAlertState] = useState<AlertDialogState | null>(null);

  const busyRef = useRef(false);
  const hashingImageRef = useRef(false);
  const contentSearchingRef = useRef(false);
  const backgroundBusyRef = useRef(false);
  const inspectingBundleRef = useRef(false);
  const clearPendingProgressRef = useRef<() => void>(() => {});
  const snapshotRef = useRef<CaseSnapshot | null>(null);
  const mcpStatusRef = useRef<McpStatus | null>(null);
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

  // 启动时读取路径、当前案件快照与 MCP 实时状态
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
  }, [setSnapshotState]);

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
          const pct = ev.total > 0 ? Math.min(100, Math.floor((100 * ev.done) / ev.total)) : 0;
          scheduleProgressUpdate(
            pct,
            `后台读取整镜像 · ${pct}% · ${Math.round(ev.rateMiBs)} MiB/s`
          );
        })
      ),
      registerSafe(
        tauriEvents.onHashFinished((ev) => {
          if (!mounted) return;
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
      setDetailText(DEFAULT_DETAIL);
      setStatusText(DEFAULT_STATUS);
      applySnapshot(next);
      if (next) {
        await resumePartitions(next);
      }
    },
    [applySnapshot, resumePartitions]
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

  const handleOpenCase = async () => {
    if (backgroundBusyRef.current) {
      openBusyDialog('切换案件前请先取消后台校验或内容搜索，或等待完成。');
      return;
    }
    if (busyRef.current) {
      openBusyDialog('请等待当前任务完成后再打开案件。');
      return;
    }
    if (inTauri) {
      const picked = await tauriApi.pickFile({
        title: '打开案件 case.json',
        defaultPath: appPaths.casesDir || undefined,
        filters: [{ name: '案件元数据 (case.json)', extensions: ['json'] }],
      });
      if (!picked) return;
      // 先完成打开案件并释放并发锁，再由链式逻辑自动恢复分区浏览或扫描
      const snap = await runTask('打开案件并读取清单', () => tauriApi.openCase({ casePath: picked }), {
        requiresCase: false,
        blocksBackground: true,
      });
      if (snap) {
        await handleCaseReplaced(snap);
      }
    } else {
      setOpenCaseOpen(true);
    }
  };

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
    // 先完成镜像识别并同步释放并发锁，再在顶层链式调用分区自动扫描/根目录读取
    const snap = await runTask(
      '打开镜像并识别分区',
      () => tauriApi.loadImage({ imagePath: imagePath! }),
      { requiresCase: true, blocksBackground: true }
    );
    if (snap) {
      setSelectedEntry(null);
      applySnapshot(snap);
      await resumePartitions(snap);
    }
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
      setHashingImageState(true);
      setStatusText('后台读取整镜像 · 可继续浏览');
      setTaskStageText('后台读取整镜像 · 可继续浏览');
      try {
        await tauriApi.verifyIntegrity();
      } catch (err) {
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

  const handleCancelScan = useCallback(async () => {
    try {
      await tauriApi.cancelScanPartitions();
      setStatusText('正在取消建立索引…');
    } catch {
      // 忽略
    }
  }, []);

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
          setExportResult({
            title: res.title || '导出成功',
            path: res.path,
            note: res.note,
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
          title: '报告已生成',
          path: res.path,
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

  const handleCancelScanClick = useCallback(() => {
    void handleCancelScan();
  }, [handleCancelScan]);

  const handleExportEntryClick = useCallback(
    (entry: EntryView) => {
      void handleExportEntry(entry);
    },
    [handleExportEntry]
  );

  const handleRecordNoteClick = useCallback((entry: EntryView) => {
    setNoteTarget(entry);
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
  const headerActions = registry.actionsAt('header');
  const evidenceActions = registry.actionsAt('evidence');

  const custodyState = snapshot?.custodyState ?? 'idle';
  const showProgressBar = busy || hashingImage;

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
    if (contentSearching) return '正在流式检索镜像文件内容…';
    return statusText;
  }, [taskStageText, hashingImage, contentSearching, statusText]);

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

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {headerActions.map((act, idx) => {
            const isDeliverable = DELIVERABLE_KEYS.has(act.key);
            const prevIsDeliverable = idx > 0 && DELIVERABLE_KEYS.has(headerActions[idx - 1].key);
            const needDivider = idx > 0 && isDeliverable && !prevIsDeliverable;
            const isPrimary = act.key === 'export_bundle';
            const disabled = busy || (isDeliverable && !snapshot);

            return (
              <React.Fragment key={act.key}>
                {needDivider && <div className="td-header-divider" />}
                <button
                  type="button"
                  data-action-key={act.key}
                  disabled={disabled}
                  className={`td-btn ${isPrimary ? 'td-hdr-btn--primary' : 'td-hdr-btn'}`}
                  onClick={() => invokeAction(act.key)}
                >
                  {act.icon && (
                    <UiIcon
                      name={act.icon}
                      size={14}
                      color={
                        isPrimary
                          ? disabled
                            ? 'var(--header-primary-disabled-fg)'
                            : '#FFFFFF'
                          : disabled
                            ? 'var(--text-disabled)'
                            : 'var(--header-icon)'
                      }
                    />
                  )}
                  {act.title}
                </button>
              </React.Fragment>
            );
          })}
        </div>
      </header>

      {/* 2. 案件与证据保管状态条（3px 左侧语义指示边框） */}
      <section className="td-custody-bar" data-state={custodyState} aria-label="案件保管状态">
        <div className="td-custody-lines">
          {snapshot ? (
            <>
              <div className="td-custody-line">{snapshot.summaryLine1}</div>
              {snapshot.summaryLine2 && <div className="td-custody-line">{snapshot.summaryLine2}</div>}
            </>
          ) : (
            <div className="td-custody-line">
              尚未打开案件。新建案件并加载镜像，或打开已有案件继续分析。
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
              ? !hashingImage && (busy || !snapshot?.evidence)
              : busy || !snapshot;

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

      {/* 4. 纯白证据工作区 */}
      <main className="td-workspace">
        {/* 文件浏览与内容搜索保持挂载，避免切换标签时丢失文件树或后台流式搜索结果 */}
        <div
          style={{
            display: activeTab === 'files' ? 'flex' : 'none',
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
            onSelectEntry={setSelectedEntry}
            onDetailChange={setDetailText}
            onScanPartitions={handleScanPartitionsClick}
            onCancelScan={handleCancelScanClick}
            onBrowseDirectory={handleBrowseDirectory}
            onExportEntry={handleExportEntryClick}
            onRecordNote={handleRecordNoteClick}
            onHashEntry={handleHashEntryClick}
            onCompareEntry={handleCompareEntryClick}
            onSearchInFile={handleSearchInFile}
          />
        </div>

        {activeTab === 'info' && (
          <EvidenceInfoModule
            snapshot={snapshot}
            busy={busy}
            onRegisterSource={handleOpenRegisterSource}
            onExportFsstat={handleExportFsstatClick}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsModule
            snapshot={snapshot}
            busy={busy}
            refreshToken={refreshToken}
            onExportFindings={handleExportFindingsClick}
          />
        )}

        {registry.hasFeature('timeline') && (
          <div
            style={{
              display: activeTab === 'timeview' ? 'flex' : 'none',
              flex: 1,
              minHeight: 0,
              flexDirection: 'column',
            }}
          >
            <TimelineModule snapshot={snapshot} busy={busy} />
          </div>
        )}

        {activeTab === 'audit' && <AuditLogModule snapshot={snapshot} refreshToken={refreshToken} />}

        {registry.hasFeature('review') && (
          <div
            style={{
              display: activeTab === 'review' ? 'flex' : 'none',
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
              onSnapshotUpdated={applySnapshot}
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
        <span className="td-footer-detail" title={detailText}>
          {detailText}
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
        <span className="td-footer-status">{statusText}</span>
        {showProgressBar && (
          <div className="td-progress-track" aria-label="任务进度">
            <div
              className={`td-progress-fill ${progressPercent === null ? 'td-progress-fill--indeterminate' : ''}`}
              style={progressPercent !== null ? { width: `${progressPercent}%` } : undefined}
            />
          </div>
        )}
      </footer>

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
          entry={noteTarget}
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
          onClose={() => setExportResult(null)}
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
          progressPercent={progressPercent}
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
