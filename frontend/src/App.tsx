/**
 * TraceDesk 桌面端主工作台骨架 (5 层纵向架构 + 11 个可装配功能模块)
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { isTauriRuntime, tauriApi, tauriEvents } from './api/tauri';
import { BrandLogo, UiIcon } from './components/Icons';
import { AlertDialog, type AlertDialogState } from './components/dialogs/AlertDialog';
import { BundleExportDialog } from './components/dialogs/BundleExportDialog';
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
import { HelpGuideDialog } from './modules/HelpGuideDialog';
import { McpDialog } from './modules/McpDialog';
import { TimelineModule } from './modules/TimelineModule';
import type {
  AppPaths,
  BundleMaterialsResponse,
  CaseSnapshot,
  EntryView,
  ExamineFileResponse,
} from './types/ipc';
import { formatError } from './utils/assets';

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
  const [progressPercent, setProgressPercent] = useState<number | null>(null);
  const [scanningPartitions, setScanningPartitions] = useState(false);
  const [hashingImage, setHashingImage] = useState(false);
  const [contentSearching, setContentSearching] = useState(false);
  const [refreshToken, setRefreshToken] = useState(0);
  const [singleFileSearchToken, setSingleFileSearchToken] = useState(0);

  // 弹窗状态
  const [newCaseOpen, setNewCaseOpen] = useState(false);
  const [openCaseOpen, setOpenCaseOpen] = useState(false);
  const [registerSourceOpen, setRegisterSourceOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [mcpOpen, setMcpOpen] = useState(false);
  const [noteTarget, setNoteTarget] = useState<EntryView | null>(null);
  const [examineResult, setExamineResult] = useState<ExamineFileResponse | null>(null);
  const [exportResult, setExportResult] = useState<ExportResultInfo | null>(null);
  const [bundleMaterials, setBundleMaterials] = useState<BundleMaterialsResponse | null>(null);
  const [alertState, setAlertState] = useState<AlertDialogState | null>(null);

  const busyRef = useRef(false);
  const backgroundBusyRef = useRef(false);
  busyRef.current = busy;
  backgroundBusyRef.current = hashingImage || contentSearching;

  const showAlert = useCallback(
    (title: string, message: string, tone: AlertDialogState['tone'] = 'info') => {
      setAlertState({ title, message, tone });
    },
    []
  );

  const bumpRefresh = useCallback(() => {
    setRefreshToken((n) => n + 1);
  }, []);

  const applySnapshot = useCallback((next: CaseSnapshot | null) => {
    setSnapshot(next);
    setRefreshToken((n) => n + 1);
  }, []);

  // 启动时读取路径和当前案件快照
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
          setSnapshot(snap);
        }
      } catch {
        // 忽略初始化读取失败
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  // 订阅后台任务与大镜像哈希进度事件
  useEffect(() => {
    let mounted = true;
    const unlisteners: (() => void)[] = [];

    void (async () => {
      const u1 = await tauriEvents.onTaskProgress((ev) => {
        if (!mounted) return;
        if (ev.total > 0) {
          const pct = Math.min(100, Math.floor((100 * ev.done) / ev.total));
          setProgressPercent(pct);
          setStatusText(`${ev.stage} · ${pct}%`);
        } else {
          setProgressPercent(null);
          setStatusText(`${ev.stage}…`);
        }
      });

      const u2 = await tauriEvents.onHashProgress((ev) => {
        if (!mounted) return;
        const pct = ev.total > 0 ? Math.min(100, Math.floor((100 * ev.done) / ev.total)) : 0;
        setProgressPercent(pct);
        setStatusText(`后台读取整镜像 · ${pct}% · ${Math.round(ev.rateMiBs)} MiB/s`);
      });

      const u3 = await tauriEvents.onHashFinished((ev) => {
        if (!mounted) return;
        setHashingImage(false);
        setProgressPercent(null);
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
      });

      unlisteners.push(u1, u2, u3);
    })();

    return () => {
      mounted = false;
      for (const u of unlisteners) u();
    };
  }, [applySnapshot, showAlert]);

  // 主窗口关闭守卫（仅 Tauri 桌面端）
  useEffect(() => {
    if (!inTauri) return;
    let unlisten: (() => void) | undefined;
    void (async () => {
      try {
        const { getCurrentWindow } = await import('@tauri-apps/api/window');
        unlisten = await getCurrentWindow().onCloseRequested(async (event) => {
          if (busyRef.current || backgroundBusyRef.current) {
            event.preventDefault();
            showAlert('正在处理', '存在正在运行的后台任务或内容搜索，请先取消或等待完成后再关闭窗口。', 'warning');
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
      } catch {
        // 忽略非窗口环境
      }
    })();
    return () => {
      unlisten?.();
    };
  }, [inTauri, showAlert]);

  // 统一任务执行包装
  const runTask = useCallback(
    async <T,>(
      label: string,
      work: () => Promise<T>,
      options?: { requiresCase?: boolean; onSuccess?: (val: T) => void | Promise<void> }
    ): Promise<T | null> => {
      const requiresCase = options?.requiresCase ?? true;
      if (!requiresCase && backgroundBusyRef.current) {
        showAlert('正在处理', '切换案件前请先取消后台校验或内容搜索，或等待完成。', 'info');
        return null;
      }
      if (busyRef.current) {
        showAlert('正在处理', '请等待当前任务完成。', 'info');
        return null;
      }
      if (requiresCase && !snapshot) {
        showAlert('提示', '请先新建或打开案件。', 'info');
        return null;
      }

      setBusy(true);
      setProgressPercent(null);
      setStatusText(`${label}…`);
      try {
        const result = await work();
        setStatusText(DEFAULT_STATUS);
        setBusy(false);
        setProgressPercent(null);
        await options?.onSuccess?.(result);
        return result;
      } catch (err) {
        setBusy(false);
        setProgressPercent(null);
        setStatusText(`${label}失败`);
        showAlert(`${label}失败`, formatError(err), 'error');
        return null;
      }
    },
    [snapshot, showAlert]
  );

  // 加载镜像或打开案件后，按镜像大小自动扫描分区或浏览首个可读根目录
  const resumePartitions = useCallback(
    async (snap: CaseSnapshot) => {
      const ev = snap.evidence;
      if (!ev) return;
      const isLarge = Boolean(ev.largeImage ?? ev.large_image);
      if (isLarge && snap.browsingDirectories) {
        await runTask(
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
          {
            requiresCase: false,
            onSuccess: (res) => {
              applySnapshot(res.snapshot);
            },
          }
        );
      } else if (!isLarge && snap.needsPartitionScan) {
        setScanningPartitions(true);
        await runTask('读取所有分区与文件树', () => tauriApi.scanAllPartitions(), {
          requiresCase: false,
          onSuccess: (res) => {
            if (res.completed) {
              applySnapshot(res.snapshot);
            } else {
              setDetailText('已取消建立索引，保留原有浏览结果。');
            }
          },
        });
        setScanningPartitions(false);
      }
    },
    [runTask, applySnapshot]
  );

  const handleCaseReplaced = useCallback(
    (next: CaseSnapshot | null) => {
      setSelectedEntry(null);
      setDetailText(DEFAULT_DETAIL);
      setStatusText(DEFAULT_STATUS);
      applySnapshot(next);
      if (next) {
        void resumePartitions(next);
      }
    },
    [applySnapshot, resumePartitions]
  );

  // 案件与镜像动作
  const handleNewCase = () => {
    if (backgroundBusyRef.current) {
      showAlert('正在处理', '切换案件前请先取消后台校验或内容搜索，或等待完成。', 'info');
      return;
    }
    if (busy) {
      showAlert('正在处理', '请等待当前任务完成。', 'info');
      return;
    }
    setNewCaseOpen(true);
  };

  const handleOpenCase = async () => {
    if (backgroundBusyRef.current) {
      showAlert('正在处理', '切换案件前请先取消后台校验或内容搜索，或等待完成。', 'info');
      return;
    }
    if (busy) {
      showAlert('正在处理', '请等待当前任务完成。', 'info');
      return;
    }
    if (inTauri) {
      const picked = await tauriApi.pickFile({
        title: '打开案件 case.json',
        defaultPath: appPaths.casesDir || undefined,
        filters: [{ name: '案件元数据 (case.json)', extensions: ['json'] }],
      });
      if (!picked) return;
      await runTask('打开案件并读取清单', () => tauriApi.openCase({ casePath: picked }), {
        requiresCase: false,
        onSuccess: (snap) => handleCaseReplaced(snap),
      });
    } else {
      setOpenCaseOpen(true);
    }
  };

  const handleLoadImage = async () => {
    if (!snapshot) {
      showAlert('提示', '请先新建或打开案件。', 'info');
      return;
    }
    if (busy) {
      showAlert('正在处理', '请等待当前任务完成。', 'info');
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
    await runTask('打开镜像并识别分区', () => tauriApi.loadImage({ imagePath: imagePath! }), {
      onSuccess: async (snap) => {
        setSelectedEntry(null);
        applySnapshot(snap);
        await resumePartitions(snap);
      },
    });
  };

  const handleVerifyIntegrity = async () => {
    if (hashingImage) {
      try {
        await tauriApi.cancelVerifyIntegrity();
        setStatusText('正在取消校验…');
      } catch {
        // 忽略
      }
      return;
    }
    if (!snapshot) {
      showAlert('提示', '请先新建或打开案件。', 'info');
      return;
    }
    if (!snapshot.evidence) {
      showAlert('提示', '请先加载镜像。', 'info');
      return;
    }
    const isLarge = Boolean(snapshot.evidence.largeImage ?? snapshot.evidence.large_image);
    if (isLarge) {
      setHashingImage(true);
      setStatusText('后台读取整镜像 · 可继续浏览');
      try {
        await tauriApi.verifyIntegrity();
      } catch (err) {
        setHashingImage(false);
        setProgressPercent(null);
        setStatusText('校验失败');
        showAlert('校验失败', formatError(err), 'error');
      }
      return;
    }
    await runTask('流式校验 SHA-256', () => tauriApi.verifyIntegrity(), {
      onSuccess: (res) => {
        applySnapshot(res.snapshot);
        showAlert(
          '完整性校验',
          res.ok ? '通过：与初始固定值一致。' : '失败：原始镜像已发生变化！',
          res.ok ? 'ok' : 'error'
        );
      },
    });
  };

  const handleScanAllPartitions = async () => {
    if (!snapshot?.evidence) return;
    setScanningPartitions(true);
    await runTask('读取所有分区与文件树', () => tauriApi.scanAllPartitions(), {
      onSuccess: (res) => {
        if (res.completed) {
          applySnapshot(res.snapshot);
        } else {
          setDetailText('已取消建立索引，保留原有浏览结果。');
        }
      },
    });
    setScanningPartitions(false);
  };

  const handleCancelScan = async () => {
    try {
      await tauriApi.cancelScanPartitions();
      setStatusText('正在取消建立索引…');
    } catch {
      // 忽略
    }
  };

  const handleBrowseDirectory = async (
    offset: number,
    inode: string | null,
    path: string
  ): Promise<EntryView[] | null> => {
    const res = await runTask(`读取目录 /${path}`, () =>
      tauriApi.browseDirectory({ offset, inode, path })
    );
    if (res) {
      setSelectedEntry(null);
      applySnapshot(res.snapshot);
      return res.entries;
    }
    return null;
  };

  const handleExportEntry = async (entry: EntryView) => {
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
  };

  const handleHashEntry = async (entry: EntryView) => {
    await runTask('计算文件 SHA-256', () => tauriApi.examineFile({ entryId: entry.entryId }), {
      onSuccess: (res) => {
        applySnapshot(res.snapshot);
        setExamineResult(res);
      },
    });
  };

  const handleCompareEntry = async (entry: EntryView) => {
    let comparisonPath: string | null = null;
    if (inTauri) {
      comparisonPath = await tauriApi.pickFile({
        title: '选择与镜像内文件比较的本地副本',
        defaultPath: snapshot ? `${snapshot.caseDir}\\exports` : undefined,
      });
      if (!comparisonPath) return;
    } else {
      comparisonPath = `${snapshot?.caseDir ?? 'C:\\TraceDesk\\cases\\DEMO-01'}\\exports\\${entry.name}`;
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
  };

  const handleSearchInFile = (entry: EntryView) => {
    setSelectedEntry(entry);
    setActiveTab('review');
    setSingleFileSearchToken((n) => n + 1);
  };

  const handleExportFsstat = async (offset: number) => {
    await runTask('读取完整文件系统详情', () => tauriApi.exportFsstat({ offset }), {
      onSuccess: (res) => {
        setExportResult({
          title: '文件系统详情已导出',
          path: res.path,
        });
      },
    });
  };

  const handleExportFindings = async (groupKeys: string[]) => {
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
  };

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
    if (!snapshot) {
      showAlert('提示', '请先新建或打开案件。', 'info');
      return;
    }
    if (!snapshot.evidence) {
      showAlert('提示', '请先加载镜像。', 'info');
      return;
    }
    if (busy) {
      showAlert('正在处理', '请等待当前任务完成。', 'info');
      return;
    }
    try {
      const mat = await tauriApi.inspectBundleMaterials();
      if (mat.exports.length > 0 || mat.searches.length > 0) {
        setBundleMaterials(mat);
      } else {
        await runBuildBundle();
      }
    } catch (err) {
      showAlert('检查复核包材料失败', formatError(err), 'error');
    }
  };

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
        setMcpOpen(true);
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
            {brandActions.map((act) => (
              <button
                key={act.key}
                type="button"
                className="td-btn td-hdr-btn--ghost"
                onClick={() => invokeAction(act.key)}
              >
                {act.icon && <UiIcon name={act.icon} size={14} color="var(--header-muted)" />}
                {act.title}
              </button>
            ))}
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
            onScanPartitions={() => void handleScanAllPartitions()}
            onCancelScan={() => void handleCancelScan()}
            onBrowseDirectory={handleBrowseDirectory}
            onExportEntry={(entry) => void handleExportEntry(entry)}
            onRecordNote={(entry) => setNoteTarget(entry)}
            onHashEntry={(entry) => void handleHashEntry(entry)}
            onCompareEntry={(entry) => void handleCompareEntry(entry)}
            onSearchInFile={handleSearchInFile}
          />
        </div>

        {activeTab === 'info' && (
          <EvidenceInfoModule
            snapshot={snapshot}
            busy={busy}
            onRegisterSource={() => setRegisterSourceOpen(true)}
            onExportFsstat={(offset) => void handleExportFsstat(offset)}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsModule
            snapshot={snapshot}
            busy={busy}
            refreshToken={refreshToken}
            onExportFindings={(groupKeys) => void handleExportFindings(groupKeys)}
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
              onSearchingChange={setContentSearching}
              onSnapshotUpdated={applySnapshot}
              onAlert={showAlert}
            />
          </div>
        )}
      </main>

      {/* 5. 底部只读状态与进度遥测栏（28px） */}
      <footer className="td-footer">
        <span className="td-footer-detail" title={detailText}>
          {detailText}
        </span>
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
          onCreated={(snap) => handleCaseReplaced(snap)}
          onClose={() => setNewCaseOpen(false)}
        />
      )}

      {openCaseOpen && (
        <OpenCaseDialog
          defaultCasesDir={appPaths.casesDir || 'C:\\TraceDesk\\cases'}
          onOpened={(snap) => handleCaseReplaced(snap)}
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

      {mcpOpen && (
        <McpDialog
          activeCaseNumber={snapshot?.number ?? null}
          onCaseReleased={() => handleCaseReplaced(null)}
          onClose={() => setMcpOpen(false)}
        />
      )}

      {helpOpen && <HelpGuideDialog onClose={() => setHelpOpen(false)} />}

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
