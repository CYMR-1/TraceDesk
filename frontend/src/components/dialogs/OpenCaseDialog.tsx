/**
 * 打开已有案件弹窗：
 * - 顶部展示案件库中的最近案件卡片（点击卡片即可一键打开）
 * - 下方保留“浏览本地 case.json…”、“选目录”与手动路径输入，兼容任意磁盘位置案件
 */
import React, { useEffect, useState } from 'react';
import { tauriApi } from '../../api/tauri';
import type { CaseSnapshot, RecentCaseDto } from '../../types/ipc';
import { formatError } from '../../utils/assets';
import { UiIcon } from '../Icons';
import { Modal } from './Modal';

interface OpenCaseDialogProps {
  defaultCasesDir: string;
  /** 可选预加载的最近案件列表，打开弹窗时仍会自动刷新确保最新 */
  initialRecentCases?: RecentCaseDto[];
  onOpened: (snapshot: CaseSnapshot) => void;
  onClose: () => void;
}

export const OpenCaseDialog: React.FC<OpenCaseDialogProps> = ({
  defaultCasesDir,
  initialRecentCases,
  onOpened,
  onClose,
}) => {
  const [casePath, setCasePath] = useState(defaultCasesDir);
  const [pathTouched, setPathTouched] = useState(false);
  const [recentCases, setRecentCases] = useState<RecentCaseDto[]>(initialRecentCases ?? []);
  const [loadingRecent, setLoadingRecent] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [openingPath, setOpeningPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // 若默认目录稍后异步返回且用户尚未编辑，自动同步默认路径
  useEffect(() => {
    if (!pathTouched && defaultCasesDir) {
      setCasePath(defaultCasesDir);
    }
  }, [defaultCasesDir, pathTouched]);

  // 打开弹窗时拉取最新最近案件列表
  useEffect(() => {
    let mounted = true;
    setLoadingRecent(true);
    void tauriApi
      .listRecentCases()
      .then((list) => {
        if (!mounted) return;
        setRecentCases(list);
      })
      .catch(() => {
        // 忽略列表读取失败，用户仍可浏览本地 case.json
      })
      .finally(() => {
        if (mounted) setLoadingRecent(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const openTargetPath = async (targetPath: string) => {
    const trimmed = targetPath.trim();
    if (!trimmed) {
      setError('请选择或输入案件目录或 case.json 路径。');
      return;
    }
    setSubmitting(true);
    setOpeningPath(trimmed);
    setError(null);
    try {
      const snapshot = await tauriApi.openCase({ casePath: trimmed });
      onOpened(snapshot);
      onClose();
    } catch (err) {
      setError(`打开案件失败：${formatError(err)}`);
    } finally {
      setSubmitting(false);
      setOpeningPath(null);
    }
  };

  const handleBrowseFile = async () => {
    const picked = await tauriApi.pickFile({
      title: '打开案件 case.json',
      defaultPath: defaultCasesDir || undefined,
      filters: [{ name: '案件元数据 (case.json)', extensions: ['json'] }],
    });
    if (picked) {
      setPathTouched(true);
      setCasePath(picked);
      await openTargetPath(picked);
    }
  };

  const handleBrowseFolder = async () => {
    const picked = await tauriApi.pickDirectory({
      title: '选择案件目录',
      defaultPath: defaultCasesDir || undefined,
    });
    if (picked) {
      setPathTouched(true);
      setCasePath(picked);
    }
  };

  const handleOpen = async (e?: React.FormEvent) => {
    e?.preventDefault();
    await openTargetPath(casePath);
  };

  const handleSafeClose = () => {
    if (!submitting) {
      onClose();
    }
  };

  return (
    <Modal
      title="打开已有案件"
      width={620}
      onClose={handleSafeClose}
      footer={
        <>
          <button
            type="button"
            className="td-btn td-btn--soft"
            disabled={submitting}
            onClick={() => void handleBrowseFile()}
          >
            <UiIcon name="case_open" size={14} color="var(--accent-soft-text)" />
            浏览本地 case.json…
          </button>
          <div className="td-modal-footer-spacer" />
          <button type="button" className="td-btn" disabled={submitting} onClick={handleSafeClose}>
            取消
          </button>
          <button
            type="submit"
            form="td-open-case-form"
            className="td-btn td-btn--accent"
            disabled={submitting}
          >
            {submitting ? '正在读取清单…' : '打开案件'}
          </button>
        </>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {/* 最近案件卡片区 */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="td-section-title" style={{ fontSize: 12.5 }}>
              最近案件（点击直接打开）
            </span>
            {loadingRecent && (
              <span className="td-muted-text" style={{ fontSize: 11.5 }}>
                正在扫描案件库…
              </span>
            )}
          </div>
          {recentCases.length > 0 ? (
            <div className="td-recent-list td-recent-list--dialog">
              {recentCases.map((item) => {
                const isOpening = submitting && openingPath === item.folder;
                return (
                  <button
                    key={item.folder}
                    type="button"
                    className="td-recent-card"
                    disabled={submitting}
                    onClick={() => void openTargetPath(item.folder)}
                    title={`点击打开案件：${item.folder}`}
                  >
                    <div className="td-recent-card-head">
                      <span className="td-recent-card-number td-mono">{item.number || item.name}</span>
                      <span
                        className={`td-recent-badge ${item.hasEvidence ? 'td-recent-badge--ready' : 'td-recent-badge--empty'}`}
                      >
                        {isOpening
                          ? '正在打开…'
                          : item.hasEvidence
                            ? `已载入镜像 · ${item.inventoryCount.toLocaleString()} 项`
                            : '待载入镜像'}
                      </span>
                    </div>
                    <div className="td-recent-card-meta">
                      <span>对象：{item.target || '—'}</span>
                      <span>·</span>
                      <span>人员：{item.examiner || '—'}</span>
                      {item.created && (
                        <>
                          <span>·</span>
                          <span className="td-mono">{item.created}</span>
                        </>
                      )}
                    </div>
                    <div className="td-recent-card-path td-mono">{item.folder}</div>
                  </button>
                );
              })}
            </div>
          ) : (
            !loadingRecent && (
              <div className="td-recent-empty">
                当前案件库暂无已有案件，可点击左下角「浏览本地 case.json…」打开其他位置的案件。
              </div>
            )
          )}
        </div>

        {/* 手动路径 / 目录选择区 */}
        <form
          id="td-open-case-form"
          onSubmit={handleOpen}
          style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
        >
          <div className="td-muted-text" style={{ fontSize: 12 }}>
            或手动指定案件目录及 <span className="td-mono">case.json</span> 路径：
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <input
              className="td-input td-mono"
              style={{ flex: 1, fontSize: 12 }}
              placeholder="例如：C:\TraceDesk\cases\DEMO-01\case.json"
              value={casePath}
              disabled={submitting}
              onChange={(e) => {
                setPathTouched(true);
                setCasePath(e.target.value);
              }}
            />
            <button
              type="button"
              className="td-btn"
              disabled={submitting}
              onClick={() => void handleBrowseFolder()}
            >
              选目录
            </button>
          </div>
          {error && <div className="td-banner td-banner--error">{error}</div>}
        </form>
      </div>
    </Modal>
  );
};
