/**
 * 实时任务进度提示弹窗：
 * 当用户在前台或后台任务执行期间触发冲突操作时展示，明确列出当前正在执行的任务名称、
 * 实时阶段说明与进度条；所有关联任务结束后自动切换为“当前任务已完成”并短暂延迟后自动关闭。
 */
import React, { useEffect } from 'react';
import { UiIcon } from '../Icons';
import { Modal } from './Modal';

export interface BusyTaskDialogProps {
  /** 触发该提示时的中文说明 */
  reason: string;
  /** 当前正在执行的任务名称列表（空数组表示已全部完成） */
  taskNames: string[];
  /** 当前实时阶段或速率说明 */
  stageText: string;
  /** 确定进度百分比（0~100）；为 null 时展示不确定流动进度条 */
  progressPercent: number | null;
  /** 关闭弹窗回调 */
  onClose: () => void;
}

export const BusyTaskDialog: React.FC<BusyTaskDialogProps> = ({
  reason,
  taskNames,
  stageText,
  progressPercent,
  onClose,
}) => {
  const finished = taskNames.length === 0;

  // 所有任务完成后短暂展示“已完成”反馈并自动关闭弹窗，减少手动点击确认的负担
  useEffect(() => {
    if (!finished) return;
    const timer = window.setTimeout(() => {
      onClose();
    }, 900);
    return () => window.clearTimeout(timer);
  }, [finished, onClose]);

  const pct =
    progressPercent !== null ? Math.max(0, Math.min(100, Math.round(progressPercent))) : null;

  return (
    <Modal
      title={finished ? '任务已完成' : '正在处理'}
      width={500}
      onClose={onClose}
      footer={
        <>
          <div className="td-modal-footer-spacer" />
          <button type="button" className="td-btn td-btn--accent" onClick={onClose} autoFocus>
            {finished ? '关闭' : '我知道了'}
          </button>
        </>
      }
    >
      <div className="td-busy-dialog-body">
        <UiIcon
          name={finished ? 'check_shield' : 'help'}
          size={32}
          color={finished ? 'var(--ok-fg)' : 'var(--accent)'}
          fill={finished ? 'var(--ok-bg)' : 'var(--accent-soft-bg)'}
        />
        <div className="td-busy-dialog-content">
          {finished ? (
            <div className="td-busy-dialog-task td-busy-dialog-task--done">
              当前任务已完成，可以继续后续操作。
            </div>
          ) : (
            <>
              <div className="td-busy-dialog-task">
                <span className="td-busy-dialog-task-label">当前任务：</span>
                <span className="td-busy-dialog-task-name">{taskNames.join('、')}</span>
              </div>
              <div className="td-busy-dialog-reason">{reason}</div>
            </>
          )}

          <div className="td-busy-progress-block">
            <div className="td-busy-progress-header">
              <span className="td-busy-progress-stage">
                {finished ? '全部后台任务已结束' : stageText || `${taskNames[0]}…`}
              </span>
              <span className="td-busy-progress-pct td-mono">
                {finished ? '100%' : pct !== null ? `${pct}%` : '处理中…'}
              </span>
            </div>
            <div className="td-busy-progress-track" aria-label="当前任务进度">
              <div
                className={
                  finished
                    ? 'td-busy-progress-fill td-busy-progress-fill--done'
                    : pct === null
                      ? 'td-progress-fill td-progress-fill--indeterminate'
                      : 'td-progress-fill'
                }
                style={
                  finished
                    ? { width: '100%' }
                    : pct !== null
                      ? { width: `${pct}%` }
                      : undefined
                }
              />
            </div>
          </div>
        </div>
      </div>
    </Modal>
  );
};
