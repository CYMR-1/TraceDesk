/**
 * 轻量桌面消息提示弹窗（替代原生 alert）
 */
import React from 'react';
import { UiIcon } from '../Icons';
import { Modal } from './Modal';

export interface AlertDialogState {
  title: string;
  message: string;
  tone?: 'info' | 'ok' | 'warning' | 'error';
}

export const AlertDialog: React.FC<AlertDialogState & { onClose: () => void }> = ({
  title,
  message,
  tone = 'info',
  onClose,
}) => {
  const iconName = tone === 'ok' ? 'check_shield' : tone === 'warning' || tone === 'error' ? 'warning' : 'help';
  const color =
    tone === 'ok'
      ? 'var(--ok-fg)'
      : tone === 'error'
        ? 'var(--danger-fg)'
        : tone === 'warning'
          ? 'var(--warn-fg)'
          : 'var(--accent)';
  const fill =
    tone === 'ok'
      ? 'var(--ok-bg)'
      : tone === 'error'
        ? 'var(--danger-bg)'
        : tone === 'warning'
          ? 'var(--warn-bg)'
          : 'var(--accent-soft-bg)';

  return (
    <Modal
      title={title}
      width={480}
      onClose={onClose}
      footer={
        <>
          <div className="td-modal-footer-spacer" />
          <button type="button" className="td-btn td-btn--accent" onClick={onClose} autoFocus>
            确定
          </button>
        </>
      }
    >
      <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
        <UiIcon name={iconName} size={32} color={color} fill={fill} />
        <div
          style={{
            flex: 1,
            minWidth: 0,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            userSelect: 'text',
            lineHeight: 1.55,
          }}
        >
          {message}
        </div>
      </div>
    </Modal>
  );
};
