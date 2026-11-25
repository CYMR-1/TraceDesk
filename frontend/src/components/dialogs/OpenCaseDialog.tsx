/**
 * 打开已有案件弹窗（支持原生选择 case.json 或输入案件目录路径）
 */
import React, { useEffect, useState } from 'react';
import { tauriApi } from '../../api/tauri';
import type { CaseSnapshot } from '../../types/ipc';
import { formatError } from '../../utils/assets';
import { Modal } from './Modal';

interface OpenCaseDialogProps {
  defaultCasesDir: string;
  onOpened: (snapshot: CaseSnapshot) => void;
  onClose: () => void;
}

export const OpenCaseDialog: React.FC<OpenCaseDialogProps> = ({
  defaultCasesDir,
  onOpened,
  onClose,
}) => {
  const [casePath, setCasePath] = useState(defaultCasesDir);
  const [pathTouched, setPathTouched] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 若默认目录稍后异步返回且用户尚未编辑，自动同步默认路径
  useEffect(() => {
    if (!pathTouched && defaultCasesDir) {
      setCasePath(defaultCasesDir);
    }
  }, [defaultCasesDir, pathTouched]);

  const handleBrowseFile = async () => {
    const picked = await tauriApi.pickFile({
      title: '打开案件 case.json',
      defaultPath: defaultCasesDir,
      filters: [{ name: '案件元数据 (case.json)', extensions: ['json'] }],
    });
    if (picked) {
      setPathTouched(true);
      setCasePath(picked);
    }
  };

  const handleBrowseFolder = async () => {
    const picked = await tauriApi.pickDirectory({
      title: '选择案件目录',
      defaultPath: defaultCasesDir,
    });
    if (picked) {
      setPathTouched(true);
      setCasePath(picked);
    }
  };

  const handleOpen = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!casePath.trim()) {
      setError('请选择或输入案件目录或 case.json 路径。');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const snapshot = await tauriApi.openCase({ casePath: casePath.trim() });
      onOpened(snapshot);
      onClose();
    } catch (err) {
      setError(`打开案件失败：${formatError(err)}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleSafeClose = () => {
    if (!submitting) {
      onClose();
    }
  };

  return (
    <Modal
      title="打开已有案件"
      width={560}
      onClose={handleSafeClose}
      footer={
        <>
          <button type="button" className="td-btn" disabled={submitting} onClick={handleSafeClose}>
            取消
          </button>
          <div className="td-modal-footer-spacer" />
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
      <form
        id="td-open-case-form"
        onSubmit={handleOpen}
        style={{ display: 'flex', flexDirection: 'column', gap: 12 }}
      >
        <div className="td-muted-text" style={{ fontSize: 12 }}>
          选择已有案件目录中的 <span className="td-mono">case.json</span>，或直接指定案件目录路径。
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <input
            className="td-input td-mono"
            style={{ flex: 1, fontSize: 12 }}
            placeholder="例如：C:\TraceDesk\cases\DEMO-01\case.json"
            value={casePath}
            onChange={(e) => {
              setPathTouched(true);
              setCasePath(e.target.value);
            }}
            autoFocus
          />
          <button type="button" className="td-btn td-btn--soft" onClick={() => void handleBrowseFile()}>
            选 case.json
          </button>
          <button type="button" className="td-btn" onClick={() => void handleBrowseFolder()}>
            选目录
          </button>
        </div>
        {error && <div className="td-banner td-banner--error">{error}</div>}
      </form>
    </Modal>
  );
};
