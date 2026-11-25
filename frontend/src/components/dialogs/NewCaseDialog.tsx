/**
 * 新建取证案件弹窗（含目录选择器与案件文件夹名称编辑，对齐 NewCaseDialog + choose_case_directory）
 */
import React, { useEffect, useState } from 'react';
import { tauriApi } from '../../api/tauri';
import type { CaseSnapshot } from '../../types/ipc';
import { formatError } from '../../utils/assets';
import { Modal } from './Modal';

interface NewCaseDialogProps {
  defaultCasesDir: string;
  onCreated: (snapshot: CaseSnapshot) => void;
  onClose: () => void;
}

export const NewCaseDialog: React.FC<NewCaseDialogProps> = ({
  defaultCasesDir,
  onCreated,
  onClose,
}) => {
  const [number, setNumber] = useState('');
  const [examiner, setExaminer] = useState('');
  const [target, setTarget] = useState('');
  const [parentDir, setParentDir] = useState(defaultCasesDir);
  const [parentDirTouched, setParentDirTouched] = useState(false);
  const [folderName, setFolderName] = useState('');
  const [folderCustomized, setFolderCustomized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 若打开弹窗时应用默认路径尚未异步返回，待其到达且用户尚未手动修改时自动同步
  useEffect(() => {
    if (!parentDirTouched && defaultCasesDir) {
      setParentDir(defaultCasesDir);
    }
  }, [defaultCasesDir, parentDirTouched]);

  useEffect(() => {
    if (!number.trim() && !examiner.trim() && !target.trim()) {
      if (!folderCustomized) setFolderName('');
      return;
    }
    if (folderCustomized) return;
    let active = true;
    const timer = window.setTimeout(() => {
      tauriApi
        .suggestCaseDir({
          number: number.trim() || 'CASE',
          examiner: examiner.trim() || 'examiner',
          target: target.trim() || 'evidence',
          parentDir: parentDir.trim() || undefined,
        })
        .then((res) => {
          if (active) setFolderName(res.folderName);
        })
        .catch(() => {
          // 静默降级
        });
    }, 120);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [number, examiner, target, parentDir, folderCustomized]);

  const handleBrowseParent = async () => {
    const picked = await tauriApi.pickDirectory({
      title: '选择案件上级目录',
      defaultPath: parentDir || defaultCasesDir,
    });
    if (picked) {
      setParentDirTouched(true);
      setParentDir(picked);
    }
  };

  const fullPathPreview = parentDir.trim()
    ? `${parentDir.trim().replace(/[\\/]+$/, '')}\\${folderName.trim()}`
    : folderName.trim();

  const handleSubmit = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setError(null);
    if (!number.trim() || !examiner.trim() || !target.trim()) {
      setError('请填写案件编号、取证人员与取证对象。');
      return;
    }
    if (!parentDir.trim()) {
      setError('请指定案件上级目录。');
      return;
    }
    setSubmitting(true);
    try {
      const snapshot = await tauriApi.createCase({
        parentDir: parentDir.trim(),
        number: number.trim(),
        examiner: examiner.trim(),
        target: target.trim(),
        folderName: folderName.trim() || undefined,
      });
      onCreated(snapshot);
      onClose();
    } catch (err) {
      setError(`创建失败：${formatError(err)}`);
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
      title="新建取证案件"
      subtitle="源镜像须存放于案件库目录之外"
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
            form="td-new-case-form"
            className="td-btn td-btn--accent"
            disabled={submitting}
          >
            {submitting ? '正在创建…' : '创建案件'}
          </button>
        </>
      }
    >
      <form
        id="td-new-case-form"
        onSubmit={handleSubmit}
        style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
      >
        <div>
          <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>填写案件信息</div>
          <div className="td-muted-text" style={{ fontSize: 12, marginTop: 3 }}>
            支持选择上级目录并直接修改案件文件夹名称；自动创建审计链起点与隔离目录。
          </div>
        </div>

        <div className="td-form-grid">
          <label className="td-form-label" htmlFor="td-newcase-number">
            案件编号
          </label>
          <input
            id="td-newcase-number"
            className="td-input"
            placeholder="例如：CASE-2026-001"
            value={number}
            onChange={(e) => setNumber(e.target.value)}
            autoFocus
          />

          <label className="td-form-label" htmlFor="td-newcase-examiner">
            取证人员
          </label>
          <input
            id="td-newcase-examiner"
            className="td-input"
            placeholder="取证人员姓名"
            value={examiner}
            onChange={(e) => setExaminer(e.target.value)}
          />

          <label className="td-form-label" htmlFor="td-newcase-target">
            取证对象
          </label>
          <input
            id="td-newcase-target"
            className="td-input"
            placeholder="检材或设备说明"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />

          <label className="td-form-label" htmlFor="td-newcase-parent">
            上级目录
          </label>
          <div style={{ display: 'flex', gap: 6 }}>
            <input
              id="td-newcase-parent"
              className="td-input td-mono"
              style={{ flex: 1, fontSize: 12 }}
              value={parentDir}
              onChange={(e) => {
                setParentDirTouched(true);
                setParentDir(e.target.value);
              }}
            />
            <button type="button" className="td-btn td-btn--soft" onClick={() => void handleBrowseParent()}>
              选择目录…
            </button>
          </div>

          <label className="td-form-label" htmlFor="td-newcase-folder">
            案件文件夹名
          </label>
          <input
            id="td-newcase-folder"
            className="td-input td-mono"
            style={{ fontSize: 12 }}
            placeholder="自动按编号_人员_对象生成，可手动修改"
            value={folderName}
            onChange={(e) => {
              setFolderCustomized(true);
              setFolderName(e.target.value);
            }}
          />
        </div>

        <div
          style={{
            background: 'var(--surface-subtle)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 5,
            padding: '8px 10px',
            fontSize: 11.5,
          }}
        >
          <div className="td-muted-text" style={{ marginBottom: 3 }}>
            案件目录地址预览
          </div>
          <div className="td-mono" style={{ wordBreak: 'break-all', color: 'var(--text-secondary)' }}>
            {fullPathPreview || '（填写信息后生成）'}
          </div>
        </div>

        {error && <div className="td-banner td-banner--error">{error}</div>}
      </form>
    </Modal>
  );
};
