/**
 * 登记证据来源弹窗（5 项字段 + 64 位 SHA-256 校验，对齐 edit_evidence_source）
 */
import React, { useState } from 'react';
import { tauriApi } from '../../api/tauri';
import { SOURCE_FIELD_LABELS } from '../../features/registry';
import type { CaseSnapshot, ProvenanceInfo } from '../../types/ipc';
import { formatError, isValidSha256Hex } from '../../utils/assets';
import { Modal } from './Modal';

interface RegisterSourceDialogProps {
  initialProvenance?: ProvenanceInfo | null;
  onSaved: (snapshot: CaseSnapshot) => void;
  onClose: () => void;
}

export const RegisterSourceDialog: React.FC<RegisterSourceDialogProps> = ({
  initialProvenance,
  onSaved,
  onClose,
}) => {
  const [values, setValues] = useState({
    evidenceId: initialProvenance?.evidenceId ?? initialProvenance?.evidence_id ?? '',
    source: initialProvenance?.source ?? '',
    acquired: initialProvenance?.acquired ?? '',
    tool: initialProvenance?.tool ?? '',
    expectedSha256: initialProvenance?.expectedSha256 ?? initialProvenance?.expected_sha256 ?? '',
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const expectedTrimmed = values.expectedSha256.trim();
  const shaInvalid = expectedTrimmed.length > 0 && !isValidSha256Hex(expectedTrimmed);

  const handleSave = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (shaInvalid) {
      setError('交付方 SHA-256 必须为 64 位十六进制字符（留空表示不提供）。');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const snapshot = await tauriApi.registerSource({
        evidenceId: values.evidenceId.trim(),
        source: values.source.trim(),
        acquired: values.acquired.trim(),
        tool: values.tool.trim(),
        expectedSha256: expectedTrimmed,
      });
      onSaved(snapshot);
      onClose();
    } catch (err) {
      setError(`保存失败：${formatError(err)}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      title="登记证据来源"
      width={600}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="td-btn" disabled={submitting} onClick={onClose}>
            取消
          </button>
          <div className="td-modal-footer-spacer" />
          <button
            type="button"
            className="td-btn td-btn--accent"
            disabled={submitting || shaInvalid}
            onClick={() => void handleSave()}
          >
            {submitting ? '正在保存…' : '保存'}
          </button>
        </>
      }
    >
      <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="td-form-grid">
          {SOURCE_FIELD_LABELS.map((field, idx) => (
            <React.Fragment key={field.key}>
              <label className="td-form-label" htmlFor={`td-src-${field.key}`}>
                {field.label}
              </label>
              <input
                id={`td-src-${field.key}`}
                className={`td-input ${field.mono ? 'td-mono' : ''}`}
                style={field.mono ? { fontSize: 11.5 } : undefined}
                placeholder={field.placeholder}
                value={values[field.key]}
                onChange={(e) =>
                  setValues((prev) => ({
                    ...prev,
                    [field.key]: e.target.value,
                  }))
                }
                autoFocus={idx === 0}
              />
            </React.Fragment>
          ))}
        </div>

        {shaInvalid && (
          <div className="td-banner td-banner--warning">
            当前交付方 SHA-256 长度为 {expectedTrimmed.length} 位；标准 SHA-256 应为 64 位十六进制字符。
          </div>
        )}
        {error && <div className="td-banner td-banner--error">{error}</div>}
      </form>
    </Modal>
  );
};
