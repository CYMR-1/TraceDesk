/**
 * 文件哈希计算 / 副本一致性比对结果弹窗
 */
import React, { useEffect, useRef, useState } from 'react';
import type { ExamineFileResponse } from '../../types/ipc';
import { copyToClipboard, formatBytes } from '../../utils/assets';
import { UiIcon } from '../Icons';
import { SemanticPill } from '../SemanticPill';
import { Modal } from './Modal';

interface ExamineResultDialogProps {
  data: ExamineFileResponse;
  onClose: () => void;
}

export const ExamineResultDialog: React.FC<ExamineResultDialogProps> = ({ data, onClose }) => {
  const [copied, setCopied] = useState(false);
  const copyTimerRef = useRef<number | null>(null);

  // 组件卸载时清理未触发的复制反馈定时器
  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  const handleCopyHash = async () => {
    const ok = await copyToClipboard(data.sha256);
    if (ok) {
      setCopied(true);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopied(false);
        copyTimerRef.current = null;
      }, 2000);
    }
  };

  return (
    <Modal
      title={data.title}
      width={620}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="td-btn td-btn--soft" onClick={() => void handleCopyHash()}>
            <UiIcon name="copy" size={14} color="var(--accent-soft-text)" />
            {copied ? '已复制镜像文件 SHA-256' : '复制镜像文件 SHA-256'}
          </button>
          <div className="td-modal-footer-spacer" />
          <button type="button" className="td-btn td-btn--accent" onClick={onClose} autoFocus>
            确定
          </button>
        </>
      }
    >
      <div className="td-dossier" style={{ padding: 0, overflow: 'visible' }}>
        <table>
          <tbody>
            <tr>
              <td className="td-dossier-key">镜像内路径</td>
              <td className="td-dossier-val td-dossier-mono">{data.path}</td>
            </tr>
            <tr>
              <td className="td-dossier-key">核验结论</td>
              <td className="td-dossier-val">
                <SemanticPill text={data.result} />
              </td>
            </tr>
            <tr>
              <td className="td-dossier-key">读取字节数</td>
              <td className="td-dossier-val td-dossier-mono">
                {formatBytes(data.size)} / {formatBytes(data.recordedSize)} 字节
              </td>
            </tr>
            <tr>
              <td className="td-dossier-key">镜像内文件 SHA-256</td>
              <td className="td-dossier-val td-dossier-mono">{data.sha256}</td>
            </tr>
            {data.comparisonPath && (
              <>
                <tr>
                  <td className="td-dossier-key">对照本地副本</td>
                  <td className="td-dossier-val td-dossier-mono">{data.comparisonPath}</td>
                </tr>
                <tr>
                  <td className="td-dossier-key">本地文件 SHA-256</td>
                  <td className="td-dossier-val td-dossier-mono">{data.comparisonSha256 || '—'}</td>
                </tr>
              </>
            )}
            {data.readNote && (
              <tr>
                <td className="td-dossier-key">读取说明</td>
                <td className="td-dossier-val">{data.readNote}</td>
              </tr>
            )}
            {data.sourceNote && (
              <tr>
                <td className="td-dossier-key">来源状态</td>
                <td className="td-dossier-val">{data.sourceNote}</td>
              </tr>
            )}
            {data.sourceVerification && (
              <tr>
                <td className="td-dossier-key">完整性状态</td>
                <td className="td-dossier-val">{data.sourceVerification}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Modal>
  );
};
