/**
 * 一键复核包完整性核验与篡改检出可视化弹窗 (VerifyBundleDialog)
 * - 支持独立于当前打开案件直接运行（未打开案件时同样可用）
 * - 支持选择本地 .zip 复核包或手动粘贴路径，并可选输入 64 位期望 SHA-256（留空时自动尝试读取同目录 .zip.sha256）
 * - 可视化展示：总体通过/篡改横幅、3 张核心证据卡、跨文件审计链交叉核对清单、逐成员哈希核对表（含“仅看异常成员”开关与摘要逐行对比）
 */
import React, { useMemo, useState } from 'react';
import { isTauriRuntime, tauriApi } from '../../api/tauri';
import type { ReviewBundleMemberVerifyDto, VerifyReviewBundleResponse } from '../../types/ipc';
import { copyToClipboard, formatBytes, formatError, isValidSha256Hex } from '../../utils/assets';
import { UiIcon } from '../Icons';
import { SemanticPill, type PillVariant } from '../SemanticPill';
import { Modal } from './Modal';

interface VerifyBundleDialogProps {
  /** 默认打开文件选择器时的初始路径（可选） */
  defaultDir?: string;
  onClose: () => void;
}

/** 判断逐成员或交叉核对状态是否属于通过态 */
function isPassStatus(status: string): boolean {
  const s = (status || '').trim().toLowerCase();
  return s === 'ok' || s === 'pass' || s === 'passed' || s === 'matched' || s === '通过' || s === '一致' || s === '正常';
}

/** 将后端状态码映射为中文展示标签与语义胶囊色 */
function formatVerifyStatus(status: string): { label: string; variant: PillVariant } {
  const raw = (status || '').trim();
  const s = raw.toLowerCase();
  if (isPassStatus(raw)) {
    return { label: '一致', variant: 'ok' };
  }
  if (s === 'tampered' || s === 'mismatch' || s === 'modified' || s === 'corrupted') {
    return { label: '检出篡改', variant: 'danger' };
  }
  if (s === 'missing' || s === 'not_found') {
    return { label: '成员缺失', variant: 'danger' };
  }
  if (s === 'failed' || s === 'error' || s === 'invalid') {
    return { label: '核验失败', variant: 'danger' };
  }
  if (s === 'extra' || s === 'unexpected' || s === 'unlisted') {
    return { label: '清单外成员', variant: 'warn' };
  }
  if (s === 'skipped' || s === 'warn' || s === 'warning') {
    return { label: s === 'skipped' ? '已跳过' : '注意', variant: 'warn' };
  }
  return { label: raw || '未知', variant: 'neutral' };
}

/** 将 SHA-256 基线来源映射为中文说明 */
function formatSha256SourceLabel(source: VerifyReviewBundleResponse['sha256Source']): string {
  switch (source) {
    case 'manual':
      return '手工输入基线';
    case 'sidecar':
      return '同目录 .zip.sha256 伴随文件';
    default:
      return '未提供基线（仅计算当前摘要）';
  }
}

export const VerifyBundleDialog: React.FC<VerifyBundleDialogProps> = ({ defaultDir, onClose }) => {
  const inTauri = isTauriRuntime();
  const [bundlePath, setBundlePath] = useState(
    inTauri ? '' : 'C:\\TraceDesk\\cases\\DEMO-01\\reports\\review_bundle_DEMO-01.zip'
  );
  const [expectedSha256, setExpectedSha256] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [result, setResult] = useState<VerifyReviewBundleResponse | null>(null);
  const [onlyAbnormal, setOnlyAbnormal] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const trimmedSha = expectedSha256.trim();
  const shaInvalid = trimmedSha.length > 0 && !isValidSha256Hex(trimmedSha);

  const handlePickBundle = async () => {
    if (!inTauri) {
      setBundlePath('C:\\TraceDesk\\cases\\DEMO-01\\reports\\review_bundle_DEMO-01.zip');
      return;
    }
    const selected = await tauriApi.pickFile({
      title: '选择待核验的复核包 (.zip)',
      defaultPath: defaultDir || undefined,
      filters: [{ name: '复核包 ZIP', extensions: ['zip'] }],
    });
    if (selected) {
      setBundlePath(selected);
      setErrorMsg(null);
    }
  };

  const handleVerify = async () => {
    const cleanPath = bundlePath.trim();
    if (!cleanPath) {
      setErrorMsg('请先选择或粘贴复核包 .zip 路径。');
      return;
    }
    if (shaInvalid) {
      setErrorMsg('期望 SHA-256 必须为 64 位十六进制字符，或留空自动读取同目录 .zip.sha256。');
      return;
    }
    setVerifying(true);
    setErrorMsg(null);
    try {
      const res = await tauriApi.verifyReviewBundle({
        bundlePath: cleanPath,
        expectedSha256: trimmedSha ? trimmedSha.toLowerCase() : null,
      });
      setResult(res);
      // 若检出异常成员则保持默认可见全表，方便一眼对比正常与异常成员
      setOnlyAbnormal(false);
    } catch (err) {
      setResult(null);
      setErrorMsg(`复核包核验失败：${formatError(err)}`);
    } finally {
      setVerifying(false);
    }
  };

  const handleCopyText = async (key: string, text: string) => {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopiedKey(key);
      window.setTimeout(() => {
        setCopiedKey((prev) => (prev === key ? null : prev));
      }, 1800);
    }
  };

  const memberStats = useMemo(() => {
    if (!result) return { total: 0, passed: 0, abnormal: 0 };
    const total = result.members.length;
    const passed = result.members.filter((m) => isPassStatus(m.status)).length;
    return { total, passed, abnormal: total - passed };
  }, [result]);

  const displayedMembers = useMemo<ReviewBundleMemberVerifyDto[]>(() => {
    if (!result) return [];
    if (!onlyAbnormal) return result.members;
    return result.members.filter((m) => !isPassStatus(m.status));
  }, [result, onlyAbnormal]);

  return (
    <Modal
      title="一键复核包核验"
      subtitle="离线校验 ZIP 摘要 · 审计哈希链与 64B 锚点 · 清单结构 · 逐成员防篡改比对"
      width={940}
      height="86vh"
      onClose={() => {
        if (!verifying) onClose();
      }}
      footer={
        <>
          <span className="td-muted-text" style={{ fontSize: 12 }}>
            支持未打开案件独立离线核验 · 只读操作不修改原复核包
          </span>
          <div className="td-modal-footer-spacer" />
          <button type="button" className="td-btn" disabled={verifying} onClick={onClose}>
            关闭
          </button>
          <button
            type="button"
            className="td-btn td-btn--accent"
            disabled={verifying || !bundlePath.trim() || shaInvalid}
            onClick={() => void handleVerify()}
          >
            <UiIcon name="check_shield" size={14} color="#FFFFFF" />
            {verifying ? '正在核验复核包…' : result ? '重新核验' : '开始核验'}
          </button>
        </>
      }
    >
      <div className="td-verify-layout">
        {/* 输入配置区 */}
        <div className="td-verify-form">
          <div className="td-verify-field">
            <label className="td-verify-label" htmlFor="td-verify-bundle-path">
              复核包路径（.zip）
            </label>
            <div className="td-verify-path-row">
              <input
                id="td-verify-bundle-path"
                type="text"
                className="td-input td-mono"
                style={{ flex: 1 }}
                placeholder="选择或粘贴 review_bundle_*.zip 绝对路径"
                value={bundlePath}
                disabled={verifying}
                onChange={(e) => setBundlePath(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !verifying && bundlePath.trim() && !shaInvalid) {
                    void handleVerify();
                  }
                }}
              />
              <button
                type="button"
                className="td-btn td-btn--soft"
                disabled={verifying}
                onClick={() => void handlePickBundle()}
              >
                <UiIcon name="case_open" size={14} color="var(--accent-soft-text)" />
                选择 .zip…
              </button>
            </div>
          </div>

          <div className="td-verify-field">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
              <label className="td-verify-label" htmlFor="td-verify-expected-sha">
                期望 SHA-256（可选，64 位十六进制）
              </label>
              <span className="td-muted-text" style={{ fontSize: 11.5 }}>
                留空时自动尝试读取同目录 <span className="td-mono">.zip.sha256</span> 伴随文件
              </span>
            </div>
            <input
              id="td-verify-expected-sha"
              type="text"
              className={`td-input td-mono ${shaInvalid ? 'td-input--error' : ''}`}
              placeholder="留空自动识别伴随摘要文件，或粘贴 64 位 SHA-256 基线进行人工比对"
              value={expectedSha256}
              disabled={verifying}
              onChange={(e) => setExpectedSha256(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !verifying && bundlePath.trim() && !shaInvalid) {
                  void handleVerify();
                }
              }}
            />
            {shaInvalid && (
              <span style={{ fontSize: 11.5, color: 'var(--danger-fg)' }}>
                格式不正确：已输入 {trimmedSha.length} 位，需为 64 位十六进制字符（0-9 / a-f）。
              </span>
            )}
          </div>
        </div>

        {errorMsg && <div className="td-banner td-banner--error">{errorMsg}</div>}

        {!result && !errorMsg && (
          <div className="td-verify-placeholder">
            <UiIcon name="check_shield" size={38} color="var(--accent)" fill="var(--accent-soft-bg)" />
            <div className="td-verify-placeholder-title">等待选择复核包并开始核验</div>
            <div className="td-verify-placeholder-desc">
              核验流程将依次计算 ZIP 整包 SHA-256、重算审计哈希链与 64 字节 <span className="td-mono">audit.head</span>{' '}
              锚点、解析 <span className="td-mono">manifest.json</span> 清单、交叉比对报告/搜索/发现与审计链，并逐一核对全部打包成员哈希以精确定位任何单字节篡改。
            </div>
          </div>
        )}

        {result && (
          <div className="td-verify-results">
            {/* 1. 总体核验结果横幅 */}
            <div
              className={`td-verify-hero ${result.ok ? 'td-verify-hero--ok' : 'td-verify-hero--danger'}`}
              role="status"
            >
              <div className="td-verify-hero-head">
                <UiIcon
                  name={result.ok ? 'check_shield' : 'x_circle'}
                  size={28}
                  color={result.ok ? 'var(--ok-fg)' : 'var(--danger-fg)'}
                  fill={result.ok ? '#D4F2E2' : '#FCE0DE'}
                />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="td-verify-hero-title">
                    {result.ok
                      ? '复核包完整性核验全部通过'
                      : `检出篡改或完整性异常（共 ${Math.max(result.errors.length, memberStats.abnormal, 1)} 项）`}
                  </div>
                  <div className="td-verify-hero-sub">
                    成员校验 {memberStats.passed}/{memberStats.total} 项通过 · 审计链{' '}
                    {result.auditValid ? `完整（${result.auditCount} 条）` : '断链异常'} · 清单{' '}
                    {result.manifestValid ? '有效' : '异常'} · 交叉核对 {result.crossChecks.length} 项
                  </div>
                </div>
                <SemanticPill
                  text={result.ok ? '全部通过' : `${result.errors.length || memberStats.abnormal} 项异常`}
                  fallback={result.ok ? 'ok' : 'danger'}
                />
              </div>
              {!result.ok && result.errors.length > 0 && (
                <ul className="td-verify-error-list">
                  {result.errors.map((err, idx) => (
                    <li key={idx}>{err}</li>
                  ))}
                </ul>
              )}
            </div>

            {/* 2. 三张关键证据卡 */}
            <div className="td-verify-cards">
              {/* 卡 1：ZIP 整包 SHA-256 比对 */}
              <div
                className={`td-verify-card ${
                  result.sha256Matched === false
                    ? 'td-verify-card--danger'
                    : result.sha256Matched === true
                      ? 'td-verify-card--ok'
                      : ''
                }`}
              >
                <div className="td-verify-card-head">
                  <span className="td-verify-card-title">ZIP 整包 SHA-256</span>
                  <SemanticPill
                    text={
                      result.sha256Matched === true
                        ? '摘要一致'
                        : result.sha256Matched === false
                          ? '摘要不匹配'
                          : '仅计算摘要'
                    }
                    fallback={
                      result.sha256Matched === true
                        ? 'ok'
                        : result.sha256Matched === false
                          ? 'danger'
                          : 'neutral'
                    }
                  />
                </div>
                <div className="td-verify-card-meta">
                  基线来源：<strong>{formatSha256SourceLabel(result.sha256Source)}</strong>
                </div>
                <div className="td-verify-hash-block">
                  <div className="td-verify-hash-label">
                    <span>实测摘要</span>
                    <button
                      type="button"
                      className="td-btn td-btn--compact"
                      onClick={() => void handleCopyText('bundle', result.bundleSha256)}
                    >
                      {copiedKey === 'bundle' ? '已复制' : '复制'}
                    </button>
                  </div>
                  <div className="td-verify-hash-val td-mono">{result.bundleSha256 || '—'}</div>
                </div>
                {result.expectedSha256 && (
                  <div className="td-verify-hash-block">
                    <div className="td-verify-hash-label">
                      <span>期望基线</span>
                    </div>
                    <div
                      className={`td-verify-hash-val td-mono ${
                        result.sha256Matched === false ? 'td-verify-hash-val--danger' : ''
                      }`}
                    >
                      {result.expectedSha256}
                    </div>
                  </div>
                )}
              </div>

              {/* 卡 2：审计哈希链与 64B audit.head 锚点 */}
              <div
                className={`td-verify-card ${
                  result.auditValid ? 'td-verify-card--ok' : 'td-verify-card--danger'
                }`}
              >
                <div className="td-verify-card-head">
                  <span className="td-verify-card-title">审计链与 audit.head 锚点</span>
                  <SemanticPill
                    text={result.auditValid ? '链式完整' : '检出断链'}
                    fallback={result.auditValid ? 'ok' : 'danger'}
                  />
                </div>
                <div className="td-verify-card-meta">
                  链内审计记录：<strong>{result.auditCount}</strong> 条
                </div>
                <div className="td-verify-hash-block">
                  <div className="td-verify-hash-label">
                    <span>64B 尾部锚点（audit.head）</span>
                    {result.auditHead && (
                      <button
                        type="button"
                        className="td-btn td-btn--compact"
                        onClick={() => void handleCopyText('head', result.auditHead)}
                      >
                        {copiedKey === 'head' ? '已复制' : '复制'}
                      </button>
                    )}
                  </div>
                  <div className="td-verify-hash-val td-mono">{result.auditHead || '—'}</div>
                </div>
                {(!result.auditValid || result.auditError) && (
                  <div className="td-verify-card-alert">
                    {result.auditError || '审计哈希链或 audit.head 锚点校验未通过'}
                  </div>
                )}
              </div>

              {/* 卡 3：manifest.json 清单结构 */}
              <div
                className={`td-verify-card ${
                  result.manifestValid && memberStats.abnormal === 0
                    ? 'td-verify-card--ok'
                    : 'td-verify-card--danger'
                }`}
              >
                <div className="td-verify-card-head">
                  <span className="td-verify-card-title">清单结构 manifest.json</span>
                  <SemanticPill
                    text={result.manifestValid ? '结构有效' : '清单异常'}
                    fallback={result.manifestValid ? 'ok' : 'danger'}
                  />
                </div>
                <div className="td-verify-card-meta">
                  核对成员总数：<strong>{memberStats.total}</strong> 项
                </div>
                <div className="td-verify-stat-pills">
                  <span className="td-pill td-pill--ok">通过 {memberStats.passed}</span>
                  <span className={`td-pill ${memberStats.abnormal > 0 ? 'td-pill--danger' : 'td-pill--neutral'}`}>
                    异常 {memberStats.abnormal}
                  </span>
                </div>
                <div className="td-muted-text" style={{ fontSize: 11.5, lineHeight: 1.5, marginTop: 2 }}>
                  核对清单声明与 ZIP 内所有文件的路径、字节大小及 SHA-256 逐项一致性。
                </div>
              </div>
            </div>

            {/* 3. 跨文件审计链交叉核对清单 */}
            {result.crossChecks.length > 0 && (
              <div className="td-verify-section">
                <div className="td-verify-section-head">
                  <span className="td-section-title">跨文件审计链交叉核对</span>
                  <span className="td-muted-text" style={{ fontSize: 11.5 }}>
                    验证 report.md / report.html / searches/*.json / findings 与审计链一致性
                  </span>
                </div>
                <div className="td-verify-crosscheck-list">
                  {result.crossChecks.map((cc, idx) => {
                    const st = formatVerifyStatus(cc.status);
                    const passed = isPassStatus(cc.status);
                    return (
                      <div
                        key={`${cc.name}-${idx}`}
                        className={`td-verify-crosscheck-row ${!passed ? 'td-verify-crosscheck-row--danger' : ''}`}
                      >
                        <UiIcon
                          name={passed ? 'check_circle' : 'x_circle'}
                          size={15}
                          color={passed ? 'var(--ok-fg)' : 'var(--danger-fg)'}
                          fill={passed ? 'var(--ok-bg)' : 'var(--danger-bg)'}
                        />
                        <span className="td-verify-crosscheck-name td-mono">{cc.name}</span>
                        <SemanticPill text={st.label} fallback={st.variant} />
                        <span className="td-verify-crosscheck-msg">{cc.message}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* 4. 逐成员哈希核对表 */}
            <div className="td-verify-section">
              <div className="td-verify-section-head">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="td-section-title">逐成员哈希核对表</span>
                  <span className="td-muted-text" style={{ fontSize: 11.5 }}>
                    共 {memberStats.total} 项
                    {memberStats.abnormal > 0 ? `，其中 ${memberStats.abnormal} 项存在篡改或异常` : '，全部一致'}
                  </span>
                </div>
                <button
                  type="button"
                  className={`td-btn td-btn--compact ${onlyAbnormal ? 'td-btn--warning' : ''}`}
                  onClick={() => setOnlyAbnormal((prev) => !prev)}
                >
                  {onlyAbnormal ? `已筛选：仅看异常成员 (${memberStats.abnormal})` : `仅看异常成员 (${memberStats.abnormal})`}
                </button>
              </div>

              <div className="td-verify-member-table-wrap">
                <table className="td-verify-member-table">
                  <thead>
                    <tr>
                      <th style={{ width: '24%' }}>成员路径</th>
                      <th style={{ width: '11%' }}>分类</th>
                      <th style={{ width: '11%' }}>核验状态</th>
                      <th style={{ width: '10%', textAlign: 'right' }}>大小</th>
                      <th style={{ width: '44%' }}>SHA-256 摘要比对与核验说明</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayedMembers.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '18px 12px', color: 'var(--text-muted)' }}>
                          {onlyAbnormal ? '所有成员均通过核验，无异常成员。' : '复核包未包含可核对成员。'}
                        </td>
                      </tr>
                    ) : (
                      displayedMembers.map((m, idx) => {
                        const passed = isPassStatus(m.status);
                        const st = formatVerifyStatus(m.status);
                        return (
                          <tr
                            key={`${m.path}-${idx}`}
                            className={!passed ? 'td-verify-member-row--abnormal' : ''}
                          >
                            <td className="td-mono" style={{ wordBreak: 'break-all', fontWeight: !passed ? 600 : 500 }}>
                              {m.path}
                            </td>
                            <td>{m.category || '—'}</td>
                            <td>
                              <SemanticPill text={st.label} fallback={st.variant} />
                            </td>
                            <td className="td-mono" style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                              {m.size !== null && m.size !== undefined ? `${formatBytes(m.size)} B` : '—'}
                            </td>
                            <td>
                              <div className="td-verify-member-detail">
                                {m.message && (
                                  <div
                                    style={{
                                      fontSize: 12,
                                      fontWeight: !passed ? 600 : 400,
                                      color: !passed ? 'var(--danger-fg)' : 'var(--text-secondary)',
                                    }}
                                  >
                                    {m.message}
                                  </div>
                                )}
                                {!passed ? (
                                  <div className="td-verify-diff-hashes td-mono">
                                    <div>
                                      <span className="td-verify-diff-tag">期望</span>
                                      <span>{m.expectedSha256 || '（清单未记录）'}</span>
                                    </div>
                                    <div className="td-verify-diff-actual">
                                      <span className="td-verify-diff-tag td-verify-diff-tag--danger">实测</span>
                                      <span>{m.actualSha256 || '（文件缺失或无法读取）'}</span>
                                    </div>
                                  </div>
                                ) : (
                                  m.actualSha256 && (
                                    <div className="td-mono td-muted-text" style={{ fontSize: 11, wordBreak: 'break-all' }}>
                                      {m.actualSha256}
                                    </div>
                                  )
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};
