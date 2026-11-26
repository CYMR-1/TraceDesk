/**
 * 结构化取证档案详情面板 (DossierView)：
 * 1:1 还原 theme.DOSSIER_CSS 与 analysis_panels.page() 的排版、语义胶囊与等宽值渲染。
 */
import React from 'react';
import { isMutedPlaceholder, resolvePillVariant, SemanticPill } from './SemanticPill';

export interface DossierSection {
  title: string;
  rows: readonly [string, unknown][];
}

const HEX_DIGEST_RE = /^[0-9a-fA-F]{32,128}$/;
const WINDOWS_PATH_RE = /^[A-Za-z]:[\\/]/;
const PILL_KEYS = new Set(['结果', '状态', '操作来源', '交付方摘要比对', '事件', '操作时的完整性状态']);
const MONO_KEY_TOKENS = [
  'SHA-256',
  '哈希',
  '路径',
  '偏移',
  'inode',
  '代码',
  '字节',
  '大小',
  '时间',
  '对照文件',
  '实测摘要',
  '分段数',
];

function renderDossierValue(key: string, value: unknown): React.ReactNode {
  // 允许上层直接传入交互式 React 节点（例如可点击切换单位的镜像大小展示）
  if (React.isValidElement(value)) {
    return value;
  }

  const raw = value === null || value === undefined ? '' : String(value);
  const stripped = raw.trim();
  if (!stripped || isMutedPlaceholder(stripped)) {
    return <span className="td-muted-text">{stripped || '—'}</span>;
  }

  if (key === '交付方摘要比对') {
    if (stripped.includes('不一致')) return <SemanticPill text={stripped} fallback="danger" />;
    if (stripped.includes('一致')) return <SemanticPill text={stripped} fallback="ok" />;
    if (stripped.includes('待固定')) return <SemanticPill text={stripped} fallback="warn" />;
    return <span className="td-muted-text">{stripped}</span>;
  }

  if (PILL_KEYS.has(key) || resolvePillVariant(stripped, null) !== null) {
    const variant = resolvePillVariant(stripped, null);
    if (variant) {
      return <SemanticPill text={stripped} fallback={variant} />;
    }
  }

  const isMono =
    HEX_DIGEST_RE.test(stripped) ||
    stripped.startsWith('/') ||
    WINDOWS_PATH_RE.test(stripped) ||
    (stripped.includes('\\') && !stripped.includes(' ')) ||
    (MONO_KEY_TOKENS.some((tok) => key.includes(tok)) && !stripped.includes('\n'));

  if (isMono) {
    return <span className="td-dossier-mono" style={{ whiteSpace: 'pre-wrap' }}>{raw}</span>;
  }
  return <span style={{ whiteSpace: 'pre-wrap' }}>{raw}</span>;
}

export const DossierView: React.FC<{
  title: string;
  subtitle?: string;
  sections: DossierSection[];
  /** 可选顶部标题栏右侧扩展操作按钮（如「定位原文件」） */
  headerActions?: React.ReactNode;
  /** 可选关闭回调：传入时在顶部栏右侧展示“关闭”按钮（用于底部可收起详情分栏） */
  onClose?: () => void;
}> = ({ title, subtitle, sections, headerActions, onClose }) => (
  <div className="td-dossier">
    {onClose || headerActions ? (
      <div
        className={`td-dossier-header ${onClose ? 'td-dossier-header--closable' : ''}${
          sections.length > 0 ? ' td-dossier-header--bordered' : ''
        }`}
      >
        <div className="td-dossier-heading">
          <h2>{title}</h2>
          {subtitle && <p className="td-dossier-subtitle">{subtitle}</p>}
        </div>
        <div className="td-dossier-header-actions">
          {headerActions}
          {onClose && (
            <button
              type="button"
              className="td-dossier-close"
              onClick={onClose}
              title="关闭详情面板"
              aria-label="关闭详情面板"
            >
              <span className="td-dossier-close-icon" aria-hidden="true">×</span>
              <span>关闭</span>
            </button>
          )}
        </div>
      </div>
    ) : (
      <>
        <h2>{title}</h2>
        {subtitle && <p className="td-dossier-subtitle">{subtitle}</p>}
        {sections.length > 0 && <hr />}
      </>
    )}
    {sections.map((section, sIdx) => (
      <div key={`${section.title}-${sIdx}`}>
        <h3>{section.title}</h3>
        <table>
          <tbody>
            {section.rows.map(([k, v], rIdx) => (
              <tr key={`${k}-${rIdx}`}>
                <td className="td-dossier-key">{k}</td>
                <td className="td-dossier-val">{renderDossierValue(k, v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ))}
  </div>
);
