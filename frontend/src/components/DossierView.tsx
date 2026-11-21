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
}> = ({ title, subtitle, sections }) => (
  <div className="td-dossier">
    <h2>{title}</h2>
    {subtitle && <p className="td-dossier-subtitle">{subtitle}</p>}
    {sections.length > 0 && <hr />}
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
