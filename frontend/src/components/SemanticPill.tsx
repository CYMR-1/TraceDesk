/**
 * 语义胶囊徽章解析与渲染组件 (1:1 还原 forensic/ui/theme.py SEMANTIC_PILLS)
 */
import React from 'react';

export type PillVariant = 'ok' | 'danger' | 'warn' | 'system' | 'accent' | 'neutral';

const DIRECT_MAP: Record<string, PillVariant> = {
  现存: 'ok',
  正常: 'ok',
  人工: 'ok',
  成功: 'ok',
  通过: 'ok',
  一致: 'ok',
  校验通过: 'ok',
  运行中: 'ok',
  只读: 'ok',
  已固定: 'ok',
  B: 'ok',
  'B 创建': 'ok',

  已删除: 'danger',
  缺失: 'danger',
  失败: 'danger',
  不一致: 'danger',
  校验失败: 'danger',
  错误: 'danger',

  '已删除·重分配': 'warn',
  部分导出: 'warn',
  已取消: 'warn',
  待固定: 'warn',
  未固定: 'warn',
  '受控写入（记入审计链）': 'warn',
  受控写入: 'warn',

  MCP: 'system',
  系统区域: 'system',
  虚拟目录: 'system',
  C: 'system',
  'C 元数据变更': 'system',

  M: 'accent',
  'M 内容修改': 'accent',

  未启动: 'neutral',
  已停止: 'neutral',
  跳过: 'neutral',
  A: 'neutral',
  'A 访问': 'neutral',
};

const MUTED_PREFIXES = ['—', '未记录', '不支持', '未登记'];

export function isMutedPlaceholder(text: string | null | undefined): boolean {
  const s = (text ?? '').trim();
  if (!s) return true;
  return MUTED_PREFIXES.some((prefix) => s.startsWith(prefix));
}

export function resolvePillVariant(text: string | null | undefined, fallback: PillVariant | null = null): PillVariant | null {
  const key = (text ?? '').trim();
  if (!key) return fallback;
  if (key in DIRECT_MAP) return DIRECT_MAP[key];
  if (key.startsWith('已删除·重分配')) return 'warn';
  if (/^(已删除|不一致|失败|缺失|校验失败|错误)/.test(key)) return 'danger';
  if (/^(部分导出|已取消|待固定|未固定|受控写入|记录时待固定)/.test(key)) return 'warn';
  if (/^(校验通过|成功|通过|一致|运行中|只读)/.test(key)) return 'ok';
  if (/^(MCP|系统区域|虚拟目录)/.test(key)) return 'system';
  return fallback;
}

export const SemanticPill: React.FC<{
  text: string;
  fallback?: PillVariant;
  title?: string;
}> = ({ text, fallback = 'neutral', title }) => {
  const trimmed = (text ?? '').trim();
  if (!trimmed || isMutedPlaceholder(trimmed)) {
    return <span className="td-muted-text">{trimmed || '—'}</span>;
  }
  const variant = resolvePillVariant(trimmed, fallback) ?? fallback;
  return (
    <span className={`td-pill td-pill--${variant}`} title={title ?? trimmed}>
      {trimmed}
    </span>
  );
};
