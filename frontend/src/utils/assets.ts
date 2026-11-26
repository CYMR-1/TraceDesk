/**
 * 资源路径解析与通用格式化工具
 */

export function assetUrl(relativePath: string): string {
  const base = import.meta.env.BASE_URL || './';
  const normalizedBase = base.endsWith('/') ? base : `${base}/`;
  const normalizedRel = relativePath.replace(/^\/+/, '');
  return `${normalizedBase}${normalizedRel}`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return '0';
  return bytes.toLocaleString('en-US');
}

export function formatError(err: unknown): string {
  if (typeof err === 'string') return err;
  if (err instanceof Error) return err.message;
  if (err && typeof err === 'object' && 'message' in err) {
    return String((err as { message: unknown }).message);
  }
  return String(err);
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // 降级使用下方兜底方案
  }
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}

export function isValidSha256Hex(value: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(value.trim());
}

/**
 * 将后端返回的 ISO 时间字符串（如 2026-11-25T21:57:35.875754+08:00）
 * 优雅格式化为简洁的 YYYY-MM-DD HH:mm 展示文本，保留取证本地墙钟时间语义。
 */
export function formatCaseTimestamp(raw?: string | null): string {
  const trimmed = (raw ?? '').trim();
  if (!trimmed) return '';

  // 优先匹配带 +08:00 或无时区后缀的 ISO/SQL 时间，直接提取 YYYY-MM-DD 与 HH:mm 避免时区漂移
  const localMatch = trimmed.match(
    /^(\d{4}-\d{2}-\d{2})[T\s](\d{2}:\d{2})(?::\d{2}(?:\.\d+)?)?(?:\+08:?00)?$/
  );
  if (localMatch) {
    return `${localMatch[1]} ${localMatch[2]}`;
  }

  // 含其他时区偏移或 Z 后缀时，按 Date 解析并转为本地 YYYY-MM-DD HH:mm
  const parsed = new Date(trimmed);
  if (!Number.isNaN(parsed.getTime())) {
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())} ${pad(parsed.getHours())}:${pad(parsed.getMinutes())}`;
  }

  // 兜底：去除微秒与 T 分隔符
  return trimmed.replace('T', ' ').replace(/\.\d+/, '').replace(/([+-]\d{2}:?\d{2}|Z)$/i, '').trim();
}

/** 提取文件系统路径的末级目录名或文件名 */
export function extractPathLeafName(filePath: string): string {
  const cleaned = filePath.replace(/[\\/]+$/, '');
  const parts = cleaned.split(/[\\/]/);
  return parts[parts.length - 1] || filePath;
}
