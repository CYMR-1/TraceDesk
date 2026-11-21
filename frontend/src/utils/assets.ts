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
    // Fallback below
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
