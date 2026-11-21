/**
 * 模块 7：MCP 服务管理弹窗 (mcp)
 * - 本地 Streamable HTTP 启停（127.0.0.1 + 端口 1024..65535）、实时状态徽标
 * - 持有案件锁提示条与一键释放 case.lock
 * - 三标签页：stdio 接入配置（推荐）/ Streamable HTTP 配置 / 可用工具清单（19）
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { tauriApi } from '../api/tauri';
import { UiIcon } from '../components/Icons';
import { VirtualTable, type VirtualColumn } from '../components/VirtualTable';
import { Modal } from '../components/dialogs/Modal';
import type { McpStatus, ToolCatalogItem } from '../types/ipc';
import { copyToClipboard, formatError } from '../utils/assets';

interface McpDialogProps {
  activeCaseNumber: string | null;
  onCaseReleased: () => void;
  onClose: () => void;
}

export const McpDialog: React.FC<McpDialogProps> = ({
  activeCaseNumber,
  onCaseReleased,
  onClose,
}) => {
  const [status, setStatus] = useState<McpStatus | null>(null);
  const [port, setPort] = useState(8765);
  const [portInput, setPortInput] = useState('8765');
  const [tab, setTab] = useState<'stdio' | 'http' | 'tools'>('stdio');
  const [loading, setLoading] = useState(false);
  const [feedback, setFeedback] = useState('');
  const [error, setError] = useState<string | null>(null);

  const loadStatus = useCallback(async (targetPort?: number) => {
    try {
      const res = await tauriApi.getMcpStatus(targetPort ? { port: targetPort } : undefined);
      setStatus(res);
      if (res.running) {
        setPort(res.port);
        setPortInput(String(res.port));
      }
    } catch (err) {
      setError(`读取 MCP 状态失败：${formatError(err)}`);
    }
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  const handlePortInputChange = (raw: string) => {
    setPortInput(raw);
    const parsed = Number.parseInt(raw, 10);
    if (!Number.isNaN(parsed) && parsed >= 1024 && parsed <= 65535) {
      setPort(parsed);
      if (!status?.running) {
        void loadStatus(parsed);
      }
    }
  };

  const handlePortBlur = () => {
    const parsed = Number.parseInt(portInput, 10);
    const clamped = Number.isNaN(parsed) ? 8765 : Math.max(1024, Math.min(65535, parsed));
    setPort(clamped);
    setPortInput(String(clamped));
    if (!status?.running) {
      void loadStatus(clamped);
    }
  };

  const handleToggleHttp = async () => {
    if (!status) return;
    setLoading(true);
    setError(null);
    try {
      if (status.running) {
        const next = await tauriApi.stopMcpHttp();
        setStatus(next);
        setFeedback('本地 HTTP MCP 服务已停止');
      } else {
        const next = await tauriApi.startMcpHttp({ port });
        setStatus(next);
        setFeedback(`本地 HTTP MCP 服务已启动：${next.url}`);
      }
    } catch (err) {
      setError(`MCP 服务操作失败：${formatError(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const handleReleaseCase = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await tauriApi.closeCase();
      if (res.closed) {
        const releasedNum = activeCaseNumber ?? status?.activeCaseNumber ?? '';
        onCaseReleased();
        await loadStatus(port);
        setFeedback(`已关闭案件「${releasedNum}」并释放 case.lock，现在可由外部 MCP 客户端操作`);
      }
    } catch (err) {
      setError(`释放案件锁失败：${formatError(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async (text: string, notice: string) => {
    const ok = await copyToClipboard(text);
    setFeedback(ok ? notice : '复制到剪贴板失败，请手动选中复制');
  };

  const toolColumns = useMemo<VirtualColumn<ToolCatalogItem>[]>(
    () => [
      { key: 'name', label: '工具名称', width: 210, mono: true, getText: (t) => t.name },
      { key: 'category', label: '分类', width: 96, getText: (t) => t.category },
      {
        key: 'mode',
        label: '模式',
        width: 170,
        pill: true,
        getText: (t) => (t.readOnly ? '只读' : '受控写入（记入审计链）'),
      },
      { key: 'summary', label: '功能说明', width: 260, getText: (t) => t.summary },
    ],
    []
  );

  const running = Boolean(status?.running);
  const currentActiveCase = activeCaseNumber ?? status?.activeCaseNumber ?? null;
  const tools = status?.tools ?? [];

  return (
    <Modal
      title="MCP 服务配置 · TraceDesk"
      width={820}
      height={620}
      onClose={onClose}
      footer={
        <>
          <span className="td-muted-text" style={{ fontSize: 12 }}>
            {feedback}
          </span>
          <div className="td-modal-footer-spacer" />
          <button type="button" className="td-btn" onClick={onClose}>
            关闭
          </button>
        </>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%' }}>
        <div className="td-card">
          <div>
            <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)' }}>
              TraceDesk MCP 服务端（tracedesk_mcp）
            </div>
            <div className="td-muted-text" style={{ fontSize: 12, marginTop: 3 }}>
              提供 {tools.length || 19} 个取证工具与 2 个资源 · 源镜像只读保护 · 受控操作自动写入 SHA-256 审计链
            </div>
          </div>

          <div className={`td-status-bar-pill ${running ? 'td-status-bar-pill--running' : 'td-status-bar-pill--stopped'}`}>
            {running
              ? `本地 HTTP 服务状态：运行中 · ${status?.url}`
              : '本地 HTTP 服务状态：未启动（stdio 模式无需启动端口即可由外部客户端拉起）'}
          </div>

          {currentActiveCase && (
            <div className="td-banner td-banner--warning">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <UiIcon name="warning" size={16} color="var(--warn-fg)" />
                <div style={{ flex: 1 }}>
                  提示：桌面端当前已打开案件「{currentActiveCase}」并持有 case.lock。外部 MCP 客户端操作同一案件前，可点击右侧按钮一键释放案件锁。
                </div>
                <button
                  type="button"
                  className="td-btn td-btn--warningAction"
                  disabled={loading}
                  onClick={() => void handleReleaseCase()}
                >
                  <UiIcon name="lock_open" size={14} color="var(--warn-fg)" />
                  释放当前案件锁
                </button>
              </div>
            </div>
          )}

          {error && <div className="td-banner td-banner--error">{error}</div>}

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span>监听地址：127.0.0.1（仅本机回环）</span>
            <label htmlFor="td-mcp-port" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <span>端口：</span>
              <input
                id="td-mcp-port"
                type="number"
                min={1024}
                max={65535}
                className="td-input td-mono"
                style={{ width: 96 }}
                disabled={running || loading}
                value={portInput}
                onChange={(e) => handlePortInputChange(e.target.value)}
                onBlur={handlePortBlur}
              />
            </label>
            <div style={{ flex: 1 }} />
            <button
              type="button"
              className={`td-btn ${running ? 'td-btn--soft' : 'td-btn--accent'}`}
              disabled={loading || !status}
              onClick={() => void handleToggleHttp()}
            >
              {running ? '停止本地 HTTP 服务' : '启动本地 HTTP 服务'}
            </button>
          </div>
        </div>

        <div className="td-dialog-tabs">
          <div className="td-dialog-tab-bar" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={tab === 'stdio'}
              className={`td-dialog-tab ${tab === 'stdio' ? 'td-dialog-tab--active' : ''}`}
              onClick={() => setTab('stdio')}
            >
              stdio 接入配置（推荐）
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={tab === 'http'}
              className={`td-dialog-tab ${tab === 'http' ? 'td-dialog-tab--active' : ''}`}
              onClick={() => setTab('http')}
            >
              Streamable HTTP 配置
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={tab === 'tools'}
              className={`td-dialog-tab ${tab === 'tools' ? 'td-dialog-tab--active' : ''}`}
              onClick={() => setTab('tools')}
            >
              可用工具清单（{tools.length || 19}）
            </button>
          </div>

          <div className="td-dialog-tab-pane">
            {tab === 'stdio' && (
              <>
                <div className="td-muted-text" style={{ fontSize: 12 }}>
                  推荐用于 Claude Desktop、Cursor、Antigravity 等本地 MCP 客户端：客户端按需以子进程方式拉起，无需常驻网络端口。
                </div>
                <pre className="td-code-block" style={{ flex: 1 }}>
                  {status?.stdioConfigJson ?? '正在载入配置…'}
                </pre>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    type="button"
                    className="td-btn td-btn--soft"
                    disabled={!status}
                    onClick={() =>
                      status && void handleCopy(status.stdioConfigJson, '已复制 stdio 配置 JSON')
                    }
                  >
                    <UiIcon name="copy" size={14} color="var(--accent-soft-text)" />
                    复制配置 JSON
                  </button>
                  <button
                    type="button"
                    className="td-btn"
                    disabled={!status}
                    onClick={() =>
                      status && void handleCopy(status.stdioCli, '已复制 stdio 启动命令')
                    }
                  >
                    复制启动命令
                  </button>
                </div>
              </>
            )}

            {tab === 'http' && (
              <>
                <div className="td-muted-text" style={{ fontSize: 12 }}>
                  适用于支持 Streamable HTTP 的 MCP 客户端。点击上方“启动本地 HTTP 服务”或通过命令行启动后即可接入，已启用本机回环限制与 DNS 重绑定防护。
                </div>
                <pre className="td-code-block" style={{ flex: 1 }}>
                  {status?.httpConfigJson ?? '正在载入配置…'}
                </pre>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="td-btn td-btn--soft"
                    disabled={!status}
                    onClick={() =>
                      status && void handleCopy(status.httpConfigJson, '已复制 HTTP 配置 JSON')
                    }
                  >
                    <UiIcon name="copy" size={14} color="var(--accent-soft-text)" />
                    复制配置 JSON
                  </button>
                  <button
                    type="button"
                    className="td-btn"
                    disabled={!status}
                    onClick={() =>
                      status && void handleCopy(status.url, '已复制本地 HTTP 服务地址')
                    }
                  >
                    复制服务地址
                  </button>
                  <button
                    type="button"
                    className="td-btn"
                    disabled={!status}
                    onClick={() =>
                      status && void handleCopy(status.httpCli, '已复制 HTTP 启动命令')
                    }
                  >
                    复制命令行启动指令
                  </button>
                </div>
              </>
            )}

            {tab === 'tools' && (
              <div style={{ flex: 1, minHeight: 0, display: 'flex', border: '1px solid var(--border-subtle)', borderRadius: 4 }}>
                <VirtualTable
                  rows={tools}
                  columns={toolColumns}
                  rowKey={(t) => t.name}
                  emptyText="正在载入工具目录…"
                />
              </div>
            )}
          </div>
        </div>
      </div>
    </Modal>
  );
};
