/**
 * 模块 2：镜像与文件系统信息页 (evidence)
 * - 顶栏：镜像摘要与证据来源 + 登记证据来源按钮
 * - 上半：DossierView（证据固定、EWF 分段镜像、覆盖范围与来源 5 字段、分区概览）
 * - 下半：分区布局与文件系统 · 原始解析结果（分区下拉 + 导出完整 fsstat + 等宽只读 mmls/fsstat 视图）
 */
import React, { useEffect, useMemo, useState } from 'react';
import { DossierView, type DossierSection } from '../components/DossierView';
import { UiIcon } from '../components/Icons';
import { SplitPane } from '../components/SplitPane';
import { SOURCE_FIELD_LABELS } from '../features/registry';
import type { CaseSnapshot, EvidenceInfo } from '../types/ipc';
import { formatBytes } from '../utils/assets';

interface EvidenceInfoModuleProps {
  snapshot: CaseSnapshot | null;
  busy: boolean;
  onRegisterSource: () => void;
  /** 重新定位/重绑源证据镜像路径（含 SHA-256 基线核验） */
  onRebindImagePath: () => void;
  onExportFsstat: (offset: number) => void;
  /** 大镜像按需模式下对指定偏移分区执行“仅索引此分区” */
  onScanPartition: (offset: number) => void;
}

interface BinarySizeUnit {
  label: 'TiB' | 'GiB' | 'MiB' | 'KiB' | 'B';
  factor: number;
}

const BINARY_SIZE_UNITS: readonly BinarySizeUnit[] = [
  { label: 'TiB', factor: 1024 ** 4 },
  { label: 'GiB', factor: 1024 ** 3 },
  { label: 'MiB', factor: 1024 ** 2 },
  { label: 'KiB', factor: 1024 },
];

/** 按 1024 二进制进制推导可选显示单位序列：默认优先最大合适单位，点击后逐级向小单位循环切换 */
function resolveBinarySizeUnits(bytes: number): BinarySizeUnit[] {
  const safeBytes = Math.max(0, Number.isFinite(bytes) ? bytes : 0);
  const startIdx = BINARY_SIZE_UNITS.findIndex((u) => safeBytes >= u.factor);
  if (startIdx === -1) {
    return [{ label: 'B', factor: 1 }];
  }
  return BINARY_SIZE_UNITS.slice(startIdx);
}

/** 将字节数格式化为“<大单位值> = (<精确千分位字节数> 字节)” */
function formatBinarySizeWithBytes(bytes: number, unit: BinarySizeUnit): string {
  const exactBytes = formatBytes(bytes);
  if (unit.label === 'B') {
    return `${exactBytes} B = (${exactBytes} 字节)`;
  }
  const scaled = (bytes / unit.factor).toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
  return `${scaled} ${unit.label} = (${exactBytes} 字节)`;
}

function buildCoverageSummary(evidence: EvidenceInfo): string {
  if (evidence.coverageText) return evidence.coverageText;
  if (evidence.coverage?.text) return evidence.coverage.text;
  if (!evidence.coverage?.volumes?.length) {
    return '尚未评估；请运行完整性校验';
  }
  return (
    evidence.coverage.volumes
      .map((v) => {
        const endPos = Math.max(v.volumeEnd ?? 0, v.partitionEnd ?? 0) || '未知';
        return `偏移 ${v.offset} 扇区：${v.status}（${v.filesystem}，声明结束字节位置 ${endPos}，镜像 ${evidence.coverage?.bytes ?? evidence.size} 字节）`;
      })
      .join('；') + '。仅判断可识别的声明范围，不能证明原盘无坏扇区或已完整采集。'
  );
}

function buildSourceStatus(evidence: EvidenceInfo): string {
  if (evidence.sourceStatus) return evidence.sourceStatus;
  const expected = evidence.provenance?.expectedSha256 ?? evidence.provenance?.expected_sha256 ?? '';
  if (!evidence.sha256) return '本机整镜像 SHA-256 待固定';
  if (!expected) return '未提供交付方摘要，仅有本机固定值';
  return expected.toLowerCase() === evidence.sha256.toLowerCase()
    ? '交付方摘要与本机固定值一致'
    : '警告：交付方摘要与本机固定值不一致';
}

const EvidenceInfoModuleInner: React.FC<EvidenceInfoModuleProps> = ({
  snapshot,
  busy,
  onRegisterSource,
  onRebindImagePath,
  onExportFsstat,
  onScanPartition,
}) => {
  const evidence = snapshot?.evidence ?? null;
  const partitions = evidence?.partitions ?? [];
  const [selectedOffset, setSelectedOffset] = useState<number>(partitions[0]?.offset ?? 0);
  // 镜像大小展示单位索引：0 表示默认最大合适单位，点击逐级向小单位循环切换
  const [sizeUnitIdx, setSizeUnitIdx] = useState<number>(0);

  useEffect(() => {
    if (partitions.length > 0 && !partitions.some((p) => p.offset === selectedOffset)) {
      setSelectedOffset(partitions[0].offset);
    }
  }, [partitions, selectedOffset]);

  useEffect(() => {
    setSizeUnitIdx(0);
  }, [evidence?.path, evidence?.size]);

  const sections = useMemo<DossierSection[]>(() => {
    if (!evidence || !snapshot) return [];

    const scanMap = new Map(snapshot.partitionScans.map((s) => [s.offset, s]));
    const fixedAt = evidence.fixedAt ?? evidence.fixed_at;

    const sizeUnits = resolveBinarySizeUnits(evidence.size);
    const activeUnit = sizeUnits[sizeUnitIdx % sizeUnits.length] ?? sizeUnits[0];
    const sizeText = formatBinarySizeWithBytes(evidence.size, activeUnit);
    const nextUnit = sizeUnits.length > 1 ? sizeUnits[(sizeUnitIdx + 1) % sizeUnits.length] : null;
    const sizeValueNode =
      sizeUnits.length > 1 && nextUnit ? (
        <button
          type="button"
          className="td-size-unit-btn td-dossier-mono"
          title={`点击切换显示单位（下次切换为 ${nextUnit.label}）`}
          onClick={() => setSizeUnitIdx((idx) => (idx + 1) % sizeUnits.length)}
        >
          <span>{sizeText}</span>
          <span className="td-size-unit-hint" aria-hidden="true">
            ⇄
          </span>
        </button>
      ) : (
        <span className="td-dossier-mono">{sizeText}</span>
      );

    const list: DossierSection[] = [
      {
        title: '证据固定',
        rows: [
          ['镜像路径', evidence.path],
          ['大小', sizeValueNode],
          ['固定时间（UTC+8）', fixedAt || '待固定'],
          ['SHA-256', evidence.sha256 || '待固定'],
        ],
      },
    ];

    if (evidence.format === 'EWF' && evidence.segments) {
      const totalSegSize = evidence.segments.reduce((acc, s) => acc + s.size, 0);
      list.push({
        title: 'EWF 分段镜像',
        rows: [
          ['分段数', String(evidence.segments.length)],
          ['封装总大小（字节）', formatBytes(totalSegSize)],
          ['逻辑介质大小（字节）', formatBytes(evidence.size)],
          ['校验方式', '首次解码整个逻辑磁盘，后续逐段复算封装摘要'],
        ],
      });
    }

    const prov = evidence.provenance;
    const provRows: [string, string][] = SOURCE_FIELD_LABELS.map((f) => {
      let val = '';
      if (f.key === 'evidenceId') val = prov?.evidenceId ?? prov?.evidence_id ?? '';
      else if (f.key === 'expectedSha256') val = prov?.expectedSha256 ?? prov?.expected_sha256 ?? '';
      else val = prov?.[f.key] ?? '';
      return [f.label, val || '未登记'];
    });

    list.push({
      title: '覆盖范围与证据来源',
      rows: [
        ['范围判断', buildCoverageSummary(evidence)],
        ['交付方摘要比对', buildSourceStatus(evidence)],
        ...provRows,
      ],
    });

    const partRows: [string, unknown][] = partitions.map((p) => {
      const scan = scanMap.get(p.offset);
      const isReady = scan?.status === 'ready';
      const isError = scan?.status === 'error';
      const state = isReady ? `已读取 ${scan?.count ?? 0} 项` : scan?.error || '待读取';
      const summaryText = `${p.description} · ${state}`;
      if (!isReady && !isError) {
        return [
          `偏移 ${p.offset} 扇区`,
          <div className="td-dossier-inline-action" key={`part-${p.offset}`}>
            <span>{summaryText}</span>
            <button
              type="button"
              className="td-btn td-btn--compact td-btn--soft"
              disabled={busy}
              onClick={() => onScanPartition(p.offset)}
              title={`仅扫描并建立分区偏移 ${p.offset} 扇区的文件索引`}
            >
              <UiIcon name="index" size={12} color="var(--accent-soft-text)" />
              仅索引此分区
            </button>
          </div>,
        ];
      }
      return [`偏移 ${p.offset} 扇区`, summaryText];
    });

    list.push({
      title: '分区概览',
      rows: partRows.length > 0 ? partRows : [['分区', '未识别到有效分区']],
    });

    return list;
  }, [evidence, snapshot, partitions, sizeUnitIdx, busy, onScanPartition]);

  const rawText = useMemo(() => {
    if (!evidence) return '';
    return [evidence.layout || '', snapshot?.fsstat || ''].filter(Boolean).join('\n\n');
  }, [evidence, snapshot?.fsstat]);

  const subtitle = evidence
    ? `${partitions.length} 个分区 · ${snapshot?.inventoryCount ?? 0} 个条目 · 应用层只读`
    : '加载 RAW 镜像或 E01 首段后查看摘要与覆盖范围。';

  const evidenceMissing = Boolean(snapshot?.evidenceMissing && evidence);

  return (
    <div className="td-panel">
      <div className="td-panel-top-bar">
        <span className="td-section-title" style={{ flex: 1 }}>
          镜像摘要与证据来源
        </span>
        <button
          type="button"
          className="td-btn"
          disabled={busy || !evidence}
          title="重新指定源镜像磁盘路径（换盘符或迁移目录后，需通过 SHA-256 核验方可更新）"
          onClick={onRebindImagePath}
        >
          <UiIcon
            name="locate"
            size={14}
            color={busy || !evidence ? 'var(--text-disabled)' : 'var(--text-secondary)'}
          />
          重绑镜像路径
        </button>
        <button
          type="button"
          className="td-btn td-btn--soft"
          disabled={busy || !evidence}
          onClick={onRegisterSource}
        >
          登记证据来源
        </button>
      </div>

      {/* 源证据镜像路径失效柔和告警条：支持一键校验重绑 */}
      {evidenceMissing && evidence && (
        <div className="td-evidence-missing-banner" role="alert">
          <span className="td-evidence-missing-icon" aria-hidden="true">
            <UiIcon name="warning" size={16} color="var(--warn-fg)" />
          </span>
          <div className="td-evidence-missing-copy">
            <div className="td-evidence-missing-title">源证据镜像路径已失效，当前无法读取原镜像字节内容</div>
            <div className="td-evidence-missing-desc">
              原路径：<span className="td-mono">{evidence.path}</span> · 若镜像已迁移目录或更换盘符，请重新定位并由系统核验 SHA-256 一致后安全重绑。
            </div>
          </div>
          <button
            type="button"
            className="td-btn td-btn--warningAction"
            disabled={busy}
            onClick={onRebindImagePath}
          >
            <UiIcon name="locate" size={14} color="var(--warn-fg)" />
            重新定位源镜像…
          </button>
        </div>
      )}

      <SplitPane
        direction="vertical"
        initialSize={0.56}
        minFirst={160}
        minSecond={140}
        first={<DossierView title="镜像与文件系统" subtitle={subtitle} sections={sections} />}
        second={
          <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            <div className="td-panel-section-bar">
              <span className="td-section-title" style={{ flex: 1 }}>
                分区布局与文件系统 · 原始解析结果
              </span>
              {evidence && partitions.length > 0 && (
                <>
                  <select
                    className="td-select td-mono"
                    style={{ fontSize: 12 }}
                    aria-label="选择导出 fsstat 的分区"
                    value={selectedOffset}
                    disabled={busy}
                    onChange={(e) => setSelectedOffset(Number(e.target.value))}
                  >
                    {partitions.map((p) => (
                      <option key={p.offset} value={p.offset}>
                        偏移 {p.offset} 扇区
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="td-btn"
                    disabled={busy}
                    onClick={() => onExportFsstat(selectedOffset)}
                  >
                    <UiIcon name="export" size={14} color="var(--text-secondary)" />
                    导出完整 fsstat
                  </button>
                </>
              )}
            </div>
            <pre className="td-raw-viewer">
              {rawText || '尚未加载镜像或无原始分区表与文件系统输出。'}
            </pre>
          </div>
        }
      />
    </div>
  );
};

export const EvidenceInfoModule = React.memo(EvidenceInfoModuleInner);
