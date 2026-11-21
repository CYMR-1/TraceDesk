/**
 * TraceDesk Tauri 2 IPC 完整类型封装层（Commands + Streaming Events + Native Dialogs）
 * - 在 Tauri WebView2 环境：严格调用 @tauri-apps/api/core invoke、@tauri-apps/api/event listen 与 @tauri-apps/plugin-dialog open。
 * - 在非 Tauri 浏览器预览环境：优雅降级到只读 demoBackend，便于独立预览与验证。
 */

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import type {
  AppPaths,
  BuildTimelineResponse,
  BundleMaterialsResponse,
  CaseSnapshot,
  EntryView,
  ExamineFileResponse,
  ExportFileResponse,
  ExportFindingsResponse,
  HashFinishedEvent,
  HashProgressEvent,
  ListAuditLogResponse,
  ListFindingsResponse,
  LocateFileResponse,
  McpStatus,
  PreviewEncoding,
  PreviewImageResponse,
  PreviewPageResponse,
  QueryFilesPageResponse,
  QueryTimelinePageResponse,
  SearchEncoding,
  SearchFinishedEvent,
  SearchHitsEvent,
  SearchProgressEvent,
  StartContentSearchResponse,
  SuggestCaseDirResponse,
  TaskProgressEvent,
  TreeChildrenResponse,
} from '../types/ipc';
import { demoBackend, demoListen } from './demoBackend';

export function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

async function callCommand<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauriRuntime()) {
    return invoke<T>(cmd, args);
  }
  const backend = demoBackend as unknown as Record<
    string,
    (a?: Record<string, unknown>) => Promise<unknown>
  >;
  const fn = backend[cmd];
  if (!fn) {
    throw new Error(`演示模式未实现命令：${cmd}`);
  }
  return (await fn.call(demoBackend, args)) as T;
}

/* ---------- 3.1 App 状态与案件管理 Commands ---------- */

export const tauriApi = {
  getAppPaths(): Promise<AppPaths> {
    return callCommand<AppPaths>('get_app_paths', {});
  },

  suggestCaseDir(params: {
    number: string;
    examiner: string;
    target: string;
    parentDir?: string;
  }): Promise<SuggestCaseDirResponse> {
    return callCommand<SuggestCaseDirResponse>('suggest_case_dir', params);
  },

  createCase(params: {
    parentDir: string;
    number: string;
    examiner: string;
    target: string;
    folderName?: string;
  }): Promise<CaseSnapshot> {
    return callCommand<CaseSnapshot>('create_case', params);
  },

  openCase(params: { casePath: string }): Promise<CaseSnapshot> {
    return callCommand<CaseSnapshot>('open_case', params);
  },

  closeCase(): Promise<{ closed: boolean }> {
    return callCommand<{ closed: boolean }>('close_case', {});
  },

  getCaseSnapshot(): Promise<CaseSnapshot | null> {
    return callCommand<CaseSnapshot | null>('get_case_snapshot', {});
  },

  /* ---------- 3.2 证据镜像与文件浏览 Commands ---------- */

  loadImage(params: { imagePath: string }): Promise<CaseSnapshot> {
    return callCommand<CaseSnapshot>('load_image', params);
  },

  verifyIntegrity(): Promise<{ ok: boolean; initialFixed: boolean; snapshot: CaseSnapshot }> {
    return callCommand<{ ok: boolean; initialFixed: boolean; snapshot: CaseSnapshot }>('verify_integrity', {});
  },

  cancelVerifyIntegrity(): Promise<{ cancelled: boolean }> {
    return callCommand<{ cancelled: boolean }>('cancel_verify_integrity', {});
  },

  registerSource(params: {
    evidenceId: string;
    source: string;
    acquired: string;
    tool: string;
    expectedSha256: string;
  }): Promise<CaseSnapshot> {
    return callCommand<CaseSnapshot>('register_source', params);
  },

  exportFsstat(params: { offset: number }): Promise<{ path: string }> {
    return callCommand<{ path: string }>('export_fsstat', params);
  },

  scanAllPartitions(): Promise<{ completed: boolean; snapshot: CaseSnapshot }> {
    return callCommand<{ completed: boolean; snapshot: CaseSnapshot }>('scan_all_partitions', {});
  },

  cancelScanPartitions(): Promise<{ cancelled: boolean }> {
    return callCommand<{ cancelled: boolean }>('cancel_scan_partitions', {});
  },

  browseDirectory(params: {
    offset: number;
    inode?: string | null;
    path: string;
  }): Promise<{ snapshot: CaseSnapshot; entries: EntryView[] }> {
    return callCommand<{ snapshot: CaseSnapshot; entries: EntryView[] }>('browse_directory', params);
  },

  getTreeChildren(params: {
    offset: number;
    scopePath: string;
    groupIndex?: number;
  }): Promise<TreeChildrenResponse> {
    return callCommand<TreeChildrenResponse>('get_tree_children', params);
  },

  queryFilesPage(params: {
    scopeOffset?: number | null;
    scopePath?: string | null;
    suffix: string;
    keyword: string;
    status: 'all' | 'active' | 'deleted';
    page: number;
    pageSize: number;
    logFilter?: boolean;
  }): Promise<QueryFilesPageResponse> {
    return callCommand<QueryFilesPageResponse>('query_files_page', params);
  },

  locateFileInScope(params: { entryId: string }): Promise<LocateFileResponse> {
    return callCommand<LocateFileResponse>('locate_file_in_scope', params);
  },

  /* ---------- 3.3 文件预览、导出与取证发现 Commands ---------- */

  previewFilePage(params: {
    entryId: string;
    page: number;
    pageBytes?: number;
    encoding: PreviewEncoding;
  }): Promise<PreviewPageResponse> {
    return callCommand<PreviewPageResponse>('preview_file_page', {
      pageBytes: 4096,
      ...params,
    });
  },

  previewFileImage(params: { entryId: string }): Promise<PreviewImageResponse> {
    return callCommand<PreviewImageResponse>('preview_file_image', params);
  },

  exportFile(params: { entryId: string }): Promise<ExportFileResponse> {
    return callCommand<ExportFileResponse>('export_file', params);
  },

  recordFindingNote(params: { entryId: string; note: string }): Promise<{ snapshot: CaseSnapshot }> {
    return callCommand<{ snapshot: CaseSnapshot }>('record_finding_note', params);
  },

  examineFile(params: { entryId: string; comparisonPath?: string }): Promise<ExamineFileResponse> {
    return callCommand<ExamineFileResponse>('examine_file', params);
  },

  listFindings(params: {
    status?: string | null;
    offset?: string | null;
    keyword?: string;
    sortColumn: 'seq' | 'latest';
    descending: boolean;
  }): Promise<ListFindingsResponse> {
    return callCommand<ListFindingsResponse>('list_findings', params);
  },

  exportFindings(params: { groupKeys: string[] }): Promise<ExportFindingsResponse> {
    return callCommand<ExportFindingsResponse>('export_findings', params);
  },

  /* ---------- 3.4 时间线、审计、内容搜索与复核包 Commands ---------- */

  buildTimeline(): Promise<BuildTimelineResponse> {
    return callCommand<BuildTimelineResponse>('build_timeline', {});
  },

  queryTimelinePage(params: {
    query: string;
    event?: string | null;
    status?: string | null;
    offset?: string | null;
    sortColumn: 'seq' | 'time';
    descending: boolean;
    page: number;
    pageSize: number;
  }): Promise<QueryTimelinePageResponse> {
    return callCommand<QueryTimelinePageResponse>('query_timeline_page', params);
  },

  listAuditLog(params: {
    query: string;
    origin?: string | null;
    actor?: string | null;
    action?: string | null;
    result?: string | null;
    sortColumn: 'seq' | 'time';
    descending: boolean;
  }): Promise<ListAuditLogResponse> {
    return callCommand<ListAuditLogResponse>('list_audit_log', params);
  },

  startContentSearch(params: {
    query: string;
    encoding: SearchEncoding;
    selectedEntryId?: string | null;
  }): Promise<StartContentSearchResponse> {
    return callCommand<StartContentSearchResponse>('start_content_search', params);
  },

  cancelContentSearch(params: { searchId: string }): Promise<{ cancelled: boolean }> {
    return callCommand<{ cancelled: boolean }>('cancel_content_search', params);
  },

  bookmarkSearchHits(params: {
    searchId: string;
    hitIndices: number[];
  }): Promise<{ savedCount: number; snapshot: CaseSnapshot }> {
    return callCommand<{ savedCount: number; snapshot: CaseSnapshot }>('bookmark_search_hits', params);
  },

  generateReport(): Promise<{ path: string; snapshot: CaseSnapshot }> {
    return callCommand<{ path: string; snapshot: CaseSnapshot }>('generate_report', {});
  },

  inspectBundleMaterials(): Promise<BundleMaterialsResponse> {
    return callCommand<BundleMaterialsResponse>('inspect_bundle_materials', {});
  },

  buildReviewBundle(params: {
    selectedExportIndices?: number[];
    selectedSearchIndices?: number[];
  }): Promise<{ path: string; snapshot: CaseSnapshot }> {
    return callCommand<{ path: string; snapshot: CaseSnapshot }>('build_review_bundle', params);
  },

  /* ---------- 3.5 MCP 托管与系统工具 Commands ---------- */

  getMcpStatus(params?: { port?: number }): Promise<McpStatus> {
    return callCommand<McpStatus>('get_mcp_status', params || {});
  },

  startMcpHttp(params: { port: number }): Promise<McpStatus> {
    return callCommand<McpStatus>('start_mcp_http', params);
  },

  stopMcpHttp(): Promise<McpStatus> {
    return callCommand<McpStatus>('stop_mcp_http', {});
  },

  openInOs(params: { path: string; revealFolder: boolean }): Promise<{ ok: boolean }> {
    return callCommand<{ ok: boolean }>('open_in_os', params);
  },

  checkBusyBeforeClose(): Promise<{ busy: boolean; reason?: string }> {
    return callCommand<{ busy: boolean; reason?: string }>('check_busy_before_close', {});
  },

  /* ---------- Native File / Folder Pickers (@tauri-apps/plugin-dialog) ---------- */

  async pickFile(options: {
    title: string;
    defaultPath?: string;
    filters?: { name: string; extensions: string[] }[];
  }): Promise<string | null> {
    if (!isTauriRuntime()) {
      return null;
    }
    const selected = await openDialog({
      title: options.title,
      defaultPath: options.defaultPath,
      multiple: false,
      directory: false,
      filters: options.filters,
    });
    return typeof selected === 'string' ? selected : null;
  },

  async pickDirectory(options: { title: string; defaultPath?: string }): Promise<string | null> {
    if (!isTauriRuntime()) {
      return null;
    }
    const selected = await openDialog({
      title: options.title,
      defaultPath: options.defaultPath,
      multiple: false,
      directory: true,
    });
    return typeof selected === 'string' ? selected : null;
  },
};

/* ---------- 3.6 流式 Tauri Events 监听 ---------- */

export const tauriEvents = {
  onTaskProgress(handler: (payload: TaskProgressEvent) => void): Promise<UnlistenFn> {
    if (isTauriRuntime()) {
      return listen<TaskProgressEvent>('task:progress', (e) => handler(e.payload));
    }
    return Promise.resolve(demoListen('task:progress', handler));
  },

  onHashProgress(handler: (payload: HashProgressEvent) => void): Promise<UnlistenFn> {
    if (isTauriRuntime()) {
      return listen<HashProgressEvent>('hash:progress', (e) => handler(e.payload));
    }
    return Promise.resolve(demoListen('hash:progress', handler));
  },

  onHashFinished(handler: (payload: HashFinishedEvent) => void): Promise<UnlistenFn> {
    if (isTauriRuntime()) {
      return listen<HashFinishedEvent>('hash:finished', (e) => handler(e.payload));
    }
    return Promise.resolve(demoListen('hash:finished', handler));
  },

  onSearchHits(handler: (payload: SearchHitsEvent) => void): Promise<UnlistenFn> {
    if (isTauriRuntime()) {
      return listen<SearchHitsEvent>('search:hits', (e) => handler(e.payload));
    }
    return Promise.resolve(demoListen('search:hits', handler));
  },

  onSearchProgress(handler: (payload: SearchProgressEvent) => void): Promise<UnlistenFn> {
    if (isTauriRuntime()) {
      return listen<SearchProgressEvent>('search:progress', (e) => handler(e.payload));
    }
    return Promise.resolve(demoListen('search:progress', handler));
  },

  onSearchFinished(handler: (payload: SearchFinishedEvent) => void): Promise<UnlistenFn> {
    if (isTauriRuntime()) {
      return listen<SearchFinishedEvent>('search:finished', (e) => handler(e.payload));
    }
    return Promise.resolve(demoListen('search:finished', handler));
  },
};
