"""镜像载入、自动全分区扫描、完整性校验与镜像信息页。"""
from threading import Event
from PySide6.QtWidgets import QMessageBox

from ..core.coverage import SOURCE_FIELDS, source_status
from ..core.formatting import display_time
from ..core.browser_index import prepare
from ..paths import EVIDENCE_DIR
from ..ui.dialogs import RAW_IMAGE_FILTER, choose_file, edit_evidence_source
from ..ui.analysis_panels import EvidencePanel
from ..ui.views import ExportResultDialog
from .api import Action, Feature, Panel


def image_loaded(context, _):
    context.refresh(reset=True)
    resume_partitions(context)


def load(context):
    if context.available():
        path = choose_file(
            context.root, '选择 RAW 镜像或 E01 首段', str(EVIDENCE_DIR),
            RAW_IMAGE_FILTER)
        if path:
            context.task('打开镜像并识别分区', lambda: context.case().load(path, progress=lambda n, size: context.progress('固定镜像 SHA-256', n, size)),
                         lambda result: image_loaded(context, result))


def directory_listing(case, offset, inode=None, path=''):
    entries = case.browse_directory(offset, inode, path)
    if len(entries) > 1000:
        case.browser_index = prepare(entries)


def resume_partitions(context):
    case = context.case()
    if case is None:
        return
    if (case.data.get('evidence') or {}).get('large_image'):
        if case.browsing_directories:
            def first_root():
                failures = []
                for partition in case.data['evidence']['partitions']:
                    try:
                        return directory_listing(case, partition['offset'])
                    except (RuntimeError, OSError, ValueError) as error:
                        failures.append(f"偏移 {partition['offset']}：{error}")
                raise ValueError('无法读取根目录：' + '；'.join(failures))
            context.task('读取分区根目录', first_root, lambda _: context.refresh(reset=True))
    elif case.needs_partition_scan():
        scan(context)


def browse_dir(context, offset, inode, path):
    if context.available():
        case = context.case()
        context.task('读取目录 /' + path, lambda: directory_listing(case, offset, inode, path),
                     lambda _: context.refresh(reset=True))


def scan(context):
    if context.available() and context.case().data['evidence']:
        case = context.case()
        cancel = Event() if case.data['evidence'].get('large_image') else None
        context.browser().index_cancel = cancel

        def work():
            try:
                entries = case.scan_all(progress=context.progress, cancel=cancel)
            except InterruptedError:
                return False
            if len(entries) > 1000:
                case.browser_index = prepare(entries)
            return True

        def done(completed):
            if completed:
                context.refresh(reset=True)
            else:
                context.browser().detail.setText('已取消建立索引，保留原有浏览结果。')
        context.task('读取所有分区与文件树', work, done)


def verify(context):
    if context.available():
        if not context.case().data['evidence']:
            QMessageBox.information(context.root, '提示', '请先加载镜像。')
            return
        if context.case().data['evidence'].get('large_image'):
            context.hash_image()
            return
        context.task('流式校验 SHA-256', lambda: context.case().verify(lambda n, size: context.progress('校验 SHA-256', n, size)), lambda ok: QMessageBox.information(
            context.root, '完整性校验', '通过：与初始固定值一致。' if ok else '失败：原始镜像已发生变化！'))


def information(context):
    case = context.case()
    if case is None:
        return '尚未打开案件'
    evidence = case.data['evidence']
    fixed = display_time(evidence['fixed_at']) if evidence and evidence['fixed_at'] else '待固定'
    text = (f'原始镜像：{evidence["path"]}\n字节数：{evidence["size"]}\n'
            f'固定时间：{fixed}\nSHA-256：{evidence["sha256"]}\n\n'
            f'{evidence["layout"]}' if evidence else '尚未加载镜像')
    return text + '\n\n' + case.data.get('fsstat', '')


def register_source(context, on_saved=None):
    if not context.available():
        return
    case = context.case()
    if not case.data['evidence']:
        QMessageBox.information(context.root, '提示', '请先加载镜像。')
        return
    values = edit_evidence_source(context.root, SOURCE_FIELDS, case.data['evidence'].get('provenance'))
    if values is not None:
        callback = on_saved or (lambda _: None)
        context.task('登记来源', lambda: case.register_source(values), callback)


def panel_data(context):
    case = context.case()
    if not case:
        return {}
    def export_details(offset):
        if context.available():
            context.task('读取完整文件系统详情', lambda: case.export_fsstat(offset),
                         lambda path: ExportResultDialog(context.root, path, '文件系统详情已导出').exec())
    return {**case.data, 'export_fsstat': export_details,
            'register_source': lambda: register_source(context)}


def information_version(context):
    case = context.case()
    return (id(case), id(case.data['evidence']), case.data.get('fsstat')) if case else None


FEATURE = Feature('evidence', requires=('cases',), actions=(
    Action('load', load, '加载镜像', 'evidence', 'accent'),
    Action('verify', verify, '校验完整性', 'evidence'),
    Action('scan', scan), Action('browse_dir', browse_dir),
    Action('resume_partitions', resume_partitions),
), panels=(Panel('info', '镜像与文件系统', panel_data, information_version, EvidencePanel),),
    case_changed=resume_partitions)
