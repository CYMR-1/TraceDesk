"""镜像载入、自动全分区扫描、完整性校验与镜像信息页。"""
from PySide6.QtWidgets import QMessageBox

from ..core.formatting import display_time
from ..paths import EVIDENCE_DIR
from ..ui.dialogs import RAW_IMAGE_FILTER, choose_file
from ..ui.analysis_panels import EvidencePanel
from .api import Action, Feature, Panel


def image_loaded(context, _):
    context.refresh(reset=True)
    scan(context)


def load(context):
    if context.available():
        path = choose_file(
            context.root, '选择案件库之外的 RAW 镜像', str(EVIDENCE_DIR),
            RAW_IMAGE_FILTER)
        if path:
            context.task('固定镜像并识别分区', lambda: context.case().load(path),
                         lambda result: image_loaded(context, result))


def resume_partitions(context):
    if context.case().needs_partition_scan():
        scan(context)


def scan(context):
    if context.available() and context.case().data['evidence']:
        context.task('自动读取所有分区与文件树', context.case().scan_all,
                     lambda _: context.refresh(reset=True))


def verify(context):
    if context.available():
        context.task('流式校验 SHA-256', context.case().verify, lambda ok: QMessageBox.information(
            context.root, '完整性校验', '通过：与初始固定值一致。' if ok else '失败：原始镜像已发生变化！'))


def information(context):
    case = context.case()
    if case is None:
        return '尚未打开案件'
    evidence = case.data['evidence']
    text = (f'原始镜像：{evidence["path"]}\n字节数：{evidence["size"]}\n'
            f'固定时间：{display_time(evidence["fixed_at"])}\nSHA-256：{evidence["sha256"]}\n\n'
            f'{evidence["layout"]}' if evidence else '尚未加载镜像')
    return text + '\n\n' + case.data.get('fsstat', '')


def information_version(context):
    case = context.case()
    return (id(case), id(case.data['evidence']), case.data.get('fsstat')) if case else None


FEATURE = Feature('evidence', requires=('cases',), actions=(
    Action('load', load, '加载 RAW 镜像', 'evidence', 'accent'),
    Action('verify', verify, '校验完整性', 'evidence'),
    Action('scan', scan),
    Action('resume_partitions', resume_partitions),
), panels=(Panel('info', '镜像与文件系统', lambda context: context.case().data if context.case() else {}, information_version, EvidencePanel),),
    case_changed=resume_partitions)
