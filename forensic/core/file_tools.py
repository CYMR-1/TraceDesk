"""镜像内文件级取证操作；结果绑定镜像、分区、路径和 inode。"""
import hashlib

from .case import sha256
from ..engines.tsk import TSK, can_export, deleted_source_note


def identity(case, entry):
    if entry not in case.displayed_entries() or not can_export(entry):
        raise ValueError('请选择当前案件清单中的普通文件')
    return dict(image_sha256=case.data['evidence']['sha256'], offset=entry['offset'],
                inode=entry['inode'], deleted=entry.get('deleted', False))


def record_note(case, entry, text):
    reference = identity(case, entry)
    if case.source_note():
        case.operation_check()
        reference['source_verification'] = case.source_note()
    if not text.strip():
        raise ValueError('记录内容不能为空')
    case.log('FILE_NOTE', entry['path'], '成功', **reference, note=text.strip())


def examine(case, entry, comparison=None, tool=None):
    reference = identity(case, entry)
    operation = 'FILE_COMPARE' if comparison is not None else 'FILE_HASH'
    details = {**reference, 'recorded_size': entry['size']}
    if comparison is not None:
        details['comparison'] = str(comparison)
    try:
        if not case.operation_check():
            raise ValueError('原始镜像校验失败')
        if case.source_note():
            details['source_verification'] = case.source_note()
        tool = tool or TSK()
        digest = hashlib.sha256()
        size, note = tool.stream_entry(case.image(), entry, digest.update)
        if note:
            details['read_note'] = note
        details.update(size=size, sha256=digest.hexdigest())
        if not case.operation_check():
            raise ValueError('读取期间原始镜像发生变化')
        result = '成功'
        if comparison is not None:
            details['comparison_sha256'] = sha256(comparison)
            result = '一致' if details['sha256'] == details['comparison_sha256'] else '不一致'
        if size < entry['size']:
            result = '部分读取' if comparison is None else '部分读取，无法确认完整一致性'
        details['source_note'] = deleted_source_note(entry) if entry.get('deleted') else ''
        case.log(operation, entry['path'], result, **details)
        return result, details
    except Exception as error:
        case.log(operation, entry['path'], '失败', **details, error=str(error))
        raise
