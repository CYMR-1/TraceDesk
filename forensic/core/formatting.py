"""无界面依赖的时间、删除文件说明格式化。"""
from datetime import datetime, timedelta, timezone
from ..engines.tsk import deleted_source_note


EAST_8 = timezone(timedelta(hours=8))


def now():
    return datetime.now(EAST_8).isoformat()


def deleted_export_summary(record):
    if not record.get('deleted'):
        return ''
    result = '部分导出' if record['size'] < record['recorded_size'] else '已导出'
    size = f"{result} {record['size']} / {record['recorded_size']} 字节"
    return ' · '.join(filter(None, (deleted_source_note(record), f"inode {record['inode']}",
                                   size, record.get('read_note'))))


def display_time(value, *, compact=False):
    """将案件里的 ISO 时间或文件系统的 Unix 时间戳显示为东八区时间。"""
    if isinstance(value, str):
        stamp = datetime.fromisoformat(value)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        stamp = stamp.astimezone(EAST_8)
    else:
        if value <= 0:
            return '未记录'
        stamp = datetime.fromtimestamp(value, EAST_8)
    return stamp.strftime('%Y-%m-%d %H:%M:%S') if compact else stamp.isoformat()
