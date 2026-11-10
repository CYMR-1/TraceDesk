"""以参数数组调用官方 TSK，只开放读取命令，不使用 shell。"""
import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Windows 版 TSK 按本机 ANSI 代码页输出文本，独立于启动终端的 chcp。
TSK_TEXT_ENCODING = 'mbcs' if os.name == 'nt' else 'utf-8'


def tsk_error(data):
    return data.decode(TSK_TEXT_ENCODING, errors='replace').strip()[:2000]


def entry_status(entry):
    if entry.get('deleted'):
        return '已删除·重分配' if entry.get('reallocated') else '已删除'
    if entry['mode'].startswith('V/'):
        return '虚拟目录'
    if entry['mode'].startswith('v/'):
        return '系统区域'
    return '现存'


def can_export(entry):
    return not entry.get('directory') and (entry['mode'].startswith('r/') or
                                           (entry.get('deleted', False) and entry['mode'].startswith('-/r')))


def deleted_source_note(entry):
    if entry.get('reallocated'):
        return '已删除 · inode 已重分配，数据来自该 inode 当前内容'
    if entry.get('start_cluster_allocated'):
        return '已删除 · 起始簇已被占用，原内容可能已覆盖'
    return '已删除，原内容可能已覆盖' if entry.get('deleted') else ''


def entry_name(entry):
    name = entry['path'].rsplit('/', 1)[-1]
    if entry['mode'].startswith('v/'):
        if name == '$MBR':
            return '引导扇区 ($MBR)'
        if re.fullmatch(r'\$FAT\d+', name):
            return f'FAT {name[4:]} ({name})'
    return name


class TSK:
    def __init__(self, directory=None):
        candidates = [Path(directory)] if directory else []
        if os.environ.get('TSK_BIN'):
            candidates.append(Path(os.environ['TSK_BIN']))
        candidates += list((ROOT / 'tools').glob('**/bin'))
        self.bin = next((p for p in candidates if (p / 'fls.exe').exists() or (p / 'fls').exists()), None)
        if not self.bin and not shutil.which('fls'):
            raise RuntimeError('未找到 Sleuth Kit。请运行 scripts/install_tsk.ps1，或设置 TSK_BIN 为 bin 目录。')

    def command(self, name, args):
        if name not in ('mmls', 'fsstat', 'fls', 'icat'):
            raise ValueError('仅允许只读 TSK 命令')
        exe = str(self.bin / (name + ('.exe' if os.name == 'nt' else ''))) if self.bin else shutil.which(name)
        if not exe or not Path(exe).is_file():
            raise RuntimeError(f'缺少 Sleuth Kit 工具 {name}，请检查 TSK_BIN')
        return [exe, *map(str, args)]

    def run(self, name, args, **streams):
        try:
            return subprocess.run(self.command(name, args), timeout=300,
                                  creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), **streams)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError(f'{name} 执行超时（300 秒）') from error
        except OSError as error:
            raise RuntimeError(f'无法启动 {name}：{error}') from error

    def text(self, name, args):
        result = self.run(name, args, capture_output=True)
        if result.returncode:
            raise RuntimeError(tsk_error(result.stderr))
        return result.stdout.decode(TSK_TEXT_ENCODING, errors='strict' if name == 'fls' else 'replace')

    def inspect(self, image):
        # mmls 失败可能仅代表无分区表；必须再由 fsstat 验证是否为分区镜像。
        try:
            raw = self.text('mmls', ['-i', 'raw', image])
            offsets = []
            for line in raw.splitlines():
                m = re.match(r'^\s*\d+:\s+\d+:\d+\s+(\d+)\s+\d+\s+\d+\s+(.+)', line)
                if m and not any(s in m[2].lower() for s in ('unallocated', 'extended')):
                    offsets.append({'offset': int(m[1]), 'description': m[2]})
            if not offsets:
                raise RuntimeError('分区表中未发现可分析分区')
            return raw, offsets
        except RuntimeError as error:
            self.text('fsstat', ['-i', 'raw', '-o', 0, image])
            return f'无可解析分区表，fsstat 确认偏移 0 的文件系统。\n{error}', [{'offset': 0, 'description': '分区镜像 / 文件系统位于偏移 0'}]

    def files(self, image, offset):
        # FAT 等文件系统没有内置时区，本课程原型明确按 UTC 解释，避免依赖宿主时区。
        # 分别读取两种分配状态，以免把原名恰好以 " (deleted)" 结尾的正常文件误判为删除项。
        entries = []
        for flag in ('-u', '-d'):
            raw = self.text('fls', ['-i', 'raw', '-o', offset, '-z', 'UTC', '-r', flag, '-p', '-m', '/', image])
            entries.extend(self._body_entries(raw, offset, deleted=(flag == '-d')))
        return entries

    @staticmethod
    def _body_entries(raw, offset, deleted):
        for line in raw.splitlines():
            parts = line.split('|')
            if len(parts) < 11:
                raise RuntimeError('无法解析 fls bodyfile 行：' + line[:150])
            tail = parts[-9:]
            inode, mode, uid, gid, size, atime, mtime, ctime, crtime = tail
            path = '|'.join(parts[1:-9]).lstrip('/')
            reallocated = deleted and path.endswith(' (deleted-realloc)')
            if deleted:
                path = re.sub(r' \(deleted(?:-realloc)?\)$', '', path)
            yield dict(path=path, inode=inode, mode=mode, size=int(size), deleted=deleted, reallocated=reallocated,
                       atime=int(atime), mtime=int(mtime), ctime=int(ctime), crtime=int(crtime),
                       directory=mode.startswith(('d', 'V')), offset=offset)

    def file_args(self, image, offset, inode, *, recover=False):
        if not re.fullmatch(r'\d+(?:-\d+)*', str(inode)):
            raise ValueError('非法 inode')
        args = ['-i', 'raw', '-o', offset, image, inode]
        return ['-r', *args] if recover else args

    def export(self, image, offset, inode, destination):
        args = self.file_args(image, offset, inode)
        # icat 的 stdout 直接落盘，文件内容不经过文本解码，也不整文件载入内存。
        with destination.open('xb') as output:
            result = self.run('icat', args,
                              stdout=output, stderr=subprocess.PIPE)
        if result.returncode:
            destination.unlink(missing_ok=True)
            raise RuntimeError(tsk_error(result.stderr))

    def entry_args(self, image, entry):
        return self.file_args(image, entry['offset'], entry['inode'],
                              recover=entry.get('deleted', False) and not entry.get('reallocated'))

    def export_deleted(self, image, entry, destination):
        """按预览使用的 inode 和恢复模式写入可读前缀，返回读取状态说明。"""
        args = self.entry_args(image, entry)
        limit = entry['size']
        with destination.open('xb') as output:
            if limit == 0:
                return ''
            with tempfile.TemporaryFile() as errors, subprocess.Popen(
                    self.command('icat', args), stdout=subprocess.PIPE, stderr=errors,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)) as process:
                timeout = threading.Timer(300, process.kill)
                timeout.start()
                try:
                    written = 0
                    while written < limit:
                        block = process.stdout.read(min(1024 * 1024, limit - written))
                        if not block:
                            break
                        written += output.write(block)
                    if written == limit and process.stdout.read(1):
                        return '已按目录记录大小截取'
                    if process.wait():
                        errors.seek(0)
                        note = tsk_error(errors.read(2000)) or 'icat 未正常完成读取'
                        if written:
                            return note
                        raise OSError(note)
                    if not written:
                        raise OSError('未能从该删除记录读取数据')
                    return ''
                finally:
                    timeout.cancel()
                    process.kill()
