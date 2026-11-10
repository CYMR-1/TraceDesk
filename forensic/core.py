"""案件隔离、证据固定、追加审计与报告。所有证据文件均以 rb 打开。"""
import msvcrt
import tempfile
import hashlib
import json
import os
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from itertools import count
from pathlib import Path
from .fat import fat_regions
from .tsk import TSK, can_export, deleted_source_note, entry_name, entry_status


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


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def save_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(temporary, path)


def sha256(path, progress=None):
    """固定 1 MiB 缓冲区，检查读取期间的文件身份和元数据变化。"""
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        before = os.fstat(source.fileno())
        done = 0
        while block := source.read(1024 * 1024):
            digest.update(block)
            done += len(block)
            if progress:
                progress(done, before.st_size)
        after = os.fstat(source.fileno())
    fields = ('st_size', 'st_mtime_ns', 'st_ino', 'st_dev')
    current = Path(path).stat()
    if any(getattr(before, f) != getattr(snapshot, f) for snapshot in (after, current) for f in fields):
        raise RuntimeError('哈希计算期间证据发生变化，请停止分析')
    return digest.hexdigest()


def within(path, parent):
    return Path(path).resolve().is_relative_to(Path(parent).resolve())


def windows_filename(name, max_units=255):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    device = name.partition('.')[0].rstrip(' ').upper()
    if re.fullmatch(r'CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³]', device):
        name = '_' + name
    # Windows 的单个文件名最多有 255 个 UTF-16 码元。
    name = name.encode('utf-16-le')[:2 * max_units].decode('utf-16-le', errors='ignore')
    return name.rstrip(' .') or 'file'


def export_filename(source_path):
    return windows_filename(source_path.rsplit('/', 1)[-1])


class Case:
    def __init__(self, folder, actor=None):
        self.folder = Path(folder).resolve()
        metadata = self.folder / 'case.json'
        if not metadata.is_file():
            raise ValueError('缺少案件元数据 case.json')
        self._lease = (self.folder / 'case.lock').open('a+b')
        try:
            self._lease.seek(0)
            msvcrt.locking(self._lease.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            self.close()
            raise RuntimeError('案件已被占用或无法加锁') from error
        try:
            self.data = json.loads(metadata.read_text(encoding='utf-8'))
            for key in ('id', 'examiner', 'number', 'target', 'created'):
                if not isinstance(self.data[key], str) or not self.data[key].strip():
                    raise ValueError(key)
            if not all(isinstance(self.data[k], list) for k in ('inventory', 'exports')):
                raise ValueError('案件清单格式错误')
            evidence = self.data['evidence']
            if evidence is not None:
                if not all(k in evidence for k in ('path','sha256','layout','partitions','fixed_at','size')):
                    raise ValueError('证据信息不完整')
            if not all((self.folder / k).is_dir() for k in ('reports','exports')):
                raise ValueError('案件输出目录缺失')
            self.actor = actor or self.data['examiner']
            self.lock = threading.RLock()
            self.check_audit()
        except (KeyError, TypeError, ValueError) as error:
            self.close()
            raise ValueError(f'案件数据损坏：{error}') from error
        except Exception:
            self.close()
            raise

    def close(self):
        self._lease.close()

    @classmethod
    def create(cls, root, number, examiner, target):
        fields = (number, examiner, target)
        if not all(isinstance(field, str) and field.strip() for field in fields):
            raise ValueError('案件编号、取证人员和取证对象不能为空')
        root = Path(root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        parts = [field.strip() for field in fields]
        name = '-'.join(parts)
        if len(name.encode('utf-16-le')) > 510:
            # 超长时为三个字段分别分配空间，每段最多 84 个 UTF-16 码元。
            name = '-'.join(p.encode('utf-16-le')[:168].decode('utf-16-le', 'ignore') for p in parts)
        for index in count(1):
            suffix = '' if index == 1 else f' ({index})'
            folder = root / (windows_filename(name, 255 - len(suffix)) + suffix)
            try:
                folder.mkdir()
                break
            except FileExistsError:
                continue
        (folder / 'exports').mkdir()
        (folder / 'reports').mkdir()
        save_json(folder / 'case.json', dict(id=uuid.uuid4().hex, number=number, examiner=examiner,
                  target=target, created=now(), evidence=None, inventory=[], exports=[]))
        (folder / 'audit.jsonl').touch()
        case = cls(folder)
        case.log('CASE_CREATE', number, '成功')
        return case

    def save(self, **changes):
        if self._lease.closed:
            raise RuntimeError('案件已关闭')
        candidate = {**self.data, **changes}
        save_json(self.folder / 'case.json', candidate)
        self.data = candidate

    def check_audit(self):
        previous = '0' * 64
        records = []
        for index, line in enumerate((self.folder / 'audit.jsonl').read_text(encoding='utf-8').splitlines(), 1):
            record = json.loads(line)
            signature = record.pop('hash')
            if record['seq'] != index or record['previous'] != previous or hashlib.sha256(canonical(record).encode()).hexdigest() != signature:
                raise RuntimeError(f'审计链第 {index} 条记录不完整或被修改')
            record['hash'] = signature
            previous = signature
            records.append(record)
        # 尾部锚点可发现直接截断日志；不能抵抗有权限者同时重写日志和锚点。
        anchor = self.folder / 'audit.head'
        if anchor.exists() and anchor.read_text().strip() != previous:
            raise RuntimeError('审计日志尾部锚点不匹配，可能被截断')
        if records and not anchor.exists():
            raise RuntimeError('审计尾部锚点缺失')
        return records

    def log(self, action, subject, result, **details):
        if self._lease.closed:
            raise RuntimeError('案件已关闭')
        with self.lock:
            records = self.check_audit()
            record = dict(seq=len(records)+1, timestamp=now(), actor=self.actor, action=action,
                          subject=str(subject), result=result, details=details,
                          previous=records[-1]['hash'] if records else '0'*64)
            record['hash'] = hashlib.sha256(canonical(record).encode()).hexdigest()
            # 日志只有追加入口，落盘后更新锚点。异常断电产生不一致时失败关闭。
            with (self.folder / 'audit.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(canonical(record)+'\n')
                stream.flush()
                os.fsync(stream.fileno())
            (self.folder / 'audit.head').write_text(record['hash'], encoding='ascii')

    def load(self, image, tsk=None, progress=None):
        if self.data['evidence']:
            raise ValueError('本原型每案固定一个镜像；请新建案件分析其他镜像')
        image = Path(image).resolve(strict=True)
        # 镜像必须位于整个案件库之外，防止落入当前案件或其他案件的输出目录。
        if not image.is_file() or within(image, self.folder.parent):
            raise ValueError('镜像必须是案件库目录之外的普通文件')
        self.log('IMAGE_LOAD_BEGIN', image, '开始')
        try:
            baseline = sha256(image, progress)
            self.log('HASH_FIXED', image, '成功', sha256=baseline)
            tsk = tsk or TSK()
            layout, partitions = tsk.inspect(image)
            evidence = dict(path=str(image), size=image.stat().st_size, sha256=baseline,
                            fixed_at=now(), partitions=partitions, layout=layout)
            self.save(evidence=evidence)
            self.log('IMAGE_LOAD', image, '成功', sha256=baseline, partitions=partitions)
        except Exception as error:
            self.log('IMAGE_LOAD', image, '失败', error=str(error))
            raise

    def image(self):
        if not self.data['evidence']:
            raise ValueError('请先加载 RAW 镜像')
        return self.data['evidence']['path']

    def verify(self, progress=None):
        try:
            actual = sha256(self.image(), progress)
            ok = actual == self.data['evidence']['sha256']
            self.save(verification=dict(time=now(), actual=actual, ok=ok))
            self.log('HASH_VERIFY', self.image(), '通过' if ok else '不匹配', actual=actual)
            return ok
        except Exception as error:
            self.log('HASH_VERIFY', self.data.get('evidence'), '失败', error=str(error))
            raise

    def scan(self, offset, tsk=None):
        allowed = [p['offset'] for p in self.data['evidence']['partitions']] if self.data['evidence'] else []
        if offset not in allowed:
            raise ValueError('请选择已识别分区')
        try:
            if not self.verify():
                raise RuntimeError('镜像校验失败，禁止扫描')
            tool = tsk or TSK()
            info = tool.text('fsstat', ['-i', 'raw', '-o', offset, self.image()])
            entries = tool.files(self.image(), offset)
            try:
                entries.extend(fat_regions(self.image(), offset, info, entries))
            except (ValueError, OSError, OverflowError) as error:
                info += f'\nFAT 空间区域未能映射：{error}'
            if not self.verify():
                raise RuntimeError('扫描期间镜像变化，文件清单未保存')
            self.save(inventory=entries, fsstat=info, offset=offset)
            self.log('FILE_BROWSE', f'{self.image()}@{offset}', '成功', count=len(entries))
            return entries
        except Exception as error:
            self.log('FILE_BROWSE', str(offset), '失败', error=str(error))
            raise

    def filtered(self, suffix='', keyword=''):
        suffix = suffix.strip().lower()
        if suffix and not suffix.startswith('.'):
            suffix = '.' + suffix
        items = [f for f in self.data['inventory'] if (not suffix or f['path'].lower().endswith(suffix))
                 and (keyword.lower() in f['path'].lower() or keyword.lower() in entry_name(f).lower())]
        self.log('FILE_FILTER', suffix or '*', '成功', keyword=keyword, count=len(items))
        return items

    def export(self, entry, tsk=None):
        with self.lock:
            return self._export(entry, tsk)

    def _export(self, entry, tsk):
        if entry not in self.data['inventory'] or not can_export(entry):
            raise ValueError('请选择当前文件清单中的普通文件或已删除文件')
        name = export_filename(entry['path'])
        folder = self.folder / 'exports'
        destination = folder / name
        duplicate_folder = None
        committed = False
        published = False
        try:
            if not self.verify():
                raise RuntimeError('原始镜像完整性校验失败，禁止导出')
            with tempfile.TemporaryDirectory(dir=folder) as staging:
                partial = Path(staging) / 'copy'
                tool = tsk or TSK()
                deleted = entry.get('deleted', False)
                read_note = ''
                if deleted:
                    read_note = tool.export_deleted(self.image(), entry, partial)
                else:
                    tool.export(self.image(), entry['offset'], entry['inode'], partial)
                size = partial.stat().st_size
                if not deleted and size != entry['size']:
                    raise RuntimeError('导出大小与文件元数据不一致')
                digest = sha256(partial)
                if not self.verify():
                    raise RuntimeError('导出期间原始镜像变化，副本不可采信')
                try:
                    partial.rename(destination)  # Windows 原子重命名，目标已存在时失败。
                except FileExistsError:
                    duplicate_folder = Path(tempfile.mkdtemp(prefix='同名副本-', dir=folder))
                    destination = duplicate_folder / name
                    partial.rename(destination)
                published = True
            record = dict(path=str(destination), source=entry['path'], inode=entry['inode'],
                          offset=entry['offset'], sha256=digest, size=size, time=now())
            if deleted:
                record.update(deleted=True, recorded_size=entry['size'], read_note=read_note,
                              reallocated=entry.get('reallocated', False),
                              start_cluster_allocated=entry.get('start_cluster_allocated', False))
            self.save(exports=[*self.data['exports'], record])
            committed = True
            self.log('FILE_EXPORT', entry['path'], '部分导出' if size < entry['size'] else '成功', **record)
            return destination
        except Exception as error:
            if published and not committed:
                destination.unlink(missing_ok=True)
            if duplicate_folder is not None and not committed:
                duplicate_folder.rmdir()
            self.log('FILE_EXPORT', entry['path'], '失败', error=str(error), inode=entry['inode'],
                     offset=entry['offset'], deleted=entry.get('deleted', False))
            raise

    def timeline_events(self):
        events = []
        for entry in self.data['inventory']:
            for field, label in [('mtime','M 内容修改'), ('atime','A 访问'), ('ctime','C 元数据变更'), ('crtime','B 创建')]:
                if entry[field] > 0:
                    events.append(dict(time=display_time(entry[field]),
                                       event=label, path=entry['path'], inode=entry['inode'], status=entry_status(entry)))
        return sorted(events, key=lambda row: row['time'])

    def timeline(self):
        events = self.timeline_events()
        self.log('TIMELINE', self.data.get('offset', ''), '成功', count=len(events))
        return events

    def report(self):
        try:
            return self._write_report()
        except Exception as error:
            self.log('REPORT_GENERATE', 'Markdown', '失败', error=str(error))
            raise

    def _write_report(self):
        if not self.verify():
            conclusion = '不通过：镜像当前 SHA-256 与固定值不一致。'
        else:
            conclusion = '通过：本次报告生成时镜像 SHA-256 与初始固定值一致。'
        self.log('REPORT_GENERATE', 'Markdown', '开始')
        records = self.check_audit()
        e = self.data['evidence']
        def cell(value):
            return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ').replace('<', '&lt;').replace('>', '&gt;')
        lines = ['# 电子数据取证报告', '', f'生成时间（东八区）：{now()}', '', '## 案件信息', '']
        for label, key in [('案件编号','number'), ('取证人员','examiner'), ('取证对象','target')]:
            lines.append(f'- {label}：{cell(self.data[key])}')
        lines.append(f'- 建立时间：{display_time(self.data["created"])}')
        lines += ['', '## 原始证据与完整性', '', f'- 路径：{cell(e["path"])}', f'- 字节数：{e["size"]}',
                  f'- 初始 SHA-256：`{e["sha256"]}`', f'- 当前 SHA-256：`{self.data["verification"]["actual"]}`',
                  f'- 校验结论：{conclusion}', '', '## 文件清单摘要', '',
                  f'当前分区偏移：{self.data.get("offset", "未浏览")}；共 {len(self.data["inventory"])} 项（最多列出 200 项）。', '',
                  '| 路径 | 状态 | inode | 字节数 | M (UTC+8) | A (UTC+8) | C (UTC+8) |', '| --- | --- | --- | ---: | --- | --- | --- |']
        for row in self.data['inventory'][:200]:
            dates = [display_time(row[k]) for k in ('mtime','atime','ctime')]
            lines.append('| ' + ' | '.join(map(cell, [row['path'], entry_status(row), row['inode'], row['size'], *dates])) + ' |')
        lines += ['', '## 导出副本', '']
        for row in self.data['exports']:
            lines.append(f'- {cell(row["source"])} → {cell(row["path"])}；SHA-256：`{row["sha256"]}`')
            if row.get('deleted'):
                lines.append('  ' + cell(deleted_export_summary(row)))
        lines += ['', '## 审计日志摘要', '', f'审计链验证通过；当前 {len(records)} 条；锚点：`{records[-1]["hash"]}`。', '',
                  '| 时间 (UTC+8) | 主体 | 操作 | 对象 | 结果 |', '| --- | --- | --- | --- | --- |']
        for row in records[-100:]:
            fields = [display_time(row['timestamp']), row['actor'], row['action'], row['subject'], row['result']]
            lines.append('| ' + ' | '.join(map(cell, fields)) + ' |')
        lines += ['', '## 取证人员确认', '', '确认人：________________    日期：________________', '',
                  '## 适用边界', '', '本工具为教学原型，实施应用层只读约束，不替代硬件写保护器或法定资质认证。',
                  'MAC 时间来自文件系统元数据，可能被修改；C 表示元数据变更时间，并非通用的创建时间。',
                  '日志哈希链和本地锚点可发现意外修改或单独截断，不能抵抗同时重写全部案件数据的攻击者。',
                  '案件库与镜像位于独立目录；若要求不同物理介质，需由操作人员另行安排。', '']
        destination = self.folder / 'reports' / ('report_' + uuid.uuid4().hex[:12] + '.md')
        destination.write_text('\n'.join(lines), encoding='utf-8')
        self.log('REPORT_GENERATE', destination, '成功', sha256=sha256(destination))
        return destination
