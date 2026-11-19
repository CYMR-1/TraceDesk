"""分段 EWF 的物理封装与解码后介质是不同的哈希对象。"""
import hashlib
import re
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def segments(image):
    first = Path(image).resolve()
    if first.suffix.upper() != '.E01':
        raise ValueError('请选择首段 .E01')
    parts = sorted((p for p in first.parent.iterdir() if p.stem.casefold() == first.stem.casefold()
                    and re.fullmatch(r'\.E\d\d', p.suffix, re.I)), key=lambda p:p.suffix.upper())
    if not parts or any(int(p.suffix[2:]) != i for i,p in enumerate(parts, 1)):
        raise ValueError('E01 分段缺失或编号不连续')
    if any(p.stem.casefold() == first.stem.casefold() and re.fullmatch(r'\.E[A-Z]{2}',p.suffix,re.I)
           for p in first.parent.iterdir()):
        raise ValueError('暂不支持含字母续段的 EWF 镜像')
    return parts


def snapshot(parts):
    return [(p.name, s.st_size, s.st_mtime_ns, s.st_ino) for p in parts for s in [p.stat()]]


def physical(parts, hash_file, progress=None):
    sizes = {path: path.stat().st_size for path in parts}
    total = sum(sizes.values())
    lock = threading.Lock()
    done = 0

    def hash_part(path):
        previous = 0
        def report(count, _):
            nonlocal previous, done
            with lock:
                done += count - previous
                previous = count
                progress(done, total)
        digest = hash_file(path, report if progress else None)
        return dict(name=path.name, size=sizes[path], sha256=digest)

    # 每个封装段有独立摘要；限制同时读取的段数并按原始顺序返回。
    with ThreadPoolExecutor(max_workers=min(3, len(parts))) as pool:
        return list(pool.map(hash_part, parts))


def logical(tool, image, size, progress=None):
    digest = hashlib.sha256()
    done = 0
    path = Path(image).resolve()
    with tempfile.TemporaryFile() as err, subprocess.Popen(tool.command('img_cat', ['-i','ewf',path.name]),
            cwd=path.parent, stdout=subprocess.PIPE, stderr=err,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)) as proc:
        try:
            while block := proc.stdout.read(4 << 20):
                digest.update(block)
                done += len(block)
                if progress:
                    progress(done,size)
            if proc.wait() or done != size:
                err.seek(0)
                raise OSError(f'EWF 解码失败，读取 {done}/{size} 字节：' + err.read(512).decode(errors='replace'))
        finally:
            proc.kill()
    return digest.hexdigest()


def acquisition_info(image):
    path = Path(image).with_suffix('.info')
    if not path.is_file() or path.stat().st_size > 1024 * 1024:
        return {}
    text = path.read_bytes().decode('utf-8', errors='replace')
    match = re.search(r'^SHA256 hash\s*:\s*([0-9a-f]{64})\b', text, re.M | re.I)
    if not match:
        return {}
    result = dict(expected_sha256=match[1].lower(), source=f'随附采集记录：{path.name}')
    version = re.search(r'^Version\s*:\s*([^\r\n]+)', text, re.M)
    started = re.search(r'^Acquisition started\s*:\s*([^\r\n(]+)', text, re.M)
    if version and 'GUYMAGER ACQUISITION INFO FILE' in text:
        result['tool'] = 'Guymager ' + version[1].strip()
    if started:
        result['acquired'] = started[1].strip() + '（按采集记录原文）'
    return result
