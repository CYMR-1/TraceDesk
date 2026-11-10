"""只读文件预览。每页保留前后各三个字节，用于解码跨页的 UTF-8 字符。"""
import queue
import subprocess
import tempfile
import threading
import tkinter as tk
from bisect import bisect_right
from itertools import accumulate
from pathlib import Path
from tkinter import font, messagebox, ttk

from .appearance import DesktopAppearance
from .tsk import TSK, deleted_source_note, tsk_error


ROW_BYTES = 16
PAGE_BYTES = 4096


def preview_rows(window, start, size, encoding):
    prefix = min(3, start)
    data = window[prefix:prefix + min(PAGE_BYTES, size - start)]
    strings = [''] * ((len(data) + ROW_BYTES - 1) // ROW_BYTES)
    if encoding == 'ASCII':
        for i, byte in enumerate(data):
            strings[i // ROW_BYTES] += chr(byte) if 32 <= byte < 127 else '·'
    else:
        # 每个字符只出现一次，归到其首字节所在行。非法字节各占一个替换符。
        index = -prefix
        for char in window.decode('utf-8', errors='surrogateescape'):
            if 0 <= index < len(data):
                if 0xDC80 <= ord(char) <= 0xDCFF:
                    display = '�'
                else:
                    display = char if char.isprintable() else '·'
                strings[index // ROW_BYTES] += display
            index += len(char.encode('utf-8', errors='surrogateescape'))
    for row, chars in enumerate(strings):
        i = row * ROW_BYTES
        yield (f'{start + i:08X}', data[i:i + ROW_BYTES].hex(' ').upper(), chars)


class PreviewReader:
    """在后台按需读取 icat 字节流，缓存已查看的部分以便向前翻页。"""

    def __init__(self, image, entry):
        self.pages = queue.Queue()
        self.results = queue.Queue()
        self.closed = threading.Event()
        self.process = None
        self.pages.put(0)
        threading.Thread(target=self._run, args=(image, entry), daemon=True).start()

    def close(self):
        self.closed.set()
        self.pages.put(None)
        process = self.process
        if process is not None:
            process.kill()

    def _run(self, image, entry):
        try:
            if not Path(image).is_file():
                raise FileNotFoundError(f'案件记录的镜像不存在：{image}')
            if 'extents' in entry:
                with open(image, 'rb') as source:
                    self._read_extents(source, entry['extents'])
                return
            tool = TSK()
            deleted = entry.get('deleted', False)
            args = tool.entry_args(image, entry)
            command = tool.command('icat', args)
            with tempfile.TemporaryFile() as errors, tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as cache:
                with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors,
                                      creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)) as process:
                    self.process = process
                    try:
                        self._read_pages(process, errors, cache, entry['size'], deleted)
                    finally:
                        process.kill()
                        self.process = None
        except Exception as error:
            if not self.closed.is_set():
                self.results.put((None, b'', 0, str(error)))

    def _read_extents(self, source, extents):
        offsets = list(accumulate((length for _, length in extents), initial=0))
        while not self.closed.is_set():
            page = self.pages.get()
            if page is None:
                return
            start = max(0, page * PAGE_BYTES - 3)
            end = min(offsets[-1], (page + 1) * PAGE_BYTES + 3)
            index = bisect_right(offsets, start) - 1
            window = bytearray()
            while start < end:
                length = min(end, offsets[index + 1]) - start
                source.seek(extents[index][0] + start - offsets[index])
                data = source.read(length)
                if len(data) != length:
                    raise OSError('空间区域超出当前镜像，请重新读取文件树')
                window.extend(data)
                start += length
                index += 1
            self.results.put((page, bytes(window), offsets[-1], ''))

    def _read_pages(self, process, errors, cache, recorded_size, deleted):
        size = recorded_size
        note = ''
        cached = 0
        while not self.closed.is_set():
            page = self.pages.get()
            if page is None:
                return
            start = page * PAGE_BYTES
            left = max(0, start - 3)
            right = min(size, start + PAGE_BYTES + 3)
            if right > cached:
                # 最后一页多读一个字节以确认 EOF 和 icat 的退出状态。
                expected = right - cached
                requested = expected + int(right == size)
                chunk = process.stdout.read(requested)
                if len(chunk) < requested and process.wait():
                    errors.seek(0)
                    note = tsk_error(errors.read(2000)) or 'icat 读取异常'
                    if not deleted or not (cached or chunk):
                        raise OSError(note)
                if len(chunk) != expected:
                    if not deleted:
                        raise OSError('读取长度与文件清单不一致，请重新读取文件树')
                    if not (cached or chunk):
                        raise OSError('未能从该删除记录读取数据')
                    if len(chunk) < expected:
                        # 已删除文件的簇链可能不完整。保留可读前缀，按实际长度翻页。
                        size = right = cached + len(chunk)
                        note = f'可读 {size} / {recorded_size} 字节' + (f' · {note}' if note else '')
                    else:
                        chunk = chunk[:expected]
                        note = '已按目录记录大小截取'
                        process.kill()
                cache.seek(cached)
                cache.write(chunk)
                cached = right
            cache.seek(left)
            self.results.put((page, cache.read(right - left), size, note))


class FilePreview(ttk.Frame):
    """独立的文件内容视图；读取器只提供字节，视图负责分页和编码选择。"""

    def __init__(self, parent):
        super().__init__(parent)
        self.appearance = DesktopAppearance(self.winfo_toplevel())
        self.reader = None
        self.window = b''
        self.size = self.page = 0
        self._build_toolbar()
        self._build_rows()
        self.clear()

    def _build_toolbar(self):
        px = self.appearance.px
        bar = ttk.Frame(self)
        bar.pack(fill='x', pady=(px(3), px(4)))
        bar.columnconfigure(3, weight=1)
        ttk.Label(bar, text='文件内容', style='Section.TLabel').grid(row=0, column=0, padx=(px(2), px(12)))
        ttk.Label(bar, text='字符编码').grid(row=0, column=1)
        self.encoding = ttk.Combobox(bar, values=('ASCII', 'UTF-8'), width=7, state='readonly')
        self.encoding.current(0)
        self.encoding.grid(row=0, column=2, padx=px(6))
        self.encoding.bind('<<ComboboxSelected>>', self.render)
        self.next = ttk.Button(bar, text='下一页', command=lambda: self.turn(1))
        self.previous = ttk.Button(bar, text='上一页', command=lambda: self.turn(-1))
        self.previous.grid(row=0, column=5, padx=px(2))
        self.next.grid(row=0, column=6, padx=px(2))
        self.status = tk.StringVar()
        # 状态占用弹性列，避免长错误或删除记录提示挤走翻页按钮。
        # 点击或按 Enter 可阅读完整状态，原始状态文本始终保存在 StringVar。
        self.status_label = ttk.Label(bar, textvariable=self.status, width=1, anchor='w',
                                      style='Muted.TLabel', cursor='hand2', takefocus=True)
        self.status_label.grid(row=0, column=3, sticky='ew', padx=px(8))
        self.status_label.bind('<Button-1>', self._show_status)
        self.status_label.bind('<Return>', self._show_status)
        self.status_details = ttk.Label(bar, text='状态详情', foreground=DesktopAppearance.ACCENT,
                                        cursor='hand2', takefocus=True)
        self.status_details.grid(row=0, column=4, padx=(0, px(8)))
        self.status_details.bind('<Button-1>', self._show_status)
        self.status_details.bind('<Return>', self._show_status)

    def _show_status(self, event=None):
        if self.status.get():
            messagebox.showinfo('文件预览状态', self.status.get(), parent=self)

    def _build_rows(self):
        px = self.appearance.px
        fixed = font.nametofont('TkFixedFont', root=self)
        ttk.Style(self).configure('Hex.Treeview', font=fixed, rowheight=fixed.metrics('linespace') + px(10))
        table = ttk.Frame(self)
        table.pack(fill='both', expand=True)
        self.rows = ttk.Treeview(table, columns=('offset', 'hex', 'chars'), show='headings',
                                 style='Hex.Treeview', height=5, selectmode='browse')
        for key, label, width in [('offset', '文件偏移 (HEX)', fixed.measure('0') * 16),
                                  ('hex', '十六进制', fixed.measure('0') * 48),
                                  ('chars', '字符', fixed.measure('0') * 20)]:
            self.rows.heading(key, text=label, anchor='w')
            self.rows.column(key, width=width + px(16), minwidth=width + px(16), stretch=(key == 'chars'))
        self.vertical = ttk.Scrollbar(table, orient='vertical', command=self.rows.yview)
        self.horizontal = ttk.Scrollbar(table, orient='horizontal', command=self.rows.xview)
        self.rows.configure(yscrollcommand=self.vertical.set, xscrollcommand=self.horizontal.set)
        self.rows.grid(row=0, column=0, sticky='nsew')
        self.vertical.grid(row=0, column=1, sticky='ns')
        self.horizontal.grid(row=1, column=0, sticky='ew')
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)

    def clear(self, message='请选择文件'):
        if self.reader:
            self.reader.close()
            self.reader = None
        self.page = self.size = 0
        self.window = b''
        self.source_note = ''
        self.rows.delete(*self.rows.get_children())
        self.status.set(message)
        self.previous.state(['disabled'])
        self.next.state(['disabled'])

    def open_file(self, image, entry):
        self.clear()
        self.source_note = deleted_source_note(entry)
        self.size = entry['size']
        if self.size:
            self.status.set('正在读取…')
            self.reader = PreviewReader(image, entry)
        else:
            self.status.set('删除记录为 0 字节，无内容可显示' if entry.get('deleted') else '空文件（0 字节）')

    def turn(self, direction):
        self.previous.state(['disabled'])
        self.next.state(['disabled'])
        self.status.set('正在读取…')
        self.reader.pages.put(self.page + direction)

    def poll(self):
        if self.reader is None:
            return
        try:
            page, value, size, note = self.reader.results.get_nowait()
        except queue.Empty:
            return
        if page is None:
            self.clear('读取失败：' + note)
            return
        self.page, self.window, self.size = page, value, size
        self.render()
        self.rows.yview_moveto(0)
        count = (self.size + PAGE_BYTES - 1) // PAGE_BYTES
        self.status.set(' · '.join(filter(None, (f'第 {page + 1} / {count} 页', self.source_note, note))))
        self.previous.state(['!disabled' if page else 'disabled'])
        self.next.state(['!disabled' if page + 1 < count else 'disabled'])

    def render(self, event=None):
        position = self.rows.yview()[0]
        self.rows.delete(*self.rows.get_children())
        for values in preview_rows(self.window, self.page * PAGE_BYTES, self.size, self.encoding.get()):
            self.rows.insert('', 'end', values=values)
        self.rows.yview_moveto(position)
