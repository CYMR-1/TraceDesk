"""工作台视图与文件浏览组件；不负责案件读写和取证操作。"""
import tkinter as tk
from tkinter import ttk

from .core import display_time
from .preview import FilePreview
from .tsk import entry_name, entry_status
from .views import ReadOnlyTextPanel


class FileBrowserView(ttk.Frame):
    """封装文件树、筛选条件、内容预览和分批显示。"""

    def __init__(self, parent, appearance, commands):
        super().__init__(parent, padding=appearance.px(8))
        self.appearance = appearance
        self.entries, self._nodes = {}, {}
        self._batch_id = None
        px = appearance.px
        controls = ttk.Frame(self)
        controls.pack(fill='x', pady=(0, px(6)))
        controls.columnconfigure(1, weight=1)
        ttk.Label(controls, text='分析分区').grid(row=0, column=0, sticky='w', padx=(0, px(10)))
        self.partition = ttk.Combobox(controls, state='readonly', width=38)
        self.partition.grid(row=0, column=1, sticky='ew')
        self.scan_button = ttk.Button(controls, text='读取文件树', command=commands['scan'], style='Accent.TButton')
        self.scan_button.grid(row=0, column=2, padx=(px(10), 0))

        filters = ttk.Frame(controls)
        filters.grid(row=1, column=0, columnspan=3, sticky='ew', pady=(px(6), 0))
        filters.columnconfigure(3, weight=1)
        ttk.Label(filters, text='文件后缀').grid(row=0, column=0, padx=(0, px(10)))
        self.suffix = ttk.Entry(filters, width=12)
        self.suffix.grid(row=0, column=1, padx=(0, px(18)))
        ttk.Label(filters, text='路径关键词').grid(row=0, column=2, padx=(0, px(10)))
        self.keyword = ttk.Entry(filters)
        self.keyword.grid(row=0, column=3, sticky='ew')
        self.filter_button = ttk.Button(filters, text='筛选', command=commands['filter'])
        self.filter_button.grid(row=0, column=4, padx=(px(10), 0))
        for entry in (self.suffix, self.keyword):
            entry.bind('<Return>', lambda event: commands['filter']())

        self.split = tk.PanedWindow(self, orient='vertical', sashwidth=px(8),
                                   sashrelief='flat', background='#d6deea',
                                   showhandle=True, borderwidth=0, opaqueresize=True)
        self.split.pack(fill='both', expand=True)
        tree_frame = ttk.Frame(self.split)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        self.split.add(tree_frame, minsize=px(105), stretch='always')
        self.tree = ttk.Treeview(tree_frame, columns=('state', 'size', 'inode', 'm', 'a', 'c'),
                                 selectmode='browse', height=5)
        self.tree.tag_configure('deleted', foreground='#9a3412')
        self.tree.tag_configure('alternate', background='#f2f6fb')
        self.tree.heading('#0', text='镜像内路径 / 文件目录', anchor='w')
        self.tree.column('#0', width=px(270), minwidth=px(180), stretch=True)
        for key, label, width in [('state', '状态', 105), ('size', '字节数', 100), ('inode', 'inode', 90),
                                  ('m', 'M 内容修改 (UTC+8)', 195), ('a', 'A 访问 (UTC+8)', 195),
                                  ('c', 'C 元数据变更 (UTC+8)', 195)]:
            self.tree.heading(key, text=label, anchor='w')
            self.tree.column(key, width=px(width), minwidth=px(width), stretch=False,
                             anchor='e' if key == 'size' else 'w')
        vertical = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        horizontal = ttk.Scrollbar(tree_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vertical.grid(row=0, column=1, sticky='ns')
        horizontal.grid(row=1, column=0, sticky='ew')
        self.tree.bind('<<TreeviewSelect>>', commands['select'])
        self.preview = FilePreview(self.split)
        self.split.add(self.preview, minsize=px(135), stretch='always')
        self.detail = tk.StringVar(value='选择文件可预览、导出副本。拖动中间分隔条可调整预览区域。')
        self.detail_label = ttk.Label(self, textvariable=self.detail, style='Muted.TLabel')
        self.detail_label.pack(fill='x', pady=(px(4), 0))
        self.bind('<Configure>', self._resize)

    def _resize(self, event):
        if event.widget is self:
            self.detail_label.configure(wraplength=max(1, event.width - self.appearance.px(24)))

    def display(self, entries):
        self.cancel_display()
        self.preview.clear()
        self.tree.delete(*self.tree.get_children())
        self.entries, self._nodes = {}, {}
        ordered = sorted(entries, key=lambda e: (e['path'].count('/'), e['mode'].lower().startswith('v/'),
                                                 not e['directory'], e['path'], e.get('deleted', False)))
        self._remaining = iter(ordered)
        self._row_number = 0
        self._insert_batch()
        self.detail.set(f'当前显示 {len(entries)} 项。M：内容修改，A：访问，C：元数据变更；时间为东八区（UTC+8）。')

    def _parent_node(self, path):
        if not path or path == '.':
            return ''
        if path not in self._nodes:
            parent, _, name = path.rpartition('/')
            self._nodes[path] = self.tree.insert(self._parent_node(parent), 'end', text=name, open=True)
        return self._nodes[path]

    def _insert_entry(self, entry):
        path = entry['path'].rstrip('/')
        tags = ['alternate'] if self._row_number % 2 else []
        if entry.get('deleted'):
            tags.append('deleted')
        dates = [display_time(entry[key], compact=True) for key in ('mtime', 'atime', 'ctime')]
        item = self.tree.insert(self._parent_node(path.rpartition('/')[0]), 'end', text=entry_name(entry) or '/',
                                open=True, values=(entry_status(entry), entry['size'], entry['inode'] or '—', *dates),
                                tags=tags)
        # 同名删除项分别保留 inode；路径仅用于父目录定位。
        if entry['directory']:
            self._nodes.setdefault(path, item)
        self.entries[item] = entry
        self._row_number += 1

    def _insert_batch(self):
        self._batch_id = None
        for _ in range(200):
            entry = next(self._remaining, None)
            if entry is None:
                return
            self._insert_entry(entry)
        self._batch_id = self.after(1, self._insert_batch)

    def cancel_display(self):
        if self._batch_id is not None:
            self.after_cancel(self._batch_id)
            self._batch_id = None

    def set_busy(self, busy):
        for button in (self.scan_button, self.filter_button):
            button.state(['disabled' if busy else '!disabled'])


class WorkbenchView:
    """主窗口布局；由控制器注入命令，组件之间不调用案件逻辑。"""

    def __init__(self, root, appearance, commands):
        self.root, self.appearance = root, appearance
        self._toolbar_columns = None
        px = appearance.px
        root.title('TraceDesk · 电子数据取证工作台')
        appearance.fit_window(width=1360, height=900, min_width=900, min_height=640)

        self.header = ttk.Frame(root, style='Header.TFrame', padding=(px(20), px(8)))
        self.header.pack(fill='x')
        self.title_label = ttk.Label(self.header, text='TraceDesk  取证工作台', style='Title.TLabel')
        self.title_label.pack(side='left')
        self.subtitle_label = ttk.Label(self.header, text='RAW 镜像分析   /   SHA-256 证据固定   /   全流程审计',
                                        style='Subtitle.TLabel')
        self.subtitle_label.pack(side='left', padx=(px(24), 0))
        self.header.bind('<Configure>', self._layout_header)
        self.toolbar = ttk.Frame(root, padding=(px(24), 0))
        self.toolbar.pack(fill='x')
        self.buttons = []
        for index, (label, key) in enumerate([('新建案件', 'new_case'), ('打开案件', 'open_case'),
                                             ('加载 RAW 镜像', 'load'), ('校验完整性', 'verify'),
                                             ('导出所选文件', 'export'), ('生成 Markdown 报告', 'report')]):
            button = ttk.Button(self.toolbar, text=label, command=commands[key],
                                style='Accent.TButton' if index in (0, 2) else 'TButton')
            self.buttons.append(button)
        self.toolbar.bind('<Configure>', self._layout_toolbar)

        card = ttk.Frame(root, style='Card.TFrame', padding=(px(12), px(6)))
        card.pack(fill='x', padx=px(24), pady=(px(6), px(4)))
        self.summary = tk.StringVar(value='尚未打开案件。新建案件后加载镜像，或打开已有案件继续分析。')
        summary = ttk.Label(card, textvariable=self.summary, style='Card.TLabel', justify='left')
        summary.pack(fill='x')
        card.bind('<Configure>', lambda event: summary.configure(wraplength=max(1, event.width - px(24))))

        # 先保留底部空间，再让选项卡占用剩余区域。
        footer = ttk.Frame(root, padding=(px(24), px(4)))
        footer.pack(side='bottom', fill='x')
        self.status = tk.StringVar(value='就绪 · 应用层只读模式 · 东八区 UTC+8')
        ttk.Label(footer, textvariable=self.status, style='Muted.TLabel').pack(side='left')
        self.progress = ttk.Progressbar(footer, mode='indeterminate', length=px(180))
        self.progress.pack(side='right')
        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill='both', expand=True, padx=px(24), pady=px(4))
        self.browser = FileBrowserView(self.tabs, appearance, commands)
        self.tabs.add(self.browser, text='文件浏览')
        self.panels = {}
        for key, title in [('info', '镜像与文件系统'), ('audit', '审计日志'),
                            ('timeview', 'MAC 时间线'), ('help', '操作说明')]:
            panel = ReadOnlyTextPanel(self.tabs)
            self.panels[key] = panel
            self.tabs.add(panel, text=title)

    def _layout_header(self, event):
        if event.widget is not self.header:
            return
        needed = self.title_label.winfo_reqwidth() + self.subtitle_label.winfo_reqwidth() + self.appearance.px(64)
        if event.width >= needed:
            if not self.subtitle_label.winfo_manager():
                self.subtitle_label.pack(side='left', padx=(self.appearance.px(24), 0))
        elif self.subtitle_label.winfo_manager():
            self.subtitle_label.pack_forget()

    def _layout_toolbar(self, event):
        if event.widget is not self.toolbar:
            return
        needed = sum(button.winfo_reqwidth() for button in self.buttons) + self.appearance.px(50)
        columns = 6 if event.width >= needed else 3
        if columns == self._toolbar_columns:
            return
        self._toolbar_columns = columns
        for column in range(6):
            self.toolbar.columnconfigure(column, weight=1 if column < columns else 0)
        for index, button in enumerate(self.buttons):
            button.grid(row=index // columns, column=index % columns, sticky='ew',
                        padx=(0, self.appearance.px(8) if index % columns < columns - 1 else 0),
                        pady=(0, self.appearance.px(4)))

    def set_busy(self, busy):
        for button in self.buttons:
            button.state(['disabled' if busy else '!disabled'])
        self.browser.set_busy(busy)
        if busy:
            self.progress.start()
        else:
            self.progress.stop()
