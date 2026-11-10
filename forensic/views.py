"""可复用的桌面组件；组件只处理显示和输入，不承担取证业务。"""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .appearance import DesktopAppearance
from .tsk import ROOT


class ReadOnlyTextPanel(ttk.Frame):
    """带双向滚动的只读文字区，保留可选择、复制的原生 Text。"""

    def __init__(self, parent):
        super().__init__(parent, style='Card.TFrame')
        appearance = DesktopAppearance(self.winfo_toplevel())
        self.text = tk.Text(self, wrap='none', font='TkTextFont', background='#ffffff',
                            foreground=DesktopAppearance.FOREGROUND, relief='flat', borderwidth=0,
                            padx=appearance.px(16), pady=appearance.px(14),
                            insertwidth=0, selectbackground='#cce2f8', selectforeground='#153d63',
                            spacing1=appearance.px(2), spacing3=appearance.px(3), state='disabled')
        self.vertical = ttk.Scrollbar(self, orient='vertical', command=self.text.yview)
        self.horizontal = ttk.Scrollbar(self, orient='horizontal', command=self.text.xview)
        self.text.configure(yscrollcommand=self.vertical.set, xscrollcommand=self.horizontal.set)
        self.text.grid(row=0, column=0, sticky='nsew')
        self.vertical.grid(row=0, column=1, sticky='ns')
        self.horizontal.grid(row=1, column=0, sticky='ew')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

    def set_text(self, value):
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        self.text.insert('1.0', value)
        self.text.configure(state='disabled')


class NewCaseDialog(tk.Toplevel):
    """收集新案件信息，创建工作交给注入的回调完成。"""

    def __init__(self, parent, on_create):
        super().__init__(parent)
        self.on_create = on_create
        self.appearance = DesktopAppearance(self)
        px = self.appearance.px
        self.title('新建取证案件')
        self.configure(background=DesktopAppearance.BACKGROUND)
        self.transient(parent)
        self.resizable(False, False)
        content = ttk.Frame(self, padding=px(24))
        content.pack(fill='both', expand=True)
        ttk.Label(content, text='填写案件信息', style='Section.TLabel').grid(row=0, column=0, sticky='w')
        ttk.Label(content, text='创建后选择案件库，用于保存导出副本、日志和报告。',
                  style='Muted.TLabel', wraplength=px(430)).grid(row=1, column=0, sticky='w', pady=(px(6), px(12)))
        self.fields = []
        for index, label in enumerate(('案件编号', '取证人员', '取证对象')):
            row = 2 + index * 2
            ttk.Label(content, text=label).grid(row=row, column=0, sticky='w', pady=(px(8), px(4)))
            entry = ttk.Entry(content, width=38)
            entry.grid(row=row + 1, column=0, sticky='ew')
            self.fields.append(entry)
        ttk.Button(content, text='选择案件库并创建', style='Accent.TButton', command=self.create).grid(
            row=8, column=0, sticky='ew', pady=(px(22), 0))
        content.columnconfigure(0, weight=1)
        self.bind('<Return>', lambda event: self.create())
        self.bind('<Escape>', lambda event: self.destroy())
        self.update_idletasks()
        left, top, width, height = DesktopAppearance.work_area(parent)
        x = max(left, min(parent.winfo_rootx() + (parent.winfo_width() - self.winfo_reqwidth()) // 2,
                          left + width - self.winfo_reqwidth()))
        y = max(top, min(parent.winfo_rooty() + (parent.winfo_height() - self.winfo_reqheight()) // 2,
                         top + height - self.winfo_reqheight()))
        self.geometry(f'{x:+d}{y:+d}')
        self.grab_set()
        self.fields[0].focus_set()

    def create(self):
        values = [entry.get().strip() for entry in self.fields]
        if not all(values):
            messagebox.showerror('信息不全', '请填写所有案件信息。', parent=self)
            return
        folder = filedialog.askdirectory(title='选择案件库目录', initialdir=ROOT / 'cases', parent=self)
        if not folder:
            return
        try:
            self.on_create(folder, *values)
        except Exception as error:
            messagebox.showerror('创建失败', str(error), parent=self)
            return
        self.destroy()
