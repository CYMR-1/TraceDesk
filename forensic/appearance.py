"""桌面显示设置：原生 DPI 感知、可读字体和统一的 ttk 主题。"""
import os
from tkinter import font, ttk


class DesktopAppearance:
    """所有尺寸以 96 DPI 设计像素表达，字体使用可随 DPI 缩放的点数。"""

    BACKGROUND = '#eef3f8'
    SURFACE = '#ffffff'
    FOREGROUND = '#182c43'
    MUTED = '#52667d'
    BORDER = '#c8d4e1'
    ACCENT = '#195b9d'

    def __init__(self, root):
        self.root = root
        self.scale = self._dpi(root) / 96
        self.style = ttk.Style(root)
        self.fonts = {}

    @staticmethod
    def enable_high_dpi():
        """须在创建第一个 Tk 窗口前调用；旧版 Windows 自动回退。

        Microsoft 定义 PER_MONITOR_AWARE_V2 为句柄 -4。若宿主已经
        设定进程 DPI 感知，API 会拒绝重复设置，此时保留宿主配置。
        """
        if os.name != 'nt':
            return
        import ctypes
        from ctypes import wintypes
        try:
            user32 = ctypes.WinDLL('user32', use_last_error=True)
            set_context = user32.SetProcessDpiAwarenessContext
            set_context.argtypes = [ctypes.c_void_p]
            set_context.restype = wintypes.BOOL
            if set_context(ctypes.c_void_p(-4)) or ctypes.get_last_error() == 5:
                return
        except (AttributeError, OSError):
            pass
        try:
            set_awareness = ctypes.WinDLL('shcore').SetProcessDpiAwareness
            set_awareness.argtypes = [ctypes.c_int]
            set_awareness.restype = ctypes.c_long
            result = set_awareness(2)
            if result in (0, -2147024891):  # S_OK / E_ACCESSDENIED（已设置）
                return
        except (AttributeError, OSError):
            pass
        try:
            user32.SetProcessDPIAware()
        except (AttributeError, OSError, UnboundLocalError):
            pass

    @staticmethod
    def _dpi(root):
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes
            try:
                get_dpi = ctypes.WinDLL('user32').GetDpiForWindow
                get_dpi.argtypes = [wintypes.HWND]
                get_dpi.restype = wintypes.UINT
                dpi = get_dpi(root.winfo_id())
                if dpi:
                    return dpi
            except (AttributeError, OSError):
                pass
        return root.winfo_fpixels('1i')

    def px(self, value):
        return max(1, round(value * self.scale)) if value else 0

    def configure(self, root=None):
        root = root or self.root
        # Tk 的 scaling 单位为“每个排版点的像素数”，1 点 = 1/72 英寸。
        root.tk.call('tk', 'scaling', 96 * self.scale / 72)
        available = set(font.families(root))
        family = next((name for name in ('Microsoft YaHei UI', 'Microsoft YaHei', 'Noto Sans CJK SC', 'Arial')
                       if name in available), 'TkDefaultFont')
        fixed_family = 'Consolas' if 'Consolas' in available else 'Courier New'
        for name in ('TkDefaultFont', 'TkTextFont', 'TkMenuFont', 'TkHeadingFont',
                     'TkCaptionFont', 'TkSmallCaptionFont', 'TkTooltipFont', 'TkFixedFont'):
            named = font.nametofont(name, root=root)
            named.configure(family=fixed_family if name == 'TkFixedFont' else family,
                            size=10 if name in ('TkSmallCaptionFont', 'TkTooltipFont') else 11,
                            weight='bold' if name == 'TkHeadingFont' else 'normal')
            self.fonts[name] = named
        # ttk 的 font 选项优先于样式；全局 *Font 会覆盖标题等样式的字号。
        root.option_add('*TCombobox*Listbox.font', 'TkDefaultFont')
        root.option_add('*TCombobox*Listbox.selectBackground', self.ACCENT)
        root.option_add('*TCombobox*Listbox.selectForeground', '#ffffff')
        root.configure(background=self.BACKGROUND)

        style = self.style
        style.theme_use('clam')
        style.configure('.', font='TkDefaultFont', background=self.BACKGROUND,
                        foreground=self.FOREGROUND, bordercolor=self.BORDER,
                        lightcolor=self.BORDER, darkcolor=self.BORDER, focuscolor=self.ACCENT)
        style.configure('TFrame', background=self.BACKGROUND)
        for name in ('Card.TFrame', 'Header.TFrame'):
            style.configure(name, background=self.SURFACE)
        style.configure('TLabel', background=self.BACKGROUND, foreground=self.FOREGROUND)
        style.configure('Title.TLabel', background=self.SURFACE, font=(family, 23, 'bold'),
                        foreground='#143e6a')
        style.configure('Subtitle.TLabel', background=self.SURFACE, foreground=self.MUTED)
        style.configure('Muted.TLabel', foreground=self.MUTED)
        style.configure('Section.TLabel', font=(family, 11, 'bold'))
        style.configure('Status.TLabel', foreground=self.MUTED)
        style.configure('Card.TLabel', background=self.SURFACE)
        style.configure('TButton', padding=(self.px(12), self.px(7)),
                        background='#e5edf5', borderwidth=1, relief='flat')
        style.map('TButton', background=[('active', '#d5e3f1'), ('pressed', '#c4d8ec')],
                  foreground=[('disabled', '#8191a3')])
        style.configure('Accent.TButton', foreground='#ffffff', background=self.ACCENT,
                        bordercolor=self.ACCENT, font=(family, 11, 'bold'))
        style.map('Accent.TButton', background=[('disabled', '#c1cddb'), ('pressed', '#124777'),
                                               ('active', '#2470b8')],
                  foreground=[('disabled', '#66778a'), ('!disabled', '#ffffff')],
                  bordercolor=[('!disabled', self.ACCENT)])
        style.configure('Secondary.TButton', background='#ffffff', bordercolor=self.BORDER)
        style.map('Secondary.TButton', background=[('active', '#e3edf7'), ('pressed', '#cfdfef')])
        style.configure('TEntry', fieldbackground=self.SURFACE, foreground=self.FOREGROUND,
                        padding=self.px(5), insertcolor=self.FOREGROUND)
        style.configure('TCombobox', padding=self.px(5), fieldbackground=self.SURFACE,
                        foreground=self.FOREGROUND, arrowsize=self.px(15))
        style.map('TCombobox', fieldbackground=[('readonly', self.SURFACE)],
                  foreground=[('readonly', self.FOREGROUND)],
                  selectbackground=[('readonly', self.ACCENT)],
                  selectforeground=[('readonly', '#ffffff')])
        style.configure('TNotebook', background=self.BACKGROUND, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure('TNotebook.Tab', padding=(self.px(18), self.px(10)),
                        background='#e0e8f2', foreground=self.MUTED)
        style.map('TNotebook.Tab', background=[('selected', self.SURFACE), ('active', '#d6e4f2')],
                  foreground=[('selected', self.ACCENT)])
        line = self.fonts['TkDefaultFont'].metrics('linespace')
        style.configure('Treeview', font='TkDefaultFont', rowheight=line + self.px(12),
                        background=self.SURFACE, fieldbackground=self.SURFACE,
                        foreground=self.FOREGROUND, borderwidth=0)
        style.configure('Treeview.Heading', font='TkHeadingFont', padding=(self.px(9), self.px(8)),
                        background='#e8eff7', foreground='#254667', relief='flat')
        style.map('Treeview', background=[('selected', '#d4e7fa')],
                  foreground=[('selected', '#123f6d')])
        style.map('Treeview.Heading', background=[('active', '#dce8f5')])
        style.configure('TScrollbar', arrowsize=self.px(15), background='#d3deea',
                        troughcolor='#eef3f8', borderwidth=0)
        style.configure('TProgressbar', background=self.ACCENT, troughcolor='#dfe8f2',
                        borderwidth=0, thickness=self.px(8))
        return self

    @staticmethod
    def work_area(root):
        """返回当前窗口所在显示器的工作区（含起点，排除任务栏）。"""
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes

            class MonitorInfo(ctypes.Structure):
                _fields_ = [('cbSize', wintypes.DWORD), ('rcMonitor', wintypes.RECT),
                            ('rcWork', wintypes.RECT), ('dwFlags', wintypes.DWORD)]

            try:
                user32 = ctypes.WinDLL('user32')
                user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
                user32.MonitorFromWindow.restype = wintypes.HANDLE
                user32.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MonitorInfo)]
                user32.GetMonitorInfoW.restype = wintypes.BOOL
                monitor = user32.MonitorFromWindow(root.winfo_id(), 2)
                info = MonitorInfo()
                info.cbSize = ctypes.sizeof(info)
                if user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
                    area = info.rcWork
                    return area.left, area.top, area.right - area.left, area.bottom - area.top
            except (AttributeError, OSError):
                pass
        return 0, 0, root.winfo_screenwidth(), root.winfo_screenheight()

    def fit_window(self, width=1320, height=860, min_width=960, min_height=640):
        left, top, screen_width, screen_height = self.work_area(self.root)
        margin = self.px(16)
        available_width = max(320, screen_width - margin * 2)
        available_height = max(240, screen_height - self.px(60))
        width, height = min(self.px(width), available_width), min(self.px(height), available_height)
        self.root.minsize(min(self.px(min_width), available_width), min(self.px(min_height), available_height))
        x, y = left + (screen_width - width) // 2, top + margin
        self.root.geometry(f'{width}x{height}{x:+d}{y:+d}')
