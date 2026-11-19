"""从工作台标题旁打开分步操作引导。"""
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QTextBrowser, QVBoxLayout

from .api import Action, Feature


GUIDE_PAGES = (
    ('操作顺序', '''1. 新建案件：填写编号、取证人员、对象，选择案件库。
2. 加载 RAW 镜像或首段 E01：所有分段须在同一目录，镜像须在案件库之外。自动固定 SHA-256，识别并读取分区。
3. 左侧按分区展示完整文件树，点击分区或目录浏览；支持后缀及路径关键词筛选。
4. 校验完整性；选择现存或已删除的文件导出。导出前后自动校验原镜像。
5. 右键文件可添加取证笔记、计算 SHA-256 或选择本地副本比对。在“取证发现”中查看结果。
6. 在“内容搜索与复核”登记来源、搜索文件内容、双击命中查看原始字节，把命中保存为发现。导出复核 ZIP 时另存其摘要供接收人比对。'''),
    ('浏览与预览', '''左侧完整文件树保留目录、文件、删除记录与系统区域。点击目录更新右上文件列表，点击文件查看下方内容。
双击右侧目录进入，点击镜像查看所有分区条目，点击分区仅查看该分区。无法读取的分区保留节点并显示原因。
筛选只影响右侧列表；切换目录或点击“重置”清除筛选。打开旧案件时自动补齐尚未扫描的分区。
通过“全部展开/全部折叠”控制目录树；拖动左右、上下分隔条可调整区域大小。
下方“文本/十六进制”标签切换内容表示，两种视图共用编码选择。中文文件可尝试 UTF-8、UTF-16LE/BE、GBK、GB18030 或 Big5，也可选择 ASCII、Windows-1252 和 ISO-8859-1。
双击文件列表、时间线或内容预览中的页码可以跳页。在 MACB 时间线、审计日志和取证发现中，双击记录在下方打开详情；打开后，单击其他记录即可切换内容。
选择图片时“文本”自动变为“图片”，按内容识别格式并等比例显示；仍可切换十六进制查看字节。
图片预览支持 Qt 可解码的 PNG、JPEG、BMP、GIF 等格式（动画显示首帧），上限为 32 MiB、4000 万像素；超限可导出查看。
表格底部可横向滚动，查看全部时间列或十六进制内容。
双击“启动取证工作台.bat”启动；脚本使用本项目虚拟环境，保留终端窗口，运行失败时暂停。'''),
    ('取证说明与演示镜像', '''案件时间按东八区（UTC+8）显示；C 为元数据变更时间。
本工具仅承诺应用层只读，不替代硬件写保护。
本地审计哈希链可检测单独修改及截断，不能抵御全案重写。
每案固定一份证据，支持 512 字节扇区 RAW 与数字编号 E01–E99。声明范围被覆盖不等于原盘采集完整。
案件目录分离不等于不同物理磁盘，物理介质隔离由操作人员安排。

演示镜像：evidence/demo.dd（分区偏移 2048）与 evidence/demo_volume.dd（偏移 0）。'''),
)


class GuideDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle('操作说明 · TraceDesk')
        self.resize(560, 390)
        layout = QVBoxLayout(self)
        heading = QLabel()
        heading.setProperty('role', 'section')
        layout.addWidget(heading)
        body = QTextBrowser()
        layout.addWidget(body)
        controls = QHBoxLayout()
        controls.addStretch()
        back = QPushButton('上一步')
        forward = QPushButton('下一步')
        close = QPushButton('关闭')
        for button in (back, forward, close):
            controls.addWidget(button)
        layout.addLayout(controls)
        self.index = 0

        def show_step(index):
            self.index = index
            title, content = GUIDE_PAGES[index]
            heading.setText(f'{index + 1} / {len(GUIDE_PAGES)} · {title}')
            body.setPlainText(content)
            back.setEnabled(index > 0)
            forward.setEnabled(index + 1 < len(GUIDE_PAGES))

        back.clicked.connect(lambda: show_step(self.index - 1))
        forward.clicked.connect(lambda: show_step(self.index + 1))
        close.clicked.connect(self.accept)
        show_step(0)


def show_guide(context):
    dialog = GuideDialog(context.root)
    try:
        dialog.exec()
    finally:
        dialog.deleteLater()


FEATURE = Feature('help', actions=(Action('help', show_guide, '操作说明', 'brand', 'pager'),))
