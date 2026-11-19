"""功能启用清单及显示顺序。移除可选项后，其入口和刷新逻辑同时停用。"""

ENABLED_FEATURES = (
    'cases', 'evidence', 'files',  # 基础工作流，不能禁用。
    'export', 'file_tools', 'report', 'timeline', 'audit', 'help', 'review',
)
