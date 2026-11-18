"""功能模块的最小接口：命令、页面与案件切换回调。"""
from dataclasses import dataclass
from functools import partial
from typing import Callable


@dataclass(frozen=True)
class FeatureContext:
    root: object
    case: Callable
    browser: Callable
    available: Callable
    task: Callable
    refresh: Callable
    replace_case: Callable
    selected_entry: Callable


@dataclass(frozen=True)
class Action:
    key: str
    handler: Callable
    title: str = ''
    location: str | None = None
    role: str = ''
    accepts_entry: Callable | None = None


@dataclass(frozen=True)
class Panel:
    key: str
    title: str
    render: Callable
    cache_key: Callable | None = None


@dataclass(frozen=True)
class Feature:
    key: str
    actions: tuple[Action, ...] = ()
    panels: tuple[Panel, ...] = ()
    requires: tuple[str, ...] = ()
    case_changed: Callable | None = None


class FeatureRegistry:
    """验证依赖并统一装配；未启用的功能不会创建按钮、页面或刷新任务。"""

    REQUIRED = frozenset(('cases', 'evidence', 'files'))

    def __init__(self, features, context):
        self.features = tuple(features)
        self.context = context
        keys = [feature.key for feature in self.features]
        if len(set(keys)) != len(keys):
            raise ValueError('功能标识重复')
        missing = self.REQUIRED - set(keys)
        if missing:
            raise ValueError('缺少工作台基础功能：' + ', '.join(sorted(missing)))
        self.actions, self.panels = {}, {}
        for feature in self.features:
            missing = set(feature.requires) - set(keys)
            if missing:
                raise ValueError(f'功能 {feature.key} 缺少依赖：' + ', '.join(sorted(missing)))
            for action in feature.actions:
                if action.key in self.actions:
                    raise ValueError(f'命令标识重复：{action.key}')
                if action.location not in (None, 'header', 'evidence', 'preview', 'file_menu'):
                    raise ValueError(f'未知按钮位置：{action.location}')
                self.actions[action.key] = action
            for panel in feature.panels:
                if panel.key in self.panels:
                    raise ValueError(f'页面标识重复：{panel.key}')
                self.panels[panel.key] = panel
        self.commands = {key: partial(action.handler, context) for key, action in self.actions.items()}
        self._rendered = {}

    def actions_at(self, location):
        return tuple(action for action in self.actions.values() if action.location == location)

    def invoke(self, key, *args, **kwargs):
        if key not in self.commands:
            raise ValueError(f'未启用功能命令：{key}')
        return self.commands[key](*args, **kwargs)

    def case_changed(self):
        for feature in self.features:
            if feature.case_changed:
                feature.case_changed(self.context)

    def refresh_panels(self, widgets, *, reset=False):
        for key, panel in self.panels.items():
            version = panel.cache_key(self.context) if panel.cache_key else None
            if reset or panel.cache_key is None or key not in self._rendered or self._rendered[key] != version:
                widgets[key].set_text(panel.render(self.context))
                self._rendered[key] = version
