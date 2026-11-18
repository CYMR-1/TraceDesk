"""明确登记功能模块；按启用清单延迟导入，不扫描目录或执行外部插件。"""
from importlib import import_module

from .config import ENABLED_FEATURES


MODULES = {
    'cases': 'forensic.features.cases',
    'evidence': 'forensic.features.evidence',
    'files': 'forensic.features.files',
    'export': 'forensic.features.export',
    'report': 'forensic.features.report',
    'timeline': 'forensic.features.timeline',
    'audit': 'forensic.features.audit',
    'help': 'forensic.features.help',
}


def load_features(enabled=None):
    keys = tuple(ENABLED_FEATURES if enabled is None else enabled)
    unknown = set(keys) - MODULES.keys()
    if unknown:
        raise ValueError('未知功能：' + ', '.join(sorted(unknown)))
    return tuple(import_module(MODULES[key]).FEATURE for key in keys)
