#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""i18n —— 轻量国际化（JSON 字典 + 全局翻译器，零第三方依赖）

用法：
    from i18n import t, set_language
    set_language("en")
    print(t("done", round=3, sec=2.5))

约定：
    - 键名即语义标识（如 "done"、"banner_hint"）
    - 缺失翻译时回退到 zh.json，再缺失则原样返回键名
"""

import json
import threading
from pathlib import Path
from typing import Any, Dict

LOCALES_DIR = Path(__file__).resolve().parent / "locales"
SUPPORTED = ("zh", "en", "ja")
DEFAULT_LANG = "zh"


class I18n:
    """翻译器实例：加载指定语言包，支持 {kwarg} 格式化与 zh 回退"""

    def __init__(self, lang: str = DEFAULT_LANG) -> None:
        self._lang = lang if lang in SUPPORTED else DEFAULT_LANG
        self._strings: Dict[str, str] = {}
        self._fallback: Dict[str, str] = {}
        self._load(self._lang)

    def _load(self, lang: str) -> None:
        self._strings = self._read(lang)
        self._fallback = self._read(DEFAULT_LANG) if lang != DEFAULT_LANG else {}

    @staticmethod
    def _read(lang: str) -> Dict[str, str]:
        path = LOCALES_DIR / f"{lang}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def set_language(self, lang: str) -> None:
        if lang not in SUPPORTED:
            raise ValueError(f"不支持的语言: {lang}，可选: {', '.join(SUPPORTED)}")
        self._lang = lang
        self._load(lang)

    @property
    def lang(self) -> str:
        return self._lang

    def t(self, key: str, **kwargs: Any) -> str:
        text = self._strings.get(key)
        if text is None:
            text = self._fallback.get(key, key)
        if kwargs and text:
            try:
                return text.format(**kwargs)
            except (KeyError, IndexError, ValueError):
                return text
        return text


_translator = I18n(DEFAULT_LANG)
_lock = threading.Lock()


def t(key: str, **kwargs: Any) -> str:
    """翻译当前语言的键；支持 {kwarg} 格式化"""
    with _lock:
        return _translator.t(key, **kwargs)


def set_language(lang: str) -> None:
    """切换全局翻译语言（zh/en/ja）"""
    with _lock:
        _translator.set_language(lang)


def current_lang() -> str:
    return _translator.lang
