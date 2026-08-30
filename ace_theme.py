# -*- coding: utf-8 -*-
"""
ace_theme.py —— ACE 语义主题 token 模块（借鉴 OpenClaw 的 theme.ts）

目标：把 CLI（ai_code.py）里 c("red", ...) / c("green", ...) 这类硬编码 ANSI
颜色收敛为「语义 token → ANSI 色名」的双套调色板（dark / light）。换肤只改
这一处，并支持深 / 浅色自动检测。

用法：
    import ace_theme as theme
    color = theme.tc("error")          # 取当前主题下 error 的 ANSI 色名
    theme.set_theme("light")           # 显式切换（缓存）
    theme.set_theme(None)              # 恢复自动检测
    theme.detect_theme()               # 检测：ACE_THEME 优先 → COLORFGBG → dark

纯 stdlib，无任何第三方依赖；导入无副作用（首次取色时才懒检测主题）。
"""

import os

# ---------------------------------------------------------------------------
# 语义 token → ANSI 色名 的双套调色板（dark 默认 / light 浅色）
# 色名采用 Rich 风格（ansired / ansibrightwhite / bg:#RRGGBB），方便后续
# 直接喂给 Rich 或自研 ANSI 适配层。
# ---------------------------------------------------------------------------
THEMES = {
    "dark": {
        "text": "ansibrightwhite",      # 正文：亮白
        "dim": "ansibrightblack",       # 次要 / 弱化：灰
        "accent": "ansiyellow",         # 强调（标题 / 高亮）：黄
        "border": "ansibrightblack",    # 边框 / 分隔线：灰
        "error": "ansired",             # 错误：红
        "success": "ansigreen",         # 成功：绿
        "warn": "ansiyellow",           # 警告：黄
        "info": "ansicyan",             # 信息：青
        "user_bg": "bg:#2b2b3c",        # 用户消息底色（深紫灰，与 ai_code 底栏一致）
        "tool_pending": "ansiblue",     # 工具三态 · 执行中：蓝
        "tool_ok": "ansigreen",         # 工具三态 · 成功：绿
        "tool_fail": "ansired",         # 工具三态 · 失败：红
        "perm_ro": "ansiblue",          # 权限 · 只读：蓝
        "perm_write": "ansiyellow",     # 权限 · 可写：黄
        "perm_full": "ansired",         # 权限 · 全权：红
        "goal_active": "ansigreen",     # 目标 · 进行中：绿
        "goal_paused": "ansiyellow",    # 目标 · 暂停：黄
    },
    "light": {
        "text": "ansiblack",            # 正文：黑
        "dim": "ansibrightblack",       # 次要 / 弱化：灰
        "accent": "ansiblue",           # 强调：蓝（浅底上比黄色清晰）
        "border": "ansibrightblack",    # 边框 / 分隔线：灰
        "error": "ansibrightred",       # 错误：亮红（浅底上增强对比）
        "success": "ansigreen",         # 成功：绿
        "warn": "ansimagenta",          # 警告：品红（浅底上黄字不可读）
        "info": "ansiblue",             # 信息：蓝
        "user_bg": "bg:#eef0f6",        # 用户消息底色（浅蓝灰）
        "tool_pending": "ansiblue",     # 工具三态 · 执行中：蓝
        "tool_ok": "ansigreen",         # 工具三态 · 成功：绿
        "tool_fail": "ansibrightred",   # 工具三态 · 失败：亮红
        "perm_ro": "ansiblue",          # 权限 · 只读：蓝
        "perm_write": "ansimagenta",    # 权限 · 可写：品红
        "perm_full": "ansibrightred",   # 权限 · 全权：亮红
        "goal_active": "ansigreen",     # 目标 · 进行中：绿
        "goal_paused": "ansimagenta",   # 目标 · 暂停：品红
    },
}

# 未知 token 的回退色名（tc 永不抛异常）
_FALLBACK = "ansi"

# 当前主题状态：None = 尚未显式设置 → 首次使用时懒调用 detect_theme()
_CURRENT = None


def detect_theme() -> str:
    """检测终端主题（返回 "dark" 或 "light"）。

    优先级：
      1. 环境变量 ACE_THEME=dark|light 显式指定（最高优先）；
      2. 环境变量 COLORFGBG（如 '15;0' 白字黑底 → 深色；'0;15' → 浅色）；
      3. 兜底默认 "dark"。
    """
    # 1) 显式指定优先
    explicit = os.environ.get("ACE_THEME", "").strip().lower()
    if explicit in THEMES:
        return explicit
    # 2) COLORFGBG 推断：格式 "fg;bg"，背景色号 >= 8 视为浅色底
    fgbg = os.environ.get("COLORFGBG", "").strip()
    if fgbg:
        bg = fgbg.split(";")[-1].strip()
        if bg.isdigit():
            return "light" if int(bg) >= 8 else "dark"
    # 3) 默认深色
    return "dark"


def _resolve_theme() -> str:
    """内部：返回当前生效的主题名（未显式设置时懒检测）。"""
    return _CURRENT if _CURRENT is not None else detect_theme()


def tc(token: str) -> str:
    """取当前主题下 token 对应的 ANSI 色名。

    token 不存在时回退 "ansi"（默认前景），绝不抛异常。
    """
    palette = THEMES.get(_resolve_theme(), {})
    return palette.get(token, _FALLBACK)


def set_theme(theme: str) -> None:
    """显式设置并缓存当前主题。

    theme 为 "dark" / "light" 时直接切换；为 None 时恢复自动检测；
    传入未知名字则回退到 detect_theme() 的结果（不抛异常）。
    """
    global _CURRENT
    if theme is None:
        _CURRENT = None
        return
    name = str(theme).strip().lower()
    if name not in THEMES:
        name = detect_theme()
    _CURRENT = name


def current_theme() -> str:
    """返回当前生效的主题名（"dark" 或 "light"）。"""
    return _resolve_theme()
