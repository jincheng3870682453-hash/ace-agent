#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ace_chatscroll —— 聊天内置滚动引擎(方案 C,纯逻辑、可单测)

聊天"视口"只滚动本会话的行缓冲,永远滚不到首页/菜单(它们不在缓冲里)。
接线方(repl/流式打印)负责:把产出的会话行 append 进来,并据 view() 重绘屏幕底部视口。

- ChatScroll: 行缓冲 + 滚动偏移 + 视口切片(0 = 贴底)
- decode_wheel: 解析终端滚轮序列(SGR: ESC[<64..M 上 / <65..M 下;容错非滚轮)
- KEY_ROLL: 接线方把键名映射为滚动方向(+1/-1/Page 翻页)
"""

import re
from typing import List, Optional, Tuple

MAX_LINES = 2000
_SGR_WHEEL_RE = re.compile(r"\x1b\[<(\d+);(\d+);(\d+)([Mm])")


class ChatScroll:
    """会话行缓冲 + 视口滚动(与任何渲染/输入解耦)"""

    def __init__(self, view_height: Optional[int] = None, max_lines: int = MAX_LINES) -> None:
        self.lines: List[str] = []
        self.max_lines = max_lines
        self.scroll = 0          # 0 = 贴底;正值 = 向上回滚的行数
        self.view_height = view_height or 12

    def set_view_height(self, h: int) -> None:
        self.view_height = max(3, h)

    def append(self, line: str) -> None:
        if line == "":
            return
        self.lines.extend(line.split("\n"))
        if len(self.lines) > self.max_lines:
            del self.lines[: len(self.lines) - self.max_lines]
        # 追加后贴底(新内容到达时跟随到底),聊天软件惯例
        self.scroll = 0

    def max_scroll(self) -> int:
        return max(0, len(self.lines) - self.view_height)

    def scroll_line(self, delta: int) -> None:
        """滚动 delta 行:负数 = 向上看旧内容(增加值),正数 = 向下回底"""
        self.scroll = max(0, min(self.max_scroll(), self.scroll - delta))

    def page(self, delta: int) -> None:
        """翻页:delta=+1 向上一页看旧内容"""
        self.scroll_line(-delta * (self.view_height - 2))

    def view(self) -> Tuple[int, int, List[str]]:
        """返回 (start, end, 视口行) —— 接线方据 height 重绘屏幕底部"""
        start = max(0, len(self.lines) - self.view_height - self.scroll)
        end = len(self.lines) - self.scroll
        return start, end, self.lines[start:end]

    def at_bottom(self) -> bool:
        return self.scroll == 0


def decode_wheel(seq: str) -> Optional[int]:
    """解析滚轮序列:返回 +1(上滚旧内容)/ -1(下滚到底)/ 0(按下,忽略)/ None(非滚轮)。

    SGR 鼠标: ESC[<64;col;rowM = 上滚, <65;col;rowM = 下滚(滚动轮 64/65)。
    非 SGR 的 X10 滚轮(ESC[M 前缀)少见且缺方向,不在本解码范围——由探测方回退键盘。
    """
    m = _SGR_WHEEL_RE.search(seq or "")
    if not m:
        return None
    btn = int(m.group(1))
    if btn in (64, 65):
        return 1 if btn == 64 else -1
    return 0 if btn in (0, 1) else None  # 左/右键按下:交按键处理,不算滚动


# 接线方:把"键名 → 滚动动作"翻译(在真机键循环里用)
def key_to_delta(key: str) -> Optional[int]:
    """上/下/页上/页下/小键盘 8/2 等 → 滚动的行数差(delta,负=向上看)"""
    up_keys = {"up", "pageup", "k", "8", "kp_up"}
    down_keys = {"down", "pagedown", "j", "2", "kp_down"}
    if key.lower() in up_keys:
        return -3
    if key.lower() in down_keys:
        return 3
    return None
