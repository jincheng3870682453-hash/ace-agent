#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ace_selector —— 搜索式选择器（借鉴 OpenClaw 的 SearchableSelectList）

给 REPL 的 /model /provider /goal 等切换命令提供「居中浮层选择器」：

- 输入即过滤：顶部输入框键入即按子串过滤列表，命中词高亮
- ↑↓ / j k 导航（j/k 在过滤框为空时生效，避免与打字冲突），Enter 确认
- Esc 分级取消：先清空过滤词回到全量列表，再按一次才真正取消
- v 展开/收起预览（提供 preview_fn 时），底部显示滚动位置（如 12/50）
- 非 TTY（sys.stdin / sys.stdout 非 isatty）不进入交互、不阻塞：
  直接返回第一个匹配（空过滤 = 全部项 → 下标 0）或 None（无选项时）

实现说明
--------
为什么不用 PromptSession 直接承载列表：PromptSession（及其底层的
create_prompt_application）只能渲染「单行输入 + 单行 bottom_toolbar」，
放不下「输入 + 列表」双窗格，completer 弹窗菜单也不是整页列表。因此本模块
采用 prompt_toolkit 官方对话框（input_dialog / message_dialog）同款写法：
Application + Layout + Float，把面板做成居中浮层（FloatContainer 覆盖在
当前屏幕之上）。交互模型与需求一致——一个 Buffer 接收过滤词，
on_text_changed 每次输入变化重绘列表窗格（invalidate），Enter 确认当前
高亮项，Esc 分级处理，v 预览，j/k 导航。

可测性：匹配 / 过滤 / 高亮抽成纯函数（match_score / filter_items /
highlight_match），不依赖 prompt_toolkit，test_all.py 直接测试。

依赖：prompt_toolkit 为可选依赖，仅在交互路径内延迟导入；缺失或运行异常时
run_selector 返回 None（降级不阻塞，绝不拖垮 REPL）。
"""

from __future__ import annotations

import sys
from typing import Callable, List, Optional, Tuple

__all__ = ["run_selector", "match_score", "filter_items", "highlight_match"]


# ============================================================
# 纯逻辑（不依赖 prompt_toolkit，可直接单测）
# ============================================================

def match_score(item: str, query: str) -> int:
    """子串匹配评分；0 = 不匹配，分数越高越靠前。

    - 空查询：全部项等权（返回 1）
    - 多词查询按空格拆分，每词都必须是子串（AND 语义）
    - 前缀命中比中间命中得分高；命中位置越靠前分越高
    - 完全相等额外加权置顶
    """
    q = query.strip().lower()
    if not q:
        return 1
    text = item.lower()
    total = 0
    for term in q.split():
        idx = text.find(term)
        if idx < 0:
            return 0
        # 前缀命中 +1000；中间命中按位置递减（200 - idx，最低 1）
        total += 1000 if idx == 0 else max(1, 200 - idx)
    if text == q:
        total += 5000          # 完全相等置顶
    return total


def filter_items(items: List[str], query: str) -> List[Tuple[int, int]]:
    """过滤并排序：返回 [(原下标, 评分), ...]，评分 0 的被滤除。

    按评分降序，同分保持原列表顺序（Python sort 稳定），因此空查询时
    结果顺序 == 原列表顺序，非 TTY 降级路径的「第一个匹配」即下标 0。
    """
    scored = [(i, match_score(it, query)) for i, it in enumerate(items)]
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return [(i, s) for i, s in scored if s > 0]


def highlight_match(text: str, query: str) -> List[Tuple[str, str]]:
    """命中高亮分段：返回 [(token, 片段), ...]，可直接喂 prompt_toolkit 渲染。

    - token 为 "sel.row"（普通）或 "sel.hl"（命中）；渲染端对选中行再做
      "sel.row"→"sel.row.sel" / "sel.hl"→"sel.hl.sel" 升级
    - 多词查询的每个词的所有出现都会被标记，重叠/相邻区间合并
    - 纯函数、不依赖 prompt_toolkit，可直接单测
    """
    q = query.strip().lower()
    if not q:
        return [("sel.row", text)]
    spans: List[Tuple[int, int]] = []
    low = text.lower()
    for term in q.split():
        start = 0
        while True:
            idx = low.find(term, start)
            if idx < 0:
                break
            spans.append((idx, idx + len(term)))
            start = idx + len(term)
    if not spans:
        return [("sel.row", text)]
    # 合并重叠/相邻区间
    spans.sort()
    merged = [list(spans[0])]
    for s, e in spans[1:]:
        if s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    segs: List[Tuple[str, str]] = []
    pos = 0
    for s, e in merged:
        if s > pos:
            segs.append(("sel.row", text[pos:s]))
        segs.append(("sel.hl", text[s:e]))
        pos = e
    if pos < len(text):
        segs.append(("sel.row", text[pos:]))
    return segs


# ============================================================
# 交互状态
# ============================================================

class _SelectorState:
    """交互状态：过滤词、高亮下标、滚动偏移、预览开关、过滤结果。"""

    def __init__(self, items: List[str], preview_fn, max_height: int) -> None:
        self.items = items
        self.preview_fn = preview_fn
        self.max_height = max(3, int(max_height))
        self.query = ""
        self.selected = 0          # 在过滤结果中的下标（0-based）
        self.scroll = 0            # 可见窗口首行（相对过滤结果）
        self.show_preview = False  # v 开关
        self.result: Optional[int] = None
        self.matches = filter_items(items, "")   # [(原下标, 评分)]

    @property
    def matched_items(self) -> List[Tuple[int, str]]:
        """过滤结果 [(原下标, 文本), ...]，评分降序（同分保持原序）。"""
        return [(i, self.items[i]) for i, _ in self.matches]

    @property
    def selected_item(self) -> Optional[Tuple[int, str]]:
        """当前高亮项 (原下标, 文本)；无匹配时 None。"""
        if not self.matches:
            return None
        idx = min(self.selected, len(self.matches) - 1)
        i = self.matches[idx][0]
        return (i, self.items[i])


# ============================================================
# 交互主流程（Application + Layout + Float 居中浮层）
# ============================================================

def _interactive_select(title: str, items: List[str],
                        preview_fn, max_height: int) -> Optional[int]:
    """交互主流程：居中浮层 Application + Layout。

    prompt_toolkit 缺失或交互异常时返回 None（降级，不阻塞、不崩溃）。
    """
    try:
        from prompt_toolkit.application import Application
        from prompt_toolkit.application.current import get_app
        from prompt_toolkit.buffer import Buffer
        from prompt_toolkit.filters import Condition
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout import (Float, FloatContainer,
                                           FormattedTextControl, HSplit, Layout,
                                           VSplit, Window)
        from prompt_toolkit.layout.controls import BufferControl
        from prompt_toolkit.styles import Style
        from prompt_toolkit.widgets.base import Frame
    except ImportError:
        return None

    state = _SelectorState(items, preview_fn, max_height)

    # ---------- 过滤输入缓冲：每次输入变化重绘列表（输入即过滤） ----------
    def _on_text_changed(buf):
        state.query = buf.text
        state.selected = 0
        state.scroll = 0
        state.matches = filter_items(items, state.query)
        try:
            get_app().invalidate()   # 通知渲染器重绘列表窗格
        except Exception:
            pass                     # 缓冲在 app 未运行时被修改：无需重绘

    buf = Buffer(on_text_changed=_on_text_changed)

    # ---------- 布局尺寸：面板固定视口，列表在窗口内滚动 ----------
    def _layout_heights(rows: int) -> Tuple[int, int, int]:
        """返回 (列表行数, 预览行数, 面板总高)。终端太小时压缩列表。"""
        prev_h = 0
        if state.show_preview and state.preview_fn:
            prev_h = max(2, min(state.max_height // 2, 8))
        list_h = min(state.max_height, max(1, len(state.matches)))
        body = 1 + list_h + prev_h + 1            # 输入 + 列表 + 预览 + 底部提示
        panel_h = min(body + 2, max(6, rows - 4))  # 含上下边框
        list_h = max(1, (panel_h - 2) - 1 - prev_h - 1)  # 被截断时压缩列表
        return list_h, prev_h, panel_h

    # ---------- 列表窗格内容（命中高亮 + 选中标记 + 滚动窗口） ----------
    _NORM = {"sel.row": "class:sel.row", "sel.hl": "class:sel.hl"}
    _SEL = {"sel.row": "class:sel.row.sel", "sel.hl": "class:sel.hl.sel"}

    def _list_rows() -> List[List[Tuple[str, str]]]:
        """当前可见行（每行是一组 FormattedText 分段）。"""
        rows = state.matched_items
        if not rows:
            return [[("class:sel.empty", "  无匹配项（Esc 清空过滤词）")]]
        total = len(rows)
        sel = min(state.selected, total - 1)
        # 滚动窗口：让选中项始终可见（逐行滚动）
        if state.scroll > sel:
            state.scroll = sel
        elif state.scroll + state.max_height <= sel:
            state.scroll = sel - state.max_height + 1
        state.scroll = max(0, state.scroll)
        lines = []
        for k, (i, text) in enumerate(rows[state.scroll:state.scroll + state.max_height]):
            is_sel = state.scroll + k == sel
            # 纯函数 token（sel.row/sel.hl）→ 渲染用 class: 样式串
            segs = [(_SEL[t] if is_sel else _NORM[t], s)
                    for t, s in highlight_match(text, state.query)]
            lines.append([("class:sel.row.sel" if is_sel else "class:sel.row",
                           "▶ " if is_sel else "  "), *segs])
        return lines

    def _list_formatted() -> List[Tuple[str, str]]:
        """展平为 FormattedText（行间插 \n 分隔）。"""
        out = []
        for row in _list_rows():
            if out:
                out.append(("", "\n"))
            out.extend(row)
        return out

    # ---------- 预览窗格 ----------
    def _preview_rows() -> List[Tuple[str, str]]:
        if not state.show_preview or not state.preview_fn:
            return []
        cur = state.selected_item
        if cur is None:
            return [("class:sel.preview", "  (无匹配，无预览)")]
        i, _ = cur
        try:
            text = state.preview_fn(i) or ""
        except Exception as e:
            text = f"(预览出错: {type(e).__name__}: {e})"
        lines = text.splitlines() or [""]
        cap = max(2, min(state.max_height // 2, 8))
        rows = [("class:sel.preview", f"  {l}") for l in lines[:cap]]
        if len(lines) > cap:
            rows.append(("class:sel.preview",
                         f"  … 共 {len(lines)} 行，仅显示前 {cap} 行"))
        return rows

    def _preview_formatted() -> List[Tuple[str, str]]:
        out = []
        for t, s in _preview_rows():
            if out:
                out.append(("", "\n"))
            out.append((t, s))
        return out

    # ---------- 底部提示条（滚动位置 + 按键提示） ----------
    def _footer_formatted() -> List[Tuple[str, str]]:
        total = len(state.matches)
        cur = 0 if not total else min(state.selected, total - 1) + 1
        bits = [f"{cur}/{total}", "↑↓/jk 选择", "输入过滤", "Enter 确认", "Esc 取消"]
        if state.preview_fn:
            bits.append("v 关闭预览" if state.show_preview else "v 预览")
        return [("class:sel.footer", "  " + "  ·  ".join(bits))]

    # ---------- 窗格与面板 ----------
    input_window = Window(BufferControl(buffer=buf, focusable=True), height=1,
                          style="class:sel.input")
    label_window = Window(FormattedTextControl("🔍 过滤 "), height=1,
                          style="class:sel.prompt", dont_extend_width=True)
    list_window = Window(
        FormattedTextControl(text=_list_formatted),
        height=lambda: _layout_heights(get_app().output.get_size().rows)[0],
        style="class:sel.list",
    )
    preview_window = Window(
        FormattedTextControl(text=_preview_formatted),
        height=lambda: _layout_heights(get_app().output.get_size().rows)[1],
        style="class:sel.preview",
    )
    footer_window = Window(FormattedTextControl(text=_footer_formatted), height=1,
                           style="class:sel.footer")

    body = HSplit([VSplit([label_window, input_window]),
                   list_window, preview_window, footer_window])
    frame = Frame(body=body, title=f" {title} ")
    panel = Float(content=frame)   # left/top/width/height 在 app 建立后计算
    root = FloatContainer(content=Window(FormattedTextControl("")),
                          floats=[panel])

    # ---------- 居中浮层定位 ----------
    def _compute_panel(size) -> Tuple[int, int]:
        """面板宽高：宽度随终端，高度随内容（含边框）。"""
        pw = max(50, min(90, size.columns - 6))
        _, _, ph = _layout_heights(size.rows)
        return pw, ph

    def _place_panel() -> None:
        """按当前终端尺寸重算面板位置（水平垂直居中）。"""
        size = get_app().output.get_size()
        pw, ph = _compute_panel(size)
        panel.width, panel.height = pw, ph
        panel.left = max(0, (size.columns - pw) // 2)
        panel.top = max(0, (size.rows - ph) // 2)
        get_app().invalidate()

    # ---------- 按键绑定 ----------
    kb = KeyBindings()

    # 仅当过滤框为空时 j/k/v 生效（避免与打字冲突：输入字母即过滤）
    browse_mode = Condition(lambda: get_app().current_buffer.text == "")

    @kb.add("enter")
    def _confirm(event):
        cur = state.selected_item
        if cur is not None:
            state.result = cur[0]
            event.app.exit()

    @kb.add("escape")
    def _escape(event):
        # 有过滤词：先清空过滤回到全量列表；无过滤词：取消
        if state.query:
            event.app.current_buffer.text = ""   # 触发 on_text_changed 重绘
        else:
            event.app.exit()

    @kb.add("c-c")
    def _cancel(event):
        event.app.exit()

    @kb.add("down")
    @kb.add("c-n")
    def _next(event):
        if state.matches:
            state.selected = min(state.selected + 1, len(state.matches) - 1)
            event.app.invalidate()

    @kb.add("up")
    @kb.add("c-p")
    def _prev(event):
        if state.matches:
            state.selected = max(state.selected - 1, 0)
            event.app.invalidate()

    @kb.add("pagedown")
    def _page_down(event):
        if state.matches:
            state.selected = min(state.selected + state.max_height,
                                 len(state.matches) - 1)
            event.app.invalidate()

    @kb.add("pageup")
    def _page_up(event):
        if state.matches:
            state.selected = max(state.selected - state.max_height, 0)
            event.app.invalidate()

    @kb.add("j", filter=browse_mode)
    def _j_next(event):
        _next(event)

    @kb.add("k", filter=browse_mode)
    def _k_prev(event):
        _prev(event)

    @kb.add("v", filter=browse_mode)
    def _toggle_preview(event):
        if state.preview_fn:
            state.show_preview = not state.show_preview
            _place_panel()   # 预览区出现/消失 → 重算面板高度并居中

    # ---------- 应用与运行 ----------
    style = Style.from_dict({
        # Frame 自带 class:frame.*（边框/标题）—— 字典 key 是裸类名
        "frame.border": "#8a8a9a",
        "frame.label": "bold #f6c453",
        # 输入行
        "sel.prompt": "bold #7ecb8f",
        "sel.input": "#ffffff",
        # 列表行
        "sel.row": "#cccccc",
        "sel.row.sel": "bg:#5f3dc4 #ffffff",
        "sel.hl": "bold #f6c453",
        "sel.hl.sel": "bg:#5f3dc4 #f6c453 bold",
        "sel.empty": "#666666 italic",
        # 底部提示条 / 预览区
        "sel.footer": "bg:#2b2b3c #aaaaaa",
        "sel.preview": "#9cdcfe",
    })

    app = Application(
        layout=Layout(root, focused_element=input_window),
        style=style,
        key_bindings=kb,
        erase_when_done=True,                  # 结束后擦除浮层，露出下层屏幕
        enable_page_navigation_bindings=False,  # PageUp/PageDown 走自绘滚动
    )

    # 首次定位面板（居中）；随后 v 切换预览时由 _place_panel 重算
    size0 = app.output.get_size()
    pw0, ph0 = _compute_panel(size0)
    panel.width, panel.height = pw0, ph0
    panel.left = max(0, (size0.columns - pw0) // 2)
    panel.top = max(0, (size0.rows - ph0) // 2)

    try:
        app.run()
    except (Exception, KeyboardInterrupt, EOFError):
        return None          # 任何异常都降级为取消，绝不拖垮 REPL
    return state.result


# ============================================================
# 入口
# ============================================================

def run_selector(title: str, items: List[str],
                 preview_fn: Optional[Callable[[int], str]] = None,
                 max_height: int = 12) -> Optional[int]:
    """交互式搜索选择器。返回选中项 index；用户取消（Esc/Ctrl+C）返回 None。

    参数:
      title:      顶部标题（如 "选择模型"）
      items:      选项列表（纯文本，可含描述，如 "deepseek-v4-flash  DeepSeek 官方"）
      preview_fn: 可选；选中项时显示预览，接收 index（原下标）返回多行文本
      max_height: 列表可见行数上限（默认 12）

    行为:
      - 非 TTY（sys.stdin / sys.stdout 非 isatty）：不阻塞，直接返回
        第一个匹配（空过滤 = 全部项 → 下标 0）；无选项返回 None
      - prompt_toolkit 缺失或交互异常：返回 None（可选依赖降级）
    """
    # 无选项：无可选择，直接返回 None（不进交互，也不阻塞）
    if not items:
        return None
    # 非 TTY：不阻塞，直接返回首个（最佳）匹配
    try:
        interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:
        interactive = False
    if not interactive:
        return filter_items(items, "")[0][0]
    return _interactive_select(title, items, preview_fn, max_height)
