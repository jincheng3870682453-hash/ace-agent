#!/usr/bin/env python3
"""把一次真实的 `ai_code.py --mock` 会话录成 README 里的动画 SVG。

为什么自己写而不是用 VHS / asciinema：
它们都要 PTY + ffmpeg（VHS 还要 Docker），本项目核心零依赖，不想为一张图引入这些。
mock 模式本身就是脚本化的离线假模型，输出稳定可复现 —— 正好满足「演示要能重复渲染」。

口径：SVG 里的每一行文字都是子进程真实打印的字节（含真实 ANSI 配色），
唯一的人为补写是「用户敲进去的那一行」—— 管道 stdin 不会回显，
而真实终端会，所以在提示符后面把输入补回去，才是用户实际看到的画面。

用法：
    python demo/record_demo.py              # 重新录制并写出 demo/demo.svg
    python demo/record_demo.py --check      # 只检查现有 SVG 是否还能重现（CI 用）
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT_SVG = HERE / "demo.svg"

# 演示脚本：mock 是两步剧本（工具调用 → 基于结果作答），其余都是本地斜杠命令。
# 不要写"改代码/装依赖"这种 mock 演不出来的台词，演示必须和真实行为一致。
SESSION = ["现在几点", "/status", "/permission readonly", "/exit"]

# 只保留演示需要的行数：/help 那张大表会把画面撑爆，不进脚本。
MAX_LINES = 26
PROMPT = "❯"

# 一眼能看懂的暗色主题（对比度按 WCAG AA 选的，前景 #d7dce5 / 背景 #11141b）
THEME = {
    "bg": "#11141b", "chrome": "#1b1f29", "fg": "#d7dce5", "dim": "#7d879c",
    "red": "#f2777a", "green": "#5fd68a", "yellow": "#f0c674",
    "blue": "#7aa6f0", "magenta": "#c39ac9", "cyan": "#66cccc",
}
SGR_TO_KEY = {"31": "red", "32": "green", "33": "yellow",
              "34": "blue", "35": "magenta", "36": "cyan", "2": "dim"}

FONT_SIZE = 15
LINE_H = 24
CHAR_W = FONT_SIZE * 0.6          # 等宽西文字符宽度
PAD_X, PAD_TOP = 22, 52           # PAD_TOP 留给窗口栏
CURSOR_LINE_DELAY = 0.75          # 用户输入行之间的停顿，给人"在打字"的节奏
LINE_DELAY = 0.28                 # 普通输出行的间隔
TAIL_PAUSE = 2.6                  # 循环前的停顿，不然看完就闪回开头

_SGR_RE = re.compile(r"\033\[([0-9;]*)m")
# 清屏 / 移光标之类的控制序列（注意排除 m，那是配色，要留给 split_ansi 解析）
_ANSI_OTHER_RE = re.compile(r"\033\[[0-9;]*(?!m)[A-Za-z]")
_SPINNER_RE = re.compile(r"^[◈◐◑◒◓]\s")



def display_width(text: str) -> int:
    """CJK 占两列 —— 不算宽度的话中文行会溢出画布。"""
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)


def capture_session() -> str:
    """真的把 CLI 跑起来，拿它打印的原始字节（含 ANSI）。"""
    env = dict(os.environ)
    env["FORCE_COLOR"] = "1"          # 管道下强制上色，见 ai_code.py 的 USE_COLOR
    env.pop("NO_COLOR", None)
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "ai_code.py", "--mock"],
        input="\n".join(SESSION) + "\n",
        cwd=str(ROOT), env=env, text=True, encoding="utf-8",
        capture_output=True, timeout=120,
    )
    if proc.returncode != 0:
        raise SystemExit(f"录制失败（退出码 {proc.returncode}）:\n{proc.stderr[-2000:]}")
    return proc.stdout


def to_transcript(raw: str) -> list[tuple[str, bool]]:
    """原始输出 → [(带 ANSI 的一行, 是否是用户输入行)]。

    做四件事：折叠 \\r（转轮动画只留最后一帧）、丢掉管道模式独有的噪声行、
    把「提示符 + 紧跟其后的输出」拆成两行并补回用户敲的内容、合并重复的转轮帧。

    提示符是 print(..., end="") 打出来的，管道里它和后面的输出粘在同一物理行；
    真实终端上用户先看到 "❯ 我敲的字"，回车后输出才另起一行 —— 拆开才还原真实画面。
    """
    typed = list(SESSION)
    out: list[tuple[str, bool]] = []

    def push(line: str, is_input: bool = False) -> None:
        plain = _SGR_RE.sub("", line).strip()
        if not plain:
            if not out or out[-1][0] == "":
                return                                     # 不留连续空行 / 开头空行
            out.append(("", False))
            return
        if "非交互终端" in plain or "补全菜单不可用" in plain:
            return                                          # 只有管道录制才有，真实终端没有
        if out and _SPINNER_RE.match(plain) and _SPINNER_RE.match(
                _SGR_RE.sub("", out[-1][0]).strip()):
            out[-1] = (line, False)                         # 同一段转轮动画只留最后一帧
            return
        out.append((line, is_input))

    for physical in raw.replace("\r\n", "\n").split("\n"):
        line = _ANSI_OTHER_RE.sub("", physical.split("\r")[-1].rstrip())
        plain = _SGR_RE.sub("", line)
        if PROMPT in plain and plain.lstrip().startswith(PROMPT):
            if not typed:
                continue
            push(f"{PROMPT} {typed.pop(0)}", is_input=True)
            idx = line.find(PROMPT) + len(PROMPT)
            push(line[idx:].lstrip())                       # 提示符后面粘着的那段输出
            continue
        push(line)

    while out and out[-1][0] == "":
        out.pop()
    return out[:MAX_LINES]



def split_ansi(line: str) -> list[tuple[str, str]]:
    """ANSI 行 → [(文本, 颜色 key)]，只认本项目用到的那几个 SGR。"""
    spans: list[tuple[str, str]] = []
    color = "fg"
    pos = 0
    for m in _SGR_RE.finditer(line):
        if m.start() > pos:
            spans.append((line[pos:m.start()], color))
        codes = [c for c in m.group(1).split(";") if c]
        if not codes or "0" in codes:
            color = "fg"
        else:
            for code in codes:
                if code in SGR_TO_KEY:
                    color = SGR_TO_KEY[code]
        pos = m.end()
    if pos < len(line):
        spans.append((line[pos:], color))
    return [(t, c) for t, c in spans if t]


def build_svg(transcript: list[tuple[str, bool]]) -> str:
    cols = max((display_width(_SGR_RE.sub("", ln)) for ln, _ in transcript), default=60)
    width = int(PAD_X * 2 + max(cols, 62) * CHAR_W)
    height = int(PAD_TOP + len(transcript) * LINE_H + 22)

    # 时间轴：输入行停久一点，输出行连着走
    times, clock = [], 0.6
    for _, is_input in transcript:
        times.append(clock)
        clock += CURSOR_LINE_DELAY if is_input else LINE_DELAY
    total = clock + TAIL_PAUSE

    rules, body = [], []
    for i, ((line, is_input), t0) in enumerate(zip(transcript, times)):
        pct = max(0.0, min(99.9, t0 / total * 100))
        # 每行一条 keyframes：到点显形、留到循环末尾。比 animation-delay 更可控，
        # 也能干净地无限循环（delay 方案在循环边界会闪）。
        rules.append(f"@keyframes s{i}{{0%,{pct:.3f}%{{opacity:0}}"
                     f"{pct + 0.001:.3f}%,100%{{opacity:1}}}}")
        rules.append(f".r{i}{{animation:s{i} {total:.2f}s steps(1,end) infinite}}")
        y = PAD_TOP + i * LINE_H
        tspans = "".join(
            f'<tspan fill="{THEME[key]}">{escape(text)}</tspan>'
            for text, key in split_ansi(line)
        ) or "&#160;"
        cursor = (f'<tspan class="cur" fill="{THEME["magenta"]}">&#9601;</tspan>'
                  if is_input else "")
        body.append(f'<text class="r{i}" x="{PAD_X}" y="{y}" xml:space="preserve">'
                    f'{tspans}{cursor}</text>')

    dots = "".join(
        f'<circle cx="{22 + n * 18}" cy="20" r="5.5" fill="{col}"/>'
        for n, col in enumerate(("#ff5f57", "#febc2e", "#28c840"))
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" \
viewBox="0 0 {width} {height}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,\
'DejaVu Sans Mono','Noto Sans Mono CJK SC',monospace" font-size="{FONT_SIZE}">
<style>
text{{white-space:pre;dominant-baseline:middle}}
{chr(10).join(rules)}
.cur{{animation:blink 1.05s steps(1,end) infinite}}
@keyframes blink{{0%,49%{{opacity:1}}50%,100%{{opacity:0}}}}
</style>
<rect width="{width}" height="{height}" rx="10" fill="{THEME['chrome']}"/>
<rect y="40" width="{width}" height="{height - 40}" fill="{THEME['bg']}"/>
{dots}
<text x="{width / 2}" y="21" text-anchor="middle" font-size="12.5" \
fill="{THEME['dim']}">ace-agent — python ai_code.py --mock</text>
{chr(10).join(body)}
</svg>
"""


def main() -> None:
    ap = argparse.ArgumentParser(description="录制 ace-agent 演示动画（SVG）")
    ap.add_argument("--check", action="store_true",
                    help="只校验现有 demo.svg 能否原样重现，不覆盖文件")
    args = ap.parse_args()

    transcript = to_transcript(capture_session())
    if not transcript:
        raise SystemExit("录制到的会话是空的，脚本或 CLI 输出可能变了")
    svg = build_svg(transcript)

    if args.check:
        if not OUT_SVG.exists():
            raise SystemExit(f"{OUT_SVG} 不存在，先跑一次不带 --check 的录制")
        # 时间戳会变（mock 会问当前时间），只比结构：行数与去掉数字后的骨架
        old = re.sub(r"[\d.]+", "#", OUT_SVG.read_text(encoding="utf-8"))
        if re.sub(r"[\d.]+", "#", svg) != old:
            raise SystemExit("demo.svg 与当前 CLI 输出不一致，请重新录制")
        print("demo.svg 与当前 CLI 输出一致")
        return

    OUT_SVG.write_text(svg, encoding="utf-8")
    print(f"已写出 {OUT_SVG.relative_to(ROOT)}（{len(transcript)} 行）")



if __name__ == "__main__":
    main()
