#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_code.py —— ACE（AI Code Engine）命令行

    ❯ 输入提示符 / ◈ 流式输出 / 斜杠命令 / 状态统计 / 快照回滚 / 报告生成

配置优先级（从高到低）：
    1. 命令行参数
    2. ~/.ai_code.json            （AI Code 的配置文件）
    3. ~/.claude/settings.json    （本机已有模型配置，自动复用 ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN / model）
    4. 环境变量 AGENT_BASE_URL / AGENT_API_KEY / AGENT_MODEL

支持两种 API 格式（自动识别）：
    · OpenAI 兼容：  {base}/chat/completions
    · Anthropic 兼容：{base}/v1/messages

用法：
    ace                                        # cmd 全局命令（已注册到 PATH，随时唤醒）
    python ai_code.py                          # 交互模式
    python ai_code.py --mock                   # 离线演示
    python ai_code.py --input "现在几点了"      # 单次对话
    python ai_code.py --base-url https://api.deepseek.com/v1 --api-key sk-xxx --model deepseek-chat

斜杠命令（输入 / 或命令前缀会自动给出补全提示）：
    /help  /clear  /status  /stats  /memory  /snapshots  /undo  /rollback <id>
    /report  /permission [level]  /mock  /model [模型名]  /provider [编号|id] [api-key]
    /config  /open <路径>  /edit <路径>  /exit
"""

import argparse
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Windows GBK 控制台兼容：强制 UTF-8 输出（否则 emoji 会 UnicodeEncodeError）
for _stream in (sys.stdout, sys.stderr):
    try:
        if _stream.encoding and _stream.encoding.lower() not in ("utf-8", "utf8"):
            _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(FOLDER))

from execution_layer import ExecutionLayer  # noqa: E402
from ace_cards import status_mark, tool_card  # noqa: E402
try:
    from ace_selector import run_selector  # noqa: E402
except ImportError:
    run_selector = None
from agent_runner import (ERROR_STATUSES, GRANT_DENY, GRANT_SESSION,  # noqa: E402
                          PROMPT_EXEC_EXCEPTION, PROMPT_ERROR_RETRY,
                          PROMPT_PLAN_APPROVED, PROMPT_TOOL_RESULT,
                          PROMPT_UNVERIFIED_CLAIM,
                          ModelProvider, ask_grant, ask_yes_no,
                          claims_completed_action,
                          content_to_tool_protocol, final_reply_protocol,
                          load_system_prompt, render_result, render_tool_result,
                          resolve_permission, resolve_plan,
                          retry_notice, tools_for_permission,
                          sanitize_plain_content, tool_calls_to_protocol)
from ace_isolation import wrap_untrusted  # noqa: E402
import ace_http  # noqa: E402
import ace_context  # noqa: E402
from i18n import set_language, t  # noqa: E402

CONFIG_PATH = Path.home() / ".ai_code.json"
LEGACY_CONFIG_PATH = Path.home() / ".agent_cli.json"
CLAUDE_SETTINGS_PATH = Path.home() / ".claude" / "settings.json"
MAX_ROUNDS = 20
STALL_ABORT_ROUNDS = 6  # 连续失败轮数阈值：达到即中止会话（防死循环烧轮数）

# Windows 无默认打开程序时，这些文本类扩展名回退记事本打开
_TEXT_EXTENSIONS = {".py", ".txt", ".md", ".json", ".log", ".csv", ".ini", ".cfg",
                    ".yaml", ".yml", ".toml", ".xml", ".html", ".css", ".js",
                    ".ts", ".bat", ".cmd", ".ps1", ".sql", ".env"}
SYSTEM_PROMPT = load_system_prompt()

logger = logging.getLogger("ace")


class CommandCancelled(Exception):
    """交互子流程被用户取消（如 Ctrl+C），区别于致命异常：只中止当前命令，不退出整个 CLI"""


# ACE ASCII 品牌 logo（ANSI Shadow 字体）
ACE_LOGO = r"""
 █████╗  ██████╗ ███████╗
██╔══██╗██╔════╝ ██╔════╝
███████║██║      █████╗
██╔══██║██║      ██╔══╝
██║  ██║╚██████╗ ███████╗
╚═╝  ╚═╝ ╚═════╝ ╚══════╝""".strip("\n")


# AI 提供商注册表（参考本机 cli/AI-CLI-安装平台/lib/api.js，模型名 2026-08 调研整理）
PROVIDERS = [
    {"id": "zhipu", "name": "智谱 GLM（Anthropic 兼容端点）",
     "base_url": "https://open.bigmodel.cn/api/anthropic", "api_format": "anthropic",
     "models": ["glm-4.7-flash", "glm-4.6", "glm-4.5-air", "glm-4.7",
                "glm-5.2", "glm-4.5-flash"]},
    {"id": "zhipu-openai", "name": "智谱 GLM（OpenAI 兼容端点）",
     "base_url": "https://open.bigmodel.cn/api/paas/v4", "api_format": "openai",
     "models": ["glm-4.7-flash", "glm-4.6", "glm-4.5-air", "glm-4.7",
                "glm-5.2", "glm-4.5-flash"]},
    {"id": "deepseek", "name": "DeepSeek（深度求索）",
     "base_url": "https://api.deepseek.com/v1", "api_format": "openai",
     "models": ["deepseek-v4-pro", "deepseek-v4-flash", "deepseek-chat",
                "deepseek-reasoner"]},
    {"id": "moonshot", "name": "Kimi / Moonshot AI",
     "base_url": "https://api.moonshot.cn/v1", "api_format": "openai",
     "models": ["kimi-k2.7", "kimi-k2.7-code", "kimi-k2.6", "kimi-k2", "kimi-latest"]},
    {"id": "openai", "name": "OpenAI",
     "base_url": "https://api.openai.com/v1", "api_format": "openai",
     "models": ["gpt-5.5", "gpt-5.2", "gpt-4o", "o3", "o4-mini"]},
    {"id": "anthropic", "name": "Anthropic Claude",
     "base_url": "https://api.anthropic.com", "api_format": "anthropic",
     "models": ["claude-opus-4.7", "claude-sonnet-4.5", "claude-3.7-sonnet"]},
    {"id": "qwen", "name": "阿里通义 Qwen",
     "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "api_format": "openai",
     "models": ["qwen3-max", "qwen3-coder", "qwen3.6", "qwen2.5-coder"]},
    {"id": "siliconflow", "name": "硅基流动 SiliconFlow",
     "base_url": "https://api.siliconflow.cn/v1", "api_format": "openai",
     "models": ["deepseek-ai/DeepSeek-V3", "Qwen/Qwen3-235B-A22B", "zai-org/GLM-5.2"]},
    {"id": "openrouter", "name": "OpenRouter（聚合）",
     "base_url": "https://openrouter.ai/api/v1", "api_format": "openai",
     "models": ["deepseek/deepseek-chat", "openai/gpt-5.5",
                "anthropic/claude-opus-4.7", "z-ai/glm-5.2"]},
    {"id": "ollama", "name": "Ollama（本地模型）",
     "base_url": "http://localhost:11434/v1", "api_format": "openai",
     "models": ["qwen2.5", "llama3.2", "deepseek-r1"]},
]


def _find_provider(cfg: Dict) -> Optional[Dict]:
    """按 base_url 匹配当前提供商预设"""
    base = str(cfg.get("base_url", "")).rstrip("/")
    for p in PROVIDERS:
        if base == p["base_url"].rstrip("/"):
            return p
    return None


def _pip_install_with_fallbacks(target: str) -> bool:
    """智能安装：已装则跳过；默认源失败自动切换清华/阿里/豆瓣镜像；装完导入验证"""
    import importlib
    import subprocess as _sp
    try:
        importlib.import_module(target)
        return True   # 已安装，无需重复下载
    except ImportError:
        pass
    sources = [
        [],
        ["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"],
        ["-i", "https://mirrors.aliyun.com/pypi/simple"],
        ["-i", "https://pypi.doubanio.com/simple"],
    ]
    for src in sources:
        name = src[-1] if src else "默认源"
        print(f"  尝试 {name} ...")
        try:
            rc = _sp.run([sys.executable, "-m", "pip", "install", target] + src,
                         timeout=300).returncode
        except Exception:
            rc = 1
        if rc == 0:
            check = _sp.run([sys.executable, "-c", f"import {target}"])
            if check.returncode == 0:
                return True
    return False


def _looks_like_cli_command(line: str) -> bool:
    """防蠢检测：用户把 cmd 命令/参数误打进 REPL（如 ace --install-ui、--mock、pip install）"""
    s = line.strip().lower()
    return bool(re.match(r"^(ace|ai[-_ ]?code)\s+--", s)
                or re.match(r"^--[a-z-]+", s)
                or re.match(r"^pip(3)?\s", s))


def _model_error_hint(e: Exception) -> str:
    """根据 HTTP 错误码返回排查提示（401 等常见错误不再只甩英文；跟随界面语言）"""
    code = getattr(getattr(e, "response", None), "status_code", None)
    if code == 401:
        return t("model_err_401")
    if code == 403:
        return t("model_err_403")
    if code == 404:
        return t("model_err_404")
    if code == 429:
        return t("model_err_429")
    if code and 500 <= code < 600:
        return t("model_err_5xx")
    return ""


# —— 项目指令（AGENTS.md，借鉴 Codex agents_md.rs） ——
AGENTS_MD_MAX_BYTES = 32 * 1024   # 与 Codex project_doc_max_bytes 同级预算
AGENTS_MD_FILENAMES = ("AGENTS.md", "CLAUDE.md")   # AGENTS.md 优先，CLAUDE.md 兼容


def load_project_instructions(cwd: str) -> str:
    """Codex 式 AGENTS.md 层级发现：cwd 向上找项目根（最近的 .git 标记），
    收集 根 → cwd 每层 的 AGENTS.md（无则 CLAUDE.md，每层至多一个），根到叶拼接，
    32 KiB 预算硬截断。无任何指令文件返回空串。纯只读，不执行任何内容。"""
    root = Path(cwd).resolve()
    git_root = None
    probe = root
    while True:
        if (probe / ".git").exists():
            git_root = probe
            break
        if probe.parent == probe:
            break
        probe = probe.parent
    base = git_root or root

    layers = []   # (相对路径, 文本)，从 cwd 向上收集，最后反转成根→叶
    cur = root
    while True:
        for name in AGENTS_MD_FILENAMES:
            f = cur / name
            if f.is_file():
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    break
                if text.strip():
                    rel = str(f.relative_to(base)) if git_root else str(f)
                    layers.append((rel, text))
                break
        if cur == base:
            break
        if cur.parent == cur:
            break
        cur = cur.parent
    layers.reverse()

    parts: List[str] = []
    total = 0
    for rel, text in layers:
        block = f"# {rel}\n\n{text.strip()}"
        if total + len(block) > AGENTS_MD_MAX_BYTES:
            remain = AGENTS_MD_MAX_BYTES - total
            if remain > 0:
                parts.append(block[:remain])
            break
        parts.append(block)
        total += len(block)
    return "\n\n".join(parts)


# 支持"无空格参数"的斜杠命令：/search关键词 → /search 关键词
ARG_COMMANDS = {"/search", "/open", "/edit", "/model", "/provider",
                "/rollback", "/permission"}


def _parse_slash_command(cmd: str):
    """兼容无空格参数：/search关键词 → ("/search", "关键词")；
    带空格或非参数命令原样返回（("命令", "")），由 run_command 走正常拆分。"""
    raw = (cmd or "").strip()
    if not raw.startswith("/") or len(raw) < 2:
        parts = raw.split()
        return (parts[0].lower() if parts else ""), ""
    first = raw.split()[0].lower()
    if first in ARG_COMMANDS:
        # 带空格场景：由 run_command 正常拆分，这里不吞参数
        return first, ""
    # 无空格场景：raw 直接以某个命令名开头（如 /search今天天气）
    for k in sorted(ARG_COMMANDS, key=len, reverse=True):
        if raw.lower().startswith(k) and len(raw) > len(k):
            return k, raw[len(k):].strip()
    return first, ""


# ============================================================
# @ 快捷方式：语言切换 / 技能切换 / 文件与文件夹引用
# ============================================================

LANG_NAMES = {"zh": "中文", "en": "English", "ja": "日本語"}

SKILLS = {
    "coding": {"name": "编程开发", "desc": "专注写代码、改代码、调试与解释代码",
               "tools": ["code_execute", "file_write", "terminal_exec", "search"]},
    "writing": {"name": "文案写作", "desc": "专注写作、润色、总结与报告",
                "tools": ["file_write", "search", "notify_send", "parse_document"]},
    "analysis": {"name": "数据分析", "desc": "专注数据分析、统计与报表",
                 "tools": ["db_query", "math_calc", "parse_document", "search"]},
    "fiction": {"name": "小说创作", "desc": "专注小说、故事、角色与剧情创作",
                "tools": ["file_write", "search", "file_read"]},
    "general": {"name": "通用助手", "desc": "通用对话与日常任务",
                "tools": ["search", "file_read", "datetime_now"]},
}

AT_HELP = (
    "  ✨ @ 快捷方式 —— 对话上下文控制\n"
    "\n"
    "  输入 @ 可快速调整 Agent 的「工作方式」：\n"
    "    · 语言：让 Agent 用指定语言回复（@lang）\n"
    "    · 技能：切换专注方向，编程/写作/分析/小说/通用（@skill）\n"
    "    · 引用：把文件或文件夹内容带进对话上下文（@file / @folder）\n"
    "\n"
    "  @lang zh|en|ja     切换回复语言（当前: {lang}）\n"
    "  @skill <名称>      切换技能（coding/writing/analysis/fiction/general）\n"
    "  @file <路径>       把文件内容加入上下文（≤4000 字符，自动截断）\n"
    "  @folder <路径>     把文件夹文件列表加入上下文（≤30 项）\n"
    "  @refs              查看当前已引用内容\n"
    "  @clear             清空文件/文件夹引用\n"
    "\n"
    "  示例: @lang en · @skill coding · @file README.md"
)

AT_COMPLETE_META = {
    "lang": "at_complete_lang",
    "skill": "at_complete_skill",
    "file": "at_complete_file",
    "folder": "at_complete_folder",
    "refs": "at_complete_refs",
    "clear": "at_complete_clear",
}


def _config_sanity_hints(cfg: Dict) -> List[str]:
    """启动自检：配置防蠢提示（如 ZAI 别名模型直连 BigModel 不被识别）"""
    hints = []
    model = str(cfg.get("model", ""))
    base = str(cfg.get("base_url", ""))
    if model.startswith("deepseek-v4") and "bigmodel" in base:
        hints.append("检测到模型名是 ZAI 网关别名（deepseek-v4-*），直连 BigModel 不认，请用 /model glm-4.6 切换")
    return hints


@dataclass
class CLIConfig:
    """ACE 运行配置（纯标准库 dataclass 校验，替代手写 get("key", default) 与 Pydantic 方案）"""

    base_url: str = ""
    api_key: str = ""
    model: str = "default"
    permission: str = "readonly"
    project_root: str = "."
    bait: bool = True
    tools: bool = False
    max_history: int = 0
    # 模型上下文窗口。压缩阈值按它算，所以宁可填小不要填大：
    # 填大了会在"以为还有余量"的时候被服务端直接拒掉。
    context_window: int = 32768
    # 上下文压缩开关。关掉就退回纯硬截断（会丢早期对话，包括第一条用户消息）。
    compact: bool = True
    lang: str = "zh"
    skill: str = "general"
    # 执行位置：
    #   off    = 宿主直跑（Go 执行器在时顺带用一下，只为把进程树收干净）
    #   job    = Windows Job Object 边界（executor/ 里的 Go 执行器，Tier-1）
    #   docker = 一次性容器（见 tools/docker_sandbox.py）
    # job 与 docker 都不做静默回退：拿不到边界就报 503，绝不偷偷改回宿主执行。
    sandbox: str = "off"
    sandbox_image: str = ""

    @classmethod
    def from_dict(cls, data: Dict) -> "CLIConfig":
        """从字典构造，只取已知字段；缺失字段用默认值"""
        known = {f.name: data[f.name] for f in fields(cls) if f.name in data}
        return cls(**known)

    def __post_init__(self) -> None:
        if self.permission not in ("readonly", "write", "full"):
            raise ValueError(f"permission 必须是 readonly/write/full，收到: {self.permission!r}")
        if (not isinstance(self.max_history, int)
                or isinstance(self.max_history, bool) or self.max_history < 0):
            raise ValueError(f"max_history 必须是非负整数，收到: {self.max_history!r}")
        if (not isinstance(self.context_window, int)
                or isinstance(self.context_window, bool) or self.context_window < 2048):
            raise ValueError(
                f"context_window 必须是不小于 2048 的整数，收到: {self.context_window!r}")
        if self.lang not in LANG_NAMES:
            raise ValueError(f"lang 必须是 {', '.join(LANG_NAMES)}，收到: {self.lang!r}")
        if self.skill not in SKILLS:
            raise ValueError(f"skill 必须是 {', '.join(SKILLS)}，收到: {self.skill!r}")
        if self.sandbox not in ("off", "job", "docker"):
            raise ValueError(f"sandbox 必须是 off/job/docker，收到: {self.sandbox!r}")

# ---- ANSI 颜色（非 tty 或 NO_COLOR 时自动关闭，遵循 NO_COLOR 约定）----
ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
}
# FORCE_COLOR：管道/重定向下强制保留颜色。NO_COLOR 优先级更高（用户明确要求关色）。
# demo/record_demo.py 靠它抓到带色的真实会话，否则录出来的演示是灰的。
USE_COLOR = bool((sys.stdout.isatty() or os.environ.get("FORCE_COLOR"))
                 and not os.environ.get("NO_COLOR"))
if os.name == "nt":
    try:
        os.system("")  # Windows 启用 ANSI 转义（其他平台无此需要）
    except Exception:
        pass


def c(color: str, text: str) -> str:
    return f"{ANSI[color]}{text}{ANSI['reset']}" if USE_COLOR else text


def _build_slash_completer(commands: Dict[str, str]):
    """构建 / 命令实时补全器（Claude Code 同款：按下 / 弹菜单，边打字边过滤）
    需要 prompt_toolkit；/open /edit 后面接文件路径补全。"""
    from prompt_toolkit.completion import Completer, Completion, PathCompleter
    from prompt_toolkit.document import Document as PTDocument

    class SlashCompleter(Completer):
        def __init__(self) -> None:
            self.commands = commands
            self._path = PathCompleter(only_directories=False, expanduser=True)

        def get_completions(self, document, complete_event):
            text = document.text_before_cursor
            if text.startswith("@"):
                # @ 快捷方式补全：@lang / @skill / @file / @folder / @refs / @clear
                m = re.match(r"^@(file|folder)\s+(.*)$", text)
                if m:
                    sub = PTDocument(m.group(2), cursor_position=len(m.group(2)))
                    # 子 document 光标与全局光标位置一致，start_position 直接透传；
                    # 加 offset 会在路径为空（输入 @file 后按空格）时算出正数，触发
                    # prompt_toolkit 的 assert start_position <= 0 崩溃
                    for comp in self._path.get_completions(sub, complete_event):
                        yield Completion(
                            comp.text,
                            start_position=comp.start_position,
                            display=comp.display,
                            display_meta=comp.display_meta,
                        )
                    return
                m = re.match(r"^@skill\s+(.*)$", text)
                if m:
                    sk_prefix = m.group(1)
                    for key in SKILLS:
                        if key.startswith(sk_prefix):
                            yield Completion(
                                key,
                                start_position=-(len(text) - len("@skill ")),
                                display_meta=SKILLS[key]["name"],
                            )
                    return
                prefix = text[1:]
                for key in ("lang", "skill", "file", "folder", "refs", "clear"):
                    if key.startswith(prefix):
                        yield Completion("@" + key, start_position=-len(text),
                                         display_meta=t(AT_COMPLETE_META.get(key, key)))
                return
            if not text.startswith("/"):
                return
            # /open /edit 后面的路径做文件补全
            m = re.match(r"^/(open|edit)\s+(.*)$", text)
            if m:
                sub = PTDocument(m.group(2), cursor_position=len(m.group(2)))
                # 同 @file：start_position 直接透传，避免空格后算出正数触发断言崩溃
                for comp in self._path.get_completions(sub, complete_event):
                    yield Completion(
                        comp.text,
                        start_position=comp.start_position,
                        display=comp.display,
                        display_meta=comp.display_meta,
                    )
                return
            # 命令名前缀实时过滤
            prefix = text[1:]
            for name, desc in self.commands.items():
                if name.startswith("/" + prefix):
                    yield Completion(name, start_position=-len(text),
                                     display_meta=t(desc))

    return SlashCompleter()


def _handle_enter_key(buf) -> None:
    """REPL 回车键统一决策（独立成函数便于测试）：
    - 补全菜单开着且已选定（↑↓ 移动过）→ 把选中项填入输入行并关闭菜单，
      不发送（再按一次回车才发送）
      （修复：此前回车会把选中项丢掉——菜单关了但命令也没进去）
    - 斜杠命令第一次回车只弹出命令列表（预览，不发送）
    - 第二次回车才真正发送
    """
    cs = buf.complete_state
    if cs is not None:
        cur = cs.current_completion
        if cur is not None:
            # 有选中补全：插入输入行并关闭菜单，等待下一次回车发送
            buf.apply_completion(cur)
            buf._ace_preview_shown = True
            return
        # 菜单开着但没选定：维持两段回车语义
        if getattr(buf, "_ace_preview_shown", False):
            buf._ace_preview_shown = False
            buf.validate_and_handle()
            return
        # 菜单由打字自动弹出（complete_while_typing），
        # 这次回车算第一次（预览），等第二次回车发送
        buf._ace_preview_shown = True
        return
    text = buf.text.strip()
    if text.startswith("/") and not getattr(buf, "_ace_preview_shown", False):
        # 第一次回车：展开补全菜单（列表预览），不发送
        buf._ace_preview_shown = True
        try:
            buf.start_completion(select_first=False)
        except Exception:
            pass
        return
    # 第二次回车（或非命令输入）：正常提交
    buf._ace_preview_shown = False
    buf.validate_and_handle()


def mask_secret(s: str) -> str:
    s = s or ""
    if len(s) <= 8:
        return "***"
    return f"{s[:6]}***{s[-4:]}"


# ============================================================
# 配置加载（优先 AI Code 配置，回退复用本机已有模型配置）
# ============================================================

def load_claude_settings() -> Dict:
    """读取 ~/.claude/settings.json，提取模型端点配置"""
    if not CLAUDE_SETTINGS_PATH.exists():
        return {}
    try:
        data = json.loads(CLAUDE_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    env = data.get("env", {}) if isinstance(data, dict) else {}
    return {
        "base_url": env.get("ANTHROPIC_BASE_URL") or "",
        "api_key": env.get("ANTHROPIC_AUTH_TOKEN") or "",
        "model": data.get("model") or "",
        "api_format": "anthropic",
    }


def load_cli_config() -> Dict:
    for path in (CONFIG_PATH, LEGACY_CONFIG_PATH):
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
    return {}


def merge_config(args) -> Dict:
    """配置合并：args > ~/.ai_code.json > ~/.claude/settings.json（本机已有配置） > 环境变量"""
    cfg: Dict = {}
    cfg.update(load_claude_settings())
    cfg.update(load_cli_config())
    cfg.update({k: v for k, v in {
        "base_url": args.base_url, "api_key": args.api_key, "model": args.model,
        "permission": args.permission, "project_root": args.project_root,
        "kb_root": getattr(args, "kb", None),
        "skills_dir": getattr(args, "skills", None),
    }.items() if v})
    cfg.setdefault("base_url", os.environ.get("AGENT_BASE_URL", ""))
    cfg.setdefault("api_key", os.environ.get("AGENT_API_KEY", ""))
    cfg.setdefault("model", os.environ.get("AGENT_MODEL", "default"))
    cfg.setdefault("permission", "readonly")
    cfg.setdefault("project_root", ".")
    cfg.setdefault("bait", True)
    cfg.setdefault("tools", bool(getattr(args, "tools", False)))
    cfg.setdefault("max_history", int(getattr(args, "max_history", 0) or 0))
    cfg.setdefault("context_window",
                   int(getattr(args, "context_window", 0) or 32768))
    cfg.setdefault("compact", not bool(getattr(args, "no_compact", False)))
    cfg.setdefault("sandbox", getattr(args, "sandbox", None) or "off")
    cfg.setdefault("sandbox_image", getattr(args, "sandbox_image", None) or "")
    # 第三方搜索 API（可选）：配置了 key 时 search 优先走它，失败自动回退免 key 爬虫。
    # 支持 provider=bocha（默认端点写死）或 provider=custom（用 search_api_url 指定端点）。
    cfg.setdefault("search_api_provider", os.environ.get("ACE_SEARCH_API_PROVIDER", ""))
    cfg.setdefault("search_api_key", os.environ.get("ACE_SEARCH_API_KEY", ""))
    cfg.setdefault("search_api_url", os.environ.get("ACE_SEARCH_API_URL", ""))
    # 配置校验与归一化（纯 stdlib dataclass）
    try:
        cli_cfg = CLIConfig.from_dict(cfg)
        for f in fields(CLIConfig):
            if f.name in cfg:
                cfg[f.name] = getattr(cli_cfg, f.name)
    except ValueError as e:
        print(c("yellow", f"  ⚠ 配置校验: {e}"))
    return cfg


def save_cli_config(cfg: Dict) -> None:
    # 配置里有明文 api_key，所以先建文件再 chmod 是不够的：那两步之间有一个窗口，
    # 文件以默认权限（umask 决定，常见是 0644）躺在主目录里。用 O_CREAT|O_EXCL
    # 带 mode 创建，权限从第一个字节就是对的。
    #
    # 已存在时退回 write_text + chmod —— 这条路上文件权限本来就已经是上次收紧过的，
    # 没有新窗口。
    payload = json.dumps(cfg, ensure_ascii=False, indent=2)
    try:
        fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        CONFIG_PATH.write_text(payload, encoding="utf-8")
    except OSError:
        CONFIG_PATH.write_text(payload, encoding="utf-8")
    else:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
    # Windows 上 os.chmod 只影响只读位（真正的 ACL 收紧需要 icacls），
    # O_CREAT 的 mode 也基本被忽略 —— 这一档在 Windows 上就是尽力而为，
    # 不要因为这里写了 0o600 就以为主目录里那份明文 key 有 OS 级保护。
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass
    print(c("green", f"配置已保存到 {CONFIG_PATH}"))


def detect_api_format(base_url: str) -> str:
    if not base_url:
        return "openai"
    if "/anthropic" in base_url:
        return "anthropic"
    return "openai"


# ============================================================
# 模型客户端（流式，支持 OpenAI / Anthropic 两种格式）
# ============================================================

class ModelClient:
    def __init__(self, cfg: Dict, mock: bool = False) -> None:
        self.mock = mock
        self.base_url = cfg.get("base_url", "").rstrip("/")
        self.api_key = cfg.get("api_key", "")
        self.model = cfg.get("model", "default")
        self.api_format = detect_api_format(self.base_url)
        # 原生工具调用：仅 OpenAI 兼容端点开启；端点拒绝时自动降级为文本协议
        self.tools = bool(cfg.get("tools", False))
        self.tools_ok = self.tools and self.api_format == "openai"
        self.max_history = int(cfg.get("max_history", 0) or 0)
        # 按权限等级裁剪发给模型的工具列表（readonly 只给只读+控制工具）
        self.permission_level = str(cfg.get("permission", "readonly") or "readonly").lower()
        self._mock_provider = ModelProvider(_MockArgs()) if mock else None

    def describe(self) -> str:
        if self.mock:
            return "mock（离线演示）"
        return (f"{self.model} @ {self.base_url} "
                f"(api: {self.api_format}, key: {mask_secret(self.api_key)})")

    def stream_generate(self, system: str, messages: List[Dict],
                        on_delta: Optional[Callable] = None) -> str:
        """on_delta(full_text)：接收增量完整文本，用于自定义展示（不打印原始输出）"""
        if self.mock:
            return self._stream_mock(messages, on_delta)
        if not self.base_url or not self.api_key:
            raise RuntimeError(
                "未配置模型：用 --base-url/--api-key/--model 指定，"
                "或写入 ~/.ai_code.json；也可 --mock 离线演示")
        if self.api_format == "anthropic":
            return self._stream_anthropic(system, messages, on_delta)
        return self._stream_openai(system, messages, on_delta)

    def _stream_mock(self, messages: List[Dict], on_delta: Optional[Callable] = None) -> str:
        text = self._mock_provider.generate(messages[-1]["content"])
        if on_delta is None:
            for line in text.splitlines():
                print(line)
                time.sleep(0.02)
            return text
        buf = ""
        for line in text.splitlines():
            buf += line + "\n"
            on_delta(buf)
            time.sleep(0.02)
        return text

    def _post_openai_once(self, payload: Dict,
                          on_delta: Optional[Callable] = None) -> tuple:
        """非流式请求一次，返回 (正文, {index: tool_call})。
        tools 模式走这条路——见 _stream_openai 里关于 /v1 流式丢 tool_calls 的说明。
        返回值刻意和流式分支同构，后面的协议转换逻辑就不用分情况。

        "一次"指的是**一次逻辑请求**：429 / 502 / 连接抖动由 ace_http 在里面退避重试，
        对调用方仍然是一次调用。400/404 属于 FATAL_STATUS，不重试、原样抛
        requests.HTTPError —— _stream_openai 的 tools 降级就是靠它，绝不能被吞掉。
        """
        r = ace_http.request_with_retry(
            "POST", f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json=payload, timeout=300,
            on_retry=retry_notice,
        )
        # request_with_retry 只在 status < 400 时返回，raise_for_status 已无事可做。
        body = r.json()
        choices = body.get("choices") or []
        msg = ((choices[0] or {}).get("message") or {}) if choices else {}
        full = msg.get("content") or ""
        tool_calls: Dict[int, Dict] = {}
        for i, tc in enumerate(msg.get("tool_calls") or []):
            if isinstance(tc, dict):
                tool_calls[i] = tc
        if full:
            # 一次性把整段正文交给展示层，等价于"只有一个 delta"的流式
            if on_delta is not None:
                on_delta(full)
            else:
                print(full, end="", flush=True)
        return full, tool_calls

    def _stream_openai(self, system: str, messages: List[Dict],
                       on_delta: Optional[Callable] = None) -> str:
        # requests 只为下面 except 里的异常类型；请求本身都交给 ace_http。
        import requests
        # 这个循环是**协议降级**配额，不是网络重试 —— 网络重试在 ace_http 里，比这层低
        # 一级。两层各管一件事：这里管"端点认不认 tools 参数"，那里管"这次失败再试一下
        # 会不会变"。把它们叠成一个循环，结果就是一次 429 也会把 tools 关掉。
        for _attempt in (1, 2):
            # tools 模式强制非流式。Ollama 一类端点的 OpenAI 兼容层在 stream=true 下会
            # 丢掉 tool_calls 增量（ollama#7881：delta.tool_calls 不带 index；#5769：整块
            # 不下发），后果不是报错而是静默降级——模型明明生成了 file_write 调用，agent
            # 只收到"我已经帮你在桌面创建了 example.py"这段纯文本，再被当成最终回复，
            # 文件根本没写。打字机效果没有"工具真的被执行"重要，这里牺牲流式换正确性。
            streaming = not self.tools_ok
            payload = {
                "model": self.model,
                "messages": [{"role": "system", "content": system}] + messages,
                "stream": streaming,
                "temperature": 0.2,
            }
            if self.tools_ok:
                payload["tools"] = tools_for_permission(self.permission_level)
                payload["tool_choice"] = "auto"
            full = ""
            tool_calls: Dict[int, Dict] = {}
            try:
                if not streaming:
                    full, tool_calls = self._post_openai_once(payload, on_delta)
                else:
                    # 重试只覆盖到"拿到响应头"为止，这一点是刻意的：此刻还没有
                    # 任何字符吐给用户，重发是安全的。读到一半断流则不在覆盖范围内 ——
                    # 那时正文已经在屏幕上了，重发会造成重复输出，宁可报错。
                    with ace_http.request_with_retry(
                        "POST", f"{self.base_url}/chat/completions",
                        headers={"Authorization": f"Bearer {self.api_key}"},
                        json=payload, stream=True, timeout=300,
                        on_retry=retry_notice,
                    ) as r:
                        for line in r.iter_lines():
                            if not line:
                                continue
                            line = line.decode("utf-8", errors="ignore").strip()
                            if not line.startswith("data:"):
                                continue
                            data = line[5:].strip()
                            if data == "[DONE]":
                                break
                            try:
                                obj = json.loads(data)
                            except json.JSONDecodeError:
                                continue
                            if not isinstance(obj, dict):
                                continue
                            choices = obj.get("choices") or []
                            delta = ((choices[0] or {}).get("delta", {})
                                     if choices else {})
                            if not isinstance(delta, dict):
                                continue
                            content = delta.get("content")
                            if content:
                                full += content
                                if on_delta is not None:
                                    on_delta(full)
                                else:
                                    print(content, end="", flush=True)
                            for tc in (delta.get("tool_calls") or []):
                                if not isinstance(tc, dict):
                                    continue
                                idx = int(tc.get("index", 0))
                                slot = tool_calls.setdefault(
                                    idx, {"function": {"name": "", "arguments": ""}})
                                fn = tc.get("function") or {}
                                if fn.get("name"):
                                    slot["function"]["name"] = fn["name"]
                                if fn.get("arguments"):
                                    slot["function"]["arguments"] += fn["arguments"]
            except requests.HTTPError as e:
                # 端点不支持 tools 参数（400/404）→ 降级重试一次文本协议
                if (self.tools_ok and e.response is not None
                        and e.response.status_code in (400, 404)):
                    self.tools_ok = False
                    continue
                raise
            if tool_calls:
                calls = [v for _, v in sorted(tool_calls.items())]
                text = tool_calls_to_protocol(calls)
                if on_delta is not None:
                    on_delta(text)
                else:
                    print()
                return text
            if on_delta is None:
                print()
            if self.tools:
                # tools 模式：清洗模型残留的协议标签后，再决定是工具调用还是纯文本回复
                full = sanitize_plain_content(full)
                converted = content_to_tool_protocol(full)
                if converted:
                    if on_delta is not None:
                        on_delta(converted)
                    return converted
                return final_reply_protocol(full)
            return full
        raise RuntimeError("模型 API 调用失败")

    @staticmethod
    def trim_messages(messages: List[Dict], max_history: int) -> List[Dict]:
        """限制对话历史长度，防止本地小模型上下文溢出（保留最近 N 轮）"""
        if max_history <= 0:
            return messages
        max_msgs = max_history * 2
        return messages[-max_msgs:] if len(messages) > max_msgs else messages

    def summarize_context(self, prompt: str) -> str:
        """上下文压缩用的单次纯文本调用。

        临时关掉 tools 的原因：压缩请求不需要工具，带上 tools 就给了模型
        返回 tool_call 的机会 —— 那时拿到的"摘要"是一段 JSON，会被原样塞进历史。
        用 try/finally 还原，否则一次压缩会把整个会话的原生工具调用关掉。
        """
        saved_tools = self.tools_ok
        self.tools_ok = False
        try:
            raw = self.stream_generate(
                "你是上下文压缩器。只输出压缩后的交接说明正文，不要寒暄，不要调用工具。",
                [{"role": "user", "content": prompt}])
        finally:
            self.tools_ok = saved_tools
        # 模型仍可能按协议格式包一层（系统提示词训出来的习惯），统一剥成纯文本
        return sanitize_plain_content(raw)

    def _anthropic_payload_variants(self, system: str, messages: List[Dict]) -> List[Dict]:
        """生成多组兼容变体：不同服务商对 system 字段格式 / 流式支持要求不一，逐个降级尝试"""
        base = {"model": self.model, "max_tokens": 8192, "messages": messages}
        msgs_blocks = [
            {"role": m.get("role", "user"),
             "content": [{"type": "text", "text": str(m.get("content", ""))}]}
            for m in messages
        ]
        sys_blocks = [{"type": "text", "text": system}]
        return [
            {**base, "system": system, "stream": True},
            {**base, "system": sys_blocks, "stream": True},
            {**base, "system": system, "messages": msgs_blocks, "stream": True},
            {**base, "system": sys_blocks, "messages": msgs_blocks, "stream": True},
            {**base, "system": system, "stream": False},
            {**base, "system": sys_blocks, "stream": False},
        ]

    def _post_anthropic(self, payload: Dict,
                        on_delta: Optional[Callable] = None) -> str:
        """POST /v1/messages，自动处理流式（SSE）与非流式（JSON）两种响应

        重试同样在 ace_http 里，且和 _stream_anthropic 的变体循环分工明确：
        变体循环只处理 400（"这个端点不认这种 payload 形状"），而 429/5xx 由退避
        接手。这一点在合并前是缺的 —— 一次 429 会让变体循环立刻 break，
        整个会话报"已尝试多种请求格式"然后死掉，用户看不出真实原因是限流。
        """
        stream = bool(payload.get("stream"))
        with ace_http.request_with_retry(
            "POST", f"{self.base_url}/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=payload, stream=stream, timeout=300,
            on_retry=retry_notice,
        ) as r:
            if not stream:
                data = r.json()
                blocks = data.get("content") or []
                full = "".join(b.get("text", "") for b in blocks
                               if isinstance(b, dict) and b.get("type") == "text")
                if on_delta is not None:
                    on_delta(full)
                else:
                    print(full, end="", flush=True)
                    print()
                return full
            full = ""
            for line in r.iter_lines():
                if not line:
                    continue
                line = line.decode("utf-8", errors="ignore").strip()
                if not line.startswith("data:"):
                    continue
                try:
                    obj = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                if obj.get("type") == "content_block_delta":
                    delta = obj.get("delta") or {}
                    text = delta.get("text", "") if isinstance(delta, dict) else ""
                    if text:
                        full += text
                        if on_delta is not None:
                            on_delta(full)
                        else:
                            print(text, end="", flush=True)
            if on_delta is None:
                print()
            return full

    def _stream_anthropic(self, system: str, messages: List[Dict],
                          on_delta: Optional[Callable] = None) -> str:
        """Anthropic Messages 调用：多格式变体自动降级，兼容不同服务商"""
        import requests
        last_err = ""
        for payload in self._anthropic_payload_variants(system, messages):
            try:
                return self._post_anthropic(payload, on_delta)
            except requests.HTTPError as e:
                body = ""
                try:
                    body = (e.response.text or "")[:400]
                except Exception:
                    pass
                last_err = f"{e} | 响应体: {body}"
                # 常见错误码给出可操作提示（如智谱 1214 = 模型名不存在）
                try:
                    err_obj = json.loads(e.response.text or "{}")
                    code = str(err_obj.get("error", {}).get("code", ""))
                    msg = str(err_obj.get("error", {}).get("message", ""))
                    if code == "1214" or "modelCode" in msg or "不存在" in msg:
                        last_err += ("\n提示: 该端点不存在这个模型名。用 /model glm-4.6 切换"
                                     "（智谱真实模型码，如 glm-4.6 / glm-4.5-air），或用 /config 改端点")
                except Exception:
                    pass
                if e.response is not None and e.response.status_code != 400:
                    break   # 401/403/429/5xx 等不重试，避免浪费请求
            except requests.RequestException as e:
                last_err = str(e)
                break
        raise RuntimeError(f"模型 API 调用失败（已尝试多种请求格式）: {last_err}")


class _MockArgs:
    mock = True
    base_url = None
    api_key = None
    model = None


class _Spinner:
    """状态行动画线程：◈ 思考中... / ◈ 正在调用工具...（动态加点，后台每 0.12s 重绘）"""

    def __init__(self, label: str = "思考中") -> None:
        self._label = label
        self._stop_ev = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def set_label(self, label: str) -> None:
        self._label = label

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_ev.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        frame = 0
        while not self._stop_ev.is_set():
            dots = "." * (frame % 4)
            sys.stdout.write(f"\r◈ {self._label}{dots}   ")
            sys.stdout.flush()
            frame += 1
            self._stop_ev.wait(0.12)

    def stop(self, newline: bool = False) -> None:
        self._stop_ev.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        if newline:
            sys.stdout.write("\n")
            sys.stdout.flush()


def _sanitize_display_text(text: str) -> str:
    """流式显示专用：只删除标签/思考标记，不把思考块内容当回复（避免逐帧泄漏）。"""
    t = re.sub(
        r"\[/?\s*INTERNAL_THINKING\s*\]?.*?\[/?\s*INTERNAL_THINKING\s*\]?",
        "", text or "", flags=re.DOTALL | re.IGNORECASE)
    t = re.sub(r"\[?/?\s*INTERNAL_THINKING\s*\]?", "", t, flags=re.IGNORECASE)
    for label in ("PLAN", "REASON", "ACT", "OBSERVE", "REPLAN", "CHECK",
                  "EXPLORE", "DESIGN", "REVIEW", "FINALIZE", "EXECUTE"):
        t = re.sub(rf"\[{label}\]", "", t, flags=re.IGNORECASE)
    t = re.sub(r"</?INTERNAL\s*>?", "", t, flags=re.IGNORECASE)
    t = re.sub(r"</?EXTERNAL\s*>?", "", t, flags=re.IGNORECASE)
    t = re.sub(r"</?EXTERNAL\s*$", "", t, flags=re.IGNORECASE)   # 残缺结尾标签
    t = re.sub(r"</?[A-Za-z]*$", "", t)                          # 裸结尾残标签（</、</E、< 等）
    t = re.sub(r"^\s*answer\.\s*", "", t)
    return t.strip()


# ============================================================
# Agent CLI 主类
# ============================================================

class _AtCommands:
    """@ 快捷方式：@lang / @skill / @file / @folder / @refs

    只负责解析 @ 输入并落到 self.context_refs / 配置上，不碰会话循环。
    """

    # ---------- @ 快捷方式 ----------

    def _handle_at_command(self, line: str) -> None:
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if cmd in ("@lang", "@language"):
            self._at_lang(arg)
        elif cmd == "@skill":
            self._at_skill(arg)
        elif cmd == "@file":
            self._at_file(arg)
        elif cmd == "@folder":
            self._at_folder(arg)
        elif cmd in ("@refs", "@context"):
            self._at_refs()
        elif cmd == "@clear":
            self.context_refs = []
            print(c("green", t("at_clear_done")))
        else:
            print(t("at_help", lang=LANG_NAMES.get(self.lang, self.lang)))

    def _at_lang(self, arg: str) -> None:
        if not arg:
            print(t("at_current_lang",
                    name=LANG_NAMES.get(self.lang, self.lang), code=self.lang))
            print(c("dim", t("at_lang_usage")))
            return
        key = arg.lower()
        if key not in LANG_NAMES:
            print(c("red", t("at_lang_unsupported", arg=arg,
                             names=", ".join(LANG_NAMES))))
            return
        self.lang = key
        set_language(key)  # 界面语言同步切换
        print(c("green", t("at_lang_switched", name=LANG_NAMES[key])))

    def _at_skill(self, arg: str) -> None:
        if not arg:
            print(t("at_skills_title"))
            for key, info in SKILLS.items():
                mark = " ✓" if self.skill == key else ""
                name = t(f"skill_{key}")
                desc = t(f"skill_{key}_desc")
                print(f"    {c('magenta', key):<12} {name} — {desc}{mark}")
            print(c("dim", t("at_skill_usage")))
            return
        key = arg.lower()
        if key not in SKILLS:
            print(c("red", t("at_skill_unknown", key=key,
                             names=", ".join(SKILLS))))
            return
        self.skill = key
        print(c("green", t("at_skill_switched",
                           name=t(f"skill_{key}"),
                           desc=t(f"skill_{key}_desc"))))

    def _at_file(self, arg: str) -> None:
        if not arg:
            print(c("dim", t("at_file_usage")))
            return
        p = self._resolve_local_path(arg)
        if not p or not p.exists():
            print(c("red", t("at_file_not_found", arg=arg)))
            return
        if p.is_dir():
            print(c("yellow", t("at_file_is_dir")))
            return
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(c("red", t("at_read_failed", err=e)))
            return
        if len(content) > 4000:
            content = content[:4000] + "\n…(已截断)"
        self.context_refs.append(f"{p}\n{content}")
        self.context_refs = self.context_refs[-3:]
        print(c("green", t("at_file_added", path=p, n=len(content))))

    def _at_folder(self, arg: str) -> None:
        if not arg:
            print(c("dim", t("at_folder_usage")))
            return
        p = self._resolve_local_path(arg)
        if not p or not p.exists() or not p.is_dir():
            print(c("red", t("at_folder_not_found", arg=arg)))
            return
        try:
            items = sorted(os.listdir(p))
        except Exception as e:
            print(c("red", t("at_read_failed", err=e)))
            return
        if len(items) > 30:
            items = items[:30] + ["…(更多)"]
        self.context_refs.append(f"{p}\n" + "\n".join(items))
        self.context_refs = self.context_refs[-3:]
        print(c("green", t("at_folder_added", path=p, n=len(items))))

    def _at_refs(self) -> None:
        if not self.context_refs:
            print(t("at_refs_empty"))
            return
        print(t("at_refs_count", n=len(self.context_refs)))
        for ref in self.context_refs:
            print(f"    {ref.splitlines()[0]}")


class _SlashCommands:
    """斜杠命令表与各命令实现（/help /model /provider /open ...）

    COMMANDS 是命令名 → i18n 描述键的映射，补全器与 /help 都从它派生。
    """

    # ---------- 斜杠命令 ----------

    COMMANDS = {
        "/help": "cmd_help",
        "/clear": "cmd_clear",
        "/status": "cmd_status",
        "/stats": "cmd_stats",
        "/memory": "cmd_memory",
        "/snapshots": "cmd_snapshots",
        "/undo": "cmd_undo",
        "/rollback": "cmd_rollback",
        "/report": "cmd_report",
        "/permission": "cmd_permission",
        "/mock": "cmd_mock",
        "/model": "cmd_model",
        "/provider": "cmd_provider",
        "/config": "cmd_config",
        "/goal": "cmd_goal",
        "/audit": "cmd_audit",
        "/net": "cmd_net",
        "/sandbox": "cmd_sandbox",
        "/open": "cmd_open",
        "/edit": "cmd_edit",
        "/search": "cmd_search",
        "/exit": "cmd_exit",
    }

    def run_command(self, cmd: str) -> bool:
        """处理斜杠命令，返回 False 表示退出（支持前缀补全提示）"""
        parts = cmd.split()
        name = parts[0].lower() if parts else ""

        # 裸 exit / quit 直接退出（避免被前缀匹配截胡）
        if name in ("exit", "quit"):
            return False

        # 兼容无空格参数：/search关键词 → /search 关键词
        if name not in self.COMMANDS:
            parsed_name, inline_arg = _parse_slash_command(cmd)
            if parsed_name in self.COMMANDS and inline_arg:
                name = parsed_name
                parts = [parsed_name, inline_arg]

        # 前缀补全：/ 或 /h 这类输入自动提示；唯一匹配直接执行
        if name not in self.COMMANDS:
            matches = [k for k in self.COMMANDS if k.startswith(name)] if name else list(self.COMMANDS)
            if not name:
                matches = list(self.COMMANDS)
            if len(matches) == 1:
                parts[0] = matches[0]
                name = matches[0]
            else:
                if matches:
                    print(c("dim", t("you_typed", cmd=cmd or "/")))
                    for k in matches:
                        print(f"    {c('magenta', k):<26} {t(self.COMMANDS[k])}")
                else:
                    print(t("unknown_prefix", name=name))
                return True

        if name == "/help":
            print(c("bold", "\n" + t("help_title")))
            for k, v in self.COMMANDS.items():
                print(f"  {c('magenta', k):<22} {t(v)}")
            print(c("dim", t("help_hint")))
        elif name == "/clear":
            self.messages.clear()
            self.context_refs = []
            self._init_execution_layer()
            self.session.update(rounds=0, tools=0, violations=0, start=time.time())
            print(c("green", t("clear_done")))
        elif name == "/status":
            self._show_status()
        elif name == "/stats":
            print(json.dumps(self.el.get_stats(), ensure_ascii=False, indent=2))
        elif name == "/memory":
            self._show_memory()
        elif name == "/snapshots":
            snaps = self.el.guardian.list_snapshots() if self.el.guardian else []
            if not snaps:
                print(t("snap_none"))
            for s in snaps:
                print(f"  {s['id']}  {s.get('created_iso')}  {s.get('tag')}  ({s.get('file_count')} 文件)")
        elif name == "/undo":
            self._undo_last()
        elif name == "/rollback":
            if len(parts) < 2:
                print("用法: /rollback <快照id>（用 /snapshots 查看）")
            elif not re.match(r"^\d+_[\w\-]{1,60}$", parts[1]):
                print(c("red", "快照 id 格式非法（应为 时间戳_标签，用 /snapshots 查看）"))
            else:
                try:
                    answer = input(f"确认回滚到 {parts[1]}？这会覆盖当前文件状态 [y/N]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    print(t("cancelled"))
                    return True
                if answer == "y":
                    try:
                        ok = self.el.guardian.rollback(parts[1])
                        print(c("green", t("undo_rollback_ok"))
                              if ok else c("red", t("rollback_partial")))
                    except Exception as e:
                        print(c("red", t("rollback_fail", err=e)))
                else:
                    print(t("cancelled"))
        elif name == "/report":
            path = self.el.generate_poc_report("Agent CLI 会话报告")
            print(c("green", f"报告已生成: {path}") if path else c("red", "Nuwa 未启用"))
        elif name == "/permission":
            self._handle_permission(parts)
        elif name == "/sandbox":
            self._handle_sandbox(parts)
        elif name == "/model":
            self._handle_model(parts)
        elif name == "/mock":
            self._toggle_mock()
        elif name == "/provider":
            self._handle_provider(parts)
        elif name == "/config":
            self._config_wizard()
        elif name == "/goal":
            self._show_goal(parts)
        elif name == "/audit":
            self._show_audit(parts)
        elif name == "/net":
            self._toggle_net(parts)
        elif name == "/open":
            self._open_file(" ".join(parts[1:]), prefer_editor=False)
        elif name == "/edit":
            self._open_file(" ".join(parts[1:]), prefer_editor=True)
        elif name == "/search":
            self._search_web(" ".join(parts[1:]).strip())
        elif name in ("/exit", "/quit", "exit", "quit"):
            return False
        else:
            print(t("unknown_cmd", name=name))
        return True

    # ---------- 联网搜索（人可用的 /search，与 Agent 的 search 工具同源） ----------

    def _search_web(self, query: str) -> None:
        if not query:
            print(t("search_usage"))
            return
        print(c("dim", t("search_running", q=query)))
        res = self.el.executor.execute({"tool": "search", "query": query, "top_k": 5})
        if res.status != "success":
            print(c("red", t("search_failed", err=res.message)))
            return
        data = res.data
        print(c("dim", t("search_engine",
                         engine=data.get("engine", "?"),
                         network=data.get("network_status", "?"))))
        for i, item in enumerate(data.get("results", []), 1):
            print(f"  {i}. {item.get('title', '')}")
            print(f"     {c('dim', item.get('url', ''))}")
            snippet = item.get("snippet", "")
            if snippet:
                print(f"     {c('dim', snippet[:120])}")

    # ---------- 文件打开（编辑器无关，裸终端可用） ----------

    def _resolve_local_path(self, path_str: str, create: bool = False) -> Optional[Path]:
        """把用户输入的路径解析到项目目录内的绝对路径"""
        p = Path(path_str)
        if not p.is_absolute():
            p = Path(self.cfg["project_root"]) / p
        p = p.resolve()
        if create and not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("", encoding="utf-8")
        if not p.exists():
            print(c("red", f"文件不存在: {p}"))
            return None
        return p

    # ---------- 目标状态机（/goal：查看 / 恢复 / 暂停 / 完成） ----------

    def _show_goal(self, parts: List[str]) -> None:
        """/goal：无参查看；resume 恢复（重启后自动 disarmed）；pause 暂停；complete 完成"""
        from tools.goal_tools import GoalError  # noqa: E402
        store = self.el.goal_store
        snap = store.snapshot()
        action = parts[1].lower() if len(parts) > 1 else ""
        try:
            if action == "resume":
                if snap is None:
                    print(c("yellow", t("goal_no_goal")))
                    return
                store.resume(snap["id"], snap["revision"])
                print(c("green", t("goal_resumed", obj=snap['objective'][:60])))
                return
            if action == "pause":
                if snap is None or snap["phase"] != "active":
                    print(c("yellow", t("goal_no_pauseable")))
                    return
                store.update(snap["id"], snap["revision"], phase="paused")
                print(c("green", t("goal_paused")))
                return
            if action == "complete":
                if snap is None or snap["phase"] != "active":
                    print(c("yellow", t("goal_no_completable")))
                    return
                store.update(snap["id"], snap["revision"], phase="complete")
                print(c("green", t("goal_completed")))
                return
            if action not in ("", "status"):
                print(c("yellow", t("goal_usage")))
                return
        except GoalError as e:
            print(c("red", f"goal: {e.message}"))
            return
        if snap is None:
            print(c("dim", t("goal_no_active")))
            return
        phase = snap["phase"]
        armed = "armed" if snap["armed"] else "disarmed"
        print(c("bold", t("goal_status_title")))
        print(f"  {c('magenta', 'objective')}: {snap['objective']}")
        print(f"  {c('magenta', 'phase')}: {phase} | {c('magenta', 'rounds')}: "
              f"{snap['rounds_started']}/{snap['max_rounds']} | {c('magenta', 'armed')}: {armed}")
        if snap.get("blocked_reason_code"):
            print(f"  {c('red', 'blocked')}: [{snap['blocked_reason_code']}] "
                  f"{snap.get('blocked_reason_message', '')}")
        print(c("dim", t("goal_ops")))

    # ---------- 子代理（/subagent 工具的执行钩子，由执行层回调） ----------

    def _build_subagent_system(self) -> str:
        return (load_system_prompt(tools_mode=True)
                + f"\n【工作目录】{os.path.abspath(self.cfg['project_root'])}。"
                  "你是被父代理派来的子代理：专注完成上面的子任务，可以调用工具（终端/文件/代码执行），"
                  "完成后给出结论。禁止调用 subagent（不允许再开子代理），禁止 plan_propose 和 "
                  "request_permission（子代理环境无人批准，需要批准的操作换用不需要批准的方式）。")

    def _run_subagent(self, mode: str, prompt: str):
        """执行 subagent 工具（阶段 2：子代理拥有自己的工具执行循环）。

        spawn=全新上下文；fork=继承父会话最近 6 轮。子代理有独立的 ExecutionLayer
        （独立消息历史、独立日志、独立权限裁决），最多 8 轮内 模型↔工具 循环，
        直到给出最终结论。结果作为文本回传父代理整合。
        返回 (ok, text)。
        """
        try:
            root = self.cfg.get("project_root", ".")
            sub_slog = str(Path(root) / ".ace_sessions"
                           / f"{int(time.time() * 1000)}_sub.jsonl")
            sub_el = ExecutionLayer(
                project_root=root,
                permission_level=str(self.cfg.get("permission", "readonly")),
                config={"bait": {"enabled": False},
                        # 子代理跟随主会话的执行沙箱档位：主会话开着 job/docker 边界时，
                        # 子代理的 code_execute/terminal_exec 不能在宿主上静默跑——
                        # 那等于主会话切了沙箱、子代理又给开个后门。
                        "sandbox_base": str(Path(root).resolve() / ".sandbox_tmp"),
                        "sandbox": {"mode": self.cfg.get("sandbox", "off"),
                                    "image": self.cfg.get("sandbox_image")},
                        "session_log": sub_slog})
            sub_el.executor.subagent_hook = None   # 子代理不允许再开子代理（防无限递归）
            sub_sys = self._build_subagent_system()
            msgs: List[Dict] = list(self.messages[-6:]) if mode == "fork" else []
            msgs.append({"role": "user", "content": prompt})
            # 会话日志：记录子代理请求（带 subagent 标记，replay 时可区分）
            self.session_log.record_request(
                model=self.client.model, base_url=self.client.base_url,
                permission=str(self.cfg.get("permission", "readonly")),
                system_len=len(sub_sys), messages_count=len(msgs), subagent=mode)
            for _r in range(1, 9):
                output = self.client.stream_generate(sub_sys, msgs)
                self.session_log.record_assistant(output)
                result = sub_el.process_agent_output(output, prompt)
                status = result["status"]
                if status == "FINAL_REPLY":
                    return True, result["message"]
                if status in ("PLAN_PROPOSED", "PERMISSION_REQUEST"):
                    # 子代理环境无人批准：明确告知后让它换方式
                    msgs.append({"role": "assistant", "content": output})
                    msgs.append({"role": "user", "content": t("subagent_no_approval")})
                    continue
                if status == "SUCCESS":
                    msgs.append({"role": "assistant", "content": output})
                    msgs.append({"role": "user", "content":
                                 PROMPT_TOOL_RESULT.format(rendered=render_tool_result(result))})
                    continue
                # 错误态：回喂修正
                msgs.append({"role": "assistant", "content": output})
                msgs.append({"role": "user", "content":
                             PROMPT_ERROR_RETRY.format(rendered=render_result(result))})
                continue
            return False, t("subagent_limit")
        except Exception as e:
            return False, f"子代理执行失败: {type(e).__name__}: {e}"

    # ---------- 切换类命令统一交互（/net /permission /sandbox） ----------
    #
    # 三个命令同一套交互契约：
    #   - 带参快路径：/net on、/permission write、/sandbox job 直接生效；
    #   - 交互 TTY 下裸命令（回车）不立即生效，而是弹出「二次选择框」：
    #     选项 = 该主类型的分类型（当前值置顶并标注），输入过滤/↑↓/Enter 选择；
    #   - 非 TTY（脚本/管道/测试）保持旧的直接行为（/net 开关翻转、
    #     /permission 打印 JSON、/sandbox 打印用法）——没人可问时不弹框不阻塞。

    def _interactive_tty(self) -> bool:
        """是否处于可以弹选择框的交互会话（真 TTY 且 prompt_toolkit 可用）"""
        if run_selector is None:
            return False
        try:
            return bool(sys.stdin.isatty() and sys.stdout.isatty())
        except Exception:
            return False

    def _pick_option(self, title: str, options: List[Tuple[str, Any]]) -> Optional[Any]:
        """弹搜索式二次选择框，返回选中值；用户取消（Esc/Ctrl+C）返回 None。
        仅在 _interactive_tty() 为 True 时调用（内部不再重复判 TTY）。
        options = [(显示文本, 取值), ...]，显示文本可带"（当前）"标注。"""
        labels = [o[0] for o in options]
        idx = run_selector(title, labels)
        if idx is None or not (0 <= idx < len(options)):
            return None
        return options[idx][1]

    def _toggle_net(self, parts: List[str]) -> None:
        """/net 或 /net on|off：联网开/关。交互 TTY 下裸命令弹 on/off 选择框。"""
        cur = self.el.executor.network_enabled
        if len(parts) > 1:
            arg = parts[1].lower()
            if arg in ("on", "1", "开", "true"):
                self._set_net(True)
                return
            if arg in ("off", "0", "关", "false"):
                self._set_net(False)
                return
            print(c("yellow", t("net_usage")))
            return
        if self._interactive_tty():
            net_labels = {True: t("net_on"), False: t("net_off")}
            opts = [(net_labels[v] + ("（当前）" if v == cur else ""), v)
                    for v in (cur, not cur)]
            pick = self._pick_option("联网: 选择要切到的状态", opts)
            if pick is not None:
                self._set_net(pick)
            return
        # 非交互（脚本/管道/测试）：保持原"回车翻转"语义
        self._set_net(not cur)

    def _set_net(self, enabled: bool) -> None:
        self.el.executor.network_enabled = enabled
        self.cfg["network_enabled"] = enabled
        print(c("green" if enabled else "yellow",
                t("net_status", state=t("net_on") if enabled else t("net_off"))))

    def _handle_permission(self, parts: List[str]) -> None:
        """/permission 或 /permission [readonly|write|full]：切换权限等级。
        交互 TTY 下裸命令弹出三档选择框（当前档置顶）。"""
        if len(parts) >= 2 and parts[1] in ("readonly", "write", "full"):
            self._set_permission(parts[1])
            return
        if self._interactive_tty():
            cur = str(self.cfg.get("permission", "readonly"))
            levels = ("readonly", "write", "full")
            ordered = [cur] + [lv for lv in levels if lv != cur]
            opts = [(lv + ("（当前）" if lv == cur else ""), lv) for lv in ordered]
            pick = self._pick_option("权限: 选择等级", opts)
            if pick is not None:
                self._set_permission(pick)
            return
        # 非交互（脚本/管道/测试）：保持原"打印 JSON 状态"语义
        print(json.dumps(self.el.permission.get_status(), ensure_ascii=False, indent=2))

    def _set_permission(self, level: str) -> None:
        if level not in ("readonly", "write", "full"):
            return
        self.el.permission.upgrade(level)
        self.cfg["permission"] = level
        print(c("green", f"权限已切换为 {level}"))

    def _handle_sandbox(self, parts: List[str]) -> None:
        """/sandbox 或 /sandbox [off|job|docker]：切换命令执行沙箱档位。
        交互 TTY 下裸命令弹出三档选择框（当前档置顶）。热切换：会话/历史/工具状态
        全部保留，只重建执行边界；job/docker 起不来会诚实 503，绝不静默回落宿主。"""
        if len(parts) >= 2:
            arg = parts[1].lower()
            if arg in ("off", "job", "docker"):
                self._set_sandbox(arg)
                return
            print(c("yellow", t("sandbox_usage")))
            return
        if self._interactive_tty():
            cur = str(self.cfg.get("sandbox", "off") or "off")
            modes = ("off", "job", "docker")
            ordered = [cur] + [m for m in modes if m != cur]
            opts = [(m + ("（当前）" if m == cur else ""), m) for m in ordered]
            pick = self._pick_option("沙箱: 选择执行位置", opts)
            if pick is not None:
                self._set_sandbox(pick)
            return
        # 非交互（脚本/管道/测试）：只报当前档与用法，不擅动
        cur = str(self.cfg.get("sandbox", "off") or "off")
        print(c("yellow", t("sandbox_usage") + f"  当前: {cur}"))

    def _set_sandbox(self, mode: str) -> None:
        """热切换执行沙箱档位（off/job/docker）。

        ToolExecutor 每次执行时实时读 self.docker_sandbox / self.sandbox_mode /
        self.use_go_executor，所以只改这三个字段就能无缝换挡：会话历史、权限、
        快照、审批闸门、联网开关全部原样保留，不需要重启 /clear。

        失败语义与 --sandbox 启动参数完全一致：job/docker 是硬边界，起不来时
        调用方会收到 503（含 go build / docker build 提示），绝不静默回落宿主；
        off 档是宿主直跑（可选的 Go 执行器增强起不来才允许静默降级）。
        """
        if mode not in ("off", "job", "docker"):
            print(c("yellow", t("sandbox_usage")))
            return
        ex = self.el.executor
        if mode == "docker":
            from tools.docker_sandbox import build_sandbox  # noqa: E402
            ex.docker_sandbox = build_sandbox(
                {"mode": "docker", "image": self.cfg.get("sandbox_image")},
                str(ex.project_root))
        else:
            ex.docker_sandbox = None
        ex.sandbox_mode = mode
        # job 档必须走 Go 执行器（起不来报 503）；off 档顺带用（可静默回退宿主）；
        # docker 档由 docker_sandbox 接管，不走 Go 执行器。
        ex.use_go_executor = (
            mode == "job"
            or (mode == "off"
                and os.environ.get("ACE_USE_GO_EXECUTOR", "1").lower()
                not in ("0", "false", "no", "off")))
        # job 档每次切换都强制重新探测执行器（之前失败被缓存成 use_go_executor=False，
        # 换挡后用户可能已 go build，给一次重试机会）。
        if mode == "job":
            ex._go_client = None
        self.cfg["sandbox"] = mode
        print(c("green", t("sandbox_set", mode=mode)))

    # ---------- OpenClaw 式底部状态栏（Footer 聚合，状态带动作提示） ----------

    def _footer(self) -> List[Tuple[str, str]]:
        """模型 | 权限(着色) | 沙箱 | 联网 | 目标(带动作提示) | 统计。
        状态永远附带下一步动作（如 目标:paused(/goal resume)）。"""
        parts: List[Tuple[str, str]] = []
        model = self.client.model.split("/")[-1] if self.client.model else "?"
        parts.append(("class:footer", f" {model} "))
        perm = str(self.cfg.get("permission", "readonly"))
        perm_cls = {"readonly": "class:footer-ro",
                    "write": "class:footer-w",
                    "full": "class:footer-f"}.get(perm, "class:footer")
        parts.append((perm_cls, f" 权限:{perm} "))
        parts.append(("class:footer-dim", " F1 "))
        sb = str(self.cfg.get("sandbox", "off") or "off")
        parts.append(("class:footer", f" 沙箱:{sb} "))
        parts.append(("class:footer-dim", " F2 "))
        net = "开" if getattr(self.el.executor, "network_enabled", True) else "关"
        parts.append(("class:footer-dim", f" 联网:{net} "))
        parts.append(("class:footer-dim", " F3 "))
        try:
            g = self.el.goal_store.snapshot()
        except Exception:
            g = None
        if g:
            phase = g["phase"]
            if phase == "active":
                parts.append(("class:footer-goal",
                              f" 目标:R{g['rounds_started']}/{g['max_rounds']} "))
            elif phase == "paused":
                parts.append(("class:footer-goal", " 目标:paused(/goal resume) "))
            elif phase == "blocked":
                parts.append(("class:footer-goal", " 目标:blocked(/goal resume) "))
            else:
                parts.append(("class:footer-dim", " 目标:done "))
        parts.append(("class:footer-dim",
                      f" 轮{self.session['rounds']} 工具{self.session['tools']} "))
        return parts

    # ---------- 会话审计（/audit：从事件日志展示全链路） ----------

    def _show_audit(self, parts: List[str]) -> None:
        """/audit [n] [kind]：展示会话事件日志（默认最近 20 条，可按类型过滤）。
        日志是 append-only 事实源：用户输入 → 模型请求/输出 → 工具往返 →
        权限裁决 → 快照/回滚 → 守卫违规，全部可逐事件回放。"""
        n = 20
        kind_filter = ""
        for p in parts[1:]:
            if p.isdigit():
                n = min(int(p), 500)
            else:
                kind_filter = p
        events = list(self.session_log.events())
        if kind_filter:
            events = [e for e in events if kind_filter in e.get("kind", "")]
        events = events[-n:]
        if not events:
            print(c("dim", t("audit_empty")))
            return
        print(c("bold", t("audit_title",
                          n=len(events),
                          filter=t("audit_filter", kind=kind_filter) if kind_filter else "",
                          file=self.session_log.path.name)))
        for ev in events:
            kind = ev.get("kind", "?")
            seq = ev.get("seq", "?")
            ts = ev.get("ts", "")
            detail = self._audit_summary(kind, ev)
            print(f"  {c('dim', f'#{seq} {ts}')} {c('magenta', kind):<22} {detail[:100]}")
        print(c("dim", t("audit_file", path=str(self.session_log.path))))

    @staticmethod
    def _audit_summary(kind: str, ev: Dict) -> str:
        """按事件类型渲染一行摘要（截断到适合终端）。"""
        if kind == "user/message":
            return str(ev.get("content", ""))[:100]
        if kind == "assistant/message":
            return (str(ev.get("content", ""))[:80] + "…") \
                if len(str(ev.get("content", ""))) > 80 else str(ev.get("content", ""))
        if kind == "request/snapshot":
            return (f"model={ev.get('model')} msgs={ev.get('messages_count')} "
                    f"system={ev.get('system_len')}B perm={ev.get('permission')}")
        if kind == "system/snapshot":
            return f"系统提示词全文（{len(str(ev.get('system', '')))} 字符，含 AGENTS.md/记忆/目标）"
        if kind == "tool/call":
            return f"{ev.get('tool')} {str(ev.get('params', ''))[:80]}"
        if kind == "tool/result":
            return f"{ev.get('tool')} [{ev.get('status')}] {str(ev.get('message', ''))[:60]}"
        if kind == "permission/decision":
            return f"{ev.get('tool')} → {ev.get('decision')} (level={ev.get('level')})"
        if kind == "snapshot/create":
            return f"{ev.get('tag') or ev.get('snapshot_id')}"
        if kind == "snapshot/rollback":
            return f"回滚到 {ev.get('snapshot_id')}"
        if kind == "guard/verdict":
            return f"规则={ev.get('rule')} action={ev.get('action')}"
        if kind == "compaction/event":
            return f"{ev.get('before')}→{ev.get('after')} tokens ({ev.get('reason')})"
        if kind == "goal/round":
            return f"R{ev.get('rounds_started')}/{ev.get('max_rounds')}"
        if kind == "model/error":
            return str(ev.get("error", ""))[:100]
        return str(ev)[:100]

    def _open_file(self, path_str: str, prefer_editor: bool = False) -> None:
        """在系统默认程序（或 VS Code）中打开文件；Windows 无关联程序时文本文件回退记事本"""
        if not path_str.strip():
            print(f"用法: {'/edit' if prefer_editor else '/open'} <文件路径>")
            return
        p = self._resolve_local_path(path_str, create=prefer_editor)
        if p is None:
            return
        try:
            if prefer_editor:
                code = shutil.which("code")
                if code:
                    subprocess.Popen([code, str(p)])
                    print(c("green", f"已在 VS Code 中打开: {p}"))
                    return
            try:
                if os.name == "nt":
                    os.startfile(str(p))
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", str(p)])
                else:
                    subprocess.Popen(["xdg-open", str(p)])
            except Exception as e:
                # Windows 上 .py 等常无关联默认程序（找不到应用程序）：
                # 文本类文件回退记事本打开
                if os.name == "nt" and p.suffix.lower() in _TEXT_EXTENSIONS:
                    try:
                        subprocess.Popen(["notepad.exe", str(p)])
                        print(c("green",
                                f"该类型无默认打开程序，已用记事本打开: {p}"))
                        return
                    except Exception as e2:
                        print(c("red", f"打开失败（记事本回退也失败）: {e2}"))
                        return
                print(c("red", f"打开失败: {e}"))
                return
            print(c("green", f"已打开: {p}"))
        except Exception as e:
            print(c("red", f"打开失败: {e}"))

    # ---------- 模型自定义 ----------

    def _reload_client(self) -> None:
        """配置变更后重建模型客户端（保留 mock 模式）"""
        was_mock = self.client.mock
        self.client = ModelClient(self.cfg, mock=was_mock)

    def _handle_model(self, parts: List[str]) -> None:
        if len(parts) == 1:
            print(f"  当前模型: {self.client.describe()}")
            prov = _find_provider(self.cfg)
            if prov:
                print(c("dim", f"  该提供商可选模型: {' / '.join(prov['models'][:8])}（/model <名> 切换）"))
            # OpenClaw 式选择器：stdin/stdout 都是 TTY 时弹搜索式选择器选模型
            # （测试环境 stdout 被重定向 → 不弹选择器，直接打印提示）
            if run_selector is not None and prov and sys.stdin.isatty() and sys.stdout.isatty():
                _models = prov.get("models") or []
                if _models:
                    _items = [f"{m}  ({t('model_opt')})" if False else m
                              for m in _models]
                    idx = run_selector("选择模型（输入过滤，Enter 确认，Esc 取消）", _models)
                    if idx is not None and 0 <= idx < len(_models):
                        self.cfg["model"] = _models[idx]
                        save_cli_config(self.cfg)
                        self._reload_client()
                        print(c("green", f"模型已切换: {_models[idx]}，已保存"))
                        return
            print(c("dim", "  切换: /model <模型名> | 换提供商: /provider | 设密钥: /model api-key <key>"))
            return
        if parts[1] == "base-url" and len(parts) >= 3:
            self.cfg["base_url"] = parts[2]
            save_cli_config(self.cfg)
            self._reload_client()
            print(c("green", f"端点已设置: {parts[2]}（自动识别为 {detect_api_format(parts[2])} 格式），已保存"))
        elif parts[1] == "api-key" and len(parts) >= 3:
            self.cfg["api_key"] = parts[2]
            save_cli_config(self.cfg)
            self._reload_client()
            print(c("green", f"密钥已更新: {mask_secret(parts[2])}，已保存"))
        else:
            model_name = " ".join(parts[1:]).strip()
            self.cfg["model"] = model_name
            save_cli_config(self.cfg)
            self._reload_client()
            print(c("green", f"模型已切换: {model_name}，已保存到 ~/.ai_code.json"))

    def _handle_provider(self, parts: List[str]) -> None:
        """查看/切换 AI 提供商：/provider 列清单，/provider <编号|id> [api-key] 一键切换"""
        if len(parts) == 1:
            # OpenClaw 式选择器：stdin/stdout 都是 TTY 时弹搜索式选择器选提供商
            # （测试环境 stdout 被重定向 → 不弹选择器，直接打印清单）
            if run_selector is not None and sys.stdin.isatty() and sys.stdout.isatty():
                _items = [f"{p['name']}  {p['base_url']}" for p in PROVIDERS]
                idx = run_selector("选择提供商（输入过滤，Enter 确认，Esc 取消）", _items)
                if idx is not None and 0 <= idx < len(PROVIDERS):
                    parts = ["/provider", str(idx + 1)]
                    self._handle_provider(parts)
                    return
            print(c("bold", "\nAI 提供商（/provider <编号或id> [api-key] 一键切换）:"))
            for i, p in enumerate(PROVIDERS, 1):
                cur = self.cfg.get("base_url", "").rstrip("/") == p["base_url"].rstrip("/")
                mark = c("green", " ✓ 当前") if cur else ""
                print(f"  {c('magenta', str(i)):>3}. {p['name']}{mark}")
                print(f"      {c('dim', p['base_url'] + '   模型: ' + ' / '.join(p['models'][:6]))}")
            return

        arg = parts[1].lower()
        target = None
        if arg.isdigit() and 1 <= int(arg) <= len(PROVIDERS):
            target = PROVIDERS[int(arg) - 1]
        else:
            for p in PROVIDERS:
                if p["id"] == arg:
                    target = p
                    break
        if target is None:
            print(c("red", f"未知提供商: {parts[1]}（输入 /provider 查看列表）"))
            return

        self.cfg["base_url"] = target["base_url"]
        # 防蠢：当前模型不在新提供商列表里时自动切到它的第一个模型
        if self.cfg.get("model", "") not in target["models"]:
            self.cfg["model"] = target["models"][0]
        if len(parts) >= 3:
            self.cfg["api_key"] = parts[2]
        save_cli_config(self.cfg)
        self._reload_client()
        print(c("green", f"已切换提供商: {target['name']}"))
        print(f"  端点: {target['base_url']}（{target['api_format']} 格式）")
        print(f"  模型: {self.cfg['model']}（可选: {' / '.join(target['models'][:6])}，用 /model <名> 换）")
        if not self.cfg.get("api_key"):
            print(c("yellow", "  ⚠ 还没有该提供商的 API Key：用 /provider <id> <api-key> 或 /config 设置"))

    def _config_wizard(self) -> None:
        print(c("bold", "\n模型配置向导（回车跳过 = 保持原值，Ctrl+C 取消且不保存）"))

        def _ask(label: str, current: str, hidden: bool = False) -> Optional[str]:
            try:
                if hidden:
                    import getpass
                    answer = getpass.getpass(f"  {label} [{current}]: ").strip()
                else:
                    answer = input(f"  {label} [{current}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                raise CommandCancelled() from None
            return answer or None

        try:
            # ① 选提供商（一键换端点 + 自动选默认模型）
            print(c("bold", "① 选择 AI 提供商:"))
            for i, p in enumerate(PROVIDERS, 1):
                print(f"  {i}. {p['name']}  {c('dim', p['base_url'])}")
            choice = _ask("提供商编号（回车跳过）", "")
            if choice:
                if choice.isdigit() and 1 <= int(choice) <= len(PROVIDERS):
                    p = PROVIDERS[int(choice) - 1]
                    self.cfg["base_url"] = p["base_url"]
                    if self.cfg.get("model", "") not in p["models"]:
                        self.cfg["model"] = p["models"][0]
                else:
                    print(c("yellow", "编号无效，跳过（可用 /provider 重试）"))
            # ② 密钥（隐藏输入，不回显）
            key = _ask("API Key（输入时不显示）", mask_secret(self.cfg.get("api_key", "")), hidden=True)
            if key:
                self.cfg["api_key"] = key
            # ③ 模型
            prov = _find_provider(self.cfg)
            model_hint = ""
            if prov:
                model_hint = f"（可选: {' / '.join(prov['models'][:8])}）"
            model = _ask(f"模型名{model_hint}", self.cfg.get("model", ""))
            if model:
                self.cfg["model"] = model
        except CommandCancelled:
            print(c("yellow", "已取消，配置未保存。"))
            return
        save_cli_config(self.cfg)
        self._reload_client()
        print(c("green", "配置已保存，当前: " + self.client.describe()))

    def _handle_cli_mistype(self, line: str) -> None:
        """防蠢处理：识别并接管误打进 REPL 的命令行指令"""
        if "--install-ui" in line:
            print(c("yellow", "检测到你想安装实时补全依赖，正在自动安装（已装跳过 + 多镜像回退）..."))
            if _pip_install_with_fallbacks("prompt_toolkit"):
                print(c("green", "✅ 安装完成！输入 exit 退出后重新运行 ace 即可享受 / 弹窗补全"))
            else:
                print(c("red", "安装失败，请手动: "
                                "pip install prompt_toolkit -i https://pypi.tuna.tsinghua.edu.cn/simple"))
            return
        print(c("yellow", f"“{line.strip()}” 看起来是 ACE 的命令行参数/系统命令，不是发给 Agent 的话。"))
        print(c("dim", "  请先输入 exit 退出 ACE，再在 cmd 里直接运行它。"))


class _LandingUI:
    """登录页：ANSI 绘制 + 键盘导航 + 菜单动作

    纯呈现与输入层，动作最终都委托回 AgentCLI 上的方法。
    """

    # ---------- 登录页 / 首页（参考 AI-CLI 启动平台主菜单） ----------

    LANDING_ITEMS = [
        ("landing_enter", "landing_enter_desc", "chat"),
        ("landing_config", "landing_config_desc", "wizard"),
        ("landing_provider", "landing_provider_desc", "provider"),
        ("landing_mock", "landing_mock_desc", "mock"),
        ("landing_status", "landing_status_desc", "status"),
        ("landing_help", "landing_help_desc", "help"),
        ("landing_exit", "landing_exit_desc", "exit"),
    ]

    @staticmethod
    def _clear_screen() -> None:
        if sys.stdout.isatty():
            sys.stdout.write("\x1b[2J\x1b[H")
            sys.stdout.flush()

    @staticmethod
    def _read_key() -> Optional[str]:
        """读取单次按键（↑/↓/数字/回车/Esc/q）；非 tty 返回 None"""
        if not sys.stdin.isatty():
            return None
        try:
            import msvcrt  # Windows
            first = msvcrt.getwch()
            if first in ("\x00", "\xe0"):
                second = msvcrt.getwch()
                return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(second, None)
            if first in ("\r", "\n"):
                return "enter"
            if first == "\x1b":
                return "esc"
            return first
        except ImportError:
            pass
        try:
            import termios
            import tty
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            try:
                ch = sys.stdin.read(1)
                if ch == "\x1b":
                    nxt = sys.stdin.read(2)
                    return {"[A": "up", "[B": "down"}.get(nxt, "esc")
                if ch in ("\r", "\n"):
                    return "enter"
                return ch
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except (ImportError, OSError):
            return input()

    def _wait_key(self) -> None:
        print(c("dim", "  按任意键返回..."))
        self._read_key()

    def _banner_extras(self) -> List[str]:
        """启动信息行：沙箱档位 / 知识库 / 会话日志（一眼看清当前运行环境）。
        刻意不用 emoji：Windows 旧终端（conhost）会渲染成方框。"""
        lines = []
        sandbox = str(self.cfg.get("sandbox", "off") or "off")
        if sandbox == "job":
            lines.append(c("dim", t("banner_sandbox_job")))
        elif sandbox == "docker":
            lines.append(c("dim", t("banner_sandbox_docker")))
        else:
            lines.append(c("dim", t("banner_sandbox_off")))
        kb = self.cfg.get("kb_root")
        kb_path = kb or (os.path.abspath(self.cfg['project_root']) + os.sep + '.ace_kb')
        lines.append(c("dim", t("banner_kb", path=kb_path,
                                ext=t("banner_kb_ext") if kb else "")))
        lines.append(c("dim", t("banner_sesslog")))
        net = "on" if self.el.executor.network_enabled else "off"
        lines.append(c("dim", t("banner_net", state=t("net_on") if net == "on"
                                else t("net_off"))))
        return lines

    def _draw_landing(self, sel: int) -> None:
        self._clear_screen()
        for line in ACE_LOGO.split("\n"):
            print(c("cyan", " " + line))
        print(c("bold", t("banner_title")))
        print()
        print(t("banner_model", desc=self.client.describe()))
        print(t("banner_permission",
                perm=self.cfg.get("permission", "readonly"),
                root=self.cfg.get("project_root", ".")))
        for line in self._banner_extras():
            print(line)
        if not self.cfg.get("api_key") and not self.client.mock:
            print(c("yellow", t("banner_missing_key")))
        print()
        for i, (label_key, desc_key, action) in enumerate(self.LANDING_ITEMS, 1):
            label = t(label_key)
            desc = t(desc_key)
            if action == "mock":
                # 根据当前模式动态显示：可来回切换
                if self.client.mock:
                    label, desc = t("landing_back_real"), t("landing_back_real_desc")
            mark = c("magenta", "❯") if i - 1 == sel else " "
            print(f"  {mark} {i}. {label}   {c('dim', desc)}")
        print()
        print(c("dim", t("banner_nav")))

    def _toggle_mock(self) -> None:
        """切换离线演示 / 真实模型模式（可来回切换）"""
        if self.client.mock:
            self.client = ModelClient(self.cfg, mock=False)
            print(c("green", "已切换回真实模型模式: " + self.client.describe()))
            if not self.cfg.get("base_url") or not self.cfg.get("api_key"):
                print(c("yellow", "  ⚠ 尚未配置模型/密钥，请先用 /config 或首页配置向导设置"))
        else:
            self.client = ModelClient(self.cfg, mock=True)
            print(c("green", "已切换为离线演示模式（mock，无需密钥）"))

    def _run_landing_action(self, action: str) -> bool:
        """执行首页菜单动作；返回 True 表示整体退出"""
        if action == "exit":
            self._clear_screen()
            print(c("dim", t("bye")))
            return True
        if action == "chat":
            self.repl(return_to_landing=True)
            return False   # 聊天退出后回到主界面，而不是直接退出程序
        if action == "wizard":
            try:
                self._config_wizard()
            except CommandCancelled:
                print(c("yellow", t("cancelled") + "。"))
            return False
        if action == "provider":
            self._handle_provider(["/provider"])
            self._wait_key()
            return False
        if action == "mock":
            self._toggle_mock()
            self._wait_key()
            return False
        if action == "status":
            self._show_status()
            self._wait_key()
            return False
        if action == "help":
            self.run_command("/help")
            self._wait_key()
            return False
        return False

    def landing(self) -> None:
        """登录页：默认进入的欢迎界面（清屏 → logo → ❯ 光标菜单）"""
        sel = 0
        while True:
            self._draw_landing(sel)
            key = self._read_key()
            if key is None:
                # 非交互（管道/重定向）：跳过首页直接进聊天
                self.repl()
                return
            if key == "up":
                sel = (sel - 1) % len(self.LANDING_ITEMS)
            elif key == "down":
                sel = (sel + 1) % len(self.LANDING_ITEMS)
            elif key == "enter":
                if self._run_landing_action(self.LANDING_ITEMS[sel][2]):
                    return
            elif key == "esc" or key == "q":
                self._clear_screen()
                print(c("dim", t("bye")))
                return
            elif key.isdigit() and 1 <= int(key) <= len(self.LANDING_ITEMS):
                if self._run_landing_action(self.LANDING_ITEMS[int(key) - 1][2]):
                    return


class AgentCLI(_AtCommands, _SlashCommands, _LandingUI):
    def __init__(self, cfg: Dict, mock: bool = False) -> None:
        self.cfg = cfg
        self.client = ModelClient(cfg, mock=mock)
        self.max_history = int(cfg.get("max_history", 0) or 0)
        self.context_window = int(cfg.get("context_window", 32768) or 32768)
        self.compact_enabled = bool(cfg.get("compact", True))
        self.lang = str(cfg.get("lang", "zh"))
        set_language(self.lang)  # 界面语言跟随配置/@lang
        self.skill = str(cfg.get("skill", "general"))
        self.context_refs: List[str] = []
        # 项目指令（AGENTS.md）会话缓存：None = 未计算
        self._project_instructions: Optional[str] = None
        # SEC-011：隔离块的 id 按会话固定。每轮换 id 会让系统提示词逐轮变化，
        # 白费上游 KV 缓存；要防的是引用文件的作者猜中 id，不是同会话内的重放。
        self._ctx_nonce = secrets.token_hex(4)
        self.messages: List[Dict] = []
        self.session = {"rounds": 0, "tools": 0, "violations": 0, "start": time.time()}
        # 会话事件日志（全链路）：CLI 建一份，传给执行层共用 —— 权限/守卫/快照/
        # 工具往返（执行层）+ 模型请求/输出（CLI）都进同一份 append-only 事实源。
        self.cfg["session_log"] = str(Path(self.cfg.get("project_root", "."))
                                      / ".ace_sessions"
                                      / f"{int(time.time() * 1000)}.jsonl")
        self._resumed_from: Optional[str] = None
        self._init_execution_layer()
        self.session_log = self.el.session_log
        # 会话恢复：从上次会话的事件日志重建消息历史（DSH「消息历史 = 日志派生」）。
        # 重启后对话接着来，而不是从零开始。
        self._resume_previous_session()
        # 子代理钩子：执行层的 subagent 工具通过它调用真实模型（与 approval_hook 同模式）
        self.el.executor.subagent_hook = self._run_subagent
        # 目标状态机：每次启动自动 disarm（保留 phase，但不无授权续跑；
        # 重启后须 /goal resume 或会话内重试才重新武装）。
        try:
            self.el.goal_store.disarm()
        except Exception:
            pass

    def _resume_previous_session(self) -> None:
        """启动时从 .ace_sessions/ 里最近一次**非本次**会话日志重建消息历史。

        事件日志是事实源：上次会话的 user/assistant 事件逐条在盘上，replay_messages
        就能重建"上次聊到哪"。恢复上限 20 条（10 轮），防止旧会话无限膨胀。
        """
        try:
            sess_dir = Path(self.cfg.get("project_root", ".")) / ".ace_sessions"
            if not sess_dir.is_dir():
                return
            current = Path(self.cfg["session_log"])
            candidates = [p for p in sorted(sess_dir.glob("*.jsonl"),
                                            key=lambda p: p.stat().st_mtime, reverse=True)
                          if p != current]
            if not candidates:
                return
            from ace_sessionlog import SessionLog as _SL
            prev = _SL(str(candidates[0]))
            history = prev.replay_messages()[-20:]
            if history:
                self.messages = history
                self._resumed_from = candidates[0].name
        except Exception:
            self._resumed_from = None

    def _init_execution_layer(self) -> None:
        self.el = ExecutionLayer(
            project_root=self.cfg["project_root"],
            permission_level=self.cfg["permission"],
            config={
                "bait": {"enabled": bool(self.cfg.get("bait", True)), "frequency": 0},
                "sandbox_base": str(Path(self.cfg["project_root"]).resolve() / ".sandbox_tmp"),
                # docker 一次性容器执行层：mode="off" 时整块失效，行为与以前一致
                "sandbox": {"mode": self.cfg.get("sandbox", "off"),
                            "image": self.cfg.get("sandbox_image")},
                # 会话事件日志（全链路）：执行层记录权限/守卫/快照/工具往返
                "session_log": self.cfg.get("session_log"),
                # 自定义外挂知识库（kb_search/kb_add 的根目录）
                "kb_root": self.cfg.get("kb_root"),
                # 文件式技能库目录（skill_list/skill_load 扫描的目录）
                "skills_dir": self.cfg.get("skills_dir"),
                # 联网开关（/net 切换；默认开）
                "network_enabled": bool(self.cfg.get("network_enabled", True)),
                # 第三方搜索 API（可选；search 先试 API，失败自动回退免 key 爬虫）
                "search_api": {
                    "key": self.cfg.get("search_api_key", ""),
                    "provider": self.cfg.get("search_api_provider", ""),
                    "url": self.cfg.get("search_api_url", ""),
                },
            },
        )

    def _compact_if_needed(self, system: str) -> None:
        """历史逼近上下文窗口时把中间段折成摘要。

        为什么不在这里抛错：上下文超限是可缓解的问题。压缩失败就退回硬截断
        （ace_context 内部已经这么做），会话继续 —— 但必须**告诉用户**丢了东西，
        否则模型突然"忘事"看起来像是模型变蠢了。
        """
        if not self.compact_enabled or not self.messages:
            return
        policy = ace_context.CompactionPolicy(
            context_window=self.context_window,
            # 系统提示词每轮都在，算进固定开销里，否则阈值会算得偏松
            fixed_overhead=ace_context.estimate_tokens(system),
        )
        try:
            outcome = ace_context.maybe_compact(
                self.messages, policy, summarize=self.client.summarize_context)
        except Exception as e:
            # 压缩是增强，不能反过来打断会话
            print(c("yellow", t("compact_failed", err=e)))
            return
        if not (outcome.compacted or outcome.truncated):
            return
        before, after = outcome.plan.tokens_before, ace_context.measure(outcome.messages)
        self.messages = outcome.messages
        # 会话事件日志：压缩是无损的（被替换的原始消息已逐条落在日志里），
        # 这里记录压缩发生本身，让"这段历史去哪了"可审计、可追溯。
        self.session_log.record_compaction(
            before, after, "compacted" if outcome.compacted else "truncated")
        if outcome.compacted:
            print(c("dim", t("compact_done", before=before, after=after)))
        else:
            print(c("yellow", t("compact_truncated", before=before, after=after,
                                reason=outcome.error or "-")))

    @staticmethod
    def _clickable_uri(path: str) -> str:
        """路径 → file:// URI（Windows Terminal 等现代终端支持点击）"""
        return "file:///" + Path(path).as_posix()

    @staticmethod
    def _print_clickables(result: Dict) -> None:
        """把文件/截图/图片结果渲染成可点击链接：默认收起，用户点击才全屏查看"""
        data = result.get("data")
        if not isinstance(data, dict):
            return
        tool = result.get("tool")
        candidates = []
        if tool == "open_file":
            candidates.append((t("click_open"), data.get("link") or data.get("path")))
        elif tool in ("browser_screenshot", "image_generate"):
            candidates.append((t("click_view"), data.get("image_path")))
        for label, val in candidates:
            if not val:
                continue
            val = str(val)
            uri = val if val.startswith("file:///") else AgentCLI._clickable_uri(val)
            if USE_COLOR:
                click = f"\x1b]8;;{uri}\x1b\\{val}\x1b]8;;\x1b\\"
            else:
                click = val
            print(c("dim", f"  {label}: {click}"))

    # ---------- 对话循环 ----------

    def _build_system_prompt(self) -> str:
        """组装系统提示词：基础提示词 + 语言指令 + 技能 + 已引用文件/文件夹"""
        base = load_system_prompt(tools_mode=bool(self.client.tools_ok))
        parts = [base]
        if self.lang != "zh":
            parts.append(f"【语言指令】请始终使用 {LANG_NAMES.get(self.lang, self.lang)} 回答用户。")
        parts.append(f"【工作目录】{os.path.abspath(self.cfg['project_root'])}。"
                     f"文件操作请使用该目录下的相对路径或该绝对路径，不要臆造路径。")
        # 用户环境：让模型知道"桌面/主目录"在哪，避免把工作目录当成用户桌面
        _home = os.path.expanduser("~")
        _desktop = os.path.join(_home, "Desktop")
        if not os.path.isdir(_desktop):
            _desktop = os.path.join(_home, "桌面")
        parts.append(f"【用户环境】用户主目录: {_home}；用户桌面目录: {_desktop}。"
                     f"当用户问'桌面/桌面上有什么/我的文件'等时，请列出 {_desktop} 的内容，"
                     f"而不是工作目录；路径可用 ~ 展开（如 ls {os.path.join('~', 'Desktop')}）。")
        skill = SKILLS.get(self.skill)
        if skill and self.skill != "general":
            parts.append(f"【当前技能】{skill['name']}：{skill['desc']}。"
                         f"推荐工具：{', '.join(skill['tools'])}。")
        # 项目指令（AGENTS.md / CLAUDE.md）：项目所有者的约定，性质介于指令与数据之间，
        # 注入时明确标注来源；会话内缓存一次（project_root 不变则不复读盘）。
        if self._project_instructions is None:
            self._project_instructions = load_project_instructions(
                self.cfg.get("project_root", "."))
        if self._project_instructions:
            parts.append("【项目指令】以下内容来自项目目录里的约定文件"
                         "（AGENTS.md / CLAUDE.md，项目所有者写的规则，应遵循）：\n"
                         + self._project_instructions)
        if self.context_refs:
            # SEC-011：@file / @folder 的内容进的是**系统提示词**，比工具结果那条路径更
            # 危险 —— 系统 role 天然被模型当成最高权威。文件正文可能来自任何地方
            # （克隆的仓库、收到的附件），所以逐条包进隔离块并标注来源。
            # context_refs 本身保持原样，因为 _at_refs 要拿首行当标题显示。
            parts.append("【已引用上下文】\n" + "\n".join(
                wrap_untrusted(ref, source="用户 @ 引用的文件/目录内容",
                               origin="at_ref", nonce=self._ctx_nonce)
                for ref in self.context_refs))
        return "\n\n".join(parts)

    @staticmethod
    def _make_display(tools_mode: bool = False,
                      spinner: Optional["_Spinner"] = None) -> Dict:
        """智能展示回调：隐藏 <INTERNAL> 内部思考，◈ 状态行实时反馈过程

        状态流转：思考中… → 正在调用工具… → 回复正文流式输出
        用户只会看到 EXTERNAL 的最终内容，内部推理不泄漏。
        tools_mode=True 时模型直接输出纯文本（无 EXTERNAL 标签），流式内容本身就是回复。
        spinner 提供动效：思考/工具阶段持续加点动画，回复正文出现时自动停掉。
        """
        st = {"state": "thinking", "reply_printed": 0}

        def on_delta(full: str) -> None:
            state = "thinking"
            has_protocol = "<INTERNAL>" in full or "<EXTERNAL>" in full
            if has_protocol:
                # 模型按协议输出：隐藏 INTERNAL 思考，只展示 EXTERNAL 内容
                if "<EXTERNAL>" not in full:
                    # INTERNAL 已到但 EXTERNAL 未到：继续等待，不泄漏任何思考片段
                    st["state"] = state
                    return
                ext = full.split("<EXTERNAL>", 1)[1]
                if "answer." in ext:
                    after = ext.split("answer.", 1)[1]
                    if after.lstrip().startswith("{"):
                        state = "tool"
                    else:
                        state = "reply"
                        if spinner is not None:
                            spinner.stop()
                        visible = after.lstrip()
                        # 清理结尾 </EXTERNAL>（含残缺的 </EXTERNAL 无 > 变体）与裸 </ 残标签
                        for _tag in ("</EXTERNAL>", "</EXTERNAL"):
                            if _tag in visible:
                                visible = visible.split(_tag)[0]
                                break
                        visible = re.sub(r"</?[A-Za-z]*$", "", visible)
                        if len(visible) > st["reply_printed"]:
                            if st["state"] != "reply":
                                print()   # 状态行 → 正文换行
                            delta = visible[st["reply_printed"]:]
                            print(delta, end="", flush=True)
                            st["reply_printed"] = len(visible)
                        st["state"] = state
                        return
            elif tools_mode and full.strip():
                stripped = full.strip()
                # 工具调用 JSON 特征：含 name/tool/arguments 键 + {；
                # 或 thinking 阶段以 ``` / { 开头（流式分片时第一个 delta
                # 可能只有 ```json 和 {，还没出现 "name" 键，也要隐藏）
                tool_like = ('"name"' in stripped or '"tool"' in stripped
                             or '"arguments"' in stripped) and "{" in stripped
                json_head = (st["state"] == "thinking"
                             and (stripped.startswith("```") or stripped.startswith("{")))
                if tool_like or json_head:
                    state = "tool"
                    if spinner is not None:
                        spinner.set_label(t("calling_tool"))
                    st["state"] = state
                    return
                # 原生工具模式：纯文本内容即最终回复（清洗思考标记后显示）
                state = "reply"
                if spinner is not None:
                    spinner.stop()
                if st["state"] != "reply":
                    print()
                visible = _sanitize_display_text(full)
                delta = visible[st["reply_printed"]:]
                if delta:
                    print(delta, end="", flush=True)
                    st["reply_printed"] = len(visible)
                st["state"] = state
                return
            if state == "tool" and spinner is not None:
                spinner.set_label(t("calling_tool"))
            if spinner is None:
                # 无 spinner（如测试禁用）时退化为静态状态行
                if st["state"] == "reply":
                    print()
                label = (t("thinking") + "…" if state == "thinking"
                         else t("calling_tool") + "…")
                sys.stdout.write(f"\r◈ {label}   ")
                sys.stdout.flush()
            st["state"] = state

        return {"state": st, "on_delta": on_delta}

    def converse(self, user_input: str, echo_input: bool = True) -> None:
        if echo_input:
            # 单次对话（--input）没有终端回显，打印聊天标题
            print(f"\n{c('magenta', '❯')} {user_input}")
        else:
            # 交互模式：输入已由终端回显，只留一个空行分隔，避免重复显示
            print()
        t0 = time.time()
        # 会话事件日志：记录用户输入（可审计、可重放）
        self.session_log.record_user(user_input)
        # 记忆预注入：模型生成前把相关历史记忆放进 prompt（无记忆时原样返回）
        next_user = self.el.prepare_context(user_input)
        fail_streak = 0
        # 反幻觉：本次请求内是否真有工具落地执行、已经纠正过几次
        tool_ran = False
        claim_nudges = 0
        for _round in range(1, MAX_ROUNDS + 1):
            msgs = self.messages + [{"role": "user", "content": next_user}]
            spinner = _Spinner(t("thinking"))
            disp = self._make_display(tools_mode=bool(self.client.tools),
                                      spinner=spinner)
            spinner.start()
            try:
                # 基础提示词 + 语言/技能/引用上下文
                system = self._build_system_prompt()
                # 会话事件日志：记录每次模型请求的 envelope 与完整系统提示词
                # （可重建"模型看到了什么"——含 AGENTS.md/记忆注入/目标）
                self.session_log.record_request(
                    model=self.client.model,
                    base_url=self.client.base_url,
                    permission=str(self.cfg.get("permission", "readonly")),
                    system_len=len(system),
                    messages_count=len(msgs))
                self.session_log.record_system(system)
                output = self.client.stream_generate(system, msgs,
                                                     on_delta=disp["on_delta"])
            except KeyboardInterrupt:
                spinner.stop(newline=True)
                print("\n" + t("interrupted"))
                return
            except Exception as e:
                spinner.stop(newline=True)
                hint = _model_error_hint(e)
                self.session_log.record_model_error(str(e), hint)
                print(c("red", "\n" + t("model_call_failed", err=e)
                        + (f"\n  提示: {hint}" if hint else "")))
                return
            # 状态行/流式正文收尾换行
            if disp["state"]["state"] in ("thinking", "tool"):
                spinner.stop(newline=True)
            elif disp["state"]["reply_printed"]:
                spinner.stop()
                print()
            else:
                spinner.stop()
            # 会话事件日志：记录模型本轮完整输出（原文，可重放）
            self.session_log.record_assistant(output)
            self.messages = self.client.trim_messages(
                msgs + [{"role": "assistant", "content": output}],
                self.max_history)
            # 压缩放在硬截断之后：max_history 是用户显式设的上限，压缩只负责
            # 在仍然超出模型窗口时把中间段折成摘要，而不是替用户改主意。
            self._compact_if_needed(system)

            # 工具执行阶段动画（仅当本轮确实是工具调用）
            exec_spinner = (_Spinner(t("calling_tool"))
                            if disp["state"]["state"] == "tool" else None)
            if exec_spinner:
                exec_spinner.start()
            try:
                result = self.el.process_agent_output(output, user_input)
            except KeyboardInterrupt:
                if exec_spinner:
                    exec_spinner.stop(newline=True)
                print("\n" + t("interrupted"))
                return
            except Exception as e:
                if exec_spinner:
                    exec_spinner.stop(newline=True)
                print(c("yellow", t("exec_layer_error", err=e)))
                next_user = PROMPT_EXEC_EXCEPTION.format(err=e)
                continue
            if exec_spinner:
                exec_spinner.stop(newline=True)
            self.session["rounds"] += 1

            # 连续失败/无进展熔断：工具反复失败说明模型已死循环，不再浪费轮数。
            # 查看类工具（terminal_view/file_read/search/browser_screenshot）成功不算进展，
            # 防止模型靠反复 ls 假装干活、绕过熔断。
            _status = result["status"]
            _VIEW_TOOLS = {"terminal_view", "file_read", "search", "browser_screenshot"}
            if result.get("tool") and _status == "SUCCESS":
                tool_ran = True  # 本次请求内确实有工具落地执行过
            if _status == "FINAL_REPLY":
                fail_streak = 0
            elif _status == "SUCCESS":
                if result.get("tool") in _VIEW_TOOLS:
                    pass  # 查看类成功不重置（不视为实质进展）
                else:
                    fail_streak = 0
            elif _status in ("PLAN_PROPOSED", "PLAN_ALREADY_APPROVED",
                             "PERMISSION_REQUEST", "PLAN_PENDING"):
                pass  # 计划/权限交互是正常流程，不计数也不重置
            else:
                fail_streak += 1
                if fail_streak >= STALL_ABORT_ROUNDS:
                    print(c("red", "\n" + t("stall_abort", n=fail_streak)))
                    return

            if result["status"] == "PLAN_PROPOSED":
                print(c("cyan", f"\n  {result.get('plan') or result.get('message', '')}"))
                next_user = resolve_plan(self.el, ask_yes_no(
                    c("yellow", t("plan_approve_q")),
                    lambda: print(c("dim", t("auto_reject_plan")))))
                print(c("green", t("plan_approved_msg"))
                      if next_user == PROMPT_PLAN_APPROVED
                      else c("yellow", t("plan_rejected_msg")))
                continue

            if result["status"] == "PLAN_ALREADY_APPROVED":
                next_user = PROMPT_PLAN_APPROVED
                continue

            if result["status"] == "PERMISSION_REQUEST":
                tool_name = result.get("tool")
                print(c("yellow", "\n" + t("perm_request_title", tool=tool_name)))
                if result.get("reason"):
                    print(c("dim", t("perm_reason", reason=result["reason"])))
                decision = ask_grant(c("yellow", t("perm_approve_q")),
                                     lambda: print(c("dim", t("auto_deny_perm"))))
                next_user = resolve_permission(self.el, decision)
                if decision == GRANT_DENY:
                    print(c("yellow", t("perm_denied_msg")))
                elif tool_name in self.el.permission.session_grants:
                    print(c("green", t("perm_granted_session_msg")))
                else:
                    # 选了"本会话"但被 grant_session 降级回单次（terminal_exec 这类）
                    if decision == GRANT_SESSION:
                        print(c("yellow", t("perm_session_refused", tool=tool_name)))
                    print(c("green", t("perm_granted_msg")))
                continue



            if result["status"] == "FINAL_REPLY":
                # 反幻觉闸门：模型声称"已创建/已保存/已执行"，但本次请求里一个工具都
                # 没落地 —— 那就是编的。不能打绿色的 ✓ 完成然后退出（用户会以为成功，
                # 桌面上什么都没有）。先让模型自己改一次；改不动就把真相打给用户。
                if (not tool_ran
                        and claims_completed_action(result.get("message") or "")):
                    if claim_nudges < 1:
                        claim_nudges += 1
                        print(c("yellow", "\n" + t("unverified_claim")))
                        next_user = PROMPT_UNVERIFIED_CLAIM
                        continue
                    print(c("yellow", "\n" + t("unverified_claim_final")))
                if disp["state"]["reply_printed"] < len(result["message"]):
                    # 兜底：流式展示未覆盖时补打完整回复
                    print()
                    print(result["message"], end="", flush=True)
                print(c("green", t("done", round=_round,
                                   sec=time.time() - t0)))
                # 目标轮次驱动（借鉴 DSH goal-round-driver）：goal active+armed+预算内
                # → 自动进入下一轮（不返回主界面），直到模型标记 complete/blocked、
                # 预算耗尽或用户中断。start_round() 返回 None 即不可续。
                _g = self.el.goal_store.start_round()
                if _g is None:
                    return
                print(c("dim", t("goal_continue",
                                 r=_g.rounds_started, m=_g.max_rounds,
                                 obj=_g.objective[:60])))
                self.session_log.record_goal_round(_g.rounds_started, _g.max_rounds)
                next_user = (f"【目标续跑】目标：{_g.objective}\n"
                             f"轮次 {_g.rounds_started}/{_g.max_rounds}。"
                             "继续推进目标；完成用 goal_update(phase=complete)，"
                             "遇到无法继续的阻塞用 goal_update(phase=blocked, "
                             "reason_code=..., reason_message=...)。")
                fail_streak = 0
                tool_ran = False
                claim_nudges = 0
                continue

            if result["status"] in ERROR_STATUSES:
                self.session["violations"] += 1
                print(c("red", t("error_line", status=result["status"],
                                 msg=result.get("message", "")[:80])))
                next_user = PROMPT_ERROR_RETRY.format(rendered=render_tool_result(result))
            else:
                self.session["tools"] += 1
                # OpenClaw 式工具卡片：三态标记 + 参数摘要 + 输出折叠
                _st = result["status"]
                _elapsed = result.get("elapsed")
                _elapsed_f = float(_elapsed) if isinstance(_elapsed, (int, float)) else 0.0
                _out = ""
                if _st == "SUCCESS":
                    _d = result.get("data") or {}
                    if isinstance(_d, dict):
                        _out = str(_d.get("stdout") or _d.get("content") or "")[:4000]
                _mark, _color = status_mark(_st)
                _card = tool_card(
                    result.get("tool", ""), _st,
                    message=result.get("message", ""),
                    output=_out, elapsed=_elapsed_f,
                    collapsed=True, max_lines=8)
                # 上色：标题行按状态色，其余 dim
                for _i, _ln in enumerate(_card):
                    if _i == 0:
                        _ln = _ln.replace(f" {_mark} ", f" {c(_color, _mark)} ", 1)
                        print(c(_color, _ln))
                    else:
                        print(c("dim", _ln))
                if result["status"] == "SUCCESS":
                    self._print_clickables(result)
                if result.get("memory_injected"):
                    print(c("dim", t("memory_injected",
                                     n=len(result["memory_injected"]))))
                if self.client.mock and result["status"] == "SUCCESS":
                    data = result.get("data") or {}
                    self.client._mock_provider.mock_tool_result = (
                        data.get("datetime") or json.dumps(data, ensure_ascii=False))
                next_user = PROMPT_TOOL_RESULT.format(rendered=render_tool_result(result))
        print(c("yellow", t("max_rounds")))

    # ---------- 无感回滚 ----------

    def _undo_last(self) -> None:
        """一键回滚到最近一次自动快照（无需记 id，写入操作前都会自动快照）"""
        if not self.el.guardian:
            print(c("red", t("snap_disabled")))
            return
        snaps = self.el.guardian.list_snapshots()
        if not snaps:
            print(t("undo_none"))
            return
        latest = snaps[-1]
        try:
            ok = self.el.guardian.rollback(latest["id"])
            if ok:
                print(c("green", t("undo_done", id=latest["id"]) +
                                 f"（{latest.get('created_iso')}，{latest.get('file_count')} 个文件）"))
            else:
                print(c("red", t("rollback_partial")))
        except Exception as e:
            print(c("red", t("rollback_fail", err=e)))

    def _show_status(self) -> None:
        stats = self.el.get_stats()
        elapsed = time.time() - self.session["start"]
        print(t("status_session", rounds=self.session["rounds"],
                tools=self.session["tools"], violations=self.session["violations"],
                sec=elapsed))
        print(t("status_lang_skill",
                lang=LANG_NAMES.get(self.lang, self.lang),
                skill=t(f"skill_{self.skill}") if self.skill in SKILLS else self.skill,
                refs=len(self.context_refs)))
        print(t("status_permission", level=stats["permission"]["current_level"],
                viol=stats["violation_count"], exec=stats["execution_count"]))
        if self.el.guardian:
            snaps = self.el.guardian.list_snapshots()
            limit = getattr(self.el.guardian, "max_snapshots", 20)
            print(t("status_snapshots", n=len(snaps), limit=limit))
        print(t("status_modules", v2=stats["v2_gateway"],
                v1=stats["v1_modules"], parser=stats["parser"]))

    def _show_memory(self) -> None:
        if not self.el.archive:
            print(t("memory_disabled"))
            return
        print(f"  {json.dumps(self.el.archive.stats(), ensure_ascii=False)}")
        mem = self.el.archive.get_memory(top_k=5)
        if not mem:
            print(t("memory_empty"))
        for m in mem:
            mark = "⚡" if m["urgent"] else "·"
            print(f"  {mark} {m['text'][:60]}  (sim={m['similarity']}, w={m['weight']})")

    # ---------- REPL ----------

    def repl(self, return_to_landing: bool = False) -> None:
        """聊天 REPL；return_to_landing=True 时退出聊天回到主界面，否则结束程序"""
        # 进入聊天前清屏，避免登录页的 logo/菜单残留在屏幕上造成双头部
        self._clear_screen()
        print(c("bold", "ACE") + c("dim", t("banner_sub")))
        print(t("banner_model", desc=self.client.describe()))
        print(t("banner_permission",
                perm=self.cfg["permission"], root=self.cfg["project_root"]))
        for line in self._banner_extras():
            print(line)
        if self.cfg["permission"] != "readonly":
            print(c("yellow", t("banner_warn_write")))
        print(t("banner_hint",
                help=c("magenta", "/help"), at=c("magenta", "@"),
                exit=c("magenta", "/exit")))

        # 启动自检：配置防蠢提示
        for hint in _config_sanity_hints(self.cfg):
            print(c("yellow", f"  ⚠ {hint}"))

        # 会话恢复提示：从上次会话日志重建的消息历史
        if getattr(self, "_resumed_from", None):
            print(c("dim", t("session_resumed", n=len(self.messages),
                             file=self._resumed_from)))

        # 目标状态机：重启后自动 disarmed（不无授权续跑），提示未完成目标
        try:
            self.el.goal_store.disarm()
        except Exception:
            pass
        _g = self.el.goal_store.snapshot()
        if _g and _g["phase"] in ("active", "paused", "blocked"):
            print(c("dim", t("goal_pending", phase=_g["phase"],
                             obj=_g["objective"][:50]
                             + ("…" if len(_g["objective"]) > 50 else ""))))

        # 实时补全：有 prompt_toolkit 就上 Claude Code 同款弹窗菜单，没有则降级普通输入
        session = None
        if sys.stdin.isatty() and sys.stdout.isatty():
            try:
                from prompt_toolkit import PromptSession
                from prompt_toolkit.styles import Style
                from prompt_toolkit.key_binding import KeyBindings

                kb = KeyBindings()

                @kb.add("escape")
                def _exit_on_escape(event):
                    # 空输入时按 ESC 直接退出；补全菜单开着时 ESC 优先关闭菜单
                    buf = event.current_buffer
                    if not buf.text.strip():
                        raise EOFError
                    if buf.complete_state is not None:
                        buf.cancel_completion()

                # OpenClaw 式 Ctrl+C 分层：有输入 → 清空输入（防误退）；无输入 → 提示再按一次退出。
                @kb.add("c-c")
                def _ctrl_c_layer(event):
                    buf = event.current_buffer
                    if buf.text:
                        buf.reset()   # 清空输入，不退出
                        return
                    # 无输入：1 秒内第二击退出
                    now = time.monotonic()
                    if (getattr(_ctrl_c_layer, "_last", 0)
                            and now - _ctrl_c_layer._last < 1.0):
                        raise EOFError
                    _ctrl_c_layer._last = now
                    event.app.invalidate()
                    print(c("dim", "  再按一次 Ctrl+C 退出（Esc 也退出）"), end="", flush=True)

                @kb.add("enter")
                def _two_step_enter(event):
                    _handle_enter_key(event.current_buffer)

                # 状态栏三项的直接切换键：F1=权限 F2=沙箱 F3=联网。
                # 在输入框内任意时刻按下都会立即退出本行输入、弹出对应二次选择框
                # （未提交的半截输入不保留）。实现：给 prompt() 一个魔数返回值，
                # 循环外统一转成斜杠命令走 run_command —— 选择框逻辑只有一份。
                for _hotkey, _hot_cmd in (("f1", "/permission"),
                                          ("f2", "/sandbox"),
                                          ("f3", "/net")):
                    def _hotkey_handler(event, _cmd=_hot_cmd):
                        try:
                            # 先清掉当前输入行：热键打断后不留半截文字到下一轮
                            event.current_buffer.reset()
                            event.app.exit(result="\x00MENU:" + _cmd)
                        except Exception:
                            pass
                    kb.add(_hotkey)(_hotkey_handler)

                session = PromptSession(
                    completer=_build_slash_completer(self.COMMANDS),
                    complete_while_typing=True,
                    key_bindings=kb,
                    bottom_toolbar=self._footer,
                    style=Style.from_dict({
                        "prompt": "ansimagenta bold",
                        "perm": "ansicyan bold",
                        "footer": "bg:#2b2b3c #aaaaaa",
                        "footer-dim": "bg:#2b2b3c #666666",
                        "footer-ro": "bg:#2b2b3c #5fa8ff",
                        "footer-w": "bg:#2b2b3c #f6c453",
                        "footer-f": "bg:#2b2b3c #ff6b6b",
                        "footer-goal": "bg:#2b2b3c #7ecb8f",
                        "completion-menu.completion": "bg:#2b2b3c #ffffff",
                        "completion-menu.completion.current": "bg:#5f3dc4 #ffffff",
                        "completion-menu.completion.meta": "bg:#1e1e2e #aaaaaa",
                    }),
                )
                print(c("dim", "  ✓ 实时补全已启用（输入 / 或 @ 弹出菜单）"))
                print(c("dim", "  状态栏快捷切换: F1=权限  F2=沙箱  F3=联网（直接弹框选档，"
                               "也可打 /permission /sandbox /net 回车弹框）"))
            except ImportError:
                print(c("dim", "  提示: 运行 ace --install-ui 一键安装实时补全依赖（Claude Code 同款 / 弹窗菜单）"))
            except Exception as e:
                # 构造失败（终端/版本兼容等）：降级为普通 input()，但明示原因便于排查
                print(c("yellow", f"  ⚠ 补全菜单未启用（{type(e).__name__}: {e}），已降级为普通输入"))
                session = None
        else:
            print(c("dim", "  ⚠ 非交互终端（stdin/stdout 非 TTY），实时补全菜单不可用"))

        while True:
            try:
                # 提示符带权限状态（readonly=蓝 / write=黄 / full=红），一眼看清当前权限
                _perm = str(self.cfg.get("permission", "readonly"))
                _perm_color = {"readonly": "ansiblue", "write": "ansiyellow",
                               "full": "ansired"}.get(_perm, "ansicyan")
                if session is not None:
                    line = session.prompt([
                        ("class:perm", f"[{_perm}] "),
                        ("class:prompt", "❯ "),
                    ]).strip()
                else:
                    line = input(c(_perm_color, f"[{_perm}] ") + c("magenta", "❯ ")).strip()
                line = line.lstrip("\ufeff")  # 兼容带 UTF-8 BOM 的管道/重定向输入
                # F1/F2/F3 热键退出输入框时带回魔数标记 → 还原成斜杠命令
                # （魔数值本身以 / 开头，如 \x00MENU:/permission，只需剥掉前缀）
                if line.startswith("\x00MENU:"):
                    line = line[len("\x00MENU:"):]
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            # 防蠢：用户把 cmd 命令/参数误打进 REPL 时本地拦截，不发给模型
            if _looks_like_cli_command(line):
                self._handle_cli_mistype(line)
                continue
            if line.startswith("@"):
                # @ 快捷方式：语言 / 技能 / 文件与文件夹引用
                self._handle_at_command(line)
                continue
            if line.startswith("/") or line.lower() in ("exit", "quit"):
                try:
                    if not self.run_command(line):
                        break
                except CommandCancelled:
                    print(c("yellow", t("cancelled") + "。"))
                except KeyboardInterrupt:
                    print("\n" + t("cancelled") + "。")
                except Exception as e:
                    print(c("red", t("command_failed", err=e)))
                continue
            try:
                self.converse(line, echo_input=False)
            except KeyboardInterrupt:
                print("\n" + t("interrupted"))
            except Exception as e:
                print(c("red", t("chat_error", err=e)))
        print(c("dim", t("back_landing")) if return_to_landing
              else c("dim", t("bye")))


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Code —— AI Agent 命令行终端")
    parser.add_argument("--mock", action="store_true", help="离线演示（脚本化假模型）")
    parser.add_argument("--base-url", help="API 地址（OpenAI 或 Anthropic 兼容）")
    parser.add_argument("--api-key", help="API Key")
    parser.add_argument("--model", help="模型名")
    parser.add_argument("--project-root", help="工作目录")
    parser.add_argument("--permission", choices=["readonly", "write", "full"], help="权限等级")
    parser.add_argument("--no-bait", action="store_true", help="关闭诱饵验证")
    parser.add_argument("--sandbox", choices=["off", "job", "docker"],
                        help="terminal_exec / code_execute 的执行位置："
                             "off = 宿主（默认，仅有 Python 层策略校验）；"
                             "job = Windows Job Object（内存/进程数上限 + 整棵进程树"
                             "回收，需先在 executor/ 下 go build）；"
                             "docker = 一次性容器（--network none，只挂工作目录）。"
                             "job 与 docker 都不做静默回退：拿不到边界直接报错，"
                             "绝不偷偷改回宿主执行。")
    parser.add_argument("--kb", help="自定义外挂知识库目录（默认项目 .ace_kb/）。"
                                     "知识库里的资料 kb_search 可检索、kb_add 可写入，跨会话持久")
    parser.add_argument("--skills", help="文件式专业技能目录（如 G:\\AI_skils，每个技能一个 SKILL.md）。"
                                         "skill_list 查看、skill_load 按需加载完整 instructions")
    parser.add_argument("--sandbox-image", help="沙箱镜像（默认 ace-sandbox:latest，"
                                               "用 docker/Dockerfile.sandbox 构建）")
    parser.add_argument("--tools", action="store_true",
                        help="使用原生工具调用（OpenAI 兼容 function calling，不支持时自动降级）")
    parser.add_argument("--max-history", type=int, default=0,
                        help="保留最近 N 轮对话历史（0 = 不裁剪）")
    parser.add_argument("--context-window", type=int, default=0,
                        help="模型上下文窗口 token 数（默认 32768）。压缩阈值按它算，"
                             "填小只是早压缩一点，填大会在以为还有余量时被服务端拒掉")
    parser.add_argument("--no-compact", action="store_true",
                        help="关闭上下文压缩，退回纯硬截断（会丢早期对话，"
                             "包括第一条用户消息里的任务说明）")
    parser.add_argument("--input", help="单次对话（非交互）")
    parser.add_argument("--save-config", action="store_true", help="把当前参数保存到 ~/.ai_code.json")
    parser.add_argument("--install-ui", action="store_true",
                        help="一键安装实时补全依赖（prompt_toolkit，Claude Code 同款 / 弹窗菜单）")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.install_ui:
        print("正在安装 prompt_toolkit（自动检测已装状态 + 多镜像回退）...")
        if _pip_install_with_fallbacks("prompt_toolkit"):
            print("✅ 安装完成，重新启动 ace 即可享受 / 实时自动补全菜单")
        else:
            print("❌ 安装失败，请手动运行: "
                  "pip install prompt_toolkit -i https://pypi.tuna.tsinghua.edu.cn/simple")
        return

    cfg = merge_config(args)
    if args.no_bait:
        cfg["bait"] = False
    if args.save_config:
        save_cli_config(cfg)

    cli = AgentCLI(cfg, mock=args.mock)
    if args.input:
        cli.converse(args.input)
        return
    if args.mock:
        cli.repl()          # 显式离线演示直接进聊天
        return
    cli.landing()           # 默认进入登录页（AI-CLI 启动平台同款首页菜单）


if __name__ == "__main__":
    main()
