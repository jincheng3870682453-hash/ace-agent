#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent_runner.py —— Agent 交互循环（把 LLM 和执行层接起来）

职责：
    用户输入 → L3 模型生成 <INTERNAL>/<EXTERNAL> → ExecutionLayer 解析/裁决/执行
    → 结果回填模型 → 循环，直到模型给出最终回复（模式 B）

模型来源（优先级从高到低）：
    1. --mock                         脚本化假模型，离线演示完整循环
    2. --base-url / --api-key / --model  OpenAI 兼容 API（OpenAI/DeepSeek/Ollama/vLLM...）
    3. 环境变量 AGENT_BASE_URL / AGENT_API_KEY / AGENT_MODEL

用法：
    python agent_runner.py --mock                          # 离线演示（无需网络/密钥）
    python agent_runner.py --mock --verbose --input 现在几点了
    python agent_runner.py --base-url https://api.deepseek.com/v1 \
        --api-key sk-xxx --model deepseek-chat              # 接真实模型
    python agent_runner.py --base-url http://localhost:11434/v1 \
        --api-key ollama --model Qwen2.5-coder:7b --tools   # 本地 Ollama（原生工具调用）
    python agent_runner.py --mock --max-history 12          # 离线演示 + 历史裁剪
"""

import argparse
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("ace")

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
from ace_isolation import untrusted_source, wrap_untrusted  # noqa: E402
from tools.base import repair_backslash_json  # noqa: E402
import ace_http  # noqa: E402
from i18n import SUPPORTED as SUPPORTED_LANGS, set_language, t  # noqa: E402

SYSTEM_PROMPT_PATH = FOLDER / "agent_system_prompt_v7.md"
SYSTEM_PROMPT_V8_PATH = FOLDER / "agent_system_prompt_v8.md"
SYSTEM_PROMPT_TOOLS_PATH = FOLDER / "agent_system_prompt_tools.md"
MAX_ROUNDS = 20


def load_system_prompt(tools_mode: bool = False) -> str:
    """加载系统提示词；tools_mode=True 用原生工具调用精简版，否则用文本协议版（v8 优先，v7 兜底）"""
    candidates = [SYSTEM_PROMPT_TOOLS_PATH if tools_mode else SYSTEM_PROMPT_V8_PATH,
                  SYSTEM_PROMPT_PATH]
    for p in candidates:
        if p.exists():
            return p.read_text(encoding="utf-8")
    return "你是一个沙盒 AI Agent，按 <INTERNAL>/<EXTERNAL> 格式输出。"


class ToolsUnsupported(Exception):
    """模型端点不支持原生工具调用，触发自动降级到文本协议"""


def _approval_scope_text(rule: str) -> str:
    """把 rule 翻译成"按下 a 之后到底放宽了多大范围"的人话。

    这是最容易骗到用户的一处：`git ... | grep x` 命中的规则是 shell_syntax，
    按下 a 之后本会话**所有**带管道/重定向的命令都免审；`curl` 命中 not_allowlisted，
    按下 a 等于本会话所有非白名单命令免审。提示语只写"同类放行"，"同类"有多大
    完全没说 —— 用户是在不知道范围的情况下放权。

    文案走 i18n（键 `scope_<rule>`）：外层 `approval_scope` 早就是翻译键了，
    范围说明留在代码里会让英文界面出现"What 'a' would allow: 本会话内……"的混排。
    """
    if rule.startswith("egress:"):
        return t("scope_egress").format(host=rule.split(":", 1)[1])
    if rule in _APPROVAL_SCOPE_RULES:
        return t(f"scope_{rule}")
    # 白名单之外的 rule 不去拼 scope_<rule>：那个键不存在时 t() 会把键名原样吐给
    # 用户（"scope_foo"），比这句通用说明更糟。
    return t("scope_fallback").format(rule=rule)


# 有专属范围说明的 rule。取自 ace_execpolicy 里真实会走到 prompt 档的规则名
# （forbidden 档不问人、allow 档不拦，都不需要范围说明）。每一项对应 locales
# 里的 `scope_<rule>` 键；不在这里的 rule 回落到 `scope_fallback`。
_APPROVAL_SCOPE_RULES = frozenset({
    "shell_syntax",
    "unparsable",
    "path_qualified_binary",
    "git_global_option",
    "not_allowlisted",
    "read_only_sandbox",
    "path_escape",
})

# 请求对象类型 → 对象的**机器可读种类**。同一个确认框要装命令、路径、URL、
# 收件人等等，写死成"命令"会让用户看到"命令: C:\...\.env"这种自相矛盾的行。
# 这里刻意只存种类、不存译文：种类是给控制流看的，译文查 `label_<kind>`。
_APPROVAL_TARGET_KIND = {
    "LaunchApproval": "path",
    "DestinationApproval": "url",
    # 读项目外的路径：对象一定是路径，落到 object 会显示成"对象: C:\...\note.txt"
    "ReadApproval": "path",
}


def _approval_target_kind(request) -> str:
    """给"对象"那一行定种类（path / url / command / object）。按契约特征判定，
    不按类名硬匹配 —— 命令闸门来自 ace_execpolicy.Verdict，识别特征是带
    `decision` 字段。

    为什么返回种类而不是标签：调用方要用它同时决定"查哪个 label_<kind> 键"和
    "URL 要不要拆成两行"。把控制流挂在译文字面量上（旧代码的 `label == "URL"`）
    在 en/ja 下必然失配，查询串那一行会永远不显示 —— 与 denial_kind 同一类问题。
    """
    name = type(request).__name__
    if name in _APPROVAL_TARGET_KIND:
        return _APPROVAL_TARGET_KIND[name]
    if hasattr(request, "decision"):
        return "command"
    if str(getattr(request, "rule", "") or "").startswith("egress:"):
        return "url"
    return "object"


# 有译文的 reason 键。与 `_APPROVAL_SCOPE_RULES` 同源不是巧合：会走到确认框的
# 命令闸门就是那几条 prompt 档规则，`ace_execpolicy` 给它们填的 `reason_key`
# 也正好是 `reason_<rule>`。用白名单而不是无条件相信 `reason_key`，是因为
# `i18n.t()` 查不到键时会把**键名**原样吐给用户 —— 那比一句中文原文更糟。
_APPROVAL_REASON_KEYS = frozenset(f"reason_{_r}" for _r in _APPROVAL_SCOPE_RULES)


def _approval_reason_text(request) -> str:
    """确认框"原因"那一行的文案：能翻译就翻译，翻不了就回落到产生方给的原文。

    为什么不是"中文 reason → 键"的映射表：那等于把判据重新挂回中文子串，
    与 `DenialKind` 那一轮拆掉的东西是同一个反模式 —— 闸门文案一改，映射静默
    失效，不报错、只是又变回中文。所以键必须由**产生方**给。

    回落分支现在仍会命中：`tools/base.py` 的几类逐次确认（项目外读取、外发目的地、
    不可回滚写入、抓屏）还没有 `reason_key`，它们的 reason 与 deny_hint 依旧是
    硬编码中文。那批的产生方在 tools/ 下，不在本轮改动范围内。
    """
    key = str(getattr(request, "reason_key", "") or "")
    if key in _APPROVAL_REASON_KEYS:
        args = getattr(request, "reason_args", None)
        return t(key, **args) if isinstance(args, dict) and args else t(key)
    return getattr(request, "reason", "") or ""


def result_display_message(result: Dict) -> str:
    """执行层返回里**给人看**的那句话。

    `message` 一直是给模型看的（固定中文，见 `execution_layer` 里 403 分支上方的
    说明），闸门自己带上 `message_key` / `message_args` 之后，展示层就该优先用
    键去查译文，拿不到才回落 `message`。

    分成两个字段而不是把 `message` 直接翻译掉：`message` 会进模型上下文，
    让它随界面语言漂移等于让模型的输入语言由用户的界面偏好决定；而 test_all.py
    里还有若干断言按中文子串核对 `message`，翻译它会让"文案改没改"这件事
    由测试来发现，而不是由这一层的契约来保证。
    """
    key = str(result.get("message_key") or "")
    if key:
        args = result.get("message_args")
        text = t(key, **args) if isinstance(args, dict) and args else t(key)
        # t() 查不到键时返回键名本身。宁可给中文原文，也不要给用户看 `deny_xxx`。
        if text != key:
            return text
    return str(result.get("message") or "")


def make_cli_approval_hook(*, out=None, ask=input) -> "callable":
    """构造审批回调，返回 hook(request) -> bool。terminal_exec 与各类逐次确认共用。

    为什么必须有这个东西：SEC-001 之后，判定为 prompt 的命令在
    `approval_hook is None` 时会被一律拒绝（见 tools/file_tools.py 的 403 分支）。
    这个失败方向是对的，但如果没人把 hook 接上，`git commit -m x`、带管道的命令
    这类**合法但需要确认**的操作就彻底不可用了 —— 安全闸门变成了功能墙。

    三个答案，语义对齐 codex 的 ApprovalPolicy：
        y  仅这一次
        a  本会话内这一类规则都放行（仅在请求带 rule 时提供，见下）
        n  拒绝（默认；直接回车也是拒绝）

    `rule` 为空的请求（不可回滚写入、外发内容、抓屏……）压根没有"这一类都放行"
    的合理语义，所以对它们**不展示** a；用户真按了 a 也会被明确告知不支持，
    而不是像以前那样静默落进拒绝分支 —— 那会让人以为自己批准了。

    提示走 stderr：`ace > log.txt` 时若写 stdout，问题会进日志文件，
    终端上只剩一个不知在等什么的光标。

    非 TTY 一律拒绝，绝不猜"用户大概会同意"—— SEC-004 就是这么出的。
    """
    if out is None:
        def out(s):
            print(s, file=sys.stderr)
    session_approved_rules = set()

    def hook(request) -> bool:
        rule = getattr(request, "rule", "") or ""
        if rule and rule in session_approved_rules:
            # 静默放行等于用户不知道自己早先那次 a 正在生效，回显一行。
            out(t("approval_auto_allowed").format(rule=rule))
            return True
        if not sys.stdin.isatty():
            out(t("approval_non_tty"))
            return False
        kind = _approval_target_kind(request)
        label = t(f"label_{kind}")
        target = getattr(request, "normalized", "") or ""
        out(t("approval_needed_header"))
        if kind == "url":
            # 数据是靠查询串带出去的，只给域名等于让用户在信息不足时点同意；
            # 而整条 URL 单行直出又会被窗口硬折。拆成两行。
            parts = urllib.parse.urlsplit(target)
            out(t("approval_target").format(label=label,
                                            target=f"{parts.scheme}://{parts.netloc}{parts.path}"))
            if parts.query:
                out(t("approval_query").format(query=parts.query))
        else:
            out(t("approval_target").format(label=label, target=target))
        out(t("approval_reason").format(reason=_approval_reason_text(request),
                                        rule=rule or "-"))
        hint = getattr(request, "deny_hint", "") or ""
        if hint:
            out(t("approval_hint").format(hint=hint))
        if rule:
            out(t("approval_scope").format(scope=_approval_scope_text(rule)))
        try:
            answer = (ask(t("approval_q_scoped") if rule
                          else t("approval_q_once")) or "").strip().lower()
        except (EOFError, KeyboardInterrupt):
            out("")
            return False
        if answer in ("a", "always"):
            if rule:
                session_approved_rules.add(rule)
                out(t("approval_remembered").format(rule=rule))
                return True
            out(t("approval_no_rule"))
            return False
        return answer in ("y", "yes")

    return hook


VIEW_TOOLS = {"terminal_view", "file_read", "search", "browser_screenshot"}
# 计划/权限交互是正常流程，既不算失败也不算进展
NEUTRAL_STATUSES = {"PLAN_PROPOSED", "PLAN_ALREADY_APPROVED",
                    "PERMISSION_REQUEST", "PLAN_PENDING"}
STALL_ABORT_ROUNDS = 6


class StallTracker:
    """连续无进展检测。纯状态机，不打印、不抛异常。

    为什么抽出来：ai_code.py 的主循环里本来内联着这套判定，agent_runner.py 的
    主循环则完全没有 —— 同一个 Agent 有两个入口，其中一个会在模型死循环时
    把 20 轮全部烧掉。抽成一个类之后两边共用一套语义，改一处两边都对。

    为什么查看类工具成功不算进展：模型卡住时最常见的行为是反复 ls / 读同一个文件，
    每次都是 SUCCESS。如果 SUCCESS 一律重置计数，熔断就永远不会触发 ——
    模型靠"假装在看"绕过了保护。
    """

    def __init__(self, abort_after: int = STALL_ABORT_ROUNDS) -> None:
        self.abort_after = abort_after
        self.streak = 0

    def observe(self, status: str, tool: Optional[str] = None) -> bool:
        """记录一轮结果，返回是否应当中止本次会话"""
        if status == "FINAL_REPLY":
            self.streak = 0
        elif status == "SUCCESS":
            if tool not in VIEW_TOOLS:
                self.streak = 0
        elif status in NEUTRAL_STATUSES:
            pass
        else:
            self.streak += 1
        return self.streak >= self.abort_after


def _post_chat(base_url: str, api_key: str, model: str, messages: List[Dict],
               tools: Optional[List[Dict]] = None, timeout: int = 120) -> Dict:
    """OpenAI 兼容 /chat/completions（纯标准库 urllib，无 requests 依赖）"""
    payload = {"model": model, "messages": messages, "temperature": 0.2}
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}",
                 "Content-Type": "application/json"},
        method="POST",
    )
    # 带退避重试：之前是裸 urlopen，一次 429 或一次连接抖动就终止整轮，
    # 用户已经跑掉的上下文全部作废。判定逻辑在 ace_http.decide（纯函数）。
    return ace_http.urlopen_json_with_retry(req, timeout=timeout)


# ============================================================
# 原生工具调用（OpenAI 兼容 function calling，Ollama/Qwen 等均支持）
# ============================================================

TOOLS = [
    {"type": "function", "function": {"name": "terminal_view",
     "description": "只读查看目录/文件/进程状态（白名单命令，无 shell 副作用）",
     "parameters": {"type": "object", "properties": {"command": {"type": "string",
     "description": "只读命令，如 ls -la / pwd / cat file.py"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "file_read",
     "description": "读取文件内容", "parameters": {"type": "object",
     "properties": {"path": {"type": "string", "description": "文件路径"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "file_write",
     "description": "写入/覆盖文件（执行层自动快照）", "parameters": {"type": "object",
     "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
     "required": ["path", "content"]}}},
    {"type": "function", "function": {"name": "file_delete",
     "description": "删除文件（执行层自动快照）", "parameters": {"type": "object",
     "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "file_move",
     "description": "移动/重命名文件", "parameters": {"type": "object",
     "properties": {"source": {"type": "string"}, "dest": {"type": "string"}},
     "required": ["source", "dest"]}}},
    {"type": "function", "function": {"name": "terminal_exec",
     "description": "执行修改性 shell 命令（写入权限，自动快照）", "parameters": {"type": "object",
     "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "code_execute",
     "description": "在受限沙盒中执行 Python 代码（禁止 os/subprocess/socket 等危险调用）",
     "parameters": {"type": "object", "properties": {"language": {"type": "string"},
     "code": {"type": "string"}}, "required": ["language", "code"]}}},
    {"type": "function", "function": {"name": "search",
     "description": "联网搜索（DuckDuckGo/Bing，无需 API Key）", "parameters": {"type": "object",
     "properties": {"query": {"type": "string"}, "top_k": {"type": "integer"}},
     "required": ["query"]}}},
    {"type": "function", "function": {"name": "math_calc",
     "description": "纯算术表达式求值（白名单 AST，无副作用）", "parameters": {"type": "object",
     "properties": {"expression": {"type": "string"}}, "required": ["expression"]}}},
    {"type": "function", "function": {"name": "datetime_now",
     "description": "获取当前时间", "parameters": {"type": "object",
     "properties": {"format": {"type": "string"}}}}},
    {"type": "function", "function": {"name": "api_get",
     "description": "GET 请求获取数据（自动拦截内网/SSRF）", "parameters": {"type": "object",
     "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "api_post",
     "description": "POST 请求提交数据", "parameters": {"type": "object",
     "properties": {"url": {"type": "string"}, "data": {"type": "object"}},
     "required": ["url"]}}},
    {"type": "function", "function": {"name": "db_query",
     "description": "SQLite 只读查询（仅 SELECT/WITH，最多 100 行）", "parameters": {"type": "object",
     "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "db_write",
     "description": "SQLite 写入（INSERT/UPDATE/DELETE/CREATE/ALTER，拒绝 DROP 等）",
     "parameters": {"type": "object", "properties": {"query": {"type": "string"}},
     "required": ["query"]}}},
    {"type": "function", "function": {"name": "browser_open",
     "description": "用系统默认浏览器打开 http/https 链接", "parameters": {"type": "object",
     "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "browser_screenshot",
     "description": "截取屏幕画面保存到 .ace_shots/（需 pillow，Windows 可免依赖）",
     "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "notify_send",
     "description": "发送通知（console/file/toast）", "parameters": {"type": "object",
     "properties": {"channel": {"type": "string"}, "to": {"type": "string"},
     "content": {"type": "string"}}, "required": ["channel", "content"]}}},
    {"type": "function", "function": {"name": "image_generate",
     "description": "生成图片保存到 .ace_images/（pollinations.ai 免费）", "parameters": {"type": "object",
     "properties": {"prompt": {"type": "string"}, "size": {"type": "string"}},
     "required": ["prompt"]}}},
    {"type": "function", "function": {"name": "parse_document",
     "description": "解析 Word/Excel/PPT/PDF/图片/文本并提取内容", "parameters": {"type": "object",
     "properties": {"path": {"type": "string"}, "force_ocr": {"type": "boolean"}},
     "required": ["path"]}}},
    {"type": "function", "function": {"name": "open_file",
     "description": "生成可点击文件链接（用户点击后打开）", "parameters": {"type": "object",
     "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "edit_file",
     "description": "用 VS Code 或系统默认编辑器打开文件", "parameters": {"type": "object",
     "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "plan_propose",
     "description": "复杂任务先输出分步计划，等待用户批准后再执行",
     "parameters": {"type": "object", "properties": {"title": {"type": "string"},
     "steps": {"type": "array", "items": {"type": "string"}}},
     "required": ["steps"]}}},
    {"type": "function", "function": {"name": "request_permission",
     "description": "请求用户临时授权某个工具（如被 403 拦截的写入/高权限操作）",
     "parameters": {"type": "object", "properties": {"target": {"type": "string"},
     "reason": {"type": "string"}},
     "required": ["target"]}}},
]

TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


def tool_calls_to_protocol(tool_calls: List[Dict]) -> str:
    """把原生工具调用转换为 <INTERNAL>/<EXTERNAL> 协议文本，复用执行层同一代码路径"""
    if not tool_calls:
        return ""
    tc = tool_calls[0]
    fn = tc.get("function") or {}
    name = fn.get("name", "")
    raw_args = fn.get("arguments")
    if isinstance(raw_args, dict):
        args = raw_args
    else:
        try:
            args = json.loads(raw_args or "{}")
        except (json.JSONDecodeError, TypeError):
            # 模型可能把 Windows 绝对路径写进 arguments 字符串（C:\Users → \U 非法转义）
            try:
                args = json.loads(repair_backslash_json(raw_args or "{}"))
            except (json.JSONDecodeError, TypeError):
                args = {}
    # 兼容部分端点直接把 name/arguments 放在顶层
    if not name:
        name = tc.get("name", "")
    if not args and isinstance(tc.get("arguments"), dict):
        args = tc["arguments"]
    if not isinstance(args, dict):
        args = {}
    body = json.dumps({"tool": name, **args}, ensure_ascii=False)
    return (f"<INTERNAL>\n[INTERNAL_THINKING]\n"
            f"[ACT] 原生工具调用: {name}\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
            f"<EXTERNAL>\nanswer.\n{body}\n</EXTERNAL>")


def final_reply_protocol(content: str) -> str:
    """把模型无工具调用的纯文本回答包装为协议模式 B（最终回复）"""
    return (f"<INTERNAL>\n[INTERNAL_THINKING]\n"
            f"[REASON] 信息已足够，输出最终回复\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
            f"<EXTERNAL>\nanswer.\n{content.strip()}\n</EXTERNAL>")


def sanitize_plain_content(content: str) -> str:
    """tools 模式下模型偶尔输出思考标签/协议残片，清洗成纯文本。
    完整协议则提取 EXTERNAL 正文；思考块包裹正文时删除整块；
    若整段输出都是思考块（小模型把回答写进思考块），则取其内容作为回复。"""
    text = (content or "")
    m = re.search(r"<EXTERNAL>\s*(?:answer\.)?(.*?)</EXTERNAL>",
                  text, re.DOTALL | re.IGNORECASE)
    if m:
        text = m.group(1)
    # 捕获思考块正文（兼容缺失闭合括号，如 [INTERNAL_THINKING 无 ]）
    thinking_m = re.search(
        r"\[/?\s*INTERNAL_THINKING\s*\]?\s*(.*?)\s*\[/?\s*INTERNAL_THINKING\s*\]?",
        text, re.DOTALL | re.IGNORECASE)
    # 删除思考块（含内容）
    text = re.sub(
        r"\[/?\s*INTERNAL_THINKING\s*\]?.*?\[/?\s*INTERNAL_THINKING\s*\]?",
        "", text, flags=re.DOTALL | re.IGNORECASE)
    # 删除残留标签与状态标签
    text = re.sub(r"\[?/?\s*INTERNAL_THINKING\s*\]?", "", text, flags=re.IGNORECASE)
    for label in ("PLAN", "REASON", "ACT", "OBSERVE", "REPLAN", "CHECK",
                  "EXPLORE", "DESIGN", "REVIEW", "FINALIZE", "EXECUTE"):
        text = re.sub(rf"\[{label}\]", "", text, flags=re.IGNORECASE)
    text = re.sub(r"</?INTERNAL\s*>?", "", text, flags=re.IGNORECASE)
    text = re.sub(r"</?EXTERNAL\s*>?", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^\s*answer\.\s*", "", text)
    cleaned = text.strip()
    if not cleaned and thinking_m and thinking_m.group(1).strip():
        cleaned = thinking_m.group(1).strip()
    return cleaned


def _extract_json_objects(text: str) -> List[str]:
    """从文本中提取所有最外层完整平衡的 {...} JSON 对象片段。
    正确处理字符串内的花括号/转义/```围栏，防止模型把 markdown 围栏
    嵌进 JSON 字符串（如 plan 步骤里带 ```python 代码）时提取错乱。"""
    objs: List[str] = []
    n = len(text)
    i = 0
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        in_str = False
        esc = False
        start = i
        j = i
        while j < n:
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        objs.append(text[start:j + 1])
                        i = j
                        break
            j += 1
        i += 1
    return objs


def content_to_tool_protocol(content: str) -> str:
    """部分本地模型（如 Ollama 上的 Qwen）把工具调用写成 JSON 文本而非结构化 tool_calls。
    识别两种文本 schema：项目自有 {"tool": ...} 与 Ollama 原生 {"name", "arguments"}；
    从 ``` 围栏块 + 平衡花括号扫描中提取候选并逐个尝试；
    只转换已注册的工具名，防止误伤正常 JSON 回答。"""

    def _convert(obj: dict) -> str:
        if not isinstance(obj, dict):
            return ""
        if isinstance(obj.get("tool"), str) and obj["tool"].strip() in TOOL_NAMES:
            extra = {k: v for k, v in obj.items() if k != "tool"}
            return tool_calls_to_protocol([
                {"function": {"name": obj["tool"],
                              "arguments": json.dumps(extra, ensure_ascii=False)}}])
        name = obj.get("name")
        args = obj.get("arguments")
        if (isinstance(name, str) and name.strip() in TOOL_NAMES
                and isinstance(args, dict)):
            return tool_calls_to_protocol([
                {"function": {"name": name,
                              "arguments": json.dumps(args, ensure_ascii=False)}}])
        return ""

    text = (content or "").strip()
    candidates: List[str] = []
    if "```" in text:
        for m in re.finditer(r"```[a-zA-Z0-9_+-]*\s*(.*?)```", text, re.DOTALL):
            candidates.append(m.group(1).strip())
    else:
        candidates.append(text)
    # 增强：平衡花括号扫描，防嵌套围栏/正文干扰导致漏识别
    for obj in _extract_json_objects(text):
        candidates.append(obj)
    for cand in candidates:
        if not cand.startswith("{"):
            continue
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            # Windows 绝对路径（C:\Users → \U 非法转义）会导致解析失败，修复后重试
            try:
                obj = json.loads(repair_backslash_json(cand))
            except json.JSONDecodeError:
                continue
        converted = _convert(obj)
        if converted:
            return converted
    return ""


class ModelProvider:
    """L3 模型接入：mock（离线演示）或 OpenAI 兼容 API"""

    def __init__(self, args) -> None:
        self.mode = "mock" if args.mock else "api"
        self.base_url = args.base_url or os.environ.get("AGENT_BASE_URL")
        self.api_key = args.api_key or os.environ.get("AGENT_API_KEY")
        self.model = args.model or os.environ.get("AGENT_MODEL") or "default"
        self.tools = bool(getattr(args, "tools", False))             # 原生工具调用开关
        self.max_history = int(getattr(args, "max_history", 0) or 0)  # 0 = 不裁剪
        self.tools_ok = self.tools                                   # 端点不支持时自动降级
        # 把真实工作目录注入系统提示词，防止小模型臆造路径
        project_root = str(getattr(args, "project_root", "."))
        self.system_suffix = (f"\n\n【工作目录】{os.path.abspath(project_root)}\n"
                              f"文件操作请使用该目录下的相对路径或该绝对路径，不要臆造路径。")
        self.history: List[Dict[str, str]] = []
        self.mock_step = 0
        self.mock_tool_result: Optional[str] = None

    # ---------- 脚本化假模型（离线演示完整循环） ----------

    def generate_mock(self, prompt: str) -> str:
        self.mock_step += 1
        if self.mock_step == 1:
            # 第一轮：输出工具调用
            return (
                "<INTERNAL>\n[INTERNAL_THINKING]\n"
                "[PLAN] 演示：查询当前时间\n"
                "[REASON] datetime_now 可以直接获取时间\n"
                "[ACT] 调用 datetime_now\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
                "<EXTERNAL>\nanswer.\n"
                '{"tool":"datetime_now","format":"YYYY-MM-DD HH:mm:ss"}\n</EXTERNAL>'
            )
        # 第二轮：基于工具结果的最终回复
        result_text = self.mock_tool_result or "(未知)"
        return (
            "<INTERNAL>\n[INTERNAL_THINKING]\n"
            "[OBSERVE] 工具执行成功，拿到时间\n"
            "[REASON] 信息已足够，输出最终回复\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
            f"<EXTERNAL>\nanswer.\n当前时间是 {result_text}\n</EXTERNAL>"
        )

    # ---------- 真实模型 ----------

    def generate(self, prompt: str) -> str:
        if self.mode == "mock":
            return self.generate_mock(prompt)
        if not self.base_url:
            raise RuntimeError(
                "未配置模型：请使用 --mock 离线演示，或提供 --base-url/--api-key"
                "（或环境变量 AGENT_BASE_URL / AGENT_API_KEY / AGENT_MODEL）")
        if self.tools_ok:
            try:
                return self._generate_tools(prompt)
            except ToolsUnsupported:
                # 端点不支持原生工具调用 → 本次自动降级，并永久关闭 tools 避免反复失败
                self.tools_ok = False
        return self._generate_text(prompt)

    def _generate_tools(self, prompt: str) -> str:
        """原生工具调用：模型返回结构化 tool_calls，由执行层统一裁决执行"""
        logger.debug("LLM 请求 model=%s tools=on", self.model)
        messages = ([{"role": "system",
                      "content": load_system_prompt(tools_mode=True) + self.system_suffix}]
                    + self.history + [{"role": "user", "content": prompt}])
        try:
            data = _post_chat(self.base_url, self.api_key, self.model,
                              messages, tools=TOOLS)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="ignore").lower()
            except Exception:
                pass
            if e.code in (400, 404) and "tool" in body:
                raise ToolsUnsupported(f"端点不支持 tools 参数: HTTP {e.code}") from e
            raise
        message = data["choices"][0]["message"]
        tool_calls = message.get("tool_calls") or []
        if tool_calls:
            return tool_calls_to_protocol(tool_calls)
        content = message.get("content") or ""
        if content.strip():
            # 清洗模型残留的协议标签残片（如 </EXTERNAL>），避免污染解析
            content = sanitize_plain_content(content)
        converted = content_to_tool_protocol(content)
        if converted:
            return converted
        if not content.strip():
            raise RuntimeError("模型返回空内容")
        return final_reply_protocol(content)

    def _generate_text(self, prompt: str) -> str:
        """文本协议回退：模型按 <INTERNAL>/<EXTERNAL> 格式输出"""
        logger.debug("LLM 请求 model=%s tools=off", self.model)
        messages = ([{"role": "system",
                      "content": load_system_prompt() + self.system_suffix}]
                    + self.history + [{"role": "user", "content": prompt}])
        data = _post_chat(self.base_url, self.api_key, self.model, messages)
        return data["choices"][0]["message"]["content"]

    def _trim_history(self) -> None:
        """限制对话历史长度，防止本地小模型上下文溢出（保留最近 N 轮）"""
        if self.max_history <= 0:
            return
        max_msgs = self.max_history * 2
        if len(self.history) > max_msgs:
            self.history = self.history[-max_msgs:]


def render_result(r: Dict) -> str:
    """把执行层返回压缩成给模型看的文本（default=str 兜底 Path 等非 JSON 类型）"""
    keys = ("status", "message", "data", "tool", "instruction", "report",
            "bait_type", "baited_code", "rule", "memory_injected",
            "intent", "skills", "plan", "steps", "title", "reason")
    d = {k: r[k] for k in keys if k in r}
    return json.dumps(d, ensure_ascii=False, default=str)


# ============================================================
# 外部内容隔离（SEC-011）
# ============================================================
# 定界 + 来源标注的实现在 ace_isolation.py —— 那里不 import 项目内任何模块，
# 因为 execution_layer（记忆预注入）也要用它，而 execution_layer 不能反向依赖入口。


def render_tool_result(r: Dict) -> str:
    """给模型看的工具结果：序列化 + 隔离标记 + 来源标注"""
    tool = r.get("tool")
    return wrap_untrusted(render_result(r), source=untrusted_source(tool),
                          origin=f"tool:{tool}" if tool else "")


# ============================================================
# metadata 的"只给人"渲染通道
# ============================================================
# 三份受众已经拆开了（`message` 给模型、确认框给人、`metadata` 给日志/UI），
# 但 `metadata` 一直没有"给人"的出口：脱敏之后终端上只剩一句
# "代码分析失败（PermissionError）"，而"哪个文件、系统说了什么"全躺在 metadata 里
# 没人读。信息没丢，受众错了 —— 这比脱敏之前更糟，以前至少人能看到。
#
# 这条通道刻意**不**从 payload 走：`execution_layer` 的错误 payload 没有
# `metadata` 键、`render_result` 的白名单也不含它，这两道是 metadata 能装完整
# 绝对路径的全部前提。往任何一处加键，都会让下一次改动有机会把它喂回模型。
# 所以细节从上游的 `el.executor.execute()` 旁路取 —— 那里手上还是完整的
# `ExecutionResult`，而取到的东西只用于打印和日志，永不回填 payload。


class ExecutionDetailTap:
    """在 `el.executor.execute` 外面包一层，把每轮的 `metadata` 留在旁路。

    为什么 `take()` 取走即清空：这一份是"本轮"的细节。留着的话，第 3 轮的 500
    会把第 2 轮那个文件的路径打给用户 —— 指错文件比什么都不指更糟，人会照着
    错的位置查下去。

    单线程假设：两个入口都是"一轮模型、一轮执行"的串行循环，所以一个待取槽位
    够用。真要并发跑工具时这里必须换成按调用标识的映射，否则两轮的细节会互相覆盖。
    """

    def __init__(self) -> None:
        self._pending: Dict = {}

    def install(self, el) -> None:
        """幂等安装。重复包一层会让同一份 metadata 被记两次、且每次重建执行层
        （/clear、/permission 切换）都多叠一层调用栈。"""
        executor = getattr(el, "executor", None)
        if executor is None or getattr(executor, "_ace_detail_tapped", False):
            return
        original = executor.execute

        def execute(tool_call, *args, **kwargs):
            result = original(tool_call, *args, **kwargs)
            self._pending = dict(getattr(result, "metadata", None) or {})
            # 全文 json.dumps 只出现在这一处：那是**日志**要的形状（全字段、
            # 可 grep）。人在终端上要的是两句话，字段名对他没有意义。
            if self._pending:
                logger.debug(
                    "tool=%s metadata=%s",
                    tool_call.get("tool") if isinstance(tool_call, dict) else "?",
                    json.dumps(self._pending, ensure_ascii=False, default=str))
            return result

        executor.execute = execute
        executor._ace_detail_tapped = True

    def take(self) -> Dict:
        pending, self._pending = self._pending, {}
        return pending


# 两个入口共用一个实例：同一进程里只跑一个会话循环，各自持有反而要在
# ai_code 里再导一遍安装逻辑。
DETAIL_TAP = ExecutionDetailTap()

# metadata 的字段名是给日志的，对人没有意义。所以按"角色"取值而不是把 dict
# 整个倒出来：人只想知道哪个位置、系统说了什么。白名单式取值顺手挡住了
# `elapsed` / `policy` / `executor` 这些每轮都在、对排障无用的字段 ——
# 否则连成功轮都会多打一行噪音。
#
# `resolved` 排在 `target` 前面不是笔误：路径越界那一档里 `target` 存的是模型
# 原样传进来的参数（`../../etc/passwd`），`resolved` 才是它真正指向的那个位置。
# 人要的是后者 —— 前者他在上一行的报错里已经看见了。
_DETAIL_WHERE_FIELDS = (("denial", "resolved"), ("denial", "target"),
                        ("error", "target"), ("resolved_path",))
_DETAIL_WHAT_FIELDS = (("exception",), ("error", "detail"), ("parser_error",),
                       ("denial", "hook_error"))
_DETAIL_CATEGORY_FIELDS = (("denial", "category"),)

# 系统原话的单行上限。OSError / 第三方库的异常 str 能有几百字符，整段糊上去
# 会把上一行的真正错误顶出屏幕。
DETAIL_LINE_LIMIT = 200


def _detail_pick(detail: Dict, fields) -> str:
    """按字段路径取第一个非空字符串值；一个都没有就返回空串"""
    for path in fields:
        node = detail
        for seg in path:
            node = node.get(seg) if isinstance(node, dict) else None
            if node is None:
                break
        if isinstance(node, str) and node.strip():
            return node.strip()
    return ""


def _detail_clip(text: str, verbose: bool) -> str:
    """压成一行并按需截断。verbose 下不截 —— 那时人就是来看全文的。"""
    one_line = " ".join(str(text).split())
    if verbose or len(one_line) <= DETAIL_LINE_LIMIT:
        return one_line
    return one_line[:DETAIL_LINE_LIMIT] + "…"


def detail_is_default_visible(status: str) -> bool:
    """默认只对 5xx（ACE 自己坏了）展示细节。

    403 默认不展示，理由不是"细节不重要"，而是**受众已经看过了**：prompt 档的
    确认框刚刚把完整真实路径摆在人眼前，紧接着再糊一遍 metadata 就是重复。
    这个仓库反复踩的坑正是"确认框/拒绝提示变噪音之后，用户唯一的出路是关掉整个
    开关"—— 一旦拒绝提示变吵，被关掉的是安全闸门本身，代价远大于少两行细节。

    5xx 相反：它是意料之外的故障，人手上除了一个异常类型名什么都没有，
    不给位置等于让他去猜。而 5xx 本就罕见，展示它不构成噪音。
    """
    s = str(status or "")
    return len(s) == 3 and s.isdigit() and s[0] == "5"


def execution_detail_lines(detail: Optional[Dict], status: str = "",
                           *, verbose: Optional[bool] = None) -> List[str]:
    """把旁路细节渲染成给人看的若干行；没什么可说时返回空列表。

    `verbose=None` 时跟随现有日志等级（两个入口的 --verbose 都落到
    `logging.basicConfig(level=DEBUG)`），不另造开关 —— 多一个只服务这一处的
    flag，等于让用户为了看一行细节去记第二套开关。
    """
    if not isinstance(detail, dict) or not detail:
        return []
    if verbose is None:
        verbose = logger.isEnabledFor(logging.DEBUG)
    if not (verbose or detail_is_default_visible(status)):
        return []
    where = _detail_pick(detail, _DETAIL_WHERE_FIELDS)
    what = _detail_pick(detail, _DETAIL_WHAT_FIELDS)
    category = _detail_pick(detail, _DETAIL_CATEGORY_FIELDS)
    lines: List[str] = []
    if where:
        lines.append(t("detail_location", where=_detail_clip(where, verbose)))
    if what:
        lines.append(t("detail_system", what=_detail_clip(what, verbose)))
    # 类别只在展开时给：默认那两行回答的是"哪个文件 / 系统说了什么"，
    # 命中类别是排障第二步才用得上的东西，默认列出来只是多一行。
    if verbose and category:
        lines.append(t("detail_category", category=category))
    if lines and not verbose:
        # 默认档是摘要且可能被截断，必须告诉人全文在哪 —— 否则"截断"就变成了
        # 第二次信息丢失，而这一整条通道就是为了修第一次。
        lines.append(t("detail_more_hint"))
    return lines


def run_conversation(provider: ModelProvider, el: ExecutionLayer,
                     user_input: str, verbose: bool = False) -> None:
    print("\n" + t("runner_user_line", text=user_input))
    # 每次会话重置 mock 状态，防止跨会话串号
    provider.mock_step = 0
    provider.mock_tool_result = None
    # 记忆预注入：在模型生成之前把相关历史记忆放进 prompt（无记忆时原样返回）
    next_prompt = el.prepare_context(user_input)
    # 无进展熔断。这个入口原先完全没有，模型死循环时会把 MAX_ROUNDS 全部烧掉。
    stall = StallTracker()
    for round_no in range(1, MAX_ROUNDS + 1):
        try:
            output = provider.generate(next_prompt)
        except KeyboardInterrupt:
            print("\n" + t("interrupted"))
            return
        except Exception as e:
            # 复用 ai_code 的键：同一件事（模型调不通）两个入口必须是同一句话，
            # 各写一份文案就是下一次漂移的起点。
            print("\n" + t("model_call_failed", err=e))
            return
        if verbose:
            print(f"\n--- 第 {round_no} 轮模型输出 ---\n{output}")
        try:
            result = el.process_agent_output(output, user_input)
        except Exception as e:
            print("\n" + t("exec_layer_error", err=e))
            next_prompt = f"执行层抛出异常: {e}\n请调整输出格式后重新输出。"
            continue
        provider.history.append({"role": "user", "content": next_prompt})
        provider.history.append({"role": "assistant", "content": output})
        provider._trim_history()
        if verbose:
            print(f"\n--- 执行层返回 ---\n{json.dumps(result, ensure_ascii=False, indent=2)}")

        # metadata 的"只给人"通道。每轮都 take：取走即清空，不让本轮没细节时
        # 把上一轮的路径打出来。写 stderr 与审批提示同理 —— `ace > log.txt` 时
        # 若走 stdout，故障线索会全进日志文件，终端上什么都看不到。
        # `verbose or None`：显式 --verbose 直接展开，否则交给日志等级判断。
        for detail_line in execution_detail_lines(DETAIL_TAP.take(),
                                                  result.get("status", ""),
                                                  verbose=verbose or None):
            print(detail_line, file=sys.stderr)

        if stall.observe(result["status"], result.get("tool")):
            print("\n" + t("stall_abort", n=stall.streak))
            return

        if result["status"] == "PLAN_PROPOSED":
            # 计划正文优先取 `plan`；退到 message 时必须走展示层。
            # 直接写 result.get("message") 的话，闸门给的 message_key 在这个入口
            # 完全不生效 —— en/ja 界面下这一行会退回中文原文（本次修的就是它）。
            print(f"\n📋 {result.get('plan') or result_display_message(result)}")
            if sys.stdin.isatty():
                try:
                    answer = input(t("plan_approve_q")).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    answer = "n"
            else:
                # SEC-004：非交互模式下没有人可以确认，必须默认拒绝。
                # 这个入口曾写成 answer = "y"（ai_code.py 的同一处已修，这里被漏掉了）——
                # 于是 `echo "..." | python agent_runner.py --permission write` 会让
                # 模型自己提计划、自己获批、自己执行，整个审批环节形同不存在。
                # 注意同函数下方的权限申请分支一直是 "n"，两者本该同向。
                print(t("auto_deny_plan"))
                answer = "n"
            if answer in ("y", "yes"):
                el.approve_plan()
                print(t("plan_approved_msg"))
                next_prompt = ("计划已批准，不要再调用 plan_propose。"
                               "请直接按计划逐步执行，每步调用相应工具，最后给出总结。")
            else:
                el.reject_plan()
                print(t("plan_rejected_msg"))
                next_prompt = "用户拒绝了该计划，请调整方案或直接回答。"
            continue

        if result["status"] == "PLAN_ALREADY_APPROVED":
            next_prompt = ("计划已批准，不要再调用 plan_propose。"
                           "请直接按计划逐步执行，每步调用相应工具，最后给出总结。")
            continue

        if result["status"] == "PERMISSION_REQUEST":
            print("\n" + t("perm_request_title", tool=result.get("tool")))
            if result.get("reason"):
                print(t("perm_reason", reason=result["reason"]))
            if sys.stdin.isatty():
                try:
                    answer = input(t("perm_approve_q")).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    answer = "n"
            else:
                print(t("auto_deny_perm"))
                answer = "n"
            if answer in ("y", "yes"):
                el.grant_pending_permission()
                print(t("perm_granted_msg"))
                next_prompt = "用户已授权，请重试刚才被拦截的工具。"
            else:
                el.reject_pending_permission()
                print(t("perm_denied_msg"))
                next_prompt = "用户拒绝授权，请换一种不需要该工具的方式完成任务。"
            continue

        if result["status"] == "FINAL_REPLY":
            # 必须走 result_display_message：这里原来直接取 result['message']，
            # 于是展示层（message_key → 译文）在这个入口整个失效。
            print("\n" + t("runner_agent_reply", msg=result_display_message(result)))
            return

        if result["status"] in ("FORMAT_ERROR", "GUARD_VIOLATION",
                               "BAIT_TRIGGERED", "AST_FAILED", "403"):
            # 被挡了必须让人看见，否则终端上只是"什么都没发生"，用户无从判断
            # 该改需求还是该提权。文案与 ai_code 共用 `error_line` 一个键。
            print(t("error_line", status=result["status"],
                    msg=result_display_message(result)[:80]))
            # 把错误反馈给模型，让它修正后继续
            next_prompt = (
                f"执行层返回了错误，请修正后继续：\n{render_tool_result(result)}\n"
                f"注意：必须严格按 <INTERNAL>/<EXTERNAL> 格式输出。")
            continue

        # 工具执行成功：结果回填模型，继续下一轮
        if provider.mode == "mock" and result["status"] == "SUCCESS":
            data = result.get("data") or {}
            provider.mock_tool_result = data.get("datetime") or json.dumps(data, ensure_ascii=False)
        next_prompt = (f"工具执行结果：\n{render_tool_result(result)}\n"
                       f"请根据结果继续（输出下一条工具调用，或最终回复）。")
    print("\n" + t("max_rounds"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent 交互循环（LLM + 执行层）")
    parser.add_argument("--mock", action="store_true", help="使用脚本化假模型，离线演示")
    parser.add_argument("--base-url", help="OpenAI 兼容 API 地址")
    parser.add_argument("--api-key", help="API Key")
    parser.add_argument("--model", help="模型名")
    parser.add_argument("--project-root", default=".", help="Agent 工作目录")
    # SEC-002：默认 readonly（原为 write）。WRITE_TOOLS 含 terminal_exec / file_delete /
    # code_execute，默认给写权限等于默认放开最危险的三个工具。写权限需显式声明。
    parser.add_argument("--permission", default="readonly", choices=["readonly", "write", "full"])
    parser.add_argument("--no-bait", action="store_true", help="关闭诱饵验证")
    parser.add_argument("--verbose", action="store_true", help="打印每轮原始输出")
    parser.add_argument("--tools", action="store_true",
                        help="使用原生工具调用（OpenAI 兼容 function calling，端点不支持时自动降级）")
    parser.add_argument("--max-history", type=int, default=0,
                        help="保留最近 N 轮对话历史（0 = 不裁剪）")
    parser.add_argument("--input", help="直接传入一条用户消息（非交互模式）")
    # 界面语言。这个入口没有配置文件（ai_code 从 ~/.ai_code.json 读 lang），
    # 所以只能由命令行/环境变量给；不给就是 zh。没有这个开关的话，t() 接得再全，
    # en/ja 用户也永远看不到译文 —— 展示层会变成只有测试才走到的死代码。
    parser.add_argument("--lang", default="",
                        help="界面语言 zh|en|ja（默认取环境变量 ACE_LANG，再默认 zh）")
    args = parser.parse_args()

    # 非法值静默回落 zh 而不是报错退出：界面语言拼错不该让整个 CLI 起不来，
    # 而 argparse 的 choices 对 ACE_LANG 这种外部输入正是那种失败方式。
    _lang = (args.lang or os.environ.get("ACE_LANG") or "").strip().lower()
    if _lang in SUPPORTED_LANGS:
        set_language(_lang)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    provider = ModelProvider(args)
    el = ExecutionLayer(
        project_root=args.project_root,
        permission_level=args.permission,
        config={"bait": {"enabled": not args.no_bait, "frequency": 0},
                "sandbox_base": str(Path(args.project_root).resolve() / ".sandbox_tmp"),
                # 同 ai_code.py：prompt 档命令需要人来点头，非 TTY 时 hook 自己会拒。
                "approval_hook": make_cli_approval_hook()},
    )
    # 打开 metadata 的"只给人"通道。不装的话 500 在终端上就只剩一个异常类型名，
    # 位置与系统原话烂在 metadata 里 —— 那是这条通道要修的缺口本身。
    DETAIL_TAP.install(el)
    print(t("runner_banner", mode=provider.mode, perm=args.permission,
            root=args.project_root,
            tools=t("runner_tools_on") if provider.tools else t("runner_tools_off")))
    # SEC-010：签名没生效必须让人看见。这个入口没有配置文件，密钥来自
    # ACE_SIGNING_KEY 或自动生成的密钥文件，两条都可能失败（主目录不可写等）。
    # 警告正文由 execution_layer 生成（固定中文，产生方不在本轮改动范围），
    # 这里只加前缀 —— 不套 t() 是因为没有任何本文件自己的文案可翻。
    if getattr(el, "signing_key_warning", ""):
        print(f"⚠ {el.signing_key_warning}")
    if args.permission != "readonly":
        print(t("runner_warn_write"))
    stats = el.get_stats()
    print(t("status_modules", v2=stats["v2_gateway"], v1=stats["v1_modules"],
            parser=stats["parser"]))

    if args.input:
        run_conversation(provider, el, args.input, args.verbose)
        return
    print(t("runner_hint"))
    while True:
        try:
            user_input = input(t("runner_prompt")).strip()
        except (EOFError, KeyboardInterrupt):
            break
        if user_input.lower() in ("exit", "quit", "退出"):
            break
        if not user_input:
            continue
        run_conversation(provider, el, user_input, args.verbose)


if __name__ == "__main__":
    main()
