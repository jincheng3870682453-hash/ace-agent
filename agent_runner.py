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
import ace_http  # noqa: E402
from tools.base import repair_backslash_json  # noqa: E402
from tools.registry import openai_tools  # noqa: E402


PROMPT_DIR = FOLDER / "prompts"
SYSTEM_PROMPT_PATH = PROMPT_DIR / "agent_system_prompt_v7.md"
SYSTEM_PROMPT_V8_PATH = PROMPT_DIR / "agent_system_prompt_v8.md"
SYSTEM_PROMPT_TOOLS_PATH = PROMPT_DIR / "agent_system_prompt_tools.md"
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


def retry_notice(decision, attempt: int) -> None:
    """把 ace_http 的退避决定告诉用户。ai_code 也用这一份。

    必须写 stderr：ai_code 那边 stdout 正被流式渲染器（打字机效果 / 状态行）占着，
    往里插一行会把画面搅乱。而完全不提示更糟 —— 一次 429 带 Retry-After: 30 的退避，
    在用户看来和卡死没有区别，他会去按 Ctrl-C。
    """
    src = "服务端指定" if decision.source == "retry_after" else "退避"
    print(f"\n  ⏳ 第 {attempt} 次请求失败，{src} {decision.delay:.1f}s 后重试"
          f"（{decision.reason}）", file=sys.stderr, flush=True)


def _post_chat(base_url: str, api_key: str, model: str, messages: List[Dict],
               tools: Optional[List[Dict]] = None, timeout: int = 120) -> Dict:
    """OpenAI 兼容 /chat/completions（纯标准库 urllib，无 requests 依赖）

    429 / 5xx / 连接抖动由 ace_http 退避重试；4xx 原样抛 urllib.error.HTTPError，
    _generate_tools 的 tools 降级判断（读 e.read() 里的错误正文）因此还能照常工作 ——
    ace_http 只碰 e.headers 取 Retry-After，不会把响应体读掉。
    """
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
    return ace_http.urlopen_json_with_retry(req, timeout=timeout,
                                            on_retry=retry_notice)


# ============================================================
# 原生工具调用（OpenAI 兼容 function calling，Ollama/Qwen 等均支持）
# ============================================================

TOOLS = openai_tools()  # 由 tools/registry.py 的 TOOL_SPECS 派生，勿在此手写工具


def tools_for_permission(level: str) -> List[Dict]:
    """按权限等级裁剪发给模型的工具列表。

    理由：把全部工具直接发给 7B 小模型是认知超载（数量随 registry 增长）（记不住参数、乱选工具的根源），
    而 readonly 权限下写工具反正会被执行层 403 —— 让模型"看得见但用不了"
    只会诱导它去申请权限。按等级裁剪后模型只在真实可用的工具里决策。
    控制类工具（plan_propose / request_permission）任何等级都保留。
    """
    from execution_layer import (CONTROL_TOOLS, HIGH_RISK_TOOLS,
                                 READ_TOOLS, WRITE_TOOLS)
    level = (level or "readonly").lower()
    if level == "full":
        allowed = READ_TOOLS | WRITE_TOOLS | HIGH_RISK_TOOLS | CONTROL_TOOLS
    elif level == "write":
        allowed = READ_TOOLS | WRITE_TOOLS | CONTROL_TOOLS
    else:
        allowed = READ_TOOLS | CONTROL_TOOLS
    return [t for t in TOOLS if t["function"]["name"] in allowed]



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


# 模型"声称已完成写操作"的措辞。只匹配完成态（已…/…了/created/has been），
# 不匹配"我将要创建"这类意图陈述，否则正常的计划说明会被误判。
_CLAIM_DONE_RE = re.compile(
    r"已(?:经)?(?:为你|帮你|在)?[^。\n]{0,12}?"
    r"(?:创建|建立|新建|写入|保存|生成|修改|更新|删除|移动|重命名|执行)"
    r"|(?:创建|写入|保存|生成|修改|删除|执行)(?:好|完)了"
    r"|文件已(?:经)?(?:成功)?(?:创建|保存|生成|写入|修改|删除)"
    r"|(?:created|wrote|saved|generated|deleted|updated|executed)\s+(?:the\s+)?file"
    r"|file\s+(?:has\s+been|was)\s+(?:created|written|saved|updated|deleted)"
    r"|I(?:'ve|\s+have)\s+(?:created|written|saved|updated|deleted|executed)",
    re.IGNORECASE)


def claims_completed_action(content: str) -> bool:
    """模型是否在"没有调用任何工具"的前提下声称自己完成了文件/命令操作。

    这是本项目见过的最有害的失败模式：小模型（或被端点吞掉了 tool_calls 的情况）
    回一句"我已经帮你在桌面创建了 example.py"，final_reply_protocol 无条件把它
    包成模式 B，执行层判 FINAL_REPLY，CLI 打绿色的"✓ 完成（1 轮）"然后退出——
    用户以为成功了，桌面上什么都没有。零工具调用 + 完成态措辞 = 必须拦。

    只做措辞检测、不做语义判断：宁可偶尔多问模型一轮，也不能把幻觉当成功。
    """
    return bool(_CLAIM_DONE_RE.search(content or ""))



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
        # 按权限等级裁剪发给模型的工具列表（readonly 只给只读+控制工具）
        self.permission_level = getattr(args, "permission", "readonly") or "readonly"
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
                              messages, tools=tools_for_permission(self.permission_level))
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
#
# 分成两个函数而不是直接改 render_result：render_result 还被人类可读的展示通道
# 和测试用，往里塞隔离块会把"给模型看"和"给人看"两件事又搅在一起。


def truncate_tool_output(text: str, *, head_chars: int = 4000,
                         tail_chars: int = 2000, max_chars: int = 8000) -> str:
    """工具结果的确定性头/尾裁剪（借鉴 DSH compaction-tool-result-pruner）。

    超大工具输出（如 terminal_exec 的整页日志）直接塞进上下文会挤爆窗口；
    这里保留头部 + 尾部 + 中间替换为标记，**同输入必同输出**（纯函数、可重放
    验证），不调用模型。Python str 按码点索引，天然不会切破代理对。
    """
    if len(text) <= max_chars:
        return text
    head = text[:head_chars]
    tail = text[-tail_chars:] if tail_chars else ""
    cut = len(text) - head_chars - (tail_chars or 0)
    # 裁剪标记跟随界面语言（i18n 全局切换）
    from i18n import t as _t
    return (f"{head}\n…[{_t('trunc_hint', cut=cut, total=len(text))}]\n{tail}")


def render_tool_result(r: Dict) -> str:
    """给模型看的工具结果：序列化 + 隔离标记 + 来源标注（超大输出确定性裁剪）"""
    tool = r.get("tool")
    body = truncate_tool_output(render_result(r))
    return wrap_untrusted(body, source=untrusted_source(tool),
                          origin=f"tool:{tool}" if tool else "")



# ============================================================
# 会话状态机（run_conversation 与 ai_code.AgentCLI.converse 共用）
#
# 两个前端的呈现层差别很大（一个 emoji 直打，一个 i18n + spinner + 流式），
# 但「执行层返回什么状态 → 下一轮该喂模型什么 / 该问用户什么」是同一套规则。
# 这套规则以前在两处各写一份，已经漂移出真实后果：agent_runner 在非交互模式下
# 自动批准计划（answer="y"），而 CLI 侧是 fail-close 拒绝——同一个二进制里
# 两种安全口径。所以这里只抽「决策」，不抽「渲染」。
# ============================================================

PROMPT_PLAN_APPROVED = ("计划已批准，不要再调用 plan_propose。"
                        "请直接按计划逐步执行，每步调用相应工具，最后给出总结。")
PROMPT_PLAN_REJECTED = "用户拒绝了该计划，请调整方案或直接回答。"
PROMPT_PERM_GRANTED = "用户已授权，请重试刚才被拦截的工具。"
PROMPT_PERM_DENIED = "用户拒绝授权，请换一种不需要该工具的方式完成任务。"
PROMPT_EXEC_EXCEPTION = "执行层抛出异常: {err}\n请调整输出格式后重新输出。"
PROMPT_ERROR_RETRY = ("执行层返回了错误，请修正后继续：\n{rendered}\n"
                      "注意：必须严格按 <INTERNAL>/<EXTERNAL> 格式输出。")
PROMPT_TOOL_RESULT = ("工具执行结果：\n{rendered}\n"
                      "请根据结果继续（输出下一条工具调用，或最终回复）。")
PROMPT_UNVERIFIED_CLAIM = (
    "停。你刚才声称已经完成了文件/命令操作，但这一轮你没有调用任何工具，"
    "所以系统里什么都没有发生——文件不存在，命令没执行。\n"
    "二选一：\n"
    "1) 如果确实要做，现在就调用对应工具真正执行（新建文件用 file_write，"
    "改已有文件用 str_replace，跑命令用 terminal_exec）；\n"
    "2) 如果不需要执行，重写你的回答，去掉「已创建 / 已保存 / 已执行」这类说法，"

    "改成如实描述。\n"
    "不要再向用户索要确认——权限审批由执行层负责，不是你的职责。")


# 需要回喂模型让它自行修正的错误态
ERROR_STATUSES = ("FORMAT_ERROR", "GUARD_VIOLATION", "BAIT_TRIGGERED",
                  "AST_FAILED", "403", "TOOL_BANNED")

# 授权决策三态
GRANT_ONCE = "once"
GRANT_SESSION = "session"
GRANT_DENY = "deny"


def ask_yes_no(question: str, on_auto_deny=None) -> bool:
    """y/N 确认；非交互（管道 / CI / 无 tty）一律判否。

    fail-close 是这里唯一正确的默认：没人能点头时自动批准，等于把审批环节
    变成空过场。计划审批与临时授权都必须走这一个入口。
    """
    if not sys.stdin.isatty():
        if on_auto_deny is not None:
            on_auto_deny()
        return False
    try:
        return input(question).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def ask_grant(question: str, on_auto_deny=None) -> str:
    """授权三态确认：y 本次 / a 本会话 / 其他一律拒绝。

    默认权限是 readonly，而临时授权用后即焚——如果只有"本次"一个选项，
    一个 10 处编辑的任务就要弹 10 次窗、多跑 10 轮模型。"本会话"这一档是
    为了让这个默认可用，而不是逼用户直接把等级升到 write 了事。
    非交互同样 fail-close。
    """
    if not sys.stdin.isatty():
        if on_auto_deny is not None:
            on_auto_deny()
        return GRANT_DENY
    try:
        answer = input(question).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return GRANT_DENY
    if answer in ("a", "all", "always", "session"):
        return GRANT_SESSION
    if answer in ("y", "yes"):
        return GRANT_ONCE
    return GRANT_DENY


def resolve_plan(el: "ExecutionLayer", approved: bool) -> str:
    """落定计划审批结果，返回下一轮要喂给模型的提示"""
    if approved:
        el.approve_plan()
        return PROMPT_PLAN_APPROVED
    el.reject_plan()
    return PROMPT_PLAN_REJECTED


def resolve_permission(el: "ExecutionLayer", decision: str) -> str:
    """落定授权结果（once / session / deny），返回下一轮要喂给模型的提示"""
    if decision in (GRANT_ONCE, GRANT_SESSION):
        el.grant_pending_permission(session=decision == GRANT_SESSION)
        return PROMPT_PERM_GRANTED
    el.reject_pending_permission()
    return PROMPT_PERM_DENIED




def run_conversation(provider: ModelProvider, el: ExecutionLayer,
                     user_input: str, verbose: bool = False) -> None:
    print(f"\n🧑 用户: {user_input}")
    # 每次会话重置 mock 状态，防止跨会话串号
    provider.mock_step = 0
    provider.mock_tool_result = None
    # 记忆预注入：在模型生成之前把相关历史记忆放进 prompt（无记忆时原样返回）
    next_prompt = el.prepare_context(user_input)
    for round_no in range(1, MAX_ROUNDS + 1):
        try:
            output = provider.generate(next_prompt)
        except KeyboardInterrupt:
            print("\n已中断")
            return
        except Exception as e:
            print(f"\n⚠ 模型调用失败: {e}")
            return
        if verbose:
            print(f"\n--- 第 {round_no} 轮模型输出 ---\n{output}")
        try:
            result = el.process_agent_output(output, user_input)
        except Exception as e:
            print(f"\n⚠ 执行层异常: {e}（已要求模型调整输出格式）")
            next_prompt = PROMPT_EXEC_EXCEPTION.format(err=e)
            continue
        provider.history.append({"role": "user", "content": next_prompt})
        provider.history.append({"role": "assistant", "content": output})
        provider._trim_history()
        if verbose:
            print(f"\n--- 执行层返回 ---\n{json.dumps(result, ensure_ascii=False, indent=2)}")

        if result["status"] == "PLAN_PROPOSED":
            print(f"\n📋 {result.get('plan') or result.get('message', '')}")
            next_prompt = resolve_plan(el, ask_yes_no(
                "  批准该计划并执行？[y/N]: ",
                lambda: print("  非交互模式：自动拒绝计划。")))
            continue

        if result["status"] == "PLAN_ALREADY_APPROVED":
            next_prompt = PROMPT_PLAN_APPROVED
            continue

        if result["status"] == "PERMISSION_REQUEST":
            print(f"\n🔑 Agent 请求临时授权工具: {result.get('tool')}")
            if result.get("reason"):
                print(f"   原因: {result['reason']}")
            next_prompt = resolve_permission(el, ask_grant(
                "  是否授权？[y 本次 / a 本会话 / N 拒绝]: ",
                lambda: print("  非交互模式：自动拒绝授权。")))
            continue

        if result["status"] == "FINAL_REPLY":
            print(f"\n🤖 Agent: {result['message']}")
            return

        if result["status"] in ERROR_STATUSES:
            # 把错误反馈给模型，让它修正后继续
            next_prompt = PROMPT_ERROR_RETRY.format(rendered=render_tool_result(result))
            continue

        # 工具执行成功：结果回填模型，继续下一轮
        if provider.mode == "mock" and result["status"] == "SUCCESS":
            data = result.get("data") or {}
            provider.mock_tool_result = data.get("datetime") or json.dumps(data, ensure_ascii=False)
        next_prompt = PROMPT_TOOL_RESULT.format(rendered=render_tool_result(result))
    print("\n⚠️ 达到最大轮数，Agent 未给出最终回复。")



def main() -> None:
    parser = argparse.ArgumentParser(description="Agent 交互循环（LLM + 执行层）")
    parser.add_argument("--mock", action="store_true", help="使用脚本化假模型，离线演示")
    parser.add_argument("--base-url", help="OpenAI 兼容 API 地址")
    parser.add_argument("--api-key", help="API Key")
    parser.add_argument("--model", help="模型名")
    parser.add_argument("--project-root", default=".", help="Agent 工作目录")
    parser.add_argument("--permission", default="readonly", choices=["readonly", "write", "full"])
    parser.add_argument("--no-bait", action="store_true", help="关闭诱饵验证")
    parser.add_argument("--verbose", action="store_true", help="打印每轮原始输出")
    parser.add_argument("--tools", action="store_true",
                        help="使用原生工具调用（OpenAI 兼容 function calling，端点不支持时自动降级）")
    parser.add_argument("--max-history", type=int, default=0,
                        help="保留最近 N 轮对话历史（0 = 不裁剪）")
    parser.add_argument("--input", help="直接传入一条用户消息（非交互模式）")
    # 与 ai_code.py 的 --sandbox 同一套档位。之前这里只有 sandbox_base（沙箱临时目录），
    # 没有档位开关 —— 也就是说从这个入口进来永远是 off 档，用户以为两个前端一致，
    # 实际上没有任何边界。档位不一致比没有档位更糟：它是个错误的心理预期。
    parser.add_argument("--sandbox", default="off", choices=["off", "job", "docker"],
                        help="执行位置档位：off=宿主直跑 / job=Job Object / docker=一次性容器")
    parser.add_argument("--egress-allowlist", default="",
                        help="出站域名白名单，逗号分隔（缺省 = 闸门关闭）")
    args = parser.parse_args()


    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    provider = ModelProvider(args)
    _egress = [s.strip() for s in (args.egress_allowlist or "").split(",") if s.strip()]
    el = ExecutionLayer(
        project_root=args.project_root,
        permission_level=args.permission,
        config={"bait": {"enabled": not args.no_bait, "frequency": 0},
                "sandbox": {"mode": args.sandbox},
                # 没给 --egress-allowlist 时传 None（闸门关），而不是空列表 ——
                # 空列表的含义是"配了，但除内置端点外全拦"，两者不能混。
                "egress_allowlist": _egress or None,
                "sandbox_base": str(Path(args.project_root).resolve() / ".sandbox_tmp")},
    )
    print(f"Agent 已启动 | 模型: {provider.mode} | 权限: {args.permission} | "
          f"沙箱: {args.sandbox} | "
          f"工作目录: {args.project_root} | 原生工具: {'开' if provider.tools else '关'}")

    if args.permission != "readonly":
        print("⚠ 当前为写权限：terminal_exec 可执行任意 shell 命令。生产环境建议 readonly 起步。")
    stats = el.get_stats()
    print(f"模块状态: v2_gateway={stats['v2_gateway']} v1={stats['v1_modules']} parser={stats['parser']}")

    if args.input:
        run_conversation(provider, el, args.input, args.verbose)
        return
    print("输入消息开始对话，输入 exit / quit 退出。")
    while True:
        try:
            user_input = input("你: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if user_input.lower() in ("exit", "quit", "退出"):
            break
        if not user_input:
            continue
        run_conversation(provider, el, user_input, args.verbose)


if __name__ == "__main__":
    main()
