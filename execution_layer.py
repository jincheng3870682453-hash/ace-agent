#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
execution_layer.py —— Agent 执行层（完整版）

串联 Word 体系 V1+V2：
  · gateway_v2.py  → L1-L5 五层网关
  · work.py        → 诱饵 + AST 检测
  · guardian.py    → 物理快照回滚
  · Archive.py     → SimHash 记忆注入
  · Nuwa.py        → POC 报告生成
  · universal_document_parser.py → 文档解析

职责：
  1. 解析 Agent 的 <INTERNAL>/<EXTERNAL> 输出
  2. 权限裁决（执行层说了算，不让 AI 预判）
  3. 工具执行 + 安全监控
  4. 错误码标准化返回
  5. 记忆自动管理（对 Agent 透明）

用法：
    from execution_layer import ExecutionLayer
    el = ExecutionLayer(project_root="./my_project")
    result = el.process_agent_output(agent_output_text, user_input="帮我写代码")
"""

import os
import re
import ast
import sys
import html
import json
import shutil
import time
import tempfile
import ipaddress
import urllib.parse
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

from tools import ExecutionResult, ToolExecutor, repair_backslash_json
from tools.result import DenialKind
from ace_isolation import wrap_untrusted

# ============================================================
# 导入用户代码库（V1 + V2）
# ============================================================

# V2 主网关
try:
    from gateway_v2 import WordGateway, GuardViolation
    V2_AVAILABLE = True
except ImportError:
    V2_AVAILABLE = False
    WordGateway = None
    GuardViolation = Exception

# V1 行为约束
try:
    from work import BehaviorConstraint, BaitFactory, ASTDetector
    V1_WORK_AVAILABLE = True
except ImportError:
    V1_WORK_AVAILABLE = False
    BehaviorConstraint = None

# V1 快照回滚
try:
    from guardian import Guardian, resolve_signing_key
    V1_GUARDIAN_AVAILABLE = True
except ImportError:
    V1_GUARDIAN_AVAILABLE = False
    Guardian = None
    resolve_signing_key = None

# V1 记忆引擎
try:
    from Archive import MemoryArchive
    V1_ARCHIVE_AVAILABLE = True
except ImportError:
    V1_ARCHIVE_AVAILABLE = False
    MemoryArchive = None

# V1 POC 报告
try:
    from Nuwa import POCGenerator
    V1_NUWA_AVAILABLE = True
except ImportError:
    V1_NUWA_AVAILABLE = False
    POCGenerator = None

# 文档解析器
try:
    from universal_document_parser import parse_document, ParseResult
    PARSER_AVAILABLE = True
except ImportError:
    PARSER_AVAILABLE = False
    parse_document = None
    ParseResult = None


# ============================================================

# ============================================================
# 常量配置
# ============================================================

WRITE_TOOLS = {
    "terminal_exec", "file_write", "file_delete", "file_move",
    "api_post", "code_execute", "browser_click", "browser_type",
    "db_write", "notify_send", "image_generate",
    # SEC-012：browser_screenshot 抓的是整个虚拟桌面，不是"读工作区里的一个文件"。
    # 它原先在 READ_TOOLS 里，于是 readonly 档位就能把密码管理器、聊天窗口、
    # 另一个项目的代码一起拍进上下文 —— "只读"这个名字承诺的范围被它突破了。
    # 归到写入类只是把权限档位摆正；每次抓屏仍要单独确认（见 web_tools）。
    "browser_screenshot",
}

READ_TOOLS = {
    "terminal_view", "file_read", "api_get", "db_query", "search",
    "math_calc", "datetime_now", "browser_open",

    "parse_document", "open_file", "edit_file",
    "plan_propose", "request_permission",
    "git_status", "git_log", "git_diff",
    "code_analyze", "dependency_check", "test_execute",
    "performance_profile", "security_scan",
}

HIGH_RISK_TOOLS = {
    "terminal_dangerous", "db_drop"
}

# 控制类工具：由执行层直接处理（计划提议 / 权限申请），不走真实工具执行
CONTROL_TOOLS = {"plan_propose", "request_permission"}

# AST 门禁分层：安全规则熔断；风格规则仅警告（不阻塞正常开发）
AST_SAFETY_RULES = {"hardcoded_secrets", "sql_injection",
                    "infinite_recursion", "circular_ref"}
AST_STYLE_RULES = {"unused_import", "type_hints"}
AST_RULE_DESCRIPTIONS = {
    "unused_import": "未用导入",
    "type_hints": "函数缺少类型注解",
    "infinite_recursion": "无限递归",
    "circular_ref": "循环引用",
    "hardcoded_secrets": "硬编码密钥",
    "sql_injection": "SQL 注入风险",
}

# 参数报错时给模型的具体示例（小模型常漏参数，示例能显著提升修正成功率）
TOOL_EXAMPLES = {
    "terminal_view": '{"tool":"terminal_view","command":"ls -la"}',
    "terminal_exec": '{"tool":"terminal_exec","command":"mkdir test"}',
    "file_read": '{"tool":"file_read","path":"README.md"}',
    "file_write": '{"tool":"file_write","path":"out.txt","content":"hello"}',
    "file_delete": '{"tool":"file_delete","path":"old.txt"}',
    "file_move": '{"tool":"file_move","source":"a.txt","dest":"b.txt"}',
    "code_execute": '{"tool":"code_execute","language":"python","code":"print(1)"}',
    "search": '{"tool":"search","query":"Python 教程","top_k":5}',
    "math_calc": '{"tool":"math_calc","expression":"2+2*10"}',
    "datetime_now": '{"tool":"datetime_now","format":"YYYY-MM-DD HH:mm:ss"}',
    "api_get": '{"tool":"api_get","url":"https://example.com"}',
    "api_post": '{"tool":"api_post","url":"https://example.com","data":{"key":"value"}}',
    "db_query": '{"tool":"db_query","query":"SELECT * FROM t"}',
    "db_write": '{"tool":"db_write","query":"INSERT INTO t (name) VALUES (\'x\')"}',
    "browser_open": '{"tool":"browser_open","url":"https://example.com"}',
    "notify_send": '{"tool":"notify_send","channel":"console","content":"hello"}',
    "image_generate": '{"tool":"image_generate","prompt":"a cat","size":"512x512"}',
    "parse_document": '{"tool":"parse_document","path":"报告.docx"}',
    "open_file": '{"tool":"open_file","path":"README.md"}',
    "edit_file": '{"tool":"edit_file","path":"main.py"}',
    "plan_propose": '{"tool":"plan_propose","title":"任务","steps":["步骤1","步骤2"]}',
    "request_permission": '{"tool":"request_permission","target":"terminal_exec","reason":"原因"}',
    "git_status": '{"tool":"git_status","branch":"main"}',
    "git_log": '{"tool":"git_log","limit":10}',
    "git_diff": '{"tool":"git_diff","file":"main.py"}',
    "code_analyze": '{"tool":"code_analyze","path":"main.py"}',
    "dependency_check": '{"tool":"dependency_check","type":"python"}',
    "test_execute": '{"tool":"test_execute","pattern":"test_*.py"}',
    "performance_profile": '{"tool":"performance_profile","module":"myapp"}',
    "security_scan": '{"tool":"security_scan","type":"python"}',
}

# ------------------------------------------------------------
# 拒绝分类 → 给模型的下一步指令
#
# 这张表以前是一串 `"密钥类文件" in result.message` 的中文子串判断。那种写法有两个
# 硬伤：闸门文案一改，分派就悄悄失效（不报错、只是不再给指令）；文案要做 i18n 时，
# 判据会跟着语言一起漂走。所以拒绝原因由闸门用 `DenialKind` 显式带上来，这里只按
# 枚举查表。
#
# 表里的文案是给模型看的，不是给用户看的，所以不进 i18n —— 换成英文只会让中文模型
# 的指令跟随变差。用户可见的那一半在 `result.message`，那一半才需要翻译。
#
# 只有 PERMISSION_LEVEL 一档允许引导 request_permission。其余全部明确禁掉它：
# 逐次确认拿不到、硬拒、路径越界这些，调 request_permission 不会改变结果，只会
# 多烧一轮并让模型误以为还有别的门可走。
# ------------------------------------------------------------
_DENY_NO_RETRY = ("不要调用 request_permission，也不要换工具或换路径写法重试 —— "
                  "这一档没有放行通道，重试只会拿到同一个拒绝。")

DENIAL_INSTRUCTIONS: Dict[str, str] = {
    # ---- 逐次确认没拿到（非交互运行，或用户按了拒绝）----
    DenialKind.APPROVAL_UNAVAILABLE: (
        "这次动作需要用户逐次确认，但当前没有审批通道（非交互运行）。"
        "不要调用 request_permission，也不要换工具/换写法重试，"
        "直接向用户说明需要哪一项确认，以及在交互模式下重跑即可。"),
    DenialKind.APPROVAL_DENIED: (
        "用户明确拒绝了这次动作。不要重试，不要换工具绕，也不要调用 request_permission。"
        "改做用户真正想要的事，或直接问清他为什么拒绝。"),
    DenialKind.APPROVAL_ERROR: (
        "审批环节自身出错（不是用户拒绝），按拒绝处理。"
        "不要调用 request_permission，向用户说明确认没能完成。"),
    # ---- 硬拒：没有确认通道 ----
    DenialKind.SECRET_FILE: (
        "密钥类文件与凭据目录（.env / id_rsa / credentials / .ssh / .aws 等）是硬拒绝，"
        "不存在确认通道。" + _DENY_NO_RETRY +
        "请向用户说明，并改用不含密钥的文件。"),
    DenialKind.NEVER_WRITABLE: (
        "目标位于项目外的永不可写范围（凭据目录、开机启动目录、系统目录）。"
        "这类写入改变的是系统的凭据或执行路径，不是可回滚的数据，所以没有确认通道。"
        + _DENY_NO_RETRY + "请改写到项目目录内。"),
    DenialKind.NETWORK_PATH: (
        "UNC / 网络共享路径被硬拒：访问它会发起 SMB 出网并把当前账户凭据交给对面主机。"
        + _DENY_NO_RETRY + "请改用本地路径。"),
    DenialKind.EXECUTABLE_LAUNCH: (
        "拒绝启动可执行文件。" + _DENY_NO_RETRY +
        "如果确实需要运行它，把命令给用户让他自己执行。"),
    # ---- 执行层安全限制：换合法写法可能可行 ----
    DenialKind.PATH_OUT_OF_SCOPE: (
        "路径超出授权范围，这是执行层的路径边界，不是权限等级问题。"
        "请改用项目目录内的路径。不要调用 request_permission —— 它不会扩大目录范围。"),
    DenialKind.COMMAND_SHAPE: (
        "命令形态被拦截（管道/重定向/命令拼接/危险参数等）。"
        "请把它拆成单条、无 shell 元字符的简单命令后重试，或换用专用工具。"
        "不要调用 request_permission。"),
    DenialKind.TOOL_CAPABILITY: (
        "这个工具不具备该能力（例如只读工具不能执行任意命令）。"
        "请换用能做这件事的工具，不要调用 request_permission。"),
    DenialKind.CODE_GATE: (
        "代码静态检查判定这段代码有危险操作。请修改代码本身去掉该操作，"
        "不要调用 request_permission，也不要靠改写形式绕过检查。"),
    DenialKind.POLICY_FORBIDDEN: (
        "该命令在策略上被禁止执行，没有确认通道。" + _DENY_NO_RETRY +
        "请向用户说明，并考虑用别的方式达成目标。"),
    # ---- 环境问题，不是模型的错 ----
    DenialKind.SANDBOX_UNAVAILABLE: (
        "沙箱档位当前不可用，这是环境问题而不是你的调用有错。"
        "不要反复重试同一条命令，也不要调用 request_permission —— 提权不会把执行器装上。"
        "向用户说明沙箱不可用，并让他检查执行器是否就绪。"),
    # 与沙箱那一档的差别只有一句，但那一句是这条指令的全部价值：**换一条路就能成**。
    # 沙箱不可用时模型只能停手，而依赖缺失时它还有别的 channel / 别的工具可用 ——
    # 少了"换一条"这句，模型会像沙箱那样直接放弃，而 notify_send 的 console/file
    # 本来一次就能送到。
    # 同样禁掉 request_permission：提权不会把 plyer 装上，也不会把 SMTP 配置填上。
    DenialKind.DEPENDENCY_MISSING: (
        "这台机器不具备该能力（可选依赖未安装 / 外部程序不在 / 必需配置缺失），"
        "不是你的调用有错。原样重试一万次结果都一样，但换一条路可能立刻成功："
        "先改用同一工具的其他方式（如换通知 channel）或换用别的工具；"
        "确实没有替代路径时，告诉用户缺的是什么、怎么装或怎么配。"
        "不要调用 request_permission —— 提权装不上依赖，也填不上配置。"),

    # ---- 唯一一档应该走 request_permission ----
    DenialKind.PERMISSION_LEVEL: (
        "当前权限等级不足以执行该动作。这一档可以调用 request_permission 向用户申请提权，"
        "申请时说清要做什么、为什么必须提权。"),
}

# 闸门没带分类时的兜底。比今天的 None 严格更好：至少能拦住
# 「403 → 调 request_permission」这个最常见的无效重试。
DENIAL_INSTRUCTION_FALLBACK = (
    "这是执行层的安全限制，不是权限等级问题。请改用合法的路径/命令，"
    "或换用其他工具；不要调用 request_permission。")

# ------------------------------------------------------------
# 用户可见文案的翻译键
#
# 上面那张 DENIAL_INSTRUCTIONS 是给模型的、固定中文；`message` 同理 ——
# 它进模型上下文，翻译它等于让模型的输入语言由用户的界面偏好决定，而系统提示词
# 是中文写的。但 `message` 同时也是界面上唯一那句"为什么被挡了"，于是 en/ja 下
# 就出现半英半中。
#
# 解法是**按受众拆字段**，不是把 message 翻译掉：闸门额外带上 `message_key` /
# `message_args`，展示层（`agent_runner.result_display_message`）优先用键查译文。
# 反过来做（UI 侧维护一张"中文 message → 键"的映射表）等于把判据挂回中文子串，
# 与 `DenialKind` 那一轮刚拆掉的写法是同一个坑：文案一改，映射静默失效。
#
# `render_result()` 的白名单不含这两个键，所以它们不会漏进模型上下文。
# ------------------------------------------------------------
DISPLAY_TOOL_BANNED = "deny_tool_banned"
DISPLAY_PLAN_PENDING = "deny_plan_pending"
DISPLAY_PERMISSION_LEVEL = "deny_permission_level"

# Plan Mode 的计划抬头。
#
# 这两个键和上面三个的处境**不一样**，得说清楚，否则下一个人会按 `_display()` 的样子
# 去改它，然后发现界面上根本没变：
#
# `plan` 是**双受众**字段 —— `agent_runner.render_result()` 的白名单里有 "plan"
# （所以它进模型上下文），而 `agent_runner` 打印计划时也直接取 `result["plan"]`。
# 上面那三个键走的是"另开一个 `message_key` 字段、展示层查表"的拆法，前提是
# `message` 有一个独立的展示出口（`result_display_message()`）；`plan` 没有这样的
# 出口，唯一的消费点就是那一个字段。所以这里只能在渲染处就地查表。
#
# 这样做的代价被刻意压到了最小 —— 随界面语言漂的只有"抬头这个标签"：
# 计划正文（title / steps）本来就是模型自己写的，本来就不是固定中文；模型真正
# 要照着做的语义在同一个 payload 的 `status` / `message` / `instruction` / `steps`
# 里，那几项仍然是固定中文。换句话说 `plan` 对模型是 `title` + `steps` 的冗余美化，
# 不是判据。
#
# 彻底的拆法（`_handle_plan_propose` 额外带 `plan_key` / `plan_args`、
# `agent_runner` 改走展示层、`render_result` 白名单去掉 "plan"）动的是本次
# 授权范围外的文件，已作为契约疑问上报。
DISPLAY_PLAN_HEADING = "plan_heading"
DISPLAY_PLAN_UNTITLED = "plan_untitled"


def _display(key: str, **args: Any) -> Dict[str, Any]:
    """拼出返回字典里那两个展示字段。

    做成函数而不是在每个出口手写两行：漏掉 `message_args` 的表现是界面上出现
    `{tool}` 字面量 —— `i18n.t()` 在 format 失败时返回未格式化原文、不抛异常，
    所以这类错误不会红任何断言，只能靠"参数和键在同一处给出"来防。
    """
    return {"message_key": key, "message_args": {k: str(v) for k, v in args.items()}}



# terminal_view 只读白名单（修复：只读工具绝不允许 shell=True 执行任意命令）


# ============================================================
# Agent 输出解析器
# ============================================================

class AgentOutputParser:
    """解析 Agent 的 <INTERNAL>/<EXTERNAL> 输出"""

    @staticmethod
    def parse(text: str) -> Dict[str, str]:
        """
        解析 Agent 输出，提取 internal 和 external
        返回: {"internal": "...", "external": "...", "tool_call": {...} or None}
        """
        result = {
            "internal": "",
            "external": "",
            "tool_call": None,
            "final_reply": "",
            "valid": False,
            "error": ""
        }

        # 检查标签完整性
        if "<INTERNAL>" not in text or "</INTERNAL>" not in text:
            result["error"] = "缺少 <INTERNAL> 标签"
            return result
        if "<EXTERNAL>" not in text or "</EXTERNAL>" not in text:
            result["error"] = "缺少 <EXTERNAL> 标签"
            return result

        # 提取 INTERNAL
        internal_match = re.search(
            r'<INTERNAL>\s*\[INTERNAL_THINKING\](.*?)\[/INTERNAL_THINKING\]\s*</INTERNAL>',
            text, re.DOTALL
        )
        if internal_match:
            result["internal"] = internal_match.group(1).strip()
        else:
            # 宽松模式：只要内容在标签内就行
            internal_match = re.search(r'<INTERNAL>(.*?)</INTERNAL>', text, re.DOTALL)
            if internal_match:
                result["internal"] = internal_match.group(1).strip()

        # 提取 EXTERNAL
        external_match = re.search(r'<EXTERNAL>(.*?)</EXTERNAL>', text, re.DOTALL)
        if not external_match:
            result["error"] = "无法提取 <EXTERNAL> 内容"
            return result

        external_content = external_match.group(1).strip()

        # 检查 answer. 前缀
        if not external_content.startswith("answer."):
            result["error"] = "EXTERNAL 内容必须以 answer. 开头"
            return result

        # 去掉 answer. 前缀
        content_after_answer = external_content[7:].strip()

        # 判断模式 A（工具调用）还是模式 B（最终回复）
        if content_after_answer.startswith("{"):
            # 模式 A：提取 JSON（用 raw_decode 精确解析，替代手工括号扫描）
            text = content_after_answer.lstrip()
            tool_call = None
            try:
                tool_call, json_end = json.JSONDecoder().raw_decode(text)
            except json.JSONDecodeError:
                # 模型常把 Windows 绝对路径写进 JSON（C:\Users → \U 非法转义），
                # 解析失败后做反斜杠修复再试一次（后续检查用修复后的文本）
                fixed = repair_backslash_json(text)
                try:
                    tool_call, json_end = json.JSONDecoder().raw_decode(fixed)
                    text = fixed
                except json.JSONDecodeError as e:
                    result["error"] = f"JSON 解析失败: {e}"
                    return result
            if tool_call is None:
                result["error"] = "JSON 解析失败"
                return result
            remaining = text[json_end:].strip()
            if remaining:
                result["error"] = f"JSON 后存在多余内容: {remaining[:50]}"
                return result
            if not isinstance(tool_call, dict):
                result["error"] = "工具调用必须是 JSON 对象（如 {\"tool\": \"...\"}）"
                return result
            if "tool" not in tool_call:
                # 模型用 JSON 文本作答（引用配置/代码片段等），不是工具调用 → 按最终回复处理
                result["final_reply"] = content_after_answer
                result["valid"] = True
                return result
            result["tool_call"] = tool_call
            result["valid"] = True
        else:
            # 模式 B：最终回复
            if not content_after_answer.strip():
                result["error"] = "最终回复为空"
                return result
            # 检查是否包含 {"tool" 子串
            if '{"tool"' in content_after_answer:
                result["error"] = "模式 B 中禁止出现 {\"tool\" 子串"
                return result
            result["final_reply"] = content_after_answer
            result["valid"] = True

        return result


# ============================================================
# 权限管理器
# ============================================================

class PermissionManager:
    """权限裁决：执行层说了算，不让 AI 预判"""

    PERMISSION_LEVELS = {
        "readonly": {"tools": READ_TOOLS, "description": "只读权限"},
        "write": {"tools": READ_TOOLS | WRITE_TOOLS, "description": "写入修改权限"},
        "full": {"tools": READ_TOOLS | WRITE_TOOLS | HIGH_RISK_TOOLS, "description": "全部权限"},
    }

    def __init__(self, level: str = "readonly"):
        self.level = level
        self.temp_grants: set = set()  # 临时授权（单次）

    def can_execute(self, tool_name: str) -> bool:
        """判断当前权限是否允许执行该工具（临时授权单次有效，用后即焚）"""
        if tool_name in self.temp_grants:
            self.temp_grants.discard(tool_name)
            return True
        allowed = self.PERMISSION_LEVELS.get(self.level, {}).get("tools", set())
        return tool_name in allowed

    def grant_temp(self, tool_name: str):
        """临时授权单个工具（单次有效，使用一次后自动撤销）"""
        self.temp_grants.add(tool_name)

    def revoke_temp(self, tool_name: str):
        """撤销临时授权"""
        self.temp_grants.discard(tool_name)

    def upgrade(self, new_level: str):
        """升级权限等级"""
        if new_level in self.PERMISSION_LEVELS:
            self.level = new_level

    def get_status(self) -> Dict[str, Any]:
        return {
            "current_level": self.level,
            "description": self.PERMISSION_LEVELS.get(self.level, {}).get("description", "未知"),
            "allowed_tools": list(self.PERMISSION_LEVELS.get(self.level, {}).get("tools", set())),
            "temp_grants": list(self.temp_grants),
        }


# ============================================================
# 工具执行器
# ============================================================

# ============================================================
# 主执行层
# ============================================================

class ExecutionLayer:
    """
    Agent 执行层主入口

    串联 Word 体系 V1+V2，对 Agent 完全透明
    """

    def __init__(self, project_root: str = ".", permission_level: str = "readonly",
                 config: Optional[Dict] = None):
        self.project_root = Path(project_root).resolve()
        self.permission = PermissionManager(permission_level)
        self.executor = ToolExecutor(
            project_root,
            sandbox_base=(config or {}).get("sandbox_base"),
            confine_files=bool((config or {}).get("confine_files", True)),
            email_smtp=(config or {}).get("email_smtp"),
            # 双闸门配置从 config 透传。approval_hook 为 None 时，判定为 prompt
            # 的命令会被 terminal_exec 一律拒绝 —— 这是刻意的失败方向，
            # 但交互式入口必须把它接上，否则合法的 `git commit`、带管道的命令全不可用。
            approval_policy=(config or {}).get("approval_policy"),
            sandbox_policy=(config or {}).get("sandbox_policy"),
            approval_hook=(config or {}).get("approval_hook"),
            # 出站白名单（SEC-013 的另一半）。不配就用 ace_net 的默认清单；
            # 配了就完全替换 —— 理由见 tools/base.py 里那段注释。
            egress_allowlist=(config or {}).get("egress_allowlist"),
            # 项目外读取的目录白名单。不配就用 tools/base.py 的
            # DEFAULT_READ_ALLOWLIST（~/Desktop、~/Downloads）；白名单外的绝对
            # 路径每次都问人，密钥类文件一律硬拒。
            read_allowlist=(config or {}).get("read_allowlist"),
            use_go_executor=(config or {}).get("use_go_executor"),

        )
        self.parser = AgentOutputParser()

        # V2 网关（config 为空时也启用，使用默认配置）
        self.gateway = None
        if V2_AVAILABLE:
            try:
                cfg = dict(config or {})
                cfg.setdefault("flywheel_path",
                               str(self.project_root / ".agent_flywheel" / "violations.jsonl"))
                self.gateway = WordGateway(cfg)
            except Exception as e:
                self.gateway = None
                print(f"警告: V2 网关初始化失败，L4 守门已禁用: {e}", file=sys.stderr)

        # V1 模块
        self.bait_factory = BaitFactory() if V1_WORK_AVAILABLE else None
        self.ast_detector = ASTDetector() if V1_WORK_AVAILABLE else None
        # —— 快照签名密钥（SEC-010）——
        # 解析放在这里而不是各个 CLI 入口：ai_code.py 与 agent_runner.py 都建
        # ExecutionLayer，放在入口就要写两遍，而漏掉一遍正是 SEC-010 的成因
        # （README 写了 signing_key，ai_code.py 只往下传三个键，签名从未启用过）。
        # signing_key_source / signing_key_warning 供入口打印，本层不打印。
        _sk_cfg = (config or {}).get("signing_key")
        _sign_on = bool((config or {}).get("sign_snapshots", True))
        if V1_GUARDIAN_AVAILABLE and _sign_on:
            _sk = resolve_signing_key(
                _sk_cfg,
                key_path=(config or {}).get("signing_key_path"),
                project_root=self.project_root)
            self.signing_key_source = _sk.source
            self.signing_key_warning = _sk.warning
        elif V1_GUARDIAN_AVAILABLE:
            # sign_snapshots=False 是给"就是不想签"的场景留的显式出口。它必须彻底关掉：
            # 若还去读密钥文件，已存在的密钥会让"关闭"变成没关闭。关掉防护要留痕，
            # 所以带一条告警。
            _sk = None
            self.signing_key_source = "disabled"
            self.signing_key_warning = "快照签名已显式关闭：快照元信息可被伪造，回滚结果不可信"
        else:
            self.signing_key_source = "none"
            self.signing_key_warning = (
                "guardian 模块不可用：快照与签名均未启用，写操作没有回滚点"
                if _sk_cfg else "")
            _sk = None
        self.guardian = Guardian(
            str(self.project_root),
            signing_key=(_sk.key if _sk else None),
            max_snapshots=int((config or {}).get("max_snapshots", 20))) if V1_GUARDIAN_AVAILABLE else None
        self.archive = MemoryArchive(
            str(self.project_root / ".agent_memory.json"),
            session_tag=(config or {}).get("session_id", "default")) if V1_ARCHIVE_AVAILABLE else None
        self.nuwa = POCGenerator(str(self.project_root / ".poc_reports")) if V1_NUWA_AVAILABLE else None

        # 诱饵验证配置（work.py）
        bait_cfg = (config or {}).get("bait", {})
        self.bait_enabled = bool(bait_cfg.get("enabled", True))
        self.bait_frequency = int(bait_cfg.get("frequency", 0))  # 0 = 每会话仅验证一次
        self.pending_bait: Optional[Dict] = None
        self.bait_armed = True
        self.bait_fail_count = 0
        self.bait_exec_count = 0

        # 状态
        self.conversation_history: List[Dict] = []
        self.current_snapshot_id: Optional[str] = None
        self.violation_count = 0
        self.ast_fail_count = 0
        self.last_user_input = ""
        # 记忆预注入缓存：prepare_context 记录后，process_agent_output 不再重复写入
        self._last_memory_input: Optional[str] = None
        self._last_memory_shift = "stable"
        self._last_memory_list: List[Dict] = []
        # 计划模式（Plan Mode）：复杂任务先提议计划，用户批准后才执行
        self.pending_plan: Optional[Dict] = None
        self.plan_approved = False
        # 权限申请：Agent 请求临时授权，用户批准后放行一次
        self.pending_permission: Optional[Dict] = None
        # 重复失败熔断：同工具同错误连续 N 次 → 禁止再调用，防小模型死循环
        self.repeat_fail: Dict[str, int] = {}
        self.banned_tools: set = set()
        self.repeat_fail_threshold = 3
        # L1/L2 路由结果缓存（五层网关）
        self.last_route: Optional[Dict] = None
        self.last_route_input: Optional[str] = None

    # ---------- 记忆预注入（在模型生成前调用） ----------

    def prepare_context(self, user_input: str) -> str:
        """在模型生成前调用：记录用户输入到记忆库、检测主题切换，并返回可注入上下文的 prompt。

        返回值为加了记忆前缀的 user_input；无相关记忆时原样返回。
        同一 user_input 重复调用不会重复写入 Archive（process_agent_output 会复用本缓存）。
        """
        if not self.archive:
            return user_input
        self.archive.add(user_input)
        shift = self.archive.detect_topic_shift(user_input)
        self._last_memory_input = user_input
        self._last_memory_shift = shift
        self._last_memory_list = (
            self.archive.get_memory(top_k=3, exclude_last=True) if shift == "shifted" else []
        )
        if not self._last_memory_list:
            return user_input
        # SEC-011：记忆条目是从**过去的对话**里摘出来的，而过去的对话里可能已经
        # 混进过网页正文、命令输出。不隔离的话，一次注入可以在会话之间存活 ——
        # 攻击文本被记进 archive，下次自动预注入到 prompt 最前面。
        lines = ["[记忆注入] 以下是相关的历史对话记忆："]
        for m in self._last_memory_list:
            mark = "⚑" if m.get("urgent") else "·"
            lines.append(f"{mark} {m['text']}")
        return wrap_untrusted("\n".join(lines), source="历史对话记忆",
                              origin="memory_archive") + "\n\n" + user_input

    def process_agent_output(self, agent_output: str, user_input: str) -> Dict[str, Any]:
        """
        处理 Agent 的一轮输出

        返回标准化结果，Agent 收到后继续下一轮
        """
        injected_memory: List[Dict] = []

        # 0. 新任务（用户输入变化）时重置诱饵/重试状态，防止跨任务泄漏
        if user_input != self.last_user_input:
            self.pending_bait = None
            self.bait_fail_count = 0
            self.ast_fail_count = 0
            self.bait_armed = True
            self.last_user_input = user_input
            self.pending_plan = None
            self.plan_approved = False
            self.pending_permission = None
        # 0.5 L1 意图识别 + L2 技能推荐（五层网关，仅新输入时计算一次）
        if self.gateway and user_input != self.last_route_input:
            try:
                self.last_route = self.gateway.route(user_input)
            except Exception:
                self.last_route = None
            self.last_route_input = user_input
        route_meta = {}
        if self.last_route:
            route_meta = {
                "intent": (self.last_route.get("intent") or {}).get("intent"),
                "skills": self.last_route.get("skills") or [],
            }

        # 1. 解析 Agent 输出
        parsed = self.parser.parse(agent_output)
        if not parsed["valid"]:
            return {
                "status": "FORMAT_ERROR",
                "message": f"格式错误: {parsed['error']}",
                "instruction": "请严格按照 <INTERNAL>...</INTERNAL><EXTERNAL>answer...</EXTERNAL> 格式输出"
            }

        # 2. 记录到 Archive（SimHash 记忆；若已由 prepare_context 预注入，则复用缓存避免重复写入）
        if self.archive:
            if user_input != self._last_memory_input:
                # 直接库调用/测试未走 prepare_context：此处补齐记录，记忆功能依然可用
                self.archive.add(user_input)
                shift = self.archive.detect_topic_shift(user_input)
                injected_memory = (
                    self.archive.get_memory(top_k=3, exclude_last=True)
                    if shift == "shifted" else []
                )
            else:
                injected_memory = self._last_memory_list

        # 3. 模式 B：最终回复（过 L4 守门，文本规则；回复为叙述性内容，不套用代码风格规则）
        if parsed["final_reply"]:
            guard_result = self._guard_output(parsed["final_reply"], user_input,
                                              code_rules=False)
            if guard_result is not None:
                return guard_result
            return {
                "status": "FINAL_REPLY",
                "message": parsed["final_reply"],
                "internal": parsed["internal"],
                "memory_injected": injected_memory or None
            }

        # 4. 模式 A：工具调用
        tool_call = parsed["tool_call"]
        if not isinstance(tool_call, dict):
            return {
                "status": "FORMAT_ERROR",
                "message": "工具调用缺失或格式错误",
                "instruction": "模式 A 必须以 {\"tool\": \"...\"} JSON 对象输出工具调用"
            }
        tool_name = tool_call.get("tool", "")

        # 4.4 控制类工具熔断：plan_propose / request_permission 连续失败同样禁止
        if tool_name in ("plan_propose", "request_permission") and tool_name in self.banned_tools:
            return {
                "status": "TOOL_BANNED",
                "message": f"工具 '{tool_name}' 已因连续失败被熔断，本次对话禁止再调用",
                "instruction": "请直接执行任务或回复用户，不要再调用被熔断的工具",
                **_display(DISPLAY_TOOL_BANNED, tool=tool_name),
                **route_meta,
            }


        # 4.5 控制类工具：计划提议 / 权限申请（先于权限裁决，任何权限等级都可用）
        if tool_name == "plan_propose":
            return self._handle_plan_propose(tool_call, user_input, parsed, route_meta)
        if tool_name == "request_permission":
            return self._handle_permission_request(tool_call, parsed, route_meta)

        # 4.6 计划未批准前禁止执行其他工具（Plan Mode 门禁）
        if self.pending_plan and not self.plan_approved:
            return {
                "status": "PLAN_PENDING",
                "message": "当前有未批准的计划，请等待用户批准后再执行工具",
                "plan": self._render_plan(),
                "instruction": "请先等待 PLAN_PROPOSED 的批准结果",
                **_display(DISPLAY_PLAN_PENDING),
                **route_meta,
            }

        # 4.7 重复失败熔断闸门：连续失败的工具直接拒绝，防死循环
        if tool_name in self.banned_tools:
            return {
                "status": "TOOL_BANNED",
                "message": f"工具 '{tool_name}' 已因连续失败被熔断，本次对话禁止再调用",
                "instruction": "请改用其他工具完成目标，或直接向用户说明无法完成的原因，"
                               "不要再次调用被熔断的工具",
                **_display(DISPLAY_TOOL_BANNED, tool=tool_name),
                **route_meta,
            }

        # 5. 权限裁决（执行层说了算）
        # 这是唯一一档「申请提权真的有用」的 403，所以它也走 DENIAL_INSTRUCTIONS：
        # 拒绝文案只有一个出处，模型侧的判据也只有 denial_kind 一个。
        if not self.permission.can_execute(tool_name):
            return {
                "status": "403",
                "message": f"权限不足: 工具 '{tool_name}' 需要更高权限",
                "current_permission": self.permission.get_status(),
                "instruction": DENIAL_INSTRUCTIONS[DenialKind.PERMISSION_LEVEL],
                "denial_kind": DenialKind.PERMISSION_LEVEL,
                **_display(DISPLAY_PERMISSION_LEVEL, tool=tool_name),
                **route_meta,
            }


        # 6. code_execute 专属安全闸门：诱饵验证 + AST 检测（work.py）
        gate_warnings: Optional[Dict] = None
        if tool_name == "code_execute":
            gate = self._gate_code_execute(tool_call)
            if not gate["ok"]:
                return gate["result"]
            gate_warnings = gate.get("warnings")

        # 7. 写入操作前创建快照（guardian.py）；本轮快照用完即清，防止回滚到过期快照
        round_snapshot_id: Optional[str] = None
        if tool_name in WRITE_TOOLS and self.guardian:
            try:
                round_snapshot_id = self.guardian.snapshot(
                    f"before_{tool_name}_{int(time.time())}")
            except Exception:
                round_snapshot_id = None
        self.current_snapshot_id = round_snapshot_id

        # 8. 执行工具
        result = self.executor.execute(tool_call)

        # 9. L4 守门检测（gateway_v2 InstinctGuard，喂原始值避免 JSON 转义漏检；
        #    代码风格规则仅作用于生成/写入类工具，读文件等输出只过文本规则）
        if result.status == "success":
            if isinstance(result.data, dict):
                output_text = "\n".join(str(v) for v in result.data.values())
            else:
                output_text = str(result.data)
            code_rules = tool_name in ("code_execute", "file_write", "terminal_exec",
                                       "terminal_view", "api_post", "db_write",
                                       "image_generate")
            guard_result = self._guard_output(output_text, user_input, code_rules=code_rules)
            if guard_result is not None:
                notes = self._rollback_current_snapshot(round_snapshot_id)
                if notes:
                    guard_result["rollback_notes"] = notes
                self.current_snapshot_id = None
                return guard_result

        # 10. 诱饵重新武装（每 bait_frequency 次成功执行后再次验证）
        if result.status == "success" and tool_name == "code_execute" and self.bait_enabled:
            self.bait_exec_count += 1
            if self.bait_frequency > 0 and self.bait_exec_count % self.bait_frequency == 0:
                self.bait_armed = True

        # 11. 生成 POC 指标（Nuwa.py）
        if self.nuwa:
            status = "pass" if result.status == "success" else "fail"
            self.nuwa.add_metric("工具执行", tool_name, status)
            self.nuwa.add_metric("响应时间", tool_name,
                                 f"{result.metadata.get('elapsed', 0):.2f}s", "info")
            if result.status != "success":
                self.nuwa.add_metric("工具失败", tool_name, result.message, "warn")

        # 12. 构建返回（本轮快照引用用完后立即清空，防止后续轮次误回滚）
        self.current_snapshot_id = None
        if result.status == "success":
            # 成功推进：只清空该工具的失败计数，保留其他工具的计数。
            # 防止模型"成功一个工具"就把失败工具的计数清零、交替绕过熔断。
            self.repeat_fail = {k: v for k, v in self.repeat_fail.items()
                                if not k.startswith(tool_name + ":")}
            
            # —— 第4层防御：file_write 语义纠偏回喂 ——
            if tool_name == "file_write":
                wpath = str(tool_call.get("path", ""))
                wcontent = str(tool_call.get("content", "") or "")
                if not Path(wpath).suffix and not wcontent.strip():
                    result.data = dict(result.data or {})
                    result.data["hint"] = ("已创建无扩展名空文件。若用户想要的是【文件夹】，"
                                          "请改用 terminal_exec 执行 mkdir")
            
            return {
                "status": "SUCCESS",
                "tool": tool_name,
                "data": result.data,
                "elapsed": result.metadata.get("elapsed", 0),
                "internal": parsed["internal"],
                "snapshot_id": round_snapshot_id,
                "memory_injected": injected_memory or None,
                "ast_warnings": gate_warnings,
                **route_meta,
            }
        else:
            extra_instruction = None
            if result.error_code == "403" or result.denial_kind:
                # 闸门拒绝：按 denial_kind 查表。拿不到分类时也给兜底指令 ——
                # 沉默地什么都不说，模型多半会去调 request_permission。
                extra_instruction = DENIAL_INSTRUCTIONS.get(
                    result.denial_kind, DENIAL_INSTRUCTION_FALLBACK)
            elif result.error_code == "400" and tool_name in TOOL_EXAMPLES:
                # 参数缺失/格式错误：直接给模型一个可抄的示例
                extra_instruction = f"参数格式示例: {TOOL_EXAMPLES[tool_name]}"
            # 重复失败熔断：同工具同错误连续失败达阈值 → 禁止再调用
            fail_hint = self._note_tool_failure(tool_name, result.error_code,
                                                result.denial_kind)
            if fail_hint:
                extra_instruction = (extra_instruction or "") + fail_hint
            return {
                "status": result.error_code or "ERROR",
                "message": result.message,
                "tool": tool_name,
                "internal": parsed["internal"],
                "memory_injected": injected_memory or None,
                "instruction": extra_instruction,
                # 稳定的机器可读拒绝分类。文案会随 i18n 变，这个不会 ——
                # 上层（含测试）判断「为什么被拒」时应该读它，而不是去 match 中文。
                "denial_kind": result.denial_kind or None,
                **route_meta,
            }

    def _note_tool_failure(self, tool_name: str, error_code: str,
                           denial_kind: str = "") -> Optional[str]:
        """记录工具连续失败，返回附加 instruction；达阈值后熔断该工具。
        防止小模型对同一错误重复调用死循环（如缺参数的 request_permission）。
        403 安全拦截（沙盒/白名单/路径越界）是执行层主动防御，不视为模型失败，不计数。

        `denial_kind` 是为了捞回一类被误判的失败：沙箱档位不可用
        （`E_SANDBOX_UNAVAILABLE`）映射成 501 而不是 403，于是它会被计入连续失败，
        三次之后 `terminal_exec` 被永久熔断 —— 环境问题被当成了模型问题。

        `DEPENDENCY_MISSING` 是同一个误判的第二种形态，而且更狠：熔断桶是
        `f"{tool}:{code}"`，所以 `notify_send:501` 这一个桶被"toast 没装 plyer"和
        "email 没配 SMTP"共用 —— 模型试了一次 toast、两次 email，就把整个
        `notify_send` 熔断了，连本来一次就能送到的 console / file 一起禁掉。
        熔断要防的是"在同一个错误上原地打转"，而这一档恰恰是"原地重试没用、换条路
        立刻就成"，指令已经把它推向别的 channel；再计数等于用防打转的机制堵掉那条出路。"""
        if error_code == "403" or denial_kind in (DenialKind.SANDBOX_UNAVAILABLE,
                                                  DenialKind.DEPENDENCY_MISSING):
            return None
        fail_key = f"{tool_name}:{error_code or 'ERROR'}"
        self.repeat_fail[fail_key] = self.repeat_fail.get(fail_key, 0) + 1
        count = self.repeat_fail[fail_key]
        if count >= self.repeat_fail_threshold:
            self.banned_tools.add(tool_name)
            return (f" ⚠ 工具 {tool_name} 已连续失败 {count} 次，已被熔断："
                    "本次对话禁止再次调用它。请换用其他工具完成目标，"
                    "或直接向用户说明无法完成的原因。")
        if count >= 2:
            return (f"（注意：{tool_name} 已连续失败 {count} 次，"
                    "再失败一次将被熔断，请换用其他工具或直接回复用户）")
        return None

    # ---------- Plan Mode（计划提议与批准） ----------

    def _render_plan(self) -> str:
        """渲染待批计划（抬头走语言包，见 DISPLAY_PLAN_HEADING 上方的受众说明）。

        `i18n` 在函数内 import：这是本模块唯一一处展示用依赖，放模块头会让
        `execution_layer`（安全闸门）多背一个只服务于渲染的顶层依赖，而
        `i18n` 自己不 import 项目内任何模块，函数内 import 也不会有循环风险。
        """
        from i18n import t

        if not self.pending_plan:
            return ""
        title = self.pending_plan.get("title") or t(DISPLAY_PLAN_UNTITLED)
        steps = self.pending_plan.get("steps") or []
        body = "\n".join(f"  {i + 1}. {s}" for i, s in enumerate(steps))
        return f"{t(DISPLAY_PLAN_HEADING, title=title)}\n{body}"


    def _handle_plan_propose(self, tool_call: Dict, user_input: str,
                             parsed: Dict, route_meta: Dict) -> Dict:
        if self.pending_plan and self.plan_approved:
            # 计划已批准：模型重复提议 → 提示直接执行，不再重复走批准流程
            return {
                "status": "PLAN_ALREADY_APPROVED",
                "plan": self._render_plan(),
                "message": "计划已批准，请直接按计划执行，不要再提议新计划",
                "instruction": "按已批准的计划逐步调用工具执行",
                **route_meta,
            }
        title = str(tool_call.get("title", "")).strip() or "任务计划"
        steps = tool_call.get("steps")
        if not isinstance(steps, list) or not steps:
            return {
                "status": "FORMAT_ERROR",
                "message": "plan_propose 需要非空的 steps 列表",
                "instruction": '示例: {"tool": "plan_propose", "title": "...", "steps": ["步骤1", "步骤2"]}',
                **route_meta,
            }
        steps = [str(s).strip() for s in steps if str(s).strip()]
        if not steps:
            return {
                "status": "FORMAT_ERROR",
                "message": "plan_propose 的 steps 列表为空",
                **route_meta,
            }
        # 检测计划里的"手动操作"步骤（Agent 无法打开编辑器/文件管理器手动输入），
        # 提示模型改用工具完成，改善 Qwen 等小模型的计划质量
        _MANUAL_OPS = ("文件管理器", "资源管理器", "VS Code", "vscode", "编辑器",
                       "导航到", "手动", "记事本", "notepad", "打开桌面目录")
        _manual_hint = ""
        if any(kw in s for kw in _MANUAL_OPS for s in steps):
            _manual_hint = (" ⚠ 计划中包含编辑器/文件管理器等手动操作步骤："
                            "Agent 无法打开编辑器手动输入内容。创建/写入文件请用 "
                            "file_write 工具（相对路径写项目内，绝对路径写桌面等指定位置）；"
                            "查看目录用 terminal_view ls 或 file_read；"
                            "打开文件给用户看用 open_file。请修正计划中的手动操作步骤。")
        self.pending_plan = {
            "title": title, "steps": steps, "user_input": user_input,
            "internal": parsed.get("internal", ""),
        }
        self.plan_approved = False
        return {
            "status": "PLAN_PROPOSED",
            "title": title,
            "steps": steps,
            "plan": self._render_plan(),
            "message": "已生成任务计划，等待用户批准",
            "instruction": "等待用户批准：批准后按计划逐步执行；拒绝则调整方案。"
                           "若计划涉及写入桌面/主目录等用户明确指出的位置，"
                           "请用 file_write 的绝对路径（如 C:\\Users\\<用户名>\\Desktop\\文件.py），"
                           "相对路径只会写进项目目录"
                           + _manual_hint,
            **route_meta,
        }

    def approve_plan(self) -> bool:
        """用户批准计划：解除 Plan Mode 门禁"""
        if not self.pending_plan:
            return False
        self.plan_approved = True
        return True

    def reject_plan(self) -> bool:
        """用户拒绝计划：清空待批计划"""
        had = self.pending_plan is not None
        self.pending_plan = None
        self.plan_approved = False
        return had

    # ---------- 权限申请与临时授权 ----------

    def _handle_permission_request(self, tool_call: Dict, parsed: Dict,
                                   route_meta: Dict) -> Dict:
        target = str(tool_call.get("target", "")).strip()
        reason = str(tool_call.get("reason", "")).strip()
        if not target:
            hint = self._note_tool_failure("request_permission", "FORMAT_ERROR")
            return {
                "status": "FORMAT_ERROR",
                "message": "request_permission 需要 target 参数",
                "instruction": '示例: {"tool": "request_permission", "target": "terminal_exec", "reason": "..."}'
                               + (hint or ""),
                **route_meta,
            }
        # 当前权限已允许该工具：直接掐断，防止模型盲目申请权限死循环
        allowed_tools = self.permission.PERMISSION_LEVELS.get(
            self.permission.level, {}).get("tools", set())
        if target in allowed_tools:
            return {
                "status": "SUCCESS",
                "tool": "request_permission",
                "message": (f"当前权限（{self.permission.get_status()['description']}）"
                            f"已允许工具 '{target}'，无需申请权限"),
                "instruction": f"直接调用 {target} 执行，不要再调用 request_permission",
                **route_meta,
            }
        self.pending_permission = {"tool": target, "reason": reason}
        return {
            "status": "PERMISSION_REQUEST",
            "tool": target,
            "reason": reason,
            "message": f"Agent 请求临时授权使用工具: {target}",
            "instruction": "等待用户批准：批准后重试该工具；拒绝则换其他方式",
            **route_meta,
        }

    def grant_pending_permission(self) -> bool:
        """用户批准权限申请：授予目标工具一次临时权限"""
        if not self.pending_permission:
            return False
        target = self.pending_permission.get("tool", "")
        if target:
            self.permission.grant_temp(target)
        self.pending_permission = None
        return True

    def reject_pending_permission(self) -> bool:
        had = self.pending_permission is not None
        self.pending_permission = None
        return had

    # ---------- 安全闸门与守门辅助 ----------

    def _guard_output(self, output_text: str, user_input: str,
                      code_rules: bool = True) -> Optional[Dict]:
        """L4 守门：block 级违规返回 GUARD_VIOLATION 字典；warn 级或通过返回 None"""
        if not self.gateway:
            return None
        guard_result = self.gateway.guard.check(output_text, code_rules=code_rules)
        if guard_result.passed or guard_result.action == "warn":
            return None
        # L5 飞轮记录
        try:
            from gateway_v2 import Intent
            self.gateway.flywheel.log_violation(
                Intent(raw_input=user_input), output_text,
                guard_result.failed_rule,
                extra={"action": guard_result.action, "details": guard_result.details})
        except Exception:
            pass
        self.violation_count += 1
        return {
            "status": "GUARD_VIOLATION",
            "message": f"守门拦截: {guard_result.failed_rule}",
            "rule": guard_result.failed_rule,
            "action": guard_result.action,
            "details": guard_result.details,
            "instruction": "请修正输出后重试"
        }

    def _rollback_current_snapshot(self, snapshot_id: Optional[str]) -> List[str]:
        """熔断回滚：仅回滚本轮创建的快照（防止回滚到过期快照破坏无关修改）

        返回回滚过程中产生的提示（目前只有 SEC-014 的"密钥类文件未被恢复"）。
        这类提示必须往上传：回滚是"已经复原"的承诺，有例外就得说出来。
        """
        if self.guardian and snapshot_id:
            try:
                self.guardian.rollback(snapshot_id)
            except Exception:
                pass
            return list(getattr(self.guardian, "last_rollback_notes", []) or [])
        return []


    def _gate_code_execute(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """code_execute 安全闸门：诱饵验证 + AST 行为检测（work.py）"""
        code = tool_call.get("code", "")

        # a. 验证上一轮注入的诱饵是否已被修复
        if self.bait_enabled and self.bait_factory and self.pending_bait:
            fixed, reason = self.bait_factory.verify_fixed(code, self.pending_bait["meta"])
            if not fixed:
                self.bait_fail_count += 1
                return {"ok": False, "result": {
                    "status": "BAIT_TRIGGERED",
                    "message": f"诱饵验证失败: {reason}",
                    "bait_type": self.pending_bait["meta"].type,
                    "description": self.pending_bait["meta"].description,
                    "baited_code": self.pending_bait["baited_code"],
                    "attempt": self.bait_fail_count,
                    "stop_retry": self.bait_fail_count >= 3,
                    "instruction": "请识别并移除代码中的诱饵后重新调用 code_execute（连续失败 3 次请停止重试并向用户汇报）"
                }}
            self.pending_bait = None
            self.bait_fail_count = 0

        # b. AST 行为检测：安全规则熔断，风格规则只警告（不阻塞正常开发）
        if self.ast_detector:
            report = self.ast_detector.check_all(code)
            failed = [k for k, v in report.items() if not v]
            safety_failed = [k for k in failed if k in AST_SAFETY_RULES]
            style_failed = [k for k in failed if k in AST_STYLE_RULES]
            if safety_failed:
                self.ast_fail_count += 1
                return {"ok": False, "result": {
                    "status": "AST_FAILED",
                    "message": f"AST 安全检测失败: {safety_failed}",
                    "report": report,
                    "attempt": self.ast_fail_count,
                    "stop_retry": self.ast_fail_count >= 3,
                    "instruction": "请修正代码中的安全隐患后重新调用 code_execute（同一问题最多重试 3 次）"
                }}
            if style_failed:
                # 风格问题（如缺类型注解/未用导入）不熔断，仅随结果返回警告
                self.ast_fail_count = 0
                return {"ok": True, "warnings": {
                    k: AST_RULE_DESCRIPTIONS.get(k, k) for k in style_failed
                }}
            self.ast_fail_count = 0

        # c. 注入新诱饵（验证 Agent 是否能识别并修复）
        if self.bait_enabled and self.bait_factory and self.pending_bait is None and self.bait_armed:
            baited_code, meta = self.bait_factory.inject_bait(code)
            self.pending_bait = {"meta": meta, "baited_code": baited_code}
            self.bait_armed = False
            return {"ok": False, "result": {
                "status": "BAIT_TRIGGERED",
                "message": f"诱饵已注入: {meta.type}（{meta.description}）",
                "bait_type": meta.type,
                "description": meta.description,
                "bait_id": meta.id,
                "baited_code": baited_code,
                "instruction": "执行层已向你的代码注入语义诱饵。请查看 baited_code，识别诱饵特征（_bait_ 前缀），移除后重新提交 code_execute"
            }}
        return {"ok": True}

    def grant_permission(self, level: str, temp_tools: Optional[List[str]] = None):
        """用户授权权限"""
        self.permission.upgrade(level)
        if temp_tools:
            for tool in temp_tools:
                self.permission.grant_temp(tool)

    def get_stats(self) -> Dict[str, Any]:
        """获取执行层统计"""
        stats = {
            "permission": self.permission.get_status(),
            "violation_count": self.violation_count,
            "execution_count": len(self.executor.execution_log),
            "v1_modules": {
                "work": V1_WORK_AVAILABLE,
                "guardian": V1_GUARDIAN_AVAILABLE,
                "archive": V1_ARCHIVE_AVAILABLE,
                "nuwa": V1_NUWA_AVAILABLE,
            },
            "v2_gateway": V2_AVAILABLE,
            "parser": PARSER_AVAILABLE,
            # 快照签名是否真的生效，必须能从外部观测到 —— SEC-010 的根因就是
            # "看起来配了、实际没生效"，而没有任何地方能看出这件事。
            "snapshot_signing": {
                "active": bool(self.guardian and self.guardian.signing_key),
                "source": self.signing_key_source,
            },
            "bait": {
                "enabled": self.bait_enabled,
                "armed": self.bait_armed,
                "pending": self.pending_bait is not None,
                "frequency": self.bait_frequency,
            },
        }
        if self.archive:
            stats["archive"] = self.archive.stats()
        return stats

    def generate_poc_report(self, title: str = "Agent 执行层 POC 报告") -> Optional[str]:
        """生成 POC 报告（Nuwa.py）"""
        if not self.nuwa:
            return None
        self.nuwa.title = title
        report = self.nuwa.generate_report()
        return report.html_path


# ============================================================
# CLI 测试入口
# ============================================================

if __name__ == "__main__":
    import argparse

    # Windows GBK 控制台兼容（重定向/管道下 emoji 会 UnicodeEncodeError）
    for _s in (sys.stdout, sys.stderr):
        try:
            if _s.encoding and _s.encoding.lower() not in ("utf-8", "utf8"):
                _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(description="Agent 执行层")
    parser.add_argument("--test-parse", help="测试解析 Agent 输出文件")
    parser.add_argument("--stats", action="store_true", help="显示统计")
    parser.add_argument("--project-root", default=".", help="项目根目录")
    parser.add_argument("--permission", default="readonly", choices=["readonly", "write", "full"])
    args = parser.parse_args()

    el = ExecutionLayer(project_root=args.project_root, permission_level=args.permission)

    if args.test_parse:
        with open(args.test_parse, "r", encoding="utf-8") as f:
            agent_output = f.read()
        result = el.process_agent_output(agent_output, "测试输入")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.stats:
        print(json.dumps(el.get_stats(), indent=2, ensure_ascii=False))
    else:
        print("Agent 执行层已初始化")
        print(f"权限: {el.permission.get_status()['description']}")
        print(f"V1 模块: {el.get_stats()['v1_modules']}")
        print(f"V2 网关: {'✅' if V2_AVAILABLE else '⚪'}")
        print(f"文档解析: {'✅' if PARSER_AVAILABLE else '⚪'}")
