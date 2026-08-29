#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
execution_layer.py —— Agent 执行层（完整版）

串联 Word 体系 V1+V2：
  · gateway_v2.py  → L1/L2/L4/L5 网关
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
from ace_isolation import wrap_untrusted
from ace_sessionlog import (K_PERMISSION, K_SNAPSHOT_CREATE, K_SNAPSHOT_ROLLBACK,
                            K_TOOL_CALL, K_TOOL_RESULT, SessionLog)
import ace_execpolicy as execpolicy  # noqa: E402

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
    from guardian import Guardian
    V1_GUARDIAN_AVAILABLE = True
except ImportError:
    V1_GUARDIAN_AVAILABLE = False
    Guardian = None

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

# 权限集合与控制工具集：内容由 tools/registry.py 的 TOOL_SPECS 派生，
# 见下方 refresh_tool_sets()。这里只创建空集合对象占位——外部模块
# `from execution_layer import READ_TOOLS` 拿到的是这几个对象的引用，
# 刷新时就地更新（clear+update），引用保持有效。
# 不要在这里写死工具名：写死的那份一定会和注册表漂移。
WRITE_TOOLS: set = set()
READ_TOOLS: set = set()
HIGH_RISK_TOOLS: set = set()
# 控制类工具：由执行层直接处理（计划提议 / 权限申请），不走真实工具执行
CONTROL_TOOLS: set = set()
# 每次调用都需用户确认的工具：权限等级放行也不例外（见 ToolSpec.confirm）
CONFIRM_TOOLS: set = set()

# 参数报错时给模型的具体示例（小模型常漏参数，示例能显著提升修正成功率）
TOOL_EXAMPLES = {}


def refresh_tool_sets() -> None:
    """从 tools/registry.py 的 TOOL_SPECS 重建权限集合与参数示例。

    权限分级与工具清单的唯一来源是注册表；这里只做同步。
    运行时注册工具（MCP / 插件）后需再调用一次，否则新工具会被权限门当成未知工具。
    集合就地更新（clear+update）而非重新赋值，保证外部 `from execution_layer import
    READ_TOOLS` 拿到的引用同步生效。PermissionManager 不缓存并集快照
    （见 PermissionManager.allowed_tools），所以这里无需再回填它。
    """
    from tools.registry import (PERM_HIGH_RISK, PERM_READ, PERM_WRITE,
                               confirm_tool_names, control_tool_names,
                               names_with_permission, tool_examples)
    for target, names in ((READ_TOOLS, names_with_permission(PERM_READ)),
                          (WRITE_TOOLS, names_with_permission(PERM_WRITE)),
                          (HIGH_RISK_TOOLS, names_with_permission(PERM_HIGH_RISK)),
                          (CONTROL_TOOLS, control_tool_names()),
                          (CONFIRM_TOOLS, confirm_tool_names())):
        target.clear()
        target.update(names)
    TOOL_EXAMPLES.clear()
    TOOL_EXAMPLES.update(tool_examples())


refresh_tool_sets()


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

# —— 同前缀免确认（借鉴 Codex exec_policy 的"同前缀不再问"，会话级、不落盘） ——
# 用户确认过 `pip install numpy` 后，`pip install requests` 不再弹窗；但危险包装
# 前缀**永不**自动放行 —— 自动批准 `python -c` 等于没有审批（它正是策略层
# 明说拦不住的等价路径，见 CONFIRM_TOOLS 注释）。
BANNED_AUTO_PREFIXES = {
    "bash -c", "sh -c", "zsh -c", "dash -c",
    "python -c", "python3 -c", "py -c",
    "node -e", "node -p", "node --eval", "node --print",
    "cmd /c", "cmd.exe /c", "powershell", "powershell -c",
    "pwsh", "pwsh -c", "powershell.exe",
}


def command_prefix(cmd: str) -> str:
    """提取命令的 2-token 前缀（小写），用于同前缀匹配。不做 shell 解析：
    只取前两个空白分隔 token，够用于分类，不需要（也不该）信任分词结果。"""
    parts = (cmd or "").strip().split()
    return " ".join(parts[:2]).lower()

# 参数报错时给模型的具体示例：见文件顶部 TOOL_EXAMPLES（由注册表 example 字段派生）

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

    # 只存描述。允许的工具集不缓存快照，每次从模块级 READ_TOOLS / WRITE_TOOLS /
    # HIGH_RISK_TOOLS 现算——这三个集合由 refresh_tool_sets() 就地刷新，
    # 所以运行时注册工具（MCP / 插件）后无需回填本类。
    PERMISSION_LEVELS = {
        "readonly": {"description": "只读权限"},
        "write": {"description": "写入修改权限"},
        "full": {"description": "全部权限"},
    }

    _LEVEL_SOURCES = {
        "readonly": ("read",),
        "write": ("read", "write"),
        "full": ("read", "write", "high_risk"),
    }

    @classmethod
    def allowed_tools(cls, level: str) -> set:
        """现算某等级允许的工具全集（不缓存，避免与注册表漂移）"""
        buckets = {"read": READ_TOOLS, "write": WRITE_TOOLS, "high_risk": HIGH_RISK_TOOLS}
        allowed: set = set()
        for key in cls._LEVEL_SOURCES.get(level, ()):
            allowed |= buckets[key]
        return allowed

    def __init__(self, level: str = "readonly"):
        self.level = level
        self.temp_grants: set = set()     # 临时授权（单次，用后即焚）
        self.session_grants: set = set()  # 会话级授权（本次会话内长期有效）

    def can_execute(self, tool_name: str) -> bool:
        """判断当前权限是否允许执行该工具

        三级来源，从宽到严：
          1. session_grants —— 用户明确说过"本次会话都允许"，不消耗
          2. temp_grants    —— 单次授权，命中即焚
          3. 权限等级本身
        """
        if tool_name in self.session_grants:
            return True
        if tool_name in self.temp_grants:
            self.temp_grants.discard(tool_name)
            return True
        return tool_name in self.allowed_tools(self.level)

    def grant_temp(self, tool_name: str):
        """临时授权单个工具（单次有效，使用一次后自动撤销）"""
        self.temp_grants.add(tool_name)

    def grant_session(self, tool_name: str) -> bool:
        """会话级授权：本次会话内不再重复询问。返回是否真的授予。

        CONFIRM_TOOLS 里的工具（terminal_exec）拒绝会话级授权——它的危险命令
        黑名单本身可被绕过，"逐次由人看一眼命令"就是它唯一有效的防线，一旦允许
        一次性放行整场会话，这道防线等于没有。这里是唯一入口，所以在此处把门。
        """
        if tool_name in CONFIRM_TOOLS:
            self.grant_temp(tool_name)
            return False
        self.session_grants.add(tool_name)
        return True

    def revoke_temp(self, tool_name: str):
        """撤销临时授权（含会话级）"""
        self.temp_grants.discard(tool_name)
        self.session_grants.discard(tool_name)

    def upgrade(self, new_level: str):
        """升级权限等级"""
        if new_level in self.PERMISSION_LEVELS:
            self.level = new_level

    def get_status(self) -> Dict[str, Any]:
        return {
            "current_level": self.level,
            "description": self.PERMISSION_LEVELS.get(self.level, {}).get("description", "未知"),
            "allowed_tools": sorted(self.allowed_tools(self.level)),
            "temp_grants": list(self.temp_grants),
            "session_grants": sorted(self.session_grants),
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
            sandbox=(config or {}).get("sandbox"),
            approval_policy=(config or {}).get("approval_policy"),
            egress_allowlist=(config or {}).get("egress_allowlist"),
            sandbox_policy=(config or {}).get("sandbox_policy"),
            approval_hook=self._exec_approval_hook,
            kb_root=(config or {}).get("kb_root"),
            skills_dir=(config or {}).get("skills_dir"),
        )
        # 逐次确认闸门是否已就本轮调用放行；供 _exec_approval_hook 读取。
        self._round_confirmed = False
        # 同前缀免确认白名单（会话级）：用户确认过的命令前缀，同前缀 prompt 档自动放行
        self._approved_prefixes: List[str] = []
        # 目标状态机（持久化长任务）：CLI 轮次驱动与工具共用同一个 store
        self.goal_store = self.executor._goal_store()
        # 会话事件日志（全链路）：CLI 通过 config["session_log"] 注入 path；None = 禁用。
        # 执行层记录权限裁决/守卫/快照/工具往返，CLI 记录模型请求/输出 —— 同一份事实源。
        _slog_path = (config or {}).get("session_log")
        self.session_log = SessionLog(_slog_path) if _slog_path else None


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
        self.guardian = Guardian(
            str(self.project_root),
            signing_key=(config or {}).get("signing_key"),
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

    # ---------- 命令审批（接 ace_execpolicy 的 prompt 档） ----------

    def _exec_approval_hook(self, verdict) -> bool:
        """把 ace_execpolicy 判定出的 prompt 档接到本层已有的逐次确认闸门上。

        这里刻意**不**问人。上游那份实现是"在工具内部同步弹框问"，照搬到这边是错的：
        本项目的确认是一次**往返**（返回 PERMISSION_REQUEST → 人答 y → grant_temp →
        模型重发同一个调用），位置比工具内部更靠前，而且不跟流式渲染抢终端。
        再加一条同步询问通道，等于有两个地方能问、也有两个地方能被绕过。

        所以这个 hook 只回答一件事："人是否已经就本次调用点过头"——也就是 5.0 闸门
        刚刚放行的那一次。判定层拿它当 `user_approved`。

        为什么不干脆在工具里直接当成已批准：ToolExecutor 是公开类，可以脱离执行层
        单独构造（测试和嵌入方都这么用）。那种情况下 approval_hook 是 None，
        prompt 档一律拒绝——方向朝安全。
        """
        if self._round_confirmed:
            # 人刚刚确认过本次调用：记住其命令前缀，后续同前缀命令免问。
            # 只在确认当下记一次（且不在 BANNED 名单时），不重复入列。
            prefix = command_prefix(verdict.normalized or "")
            if prefix and prefix not in BANNED_AUTO_PREFIXES \
                    and prefix not in self._approved_prefixes:
                self._approved_prefixes.append(prefix)
            return True
        # 未确认但前缀已在本会话确认过 → 自动放行（与 CONFIRM_TOOLS 闸门同口径）
        return self._prefix_auto_approved(verdict.normalized or "")

    def _prefix_auto_approved(self, cmd: str) -> bool:
        """前缀白名单判定：前缀已在会话内被用户确认过，且不是 BANNED 危险包装。

        CONFIRM_TOOLS 闸门与 _exec_approval_hook 都走这里，保证同一条命令
        在两个出口的判定一致。只匹配完整 2-token 前缀（pip install 不会自动
        放行 pip uninstall）；BANNED 前缀即使被确认过也永不自动放行。
        """
        prefix = command_prefix(cmd)
        return bool(prefix and prefix not in BANNED_AUTO_PREFIXES
                    and prefix in self._approved_prefixes)

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
        lines = ["[记忆注入] 以下是相关的历史对话记忆："]
        for m in self._last_memory_list:
            mark = "⚑" if m.get("urgent") else "·"
            lines.append(f"{mark} {m['text']}")
        # SEC-011：记忆条目是从**过去的对话**里摘出来的，而过去的对话里可能已经混进过
        # 网页正文、命令输出。不隔离的话，一次注入可以在会话之间存活 —— 攻击文本被记进
        # archive，下次自动预注入到 prompt 最前面，且位置比用户本轮输入更靠前。
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
                **route_meta,
            }

        # 4.7 重复失败熔断闸门：连续失败的工具直接拒绝，防死循环
        if tool_name in self.banned_tools:
            return {
                "status": "TOOL_BANNED",
                "message": f"工具 '{tool_name}' 已因连续失败被熔断，本次对话禁止再调用",
                "instruction": "请改用其他工具完成目标，或直接向用户说明无法完成的原因，"
                               "不要再次调用被熔断的工具",
                **route_meta,
            }

        # 5. 权限裁决（执行层说了算）
        # 5.0 逐次确认闸门：CONFIRM_TOOLS 里的工具即使权限等级放行，也必须每次由人点头。
        #     terminal_exec 属于这一类——它的危险命令黑名单可被引号 / 长选项 /
        #     $HOME 展开 / PowerShell 别名 / python -c 绕过，策略层拦不住，最终防线是人。
        #     临时授权用后即焚，所以"已在 temp_grants 里"= 用户刚刚已确认过本次调用，
        #     不再重复问；等级本身不够时留给下面的 403 走常规 request_permission 流程。
        #
        #     这个标记必须在 can_execute() 之前取：它会消费掉 temp_grants，之后再读
        #     永远是 False。ace_execpolicy 的 prompt 档就靠它判断"人已经点过头"。
        self._round_confirmed = (tool_name in self.permission.temp_grants
                                 or tool_name in self.permission.session_grants)
        if (tool_name in CONFIRM_TOOLS

                and tool_name not in self.permission.temp_grants
                and tool_name in self.permission.allowed_tools(self.permission.level)):
            # on_failure 审批档 + 真实沙箱边界（docker/job）→ 先试后问：跳过逐次确认，
            # 让边界拦（与 file_tools 的 _exec_terminal_exec 同一豁免口径）。
            _of_fail = (getattr(self.executor, "approval_policy", None)
                        == execpolicy.ApprovalPolicy.ON_FAILURE
                        and (self.executor.docker_sandbox is not None
                             or self.executor.sandbox_mode == "job"))
            # 同前缀免确认：用户之前确认过同前缀命令（且不是 BANNED 危险包装）→ 跳过确认闸门。
            # 确认逻辑与 _exec_approval_hook 共用同一套前缀判定，避免两处口径漂移。
            _cmd = str(tool_call.get("command") or tool_call.get("code") or "")
            if not _of_fail and not self._prefix_auto_approved(_cmd):
                preview = _cmd
                if len(preview) > 300:
                    preview = preview[:300] + " …（已截断）"
                self.pending_permission = {"tool": tool_name, "reason": preview}
                if self.session_log:
                    self.session_log.record_permission(
                        tool_name, "confirm", self.permission.level, preview[:100])
                return {
                    "status": "PERMISSION_REQUEST",
                    "tool": tool_name,
                    "reason": preview,
                    "message": f"'{tool_name}' 需要用户逐次确认: {preview}",
                    "instruction": "等待用户确认结果，不要重复调用，也不要改用其他工具绕过确认",
                    **route_meta,
                }
        if not self.permission.can_execute(tool_name):
            if self.session_log:
                self.session_log.record_permission(
                    tool_name, "denied", self.permission.level)
            # 权限不足 → 自动弹出临时授权请求（用户 y/a/n），而不是把 403 甩回模型
            # 让模型自己调 request_permission——小模型总是漏 target 参数，最后熔断死循环。
            # 人批准才 grant_temp 放行一次（用后即焚），非交互 fail-close（SEC-004）。
            preview = str(tool_call.get("command") or tool_call.get("code") or "")
            if len(preview) > 300:
                preview = preview[:300] + " …"
            self.pending_permission = {"tool": tool_name, "reason": preview}
            return {
                "status": "PERMISSION_REQUEST",
                "tool": tool_name,
                "reason": preview,
                "message": (f"权限不足: 工具 '{tool_name}' 需要更高权限"
                            f"{'：' + preview[:100] if preview else ''}。是否临时授权？"),
                "instruction": "等待用户确认结果：批准后重试该工具；拒绝则换其他方式",
                **route_meta,
            }
        if self.session_log:
            self.session_log.record_permission(
                tool_name, "allowed", self.permission.level)

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
                if self.session_log and round_snapshot_id:
                    self.session_log.record_snapshot(K_SNAPSHOT_CREATE,
                                                     round_snapshot_id, tool_name)
            except Exception:
                round_snapshot_id = None
        self.current_snapshot_id = round_snapshot_id

        # 8. 执行工具（全链路日志：调用原始参数 + 结果）
        if self.session_log:
            self.session_log.record_tool_call(
                tool_name, {k: v for k, v in tool_call.items() if k != "tool"})
        result = self.executor.execute(tool_call)
        if self.session_log:
            self.session_log.record_tool_result(
                tool_name, result.status, result.message)

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
                self._rollback_current_snapshot(round_snapshot_id)
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
            if result.error_code == "403":
                if ("越界" in result.message or "白名单" in result.message
                        or "拦截" in result.message or "仅允许" in result.message
                        or "沙盒" in result.message):
                    extra_instruction = (
                        "这是执行层安全限制（路径越界/白名单/沙盒拦截），不是权限问题。"
                        "请改用项目目录内的合法路径或换用其他工具，不要调用 request_permission。")
            elif result.error_code == "409":
                # str_replace 多匹配：这是"定位不唯一"，不是参数格式错，也不是权限问题。
                # 明确告诉模型重试路径，否则它会去调 request_permission 或改用整文件覆盖。
                extra_instruction = (
                    "old_string 命中多处，执行层已放弃写入（文件未被修改）。"
                    "请补足唯一上下文后重试同一工具，或确认要全量替换时传 replace_all=true；"
                    "不要退化成 file_write 整文件覆盖，也不要调用 request_permission。")
            elif result.error_code == "400" and tool_name in TOOL_EXAMPLES:

                # 参数缺失/格式错误：直接给模型一个可抄的示例
                extra_instruction = f"参数格式示例: {TOOL_EXAMPLES[tool_name]}"
            # 重复失败熔断：同工具同错误连续失败达阈值 → 禁止再调用
            fail_hint = self._note_tool_failure(tool_name, result.error_code)
            if fail_hint:
                extra_instruction = (extra_instruction or "") + fail_hint
            return {
                "status": result.error_code or "ERROR",
                "message": result.message,
                "tool": tool_name,
                "internal": parsed["internal"],
                "memory_injected": injected_memory or None,
                "instruction": extra_instruction,
                **route_meta,
            }

    def _note_tool_failure(self, tool_name: str, error_code: str) -> Optional[str]:
        """记录工具连续失败，返回附加 instruction；达阈值后熔断该工具。
        防止小模型对同一错误重复调用死循环（如缺参数的 request_permission）。
        403 安全拦截（沙盒/白名单/路径越界）是执行层主动防御，不视为模型失败，不计数。"""
        if error_code == "403":
            return None
        fail_key = f"{tool_name}:{error_code or 'ERROR'}"
        self.repeat_fail[fail_key] = self.repeat_fail.get(fail_key, 0) + 1
        count = self.repeat_fail[fail_key]
        # 409（str_replace 定位不唯一）用更宽的阈值：上面的 instruction 明确要求
        # "补足上下文后重试同一工具"，而正常的消歧本来就要两三轮。按同一阈值算的话，
        # 照指令做事的模型会在第 3 次把这个工具用没了 —— 那是我们自己把路堵死。
        # 但也不能完全不计数：真死循环还是得掐，所以只是放宽到两倍。
        threshold = (self.repeat_fail_threshold * 2 if error_code == "409"
                     else self.repeat_fail_threshold)
        if count >= threshold:
            self.banned_tools.add(tool_name)
            return (f" ⚠ 工具 {tool_name} 已连续失败 {count} 次，已被熔断："
                    "本次对话禁止再次调用它。请换用其他工具完成目标，"
                    "或直接向用户说明无法完成的原因。")
        if count >= threshold - 1:
            return (f"（注意：{tool_name} 已连续失败 {count} 次，"
                    "再失败一次将被熔断，请换用其他工具或直接回复用户）")
        return None


    # ---------- Plan Mode（计划提议与批准） ----------

    def _render_plan(self) -> str:
        if not self.pending_plan:
            return ""
        title = self.pending_plan.get("title") or "任务计划"
        steps = self.pending_plan.get("steps") or []
        body = "\n".join(f"  {i + 1}. {s}" for i, s in enumerate(steps))
        return f"【任务计划】{title}\n{body}"

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
        allowed_tools = self.permission.allowed_tools(self.permission.level)
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

    def grant_pending_permission(self, session: bool = False) -> bool:
        """用户批准权限申请

        session=True 表示用户选了"本次会话都允许"：本会话内不再重复询问。
        terminal_exec 这类 CONFIRM_TOOLS 会被 grant_session 降级回单次授权，
        所以这里不需要额外判断。
        """
        if not self.pending_permission:
            return False
        target = self.pending_permission.get("tool", "")
        if target:
            if session:
                self.permission.grant_session(target)
            else:
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
        if self.session_log:
            self.session_log.record_guard(guard_result.failed_rule,
                                          guard_result.action, str(guard_result.details)[:200])
        return {
            "status": "GUARD_VIOLATION",
            "message": f"守门拦截: {guard_result.failed_rule}",
            "rule": guard_result.failed_rule,
            "action": guard_result.action,
            "details": guard_result.details,
            "instruction": "请修正输出后重试"
        }

    def _rollback_current_snapshot(self, snapshot_id: Optional[str]) -> bool:
        """熔断回滚：仅回滚本轮创建的快照（防止回滚到过期快照破坏无关修改）

        返回是否真的回滚成功。这里不抛异常——调用点正在处理一次守门违规，
        抛出会把原始违规信息盖掉。但也不能静默：回滚失败意味着违规产生的写入
        还留在磁盘上，用户必须知道，否则"已回滚"是个假承诺。
        """
        if not (self.guardian and snapshot_id):
            return False
        try:
            ok = self.guardian.rollback(snapshot_id)
            if self.session_log:
                self.session_log.record_snapshot(K_SNAPSHOT_ROLLBACK, snapshot_id)
            if not ok:
                print(f"警告: 快照 {snapshot_id} 回滚未完成，改动仍在磁盘上，"
                      f"备份见 .guardian/rollback_backups/", file=sys.stderr)
            return ok
        except Exception as e:
            print(f"警告: 快照 {snapshot_id} 回滚失败（{e}），改动仍在磁盘上，请手动检查",
                  file=sys.stderr)
            return False


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
