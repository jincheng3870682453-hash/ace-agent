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
# 数据结构
# ============================================================

@dataclass
class ExecutionResult:
    """执行结果"""
    status: str = "success"           # success / error / guard_violation / bait_triggered / permission_denied
    data: Any = None
    error_code: str = ""
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# 常量配置
# ============================================================

WRITE_TOOLS = {
    "terminal_exec", "file_write", "file_delete", "file_move",
    "api_post", "code_execute", "browser_click", "browser_type",
    "db_write", "notify_send", "image_generate"
}

READ_TOOLS = {
    "terminal_view", "file_read", "api_get", "db_query", "search",
    "browser_screenshot", "math_calc", "datetime_now", "browser_open",
    "parse_document", "open_file", "edit_file",
    "plan_propose", "request_permission",
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
}

# terminal_view 只读白名单（修复：只读工具绝不允许 shell=True 执行任意命令）
READ_ONLY_COMMANDS = {"ls", "dir", "pwd", "cat", "type", "echo", "tree",
                      "where", "which", "date", "time", "ver"}
VERSION_ONLY_COMMANDS = {"python", "py", "pip", "node", "npm"}
VERSION_SUBCOMMANDS = {"--version", "-V"}
GIT_READONLY_SUBCOMMANDS = {"status", "log", "diff", "show", "ls-files", "rev-parse", "branch"}
SHELL_META_RE = re.compile(r"[|&;<>`$\n\r]")
MAX_CODE_LENGTH = 100_000
MAX_COMMAND_LENGTH = 4_000


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
            try:
                text = content_after_answer.lstrip()
                tool_call, json_end = json.JSONDecoder().raw_decode(text)
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

            except json.JSONDecodeError as e:
                result["error"] = f"JSON 解析失败: {e}"
                return result
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

class ToolExecutor:
    """实际执行工具调用"""

    def __init__(self, project_root: str = ".", sandbox_base: Optional[str] = None,
                 confine_files: bool = True, email_smtp: Optional[Dict] = None):
        self.project_root = Path(project_root).resolve()
        self.sandbox_base = sandbox_base  # code_execute 沙箱临时目录基路径（None = 系统临时目录）
        self.confine_files = confine_files  # 文件工具是否强制限制在项目目录内
        self.email_smtp = email_smtp or {}  # {"host","port","user","password","use_tls"}
        self.execution_log: List[Dict] = []

    def _confined(self, path: Path) -> Optional[Path]:
        """把路径解析并约束到项目目录内；越界（..、绝对路径逃逸、符号链接、跨盘符）返回 None"""
        resolved = (path if path.is_absolute() else self.project_root / path).resolve()
        # 盘符一致性检查（Windows）：防止 .. 把路径解析到其他盘符后混过校验
        try:
            if resolved.drive.lower() != self.project_root.drive.lower():
                return None
        except AttributeError:
            pass
        try:
            resolved.relative_to(self.project_root)
            return resolved
        except ValueError:
            return None

    def execute(self, tool_call: Dict[str, Any]) -> ExecutionResult:
        """执行单个工具调用"""
        tool_name = tool_call.get("tool", "")
        params = {k: v for k, v in tool_call.items() if k != "tool"}

        start_time = time.time()
        result: Optional[ExecutionResult] = None

        try:
            if tool_name == "parse_document":
                result = self._exec_parse_document(params)
            elif tool_name == "open_file":
                result = self._exec_open_file(params)
            elif tool_name == "edit_file":
                result = self._exec_edit_file(params)
            elif tool_name in ("file_read", "file_write", "file_delete", "file_move"):
                result = self._exec_file_ops(tool_name, params)
            elif tool_name == "terminal_view":
                result = self._exec_terminal_view(params)
            elif tool_name == "terminal_exec":
                result = self._exec_terminal_exec(params)
            elif tool_name == "code_execute":
                result = self._exec_code_execute(params)
            elif tool_name == "search":
                result = self._exec_search(params)
            elif tool_name == "browser_screenshot":
                result = self._exec_browser_screenshot(params)
            elif tool_name == "math_calc":
                result = self._exec_math_calc(params)
            elif tool_name == "datetime_now":
                result = self._exec_datetime_now(params)
            elif tool_name == "api_get":
                result = self._exec_api_get(params)
            elif tool_name == "api_post":
                result = self._exec_api_post(params)
            elif tool_name == "db_query":
                result = self._exec_db_query(params)
            elif tool_name == "db_write":
                result = self._exec_db_write(params)
            elif tool_name == "browser_open":
                result = self._exec_browser_open(params)
            elif tool_name == "browser_click":
                result = self._exec_browser_click(params)
            elif tool_name == "browser_type":
                result = self._exec_browser_type(params)
            elif tool_name == "notify_send":
                result = self._exec_notify_send(params)
            elif tool_name == "image_generate":
                result = self._exec_image_generate(params)
            else:
                result = ExecutionResult(
                    status="error",
                    error_code="400",
                    message=f"未知工具: {tool_name}"
                )
        except Exception as e:
            result = ExecutionResult(
                status="error",
                error_code="500",
                message=f"执行异常: {e}"
            )
        finally:
            elapsed = time.time() - start_time
            self.execution_log.append({
                "tool": tool_name,
                "params": params,
                "timestamp": time.time(),
                "elapsed": elapsed,
            })
            if isinstance(result, ExecutionResult):
                result.metadata.setdefault("elapsed", elapsed)
        return result

    def _exec_parse_document(self, params: Dict) -> ExecutionResult:
        """文档解析"""
        if not PARSER_AVAILABLE:
            return ExecutionResult(status="error", error_code="500",
                                   message="文档解析器未安装")
        file_path = params.get("path", "")
        force_ocr = params.get("force_ocr", False)
        result = parse_document(file_path, force_ocr=force_ocr)
        if result.success:
            return ExecutionResult(status="success", data=result.to_dict())
        else:
            return ExecutionResult(status="error", error_code="500",
                                   message=result.error)

    @staticmethod
    def _read_text_any(path: Path) -> str:
        """读取文本：UTF-8 优先，失败回退系统默认编码（如 GBK），避免中文被静默丢弃"""
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            import locale
            return path.read_text(encoding=locale.getpreferredencoding(False), errors="ignore")

    def _exec_file_ops(self, tool_name: str, params: Dict) -> ExecutionResult:
        """文件操作（默认限制在项目目录内，防路径穿越）"""
        path = Path(params.get("path", ""))
        if self.confine_files:
            path = self._confined(path)
            if path is None:
                return ExecutionResult(status="error", error_code="403",
                                       message="路径越界：文件操作仅允许在项目目录内")
        elif not path.is_absolute():
            path = self.project_root / path

        try:
            if tool_name == "file_read":
                if not path.exists():
                    return ExecutionResult(status="error", error_code="404",
                                           message=f"文件不存在: {path}")
                content = self._read_text_any(path)
                return ExecutionResult(status="success", data={"content": content, "path": str(path)})
            elif tool_name == "file_write":
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(params.get("content", ""), encoding="utf-8")
                return ExecutionResult(status="success", data={"path": str(path), "bytes_written": len(params.get("content", ""))})
            elif tool_name == "file_delete":
                if path.exists():
                    path.unlink()
                return ExecutionResult(status="success", data={"deleted": str(path)})
            elif tool_name == "file_move":
                src = Path(params.get("source", ""))
                dest = Path(params.get("dest", ""))
                if self.confine_files:
                    src = self._confined(src)
                    dest = self._confined(dest)
                    if src is None or dest is None:
                        return ExecutionResult(status="error", error_code="403",
                                               message="路径越界：文件操作仅允许在项目目录内")
                else:
                    if not src.is_absolute():
                        src = self.project_root / src
                    if not dest.is_absolute():
                        dest = self.project_root / dest
                if not src.exists():
                    return ExecutionResult(status="error", error_code="404",
                                           message=f"源文件不存在: {src}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                src.rename(dest)
                return ExecutionResult(status="success", data={"moved": str(src), "to": str(dest)})
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))

    @staticmethod
    def _split_cmd_windows(cmd: str) -> List[str]:
        """Windows 风格命令分词：空白分割 + 双引号分组，保留反斜杠路径（如 C:\\Users\\...）"""
        parts: List[str] = []
        cur: List[str] = []
        in_quote = False
        for ch in cmd:
            if ch == '"':
                in_quote = not in_quote
                continue
            if ch in " \t" and not in_quote:
                if cur:
                    parts.append("".join(cur))
                    cur = []
                continue
            cur.append(ch)
        if cur:
            parts.append("".join(cur))
        return parts

    def _exec_terminal_view(self, params: Dict) -> ExecutionResult:
        """只读终端查看：白名单命令 + 无 shell 执行（修复：readonly 不再能执行任意命令）"""
        cmd = (params.get("command") or "").strip()
        if not cmd:
            # 小模型常漏 command 参数：缺省列出项目目录，避免 400 死循环
            cmd = "ls -la"
        if len(cmd) > MAX_COMMAND_LENGTH:
            return ExecutionResult(status="error", error_code="400", message="命令过长")
        if SHELL_META_RE.search(cmd):
            return ExecutionResult(status="error", error_code="403",
                                   message="terminal_view 检测到 shell 元字符，已拦截（只读工具禁止管道/重定向/连接符）")
        import shlex
        try:
            if os.name == "nt":
                # Windows 专用分词：双引号分组 + 保留反斜杠路径（shlex 会吃掉 \ 且在空格处断开）
                parts = ToolExecutor._split_cmd_windows(cmd)
            else:
                parts = shlex.split(cmd)
        except ValueError as e:
            return ExecutionResult(status="error", error_code="400", message=f"命令解析失败: {e}")
        if not parts:
            return ExecutionResult(status="error", error_code="400", message="命令为空")
        base = parts[0].lower()

        # —— 原生实现的只读内建命令（完全不经过 shell）——
        if base in ("ls", "dir"):
            # 忽略常见列表参数（-l/-a/-la/--all、Windows 的 /b 等），支持 ~ 展开
            target_args = [p for p in parts[1:]
                           if not p.startswith("-") and not p.startswith("/")]
            target = target_args[0] if target_args else "."
            target = os.path.expanduser(target)
            # 支持通配符：ls *.py / dir /b *.py
            if any(ch in target for ch in "*?"):
                import glob
                pattern = target if os.path.isabs(target) else str(self.project_root / target)
                try:
                    matches = sorted(glob.glob(pattern))
                except Exception as e:
                    return ExecutionResult(status="error", error_code="500", message=str(e))
                lower_parts = [p.lower() for p in parts[1:]]
                bare = "/b" in lower_parts or "-1" in lower_parts
                if bare:
                    items = [os.path.basename(m) for m in matches]
                else:
                    items = [os.path.relpath(m, self.project_root)
                             if not os.path.isabs(target) else m
                             for m in matches]
                return ExecutionResult(status="success", data={
                    "stdout": "\n".join(items), "stderr": "", "returncode": 0})
            p = Path(target)
            if not p.is_absolute():
                p = self.project_root / p
            try:
                items = sorted(os.listdir(p))
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=str(e))
            return ExecutionResult(status="success", data={"stdout": "\n".join(items),
                                                           "stderr": "", "returncode": 0})
        if base == "pwd":
            return ExecutionResult(status="success", data={"stdout": str(self.project_root),
                                                           "stderr": "", "returncode": 0})
        if base in ("cat", "type"):
            if len(parts) < 2:
                return ExecutionResult(status="error", error_code="400", message="cat/type 需要文件参数")
            p = Path(os.path.expanduser(parts[1]))
            if not p.is_absolute():
                p = self.project_root / p
            try:
                content = self._read_text_any(p)
            except FileNotFoundError:
                return ExecutionResult(status="error", error_code="404", message=f"文件不存在: {p}")
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=str(e))
            return ExecutionResult(status="success", data={"stdout": content[:5000],
                                                           "stderr": "", "returncode": 0})
        if base == "echo":
            return ExecutionResult(status="success", data={"stdout": " ".join(parts[1:]),
                                                           "stderr": "", "returncode": 0})
        if base == "ver":
            import platform
            return ExecutionResult(status="success", data={"stdout": f"{platform.system()} {platform.release()}",
                                                           "stderr": "", "returncode": 0})
        if base in ("date", "time"):
            from datetime import datetime
            return ExecutionResult(status="success", data={"stdout": datetime.now().isoformat(),
                                                           "stderr": "", "returncode": 0})

        # —— 白名单外部命令 ——
        if base in VERSION_ONLY_COMMANDS:
            # 严格校验：只允许恰好两个 token 的版本查询，防止 "-v -c 代码" 注入
            if len(parts) != 2 or parts[1] not in VERSION_SUBCOMMANDS:
                return ExecutionResult(status="error", error_code="403",
                                       message=f"{base} 仅允许查询版本（--version / -V，且不允许附加任何参数）")
        elif base == "git":
            if len(parts) < 2 or parts[1].lower() not in GIT_READONLY_SUBCOMMANDS:
                return ExecutionResult(status="error", error_code="403",
                                       message=f"git 仅允许只读子命令: {sorted(GIT_READONLY_SUBCOMMANDS)}")
        elif base not in READ_ONLY_COMMANDS:
            return ExecutionResult(status="error", error_code="403",
                                   message=f"命令 '{base}' 不在 terminal_view 白名单中（只读工具）")
        import subprocess
        try:
            result = subprocess.run(parts, capture_output=True, text=True, timeout=30,
                                    cwd=str(self.project_root), shell=False,
                                    stdin=subprocess.DEVNULL)
            return ExecutionResult(status="success", data={
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            })
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504", message="命令执行超时（30 秒）")
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))

    def _exec_terminal_exec(self, params: Dict) -> ExecutionResult:
        """写入权限下的真实终端执行（受权限门 + 快照回滚保护）"""
        cmd = (params.get("command") or "").strip()
        if not cmd:
            return ExecutionResult(status="error", error_code="400", message="command 参数为空")
        if len(cmd) > MAX_COMMAND_LENGTH:
            return ExecutionResult(status="error", error_code="400", message="命令过长")
        import subprocess
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                    timeout=30, cwd=str(self.project_root),
                                    stdin=subprocess.DEVNULL)
            return ExecutionResult(status="success", data={
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            })
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504", message="命令执行超时（30 秒）")
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))

    DANGEROUS_CALLS = {
        "os.system", "os.popen", "os.spawnl", "os.spawnv", "os.execl", "os.execv",
        "subprocess.call", "subprocess.run", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "socket.socket", "socket.connect", "socket.create_connection",
        "shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    }
    # 整模块禁用导入（含别名导入、from x import y），封死逃逸链
    DANGEROUS_MODULES = {"subprocess", "socket", "ctypes", "os", "shutil",
                         "importlib", "pickle", "marshal", "multiprocessing",
                         "pty", "builtins", "sys"}
    DANGEROUS_FUNCS = {"eval", "exec", "compile", "__import__",
                       "globals", "locals", "vars", "getattr", "setattr",
                       "delattr", "input", "breakpoint"}
    DANGEROUS_NAMES = {"__builtins__", "__loader__", "__spec__", "__import__"}
    DANGEROUS_ATTRS = {"__class__", "__bases__", "__subclasses__", "__globals__",
                       "__mro__", "__builtins__", "__code__", "__dict__"}

    @staticmethod
    def _qualname(node) -> str:
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))

    def _scan_dangerous_calls(self, code: str) -> str:
        """策略层沙箱 AST 扫描：拦截危险导入/调用/内建逃逸，返回拦截描述（空串 = 通过）

        注意：这是进程内静态策略层，不是 OS 级隔离；生产环境请配合容器/虚拟机使用。
        """
        try:
            import ast
            tree = ast.parse(code)
        except SyntaxError:
            return ""   # 语法错误交给 ASTDetector 报告
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in self.DANGEROUS_MODULES:
                        return f"沙箱禁止导入模块: {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in self.DANGEROUS_MODULES:
                    return f"沙箱禁止导入模块: {node.module}"
            elif isinstance(node, ast.Name):
                if node.id in self.DANGEROUS_NAMES:
                    return f"沙箱禁止访问内建对象: {node.id}"
            elif isinstance(node, ast.Attribute):
                if node.attr in self.DANGEROUS_ATTRS:
                    return f"沙箱禁止访问: .{node.attr}"
            elif isinstance(node, ast.Call):
                name = ""
                f = node.func
                if isinstance(f, ast.Name):
                    name = f.id
                elif isinstance(f, ast.Attribute):
                    name = self._qualname(f)
                if name in self.DANGEROUS_CALLS or name in self.DANGEROUS_FUNCS:
                    return f"沙箱禁止调用: {name}"
                if name == "open":
                    return "沙箱内禁止使用 open()（文件读写请使用 file_read/file_write 工具）"
        return ""

    def _exec_code_execute(self, params: Dict) -> ExecutionResult:
        """代码执行（受限沙箱：AST 危险调用拦截 + 临时目录 + 环境变量清洗 + 超时）"""
        lang = params.get("language", "python")
        code = params.get("code", "")
        if lang != "python":
            return ExecutionResult(status="error", error_code="400",
                                   message=f"暂不支持语言: {lang}")
        if not code.strip():
            return ExecutionResult(status="error", error_code="400", message="code 参数为空")
        if len(code) > MAX_CODE_LENGTH:
            return ExecutionResult(status="error", error_code="400", message="代码过长（上限 100KB）")

        # 沙箱 1：AST 危险调用拦截
        denied = self._scan_dangerous_calls(code)
        if denied:
            return ExecutionResult(status="error", error_code="403", message=denied)

        import subprocess
        import uuid
        base = Path(self.sandbox_base) if self.sandbox_base else Path(tempfile.gettempdir())
        sandbox_dir = base / f"agent_sandbox_{uuid.uuid4().hex[:8]}"
        try:
            sandbox_dir.mkdir(parents=True)
        except Exception as e:
            return ExecutionResult(status="error", error_code="500",
                                   message=f"沙箱目录创建失败: {e}")
        tmp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False,
                                             encoding="utf-8", dir=sandbox_dir) as f:
                f.write(code)
                tmp_file = f.name
            # 沙箱 2：最小环境变量（剥离密钥/代理等敏感信息）
            minimal_env = {
                "PATH": os.environ.get("PATH", ""),
                "SystemRoot": os.environ.get("SystemRoot", ""),
                "WINDIR": os.environ.get("WINDIR", ""),
                "TEMP": str(sandbox_dir),
                "TMP": str(sandbox_dir),
                "COMSPEC": os.environ.get("COMSPEC", ""),
                "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": "",
            }
            # 沙箱 3：临时工作目录（相对路径写入落在沙箱内）+ 超时
            result = subprocess.run(
                [sys.executable, tmp_file],
                capture_output=True, text=True, timeout=30,
                cwd=sandbox_dir, env=minimal_env, shell=False,
                stdin=subprocess.DEVNULL
            )
            return ExecutionResult(status="success", data={
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "sandbox": {"cwd": str(sandbox_dir), "env_stripped": True, "timeout": 30}
            })
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504", message="代码执行超时（30 秒）")
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))
        finally:
            if tmp_file:
                try:
                    os.unlink(tmp_file)
                except OSError:
                    pass
            try:
                shutil.rmtree(sandbox_dir, ignore_errors=True)
            except Exception:
                pass

    # ---------- 真实联网搜索（DuckDuckGo → Bing 兜底，无需 API Key） ----------

    @staticmethod
    def _clean_html(seg: str) -> str:
        return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", seg))).strip()

    @staticmethod
    def _parse_ddg(html_text: str, top_k: int) -> List[Dict]:
        """解析 DuckDuckGo HTML 搜索结果"""
        out: List[Dict] = []
        for m in re.finditer(
                r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                html_text, re.DOTALL):
            url = html.unescape(m.group(1))   # 先还原 &amp; 等实体再解析
            title = ToolExecutor._clean_html(m.group(2))
            if "uddg=" in url:   # DDG 跳转链接解码
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                url = qs.get("uddg", [url])[0]
            if url.startswith("//"):
                url = "https:" + url
            out.append({"title": title, "url": url, "snippet": ""})
            if len(out) >= top_k:
                break
        snippets = re.findall(
            r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>', html_text, re.DOTALL)
        for i, sn in enumerate(snippets[:len(out)]):
            out[i]["snippet"] = ToolExecutor._clean_html(sn)
        return out

    @staticmethod
    def _parse_bing(html_text: str, top_k: int) -> List[Dict]:
        """解析 Bing 搜索结果"""
        out: List[Dict] = []
        for m in re.finditer(
                r'<li class="b_algo".*?<h2><a[^>]*href="([^"]+)"[^>]*>(.*?)</a></h2>(.*?)</li>',
                html_text, re.DOTALL):
            url = m.group(1)
            title = ToolExecutor._clean_html(m.group(2))
            p = re.search(r"<p[^>]*>(.*?)</p>", m.group(3), re.DOTALL)
            snippet = ToolExecutor._clean_html(p.group(1)) if p else ""
            out.append({"title": title, "url": url, "snippet": snippet})
            if len(out) >= top_k:
                break
        return out

    @staticmethod
    def _search_engine(engine_url: str, query: str, top_k: int,
                       requests, parser) -> List[Dict]:
        try:
            resp = requests.get(
                engine_url, params={"q": query},
                headers={"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                                        "Chrome/124.0 Safari/537.36")},
                timeout=15)
        except Exception:
            return []
        if resp.status_code != 200 or not resp.text:
            return []
        return parser(resp.text, top_k)

    def _exec_search(self, params: Dict) -> ExecutionResult:
        """真实联网搜索（DuckDuckGo HTML → Bing 兜底，无需 API Key）"""
        query = str(params.get("query", "")).strip()
        if not query:
            return ExecutionResult(status="error", error_code="400", message="query 参数为空")
        try:
            top_k = max(1, min(int(params.get("top_k", 5)), 10))
        except (TypeError, ValueError):
            top_k = 5
        try:
            import requests
        except ImportError:
            return ExecutionResult(status="error", error_code="500",
                                   message="search 需要 requests 库: pip install requests")
        results = self._search_engine(
            "https://html.duckduckgo.com/html/", query, top_k, requests, self._parse_ddg)
        engine = "duckduckgo"
        if not results:
            results = self._search_engine(
                "https://www.bing.com/search", query, top_k, requests, self._parse_bing)
            engine = "bing"
        if not results:
            return ExecutionResult(status="error", error_code="500",
                                   message="联网搜索失败（无网络或搜索源拒绝访问），请稍后重试")
        return ExecutionResult(status="success", data={
            "query": query,
            "engine": engine,
            "results": results,
            "network_status": "ON",
        })

    def _exec_browser_screenshot(self, params: Dict) -> ExecutionResult:
        """屏幕截图：优先 pillow ImageGrab；Windows 无 pillow 时用 PowerShell 免依赖回退"""
        shot_dir = self.project_root / ".ace_shots"
        shot_dir.mkdir(parents=True, exist_ok=True)
        shot_path = shot_dir / f"shot_{int(time.time() * 1000)}.png"
        try:
            from PIL import ImageGrab
            try:
                img = ImageGrab.grab()
                img.save(str(shot_path))
                return ExecutionResult(status="success", data={
                    "image_path": str(shot_path), "format": "png", "engine": "pillow"})
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=f"截图失败: {e}")
        except ImportError:
            pass
        # Windows 免依赖回退：PowerShell System.Drawing 屏幕抓取
        if os.name == "nt":
            import subprocess
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
                "$b=[System.Windows.Forms.SystemInformation]::VirtualScreen;"
                "$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height;"
                "$g=[System.Drawing.Graphics]::FromImage($bmp);"
                "$g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size);"
                f"$bmp.Save('{str(shot_path)}');$g.Dispose();$bmp.Dispose()"
            )
            try:
                subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, timeout=30, check=True)
                if shot_path.exists():
                    return ExecutionResult(status="success", data={
                        "image_path": str(shot_path), "format": "png", "engine": "powershell"})
            except Exception as e:
                return ExecutionResult(status="error", error_code="500",
                                       message=f"截图失败: {e}")
        return ExecutionResult(status="error", error_code="500",
                               message="browser_screenshot 需要 pillow（Windows 可免依赖，"
                                       "其他平台请 pip install pillow）")

    def _exec_math_calc(self, params: Dict) -> ExecutionResult:
        expression = str(params.get("expression", ""))
        denied = self._scan_math_expression(expression)
        if denied:
            return ExecutionResult(status="error", error_code="403", message=denied)
        try:
            result = eval(expression, {"__builtins__": {}}, {})
            return ExecutionResult(status="success", data={"result": result, "expression": expression})
        except Exception as e:
            return ExecutionResult(status="error", error_code="400", message=str(e))

    @staticmethod
    def _scan_math_expression(expression: str) -> str:
        """白名单 AST 校验：只允许纯算术表达式，防任意代码执行与指数 DoS"""
        if not expression or len(expression) > 200:
            return "表达式为空或过长（上限 200 字符）"
        try:
            import ast as _ast
            tree = _ast.parse(expression, mode="eval")
        except SyntaxError:
            return ""   # 语法错误交给 eval 返回 400
        ALLOWED_NODES = (_ast.Expression, _ast.Constant)
        # 运算符节点放行（安全性由 BinOp/UnaryOp 级别的特判把关）
        ALLOWED_OPS = (_ast.Add, _ast.Sub, _ast.Mult, _ast.Div,
                       _ast.FloorDiv, _ast.Mod, _ast.Pow, _ast.UAdd, _ast.USub)
        for node in _ast.walk(tree):
            if isinstance(node, ALLOWED_NODES) or isinstance(node, ALLOWED_OPS):
                continue
            if isinstance(node, (_ast.BinOp, _ast.UnaryOp)):
                if isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.Pow):
                    def _small(n):
                        return (isinstance(n, _ast.Constant)
                                and isinstance(n.value, (int, float))
                                and abs(n.value) <= 100)
                    if _small(node.left) and _small(node.right) \
                            and abs(node.right.value) <= 1000:
                        continue
                    return "幂运算仅支持 100^1000 以内的常量运算"
                continue
            return f"math_calc 只允许纯算术表达式，禁止: {type(node).__name__}"
        return ""

    def _exec_datetime_now(self, params: Dict) -> ExecutionResult:
        from datetime import datetime
        fmt = params.get("format", "%Y-%m-%d %H:%M:%S")
        # 支持 prompt 中的 "YYYY-MM-DD HH:mm:ss" 友好格式
        fmt = (str(fmt)
               .replace("YYYY", "%Y").replace("DD", "%d").replace("HH", "%H")
               .replace("MM", "%m").replace("mm", "%M").replace("ss", "%S"))
        try:
            now = datetime.now().strftime(fmt)
        except ValueError as e:
            return ExecutionResult(status="error", error_code="400", message=str(e))
        return ExecutionResult(status="success", data={"datetime": now})

    @staticmethod
    def _check_url(url: str) -> Optional[str]:
        """URL 协议校验 + 私网地址防护（DNS 解析后拦截内网/回环/链路本地，防 SSRF）"""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
        except Exception:
            return "URL 解析失败"
        if not scheme:
            return "URL 缺少协议（需要 http/https）"
        if scheme not in ("http", "https"):
            return f"仅支持 http/https 协议，拒绝: {scheme}"
        host = parsed.hostname
        if host:
            try:
                import socket
                for info in socket.getaddrinfo(host, None):
                    ip = info[4][0].split("%")[0]
                    try:
                        addr = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if (addr.is_private or addr.is_loopback or addr.is_link_local
                            or addr.is_multicast or addr.is_reserved
                            or addr.is_unspecified
                            or (addr.version == 4 and ip.startswith("100.64."))):
                        return f"拒绝访问内网/回环/链路本地地址: {ip}"
                    break   # 首个公网解析结果即放行
            except Exception:
                pass
        return None

    def _exec_api_get(self, params: Dict) -> ExecutionResult:
        url = str(params.get("url", ""))
        url_err = self._check_url(url)
        if url_err:
            return ExecutionResult(status="error", error_code="400", message=url_err)
        try:
            import requests
            resp = requests.get(url, timeout=30)
            return ExecutionResult(status="success", data={
                "status_code": resp.status_code,
                "content": resp.text[:5000]
            })
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))

    def _exec_api_post(self, params: Dict) -> ExecutionResult:
        url = str(params.get("url", ""))
        url_err = self._check_url(url)
        if url_err:
            return ExecutionResult(status="error", error_code="400", message=url_err)
        try:
            import requests
            resp = requests.post(url, json=params.get("data", {}), timeout=30)
            return ExecutionResult(status="success", data={
                "status_code": resp.status_code,
                "content": resp.text[:5000]
            })
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))

    def _exec_db_query(self, params: Dict) -> ExecutionResult:
        """SQLite 只读查询（仅 SELECT/WITH），返回列名+行数据，上限 100 行"""
        query = str(params.get("query", "")).strip()
        if not query:
            return ExecutionResult(status="error", error_code="400", message="query 参数为空")
        m = re.match(r"(?is)^\s*(select|with)\b", query)
        if not m:
            return ExecutionResult(status="error", error_code="403",
                                   message="db_query 仅允许只读查询（SELECT/WITH）")
        if m.group(1).lower() == "with" and not re.search(r"(?is)\bselect\b", query):
            return ExecutionResult(status="error", error_code="403",
                                   message="db_query 的 WITH 必须包含 SELECT（禁止借道写入）")
        import sqlite3
        db_path = self.project_root / "agent.db"
        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            try:
                cur = conn.cursor()
                cur.execute(query)
                fetched = cur.fetchmany(101)
                columns = [d[0] for d in cur.description] if cur.description else []
            finally:
                conn.close()
        except sqlite3.Error as e:
            return ExecutionResult(status="error", error_code="400", message=f"查询失败: {e}")
        truncated = len(fetched) > 100
        rows = [list(r) for r in fetched[:100]]
        return ExecutionResult(status="success", data={
            "columns": columns, "rows": rows,
            "row_count": len(rows), "truncated": truncated, "db": str(db_path),
        })

    def _exec_db_write(self, params: Dict) -> ExecutionResult:
        """SQLite 写入（INSERT/UPDATE/DELETE/REPLACE/CREATE/ALTER），危险操作拒绝"""
        query = str(params.get("query", "")).strip()
        if not query:
            return ExecutionResult(status="error", error_code="400", message="query 参数为空")
        if re.match(r"(?is)^\s*(select|with)\b", query):
            return ExecutionResult(status="error", error_code="400",
                                   message="只读查询请使用 db_query 工具")
        if re.search(r"(?i)\b(drop|attach|detach|pragma|vacuum|reindex|load_extension)\b", query):
            return ExecutionResult(status="error", error_code="403",
                                   message="db_write 拒绝危险操作（DROP/ATTACH/PRAGMA/VACUUM 等）")
        if not re.match(r"(?is)^\s*(insert|update|delete|replace|create|alter)\b", query):
            return ExecutionResult(status="error", error_code="400",
                                   message="不支持的语句类型（支持 INSERT/UPDATE/DELETE/REPLACE/CREATE/ALTER）")
        import sqlite3
        db_path = self.project_root / "agent.db"
        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            try:
                cur = conn.cursor()
                cur.execute(query)
                conn.commit()
                affected = cur.rowcount
            finally:
                conn.close()
        except sqlite3.Error as e:
            return ExecutionResult(status="error", error_code="400", message=f"写入失败: {e}")
        return ExecutionResult(status="success", data={
            "affected_rows": affected, "db": str(db_path)})

    def _exec_browser_open(self, params: Dict) -> ExecutionResult:
        """用系统默认浏览器打开 URL（真实实现，仅 http/https）"""
        url = str(params.get("url", ""))
        url_err = self._check_url(url)
        if url_err:
            return ExecutionResult(status="error", error_code="400", message=url_err)
        import webbrowser
        try:
            ok = webbrowser.open(url)
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))
        return ExecutionResult(status="success", data={"url": url, "opened": bool(ok)})

    def _resolve_read_path(self, path_str: str) -> Optional[Path]:
        """解析对话内文件路径：支持 ~ 展开与相对项目路径"""
        p = Path(os.path.expanduser(path_str))
        if not p.is_absolute():
            p = self.project_root / p
        return p.resolve()

    def _exec_open_file(self, params: Dict) -> ExecutionResult:
        """对话内打开文件：默认返回可点击链接（用户点击后全屏查看）；
        auto_open=true 时立即用系统默认程序打开"""
        path_str = str(params.get("path", "")).strip()
        if not path_str:
            return ExecutionResult(status="error", error_code="400", message="path 参数为空")
        p = self._resolve_read_path(path_str)
        if not p.exists():
            return ExecutionResult(status="error", error_code="404", message=f"文件不存在: {p}")
        if not bool(params.get("auto_open", False)):
            # 默认收起：只给链接，用户点击才打开
            return ExecutionResult(status="success", data={
                "path": str(p), "opened": False, "link": p.as_uri(),
                "hint": "已生成可点击链接，用户点击后即可全屏查看"})
        import subprocess
        try:
            if os.name == "nt":
                os.startfile(str(p))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=f"打开失败: {e}")
        return ExecutionResult(status="success", data={"path": str(p), "opened": True})

    def _exec_edit_file(self, params: Dict) -> ExecutionResult:
        """对话内编辑文件：优先 VS Code（code 命令），否则回退系统默认程序"""
        path_str = str(params.get("path", "")).strip()
        if not path_str:
            return ExecutionResult(status="error", error_code="400", message="path 参数为空")
        p = self._resolve_read_path(path_str)
        if not p.exists():
            return ExecutionResult(status="error", error_code="404",
                                   message=f"文件不存在: {p}（可先用 file_write 创建）")
        import subprocess
        code = shutil.which("code")
        if code:
            try:
                subprocess.Popen([code, str(p)])
                return ExecutionResult(status="success",
                                       data={"path": str(p), "editor": "vscode"})
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=f"打开失败: {e}")
        try:
            if os.name == "nt":
                os.startfile(str(p))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=f"打开失败: {e}")
        return ExecutionResult(status="success", data={"path": str(p), "editor": "system_default"})

    def _exec_browser_click(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="browser_click 尚未接入浏览器（POC 占位）")

    def _exec_browser_type(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="browser_type 尚未接入浏览器（POC 占位）")

    def _exec_notify_send(self, params: Dict) -> ExecutionResult:
        """发送通知：channel = console / file / toast（toast 可选 plyer；email 未接入）"""
        channel = str(params.get("channel", "console")).lower()
        to = str(params.get("to", ""))
        content = str(params.get("content", ""))
        if not content:
            return ExecutionResult(status="error", error_code="400", message="content 参数为空")
        if channel in ("console", "stdout"):
            print(f"[ACE 通知] {content}")
            return ExecutionResult(status="success", data={"channel": channel, "delivered": True})
        if channel == "file":
            log_path = self.project_root / "notifications.log"
            try:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {to or '-'}: {content}\n")
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=str(e))
            return ExecutionResult(status="success", data={
                "channel": "file", "path": str(log_path), "delivered": True})
        if channel == "toast":
            try:
                from plyer import notification
                notification.notify(title=to or "ACE", message=content[:200], timeout=5)
            except ImportError:
                return ExecutionResult(status="error", error_code="500",
                                       message="toast 通知需要 plyer（pip install plyer）")
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=f"toast 失败: {e}")
            return ExecutionResult(status="success", data={"channel": "toast", "delivered": True})
        if channel == "email":
            smtp = self.email_smtp or {}
            host = smtp.get("host", "")
            user = smtp.get("user", "")
            if not host or not user:
                return ExecutionResult(
                    status="error", error_code="501",
                    message="email 通知需要 SMTP 配置（config: email_smtp={host,port,user,password,use_tls}）")
            try:
                import smtplib
                from email.mime.text import MIMEText
            except ImportError:
                return ExecutionResult(status="error", error_code="500",
                                       message="email 通知需要 smtplib（标准库）")
            msg = MIMEText(content, "plain", "utf-8")
            msg["Subject"] = to or "ACE 通知"
            msg["From"] = user
            msg["To"] = to
            try:
                port = int(smtp.get("port", 587))
                with smtplib.SMTP(host, port, timeout=15) as server:
                    if smtp.get("use_tls", True):
                        server.starttls()
                    if smtp.get("password"):
                        server.login(user, smtp["password"])
                    server.send_message(msg)
            except Exception as e:
                return ExecutionResult(status="error", error_code="500",
                                       message=f"email 发送失败: {e}")
            return ExecutionResult(status="success", data={
                "channel": "email", "to": to, "delivered": True, "host": host})
        return ExecutionResult(status="error", error_code="400",
                               message=f"未知通知渠道: {channel}（支持 console/file/toast）")

    def _exec_image_generate(self, params: Dict) -> ExecutionResult:
        """真实图像生成（pollinations.ai 免费端点，无需密钥），保存到项目 .ace_images/"""
        prompt = str(params.get("prompt", "")).strip()
        if not prompt:
            return ExecutionResult(status="error", error_code="400", message="prompt 参数为空")
        size = str(params.get("size", "512x512"))
        m = re.match(r"^(\d{2,4})x(\d{2,4})$", size)
        if not m:
            return ExecutionResult(status="error", error_code="400",
                                   message=f"size 格式应为 宽x高（如 512x512），收到: {size}")
        width, height = m.group(1), m.group(2)
        try:
            import requests
        except ImportError:
            return ExecutionResult(status="error", error_code="500",
                                   message="image_generate 需要 requests 库: pip install requests")
        img_dir = self.project_root / ".ace_images"
        img_dir.mkdir(parents=True, exist_ok=True)
        img_path = img_dir / f"gen_{int(time.time() * 1000)}.png"
        url = (f"https://image.pollinations.ai/prompt/{urllib.parse.quote(prompt)}"
               f"?width={width}&height={height}&nologo=true")
        try:
            resp = requests.get(url, timeout=60)
            resp.raise_for_status()
            img_path.write_bytes(resp.content)
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=f"图像生成失败: {e}")
        return ExecutionResult(status="success", data={
            "image_path": str(img_path), "size": f"{width}x{height}",
            "bytes": len(resp.content), "service": "pollinations.ai",
        })


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
        lines = ["[记忆注入] 以下是相关的历史对话记忆："]
        for m in self._last_memory_list:
            mark = "⚑" if m.get("urgent") else "·"
            lines.append(f"{mark} {m['text']}")
        return "\n".join(lines) + "\n\n" + user_input

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

        # 5. 权限裁决（执行层说了算）
        if not self.permission.can_execute(tool_name):
            return {
                "status": "403",
                "message": f"权限不足: 工具 '{tool_name}' 需要更高权限",
                "current_permission": self.permission.get_status(),
                "instruction": "请调用 request_permission 向用户申请该工具的临时授权",
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
            elif result.error_code == "400" and tool_name in TOOL_EXAMPLES:
                # 参数缺失/格式错误：直接给模型一个可抄的示例
                extra_instruction = f"参数格式示例: {TOOL_EXAMPLES[tool_name]}"
            return {
                "status": result.error_code or "ERROR",
                "message": result.message,
                "tool": tool_name,
                "internal": parsed["internal"],
                "memory_injected": injected_memory or None,
                "instruction": extra_instruction,
                **route_meta,
            }

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
            "instruction": "等待用户批准：批准后按计划逐步执行；拒绝则调整方案",
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
            return {
                "status": "FORMAT_ERROR",
                "message": "request_permission 需要 target 参数",
                "instruction": '示例: {"tool": "request_permission", "target": "terminal_exec", "reason": "..."}',
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

    def _rollback_current_snapshot(self, snapshot_id: Optional[str]) -> None:
        """熔断回滚：仅回滚本轮创建的快照（防止回滚到过期快照破坏无关修改）"""
        if self.guardian and snapshot_id:
            try:
                self.guardian.rollback(snapshot_id)
            except Exception:
                pass

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
