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
import json
import shutil
import time
import tempfile
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
    "parse_document"
}

HIGH_RISK_TOOLS = {
    "terminal_dangerous", "db_drop"
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
            # 模式 A：提取 JSON
            try:
                # 找到匹配的 }
                brace_count = 0
                json_end = 0
                in_string = False
                escape = False
                for i, char in enumerate(content_after_answer):
                    if escape:
                        escape = False
                        continue
                    if char == "\\":
                        escape = True
                        continue
                    if char == '"' and not escape:
                        in_string = not in_string
                        continue
                    if not in_string:
                        if char == "{":
                            brace_count += 1
                        elif char == "}":
                            brace_count -= 1
                            if brace_count == 0:
                                json_end = i + 1
                                break

                if json_end == 0:
                    result["error"] = "JSON 括号不匹配"
                    return result

                json_str = content_after_answer[:json_end]
                remaining = content_after_answer[json_end:].strip()

                # 检查 JSON 后是否有非空白字符
                if remaining:
                    result["error"] = f"JSON 后存在多余内容: {remaining[:50]}"
                    return result

                tool_call = json.loads(json_str)
                if not isinstance(tool_call, dict):
                    result["error"] = "工具调用必须是 JSON 对象（如 {\"tool\": \"...\"}）"
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
                 confine_files: bool = True):
        self.project_root = Path(project_root).resolve()
        self.sandbox_base = sandbox_base  # code_execute 沙箱临时目录基路径（None = 系统临时目录）
        self.confine_files = confine_files  # 文件工具是否强制限制在项目目录内
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

    def _exec_terminal_view(self, params: Dict) -> ExecutionResult:
        """只读终端查看：白名单命令 + 无 shell 执行（修复：readonly 不再能执行任意命令）"""
        cmd = (params.get("command") or "").strip()
        if not cmd:
            return ExecutionResult(status="error", error_code="400", message="command 参数为空")
        if len(cmd) > MAX_COMMAND_LENGTH:
            return ExecutionResult(status="error", error_code="400", message="命令过长")
        if SHELL_META_RE.search(cmd):
            return ExecutionResult(status="error", error_code="403",
                                   message="terminal_view 检测到 shell 元字符，已拦截（只读工具禁止管道/重定向/连接符）")
        import shlex
        try:
            parts = shlex.split(cmd)
        except ValueError as e:
            return ExecutionResult(status="error", error_code="400", message=f"命令解析失败: {e}")
        if not parts:
            return ExecutionResult(status="error", error_code="400", message="命令为空")
        base = parts[0].lower()

        # —— 原生实现的只读内建命令（完全不经过 shell）——
        if base in ("ls", "dir"):
            target = parts[1] if len(parts) > 1 else "."
            p = self._confined(Path(target)) if self.confine_files else (
                Path(target) if Path(target).is_absolute() else self.project_root / Path(target))
            if p is None:
                return ExecutionResult(status="error", error_code="403",
                                       message="路径越界：ls 仅允许查看项目目录")
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
            p = self._confined(Path(parts[1])) if self.confine_files else (
                Path(parts[1]) if Path(parts[1]).is_absolute() else self.project_root / Path(parts[1]))
            if p is None:
                return ExecutionResult(status="error", error_code="403",
                                       message="路径越界：cat 仅允许查看项目内文件")
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
                "sandbox": {"cwd": sandbox_dir, "env_stripped": True, "timeout": 30}
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

    def _exec_search(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="search 尚未接入真实搜索服务（POC 占位）")

    def _exec_browser_screenshot(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="browser_screenshot 尚未接入浏览器（POC 占位）")

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
        """URL 协议校验：仅允许 http/https（防 SSRF 类协议滥用），返回错误描述"""
        from urllib.parse import urlparse
        try:
            scheme = urlparse(url).scheme.lower()
        except Exception:
            return "URL 解析失败"
        if not scheme:
            return "URL 缺少协议（需要 http/https）"
        if scheme not in ("http", "https"):
            return f"仅支持 http/https 协议，拒绝: {scheme}"
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
        return ExecutionResult(status="error", error_code="501",
                               message="db_query 尚未接入数据库（POC 占位）")

    def _exec_db_write(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="db_write 尚未接入数据库（POC 占位）")

    def _exec_browser_open(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="browser_open 尚未接入浏览器（POC 占位）")

    def _exec_browser_click(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="browser_click 尚未接入浏览器（POC 占位）")

    def _exec_browser_type(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="browser_type 尚未接入浏览器（POC 占位）")

    def _exec_notify_send(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="notify_send 尚未接入通知服务（POC 占位）")

    def _exec_image_generate(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="image_generate 尚未接入图像模型（POC 占位）")


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

        # 1. 解析 Agent 输出
        parsed = self.parser.parse(agent_output)
        if not parsed["valid"]:
            return {
                "status": "FORMAT_ERROR",
                "message": f"格式错误: {parsed['error']}",
                "instruction": "请严格按照 <INTERNAL>...</INTERNAL><EXTERNAL>answer...</EXTERNAL> 格式输出"
            }

        # 2. 记录到 Archive（SimHash 记忆）
        if self.archive:
            self.archive.add(user_input)
            shift = self.archive.detect_topic_shift(user_input)
            if shift == "shifted":
                # 主题切换：注入相关记忆到上下文（排除刚写入的当前消息）
                injected_memory = self.archive.get_memory(top_k=3, exclude_last=True)

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

        # 5. 权限裁决（执行层说了算）
        if not self.permission.can_execute(tool_name):
            return {
                "status": "403",
                "message": f"权限不足: 工具 '{tool_name}' 需要更高权限",
                "current_permission": self.permission.get_status(),
                "instruction": "请在 <EXTERNAL> 中以模式 B 输出权限申请"
            }

        # 6. code_execute 专属安全闸门：诱饵验证 + AST 检测（work.py）
        if tool_name == "code_execute":
            gate = self._gate_code_execute(tool_call)
            if not gate["ok"]:
                return gate["result"]

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
                "memory_injected": injected_memory or None
            }
        else:
            return {
                "status": result.error_code or "ERROR",
                "message": result.message,
                "tool": tool_name,
                "internal": parsed["internal"],
                "memory_injected": injected_memory or None
            }

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

        # b. AST 行为检测（未用导入/类型注解/递归/密钥/SQL）
        if self.ast_detector:
            report = self.ast_detector.check_all(code)
            if not all(report.values()):
                self.ast_fail_count += 1
                failed = [k for k, v in report.items() if not v]
                return {"ok": False, "result": {
                    "status": "AST_FAILED",
                    "message": f"AST 检测失败: {failed}",
                    "report": report,
                    "attempt": self.ast_fail_count,
                    "stop_retry": self.ast_fail_count >= 3,
                    "instruction": "请修正代码中的结构性问题后重新调用 code_execute（同一问题最多重试 3 次）"
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
