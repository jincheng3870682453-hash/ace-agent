#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.base —— 工具执行基类：共享助手 + execute 分发"""

import os
import re
import sys
import time
import tempfile
import shutil
import subprocess
import ipaddress
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.result import ExecutionResult

SHELL_META_RE = re.compile(r"[|&;<>`$\n\r]")
MAX_CODE_LENGTH = 100_000
MAX_COMMAND_LENGTH = 4_000
READ_ONLY_COMMANDS = {"ls", "dir", "pwd", "cat", "type", "echo", "tree",
                      "where", "which", "date", "time", "ver"}
VERSION_ONLY_COMMANDS = {"python", "py", "pip", "node", "npm"}
VERSION_SUBCOMMANDS = {"--version", "-V"}
GIT_READONLY_SUBCOMMANDS = {"status", "log", "diff", "show",
                             "ls-files", "rev-parse", "branch"}

# Windows 路径反斜杠修复：模型把 C:\Users\... 直接写进 JSON 时，
# \U、\6 等是非法转义，json.loads 会失败导致整个工具调用被丢弃。
_WIN_PATH_BACKSLASH_RE = re.compile(r'\\([^"\\/bfnrtu])')


def repair_backslash_json(text: str) -> str:
    r"""把 JSON 文本中反斜杠后跟非 JSON 转义字符的 \X 修复为 \\X（C:\Users → C:\\Users）。
    合法转义（\" \\ \/ \b \f \n \r \t \u）不受影响。
    通常用于 json 解析失败后的补救重试（模型输出 Windows 绝对路径时）。"""
    return _WIN_PATH_BACKSLASH_RE.sub(r"\\\\\1", text)


class ToolExecutorBase:
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

    @staticmethod
    def _read_text_any(path: Path) -> str:
        """读取文本：UTF-8 优先，失败回退系统默认编码（如 GBK），避免中文被静默丢弃"""
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            import locale
            return path.read_text(encoding=locale.getpreferredencoding(False), errors="ignore")

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

    def _resolve_read_path(self, path_str: str) -> Optional[Path]:
        """解析对话内文件路径：支持 ~ 展开与相对项目路径"""
        p = Path(os.path.expanduser(path_str))
        if not p.is_absolute():
            p = self.project_root / p
        return p.resolve()

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

