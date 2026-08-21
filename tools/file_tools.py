#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.file_tools —— 文件与终端工具（file_* / terminal_* / open_file / edit_file）"""

import os
import re
import sys
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from tools.base import (GIT_READONLY_SUBCOMMANDS, MAX_COMMAND_LENGTH,
                        READ_ONLY_COMMANDS, SHELL_META_RE,
                        VERSION_ONLY_COMMANDS, VERSION_SUBCOMMANDS)
from tools.result import ExecutionResult

# Windows 无默认打开程序时，文本类扩展名回退记事本打开（.py 常无关联程序）
_TEXT_EXTENSIONS = {".py", ".txt", ".md", ".json", ".log", ".csv", ".ini", ".cfg",
                    ".yaml", ".yml", ".toml", ".xml", ".html", ".css", ".js",
                    ".ts", ".bat", ".cmd", ".ps1", ".sql", ".env"}


class FileTools:
    def _exec_file_ops(self, tool_name: str, params: Dict) -> ExecutionResult:
        """文件操作（相对路径限制在项目目录内；绝对路径 = 用户明确意图，防路径穿越）"""
        path_str = str(params.get("path", "")).strip()
        if not path_str and tool_name != "file_move":
            # 小模型常漏 path 参数：明确 400（配示例），而不是把 Path("") 当目录写到 500
            return ExecutionResult(status="error", error_code="400",
                                   message=f"{tool_name} 需要 path 参数（示例: "
                                           f'{{"tool": "{tool_name}", "path": "文件路径"}})')
        path = Path(os.path.expanduser(path_str))
        if self.confine_files:
            confined = self._confined(path)
            if confined is not None:
                path = confined
            elif tool_name == "file_read" and path.is_dir():
                # 只读目录列表允许越界（与 terminal_view ls 口径一致），
                # 防止"帮我看看桌面/主目录"这类问题因工具选择而失败
                pass
            elif path.is_absolute() and tool_name in ("file_write", "file_delete"):
                # 绝对路径（含 ~ 展开后） = 用户明确意图（如"放到桌面/主目录"），写工具放行；
                # 相对路径仍严格限项目内，防止穿越。读文件仍限项目内。
                path = path.resolve()
            else:
                return ExecutionResult(status="error", error_code="403",
                                       message="路径越界：相对路径仅允许在项目目录内；"
                                               "写文件（file_write/file_delete）可传绝对路径"
                                               "（如 C:\\Users\\<用户名>\\Desktop\\文件名，"
                                               "或 ~/Desktop/文件名）")
        elif not path.is_absolute():
            path = self.project_root / path

        try:
            if tool_name == "file_read":
                if not path.exists():
                    return ExecutionResult(status="error", error_code="404",
                                           message=f"文件不存在: {path}"
                                                   f"（若目标是目录，file_read 会直接返回目录列表）")
                if path.is_dir():
                    try:
                        items = sorted(os.listdir(path))
                    except Exception as e:
                        return ExecutionResult(status="error", error_code="500",
                                               message=f"目录读取失败: {e}")
                    return ExecutionResult(status="success", data={
                        "content": "\n".join(items),
                        "path": str(path),
                        "is_dir": True,
                        "listing": items,
                    })
                content = self._read_text_any(path)
                return ExecutionResult(status="success", data={"content": content, "path": str(path)})
            elif tool_name == "file_write":
                if path.is_dir():
                    return ExecutionResult(status="error", error_code="400",
                                           message=f"path 是目录: {path}，file_write 需要完整文件路径"
                                                   "（如 C:\\Users\\<用户名>\\Desktop\\文件.py）")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(params.get("content", ""), encoding="utf-8")
                return ExecutionResult(status="success", data={"path": str(path), "bytes_written": len(params.get("content", ""))})
            elif tool_name == "file_delete":
                if path.is_dir():
                    return ExecutionResult(status="error", error_code="400",
                                           message=f"path 是目录: {path}，file_delete 只删除文件")
                if path.exists():
                    path.unlink()
                return ExecutionResult(status="success", data={"deleted": str(path)})
            elif tool_name == "file_move":
                src = Path(os.path.expanduser(str(params.get("source", ""))))
                dest = Path(os.path.expanduser(str(params.get("dest", ""))))
                if not str(params.get("source", "")).strip() or not str(params.get("dest", "")).strip():
                    return ExecutionResult(status="error", error_code="400",
                                           message='file_move 需要 source 与 dest 参数'
                                                   '（示例: {"tool": "file_move", "source": "a.txt", "dest": "b.txt"}）')
                if self.confine_files:
                    src = self._confined(src) or (src.resolve() if src.is_absolute() else None)
                    dest = self._confined(dest) or (dest.resolve() if dest.is_absolute() else None)
                    if src is None or dest is None:
                        return ExecutionResult(status="error", error_code="403",
                                               message="路径越界：file_move 仅允许项目内相对路径"
                                                       "或绝对路径（绝对路径 = 明确意图）")
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
                parts = self._split_cmd_windows(cmd)
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
            except FileNotFoundError:
                return ExecutionResult(status="error", error_code="404",
                                       message=f"目录不存在: {p}")
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

    def _exec_open_file(self, params: Dict) -> ExecutionResult:
        """对话内打开文件：默认返回可点击链接（用户点击后全屏查看）；
        auto_open=true 时立即用系统默认程序打开"""
        path_str = str(params.get("path", "")).strip()
        if not path_str:
            return ExecutionResult(status="error", error_code="400", message="path 参数为空")
        p = self._resolve_read_path(path_str)
        if not p.exists():
            return ExecutionResult(status="error", error_code="404", message=f"文件不存在: {p}")
        if p.is_dir():
            # 目录：立即在系统文件管理器中打开（如"打开桌面文件夹"）
            try:
                if os.name == "nt":
                    os.startfile(str(p))
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", str(p)])
                else:
                    subprocess.Popen(["xdg-open", str(p)])
            except Exception as e:
                return ExecutionResult(status="error", error_code="500",
                                       message=f"打开文件夹失败: {e}")
            return ExecutionResult(status="success", data={
                "path": str(p), "opened": True, "is_dir": True,
                "hint": "已在系统文件管理器中打开该文件夹"})
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
            # Windows 上 .py 等常无关联默认程序：文本类文件回退记事本
            if os.name == "nt" and p.suffix.lower() in _TEXT_EXTENSIONS:
                try:
                    subprocess.Popen(["notepad.exe", str(p)])
                    return ExecutionResult(status="success", data={
                        "path": str(p), "opened": True, "editor": "notepad",
                        "hint": "该类型无默认打开程序，已用记事本打开"})
                except Exception as e2:
                    return ExecutionResult(status="error", error_code="500",
                                           message=f"打开失败（记事本回退也失败）: {e2}")
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
        if p.is_dir():
            # 目录：在系统文件管理器中打开
            try:
                if os.name == "nt":
                    os.startfile(str(p))
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", str(p)])
                else:
                    subprocess.Popen(["xdg-open", str(p)])
            except Exception as e:
                return ExecutionResult(status="error", error_code="500",
                                       message=f"打开文件夹失败: {e}")
            return ExecutionResult(status="success", data={
                "path": str(p), "opened": True, "is_dir": True,
                "hint": "已在系统文件管理器中打开该文件夹"})
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
            # Windows 上 .py 等常无关联默认程序：文本类文件回退记事本
            if os.name == "nt" and p.suffix.lower() in _TEXT_EXTENSIONS:
                try:
                    subprocess.Popen(["notepad.exe", str(p)])
                    return ExecutionResult(status="success", data={
                        "path": str(p), "editor": "notepad",
                        "hint": "该类型无默认打开程序，已用记事本打开"})
                except Exception as e2:
                    return ExecutionResult(status="error", error_code="500",
                                           message=f"打开失败（记事本回退也失败）: {e2}")
            return ExecutionResult(status="error", error_code="500", message=f"打开失败: {e}")
        return ExecutionResult(status="success", data={"path": str(p), "editor": "system_default"})

