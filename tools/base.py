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

from tools.registry import SPEC_BY_NAME
from tools.result import ExecutionResult
from tools.docker_sandbox import build_sandbox



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

# —— 敏感目标：凭据 / 持久化入口 / 系统目录 ——
# 绝对路径写入是产品意图（"放到桌面"），但意图不覆盖凭据与自启动入口：
# 写 ~/.ssh/authorized_keys、~/.bashrc 是持久化后门，读 ~/.ai_code.json 是窃取本工具自身的 API key。
# 这里按"路径成分"匹配而非全字符串正则，避免 D:\project\ssh_utils.py 这类误伤。
_SENSITIVE_BASENAMES = {
    ".ai_code.json", ".agent_cli.json", ".netrc", "_netrc",
    ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile",
    ".zshenv", ".zlogin", ".bash_aliases", ".bash_logout",
    "authorized_keys", "known_hosts", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials", "shadow", "sudoers",
    # 各类工具链的凭据存放点：都是明文 token，且不存在"agent 需要改它"的正常场景
    ".git-credentials", ".npmrc", ".pypirc", ".dockercfg",
    ".pgpass", ".my.cnf", ".htpasswd", ".terraformrc",
}
# 私钥 / 证书材料按后缀拦（.env 故意不在此列：项目内 .env 是正常开发对象，
# 一律拦死会让"帮我建个 .env"这类请求失败。它的防线是"不出项目目录"）
_SENSITIVE_SUFFIXES = (".pem", ".key", ".ppk", ".p12", ".pfx", ".keystore", ".jks")
_SENSITIVE_DIRNAMES = {
    ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker", ".config/gcloud",
    # 用户级自启动 / 定时任务：写这里等于装持久化后门
    ".config/autostart", ".config/systemd", ".local/share/systemd",
}
# 目录整体不可写（系统 / 自启动 / 定时任务）
_SENSITIVE_DIR_PREFIXES = (
    "c:/windows", "c:/program files", "c:/program files (x86)", "c:/programdata",
    "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot", "/sys", "/proc",
    "/var/spool/cron",
)
_STARTUP_FRAGMENTS = ("start menu/programs/startup", "currentversion/run")
# Agent 自身的安全状态目录：回滚快照存在项目目录内，而项目目录正是 agent 可写的范围。
# 不挡这里，agent 改一行 .guardian/snapshots/<id>/meta.json 就能让 verify_snapshot
# 失败，熔断回滚静默变成空操作——安全网被它要防的东西拆了。
_AGENT_STATE_DIRNAMES = {".guardian"}



def sensitive_target(path: "Path | str") -> Optional[str]:
    """命中敏感目标返回原因串，否则 None。

    用于文件写/删/移 与 终端命令的前置拦截。挡两类东西：用户的凭据/自启动入口，
    以及 agent 自己的回滚快照目录。注意：这是"已知高价值目标"清单，
    不是完备边界——真正的隔离仍需容器/低权限账户（见 README 部署说明）。
    """
    raw = str(path).replace("\\", "/")
    low = raw.lower()
    name = low.rsplit("/", 1)[-1]
    parts = [p for p in low.split("/") if p]

    if name in _SENSITIVE_BASENAMES:
        return f"敏感文件（凭据/启动脚本）: {name}"
    if _AGENT_STATE_DIRNAMES & set(parts):
        return "Agent 自身的回滚快照目录（改它等于拆掉回滚安全网）"

    if name.endswith(_SENSITIVE_SUFFIXES):
        return f"私钥/证书文件: {name}"
    for d in _SENSITIVE_DIRNAMES:
        if d in parts or (("/" in d) and d in low):
            return f"敏感目录: {d}"
    if low.startswith(_SENSITIVE_DIR_PREFIXES):
        return "系统目录"
    if any(frag in low for frag in _STARTUP_FRAGMENTS):
        return "自启动项"
    # .claude/settings.json 等同类配置（含模型凭据）
    if ".claude/" in low and name.endswith(".json"):
        return "敏感文件（模型凭据配置）"
    return None


def repair_backslash_json(text: str) -> str:
    r"""把 JSON 文本中反斜杠后跟非 JSON 转义字符的 \X 修复为 \\X（C:\Users → C:\\Users）。
    合法转义（\" \\ \/ \b \f \n \r \t \u）不受影响。
    通常用于 json 解析失败后的补救重试（模型输出 Windows 绝对路径时）。"""
    return _WIN_PATH_BACKSLASH_RE.sub(r"\\\\\1", text)


class ToolExecutorBase:
    def __init__(self, project_root: str = ".", sandbox_base: Optional[str] = None,
                 confine_files: bool = True, email_smtp: Optional[Dict] = None,
                 sandbox: Optional[Dict] = None):
        self.project_root = Path(project_root).resolve()
        self.sandbox_base = sandbox_base  # code_execute 沙箱临时目录基路径（None = 系统临时目录）
        self.confine_files = confine_files  # 文件工具是否强制限制在项目目录内
        self.email_smtp = email_smtp or {}  # {"host","port","user","password","use_tls"}
        # docker 一次性容器执行层（None = 未启用，命令仍在宿主跑）。
        # 只有 terminal_exec / code_execute 走它——那两个才是真正需要内核边界的地方。
        self.docker_sandbox = build_sandbox(sandbox, str(self.project_root))
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
        """URL 协议校验 + 私网地址防护（DNS 解析后拦截内网/回环/链路本地，防 SSRF）

        与旧版的差异（三处 fail-open 已收）：
          1. 校验**全部**解析结果，不再只看第一条（多 A 记录混入内网可绕过）
          2. DNS 解析失败不再放行，直接拒绝
          3. 调用方必须传 allow_redirects=False（302 跳内网是独立的绕过路径）
        残留风险：校验与实际请求之间会二次解析 DNS（TOCTOU / DNS rebinding），
        彻底修需要把已校验 IP 固定进连接层，本次未做。
        """
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
        if not host:
            return "URL 缺少主机名"
        import socket
        try:
            infos = socket.getaddrinfo(host, None)
        except Exception as e:
            return f"主机名解析失败，拒绝访问: {host}（{e}）"
        checked = 0
        for info in infos:
            ip = info[4][0].split("%")[0]
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            checked += 1
            if (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved
                    or addr.is_unspecified
                    or (addr.version == 4 and ip.startswith("100.64."))):
                return f"拒绝访问内网/回环/链路本地地址: {ip}"
        if checked == 0:
            return f"主机名未解析到可校验的 IP，拒绝访问: {host}"
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
            spec = SPEC_BY_NAME.get(tool_name)
            handler = getattr(self, spec.handler, None) if (spec and spec.handler) else None
            if handler is None:
                # 未注册 / 已登记但无 handler（如 terminal_dangerous 占位项）都走这里
                result = ExecutionResult(
                    status="error",
                    error_code="400",
                    message=f"未知工具: {tool_name}"
                )
            elif spec.pass_tool_name:
                # file_read/file_write/file_delete/file_move 共用 _exec_file_ops
                result = handler(tool_name, params)
            else:
                result = handler(params)
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

