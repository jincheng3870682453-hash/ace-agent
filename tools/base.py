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
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

import ace_execpolicy as execpolicy
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
                 sandbox: Optional[Dict] = None,
                 approval_policy: Optional[str] = None,
                 sandbox_policy: Optional[str] = None,
                 egress_allowlist=None,
                 approval_hook=None):
        self.project_root = Path(project_root).resolve()
        self.sandbox_base = sandbox_base  # code_execute 沙箱临时目录基路径（None = 系统临时目录）
        self.confine_files = confine_files  # 文件工具是否强制限制在项目目录内
        self.email_smtp = email_smtp or {}  # {"host","port","user","password","use_tls"}
        # docker 一次性容器执行层（None = 未启用，命令仍在宿主跑）。
        # 只有 terminal_exec / code_execute 走它——那两个才是真正需要内核边界的地方。
        self.docker_sandbox = build_sandbox(sandbox, str(self.project_root))
        # 执行位置档位：off / job / docker。docker 由上面那行接管，job 由 Go 执行器
        # 接管（Tier-1 Job Object），off 表示宿主直跑。
        self.sandbox_mode = str((sandbox or {}).get("mode", "off")).lower()
        self._go_client = None
        # Go 执行器：job 档是**必需**，off 档是可选增强。
        # 这个区分很要紧，理由见 _go_executor() 的注释。
        self.use_go_executor = (
            self.sandbox_mode == "job"
            or (self.sandbox_mode == "off"
                and os.environ.get("ACE_USE_GO_EXECUTOR", "1").lower()
                not in ("0", "false", "no", "off")))
        self.execution_log: List[Dict] = []

        # —— 审批 / 沙箱双闸门（见 ace_execpolicy）——
        # 两者正交，不是同一件事的两种说法：
        #   approval_policy 管"要不要问人"，sandbox_policy 管"允许它碰什么"。
        # 再叠加 PermissionManager（管"这个工具准不准用"），共三个维度。
        # 注意 sandbox_policy 和上面的 docker_sandbox 也不是一回事：前者是判定用的
        # 策略档位，后者是真正的内核边界。判定收紧不等于有了边界，有边界也不代表
        # 判定可以放松。
        self.approval_policy = approval_policy or execpolicy.ApprovalPolicy.DEFAULT
        self.sandbox_policy = sandbox_policy or execpolicy.SandboxPolicy.DEFAULT
        # approval_hook(verdict) -> bool：由上层注入的"人是否点头"实现。
        # 为 None 表示无人可问 —— 此时判定为 prompt 的命令一律拒绝，而不是放行。
        # 这个默认方向很重要：非交互场景把默认答案写成 "y" 就是 SEC-004 那类事故。
        self.approval_hook = approval_hook
        # 出站目的地白名单。None = 闸门关闭（默认，只有 ace_net 的内网判定生效）；
        # 给了列表就只放行清单内主机（自动并上 DEFAULT_EGRESS_ALLOWLIST）。
        # 默认关而不是默认开：内网判定挡的是"打到内网去"，清单挡的是"把数据带到
        # 哪个公网站点去"。后者只有宿主知道哪些站点是正当的，猜一个默认值的结果
        # 是 api_get 在升级后突然大面积失灵，而用户的第一反应是这功能坏了。
        self.egress_allowlist = egress_allowlist




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

    def _go_executor(self):
        """惰性拿到 Go 执行器客户端。返回 None 表示"这条路走不了"。

        两个档位的失败语义**不一样**，这是从 docker 那条路继承下来的原则：

        - `--sandbox off`：用户已经说了不要边界。这时候执行器只是个增强
          （Job Object 能把整棵进程树收干净，Python 的 `Process.Kill()` 只杀直接
          子进程，孙进程会变孤儿）。所以起不来就静默降级回宿主，返回 None。
        - `--sandbox job`：用户要的就是这个边界。起不来必须报错，**绝不**静默回落到
          宿主。这里同样只返回 None，但调用方看到 `sandbox_mode == "job"` 就知道
          该报 503 而不是接着跑 —— 判断留在调用方，因为只有它知道自己在执行谁。

          理由和 docker 那条一模一样：用户以为在容器/Job 里跑、实际在自己机器上跑，
          而且毫无提示，这是最坏的一种"能用"。

        真正的命令安全闸门在 ace_execpolicy，不依赖这个进程存在 —— 执行器里那道
        policy_decision 复检是第二道闸，不是唯一一道。
        """
        if not self.use_go_executor:
            return None
        if self._go_client is not None:
            return self._go_client
        try:
            import ace_executor
            client = ace_executor.ExecutorClient()
            if not client.available():
                self.use_go_executor = False
                return None
            client.start()
            self._go_client = client
            return client
        except Exception:
            # 一次失败就彻底关掉，避免每条命令都付一次启动失败的代价。
            self.use_go_executor = False
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
        """URL 协议 + 地址校验：通过返回 None，否则返回拒绝原因。

        判定本身住在 ace_net —— 那里不 import 项目内任何模块，并且和它同源的
        `safe_request()` 才是真正把"校验"和"连接"绑在一起的那条路径。

        这个函数只留给**接管不了连接**的场景（`browser_open` 把 URL 交给系统
        浏览器）。凡是本进程自己发的请求都必须走 `ace_net.safe_request()`：
        校验与连接一分开，DNS rebinding 和 302 跳内网这两条就立刻回来了 ——
        校验时解析一次、requests 再解析一次，两次之间答案可以变。
        """
        from ace_net import check_url
        return check_url(url)

    def _egress_reason(self, url: str) -> Optional[str]:
        """出站目的地是否被白名单拒绝：放行返回 None，否则返回给模型看的原因。"""
        from ace_net import egress_reject_reason
        return egress_reject_reason(url, self.egress_allowlist)

    def _egress_hop_gate(self):
        """给 `safe_request(on_hop=...)` 的回调；闸门关着时返回 None（不加回调开销）。

        重定向必须逐跳复检，否则清单是装饰品：清单里的域名回一个
        `302 Location: https://evil.tld/?data=...`，请求就落到清单外去了，
        而首跳的判定完全正确 —— 判定和最终目的地不是同一个东西。
        """
        if self.egress_allowlist is None:
            return None
        return self._egress_reason



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

