#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ace_execpolicy —— 命令安全性判定（与"执行"彻底解耦）

设计动机：
    原先 terminal_exec 把"判定"和"执行"揉在一起，导致危险命令的测试必须真的把命令跑起来
    （test_all.py 里就是这么做的），这是覆盖率的硬天花板 —— 你不可能为了测试 `format C:`
    而真的格式化硬盘。把判定抽成纯函数后，所有拒绝路径都能被单测覆盖。

威胁模型：
    **模型输出即不可信输入**。攻击者可以通过间接 prompt injection（让 agent 读到一个含
    恶意指令的文件或网页）来驱动模型产出恶意命令。因此判定不能假设"模型是善意的"。

三值判定，最严者优先：
    forbidden —— 无论何种权限、何种审批策略都不执行。用于不可逆破坏与凭据外泄。
    prompt    —— 需要人类逐次确认。这是**默认档**：不在白名单里的一切都落到这里。
    allow     —— 可直接以 argv（shell=False）执行，且所有路径参数都在工作区内。

关于 allow 为什么必须很窄：
    allow 意味着"不问人就跑"。在上述威胁模型下，只有"最坏情况被限制在工作区内、且不会
    执行任意代码"的命令才配得上 allow。所以 python / pip / npm / go / git commit 全部
    落到 prompt —— 它们都能通过各自的机制执行任意代码（-c、setup.py、生命周期脚本、
    cgo 指令、hooks）。这会让 agent 更啰嗦，但这是正确的默认值。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------- 判定三值

DECISION_ALLOW = "allow"
DECISION_PROMPT = "prompt"
DECISION_FORBIDDEN = "forbidden"

# 严重度：合并多条规则命中时取最大值（最严者优先）
_SEVERITY = {DECISION_ALLOW: 0, DECISION_PROMPT: 1, DECISION_FORBIDDEN: 2}


def stricter(a: str, b: str) -> str:
    """返回两个判定中更严格的那个"""
    return a if _SEVERITY[a] >= _SEVERITY[b] else b


# ---------------------------------------------------------------- 两个正交策略枚举
#
# 参考 codex 的设计：审批与沙箱是两个**正交**维度，不是同一件事的两种说法。
#   - ApprovalPolicy 回答"要不要问人"
#   - SandboxPolicy  回答"允许它碰什么"
# 再叠加项目原有的 PermissionManager（回答"这个工具准不准用"），共三个维度。


class ApprovalPolicy:
    NEVER = "never"            # 从不询问（危险：仅用于 CI 且必须配 read_only 沙箱）
    ON_FAILURE = "on_failure"  # 沙箱内失败后才升级询问
    ON_REQUEST = "on_request"   # 判定为 prompt 时询问（默认）
    UNTRUSTED = "untrusted"     # 除 allow 白名单外一律询问

    ALL = (NEVER, ON_FAILURE, ON_REQUEST, UNTRUSTED)
    DEFAULT = ON_REQUEST


class SandboxPolicy:
    READ_ONLY = "read_only"                    # 只读：不允许任何写
    WORKSPACE_WRITE = "workspace_write"        # 仅工作区可写（默认）
    DANGER_FULL_ACCESS = "danger_full_access"  # 无限制（需显式开启）

    ALL = (READ_ONLY, WORKSPACE_WRITE, DANGER_FULL_ACCESS)
    DEFAULT = WORKSPACE_WRITE


# ---------------------------------------------------------------- 判定结果


@dataclass
class Verdict:
    """命令判定结果

    argv 仅在 decision == allow 时保证非 None —— 调用方应当只在这种情况下
    以 argv + shell=False 执行。其余情况 argv 无意义（可能压根没分词成功）。

    `reason` 是给**模型**看的（`tools/file_tools.py` 把它拼进 403 的 message，
    而 message 会进模型上下文）。它固定中文，且刻意不随界面语言变：系统提示词是
    中文写的，把这条链路的语言跟着 UI 一起切，等于让模型的输入语言由用户的界面
    偏好决定。

    `reason_key` / `reason_args` 留给人类展示层（确认框），拿键去查 locales，
    这样 en / ja 界面不会出现"Reason: 命令需要确认 (rule: shell_syntax)"这种半英半中。
    只有 prompt 档填 `reason_key`：forbidden 不问人、allow 不拦，两者的 reason
    目前没有人类展示出口，先填键只会得到一批查不到也测不到的死键。

    `hits` 记录命中的所有规则，便于审计——一条命令可能同时触发多条。
    """

    decision: str
    reason: str = ""
    rule: str = ""
    argv: Optional[List[str]] = None
    normalized: str = ""
    # 命中的所有规则（便于审计与调试；一条命令可能同时触发多条）
    hits: List[Tuple[str, str, str]] = field(default_factory=list)
    # 展示层用的翻译键与参数。新字段一律排在末尾且带默认值：
    # 现存调用点（含 test_all.py）都是位置参数 + 关键字混用，插在中间会静默错位。
    reason_key: str = ""
    reason_args: Dict[str, str] = field(default_factory=dict)


    @property
    def allowed(self) -> bool:
        return self.decision == DECISION_ALLOW

    @property
    def forbidden(self) -> bool:
        return self.decision == DECISION_FORBIDDEN

    @property
    def needs_approval(self) -> bool:
        return self.decision == DECISION_PROMPT


# ---------------------------------------------------------------- 规范化
#
# forbidden 规则是对**原始字符串**做匹配的，因此必须先抵消掉常见的字面量混淆手法，
# 否则 `de^l /f /s /q C:\` 这种 Windows cmd 的插入符转义就能绕过纯文本黑名单。
# 注意：规范化只服务于"检测"，绝不把规范化后的字符串拿去执行。

_CARET_RE = re.compile(r"\^")
_QUOTE_RE = re.compile(r"[\"']")
_WS_RE = re.compile(r"\s+")


def normalize_for_matching(cmd: str) -> str:
    """把命令折叠成便于黑名单匹配的形式（仅用于检测，不用于执行）

    - 去掉 Windows cmd 的 `^` 转义符（`de^l` → `del`）
    - 去掉引号（`"del"` → `del`、`d"e"l` → `del`）
    - 折叠连续空白为单个空格
    - 转小写
    """
    s = _CARET_RE.sub("", cmd)
    s = _QUOTE_RE.sub("", s)
    s = _WS_RE.sub(" ", s)
    return s.strip().lower()


# ---------------------------------------------------------------- forbidden 规则表
#
# 每条 = (规则名, 正则, 人类可读原因)
# 全部针对 normalize_for_matching() 的输出（已小写、已去引号与 ^、已折叠空白）。

_FORBIDDEN_RULES: Sequence[Tuple[str, re.Pattern, str]] = (
    # ---- 不可逆的大范围删除 ----
    ("rm_rf_root", re.compile(r"\brm\s+(-[a-z]*\s+)*-[a-z]*[rf][a-z]*\s+(-[a-z]+\s+)*/(\s|$)"),
     "rm 递归删除根目录"),
    ("rm_rf_home", re.compile(r"\brm\s+(-[a-z]*\s+)*-[a-z]*r[a-z]*f?[a-z]*\s+(~|\$home)(/\s*)?(\s|$)"),
     "rm 递归删除用户主目录"),
    ("win_del_drive_root",
     # 用两个前瞻而非固定顺序：`del /f /s /q C:\` 与 `del C:\ /s` 都要命中。
     # 注意不能写 `\b/s\b` —— 空格与 / 都是非单词字符，两者之间不存在 \b，该写法永不匹配。
     re.compile(r"\b(del|erase)\b(?=.*\s/[a-z]*[sq]\b)(?=.*\b[a-z]:\\?(\s|$))"),
     "del /s 删除整个盘符"),
    ("win_rd_drive_root",
     re.compile(r"\b(rd|rmdir)\b(?=.*\s/[a-z]*s\b)(?=.*\b[a-z]:\\?(\s|$))"),
     "rd /s 删除整个盘符"),
    ("format_disk", re.compile(r"\bformat\s+[a-z]:"), "格式化磁盘"),
    ("diskpart", re.compile(r"\bdiskpart\b"), "diskpart 磁盘分区操作"),
    ("mkfs", re.compile(r"\bmkfs(\.[a-z0-9]+)?\b"), "创建文件系统（擦除数据）"),
    ("dd_to_device", re.compile(r"\bdd\b.*\bof=/dev/"), "dd 直写块设备"),

    # ---- 破坏恢复能力（先毁掉回滚路径，再干别的） ----
    ("vssadmin_delete", re.compile(r"\bvssadmin\b.*\bdelete\b.*\bshadows?\b"),
     "删除卷影副本（摧毁系统还原点）"),
    ("wmic_shadow_delete", re.compile(r"\bwmic\b.*\bshadowcopy\b.*\bdelete\b"),
     "删除卷影副本（摧毁系统还原点）"),
    ("bcdedit", re.compile(r"\bbcdedit\b"), "修改启动配置"),
    ("cipher_wipe", re.compile(r"\bcipher\b.*\s/w"), "cipher /w 擦除可用空间"),

    # ---- 权限与账户变更 ----
    ("net_user_add", re.compile(r"\bnet\s+user\b.*\s/add\b"), "创建系统账户"),
    ("net_localgroup_admin", re.compile(r"\bnet\s+localgroup\b.*\badministrators?\b.*\s/add\b"),
     "把账户加入管理员组"),
    ("takeown_drive", re.compile(r"\btakeown\b.*\s/f\s+[a-z]:\\?(\s|$)"), "夺取整盘所有权"),
    ("icacls_drive", re.compile(r"\bicacls\s+[a-z]:\\?\s"), "修改整盘 ACL"),
    ("chmod_777_root", re.compile(r"\bchmod\s+(-[a-z]+\s+)*777\s+/(\s|$)"), "把根目录改成 777"),
    ("sudoers", re.compile(r"/etc/sudoers"), "修改 sudoers"),

    # ---- 远程代码执行 / 下载即执行 ----
    ("curl_pipe_shell", re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|k|)sh\b"),
     "下载内容直接管道给 shell 执行"),
    ("iwr_iex", re.compile(r"\b(iwr|invoke-webrequest|curl)\b.*\|\s*(iex|invoke-expression)\b"),
     "下载内容直接交给 Invoke-Expression"),
    ("iex", re.compile(r"\b(iex|invoke-expression)\b"), "Invoke-Expression 执行动态字符串"),
    ("ps_encoded", re.compile(r"\bpowershell(\.exe)?\b.*\s-(e|ec|enc|encoded|encodedcommand)\b"),
     "PowerShell 编码命令（典型的规避检测手法）"),
    ("certutil_download", re.compile(r"\bcertutil\b.*-urlcache\b"), "certutil 下载器"),
    ("bitsadmin_transfer", re.compile(r"\bbitsadmin\b.*\s/transfer\b"), "bitsadmin 下载器"),
    ("mshta_remote", re.compile(r"\bmshta\b.*https?://"), "mshta 执行远程脚本"),
    ("regsvr32_remote", re.compile(r"\bregsvr32\b.*\s/i:https?://"), "regsvr32 执行远程脚本"),

    # ---- 持久化 ----
    ("schtasks_create", re.compile(r"\bschtasks\b.*\s/create\b"), "创建计划任务（持久化）"),
    ("sc_create", re.compile(r"\bsc(\.exe)?\s+create\b"), "创建系统服务（持久化）"),
    ("reg_add_run", re.compile(r"\breg\s+add\b.*\\currentversion\\run"), "写入开机自启注册表项"),
    ("crontab_write", re.compile(r"\bcrontab\s+(-|[^-\s])"), "修改 crontab（持久化）"),

    # ---- 关闭防御 ----
    ("defender_exclusion", re.compile(r"\badd-mppreference\b.*\bexclusion"),
     "给 Defender 添加排除项（关闭防护）"),
    ("defender_disable", re.compile(r"\bset-mppreference\b.*\bdisable"), "关闭 Defender 防护"),
    ("firewall_off", re.compile(r"\bnetsh\b.*\badvfirewall\b.*\bstate\s+off\b"), "关闭防火墙"),

    # ---- 注册表大范围删除 ----
    ("reg_delete_hive", re.compile(r"\breg\s+delete\s+hk(lm|cu|cr|u|cc)\\?(\s|$)"),
     "删除整个注册表配置单元"),

    # ---- 资源耗尽 ----
    ("fork_bomb", re.compile(r":\(\)\s*\{.*\|.*&.*\}\s*;\s*:"), "fork bomb"),

    # ---- 关机重启（不算破坏，但绝不该由模型自主决定） ----
    # 必须锚在**命令位置**：normalize_for_matching 会把引号去掉，于是
    # `git commit -m "fix reboot bug"` 折叠后就是 `git commit -m fix reboot bug`。
    # 无锚点的 \breboot\b 会把这条正常提交判成 forbidden —— 而 forbidden 是
    # 任何审批都覆盖不了的档，等于 git commit 从此不能带这个词。
    ("shutdown", re.compile(r"(^|&&|\|\||;|\||\bthen\b|\bdo\b)\s*"
                            r"(sudo\s+)?(shutdown|reboot|halt|poweroff)\b"),
     "关机/重启"),
)


# ---------------------------------------------------------------- shell 语法检测
#
# 出现这些字符说明命令依赖 shell 解释（管道、重定向、连接、变量展开、子命令替换）。
# 这类命令**不能**以 argv 执行，因此至少落到 prompt。
# 注意 `%` 与 `!`：Windows cmd 的变量展开与延迟展开，同样意味着"字面量不等于实际执行内容"。

_SHELL_SYNTAX_RE = re.compile(r"[|&;<>`$\n\r%!(){}]")

# 路径参数的粗判：包含分隔符、或以 . 开头、或形如 X:
_PATHLIKE_RE = re.compile(r"[\\/]|^\.{1,2}$|^[a-zA-Z]:")


# ---------------------------------------------------------------- allow 白名单
#
# 只放"最坏情况被限制在工作区内、且不执行任意代码"的命令。
# 与 tools/base.py 的 READ_ONLY_COMMANDS 是包含关系：只读的当然也 allow。

# 只读（无副作用）。公开导出：terminal_exec 需要据此把 shell 内建命令
# （echo/dir/type 在 Windows 上不是可执行文件）转交给原生实现而非 subprocess。
READ_ONLY_BASES = {
    "ls", "dir", "pwd", "cat", "type", "echo", "tree",
    "where", "which", "date", "time", "ver", "hostname", "whoami",
}

# 写，但影响面可被路径约束限制在工作区内
_WORKSPACE_WRITE_BASES = {
    "mkdir", "md",
    "copy", "cp",
    "move", "mv",
    "ren", "rename",
    "touch",
}

# git 只读子命令（沿用 tools/base.py 的口径）。
# 注意不含 config：`git config --global` 会写 ~/.gitconfig（工作区外、且可注入
# core.sshCommand 之类执行任意命令），绝不能进 allow（SEC-06）。
_GIT_READONLY_SUBS = {
    "status", "log", "diff", "show", "ls-files", "rev-parse", "branch",
    "describe", "blame", "shortlog",
}

# git 写子命令中，影响只落在本地仓库、且不触发 hook 执行任意代码的
# 说明：commit 会触发 pre-commit hook（可执行任意代码）→ 不在此列
#       push/fetch/pull/clone 有网络 → 不在此列
#       checkout/switch/restore 会改工作区文件 → 交给 prompt，避免静默覆盖用户改动
_GIT_SAFE_WRITE_SUBS = {
    "add", "stash", "init", "tag",
}


def _is_bare_command_name(token: str) -> bool:
    """基础命令名必须是裸名字，不能带路径

    否则 `.\\evil.exe`、`C:\\Windows\\System32\\cmd.exe`、`/bin/sh` 这类
    可以绕过"基础名白名单"（白名单比对的是 basename，但实际执行的是任意可执行文件）。
    """
    if not token:
        return False
    if _PATHLIKE_RE.search(token):
        return False
    return True


def _paths_within(argv: Sequence[str], project_root: Path, *,
                  posix: Optional[bool] = None) -> Tuple[bool, str]:
    """检查 argv 中所有"看起来像路径"的参数是否都落在 project_root 内

    返回 (是否全部在内, 第一个越界的参数)。
    这是 allow 档得以成立的关键前提 —— 没有它，`copy secrets.txt C:\\Users\\Public\\`
    就能在不询问的情况下把文件搬到工作区外。

    posix 参数只影响 `/` 开头的 token 怎么解读，见下面的注释；默认按本机平台。
    做成参数是为了让两种平台的判定都能在同一台机器上被测试覆盖。
    """
    if posix is None:
        posix = os.name != "nt"

    def _within(tok: str) -> Tuple[bool, str]:
        """判定单个候选路径 token 是否落在 project_root 内（含裸相对文件名）"""
        if not _PATHLIKE_RE.search(tok) and not tok:
            return True, ""
        candidate = Path(os.path.expanduser(tok))
        try:
            resolved = (candidate if candidate.is_absolute()
                        else project_root / candidate).resolve()
        except (OSError, ValueError):
            return False, tok
        try:
            if resolved.drive and project_root.drive and \
                    resolved.drive.lower() != project_root.drive.lower():
                return False, tok
            resolved.relative_to(project_root)
        except ValueError:
            return False, tok
        return True, ""

    for tok in argv[1:]:
        # 跳过选项。注意 `/` 的含义**依平台而定**：
        #   Windows：`/s`、`/R`、`/Y` 是命令开关，必须跳过
        #   POSIX：  `/tmp/x` 是绝对路径，跳过它等于把工作区外的目标当成"区内"
        # 原实现无条件跳过 `/`，于是 Linux/macOS 上 `cp secret.txt /tmp/x` 会被判为
        # allow 档、不经询问直接执行 —— 恰好是这个函数要防的那件事。
        if tok.startswith("-") or (not posix and tok.startswith("/")):
            # SEC-06：`--opt=路径`（如 --target-directory=/tmp、-O/out）把路径
            # 内嵌进单个选项 token。整 token 跳过 = 越界目标被当成"区内"，
            # 必须把 '=' 右边的值单独过一遍路径校验。
            _name, _sep, _value = tok.partition("=")
            if _sep and _PATHLIKE_RE.search(_value):
                _ok, _off = _within(_value)
                if not _ok:
                    return False, tok
            continue
        _ok, _off = _within(tok)
        if not _ok:
            return False, _off
    return True, ""


def split_argv(cmd: str, *, posix: Optional[bool] = None) -> Optional[List[str]]:
    """把命令行分词成 argv；无法可靠分词时返回 None

    Windows 上不用 shlex：shlex 会把反斜杠当转义符吃掉，导致 `C:\\Users\\x` 变成 `C:Usersx`。
    这里复用与 tools/base.py:_split_cmd_windows 相同的口径（双引号分组 + 保留反斜杠）。
    """
    if posix is None:
        posix = os.name != "nt"
    if posix:
        import shlex
        try:
            return shlex.split(cmd)
        except ValueError:
            return None
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
    if in_quote:
        return None   # 引号未闭合：分词不可靠
    if cur:
        parts.append("".join(cur))
    return parts


# ---------------------------------------------------------------- 主判定入口

MAX_COMMAND_LENGTH = 4_000


def evaluate_command(cmd: str,
                     project_root: str | os.PathLike = ".",
                     *,
                     sandbox: str = SandboxPolicy.DEFAULT,
                     posix: Optional[bool] = None) -> Verdict:
    """判定一条命令的安全性。纯函数，不执行任何东西。

    参数:
        cmd:          原始命令字符串（模型产出，不可信）
        project_root: 工作区根目录，用于路径约束
        sandbox:      当前沙箱策略；read_only 下所有写命令降级为 prompt
        posix:        强制分词风格（None = 按当前平台）。仅供测试使用。

    返回 Verdict。调用方只应在 verdict.allowed 时以 verdict.argv + shell=False 执行。
    """
    hits: List[Tuple[str, str, str]] = []

    if not cmd or not cmd.strip():
        return Verdict(DECISION_FORBIDDEN, "命令为空", "empty", normalized="")
    if len(cmd) > MAX_COMMAND_LENGTH:
        return Verdict(DECISION_FORBIDDEN,
                       f"命令过长（上限 {MAX_COMMAND_LENGTH} 字符）", "too_long")

    normalized = normalize_for_matching(cmd)

    # ---- 第 1 关：forbidden 黑名单（对规范化字符串匹配，抵消 ^ 与引号混淆）----
    decision = DECISION_ALLOW
    reason = ""
    rule = ""
    for rule_name, pattern, why in _FORBIDDEN_RULES:
        if pattern.search(normalized):
            hits.append((rule_name, DECISION_FORBIDDEN, why))
            if _SEVERITY[DECISION_FORBIDDEN] > _SEVERITY[decision]:
                decision, reason, rule = DECISION_FORBIDDEN, why, rule_name
    if decision == DECISION_FORBIDDEN:
        return Verdict(decision, reason, rule, normalized=normalized, hits=hits)

    # ---- 第 2 关：shell 语法 → 至少 prompt（无法以 argv 安全执行）----
    if _SHELL_SYNTAX_RE.search(cmd):
        hits.append(("shell_syntax", DECISION_PROMPT, "命令包含 shell 元字符"))
        return Verdict(DECISION_PROMPT,
                       "命令依赖 shell 解释（管道/重定向/连接符/变量展开），需人工确认",
                       "shell_syntax", normalized=normalized, hits=hits,
                       reason_key="reason_shell_syntax")

    # ---- 第 3 关：分词 ----
    argv = split_argv(cmd, posix=posix)
    if not argv:
        hits.append(("unparsable", DECISION_PROMPT, "无法可靠分词"))
        return Verdict(DECISION_PROMPT, "命令无法可靠分词（引号未闭合？），需人工确认",
                       "unparsable", normalized=normalized, hits=hits,
                       reason_key="reason_unparsable")

    base_raw = argv[0]
    if not _is_bare_command_name(base_raw):
        hits.append(("path_qualified_binary", DECISION_PROMPT, "基础命令带路径"))
        return Verdict(DECISION_PROMPT,
                       f"基础命令带路径（{base_raw}），无法用白名单校验，需人工确认",
                       "path_qualified_binary", argv=argv,
                       normalized=normalized, hits=hits,
                       reason_key="reason_path_qualified_binary",
                       reason_args={"base": base_raw})

    base = base_raw.lower()
    if base.endswith(".exe"):
        base = base[:-4]

    # ---- 第 4 关：白名单归类 ----
    is_read_only = base in READ_ONLY_BASES
    is_ws_write = base in _WORKSPACE_WRITE_BASES
    is_git_ok = False
    if base == "git" and len(argv) >= 2:
        sub = argv[1].lower()
        # 拒绝子命令前的全局选项：`git -c core.sshCommand=... <sub>` 可执行任意代码
        if argv[1].startswith("-"):
            hits.append(("git_global_option", DECISION_PROMPT, "git 子命令前带全局选项"))
            return Verdict(DECISION_PROMPT,
                           "git 子命令前不允许全局选项（-c 可注入任意命令），需人工确认",
                           "git_global_option", argv=argv,
                           normalized=normalized, hits=hits,
                           reason_key="reason_git_global_option")
        is_git_ok = sub in _GIT_READONLY_SUBS or sub in _GIT_SAFE_WRITE_SUBS
        if sub in _GIT_READONLY_SUBS:
            is_read_only = True
        elif sub in _GIT_SAFE_WRITE_SUBS:
            is_ws_write = True

    if not (is_read_only or is_ws_write or is_git_ok):
        hits.append(("not_allowlisted", DECISION_PROMPT, f"'{base}' 不在 allow 白名单内"))
        return Verdict(DECISION_PROMPT,
                       f"命令 '{base}' 不在免审批白名单内，需人工确认",
                       "not_allowlisted", argv=argv,
                       normalized=normalized, hits=hits,
                       reason_key="reason_not_allowlisted",
                       reason_args={"base": base})

    # ---- 第 5 关：沙箱策略降级 ----
    if is_ws_write and sandbox == SandboxPolicy.READ_ONLY:
        hits.append(("read_only_sandbox", DECISION_PROMPT, "只读沙箱下的写命令"))
        return Verdict(DECISION_PROMPT,
                       "当前为只读沙箱，写命令需人工确认或切换沙箱策略",
                       "read_only_sandbox", argv=argv,
                       normalized=normalized, hits=hits,
                       reason_key="reason_read_only_sandbox")

    # ---- 第 6 关：路径约束（allow 档成立的关键前提）----
    root = Path(project_root).resolve()
    # posix 要一路传下去。`_paths_within` 里 `/` 的含义依平台而定（Windows 是命令开关，
    # POSIX 是绝对路径），不传的话它只能按本机平台判 —— 那个分支就永远只有一半能被测到，
    # 而它恰好是"`cp secret.txt /tmp/x` 会不会被当成工作区内"这种要紧的一半。
    ok, offender = _paths_within(argv, root, posix=posix)
    if not ok:
        hits.append(("path_escape", DECISION_PROMPT, f"路径参数越界: {offender}"))
        return Verdict(DECISION_PROMPT,
                       f"路径参数越出工作区（{offender}），需人工确认",
                       "path_escape", argv=argv, normalized=normalized, hits=hits,
                       reason_key="reason_path_escape",
                       reason_args={"offender": offender})

    hits.append(("allowlisted", DECISION_ALLOW, f"'{base}' 在白名单内且路径均在工作区内"))
    return Verdict(DECISION_ALLOW, f"'{base}' 免审批白名单命中", "allowlisted",
                   argv=argv, normalized=normalized, hits=hits)


def should_execute(verdict: Verdict, approval: str = ApprovalPolicy.DEFAULT,
                   *, user_approved: bool = False) -> Tuple[bool, str]:
    """把判定 + 审批策略 + 用户答复组合成最终的"跑不跑"

    返回 (是否执行, 拒绝原因)。这一层刻意不做 IO —— 询问用户是调用方的事。
    """
    if verdict.forbidden:
        return False, verdict.reason
    if verdict.allowed:
        return True, ""
    # verdict.needs_approval
    if user_approved:
        return True, ""
    if approval == ApprovalPolicy.NEVER:
        # NEVER 的语义是"从不询问"，而不是"什么都放行"。
        # 没有人可问 + 判定为需审批 → 拒绝。这是 SEC-004 那类"失败方向搞反"的反面教材。
        return False, f"{verdict.reason}（当前审批策略 never：无人可询问，按拒绝处理）"
    return False, verdict.reason
