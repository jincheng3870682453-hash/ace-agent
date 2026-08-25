#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.base —— 工具执行基类：共享助手 + execute 分发"""

import os
import re
import sys
import json
import time
import logging
import tempfile
import shutil
import subprocess
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tools.result import Denial, DenialKind, ExecutionResult, denial_kind_of

# ace_net 同样是强依赖：它是所有出站请求的唯一闸门（见 SEC-008）。
# 导入失败宁可让工具层起不来，也不能退回"requests 自己解析、自己跟重定向"的旧行为。
import ace_net

# ace_execpolicy 是**强依赖**，不做可选降级：
# 它是 terminal_exec 唯一的命令安全闸门，导入失败时宁可整个工具层起不来，
# 也不能退回到"没有闸门直接 shell=True"的旧行为。
import ace_execpolicy as execpolicy

# guardian 只用它的 `is_sensitive_file()` 纯判定：SEC-014 之后"哪些文件不进快照"这件事
# 有且只有一份定义，逐次确认的判据必须跟它读同一份清单，否则两边一旦漂移，
# 就会出现"快照不备份它、确认框也不问它"的静默不可逆删除。
import guardian



SHELL_META_RE = re.compile(r"[|&;<>`$\n\r]")
MAX_CODE_LENGTH = 100_000
MAX_COMMAND_LENGTH = 4_000
READ_ONLY_COMMANDS = {"ls", "dir", "pwd", "cat", "type", "echo", "tree",
                      "where", "which", "date", "time", "ver"}
VERSION_ONLY_COMMANDS = {"python", "py", "pip", "node", "npm"}
VERSION_SUBCOMMANDS = {"--version", "-V"}
GIT_READONLY_SUBCOMMANDS = {"status", "log", "diff", "show",
                             "ls-files", "rev-parse", "branch"}

# —— 子进程输出进上下文的统一上限 ——
#
# 定义在 base 而不是 file_tools，是因为"子进程写到 stdout/stderr 的文本"这一类东西
# 有五个出口（git_status / git_log / git_diff / test_execute / performance_profile）在
# 本模块，另外两个（terminal_view / terminal_exec）在 file_tools。同一类通道两份上限
# 就等于没有上限：漏配的那一侧会成为唯一被走的那条路。
#
# 上限不是为了保护内存（1 MiB 打不爆宿主），而是因为这些文本**整段进模型上下文**：
# `git log` 不带 -n、pytest 跑一个大仓库，一次就能把真正重要的历史挤出窗口。
#
# 刻意**不做路径脱敏**：这些字节是外部程序对世界的陈述，不是本层 `resolve()` 的产物。
# 它常常是"到底哪一步失败了"的唯一线索，而且没有结构可言 —— 正则替换只会做出
# "半个路径 + 一个标签"的碎片，既没脱干净又读不懂。能无损脱敏的是本层自己算出来的
# 路径（`_model_path_label`），不是这一类。
MAX_VIEW_OUTPUT_CHARS = 20_000


def _cap_view_text(text: str, cap: int = MAX_VIEW_OUTPUT_CHARS) -> Tuple[str, bool]:
    """截断要进模型上下文的文本，并如实回报是否截断过。

    截了而不说比不截更糟：模型会把"目录里就这些文件"、"pytest 就报了这些"当成完整
    事实，据此得出的结论（"这个项目没有测试"）是错的，而它没有任何线索去怀疑这一点。
    """
    if len(text) <= cap:
        return text, False
    return text[:cap], True


# —— 项目外读取的目录白名单默认值 ——
#
# 只读工具默认限在项目内（SEC-006）。但"看看我桌面上那个报错日志"是真实需求，
# 一律 403 的后果不是更安全，而是用户去关 confine_files —— 那会把整条约束一起关掉。
# 所以留一条窄口：白名单内的目录静默可读，白名单外每次问人，密钥类文件一律硬拒。
#
# 默认值只有桌面与下载：这两个目录的语义本来就是"临时放东西"，而 `~` 根、
# `~/Documents`、`~/AppData` 里躺着浏览器配置、SSH 配置、云盘同步的整份工作资料 ——
# 把它们默认放开，等于用一个便利换掉整台机器的读权限。
DEFAULT_READ_ALLOWLIST: Tuple[str, ...] = ("~/Desktop", "~/Downloads")


# Windows 路径反斜杠修复：模型把 C:\Users\... 直接写进 JSON 时，
# \U、\6 等是非法转义，json.loads 会失败导致整个工具调用被丢弃。
_WIN_PATH_BACKSLASH_RE = re.compile(r'\\([^"\\/bfnrtu])')


def repair_backslash_json(text: str) -> str:
    r"""把 JSON 文本中反斜杠后跟非 JSON 转义字符的 \X 修复为 \\X（C:\Users → C:\\Users）。
    合法转义（\" \\ \/ \b \f \n \r \t \u）不受影响。
    通常用于 json 解析失败后的补救重试（模型输出 Windows 绝对路径时）。"""
    return _WIN_PATH_BACKSLASH_RE.sub(r"\\\\\1", text)


class ActionApproval:
    """交给 `approval_hook` 的"这一次要不要做"请求（鸭子类型，hook 只读这三个属性）。

    SEC-002 的另一半：逐次确认原先只有 `terminal_exec` 一条路径有，而且是
    `ace_execpolicy` 判定命令危险时顺带产生的副产品，不是权限层提供的通用能力。
    于是"提权一次 → 之后所有高危动作一路无阻"。这个类把"问一次人"从命令闸门里
    抽出来，让任何工具都能用同一套语义征求同意。

    `rule` 刻意留空：hook 的 "a"（本会话记住这条规则）因此对它失效，每一次都要
    单独点头。这类动作没有"这一类都放行"的合理语义 —— 同意把一份构建日志 POST
    到某个 webhook，不该顺带同意把 .env POST 到另一个域名。
    """

    rule = ""
    deny_hint = ""

    def __init__(self, normalized: str, reason: str, rule: str = "",
                 deny_hint: str = "") -> None:
        self.normalized = normalized
        self.reason = reason
        # 实例属性覆盖类属性：默认仍是空串（记不住），只有明确给出 rule 的动作
        # 才拿得到"本会话记住"的资格。默认方向朝"多问一次"。
        if rule:
            self.rule = rule
        # deny_hint 是"做决定所需的最后一句话"（不可逆在哪、拒绝后有什么出路）。
        # 它以前只在**无人可问**时才被拼进消息 —— 也就是恰好在有人要做决定时不显示。
        # 挂到请求对象上，hook 才有机会把它摆到用户眼前。
        if deny_hint:
            self.deny_hint = deny_hint



class LaunchApproval(ActionApproval):
    """"启动外部程序"审批：同意打开一个 .txt 不该顺带同意打开一个 .lnk。

    单独留一个子类而不是直接用 `ActionApproval`，是为了让上层 hook 能按类型
    区分提示语（例如给启动类动作加一句"这会启动系统程序"）。
    """


class DestinationApproval(ActionApproval):
    """"访问出站白名单之外的目的地"审批（SEC-013 的另一半）。

    这是唯一**带** `rule` 的一类：单位是目的地（`egress:<host>`），所以 hook 的
    "a" 表示"本会话内这个域名都放行"。理由见 `ace_net` 里出站白名单那一段 ——
    换一个域名是一个新决定，同一个域名的第二次 GET 不是；而把它做成逐次确认，
    `api_get` 就会变成每轮都要点一下的噪音，用户很快就只会无脑点同意。
    """


class ReadApproval(ActionApproval):
    """"读取项目目录之外的路径"审批。

    与 `DestinationApproval` 相反，这一类刻意**不给** `rule`：批准读一次桌面
    不等于批准整个会话随时翻桌面。出站白名单那条理由（"同一域名的第二次 GET
    不是新决定"）在这里不成立 —— 读取的对象是内容而不是通道，同一个目录里
    下一分钟可能多出一份别的东西，那确实是一个新决定。

    想免掉询问的目录走配置 `read_allowlist`（默认桌面 + 下载）：把长期授权写进
    配置，比让人在确认框里顺手点"以后都行"要好 —— 前者是有意识的一次决定，
    后者是疲劳状态下的一次误触。
    """





class ToolExecutorBase:
    def __init__(self, project_root: str = ".", sandbox_base: Optional[str] = None,
                 confine_files: bool = True, email_smtp: Optional[Dict] = None,
                 approval_policy: Optional[str] = None,
                 sandbox_policy: Optional[str] = None,
                 approval_hook=None,
                 egress_allowlist: Optional[List[str]] = None,
                 read_allowlist: Optional[List[str]] = None,
                 use_go_executor: Optional[bool] = None):


        self.project_root = Path(project_root).resolve()
        self.sandbox_base = sandbox_base  # code_execute 沙箱临时目录基路径（None = 系统临时目录）
        self.confine_files = confine_files  # 文件工具是否强制限制在项目目录内
        self.email_smtp = email_smtp or {}  # {"host","port","user","password","use_tls"}
        self.execution_log: List[Dict] = []
        # —— 审批 / 沙箱双闸门（见 ace_execpolicy 与 docs/ADR-002-executor-boundary.md）——
        # 两者正交：approval_policy 管"要不要问人"，sandbox_policy 管"允许它碰什么"。
        self.approval_policy = approval_policy or execpolicy.ApprovalPolicy.DEFAULT
        self.sandbox_policy = sandbox_policy or execpolicy.SandboxPolicy.DEFAULT
        # approval_hook(verdict) -> bool：由上层（CLI / 执行层）注入的"询问用户"实现。
        # 为 None 时表示无人可问 —— 此时判定为 prompt 的命令一律拒绝，而不是放行。
        # 这个默认方向很重要：SEC-004 就是因为非交互场景把默认答案写成了 "y"。
        self.approval_hook = approval_hook

        # —— 出站白名单（SEC-013 的另一半）——
        # None = 用 ace_net 的默认清单（只含 search / image_generate 本来就要访问的端点）。
        # 给了列表就**完全替换**默认值，不做合并：配置里写 ["api.mycorp.com"] 的人，
        # 意思是"只许这一个"，偷偷替他保留三个第三方域名等于没听懂这条配置。
        # 代价是这么配之后 search 会每次问一遍 —— 那正是他要的语义。
        self.egress_allowlist = (list(ace_net.DEFAULT_EGRESS_ALLOWLIST)
                                 if egress_allowlist is None else list(egress_allowlist))

        # —— 项目外读取的目录白名单 ——
        # 与 egress_allowlist 同样是"给了就完全替换、不做合并"：写 ["~/Downloads"]
        # 的人意思是"只有下载目录"，替他偷偷保留桌面等于没听懂这条配置。
        # 传空列表 = 项目外读取全部要问人（预置目录也不例外），这是可表达的最严档。
        self.read_allowlist = (list(DEFAULT_READ_ALLOWLIST)
                               if read_allowlist is None else list(read_allowlist))
        # 被忽略的相对条目只警告一次（见 `_read_allowlisted`）：判定发生在每一次
        # 项目外读取上，不去重的话一份错配置会把日志刷满 —— 刷满的日志等于没有日志。
        self._read_allowlist_warned: set = set()




        # —— Go 执行器（docs/ADR-002 阶段 4）——
        # 默认**开启**。之前默认关闭的理由是"切换不该在用户不知情时发生"，但那条理由
        # 站不住：`_go_executor()` 在二进制不存在 / 起不来时会静默降级回进程内实现，
        # 所以"默认开"不会让任何环境变得不可用；而"默认关"的实际后果是三个沙箱档位
        # 在真实使用中永远不生效 —— 写了进程树回收、内存上限、受限令牌，却没有一条
        # 命令走到它们。默认值决定了安全措施是否存在，不该拿它去换一个不存在的风险。
        #
        # 三态：显式传参 > 环境变量 > 默认开。
        # 排查问题时需要能把它摘掉，所以 ACE_USE_GO_EXECUTOR=0/false/no/off 强制关闭。
        if use_go_executor is None:
            _env = os.getenv("ACE_USE_GO_EXECUTOR", "").strip().lower()
            use_go_executor = _env not in ("0", "false", "no", "off")
        self.use_go_executor = bool(use_go_executor)
        self._go_client = None

    def _go_executor(self):
        """惰性拿到 Go 执行器客户端；不可用时返回 None 让调用方走进程内实现。

        这里吞掉所有异常并降级，是因为执行器是**可选增强**：它起不来（没编译、
        被杀毒拦了、协议不匹配）都不该让 terminal_exec 整个失效。
        真正的安全闸门在 ace_execpolicy，不依赖这个进程存在。
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


    def _resolve_path(self, path_str: str) -> Path:
        """解析写入类路径：~ 展开 + 相对项目根，返回绝对 Path（不做越界判定）

        越界判定由调用方用 _confined() 完成 —— 本方法只负责"算出目标在哪"。
        """
        p = Path(os.path.expanduser(str(path_str)))
        if not p.is_absolute():
            p = self.project_root / p
        return p.resolve()


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

    def _read_allowlisted(self, path: Path) -> bool:
        r"""path 是否落在读目录白名单里（含子目录）。

        逐条 `expanduser` + `resolve` 而不是预先算好：`~` 在测试里会被 monkeypatch
        （HOME/USERPROFILE 改掉），预计算会把构造那一刻的主目录固化下来。

        **只认绝对路径与 `~` 开头，相对条目一律忽略。** 原实现直接
        `Path(entry).resolve()`，相对条目会按**进程当前工作目录**解析 —— 于是同一份
        配置，ACE 从哪个目录启动，"不必问用户就能读"的范围就指向哪里；从 `C:\` 启动时
        一个 `"."` 等于把整个 C 盘静默放开。授权范围不该取决于启动姿势。
        改成按 `project_root` 解析也不行：那会留下 `"../shared"` 这种"看着像项目内、
        实际把范围扩到项目外"的写法，而这条配置的全部意义就是**明确写出**哪些项目外
        目录长期可读 —— 判据必须能一眼看出它指向哪。

        忽略必须留痕：老配置里的相对条目会因此失效，静默失效会让用户以为白名单还生效着，
        直到某次读取突然开始问人才发现（或者更糟：以为已经限住了，其实条目压根没生效）。
        """
        for entry in self.read_allowlist:
            candidate = Path(os.path.expanduser(str(entry)))
            # 用 `Path.is_absolute()` 而不是 `os.path.isabs()`：Windows 上 `\foo`、
            # `C:foo` 这类"有根没盘符 / 有盘符没根"的写法同样要靠 cwd 补全，
            # `is_absolute()` 要求盘符与根都在，正好把它们一起挡掉。
            if not candidate.is_absolute():
                if str(entry) not in self._read_allowlist_warned:
                    self._read_allowlist_warned.add(str(entry))
                    logging.getLogger("ace").warning(
                        "read_allowlist 条目 %r 是相对路径，已忽略：授权范围不能依赖"
                        "进程当前工作目录。请改成绝对路径或 ~ 开头的路径。", entry)
                continue
            try:
                root = candidate.resolve()
            except (OSError, ValueError):
                # 配置里写了非法路径不该让整个判定崩掉，跳过这一条继续看下一条。
                continue
            try:
                path.relative_to(root)
                return True
            except ValueError:
                continue
        return False


    # —— 拒绝文案的三条通道（人 / 模型 / 日志）——
    #
    # 一次拒绝会被三个受众消费，它们的信任级别不同，所以载体必须分开：
    #   * **确认框**（人）：`request_cls(summary, …)`，必须给完整真实路径 ——
    #     用户要靠它做决定，打码等于让人瞎点头。
    #   * **`message`**（模型）：会原样进入模型上下文（`execution_layer` 的错误
    #     payload 带 `message`）。这里出现 `resolve()` 之后的绝对路径，等于把用户名、
    #     项目在磁盘上的位置、以及软链背后的**真实**文件名（`id_rsa`）白送给模型，
    #     而模型的下一步完全可能是一次外发请求 —— 泄漏就此离开本机。
    #   * **`metadata`**（日志 / UI）：错误 payload 里没有 `metadata` 键，
    #     `agent_runner.render_result` 的白名单也不含它，所以它是唯一"人能看到、
    #     模型看不到"的通道。细分原因与完整路径放这里。
    #
    # 键名沿用既有风格（`metadata={"policy": {...}}` 那种一层嵌套）。
    DENIAL_METADATA_KEY = "denial"

    # 项目外路径给模型看时的替代文案。刻意说明"路径被隐去"而不是闷着不提：
    # 哑消息会让模型以为 ACE 自己丢了路径，转头用同一个参数重试一遍。
    OUTSIDE_PATH_LABEL = "项目外路径，完整路径不回显给模型"

    @staticmethod
    def _deny(kind: str, message: str,
              detail: Optional[Dict[str, Any]] = None) -> Denial:
        """造一个拒绝理由，并把"只给人看"的细节挂到 `detail` 上（走 metadata，不进 message）。

        `Denial` 是 `str` 子类，往实例上挂属性不影响任何既有的
        `"xxx" in message` 断言和 `Optional[str]` 签名 —— 这也是当初它继承 str 的理由。
        """
        denial = Denial(kind, message)
        if detail:
            # 统一转成 str：metadata 会被 json.dumps 写进日志，Path 不可序列化。
            denial.detail = {k: str(v) for k, v in detail.items() if v is not None}
        return denial

    def _model_path_label(self, path: Path) -> str:
        """把一个已 resolve 的路径压成"可以进模型上下文"的标签。

        - **项目内** → 相对项目根的相对路径。诊断能力一分不减（模型下一步本来就
          该传相对路径），顺手把绝对前缀里的用户名和项目位置摘掉。
        - **项目外** → 只给类别，不给路径。这里不是"路径笼统地敏感"：输入是软链时
          `resolve()` 得到的是**目标**，回显它等于告诉模型"你指的那个东西其实叫
          id_rsa"。模型定位问题并不需要它 —— 它知道自己刚传了什么，真正缺的是
          "边界在哪、下一步怎么改"，那由 `reason` / `denial_kind` / `deny_hint` 给。
        """
        confined = self._confined(path)
        if confined is None:
            return self.OUTSIDE_PATH_LABEL
        try:
            return str(confined.relative_to(self.project_root)) or "."
        except ValueError:
            return self.OUTSIDE_PATH_LABEL

    def _launch_path_label(self, path: Path) -> str:
        """`open_file` / `edit_file` / 截图落盘这一类"给用户去点"的字段用的标签。

        和 `_model_path_label` 分开，因为这些字段有一个**已经存在的消费者**：
        `ai_code._print_clickables` 拿 `data["path"]` / `data["image_path"]` 去拼
        `file:///` URI（`_clickable_uri`）。换成相对路径会拼出一条点不开的链接 ——
        脱敏的收益是零，代价是这个工具唯一的产出失效。

        - **项目内** → 原样给绝对路径。这一份不是新泄漏：`【工作目录】<绝对路径>`
          由 `ai_code` 与 `agent_runner` 每轮都注入系统提示词，项目根早就在上下文里了。
        - **项目外** → 只给类别标签。这一份才是新信息，而 `open_file` 自己在
          "不 auto_open"那条分支上已经定过同一个口径：项目外的文件连链接都不给，
          因为链接会把项目外的布局透进上下文、还顺带诱导用户点击。批准"打开一次"
          不等于批准"把这个位置写进上下文供后续每一轮引用"。
        """
        if self._confined(path) is None:
            return self.OUTSIDE_PATH_LABEL
        return str(path)

    # —— 别人拼好的错误文本进 message 前的过滤（默认拒绝）——
    #
    # 适用对象：**不由本层拼装**的失败文本 —— 解析器的 `error`、第三方库的异常串。
    # 原来的做法是 `raw.replace(str(p), label)`，它是**默认放行**：除了我恰好认出的
    # 那一种写法，其余一律照原样进模型上下文。而"路径被渲染成什么样"由下游决定 ——
    # `OSError.__str__` 用 `%r` 渲染文件名，Windows 上出来的是 `'C:\\Users\\…'`
    # （反斜杠成对），跟 `str(p)` 的 `C:\Users\…` 不是同一个子串，`replace` 一声不响
    # 地失配，绝对路径原样漏出去，而断言只要用了能命中的那种 fixture 就是绿的。
    # 再补 `repr(p)` / `as_posix()` / 双反斜杠 也只是多猜几种渲染，猜漏一种就再静默
    # 失效一次 —— 同一个失败模式会一直回来。
    #
    # 这里把判定方向反过来：逐 token 走，**只有能证明"它不是路径"的 token 才留下**。
    # 判据是路径自身的形态约束，不是对下游渲染方式的猜测：任何能定位到文件的写法都
    # 必须带路径分隔符（`\` `/`）或盘符（`C:`），唯一的例外是**没有目录部分的裸名字**，
    # 所以再显式挡掉这次这条路径自己的各级名字、以及家目录 / 项目根的各级名字。
    # 认漏一种写法的后果也反了：多抹掉一个词（失败原因仍在，全文还在 `metadata`），
    # 而不是漏出一条绝对路径。
    UNSAFE_TOKEN_LABEL = "（路径已隐去）"

    # 只用来兜住"孤零零一个盘符"这种带分隔符判据抓不到的形态（`C:`）。
    _DRIVE_ONLY_RE = re.compile(r"^[A-Za-z]:$")

    # 从 token 两端剥掉的包裹符：`'C:\x'`、`(path)`、`路径:` 这类外壳不该影响判定。
    _TOKEN_WRAPPERS = "'\"`()[]{}<>,;:.，。、；：（）【】《》"

    def _private_name_parts(self, related=()) -> set:
        """收集"单独出现也算泄漏"的裸名字：家目录 / 项目根 / 本次这条路径的各级名字。

        含空格的层级（`ai angent`）不会等于任何一个按空白切出来的 token，所以它只能
        以带分隔符的形态出现 —— 那一档由分隔符判据管，这里不必也不该把它拆成单词
        （拆了会把 `ai`、`test` 这种常用词一起打掉，等于把失败原因也抹了）。
        """
        names = set()
        roots = [self.project_root]
        try:
            roots.append(Path.home())
        except (OSError, RuntimeError):
            pass
        for p in list(roots) + [Path(str(x)) for x in related]:
            for part in p.parts:
                part = part.strip("\\/").strip()
                # 单字符层级（盘符根、`/`）没有识别价值，留着只会误伤正常词。
                if len(part) > 1 and not part.endswith(":"):
                    names.add(part.lower())
        return names

    def _token_is_path_like(self, token: str, private_names: set) -> bool:
        """这个 token 有没有可能是一条路径（或路径里的一级名字）。"""
        if "\\" in token or "/" in token or "~" in token:
            return True
        bare = token.strip(self._TOKEN_WRAPPERS)
        if self._DRIVE_ONLY_RE.match(bare):
            return True
        return bare.lower() in private_names

    def _model_safe_fragment(self, text: Any, related=()) -> str:
        """把外层拼好的失败文本压成"可以进 message"的片段（见上方那段说明）。

        `related` 传本次涉及的路径：它的各级名字因此也进禁止清单，挡住"错误里只剩
        一个裸文件名"这唯一不带分隔符的路径形态（软链解析后的真名就是这么漏的）。
        """
        private_names = self._private_name_parts(related)
        kept: List[str] = []
        for token in str(text).split():
            if self._token_is_path_like(token, private_names):
                # 连续多个被隐去的 token 只留一个标记：`C:\a\b c\d.txt` 被空白切开后
                # 是两个 token，连着放两个标记只是噪音。
                if kept and kept[-1] == self.UNSAFE_TOKEN_LABEL:
                    continue
                kept.append(self.UNSAFE_TOKEN_LABEL)
            else:
                kept.append(token)
        return " ".join(kept).strip()

    @staticmethod
    def _normalize_for_leak_check(text: Any) -> str:
        """把一段文本归一到"同一条路径的各种写法都长一样"的形态，供兜底校验比对。

        成对反斜杠（`%r` / JSON 转义的产物）、正斜杠、大小写、重复分隔符全部归一 ——
        兜底校验要的是"这条 message 里有没有出现私有根"，而不是"它用哪种写法出现"。
        """
        norm = str(text).replace("\\", "/").lower()
        while "//" in norm:
            norm = norm.replace("//", "/")
        return norm

    def _mentions_private_root(self, text: Any) -> bool:
        """归一化后判断文本里有没有出现项目根 / 家目录（这是不变量，不是文案约定）。"""
        norm = self._normalize_for_leak_check(text)
        if not norm:
            return False
        roots = [self.project_root]
        try:
            roots.append(Path.home())
        except (OSError, RuntimeError):
            pass
        for root in roots:
            key = self._normalize_for_leak_check(root).rstrip("/")
            # 盘符根（`c:`）这种只有一层的"根"命中率是 100%，拿它做判据等于把所有
            # message 都判成泄漏 —— 只在根确实有层级时才比对。
            if key.count("/") >= 1 and len(key) >= 4 and key in norm:
                return True
        return False

    def _sealed_message(self, message: str, fallback: str) -> str:
        """message 出厂前的兜底校验：整条消息里绝不允许出现项目根 / 家目录。

        为什么它不会像 `replace` 那样静默失效：判据挂在**不变量**上（"这条 message
        里不许出现私有根"），而不是挂在"我猜下游会把路径渲染成什么形状"上；比对前
        先做归一化（见 `_normalize_for_leak_check`），所以成对反斜杠、正斜杠、大小写
        不同的三种写法落在同一个子串上。命中就整条丢弃换成 `fallback` —— 失败方向是
        "少说一句话"，不是"多漏一条路径"。
        它是第二道：第一道 `_model_safe_fragment` 已经保证 message 只由本层的常量 +
        `_model_path_label()` 拼成。两道都不依赖下游异常怎么渲染。
        """
        if self._mentions_private_root(message):
            # 必须留痕：走到这里说明第一道漏了一种形态，那是要修的代码缺陷；
            # 静默替换会让它永远不被发现（这轮修的就是"静默"本身）。
            logging.getLogger("ace").error(
                "message 出厂校验拦下一条含本机路径的文案，已替换为兜底文案")
            return fallback
        return message

    # 本层拼进 message 的片段被兜底拦下时的替代文案。只换掉**这一段**，
    # 不动整条 message：见 `_sealed_fragment` 的说明。
    SEALED_FRAGMENT_LABEL = "（该段含本机路径，未回显给模型）"

    # 逐次确认的"给模型看的摘要"被兜底拦下时的替代片段（见 `_approve_action`）。
    # 与上面那条分开是为了让日志里看得出是哪一类出口兜住的：一个是"哪一步坏了"，
    # 一个是"这次要批准什么"，混成同一句话就没法回答"该去修谁"。
    SEALED_SUMMARY_LABEL = "（摘要含本机路径，未回显给模型；完整摘要见确认框与日志）"


    def _sealed_fragment(self, text: Any, related=()) -> str:
        """把"本层自己拼进 message 的那一段"过完两道过滤，返回可以进 message 的片段。

        为什么要有这个函数、而不是让每个统一出口各自调两遍：`_model_safe_fragment`
        （默认拒绝的 token 过滤）和 `_sealed_message`（不变量兜底）是**一对**，
        少调一道就退回这一整轮反复踩的失败模式 —— 收口处只覆盖一半，作者以为
        自己受保护。

        为什么单位是"片段"而不是"整条 message"：兜底命中时整条换成 fallback 的代价
        极大（模型丢掉全部诊断信息，连"哪个异常类型"都没了），而这条 message 通常
        是**几段拼起来**的，出问题的只可能是本层拼进去的那一段。按段兜底能把损失
        限制在那一段上，其余（异常类型、上限提示、外部程序的 stderr）照常送到。
        """
        return self._sealed_message(
            self._model_safe_fragment(text, related=related),
            self.SEALED_FRAGMENT_LABEL)


    def _approve_read_outside(self, path: Path) -> Optional[str]:

        """项目外读取的闸门；None = 可读，否则返回拒绝原因（调用方映射成 403）。

        三段顺序不能换：

        1. **密钥类文件一律硬拒，连问都不问。** 放在白名单之前，否则
           `~/Desktop/.env`、`~/Downloads/id_rsa` 就成了静默可读 —— 用户给出
           "桌面可读"这个授权时，脑子里想的是那份报错日志，不是躺在同一个目录里的私钥。
           也不给"要不要读"的选项：确认框里只有一个文件名，看不出它是不是当前有效的凭据。
        2. **白名单内静默放行。** 默认桌面 + 下载，见 `DEFAULT_READ_ALLOWLIST`。
        3. **其余每次都问**，且刻意不带 `rule` —— 见 `ReadApproval` 的说明。
        """
        if guardian.is_sensitive_file(path):
            # 不回显 basename：`DenialKind.SECRET_FILE` 的指令（见
            # `execution_layer.DENIAL_INSTRUCTIONS`）已经把类别说全了，多给一个
            # `id_rsa` 不改变模型的下一步，只多泄漏一次软链背后的真名。
            return self._deny(DenialKind.SECRET_FILE,
                              "拒绝读取密钥类文件：这类文件不在任何目录授权范围内，"
                              "也不提供逐次确认",
                              {"category": "密钥类文件", "target": path})
        if guardian.is_sensitive_location(path):
            return self._deny(DenialKind.SECRET_FILE,
                              "拒绝读取凭据目录下的文件："
                              ".ssh / .aws / .gnupg / .kube 这类目录整体硬拒，不提供逐次确认",
                              {"category": "凭据目录", "target": path})
        if self._read_allowlisted(path):
            return None
        return self._approve_action(
            str(path), "读取项目目录之外的路径",
            request_cls=ReadApproval,
            deny_hint="内容会进入模型上下文。常用目录可写进配置 read_allowlist 以免每次询问。",
            model_summary=self._model_path_label(path),
            detail={"category": "项目外读取", "target": path})


    def _deny_never_writable(self, action: str, path: Path) -> Optional[str]:
        """写侧的"永不可写"黑名单：命中就硬拒，不问人。None = 不在黑名单里。

        SEC-009。读侧一直有硬拒，写侧一直没有，于是 `~/Desktop/.env` 读不了、
        覆盖却可以；更要紧的是写闸门挂在 `path.exists()` 上（"新建没什么可撤销的"），
        而持久化攻击恰好只需要新建 —— `~/.ssh/authorized_keys`、启动目录里的一个
        `.bat`，都是原本不存在的文件。"能不能回滚"这条判据度量的是数据损失，
        度量不到"这次写入改变了系统的执行路径或凭据"。

        黑名单**只对项目外生效**：项目内的 `.env` 必须仍然可写（"帮我把 key 写进
        本项目的 .env"是日常需求），它走 `_approve_unrecoverable` 的逐次确认。
        范围也刻意窄 —— 一刀切的结果是用户关掉 `confine_files`，那一下连相对路径
        穿越保护一起没了，安全性从"有缺口"跌到"零"。
        """
        if self._confined(path) is not None:
            return None
        reason = ""
        if guardian.is_sensitive_location(path):
            reason = "凭据目录（.ssh / .aws / .gnupg / .kube / .ace 等）"
        elif guardian.is_sensitive_file(path):
            # 同 `_approve_read_outside`：类别足够，basename 不给模型。
            # `DenialKind.NEVER_WRITABLE` 的指令已经说明这一档没有确认通道，
            # 多一个文件名只会让"这次写的其实是 ~/.ssh/id_rsa"进上下文。
            reason = "密钥类文件"
        else:
            segs = [s.lower() for s in path.parts]
            if "startup" in segs:
                reason = "开机启动目录（写入等于取得持久化执行）"
            elif os.name == "nt" and any(s in ("system32", "syswow64", "windows") for s in segs):
                reason = "系统目录"
        if not reason:
            return None
        return self._deny(DenialKind.NEVER_WRITABLE,
                          f"拒绝{action}：目标位于{reason}，属项目外永不可写范围，不提供逐次确认。"
                          f"这类写入改变的是系统的凭据或执行路径，不是可以回滚的数据。",
                          {"category": reason, "target": path, "action": action})


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
        """URL 出站校验：通过返回 None，否则返回拒绝原因（见 ace_net）。

        这里只判断"能不能连"，**不负责连接**。本进程自己发的请求一律走
        `ace_net.safe_request`：把校验和连接分成两步的那一刻，DNS rebinding
        和重定向绕过就回来了（SEC-008 的成因）。本方法只留给交不出连接控制权的
        场景 —— 例如 `browser_open` 把 URL 递给系统浏览器。
        """
        return ace_net.check_url(url)

    def _resolve_read_path(self, path_str: str) -> Optional[Path]:
        """解析"读内容"用的路径：~ 展开 + 相对项目根；**越界或网络路径返回 None**。

        SEC-005 的另一半。这个函数以前只算路径、不做判定，于是 `parse_document`、
        `code_analyze`、`open_file` 这几个"只读"工具拿着绝对路径就能摸到项目外的
        任意文件（`~/.aws/credentials`、桌面上的任何东西）。可执行扩展名黑名单挡住的
        是"执行"，挡不住"路径"：文件内容照样能读、`file://` 链接照样能生成。

        口径与 `terminal_view` 的 cat/ls 对齐（SEC-006）—— 否则
        `cat <项目外绝对路径>` 被拒、`parse_document <同一路径>` 放行，
        "换个工具"本身就成了绕过手段。
        """
        if self._is_network_path(path_str):
            return None
        p = Path(os.path.expanduser(str(path_str)))
        if self.confine_files:
            return self._confined(p)
        if not p.is_absolute():
            p = self.project_root / p
        return p.resolve()

    @staticmethod
    def _is_network_path(path_str: str) -> bool:
        r"""UNC / 网络路径判定。这类路径一律拒绝，连问都不问：

        `\\attacker\share\x.txt` 一经访问就会发起 SMB 出网并把 NTLM 凭据交给对面，
        而确认框里的字面量看不出这一层 —— 用户没有足够信息做这个决定，
        所以这里不给"要不要打开"的选项。
        """
        raw = str(path_str).strip()
        return raw.startswith("\\\\") or (os.name == "nt" and raw.startswith("//"))

    def _resolve_launch_target(self, path_str: str) -> Tuple[Optional[Path], bool]:
        """解析"交给系统打开"用的路径，返回 (绝对路径, 是否在项目外)；网络路径 → (None, False)。

        和 `_resolve_read_path` 分成两条口径，因为两件事的风险不同：读内容可以一律
        限在项目内，而"打开桌面文件夹"是真实需求，砍掉不如把决定权交回用户 ——
        项目外的目标一律走 `_approve_launch()` 逐次确认。

        注意这里**不能**照搬 `file_write` 那条"绝对路径 = 用户明确意图"的规则：
        那里的路径来自用户的话，这里的路径来自模型的输出。
        """
        if self._is_network_path(path_str):
            return None, False
        p = Path(os.path.expanduser(str(path_str)))
        if not p.is_absolute():
            p = self.project_root / p
        p = p.resolve()
        outside = bool(self.confine_files) and self._confined(p) is None
        return p, outside

    def _approve_action(self, summary: str, reason: str,
                        request_cls=ActionApproval,
                        deny_hint: str = "", rule: str = "",
                        model_summary: Optional[str] = None,
                        detail: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """逐次确认的通用闸门；None = 放行，否则返回拒绝原因（调用方映射成 403）。

        无审批通道时拒绝，方向与 SEC-004 一致：没人可问不等于默认同意。
        hook 自己抛异常也算拒绝 —— 询问机制坏了不该变成"于是不问了"。

        **`summary` 与 `model_summary` 是两个受众，不是同一句话的两种写法**（见类里
        `DENIAL_METADATA_KEY` 上方那段说明）：

        - `summary` 给**人**：进 `request_cls(...)`，也就是确认框。它必须足以让人
          判断"这一次要不要"（完整路径 / 完整 URL / 收件人）。写得含糊等于把决定权
          名义上交出去、实际上没交。
        - `model_summary` 给**模型**：进 `message`，而 `message` 会进模型上下文。
          默认沿用 `summary` —— 出站目的地、外发正文这类摘要本来就是模型自己给出的
          URL 与 payload，回显它不构成泄漏。只有**路径**这一类必须显式传：那一份是
          `resolve()` 之后的结果，含用户名、磁盘布局、软链背后的真名，模型没给过
          也不需要（用 `_model_path_label()` 压一下）。

        `detail` 只进 `metadata`（日志 / UI），不进 `message`。
        `rule` 默认空 = hook 的 "a" 记不住这次同意。只有"信任单位比单次动作更大"
        的动作才该给它（目前只有出站目的地：`egress:<host>`）。

        `model_view` 出厂前过一遍**不变量兜底**（`_sealed_message`）：这条契约靠调用方
        "记得传 `model_summary`"来维持，而漏传不会报错、只会静默把完整路径送进上下文
        （`_approve_outbound` 就这么漏了一个 SMTP host）。兜底只吃摘要这一段，
        `reason` 与 `deny_hint` 照常送到 —— 模型至少知道自己被什么拦了、下一步去哪。

        这里刻意**不叠** `_model_safe_fragment` 那道逐 token 过滤：摘要里最常见的
        合法内容是**完整 URL**，而 URL 带 `/`，逐 token 判定会把它整条当成路径抹掉 ——
        那正好抹掉出站确认唯一要给模型的东西（能带走数据的是查询串）。这一层只挂
        "不许出现本机私有根"这条不变量，它跟 URL 不冲突。
        """
        model_view = self._sealed_message(
            summary if model_summary is None else model_summary,
            self.SEALED_SUMMARY_LABEL)


        if self.approval_hook is None:
            tail = f" {deny_hint}" if deny_hint else ""
            return self._deny(DenialKind.APPROVAL_UNAVAILABLE,
                              f"此操作需要人工确认，但当前无审批通道（非交互运行）："
                              f"{reason}（{model_view}）。{tail}".rstrip(),
                              detail)
        try:
            approved = bool(self.approval_hook(
                request_cls(summary, reason, rule, deny_hint)))
        except Exception as e:
            # 只留异常**类型**：hook 由上层注入，它的异常文本不受本层控制，
            # 完全可能把路径、命令行甚至凭据带进来（`FileNotFoundError` 的 str 就带路径）。
            # 类型足够让模型知道"这不是用户拒绝、别重试"；全文进 metadata 供人排障。
            return self._deny(DenialKind.APPROVAL_ERROR,
                              f"审批回调异常（{type(e).__name__}），按拒绝处理",
                              {**(detail or {}), "hook_error": f"{type(e).__name__}: {e}"})
        if not approved:
            # 不说"用户拒绝"：非 TTY / hook 返回 False 的场景里压根没人被问过，
            # 谎称用户拒绝会让模型和用户都误判刚才发生了什么。同时点明"什么都没做"，
            # 并把出路（deny_hint）带上 —— 否则用户只知道被挡了，不知道怎么继续。
            tail = f" {deny_hint}" if deny_hint else ""
            return self._deny(DenialKind.APPROVAL_DENIED,
                              f"此操作未获批准（{reason}：{model_view}）。未执行任何操作。"
                              f"{tail}".rstrip(),
                              detail)
        return None

    def _denied(self, gate: str, code: str = "403") -> ExecutionResult:
        """把闸门的拒绝理由包成 ExecutionResult，顺带把 `denial_kind` 与 metadata 带上。

        所有 403 出口都该走这里，而不是自己拼 `ExecutionResult(...)` ——
        自己拼的那些会丢掉 kind，上层就只能退回猜文案；现在还会一起丢掉
        `_deny(detail=…)` 里那份"只给人看"的细节（完整路径、细分原因）。

        **这里刻意不套 `_sealed_message`。** 理由不是"忘了"，是套上去会误伤：
        闸门理由里出现本机路径的最常见情形是**回显模型自己刚传进来的那个参数**
        （`file_tools` 的"路径越界：超出项目目录范围: {raw}"、通配符那条同理）——
        模型给的字符串回显给模型不是泄漏，而兜底命中的动作是整条换 fallback，
        那会把"越界"这个唯一有用的诊断也一起抹掉，模型只能原样重试。
        真正需要兜住的是**本层 resolve 出来的**路径，那一份的产生点在
        `_approve_action`（`model_view` 那一段已收口）与 `_model_path_label`。
        """

        detail = getattr(gate, "detail", None)
        return ExecutionResult(status="error", error_code=code, message=str(gate),
                               denial_kind=denial_kind_of(gate),
                               metadata=({self.DENIAL_METADATA_KEY: dict(detail)}
                                         if detail else {}))

    # 内部故障的 metadata 键（与 DENIAL_METADATA_KEY 分开：这不是"谁拦的"，
    # 而是"哪里坏了"，日志侧要能一眼分辨，别混进拒绝统计里）。
    ERROR_METADATA_KEY = "exception"

    def _internal_error(self, what: str, exc: BaseException,
                        code: str = "500") -> ExecutionResult:
        """内部故障的统一出口：`message` 只留异常**类型**，全文进 `metadata`。

        `str(exc)` 是本层控制不了的文本，而它会原样进模型上下文：
        `FileNotFoundError` / `PermissionError` 的 str 就是一条完整绝对路径，
        `OSError` 还会带上盘符与系统目录布局，第三方库的异常里什么都可能有
        （连接串、token）。而模型拿这些做不了任何事 —— 它要判断的只是
        "这不是我的参数错，别原样重试"，异常类型足够表达这一点。
        全文放 `metadata`：错误 payload 不带这个键（见 `execute` 上方那段
        三通道说明），所以它是唯一"人能看到、模型看不到"的通道。

        `what` 用来说明是哪一步坏了 —— 只有类型没有位置的话，人拿到
        `OSError` 也不知道该看哪。

        **`what` 也要过 `_sealed_fragment`，这是这个出口存在的意义。** 它是调用方
        拼的字符串，今天全是常量，但下一个人写 `_internal_error(f"读取 {p} 失败", e)`
        是完全自然的 —— 那一下就把 resolve 后的绝对路径送进了模型上下文，而这个
        出口的全部卖点恰恰是"用了它就不会泄漏"。判据放在这里，新增的 500 出口
        **默认**安全；放在调用点，就又变成"作者得记得"，而"逐调用点自觉"
        已经证明是漏一处等于没修、测试还给绿灯的失败模式。
        """
        return ExecutionResult(
            status="error", error_code=code,
            message=f"{self._sealed_fragment(what)}（{type(exc).__name__}）",
            metadata={self.ERROR_METADATA_KEY: f"{type(exc).__name__}: {exc}"})





    # 子进程输出的 metadata 键。与 ERROR_METADATA_KEY 分开：那一个是"本进程哪里坏了"，
    # 这一个是"外部程序说了什么" —— 混在一起，日志侧就没法把"ACE 有 bug"和
    # "git 报了个错"分开统计。
    SUBPROCESS_METADATA_KEY = "subprocess"

    def _subprocess_failed(self, what: str, proc, code: str = "500") -> ExecutionResult:
        """子进程返回非零时的统一出口：stderr **原样**进 message，只加上限。

        为什么不脱敏（见模块顶部 `MAX_VIEW_OUTPUT_CHARS` 那段）：stderr 是 git 自己
        写的文本，不是本层 `resolve()` 出来的路径。只擦这几处错误路径的 stderr 属于
        安慰剂 —— 同一类字节在 `test_execute` / `performance_profile` / `terminal_exec`
        的**成功**路径上整份放进 `data`，堵三个小洞留四个大洞，判据还不一致了。

        为什么要上限：这条 message 整段进模型上下文，而 `git log` 的 stderr 在仓库损坏
        时能刷出几十万字，把真正重要的历史挤出窗口。截断必须如实上报，否则模型会把
        "错误就这些"当完整事实。

        全文另外进 `metadata`：错误 payload 不带 `metadata`，那是唯一"人能看到、
        模型看不到"的通道，排障要的是完整那份。

        **兜底只套在 `what` 上，刻意不套在 stderr 上。** 不变量（"message 里不许出现
        本机路径"）在这一个出口上必须让位于上面那条判据：`git` / `pytest` 的 stderr
        里出现项目根是**常态**（`error: pathspec ... did not match`、pytest 的
        rootdir 行），而兜底命中的动作是"整段换成 fallback" —— 套上去等于把绝大多数
        子进程失败的诊断信息整片抹掉，换来的安全收益是零：那条路径是外部程序自己
        写出来的，不是本层 `resolve()` 的产物，且同一批字节在成功路径上本来就整份
        进 `data`（`_subprocess_output`）。堵这一处只会让判据自相矛盾。
        """
        raw = proc.stderr or ""
        shown, truncated = _cap_view_text(raw)
        tail = f"（stderr 已截断至 {MAX_VIEW_OUTPUT_CHARS} 字符，全文见日志）" if truncated else ""
        return ExecutionResult(
            status="error", error_code=code,
            message=f"{self._sealed_fragment(what)}: {shown}{tail}",
            metadata={self.SUBPROCESS_METADATA_KEY: {
                "returncode": proc.returncode, "stderr": raw,
                "stderr_truncated": truncated}})


    @staticmethod
    def _subprocess_output(proc) -> Dict[str, Any]:
        """把子进程的成功输出压成 `data`：同一份上限，同一句"截了没有"。

        `test_execute` / `performance_profile` 原先把整份 stdout+stderr 直接塞进
        `data`，一个字都不截 —— 而 `terminal_view` / `terminal_exec` 早就有上限。
        同一类通道两套规矩，模型上下文会从没上限的那一侧被灌满。
        """
        out, out_trunc = _cap_view_text(proc.stdout or "")
        err, err_trunc = _cap_view_text(proc.stderr or "")
        return {"output": out, "error": err, "returncode": proc.returncode,
                "truncated": out_trunc or err_trunc}

    @staticmethod
    def _outbound_preview(value: Any, limit: int = 240) -> str:

        """把要外发的内容压成一行摘要，供确认框展示。

        刻意**不做**打码：确认框的作用就是让用户看见"这次要发出去的是什么"。
        把 token 打成 sk-***、把正文省略成"（略）"会让人以为没什么要紧的东西，
        而这恰好是外发确认唯一需要拦住的情况。
        """
        if value is None or value == "" or value == {} or value == []:
            return "（空）"
        try:
            text = value if isinstance(value, str) else json.dumps(
                value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            text = repr(value)
        text = " ".join(str(text).split())
        if len(text) > limit:
            return f"{text[:limit]}…（共 {len(text)} 字符）"
        return text

    # 不传 `model_summary` 时，给模型的那一份摘要里目的地用这个占位。
    # 默认方向是"不给"，因为 base 无法判断调用方拼进 destination 的东西从哪来：
    # `api_post` 的目的地是模型自己给的 URL（回显无害），`notify_send(email)` 的
    # 目的地里嵌着**用户配置**的 SMTP host（回显就是泄漏）。默认放行会让后一类
    # 静默漏出去，默认隐去最坏只是模型少看到一个它本来就知道的 URL —— 而那一类
    # 调用点可以显式传 `model_summary` 把它加回来（见 `web_tools._exec_api_post`）。
    OUTBOUND_DESTINATION_LABEL = "（目的地未回显给模型，完整目的地见确认框）"

    def _approve_outbound(self, destination: str, payload: Any,
                          model_summary: Optional[str] = None) -> Optional[str]:
        """外发数据前的逐次确认（SEC-013）；None = 放行，否则返回拒绝原因。

        `write` 档位的语义是"可以修改这个项目"，它不该顺带包含"可以把项目里的东西
        寄出去"：改坏的文件能回滚，寄出去的内容不能。原实现里 `api_post` 与
        `notify_send(email)` 只要拿到 write 就一路无阻，而目标地址和正文全部来自
        模型输出 —— 提示注入要的就是这条出口。

        `destination` 一直同时喂给两个受众，这是一处真泄漏：确认框**必须**显示完整
        目的地（否则人无法判断这一次要不要），而同一个串又被 `_approve_action` 当成
        `message` 送进模型上下文 —— 于是拒绝一次 email，用户配置的 SMTP host 就进了
        上下文。拆开的办法不是把确认框写糊（那等于名义上交出决定权、实际没交），
        而是让模型侧那一份**默认不含目的地**，需要回显的调用点显式声明。

        `model_summary` 替换的只是**目的地这一段**，正文摘要两个受众看到的是同一份：
        payload 本来就是模型自己给出的内容，回显它不构成泄漏，而它恰恰是模型判断
        "这次被拒的是哪一笔外发"所需要的。
        """
        preview = self._outbound_preview(payload)
        dest_for_model = (self.OUTBOUND_DESTINATION_LABEL
                          if model_summary is None else model_summary)
        return self._approve_action(
            f"目的地 {destination}｜外发内容：{preview}",
            "把数据发往项目外",
            deny_hint="外发内容离开本机后无法撤回。",
            model_summary=f"目的地 {dest_for_model}｜外发内容：{preview}")


    def _egress_allowlisted(self, url: Any) -> bool:
        """目的地是否在出站白名单里。放在工具里先问这一句是为了省掉一次 DNS ——
        清单内的请求不该为了"要不要问人"多解析一遍。"""
        return ace_net.url_in_allowlist(url, self.egress_allowlist)

    def _approve_destination(self, url: Any, *, redirect_from: str = "") -> Optional[str]:
        """访问白名单外的目的地前确认一次（SEC-013 另一半）；None = 放行。

        摘要给的是**完整 URL**而不只是域名：能带走数据的正是查询串本身
        （`https://evil.tld/?data=…`），只显示域名等于把要判断的东西藏起来。

        这里自己也过一遍白名单，和调用方的 `_egress_allowlisted()` 判定重复 ——
        重复是刻意的：调用方那一层只为省掉一次 DNS，漏写它不该变成"白名单形同虚设"。

        `redirect_from` 非空表示这是跟随重定向落到的新目的地（见 `_hop_gate`），
        原因里要说出来源，否则用户看到一个自己没输入过的域名会不知道它从哪来。
        """
        if self._egress_allowlisted(url):
            return None
        host = ace_net.url_host(url)

        if not host:
            # 这条以前返回**裸 `str`**：`Denial` 才带 kind，裸 str 到了 `_denied()`
            # 里 `denial_kind_of()` 拿到空串，于是四个调用点（api_get / api_post /
            # image_generate / search）收到的都是兜底指令 —— 而兜底指令不会阻止模型
            # 拿同一个 URL 再试一遍，那永远不会成。文案在那儿、分类丢了，和 replace
            # 那处一样是"看起来修了"。
            # 归到 `COMMAND_SHAPE`（形态不合规、换合法写法可能成功）而不是硬拒那三档：
            # 取不出主机名说明 URL 本身不合法，正确的下一步是把地址写对（带
            # http(s):// 与主机名），不是申请提权、也不是换工具。
            return self._deny(
                DenialKind.COMMAND_SHAPE,
                "无法从 URL 中取出主机名，拒绝出站：这条 URL 本身不合法。"
                "重试同一个 URL 不会成功，请给出带 http(s):// 与主机名的完整地址",
                {"category": "URL 形态不合规", "target": url})

        if redirect_from:
            reason = f"跟随 {redirect_from} 的重定向到出站白名单之外的目的地（{host}）"
        else:
            reason = f"访问出站白名单之外的目的地（{host}）"
        return self._approve_action(
            str(url),
            reason,
            request_cls=DestinationApproval,
            deny_hint=("URL 本身（路径与查询串）就能把数据带出本机。"
                       "长期信任某个域名请写进配置 egress_allowlist。"),
            rule=f"egress:{host}")

    def _hop_gate(self, origin: Any):
        """造一个逐跳闸门，传给 `ace_net.safe_request(on_hop=…)`。

        首跳判定拦不住第二跳：清单内的**开放重定向器**能把任意目的地变成"清单内
        地址"。`duckduckgo.com` 就在默认清单里，而它的 `/l/?uddg=<任意 URL>` 正是
        一个开放重定向器（本项目自己的 `_parse_ddg` 就在解这个格式）—— 首跳过闸，
        数据从第二跳无声地出去，一个确认框都不会弹。所以每一跳都要重新判。

        同主机内的跳转（`http`→`https` 升级、路径规范化、加尾斜杠）**不**再问：
        白名单和确认框的粒度都是主机，同一主机没有新的决定可做，多问一遍只是噪音，
        而噪音会把用户训练成无脑点同意。
        """
        seen = {"host": (ace_net.url_host(origin) or "").lower()}

        def _gate(next_url: str) -> Optional[str]:
            host = (ace_net.url_host(next_url) or "").lower()
            if host and host == seen["host"]:
                return None
            denial = self._approve_destination(next_url, redirect_from=seen["host"] or "上一跳")
            if denial:
                return denial
            seen["host"] = host
            return None

        return _gate


    def _snapshot_covers(self, path: Path) -> Tuple[bool, str]:

        """这条路径出事之后能不能靠自动快照 + `/undo` 复原；返回 (能不能, 不能的原因)。

        这是"要不要逐次问人"的**唯一判据**（SEC-002 的另一半）。理由：项目内的写操作
        每轮都有快照兜底，再问一遍纯属噪音 —— 而确认框一旦变成噪音，用户就会开始
        无脑点同意，那才是真正危险的状态。所以只在快照盖不住的地方开口。

        两类盖不住：
          1. **项目外** —— `guardian` 只快照 `project_root`，出了这个圈就是不可逆删除。
          2. **密钥类文件** —— SEC-014 之后 `.env`/`*.pem` 这些刻意不进快照，于是
             它们在项目内也变成了不可回滚。这个缺口是那轮修复自己引入的，得在这里补上。

        `EXCLUDE_DIRS`（`node_modules`、`.venv`、构建缓存）**不算**在内：它们被排除是
        因为"可重建、不值得备份"，删了重装就有；密钥被排除是因为"不该复制"，删了就没了。
        两种排除的含义不同，不能合成一条规则。
        """
        if guardian.is_sensitive_file(path):
            return False, "密钥类文件不进快照（内容不备份），删除或覆盖后无法回滚"
        if self._confined(path) is None:
            return False, "该路径在项目目录之外，自动快照不覆盖它，无法 /undo"
        return True, ""

    def _approve_unrecoverable(self, action: str, target: Path) -> Optional[str]:
        """快照盖不住的破坏性操作要逐次点头；None = 放行或本就可回滚。

        与 `terminal_exec` 那条不同：那条由 `ace_execpolicy` 按命令危险度触发，这条按
        **后果能否撤销**触发。后者才是权限层该有的判据 —— 提权一次不该顺带买断
        所有不可逆操作。
        """
        covered, why = self._snapshot_covers(target)
        if covered:
            return None
        return self._approve_action(
            f"{action}：{target}", f"执行无法回滚的操作（{why}）",
            deny_hint="如果目标在项目内且不是密钥文件，改用项目内路径即可免确认。",
            # 项目内的目标（例如项目里的 .env）在这里会回显成相对路径：模型下一步
            # 本来就该用相对路径，诊断不受影响，而绝对前缀里的用户名不再进上下文。
            model_summary=f"{action}：{self._model_path_label(target)}",
            detail={"category": "无法回滚的操作", "target": target, "action": action,
                    "why": why})

    def _approve_launch(self, target: Path, action: str) -> Optional[str]:
        """项目外的"打开"动作征求用户同意；None = 放行，否则返回拒绝原因。"""
        label = self._model_path_label(target)
        detail = {"category": "项目外启动目标", "target": target, "action": action}
        if self.approval_hook is None:
            # 这条消息比通用版多一句出路（改用 file_read），所以不走 _approve_action 的
            # 默认文案。那句出路是本分支刻意多给的信息，删了模型就无处可去。
            # 路径同样只给 label：确认框那一路（下面的 summary）仍是完整真实路径。
            return self._deny(DenialKind.APPROVAL_UNAVAILABLE,
                              f"{action}项目外路径需要人工确认，但当前无审批通道（非交互运行）："
                              f"{label}。如需查看内容请改用 file_read。",
                              detail)
        return self._approve_action(
            str(target), f"{action}项目外路径（会启动系统程序）",
            request_cls=LaunchApproval,
            model_summary=label, detail=detail)




    # 工具名 → 处理器方法名。
    #
    # 为什么用表而不是 28 段 if/elif：分派表是可枚举的数据，测试能直接断言
    # "工具 schema 里声明的每个工具都有处理器"，而 if/elif 链只能靠人眼比对 ——
    # 新增工具时忘了加分支，只会在运行时变成一句"未知工具: xxx"。
    TOOL_HANDLERS: Dict[str, str] = {
        "parse_document": "_exec_parse_document",
        "open_file": "_exec_open_file",
        "edit_file": "_exec_edit_file",
        # 这四个共用一个处理器，它需要知道具体是哪一个，见 _HANDLERS_NEEDING_TOOL_NAME
        "file_read": "_exec_file_ops",
        "file_write": "_exec_file_ops",
        "file_delete": "_exec_file_ops",
        "file_move": "_exec_file_ops",
        "terminal_view": "_exec_terminal_view",
        "terminal_exec": "_exec_terminal_exec",
        "code_execute": "_exec_code_execute",
        "search": "_exec_search",
        "browser_screenshot": "_exec_browser_screenshot",
        "math_calc": "_exec_math_calc",
        "datetime_now": "_exec_datetime_now",
        "api_get": "_exec_api_get",
        "api_post": "_exec_api_post",
        "db_query": "_exec_db_query",
        "db_write": "_exec_db_write",
        "browser_open": "_exec_browser_open",
        "browser_click": "_exec_browser_click",
        "browser_type": "_exec_browser_type",
        "notify_send": "_exec_notify_send",
        "image_generate": "_exec_image_generate",
        "git_status": "_exec_git_status",
        "git_log": "_exec_git_log",
        "git_diff": "_exec_git_diff",
        "code_analyze": "_exec_code_analyze",
        "dependency_check": "_exec_dependency_check",
        "test_execute": "_exec_test_execute",
        "performance_profile": "_exec_performance_profile",
        "security_scan": "_exec_security_scan",
    }

    # 需要额外接收工具名的处理器（一个处理器覆盖多个工具时）
    _HANDLERS_NEEDING_TOOL_NAME = frozenset({"_exec_file_ops"})

    def execute(self, tool_call: Dict[str, Any]) -> ExecutionResult:
        """执行单个工具调用"""
        tool_name = tool_call.get("tool", "")
        params = {k: v for k, v in tool_call.items() if k != "tool"}

        start_time = time.time()
        result: Optional[ExecutionResult] = None

        try:
            handler_name = self.TOOL_HANDLERS.get(tool_name)
            if handler_name is None:
                result = ExecutionResult(
                    status="error",
                    error_code="400",
                    message=f"未知工具: {tool_name}"
                )
            else:
                handler = getattr(self, handler_name, None)
                if handler is None:
                    # 注册表写了但方法不存在：这是代码缺陷，不是用户输入问题，
                    # 所以给 500 并点名处理器，别让它伪装成"未知工具"。
                    result = ExecutionResult(
                        status="error",
                        error_code="500",
                        message=f"工具 {tool_name} 已注册但处理器缺失: {handler_name}"
                    )
                elif handler_name in self._HANDLERS_NEEDING_TOOL_NAME:
                    result = handler(tool_name, params)
                else:
                    result = handler(params)
        except Exception as e:
            # 这是所有处理器异常的兜底口，也是最容易把东西漏出去的一个：
            # 处理器里任何一层抛出的异常都会在这里被 f-string 拼进 message，
            # 而 message 进模型上下文。`open()` 抛的 FileNotFoundError 就是一条
            # 完整绝对路径 —— 于是"越界被拒"的路径没漏，"越界后崩了"的路径漏了。
            result = self._internal_error("执行异常", e)
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

    # ---------- v7.0 新增开发工具 ----------

    def _exec_git_status(self, params: Dict) -> ExecutionResult:
        """获取Git仓库状态"""
        try:
            result = subprocess.run(
                ["git", "status", "--short"],
                capture_output=True, text=True, timeout=10, cwd=self.project_root, shell=False
            )
            if result.returncode != 0:
                return self._subprocess_failed("Git命令执行失败", result)
            return ExecutionResult(status="success", data={
                "status": result.stdout.strip() or "工作区干净（无未提交更改）"
            })

        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504",
                                   message="Git命令执行超时（10秒）")
        except FileNotFoundError:
            return ExecutionResult(status="error", error_code="400",
                                   message="未找到git命令，请确保已安装Git")
        except Exception as e:
            return self._internal_error("Git状态查询失败", e)

    def _exec_git_log(self, params: Dict) -> ExecutionResult:
        """查看Git提交历史"""
        try:
            limit = params.get("limit", 10)
            result = subprocess.run(
                ["git", "log", "-n", str(limit), "--pretty=format:%h|%ai|%an|%s"],
                capture_output=True, text=True, timeout=10, cwd=self.project_root, shell=False
            )
            if result.returncode != 0:
                return self._subprocess_failed("Git命令执行失败", result)
            commits = []

            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("|")
                    commits.append({
                        "hash": parts[0],
                        "date": parts[1],
                        "author": parts[2],
                        "message": parts[3]
                    })
            return ExecutionResult(status="success", data={
                "commits": commits,
                "count": len(commits)
            })
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504",
                                   message="Git命令执行超时（10秒）")
        except FileNotFoundError:
            return ExecutionResult(status="error", error_code="400",
                                   message="未找到git命令，请确保已安装Git")
        except Exception as e:
            return self._internal_error("Git历史查询失败", e)

    def _exec_git_diff(self, params: Dict) -> ExecutionResult:
        """查看文件差异"""
        try:
            file_path = params.get("file", "")
            if not file_path:
                return ExecutionResult(status="error", error_code="400",
                                       message="git_diff 需要 file 参数")
            result = subprocess.run(
                ["git", "diff", "--no-color", file_path],
                capture_output=True, text=True, timeout=10, cwd=self.project_root, shell=False
            )
            if result.returncode != 0:
                return self._subprocess_failed("Git命令执行失败", result)
            return ExecutionResult(status="success", data={
                "diff": result.stdout.strip() or "无更改"
            })

        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504",
                                   message="Git命令执行超时（10秒）")
        except FileNotFoundError:
            return ExecutionResult(status="error", error_code="400",
                                   message="未找到git命令，请确保已安装Git")
        except Exception as e:
            return self._internal_error("Git差异查询失败", e)

    def _exec_code_analyze(self, params: Dict) -> ExecutionResult:
        """分析代码结构"""
        try:
            file_path = params.get("path", "")
            if not file_path:
                return ExecutionResult(status="error", error_code="400",
                                       message="code_analyze 需要 path 参数")
            
            p = self._resolve_read_path(file_path)
            if p is None:
                # 两档必须分开：UNC 是硬拒（`NETWORK_PATH`，一经访问就外发 NTLM，
                # 没有确认通道），越界是"换个项目内路径还可能成"（`PATH_OUT_OF_SCOPE`）。
                # 合成一句"越界或为网络路径"、且不带 denial_kind 的代价是上层查表
                # 落到兜底指令 —— 而这两档要求模型做的下一步正好相反。
                #
                # 这里回显的 `file_path` 是模型自己刚传进来的参数（未经 resolve），
                # 不是新信息；换成类别标签只会让模型分不清哪一次调用被拒。
                # 真正不能回显的是 resolve 之后的绝对路径 —— 而它此刻是 None。
                if self._is_network_path(file_path):
                    return self._denied(self._deny(
                        DenialKind.NETWORK_PATH,
                        "拒绝分析网络路径（UNC）：访问它会向对面主机发起 SMB 出网并交出凭据",
                        {"category": "网络路径", "target": file_path}))
                return self._denied(self._deny(
                    DenialKind.PATH_OUT_OF_SCOPE,
                    f"路径越界，拒绝分析: {file_path}（code_analyze 仅限项目目录内）",
                    {"category": "路径越界", "target": file_path}))

            if not p.exists():
                return ExecutionResult(status="error", error_code="404",
                                       message=f"文件不存在: {file_path}")
            
            with open(p, "r", encoding="utf-8") as f:
                code = f.read()
            
            # 简单的代码分析
            lines = code.split("\n")
            stats = {
                "lines": len(lines),
                "functions": 0,
                "classes": 0,
                "imports": 0,
                "comments": 0
            }
            
            for line in lines:
                line = line.strip()
                if line.startswith("def ") or line.startswith("async def "):
                    stats["functions"] += 1
                elif line.startswith("class "):
                    stats["classes"] += 1
                elif line.startswith("import ") or line.startswith("from "):
                    stats["imports"] += 1
                elif line.strip().startswith("#"):
                    stats["comments"] += 1
            
            return ExecutionResult(status="success", data={
                # 曾经是 `str(p)` —— **resolve 之后**的绝对路径。403 / 500 两条已经不
                # 回显它了，成功这条却照旧：而 `data` 和 `message` 一样进模型上下文
                # （`agent_runner.render_result` 的白名单含 `data`），所以"只修错误路径"
                # 等于没修 —— 正常调用一次就把用户名与项目位置送了出去。
                # 项目内给相对路径：模型下一步本来就该用相对路径，诊断一分不减。
                "file": self._model_path_label(p),

                "statistics": stats,
                "analysis": {
                    "complexity": "中等" if stats["functions"] > 10 else "低",
                    "maintainability": "良好" if stats["comments"] / max(stats["lines"], 1) > 0.1 else "一般"
                }
            })
        except Exception as e:
            # `open(p)` 抛出的 OSError/UnicodeDecodeError 的 str 里带的是**已 resolve 的
            # 绝对路径**（含用户名、软链背后的真名）。403 那条已经不回显它了，
            # 这条 500 走的却是同一个路径的另一半 —— 漏一处等于没修。
            return self._internal_error("代码分析失败", e)

    def _exec_dependency_check(self, params: Dict) -> ExecutionResult:
        """检查项目依赖"""
        try:
            dep_type = params.get("type", "python").lower()
            
            if dep_type == "python":
                # 检查requirements.txt或pyproject.toml
                req_files = ["requirements.txt", "pyproject.toml", "setup.py"]
                deps = []
                for req_file in req_files:
                    req_path = self.project_root / req_file
                    if req_path.exists():
                        with open(req_path, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith("#"):
                                    deps.append(line.split("==")[0].strip())
                
                return ExecutionResult(status="success", data={
                    "type": "python",
                    "dependencies": deps,
                    "count": len(deps),
                    "note": "请手动检查依赖版本兼容性"
                })
            else:
                return ExecutionResult(status="error", error_code="400",
                                       message=f"暂不支持依赖检查类型: {dep_type}")
        except Exception as e:
            return self._internal_error("依赖检查失败", e)

    def _exec_test_execute(self, params: Dict) -> ExecutionResult:
        """执行测试"""
        try:
            pattern = params.get("pattern", "test_*.py")
            test_cmd = ["python", "-m", "pytest", pattern, "-v", "--tb=short"]
            
            result = subprocess.run(
                test_cmd,
                capture_output=True, text=True, timeout=60, cwd=self.project_root, shell=False
            )
            
            return ExecutionResult(status="success",
                                   data=self._subprocess_output(result))
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504",
                                   message="测试执行超时（60秒）")

        except FileNotFoundError:
            return ExecutionResult(status="error", error_code="400",
                                   message="未找到pytest，请先安装pytest")
        except Exception as e:
            return self._internal_error("测试执行失败", e)

    def _exec_performance_profile(self, params: Dict) -> ExecutionResult:
        """性能分析"""
        try:
            module = params.get("module", "")
            if not module:
                return ExecutionResult(status="error", error_code="400",
                                       message="performance_profile 需要 module 参数")
            
            # 使用cProfile进行性能分析
            profile_output = []
            profile_cmd = ["python", "-m", "cProfile", "-o", "-", "-m", module]
            
            result = subprocess.run(
                profile_cmd,
                capture_output=True, text=True, timeout=30, cwd=self.project_root, shell=False
            )
            
            return ExecutionResult(status="success",
                                   data=self._subprocess_output(result))
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504",
                                   message="性能分析执行超时（30秒）")

        except FileNotFoundError:
            return ExecutionResult(status="error", error_code="400",
                                   message="未找到python，请确保已安装Python")
        except Exception as e:
            return self._internal_error("性能分析失败", e)

    def _exec_security_scan(self, params: Dict) -> ExecutionResult:
        """安全扫描"""
        try:
            scan_type = params.get("type", "python").lower()
            
            if scan_type == "python":
                # 检查常见安全问题
                issues = []
                
                # 检查硬编码的密钥
                sensitive_keywords = ["password", "secret", "token", "api_key", "apikey"]
                for file_path in self.project_root.rglob("*.py"):
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            for keyword in sensitive_keywords:
                                if keyword.lower() in content.lower():
                                    issues.append({
                                        "file": str(file_path.relative_to(self.project_root)),
                                        "issue": f"可能包含硬编码的 {keyword}",
                                        "severity": "中"
                                    })
                                    break
                    except Exception:
                        continue
                
                return ExecutionResult(status="success", data={
                    "type": "python",
                    "issues_found": len(issues),
                    "issues": issues[:20],  # 最多返回20个问题
                    "note": "这是基础扫描，建议使用专业安全工具进行深度扫描"
                })
            else:
                return ExecutionResult(status="error", error_code="400",
                                       message=f"暂不支持安全扫描类型: {scan_type}")
        except Exception as e:
            return self._internal_error("安全扫描失败", e)

