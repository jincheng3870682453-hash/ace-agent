#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.file_tools —— 文件与终端工具（file_* / terminal_* / open_file / edit_file）"""

import os
import re
import sys
import locale
import signal
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from tools.base import (GIT_READONLY_SUBCOMMANDS, MAX_COMMAND_LENGTH,
                        READ_ONLY_COMMANDS, SHELL_META_RE,
                        VERSION_ONLY_COMMANDS, VERSION_SUBCOMMANDS)
# `MAX_VIEW_OUTPUT_CHARS` / `_cap_view_text` 现在住在 `tools.base`，因为 git / pytest /
# cProfile 那几个出口也要用同一份上限（见 base 里那段说明），而 base 不能反向 import
# 本模块。这里保留 re-export：这两个名字既是本模块 terminal_view 的实现细节，
# 也是既有导入方（含测试）认的入口，改成"去 base 拿"只是把同一份东西挪到别人看不见的
# 地方，换不来任何东西。
from tools.base import MAX_VIEW_OUTPUT_CHARS, _cap_view_text

# 不再直接 import Denial / denial_kind_of：本模块里的拒绝一律由 `_deny()` 构造、
# 由 `_denied()` 包装。手写 `ExecutionResult(message=Denial(...), denial_kind=...)`
# 是上一版丢掉 `_deny(detail=…)` 那份"只给人看"的细节的原因 —— 少一个可用的入口，
# 就少一次"绕过 _denied()"的机会。
from tools.result import DenialKind, ExecutionResult

# terminal_exec 的命令安全闸门（强依赖，不做可选降级）
import ace_execpolicy as execpolicy

# Go 执行器客户端。与 execpolicy 不同，这个是**可选**的：
# 只在 use_go_executor 打开时才真正启动进程，模块本身不做任何副作用。
# 单独导入 ExecutorError 是因为 except 子句需要在运行时拿到类对象。
from ace_executor import ExecutorError as _GoExecutorError
from ace_executor import DEFAULT_TIMEOUT_MS as _GO_DEFAULT_TIMEOUT_MS

# 进程内回退路径的超时。和 Go 执行器共用同一个来源（含 ACE_EXEC_TIMEOUT_MS）：
# 两条路径超时不一致的话，"同一条命令在两台机器上一个超时一个不超时"就成了
# 谁都想不到的环境差异。
_INPROC_TIMEOUT_S = _GO_DEFAULT_TIMEOUT_MS / 1000.0



# Windows 无默认打开程序时，文本类扩展名回退记事本打开（.py 常无关联程序）
_TEXT_EXTENSIONS = {".py", ".txt", ".md", ".json", ".log", ".csv", ".ini", ".cfg",
                    ".yaml", ".yml", ".toml", ".xml", ".html", ".css", ".js",
                    ".ts", ".bat", ".cmd", ".ps1", ".sql", ".env"}

# SEC-005：这些扩展名一旦交给 os.startfile / xdg-open / open，等价于**执行**它。
# 原实现的 open_file 在 readonly 权限下就能 os.startfile 任意路径，
# 于是"只读"工具成了任意代码执行入口 —— 只读权限本该连写文件都不行。
# 注意 .bat/.cmd/.ps1/.js 同时也在 _TEXT_EXTENSIONS 里：它们能被"查看"，但绝不能被"启动"。
_EXECUTABLE_EXTENSIONS = {
    ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".msi", ".msp",
    ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".cpl", ".jar", ".reg", ".lnk", ".url", ".inf", ".scf", ".sct",
    ".application", ".gadget", ".msc", ".job", ".ws",
    ".sh", ".bash", ".zsh", ".command", ".app", ".appimage", ".run", ".bin",
}



def _is_switch_token(tok: str) -> bool:
    r"""这个 token 是命令开关（`-l`、`/b`）而不是路径？

    以前的判据是 `startswith("-") or startswith("/")`，按 Windows 开关语法写的，
    但它在 POSIX 上会把**绝对路径**一并吃掉：`tree /etc` 的 `/etc` 被当成开关丢弃，
    于是目标列表为空、一次闸门都不过，`/etc` 的完整目录树直接原样回给模型。
    仓库带 Dockerfile，Linux 是真实运行环境，这不是纸面问题。
    """
    if tok.startswith("-"):
        return True
    # `/` 只在 Windows 上是开关前缀；且真正的开关不含路径分隔符（`/b` vs `/etc/passwd`）
    return os.name == "nt" and tok.startswith("/") and "/" not in tok[1:] and "\\" not in tok


# 进程内回退路径的输出上限（每条流）。Go 执行器那侧由 limits.max_output_bytes 管，
# 这条路径以前**完全没有上限**：`capture_output=True` 把子进程写的每一个字节都攒在
# 宿主内存里，一条 `yes` 或者刷屏的构建日志就能把宿主吃掉。
MAX_INPROC_OUTPUT_BYTES = 1 << 20

# 杀完进程树之后允许收尾的时间。见 _run_capped 的说明。
_INPROC_REAP_S = 5.0

# terminal_view 的文本输出上限（按字符）。这条上限不是为了保护内存 —— 它的输出会
# **整段进入模型上下文**，1 MiB 打不爆宿主，但足够把上下文冲掉，让真正重要的历史
# 被挤出窗口。同一个函数里 `cat` 早就有 5000 字的上限，只有目录列表和外部命令的
# stdout 一直是无上限的：`tree` 扫一棵大仓库、`git log` 不带 `-n`，一次就能灌进几十万字。
#
# 定义已上移到 `tools.base`（见文件头那条 re-export 的理由）。




def _decode_console(raw: bytes) -> str:
    """按控制台编码解码子进程输出。

    这里刻意不用 utf-8：Windows 命令行工具（`dir`、`chcp` 之前的 `cmd` 内建）按
    控制台代码页输出，本机是 GBK，用 utf-8 解会把中文路径变成替换字符。
    原来的 `text=True` 走的就是 locale 编码，这里保持同一语义，只是把
    errors 明确成 replace —— 解码失败绝不该让一条命令整体报错。
    """
    enc = locale.getpreferredencoding(False) if os.name == "nt" else "utf-8"
    try:
        text = raw.decode(enc, "replace")
    except LookupError:
        text = raw.decode("utf-8", "replace")
    # text=True 会做换行归一化，这里补上，免得输出里混着 \r\n
    return text.replace("\r\n", "\n")


def _kill_tree(proc: subprocess.Popen) -> None:
    """杀掉整棵进程树，而不只是直接子进程。

    为什么必须整树：`shell=True` 时直接子进程是 `cmd.exe /c` 或 `sh -c`，真正干活的
    是它的孩子。只 kill 直接子进程，孙子进程会活下来继续跑 —— 而且它继承了 stdout
    的写端，管道永远收不到 EOF。
    """
    if os.name == "nt":
        try:
            # taskkill /T 按 PID 收整棵树。这里用 subprocess.run 是安全的：
            # 参数全是我们自己构造的，没有 shell。
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                           capture_output=True, timeout=_INPROC_REAP_S)
        except Exception:
            pass
    else:
        try:
            # start_new_session=True 让子进程成为新进程组的组长，负号 = 整组。
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
    try:
        proc.kill()   # 兜底：taskkill 不存在 / killpg 失败时至少收掉直接子进程
    except Exception:
        pass


def _run_capped(cmd, *, shell: bool, cwd: str, timeout_s: float,
                cap: int = MAX_INPROC_OUTPUT_BYTES) -> Tuple[str, str, int, bool, bool]:
    """进程内执行一条命令，带整树回收与输出上限。

    返回 (stdout, stderr, returncode, timed_out, truncated)。

    这个函数取代了原来的 `subprocess.run(..., timeout=30)`，修的是两个具体故障：

    1. **超时之后会永久挂住。** `subprocess.run` 超时的处置是 `Popen.kill()`（只杀
       直接子进程）之后再 `communicate()` 收尾 —— 而 communicate 要等管道 EOF。
       `shell=True` 下直接子进程是 `cmd.exe /c`，真正干活的孙子进程没被杀、还攥着
       stdout 写端，EOF 永远不来。于是"30 秒超时"变成无限期阻塞，而调用方看到的现象
       是 terminal_exec 再也不返回。
    2. **输出无上限。** 见 MAX_INPROC_OUTPUT_BYTES。

    读侧用两个线程而不是 communicate()：到顶之后仍然要继续读并丢弃，否则管道写满，
    子进程会阻塞在 write 上直到超时 —— 那样"限额"就变成了"限时"。
    """
    popen_kw: Dict[str, Any] = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                                if os.name == "nt" else {"start_new_session": True})
    proc = subprocess.Popen(cmd, shell=shell, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **popen_kw)
    bufs: Dict[str, bytearray] = {"out": bytearray(), "err": bytearray()}
    trunc: Dict[str, bool] = {"out": False, "err": False}

    def pump(key: str, fh) -> None:
        try:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                room = cap - len(bufs[key])
                if room > 0:
                    bufs[key] += chunk[:room]
                if len(chunk) > max(room, 0):
                    trunc[key] = True
        except Exception:
            pass
        finally:
            try:
                fh.close()
            except Exception:
                pass

    threads = [threading.Thread(target=pump, args=("out", proc.stdout), daemon=True),
               threading.Thread(target=pump, args=("err", proc.stderr), daemon=True)]
    for t in threads:
        t.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            proc.wait(timeout=_INPROC_REAP_S)
        except Exception:
            pass
    for t in threads:
        # 有界 join：万一还有存活者攥着管道，join 不会回来。这时 pump 线程仍在追加，
        # 下面读缓冲区只会少读到尾部几个字节（GIL 保证不会读出损坏的对象），
        # 而超时这条路径本来就不承诺输出完整。
        t.join(timeout=_INPROC_REAP_S)

    return (_decode_console(bytes(bufs["out"])), _decode_console(bytes(bufs["err"])),
            proc.returncode if proc.returncode is not None else -1,
            timed_out, trunc["out"] or trunc["err"])


class FileTools:
    # —— 500 通道的脱敏出口 ——
    #
    # 为什么不能直接 `message=str(e)`：OSError 家族的 `str()` 在 Windows 上长这样
    #   `[WinError 5] 拒绝访问。: 'C:\\Users\\xxx\\.ssh\\id_rsa'`
    # 而 `message` 会原样进模型上下文（`execution_layer` 的错误 payload 带 `message`，
    # 不带 `metadata`）。于是一次普普通通的"读失败"就把用户名、磁盘布局、以及软链背后的
    # 真实文件名送给了模型，而模型下一步完全可能是一次外发请求。
    #
    # 反过来也不能只说"失败了"：模型要靠"不存在 / 没权限 / 解码失败"决定下一步
    # （换路径？改用 file_read？放弃？），所以**异常类型名必须留在 message 里**，
    # 位置用 `_model_path_label()` 压成相对路径或类别标签，异常全文只进 metadata。
    #
    # 抽成 helper 的判据刻意很窄：**手里有 Path，且要报的就是"对这个路径做某件事失败了"**。
    # 满足这一条的点有近十处（listdir / read_text / startfile / 记事本回退），形状完全相同，
    # 各写一遍的下场是漏掉一处（SEC-004 / SEC-010 都是这么漏的）。手里**没有** Path 的 500
    # （审批回调抛异常、子进程起不来）一律不套这个 helper：那些点该说清的是"哪一步崩了"，
    # 硬塞一个路径标签只会让诊断更糊。
    def _failed_on_path(self, action: str, exc: Exception, path: Path) -> ExecutionResult:
        return ExecutionResult(
            status="error", error_code="500",
            message=f"{action}失败（{type(exc).__name__}）：{self._model_path_label(path)}",
            metadata={"error": {"action": action, "type": type(exc).__name__,
                                "detail": str(exc), "target": str(path)}})

    def _exec_file_ops(self, tool_name: str, params: Dict) -> ExecutionResult:
        """文件操作（相对路径限制在项目目录内；绝对路径 = 用户明确意图，防路径穿越）"""
        path_str = str(params.get("path", "")).strip()
        if not path_str and tool_name != "file_move":
            # 小模型常漏 path 参数：明确 400（配示例），而不是把 Path("") 当目录写到 500
            return ExecutionResult(status="error", error_code="400",
                                   message=f"{tool_name} 需要 path 参数（示例: "
                                           f'{{"tool": "{tool_name}", "path": "文件路径"}})')
        path = Path(os.path.expanduser(path_str))
        if self._is_network_path(path_str):
            # 必须在任何 Path.resolve() **之前**：Windows 上 resolve() 走
            # GetFinalPathNameByHandle，对 `\\host\share` 会真的去连对面主机并
            # 交出 NTLM 凭据 —— 那件事发生在闸门给出结论之前，之后再拒也没用。
            return ExecutionResult(status="error", error_code="403",
                                   message=f"拒绝访问网络路径: {path_str}。"
                                           f"访问 UNC 共享会发起 SMB 出网并把当前账户凭据交给对面主机。",
                                   denial_kind=DenialKind.NETWORK_PATH)
        if self.confine_files:
            confined = self._confined(path)
            if confined is not None:
                path = confined
            elif tool_name == "file_read" and path.is_absolute():
                # 项目外的**绝对**路径 = 用户明确写出了目标（"看看桌面上那个日志"）。
                # 以前这里是无条件放行目录列表，理由是"别让工具选择决定成败"——
                # 但那等于 readonly 权限下整台机器的目录树都可枚举。现在换成一道闸门：
                # 白名单内（默认桌面 + 下载）静默放行，白名单外每次问人，
                # 密钥类文件硬拒。口径与 terminal_view 的 cat/ls 完全一致，
                # 否则"换个工具"本身又会变成绕过手段。
                path = path.resolve()
                gate = self._approve_read_outside(path)
                if gate:
                    return self._denied(gate)
            elif path.is_absolute() and tool_name in ("file_write", "file_delete"):
                # 绝对路径（含 ~ 展开后） = 用户明确意图（如"放到桌面/主目录"），写工具放行；
                # 相对路径仍严格限项目内，防止穿越。读文件走上面那道闸门。
                path = path.resolve()
                gate = self._deny_never_writable(
                    "写入" if tool_name == "file_write" else "删除", path)
                if gate:
                    return self._denied(gate)
            else:
                return ExecutionResult(status="error", error_code="403",
                                       message="路径越界：相对路径仅允许在项目目录内；"
                                               "绝对路径（如 C:\\Users\\<用户名>\\Desktop\\文件名，"
                                               "或 ~/Desktop/文件名）才可指向项目外",
                                       denial_kind=DenialKind.PATH_OUT_OF_SCOPE)

        elif not path.is_absolute():
            path = self.project_root / path

        try:
            if tool_name == "file_read":
                if not path.exists():
                    # 这条 404 只在路径**已过闸门**之后可达（项目内 / read_allowlist 内 /
                    # 已获批准）。但闸门放行的是"读这一个文件"，不是"把桌面的目录结构
                    # 告诉模型" —— 用户把桌面写进白名单时想的是那份日志，不是授权枚举。
                    # 于是白名单内的项目外路径同样只给类别标签；项目内照给相对路径，
                    # 模型下一步本来就该用相对路径，改错文件名这类问题照样定位得到。
                    return ExecutionResult(status="error", error_code="404",
                                           message=f"文件不存在: {self._model_path_label(path)}"
                                                   f"（若目标是目录，file_read 会直接返回目录列表）")
                if path.is_dir():
                    try:
                        items = sorted(os.listdir(path))
                    except Exception as e:
                        return self._failed_on_path("目录读取", e, path)
                    return ExecutionResult(status="success", data={
                        "content": "\n".join(items),
                        # `data` 与 `message` 一样进模型上下文（`render_result` 白名单
                        # 含 `data`），所以这里回显 resolve 后的绝对路径与 500 那条漏出去的
                        # 是同一份东西：用户名、项目在磁盘上的位置、软链背后的真名。
                        # `listing` 只有 basename，本来就没有这个问题，不用动。
                        "path": self._model_path_label(path),
                        "is_dir": True,
                        "listing": items,
                    })
                content = self._read_text_any(path)
                return ExecutionResult(status="success",
                                       data={"content": content,
                                             "path": self._model_path_label(path)})
            elif tool_name == "file_write":
                # —— 第3层防御：尾斜杠 = 目录意图 ——
                # 注意用上面已通过 _confined() 校验的 path，而不是重新解析 path_str，
                # 否则会绕开越界校验。（原实现调用了不存在的 _resolve_path 并传了
                # ExecutionResult 不接受的 success= 关键字，整条分支一直抛异常被兜成 500。）
                if path_str.endswith(("/", "\\")):
                    target = path
                    target.mkdir(parents=True, exist_ok=True)
                    return ExecutionResult(status="success", data={
                        "created_dir": self._model_path_label(target), "is_dir": True,
                        "message": "path 以斜杠结尾，已按目录创建"})
                if path.is_dir():
                    return ExecutionResult(status="error", error_code="400",
                                           message=f"path 是目录: {self._model_path_label(path)}，"
                                                   "file_write 需要完整文件路径"
                                                   "（如 C:\\Users\\<用户名>\\Desktop\\文件.py）")
                path.parent.mkdir(parents=True, exist_ok=True)
                # SEC-002 另一半：只在快照盖不住的地方问人（项目外 / 密钥类文件）。
                # 项目内的普通写入有每轮快照 + /undo 兜底，再问一遍就是把确认框变成噪音。
                # 注意"覆盖已有文件"才是真正的损失，新建文件没什么可撤销的。
                if path.exists():
                    gate = self._approve_unrecoverable("覆盖文件", path)
                    if gate:
                        return self._denied(gate)
                path.write_text(params.get("content", ""), encoding="utf-8")
                return ExecutionResult(status="success",
                                       data={"path": self._model_path_label(path),
                                             "bytes_written": len(params.get("content", ""))})
            elif tool_name == "file_delete":
                if path.is_dir():
                    return ExecutionResult(status="error", error_code="400",
                                           message=f"path 是目录: {self._model_path_label(path)}，"
                                                   "file_delete 只删除文件")
                if path.exists():
                    gate = self._approve_unrecoverable("删除文件", path)
                    if gate:
                        return self._denied(gate)
                    path.unlink()
                return ExecutionResult(status="success",
                                       data={"deleted": self._model_path_label(path)})


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
                                                   "或绝对路径（绝对路径 = 明确意图）",
                                           denial_kind=DenialKind.PATH_OUT_OF_SCOPE)
                if not src.is_absolute():
                    src = self.project_root / src
                if not dest.is_absolute():
                    dest = self.project_root / dest
                # 两端都要过永不可写黑名单。以前只查 dest，于是"把 ~/.ssh/authorized_keys
                # 搬走"是放行的 —— 移走一个凭据文件和覆盖一个凭据文件，对系统凭据的影响
                # 是同一件事，判据本来就该是"这次操作是否改变系统的凭据或执行路径"。
                gate = (self._deny_never_writable("移动到该位置", dest)
                        or self._deny_never_writable("移动（源将消失）", src))
                if gate:
                    return self._denied(gate)
                # 移动有两个可能的损失：源没了、目标被覆盖。两端都要过一遍判据，
                # 只查一端等于留一个"从项目内搬到项目外"的口子。
                for _action, _target in (("移动（源将消失）", src), ("移动（覆盖目标）", dest)):
                    if _target is dest and not dest.exists():
                        continue      # 目标不存在，谈不上覆盖
                    gate = self._approve_unrecoverable(_action, _target)
                    if gate:
                        return self._denied(gate)
                # 存在性检查排在两道闸门**之后**：否则「404 源文件不存在」与
                # 「403 硬拒 / 要确认」是两个可区分的回答，file_move 就成了任意绝对
                # 路径的存在性查询接口。项目内的源不会走到确认框，所以常见路径上
                # 仍然是"不存在就立刻 404"，没有多余的打扰。
                if not src.exists():
                    return ExecutionResult(
                        status="error", error_code="404",
                        message=f"源文件不存在: {self._model_path_label(src)}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                # 用 os.replace 而不是 Path.rename：rename 在 Windows 上遇到已存在的目标会抛
                # WinError 183，在 POSIX 上却直接覆盖 —— 同一个工具在两个平台上语义不同，
                # 而这种分歧只会在"目标恰好存在"时才暴露出来。os.replace 两边都是原子覆盖。
                # 覆盖是有意允许的：上面那道确认已经就"会覆盖谁"问过人了。
                os.replace(src, dest)

                return ExecutionResult(status="success", data={
                    "moved": self._model_path_label(src),
                    "to": self._model_path_label(dest)})

        except Exception as e:
            # 兜底 500。这里刻意**不套** `_failed_on_path`：走到这一步的可能是 file_move
            # （真正相关的是 source/dest，`path` 在那条分支里是没用过的空壳），也可能是
            # mkdir / write_text / unlink 里的任意一步 —— 给一个可能指错对象的路径标签
            # 比不给更坏。所以 message 只承诺两件事：哪个工具、什么异常类型；
            # 完整异常（OSError 的 str 带绝对路径）只进 metadata，人排障时够用。
            _where = self._model_path_label(path) if path_str else ""
            return ExecutionResult(
                status="error", error_code="500",
                message=(f"{tool_name} 失败（{type(e).__name__}）"
                         + (f"：{_where}" if _where else "")),
                metadata={"error": {"action": tool_name, "type": type(e).__name__,
                                    "detail": str(e)}})

    def _exec_terminal_view(self, params: Dict) -> ExecutionResult:
        """只读终端查看：白名单命令 + 无 shell 执行（修复：readonly 不再能执行任意命令）"""
        cmd = (params.get("command") or "").strip()
        if not cmd:
            # 小模型常漏 command 参数：缺省列出项目目录，避免 400 死循环
            cmd = "ls -la"
        if len(cmd) > MAX_COMMAND_LENGTH:
            return ExecutionResult(status="error", error_code="400", message="命令过长")
        if SHELL_META_RE.search(cmd):
            # COMMAND_SHAPE 而不是 TOOL_CAPABILITY：拦的是**这条命令的形状**，
            # 把管道拆成两次调用就能过。分类错成"工具能力不足"会把模型推去换工具
            # （terminal_exec），而那条路要走审批 —— 白烧一轮还多问一次人。
            return ExecutionResult(status="error", error_code="403",
                                   message="terminal_view 检测到 shell 元字符，已拦截（只读工具禁止管道/重定向/连接符）",
                                   denial_kind=DenialKind.COMMAND_SHAPE)
        import shlex
        try:
            if os.name == "nt":
                # Windows 专用分词：双引号分组 + 保留反斜杠路径（shlex 会吃掉 \ 且在空格处断开）
                parts = self._split_cmd_windows(cmd)
            else:
                parts = shlex.split(cmd)
        except ValueError as e:
            # shlex 的 "No closing quotation" / "No escaped character" 是模型改命令的
            # 依据，留文本；只过滤路径形状。**这里的异常文本描述的是模型自己刚传进来
            # 的那条命令**，而那条命令里带绝对路径是常态（`type C:\...`）——
            # 今天 shlex 不回显输入，所以不会漏，但这份安全性完全来自"它恰好不回显"。
            # 走收口之后，回显与否都不改变"message 里没有本机路径"这条不变量。
            # 错误码仍是 400（对外契约）。
            return ExecutionResult(status="error", error_code="400",
                                   message=f"命令解析失败: {self._sealed_fragment(e)}")
        if not parts:
            return ExecutionResult(status="error", error_code="400", message="命令为空")
        base = parts[0].lower()

        # —— 原生实现的只读内建命令（完全不经过 shell）——
        #
        # SEC-006：这些分支原先解析完路径就直接读，全程不过 _confined()，于是 readonly
        # 权限下 `type C:\Users\<用户>\.aws\credentials` 可以读到工作区外任意文件 ——
        # 而同一份代码里的 file_read 早就有约束。防护代码一直在，只是没用在这条路径上。
        # 保留 confine_files 开关：用户显式关掉约束时行为不变。
        def _view_path(raw: str) -> Tuple[Optional[Path], str]:
            """把 terminal_view 的路径参数解析为受约束的绝对路径。

            返回 `(path, denial)`：`denial` 非空表示不许读，内容是给用户看的理由。

            以前只返回 `Optional[Path]`，由每个调用方自己拼"路径超出项目目录范围"。
            现在项目外的绝对路径有三种结局（白名单内直接读 / 问过人被拒 / 密钥类硬拒），
            拒绝理由和下一步都不同 —— "没获批准"重试一次可能就过了，"密钥类文件"
            再试一百次也不会过。理由必须由做判定的地方给出，否则调用方只能撒谎。
            """
            p = Path(os.path.expanduser(raw))
            if self._is_network_path(raw):
                # 与 _exec_file_ops 同一个理由：必须在 resolve() 之前，
                # 否则 SMB 出网和凭据交付已经发生了。这一类不给确认机会。
                #
                # 用 `_deny()` 而不是裸 `Denial(...)`：detail 是唯一能让人事后知道
                # "被拒的到底是哪个目标"的通道（它只进 metadata，不进模型上下文）。
                # 裸构造拿不到 detail，调用方就算走 `_denied()` 也只能交出一份空 metadata。
                return None, self._deny(
                    DenialKind.NETWORK_PATH,
                    f"拒绝访问网络路径: {raw}。"
                    f"访问 UNC 共享会发起 SMB 出网并把当前账户凭据交给对面主机。",
                    {"category": "网络路径", "target": raw})
            if not self.confine_files:
                return (p if p.is_absolute() else self.project_root / p).resolve(), ""
            confined = self._confined(p)
            if confined is not None:
                return confined, ""
            if not p.is_absolute():
                # 相对路径逃逸（`../../etc/passwd`）一律拒，连问都不问：
                # 它没有"用户明确写出了目标"这层含义，而恰好是路径穿越的形状。
                #
                # detail 里放**解析后**的目标：`../../etc/passwd` 这种写法，人光看原样
                # 猜不出它最终指到哪；而这一份绝对路径正是不能进 message 的那一份。
                return None, self._deny(
                    DenialKind.PATH_OUT_OF_SCOPE,
                    f"路径越界：超出项目目录范围: {raw}",
                    {"category": "相对路径逃逸", "target": raw,
                     "resolved": (self.project_root / p).resolve()})
            resolved = p.resolve()
            denial = self._approve_read_outside(resolved)
            if denial:
                return None, denial
            return resolved, ""

        if base in ("ls", "dir"):
            # 忽略常见列表参数（-l/-a/-la/--all、Windows 的 /b 等），支持 ~ 展开
            target_args = [p for p in parts[1:] if not _is_switch_token(p)]
            target = target_args[0] if target_args else "."
            target = os.path.expanduser(target)
            # 支持通配符：ls *.py / dir /b *.py
            if any(ch in target for ch in "*?"):
                import glob
                if not os.path.isabs(target):
                    # 相对通配符（`ls ../*`）不能先拼成绝对路径再送闸门：那样
                    # `dirname` 会变成绝对路径，`_view_path` 于是给它一次确认机会 ——
                    # 同一个越界语义，加个 `*` 就从"直接拒"变成"可批准"。
                    _rel_parent = (self.project_root / os.path.dirname(target)).resolve()
                    if self.confine_files and self._confined(_rel_parent) is None:
                        # 同样走 _deny/_denied：message 里只留模型自己传的 `target`
                        # （它本来就知道自己传了什么），解析后的父目录进 metadata ——
                        # 那一份才是人排障要看的，也正是不能进模型上下文的那一份。
                        return self._denied(self._deny(
                            DenialKind.PATH_OUT_OF_SCOPE,
                            f"路径越界：超出项目目录范围: {target}",
                            {"category": "相对通配符逃逸", "target": target,
                             "resolved_parent": _rel_parent}))
                pattern = target if os.path.isabs(target) else str(self.project_root / target)
                # 通配符本身不落在文件系统上，约束它的**父目录**：
                # `C:\Users\*\.ssh\id_rsa` 这类模式的父目录已经在工作区外。
                # 只调一次：_view_path 现在可能弹确认框，调两次就问两遍人。
                _parent, _denial = _view_path(os.path.dirname(pattern) or ".")
                if _parent is None:
                    # 走 _denied() 而不是自己拼：手拼的版本会把 `_deny(detail=…)` 里
                    # 那份"只给人看"的细节（被拒的目标、细分原因）整个丢掉，
                    # 于是日志里只剩一句"被拒了"，没人知道拒的是哪个文件。
                    return self._denied(_denial)
                try:
                    matches = sorted(glob.glob(pattern))
                except Exception as e:
                    return self._failed_on_path("通配符展开", e, _parent)
                lower_parts = [p.lower() for p in parts[1:]]
                bare = "/b" in lower_parts or "-1" in lower_parts
                if bare:
                    items = [os.path.basename(m) for m in matches]
                else:
                    items = [os.path.relpath(m, self.project_root)
                             if not os.path.isabs(target) else m
                             for m in matches]
                _stdout, _trunc = _cap_view_text("\n".join(items))
                return ExecutionResult(status="success", data={
                    "stdout": _stdout, "stderr": "", "returncode": 0,
                    "truncated": _trunc})
            p, _denial = _view_path(target)
            if p is None:
                return self._denied(_denial)
            try:
                items = sorted(os.listdir(p))
            except FileNotFoundError:
                # 同 file_read 的 404：`p` 是 `_view_path` resolve 之后的绝对路径。
                # 闸门放行的是"读这一个目标"，不是"把项目外的目录布局讲给模型听"。
                return ExecutionResult(status="error", error_code="404",
                                       message=f"目录不存在: {self._model_path_label(p)}")

            except Exception as e:
                return self._failed_on_path("目录读取", e, p)
            _stdout, _trunc = _cap_view_text("\n".join(items))
            return ExecutionResult(status="success", data={"stdout": _stdout,
                                                          "stderr": "", "returncode": 0,
                                                          "truncated": _trunc})
        if base == "pwd":
            return ExecutionResult(status="success", data={"stdout": str(self.project_root),
                                                           "stderr": "", "returncode": 0})
        if base in ("cat", "type"):
            if len(parts) < 2:
                return ExecutionResult(status="error", error_code="400", message="cat/type 需要文件参数")
            p, _denial = _view_path(parts[1])
            if p is None:
                return self._denied(_denial)
            try:
                content = self._read_text_any(p)
            except FileNotFoundError:
                return ExecutionResult(status="error", error_code="404",
                                       message=f"文件不存在: {self._model_path_label(p)}")
            except Exception as e:
                # 类型名在这条路径上尤其要留：`UnicodeDecodeError` 与 `PermissionError`
                # 对模型的下一步是两件完全不同的事（换读法 vs 别再试了）。
                return self._failed_on_path("文件读取", e, p)
            _stdout, _trunc = _cap_view_text(content, 5000)
            # 5000 是 cat 的既有上限，保留不动；补的是 truncated ——
            # 原来截了不说，模型会把半个文件当成整个文件去改。
            return ExecutionResult(status="success", data={"stdout": _stdout,
                                                          "stderr": "", "returncode": 0,
                                                          "truncated": _trunc})
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
                # COMMAND_SHAPE：拦的是"多带了参数"这个形状，删掉参数就能过 ——
                # 换工具或申请提权都不会改变结果。
                return ExecutionResult(status="error", error_code="403",
                                       message=f"{base} 仅允许查询版本（--version / -V，且不允许附加任何参数）",
                                       denial_kind=DenialKind.COMMAND_SHAPE)
        elif base == "git":
            if len(parts) < 2 or parts[1].lower() not in GIT_READONLY_SUBCOMMANDS:
                # 同上：子命令不在只读集合里，是"非只读子命令"这一种命令形状问题
                # （DenialKind.COMMAND_SHAPE 的定义里就点了这一条）。
                return ExecutionResult(status="error", error_code="403",
                                       message=f"git 仅允许只读子命令: {sorted(GIT_READONLY_SUBCOMMANDS)}",
                                       denial_kind=DenialKind.COMMAND_SHAPE)
        elif base in ("where", "which"):
            # SEC-007：`where /R C:\Users\<用户> *.kdbx` 是全盘递归文件枚举 ——
            # 它和 where 的正常用途（`where python`，在 PATH 里找可执行文件）是两件事。
            # 只允许"恰好一个裸命令名"这一种形态：不带 /R、不带路径分隔符、不带通配符。
            _bad = [p for p in parts[1:]
                    if p.startswith("/") or p.startswith("-")
                    or any(ch in p for ch in "\\/*?")]
            if len(parts) != 2 or _bad:
                return ExecutionResult(
                    status="error", error_code="403",
                    message=(f"{base} 仅允许查询单个命令名（如 `{base} python`）；"
                             f"不允许 /R 递归、路径或通配符 —— 那是文件枚举，不是查可执行文件。"),
                    # 形状问题而非越界：`where python` 立刻就能过，所以指令该是
                    # "把命令改成合法形状"，不是 PATH_OUT_OF_SCOPE 的"换路径"。
                    denial_kind=DenialKind.COMMAND_SHAPE,
                    metadata={self.DENIAL_METADATA_KEY: {"category": "命令形状",
                                                        "rejected_args": str(_bad)}})
        elif base == "tree":
            # tree 默认从 cwd 展开，但显式给了路径就可能指向工作区外。
            # 没给路径时也要过一次闸门（用 "."）：以前"目标列表为空"被当成安全，
            # 于是任何被误判成开关的参数都能让整条命令绕过检查。
            _targets = [p for p in parts[1:] if not _is_switch_token(p)] or ["."]
            for _t in _targets:
                _p, _denial = _view_path(_t)
                if _p is None:
                    return self._denied(_denial)
        elif base not in READ_ONLY_COMMANDS:
            # TOOL_CAPABILITY 而不是 COMMAND_SHAPE：命令本身没写错，是
            # terminal_view 这个只读工具不做这件事 —— 模型的下一步是换工具
            # （terminal_exec，走审批），不是改写命令。
            return ExecutionResult(status="error", error_code="403",
                                   message=f"命令 '{base}' 不在 terminal_view 白名单中（只读工具）",
                                   denial_kind=DenialKind.TOOL_CAPABILITY)
        # 走 _run_capped 而不是 subprocess.run：后者 capture_output 无上限，`tree` 扫一棵
        # 大仓库、`git log` 不带 -n 就能把几十万字灌进模型上下文；超时也写死 30 秒，
        # 让 ACE_EXEC_TIMEOUT_MS 对只读工具无效 —— 同一个产品里两套超时是纯粹的坑。
        # 这条路径是 shell=False + argv，没有 terminal_exec 那条 shell=True 的孙进程问题，
        # 但整树回收照样要：`git log` 会 fork 出 pager，只杀直接子进程会留下它。
        try:
            _out, _err, _rc, _to, _trunc_run = _run_capped(
                parts, shell=False, cwd=str(self.project_root),
                timeout_s=_INPROC_TIMEOUT_S)
            _out, _trunc_out = _cap_view_text(_out)
            _err, _trunc_err = _cap_view_text(_err)
            _trunc = _trunc_run or _trunc_out or _trunc_err
            if _to:
                # 超时是失败，但已经打印出来的东西照给：那往往是"它卡在哪一步"的唯一线索。
                return ExecutionResult(
                    status="error", error_code="504",
                    message=(f"命令执行超时（{_INPROC_TIMEOUT_S:.0f} 秒），已回收整棵进程树"),
                    data={"stdout": _out, "stderr": _err, "returncode": _rc,
                          "truncated": _trunc, "timed_out": True})
            return ExecutionResult(status="success", data={
                "stdout": _out,
                "stderr": _err,
                "returncode": _rc,
                "truncated": _trunc,
            })
        except FileNotFoundError:
            return ExecutionResult(status="error", error_code="404",
                                   message=f"命令不存在: {base}")
        except Exception as e:
            # 手里没有 Path（失败的是"起一个子进程"这件事），所以不套 _failed_on_path。
            # 回显 `base` 是安全的：那是模型自己刚传进来的 token，不是解析出来的路径。
            return ExecutionResult(
                status="error", error_code="500",
                message=f"命令执行失败（{type(e).__name__}）: {base}",
                metadata={"error": {"action": "terminal_view", "type": type(e).__name__,
                                    "detail": str(e)}})

    def _exec_terminal_exec(self, params: Dict) -> ExecutionResult:
        """真实终端执行 —— 经 ace_execpolicy 判定后执行（SEC-001）

        与旧实现的根本区别：**判定在执行之前，且没有任何绕过判定的快捷路径**。
        旧实现除了空值与长度检查外没有任何校验就 subprocess.run(cmd, shell=True)，
        而同文件的 terminal_view 早就有元字符过滤 + 白名单 + shell=False 三层防护 ——
        防护代码一直在，只是没用在危险的那个工具上。

        三条出口：
            forbidden → 403，任何审批都无法覆盖
            allow     → argv + shell=False 执行（不经 shell，元字符天然失效）
            prompt    → 交给 approval_hook 询问；无 hook 或被拒 → 403
        """
        cmd = (params.get("command") or "").strip()

        # 判定先行。注意这里传原始 cmd，不做任何预处理 ——
        # 任何"先展开再判定"的顺序都会让判定看到的字符串与实际执行的不一致。
        verdict = execpolicy.evaluate_command(
            cmd, str(self.project_root), sandbox=self.sandbox_policy)

        if verdict.forbidden:
            return ExecutionResult(
                status="error", error_code="403",
                message=f"命令被安全策略拒绝：{verdict.reason}",
                denial_kind=DenialKind.POLICY_FORBIDDEN,
                metadata={"policy": {"decision": verdict.decision, "rule": verdict.rule}})

        approved = False
        if verdict.needs_approval:
            if self.approval_hook is None:
                # 无人可问 → 拒绝。方向必须朝安全：SEC-004 就是把非交互默认答案写成 "y" 才出的事。
                return ExecutionResult(
                    status="error", error_code="403",
                    message=(f"命令需要人工确认但当前无审批通道：{verdict.reason}。"
                             f"可改用受限的 terminal_view，或拆成不含 shell 元字符的单条命令。"),
                    denial_kind=DenialKind.APPROVAL_UNAVAILABLE,
                    metadata={"policy": {"decision": verdict.decision, "rule": verdict.rule,
                                         "approval": "unavailable"}})
            try:
                approved = bool(self.approval_hook(verdict))
            except Exception as e:
                # 只留异常**类型**：hook 由上层注入，它的异常文本不受本层控制，完全可能
                # 把路径、命令行甚至凭据带进来（`FileNotFoundError` 的 str 就带路径）。
                # 与 base._approve_action 里那条同源处理保持一致：类型足够让模型知道
                # "这不是用户拒绝、别重试"，全文进 metadata 供人排障。
                return ExecutionResult(
                    status="error", error_code="500",
                    message=f"审批回调异常（{type(e).__name__}），按拒绝处理",
                    metadata={"error": {"action": "approval_hook",
                                        "type": type(e).__name__, "detail": str(e)},
                              "policy": {"decision": verdict.decision, "rule": verdict.rule}})
            if not approved:
                return ExecutionResult(
                    status="error", error_code="403",
                    message=f"用户拒绝执行：{verdict.reason}",
                    denial_kind=DenialKind.APPROVAL_DENIED,
                    metadata={"policy": {"decision": verdict.decision, "rule": verdict.rule,
                                         "approval": "denied"}})

        ok, why = execpolicy.should_execute(verdict, self.approval_policy,
                                            user_approved=approved)
        if not ok:
            return ExecutionResult(
                status="error", error_code="403", message=f"命令未获执行许可：{why}",
                denial_kind=DenialKind.POLICY_FORBIDDEN,
                metadata={"policy": {"decision": verdict.decision, "rule": verdict.rule}})

        # —— 只读内建命令交给 terminal_view 的原生实现 ——
        # echo / ls / dir / cat / type / pwd 等在 Windows 上是 cmd 内建命令，不是可执行文件：
        # 以 argv + shell=False 直接调用会得到 FileNotFoundError。terminal_view 早就为此
        # 写了不经 shell 的原生实现，这里复用而不是重复一遍。
        if verdict.allowed and verdict.argv:
            _base = verdict.argv[0].lower()
            if _base.endswith(".exe"):
                _base = _base[:-4]
            if _base in execpolicy.READ_ONLY_BASES:
                return self._exec_terminal_view(params)

        # —— 内建 mkdir：跨平台且不经 shell（原实现传了 ExecutionResult 不接受的
        #    success= 关键字，这条分支从来没成功返回过，一直被外层兜成 500）——
        if verdict.argv and verdict.argv[0].lower() in ("mkdir", "md"):
            targets = [t for t in verdict.argv[1:]
                       if not t.startswith("-") and not t.startswith("/")]
            made = []
            for raw in targets:
                p = Path(os.path.expanduser(raw))
                if not p.is_absolute():
                    p = self.project_root / p
                p.mkdir(parents=True, exist_ok=True)
                # 同 file_write 的 `created_dir`：这条 data 进模型上下文，而 mkdir 的
                # 目标允许是绝对路径 —— 回显 resolve 后的原样等于把项目位置和用户名
                # 一起送出去。模型下一步要用的是"我刚建的那个目录叫什么"，相对路径够了。
                made.append(self._model_path_label(p))

            if made:
                return ExecutionResult(status="success", data={
                    "stdout": "", "stderr": "", "returncode": 0,
                    "command": cmd, "mkdir_dirs": made,
                    "note": "mkdir 由执行层内建实现（跨平台，不经 shell）"})

        # —— 可选：把执行交给 Go 执行器（docs/ADR-002）——
        # 只走 allow 档：执行器只接受 argv，拿不到 shell 字符串，而已获批准的 prompt 档
        # 往往正是依赖管道/重定向才需要 shell 的。两者不能混。
        # 沙箱边界（进程树/内存/进程数上限 + 整树回收）是 OS 原语，Python 侧拿不到，
        # 这是把执行搬出进程的唯一理由；判定仍然在上面的 ace_execpolicy 完成。
        if verdict.allowed and verdict.argv:
            _client = self._go_executor()
            if _client is not None:
                try:
                    import ace_executor as _ax
                    _oc = _client.exec_command(
                        # 不写死超时：默认值与 ACE_EXEC_TIMEOUT_MS 都归 ace_executor 管，
                        # 在这里复制一份 30_000 只会让环境变量对 terminal_exec 无效。
                        verdict.argv, cwd=str(self.project_root),
                        policy=_ax.verdict_to_policy(verdict, user_approved=approved),
                        allow_weaker_tier=True)
                    return ExecutionResult(status="success", data={
                        "stdout": _oc.stdout, "stderr": _oc.stderr,
                        "returncode": _oc.exit_code,
                        "command": " ".join(verdict.argv),
                        "truncated": _oc.truncated,
                        "executor": "go",
                        "sandbox_applied": _oc.sandbox_applied,
                    })
                except _GoExecutorError as e:
                    # 执行器明确拒绝（策略/超时/沙箱不可用）不该被降级重试 ——
                    # 那等于绕过它刚刚给出的拒绝。原样上报。
                    #
                    # kind 必须区分：E_SANDBOX_UNAVAILABLE 映射成 501，压根不进
                    # 403 分支，以前给模型的 instruction 是空的，而它偏偏是
                    # "换环境/降档"而不是"模型做错了"的那一类；E_POLICY_DENIED 虽是
                    # 403，但文案里既没有"未获批准"也没有"越界"，旧的中文子串分派
                    # 一条都命中不了。
                    _kind = {"E_SANDBOX_UNAVAILABLE": DenialKind.SANDBOX_UNAVAILABLE,
                             "E_POLICY_DENIED": DenialKind.POLICY_FORBIDDEN}.get(e.code, "")
                    return ExecutionResult(
                        status="error", error_code=e.http_like,
                        message=f"Go 执行器拒绝或终止了该命令：{e.message}",
                        denial_kind=_kind,
                        metadata={"executor": "go", "code": e.code, "data": e.data})
                except Exception:
                    # 传输层意外（进程崩了、协议错乱）才降级到进程内实现，
                    # 并关掉执行器避免后续每条命令都重试一遍。
                    self.use_go_executor = False
                    self._go_client = None

        try:
            _timeout_s = _INPROC_TIMEOUT_S
            if verdict.allowed:
                # allow 档：以 argv 执行，shell 元字符不会被解释
                _out, _err, _rc, _to, _trunc = _run_capped(
                    verdict.argv, shell=False, cwd=str(self.project_root),
                    timeout_s=_timeout_s)
                used_shell = False
                shown = " ".join(verdict.argv)
            else:
                # 已获人工批准的 prompt 档：可能本来就依赖管道/重定向，只能走 shell。
                # 这是唯一还会用到 shell=True 的路径，且前置条件是"人明确点了同意"。
                _out, _err, _rc, _to, _trunc = _run_capped(
                    cmd, shell=True, cwd=str(self.project_root), timeout_s=_timeout_s)
                used_shell = True
                shown = cmd
            if _to:
                # 超时是失败，但输出照给：命令跑了 30 秒才被杀，那 30 秒里打印的东西
                # 往往正是"它卡在哪一步"的唯一线索。
                return ExecutionResult(
                    status="error", error_code="504",
                    message=f"命令执行超时（{_timeout_s:.0f} 秒），已回收整棵进程树",
                    data={"stdout": _out, "stderr": _err, "returncode": _rc,
                          "command": shown, "truncated": _trunc, "timed_out": True})
            return ExecutionResult(status="success", data={
                "stdout": _out,
                "stderr": _err,
                "returncode": _rc,
                "command": shown,
                "truncated": _trunc,
            }, metadata={"policy": {"decision": verdict.decision, "rule": verdict.rule,
                                    "used_shell": used_shell,
                                    "approval": "granted" if approved else "not_required"}})
        except FileNotFoundError:
            return ExecutionResult(status="error", error_code="404",
                                   message=f"命令不存在: {verdict.argv[0] if verdict.argv else cmd}")
        except Exception as e:
            # 同 terminal_view：失败的是"起子进程"，手里没有 Path，所以不套
            # _failed_on_path。异常全文可能带 cwd / 可执行文件的绝对路径，只进 metadata。
            return ExecutionResult(
                status="error", error_code="500",
                message=f"命令执行失败（{type(e).__name__}）",
                metadata={"error": {"action": "terminal_exec", "type": type(e).__name__,
                                    "detail": str(e)}})


    def _exec_open_file(self, params: Dict) -> ExecutionResult:
        """对话内打开文件：默认返回可点击链接（用户点击后全屏查看）；
        auto_open=true 时立即用系统默认程序打开"""
        path_str = str(params.get("path", "")).strip()
        if not path_str:
            return ExecutionResult(status="error", error_code="400", message="path 参数为空")
        p, outside = self._resolve_launch_target(path_str)
        if p is None:
            return ExecutionResult(
                status="error", error_code="403",
                message=(f"拒绝访问网络路径: {path_str}。访问 UNC 共享会发起 SMB 出网"
                         f"并把当前账户凭据交给对面主机。"),
                denial_kind=DenialKind.NETWORK_PATH)
        auto_open = bool(params.get("auto_open", False))
        # SEC-005：可执行类扩展名一律拒绝启动。os.startfile 一个 .bat 就是任意代码执行，
        # 而 open_file 是只读工具 —— 只读权限连写文件都不允许，更不该能执行东西。
        # 判定放在审批之前：会被拒的事情不该去打扰用户。suffix 从模型自己传的路径就能
        # 推出来，不构成新的信息泄漏，所以放在 exists() 之前也是安全的。
        if auto_open and p.suffix.lower() in _EXECUTABLE_EXTENSIONS:
            return ExecutionResult(
                status="error", error_code="403",
                message=(f"拒绝启动可执行类文件（{p.suffix}）：启动它等价于执行任意代码。"
                         f"如需查看内容请用 file_read；如需编辑请用 edit_file。"),
                denial_kind=DenialKind.EXECUTABLE_LAUNCH)
        # —— 项目外目标的确认必须排在 exists() **之前**，而且要在分支**之前** ——
        # 原来的顺序是先 `if not p.exists(): 404`，再在每条分支里各自问人。于是
        # 「404 文件不存在」和「403 要确认 / 不许看」成了两个可区分的回答，
        # readonly 权限就能拿任意绝对路径当存在性预言机，反复问就是文件系统枚举。
        # 一次**被拒绝**的调用不该还能当探测原语用。项目内的 404 照给 —— 那本来就是授权域。
        #
        # 提到分支之前还顺手消掉了第二个预言机：以前"目录问人、文件硬拒"这个差异本身
        # 就能区分目录和文件，而 is_dir() 对不存在的路径恒为 False，等于把存在性又漏一遍。
        # 代价是"项目外文件 + 只要链接"这一种组合会先问人再拒 —— 那一问并不冤：
        # 模型确实请求了打开项目外的路径，用户本来就该知道。
        # is_dir() 只用来把确认框的措辞写准，它的结果只给人看，不进任何返回值。
        if outside:
            why = self._approve_launch(
                p, "在系统文件管理器中打开" if p.is_dir() else "用系统默认程序打开")
            if why:
                return self._denied(why)
        if not p.exists():
            return ExecutionResult(status="error", error_code="404",
                                   message=f"文件不存在: {self._model_path_label(p)}")
        if p.is_dir():
            # 目录：在系统文件管理器中打开（如"打开桌面文件夹"）。
            # SEC-005：这一支原来无条件执行 —— readonly 权限下模型说打开哪个目录就打开哪个。
            # 项目外的确认已经在上面做过了；项目内不打扰。
            try:
                if os.name == "nt":
                    os.startfile(str(p))
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", str(p)])
                else:
                    subprocess.Popen(["xdg-open", str(p)])
            except Exception as e:
                return self._failed_on_path("打开文件夹", e, p)
            return ExecutionResult(status="success", data={
                "path": self._launch_path_label(p), "opened": True, "is_dir": True,
                "hint": "已在系统文件管理器中打开该文件夹"})
        if not auto_open:
            # 默认收起：只给链接，用户点击才打开。
            # 项目外的文件连链接都不给（哪怕上面刚问过人）：链接里带绝对路径，等于把
            # 项目外的文件布局透进上下文，还顺带诱导用户点击（报告里的
            # ~/.aws/credentials 就是这条）。要真打开请显式传 auto_open。
            if outside:
                return ExecutionResult(
                    status="error", error_code="403",
                    message=("拒绝为项目外文件生成链接：open_file 是只读工具。"
                             "确实要打开请显式传 auto_open=true；"
                             "只想看内容请用 file_read（同样受限）。"),
                    denial_kind=DenialKind.TOOL_CAPABILITY)
            return ExecutionResult(status="success", data={
                "path": self._launch_path_label(p), "opened": False, "link": p.as_uri(),
                "hint": "已生成可点击链接，用户点击后即可全屏查看"})
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
                        "path": self._launch_path_label(p), "opened": True, "editor": "notepad",
                        "hint": "该类型无默认打开程序，已用记事本打开"})
                except Exception as e2:
                    return self._failed_on_path("记事本回退打开", e2, p)
            return self._failed_on_path("打开", e, p)
        return ExecutionResult(status="success", data={"path": self._launch_path_label(p), "opened": True})

    def _exec_edit_file(self, params: Dict) -> ExecutionResult:
        """对话内编辑文件：优先 VS Code（code 命令），否则回退系统默认程序"""
        path_str = str(params.get("path", "")).strip()
        if not path_str:
            return ExecutionResult(status="error", error_code="400", message="path 参数为空")
        p, outside = self._resolve_launch_target(path_str)
        if p is None:
            return ExecutionResult(
                status="error", error_code="403",
                message=(f"拒绝访问网络路径: {path_str}。访问 UNC 共享会发起 SMB 出网"
                         f"并把当前账户凭据交给对面主机。"),
                denial_kind=DenialKind.NETWORK_PATH)
        # SEC-005：项目外的目标一律先问人 —— 不论后面走 VS Code、记事本还是系统默认程序，
        # 都是"用模型给的路径启动一个外部程序"。判定放在分支之前，免得每条分支各写一遍
        # （各写一遍正是 SEC-004/SEC-010 漏掉一处的成因）。
        #
        # 闸门必须排在 exists() **之前**：否则「404 文件不存在」与「403 要确认」是两个
        # 可区分的回答，拿任意绝对路径反复问就是文件系统枚举。项目内的 404 照给。
        if outside:
            why = self._approve_launch(p, "用编辑器打开")
            if why:
                return self._denied(why)
        if not p.exists():
            return ExecutionResult(
                status="error", error_code="404",
                message=f"文件不存在: {self._model_path_label(p)}（可先用 file_write 创建）")
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
                return self._failed_on_path("打开文件夹", e, p)
            return ExecutionResult(status="success", data={
                "path": self._launch_path_label(p), "opened": True, "is_dir": True,
                "hint": "已在系统文件管理器中打开该文件夹"})
        import subprocess
        code = shutil.which("code")
        if code:
            try:
                subprocess.Popen([code, str(p)])
                return ExecutionResult(status="success",
                                       data={"path": self._launch_path_label(p), "editor": "vscode"})
            except Exception as e:
                return self._failed_on_path("用 VS Code 打开", e, p)
        # SEC-005：可执行类扩展名绝不走 os.startfile —— 那是"运行"而不是"编辑"。
        # 直接用纯文本编辑器打开；没有可用编辑器时拒绝，而不是退回到"启动它"。
        if p.suffix.lower() in _EXECUTABLE_EXTENSIONS:
            if os.name == "nt":
                try:
                    subprocess.Popen(["notepad.exe", str(p)])
                    return ExecutionResult(status="success", data={
                        "path": self._launch_path_label(p), "editor": "notepad",
                        "hint": "可执行类文件仅以文本方式打开，不会被运行"})
                except Exception as e:
                    return self._failed_on_path("记事本打开", e, p)
            return ExecutionResult(
                status="error", error_code="403",
                message=(f"未找到纯文本编辑器（code），且 {p.suffix} 属可执行类文件，"
                         f"拒绝交给系统默认程序打开（等价于运行）。请用 file_read 查看内容。"),
                # TOOL_CAPABILITY 而不是 EXECUTABLE_LAUNCH：这一档的分类轴是"模型下一步
                # 干什么"。这里被拒的不是"启动可执行文件"这个意图本身（模型要的是编辑），
                # 而是本机没有能安全承接它的编辑器 —— 出路是换工具（file_read）。
                # 归到 EXECUTABLE_LAUNCH 会告诉模型"这一档没有任何通道、别再想了"，
                # 而事实是 file_read 现在就能看到内容。
                denial_kind=DenialKind.TOOL_CAPABILITY)
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
                        "path": self._launch_path_label(p), "editor": "notepad",
                        "hint": "该类型无默认打开程序，已用记事本打开"})
                except Exception as e2:
                    return self._failed_on_path("记事本回退打开", e2, p)
            return self._failed_on_path("打开", e, p)
        return ExecutionResult(status="success", data={"path": self._launch_path_label(p), "editor": "system_default"})

