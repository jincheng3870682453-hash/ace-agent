#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ace_executor —— Go 执行器（executor/ace-executor）的宿主侧客户端。

按 docs/ADR-002-executor-boundary.md 的 NDJSON 协议与执行器通话。

为什么要把执行搬出 Python：`subprocess.run(shell=True)` 在 Python 侧无法给子进程套上
进程树、内存、进程数上限，也无法保证整树回收——这些都是 OS 原语，宿主语言拿不到。
Go 侧用 Job Object 做到了，宿主这边只负责传策略、收结果。

**这个模块是可选路径**：二进制不存在时 `available()` 返回 False，调用方必须保留原有
进程内执行路径。默认不启用，由 ACE_USE_GO_EXECUTOR=1 或显式传参打开——沙箱这种东西
不该在用户不知情的情况下换实现。
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import queue
import subprocess
import sys
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

PROTOCOL_VERSION = 1

# 与 executor/protocol.go 的常量必须一致。宿主写超协议上限的请求只会被对面拒掉。
MAX_LINE_BYTES = 1 << 20
MAX_OUTPUT_BYTES = 5 << 20
MAX_TIMEOUT_MS = 600_000


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    """读一个整数型环境变量，读不到或不合法就用默认值。

    夹在 [lo, hi] 里而不是照抄：这些值决定的是"多久之后放弃一个正在跑的子进程"，
    一个手滑写成 0 或负数的环境变量会让每条命令刚起来就被判超时，而症状
    （所有命令都 E_TIMEOUT）完全指不向环境变量。
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(lo, min(int(raw), hi))
    except ValueError:
        return default


# 单条命令的默认超时。30s 是"交互式助手里一条命令的合理上限"这个判断，不是物理常数 ——
# 装依赖、跑构建、拉镜像都会正当地超过它，所以留出环境变量而不是让人改源码。
DEFAULT_TIMEOUT_MS = _env_int("ACE_EXEC_TIMEOUT_MS", 30_000, 100, MAX_TIMEOUT_MS)

# 宿主等 resp 时在执行器超时之上额外留的余量。
#
# 这段时间是给执行器杀进程树、收管道、算摘要、写 resp 用的。留太紧的后果不是慢，
# 而是**错误信息失真**：宿主先超时报 E_TIMEOUT（"执行器没响应"），而真相是执行器
# 正常地判了命令超时、resp 还在路上。差一秒，排查方向就从"命令太慢"跑到"执行器坏了"。
RESP_GRACE_MS = _env_int("ACE_EXEC_RESP_GRACE_MS", 10_000, 1_000, 120_000)

TIER_PROCESS = "tier0_process"
TIER_JOB_OBJECT = "tier1_job_object"
TIER_DOCKER = "tier2_docker"

# 默认环境白名单。缺 SystemRoot / COMSPEC 会让 Windows 上一批工具链直接起不来。
#
# SystemDrive / ProgramData / ALLUSERSPROFILE 不是为了"起得来"，是为了**别拉屎**：
# Windows shell 层里有一批路径写成 `%SystemDrive%\ProgramData\...` 的字面量，靠环境
# 变量展开。变量不在环境里时展开留下原文，那条路径就变成**相对路径**，子进程于是在
# 自己的 cwd（生产上 = 用户的项目目录）里造出一棵名叫 `%SystemDrive%` 的垃圾目录树。
# 这是在本仓库 executor/ 下真实长出来过的。
#
# 故意**不**放行 APPDATA / LOCALAPPDATA：那是当前用户可写的状态目录，交给沙箱里的
# 子进程等于白送一块持久化落脚点。
#
# 这份列表和 executor/run.go 的 defaultEnvAllow 是同一份东西的两份拷贝，两边必须一致。
# 注意生效的是**这一份**：ace_executor 永远显式下发 allow，而 run.go 的兜底只在
# `len(allow) == 0` 时才被查到 —— 所以只改 Go 那边等于没改。
# test_all.py 里有一条断言在盯这两份列表不许漂移。
DEFAULT_ENV_ALLOW = [
    "PATH", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC",
    "SystemDrive", "ProgramData", "ALLUSERSPROFILE",
    "TEMP", "TMP", "HOME", "USERPROFILE", "LANG", "LC_ALL",
    "PYTHONIOENCODING",
]


class ExecutorError(RuntimeError):
    """执行器返回了 error 帧，或会话本身出了问题。"""

    def __init__(self, code: str, message: str, data: Optional[Dict] = None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data or {}

    @property
    def http_like(self) -> str:
        return _HTTP_LIKE.get(self.code, "500")


_HTTP_LIKE = {
    "E_NOT_INITIALIZED": "409", "E_ALREADY_INITIALIZED": "409",
    "E_BAD_REQUEST": "400", "E_UNKNOWN_METHOD": "400", "E_UNKNOWN_TYPE": "400",
    "E_UNSUPPORTED_VERSION": "505", "E_DUPLICATE_ID": "409",
    "E_TIMEOUT": "504", "E_CANCELED": "499", "E_POLICY_DENIED": "403",
    "E_SANDBOX_UNAVAILABLE": "501", "E_SPAWN_FAILED": "500",
    "E_NOT_FOUND": "404", "E_INTERNAL": "500",
    "E_TRANSPORT": "500",
}


@dataclass
class ExecOutcome:
    """一次成功执行的终态。失败以 ExecutorError 抛出，不混在这里。"""
    exit_code: int
    duration_ms: int
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    sandbox_applied: Dict[str, Any] = field(default_factory=dict)
    bytes_counts: Dict[str, int] = field(default_factory=dict)
    # 上限之内实际留下的字节数。与 bytes_counts 不同时说明被限额截断了 ——
    # 宿主据此把"限额挡住了"和"传输丢了"分开，二者的处置完全不同。
    captured_bytes: Dict[str, int] = field(default_factory=dict)
    streamed: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def degraded(self) -> bool:
        """沙箱是否只部分生效。调用方应当把这个如实转达给用户。"""
        return bool(self.sandbox_applied.get("degraded"))


class _StreamCollector:
    """把 output 事件按流累起来，最后一次性解码并核对摘要。

    三件事分别对应三个真实的坑：
      1. **单次解码**：每收到一帧就 `bytes.decode("utf-8")` 会把跨帧的多字节字符
         劈成两半，中文输出会稳定出现替换字符。所以每帧只做 base64 解码（拿 bytes），
         UTF-8 解码留到最后一次。base64 也不能先拼字符串再解 —— 单帧长度不保证是
         3 字节的倍数，拼起来的 base64 是另一个东西。
      2. **序号连续性**：Go 侧的 seq 从 0 起、无空洞，跳变即丢帧。
      3. **摘要核对**：resp 里带的是执行器实际留下那些字节的 sha256。核对之后
         "我拿到的就是它留下的"才是可验证的事实，而不是靠信任传输层。
    """

    def __init__(self, on_event: Optional[Callable[[Dict], None]] = None):
        self._on_event = on_event
        self.parts: Dict[str, List[bytes]] = {"stdout": [], "stderr": []}
        self.next_offset: Dict[str, int] = {"stdout": 0, "stderr": 0}
        self.next_seq = 0
        self.capped = False
        self.problems: List[str] = []

    def feed(self, ev: Dict) -> None:
        seq = ev.get("seq")
        if isinstance(seq, int):
            if seq != self.next_seq:
                self.problems.append(f"事件序号跳变：期望 {self.next_seq}，收到 {seq}")
            self.next_seq = seq + 1
        if ev.get("event") == "output":
            d = ev.get("data") or {}
            stream = d.get("stream")
            if stream not in self.parts:
                self.problems.append(f"未知的流名：{stream!r}")
            else:
                try:
                    raw = base64.b64decode(d.get("data_b64") or "")
                except Exception as e:
                    self.problems.append(f"output 帧的 base64 解不开：{e}")
                    raw = b""
                off = d.get("offset")
                if isinstance(off, int) and off != self.next_offset[stream]:
                    self.problems.append(
                        f"{stream} 偏移不连续：期望 {self.next_offset[stream]}，收到 {off}")
                self.next_offset[stream] += len(raw)
                self.parts[stream].append(raw)
                if d.get("capped"):
                    self.capped = True
        if self._on_event is not None:
            self._on_event(ev)

    def raw(self, stream: str) -> bytes:
        return b"".join(self.parts.get(stream) or ())

    def verify(self, digest: Dict[str, str]) -> None:
        """核对摘要；不一致或有序号/偏移异常就抛 E_TRANSPORT。

        为什么不是"记录一条警告然后照常返回"：调用方拿到的字符串会被当成命令的输出
        喂给模型，一段静默残缺的输出比一个明确的错误危险得多。
        """
        problems = list(self.problems)
        for stream, want in (digest or {}).items():
            if stream not in self.parts or not want:
                continue
            got = hashlib.sha256(self.raw(stream)).hexdigest()
            if got != want:
                problems.append(f"{stream} 摘要不一致：执行器 {want[:16]}…，宿主 {got[:16]}…")
        if problems:
            raise ExecutorError("E_TRANSPORT", "；".join(problems),
                                {"streamed": True})


def default_binary_path() -> Path:
    name = "ace-executor.exe" if os.name == "nt" else "ace-executor"
    return Path(__file__).resolve().parent / "executor" / name


class ExecutorClient:
    """长驻的执行器会话。

    线程模型：一个读线程把 stdout 的帧按 id 投递到各自队列，一个线程排空 stderr。
    stderr 必须排空——管道写满后 Go 侧任何日志调用都会阻塞，进而把执行卡死；
    这类故障表现为"偶发超时"，极难定位。
    """

    def __init__(self, binary: Optional[str] = None, *, python: Optional[str] = None,
                 default_tier: Optional[str] = None):
        self.binary = Path(binary) if binary else default_binary_path()
        self.python = python or sys.executable
        self._proc: Optional[subprocess.Popen] = None
        self._pending: Dict[str, queue.Queue] = {}
        self._sinks: Dict[str, Callable[[Dict], None]] = {}
        self._lock = threading.Lock()
        # 写侧单独一把锁，见 _send() 的说明
        self._wlock = threading.Lock()
        self._stderr_tail: deque = deque(maxlen=200)
        self._out: Optional[io.BufferedReader] = None
        self._err: Optional[io.BufferedReader] = None
        self._caps: Dict[str, Any] = {}
        self._reader: Optional[threading.Thread] = None
        self._closed = False
        # 默认档位：Windows 上能拿到 Job Object 就用，其他平台只有 Tier-0。
        self.default_tier = default_tier or (
            TIER_JOB_OBJECT if os.name == "nt" else TIER_PROCESS)

    # ---- 生命周期 ----

    def available(self) -> bool:
        return self.binary.is_file()

    @property
    def capabilities(self) -> Dict[str, Any]:
        return dict(self._caps)

    def start(self) -> None:
        if self._proc is not None:
            return
        if not self.available():
            raise ExecutorError("E_TRANSPORT",
                                f"executor binary not found: {self.binary}; "
                                f"build it with `go build -o {self.binary.name} .` in executor/")
        self._proc = subprocess.Popen(
            [str(self.binary)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(self.binary.parent),
            # 二进制交换的是 UTF-8 JSON；让 Python 按 bytes 处理，自己控制解码，
            # 免得平台默认编码（Windows 上常是 cp936）把非 ASCII 命令行搞坏。
            #
            # bufsize=0 是为了**写**：请求发出去必须立刻到对面，缓冲住就是死锁。
            # 但它同时让 stdout 变成无缓冲的 raw FileIO，按行迭代退化成一次一个
            # 系统调用读一个字节 —— 实测拉高一个数量级以上的开销。所以读侧自己
            # 套一层 BufferedReader：写不缓冲、读缓冲，两个方向的需求本来就相反。
            bufsize=0,
            # 把执行器移出宿主的控制台信号范围。
            #
            # 默认情况下 Ctrl+C 在 Windows 上是 CTRL_C_EVENT 广播给整个控制台进程组、
            # 在 POSIX 上是 SIGINT 发给前台进程组 —— 两边都会直接命中执行器本身。
            # 执行器当场死掉，它正在跑的子进程就成了孤儿：Job Object 随句柄关闭会兜住
            # Tier-1，但 Tier-0 上那棵树没人收，而且宿主连"发生了什么"都不知道。
            #
            # 隔离之后，Ctrl+C 只打断宿主的等待，由 _call() 主动发 cancel，让执行器
            # 有序地杀树、收管道、回 resp。中断的处置权回到懂上下文的那一侧。
            **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
               if os.name == "nt" else {"start_new_session": True}),
        )
        self._out = io.BufferedReader(self._proc.stdout, buffer_size=64 << 10)
        self._err = io.BufferedReader(self._proc.stderr, buffer_size=8 << 10)
        self._reader = threading.Thread(target=self._read_loop, daemon=True,
                                        name="ace-executor-reader")
        self._reader.start()
        threading.Thread(target=self._drain_stderr, daemon=True,
                         name="ace-executor-stderr").start()
        try:
            self._handshake()
        except BaseException:
            # 握手失败 = 这个会话不可用 = 必须立刻回收。
            # 以前这里直接让异常穿出去，而 self._proc 已经被赋值：调用方
            # （tools/base.py 的 except Exception）只是把 use_go_executor 置 False
            # 并丢掉 client 引用，close() 从不被调用 —— 进程、两个 daemon 线程、
            # 三个管道全部泄漏，而且因为是 daemon 线程，直到 Python 退出都没人发现。
            # 典型触发：二进制被杀软挂起、缺 DLL 但进程活着。
            self.close()
            raise

    def close(self) -> None:
        self._closed = True
        p, self._proc = self._proc, None
        if p is None:
            return
        try:
            if p.stdin:
                p.stdin.close()
        except Exception:
            pass
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()

    def __enter__(self) -> "ExecutorClient":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- 传输层 ----

    def _read_loop(self) -> None:
        p = self._proc
        assert p is not None and self._out is not None
        for raw in self._out:
            try:
                frame = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                # 协议流里出现坏行说明 Go 侧往 stdout 写了非协议内容。
                # 不能静默丢——它意味着协议不变量被破坏，必须留痕。
                self._stderr_tail.append(f"[protocol] unparsable line: {raw[:200]!r}")
                continue
            fid = frame.get("id", "")
            if frame.get("type") == "event":
                # **就地投递，不攒起来等 resp。** 原实现把事件存进 dict、等 resp 回来
                # 之后再回放 —— 那不是流式，只是把同样的数据晚一点交出去，进度条、
                # 长任务实时输出这些开流的**唯一理由**全部落空。
                #
                # 顺带得到一个更强的顺序保证：读线程只有一个，事件必然在 resp 之前
                # 被派发完，"resp 是最后一帧"从时序巧合变成单线程本身的性质。
                with self._lock:
                    sink = self._sinks.get(fid)
                if sink is not None:
                    try:
                        sink(frame)
                    except Exception as e:
                        # 回调抛异常绝不能弄死读线程：那会让所有在等的请求一起挂到超时，
                        # 而真正的原因（某个回调写错了）被掩埋。
                        self._stderr_tail.append(f"[sink] event callback failed: {e!r}")
                continue
            with self._lock:
                q = self._pending.get(fid)
            if q is not None:
                q.put(frame)
        # stdout 结束 = 执行器退出。把所有还在等的请求叫醒，否则它们会等到自己的超时，
        # 而真正的原因（执行器死了）会被掩盖成"超时"。
        with self._lock:
            waiters = list(self._pending.values())
        for q in waiters:
            q.put({"type": "resp", "error": {
                "code": "E_TRANSPORT",
                "message": "executor exited; stderr tail: " + " | ".join(self._stderr_tail),
            }})

    def _drain_stderr(self) -> None:
        if self._err is None:
            return
        for raw in self._err:
            self._stderr_tail.append(raw.decode("utf-8", "replace").rstrip())

    def _send(self, frame: Dict) -> None:
        p = self._proc
        if p is None or p.stdin is None:
            raise ExecutorError("E_TRANSPORT", "executor session is not running")
        line = json.dumps(frame, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(line) + 1 > MAX_LINE_BYTES:
            raise ExecutorError("E_BAD_REQUEST",
                                f"frame is {len(line)} bytes, over the {MAX_LINE_BYTES} line limit")
        # 写锁独立于 self._lock：那把锁被读线程用来派发帧，复用它会把写阻塞
        # 传染到帧派发上。
        #
        # 为什么必须加锁：bufsize=0 让这里是裸 FileIO.write，超过管道缓冲
        # （Windows 匿名管道默认 64 KB）时内核分多次 WriteFile 完成，两个线程的
        # 字节可以交织。exec_python(source=...) 和 exec_command(stdin=...) 很容易
        # 超过这个量。交织的结果不是报错而是**两个请求都永远收不到 resp**：
        # Go 侧 json.Unmarshal 拿到坏行只往 stderr 打一句就 continue，
        # 两边各自等满 timeout 后报 E_TIMEOUT —— 错误信息指向完全错误的方向。
        with self._wlock:
            p.stdin.write(line + b"\n")
            p.stdin.flush()

    def _call(self, method: str, params: Dict, *, wait_s: float,
              on_event: Optional[Callable[[Dict], None]] = None) -> Dict:
        req_id = uuid.uuid4().hex
        q: queue.Queue = queue.Queue()
        with self._lock:
            self._pending[req_id] = q
            if on_event is not None:
                # 回调必须在**发请求之前**登记：反过来的话，第一个 started 事件
                # 可能在登记完成前就到了，于是它被静默丢掉。
                self._sinks[req_id] = on_event
        try:
            self._send({"v": PROTOCOL_VERSION, "type": "req", "id": req_id,
                        "method": method, "params": params})
            try:
                frame = q.get(timeout=wait_s)
            except queue.Empty:
                # 宿主侧等待超时说明执行器没在约定时间内终结该请求（它自己也有超时）。
                # 发 cancel 是为了不把子进程留在那儿跑——放弃等待不等于放弃回收。
                self._try_cancel(req_id)
                raise ExecutorError("E_TIMEOUT",
                                    f"executor did not respond to {method} within {wait_s:.1f}s")
            except BaseException:
                # Ctrl+C（KeyboardInterrupt）不是 Exception，用 except Exception 接不到。
                # 而它恰恰是最需要发 cancel 的一次：用户按下 Ctrl+C 时，执行器那边的
                # 子进程正跑着，宿主一走它就变成没人认领的后台任务 —— 编译、下载这类
                # 长命令会继续占满 CPU 和磁盘，直到自己的 timeout 到点。
                #
                # 放在 queue.Empty 之后：那一支有自己的错误语义，不该被这里吃掉。
                self._try_cancel(req_id)
                raise
            if frame.get("error"):
                e = frame["error"]
                raise ExecutorError(e.get("code", "E_INTERNAL"), e.get("message", ""),
                                    e.get("data"))
            return frame.get("result") or {}
        finally:
            with self._lock:
                self._pending.pop(req_id, None)
                self._sinks.pop(req_id, None)

    def _try_cancel(self, target_id: str) -> None:
        try:
            self._send({"v": PROTOCOL_VERSION, "type": "req", "id": uuid.uuid4().hex,
                        "method": "cancel",
                        "params": {"target_id": target_id, "mode": "graceful",
                                   "grace_ms": 2000}})
        except Exception:
            pass

    def _handshake(self) -> None:
        self._caps = self._call("initialize", {
            "client": {"name": "ace", "version": "7.0"},
            "protocol_versions": [PROTOCOL_VERSION],
            "features_requested": ["exec.command", "exec.python", "stream.stdout",
                                   "cancel.graceful"],
            "host": {"os": sys.platform, "cwd": os.getcwd()},
        }, wait_s=10)

    def sandbox_available(self) -> List[str]:
        return list((self._caps.get("sandbox") or {}).get("available") or [])

    # ---- 执行 ----

    def _exec(self, method: str, extra: Dict, *, cwd: Optional[str],
              timeout_ms: Optional[int],
              tier: Optional[str], allow_weaker_tier: bool, policy: Optional[Dict],
              env_allow: Optional[List[str]], env_set: Optional[Dict[str, str]],
              max_output_bytes: int, max_memory_bytes: int, max_child_processes: int,
              stdin: Optional[str], on_event: Optional[Callable[[Dict], None]]) -> ExecOutcome:
        self.start()
        if timeout_ms is None:
            timeout_ms = DEFAULT_TIMEOUT_MS
        timeout_ms = max(1, min(int(timeout_ms), MAX_TIMEOUT_MS))
        params = {
            "cwd": cwd,
            "timeout_ms": timeout_ms,
            "stdin": stdin,
            # on_event 为 None 时不开流：白开流只是让 stdout 多跑一遍 base64，
            # 结果反正从 resp 里取。
            "stream": on_event is not None,
            "env_policy": {
                "mode": "allowlist",
                "allow": list(env_allow) if env_allow is not None else DEFAULT_ENV_ALLOW,
                "set": dict(env_set or {}),
            },
            "sandbox": {
                "tier": tier or self.default_tier,
                "allow_weaker_tier": bool(allow_weaker_tier),
            },
            "limits": {
                "max_output_bytes": min(int(max_output_bytes), MAX_OUTPUT_BYTES),
                "max_memory_bytes": int(max_memory_bytes),
                "max_child_processes": int(max_child_processes),
            },
        }
        if policy:
            params["policy_decision"] = policy
        params.update(extra)

        # 宿主侧等待时间要比执行器超时长一截，见 RESP_GRACE_MS 的说明。
        collector = _StreamCollector(on_event) if on_event is not None else None
        result = self._call(method, params,
                            wait_s=(timeout_ms + RESP_GRACE_MS) / 1000.0,
                            on_event=collector.feed if collector else None)
        if collector is not None:
            # 开流时 resp 不带 stdout_b64（那会把同样的字节发两遍），输出只能来自事件流。
            # 核对摘要之后再交出去：静默残缺的输出会被当成命令的真实输出喂给模型，
            # 比一个明确的错误危险得多。
            collector.verify(result.get("digest") or {})
            stdout = collector.raw("stdout").decode("utf-8", "replace")
            stderr = collector.raw("stderr").decode("utf-8", "replace")
        else:
            stdout = _b64_text(result.get("stdout_b64"))
            stderr = _b64_text(result.get("stderr_b64"))
        return ExecOutcome(
            exit_code=int(result.get("exit_code", -1)),
            duration_ms=int(result.get("duration_ms", 0)),
            stdout=stdout,
            stderr=stderr,
            truncated=bool(result.get("truncated")),
            sandbox_applied=result.get("sandbox_applied") or {},
            bytes_counts=result.get("bytes") or {},
            captured_bytes=result.get("captured_bytes") or {},
            streamed=collector is not None,
        )

    def exec_command(self, argv: List[str], *, cwd: Optional[str] = None,
                     timeout_ms: Optional[int] = None, tier: Optional[str] = None,
                     allow_weaker_tier: bool = False, policy: Optional[Dict] = None,
                     env_allow: Optional[List[str]] = None,
                     env_set: Optional[Dict[str, str]] = None,
                     max_output_bytes: int = 1 << 20,
                     max_memory_bytes: int = 512 << 20,
                     max_child_processes: int = 32,
                     stdin: Optional[str] = None,
                     on_event: Optional[Callable[[Dict], None]] = None) -> ExecOutcome:
        """执行外部命令。

        只收 argv 列表，没有 shell 参数也没有字符串形式——命令注入在这个接口上
        不可表达。需要管道/重定向的场景应当由宿主拆成多步，而不是把字符串丢给 shell。
        """
        if not argv:
            raise ExecutorError("E_BAD_REQUEST", "argv is empty")
        return self._exec("exec.command", {"argv": [str(a) for a in argv]},
                          cwd=cwd, timeout_ms=timeout_ms, tier=tier,
                          allow_weaker_tier=allow_weaker_tier, policy=policy,
                          env_allow=env_allow, env_set=env_set,
                          max_output_bytes=max_output_bytes,
                          max_memory_bytes=max_memory_bytes,
                          max_child_processes=max_child_processes,
                          stdin=stdin, on_event=on_event)

    def exec_python(self, source: str, *, filename: str = "snippet.py",
                    cwd: Optional[str] = None, timeout_ms: Optional[int] = None,
                    tier: Optional[str] = None, allow_weaker_tier: bool = False,
                    env_allow: Optional[List[str]] = None,
                    env_set: Optional[Dict[str, str]] = None,
                    max_output_bytes: int = 1 << 20,
                    max_memory_bytes: int = 256 << 20,
                    max_child_processes: int = 2,
                    on_event: Optional[Callable[[Dict], None]] = None) -> ExecOutcome:
        """在受限子进程里跑一段 Python。

        注意这**不替代** tools/code_tools.py 的 AST 白名单：那一层管"这段代码
        允不允许写"，这一层管"跑起来能碰到什么"。两层是正交的，都要在。
        max_child_processes 默认 2：Windows 上部分 python.exe（venv/工具生成的
        启动器）启动时会以同样参数重启自身一次，Job 上限 1 会把它掐死在创建阶段
        （exit 101 "Unable to create process"）；上限 2 仍能拦住代码片段的 fork
        （python+自重启占满 2，代码再 fork 第 3 个进程即被 Job 拒绝）。
        """
        return self._exec("exec.python",
                          {"source": source, "filename": filename, "python": self.python},
                          cwd=cwd, timeout_ms=timeout_ms, tier=tier,
                          allow_weaker_tier=allow_weaker_tier, policy=None,
                          env_allow=env_allow,
                          env_set={"PYTHONIOENCODING": "utf-8",
                                   "PYTHONDONTWRITEBYTECODE": "1",
                                   **(env_set or {})},
                          max_output_bytes=max_output_bytes,
                          max_memory_bytes=max_memory_bytes,
                          max_child_processes=max_child_processes,
                          stdin=None, on_event=on_event)


def _b64_text(v: Optional[str]) -> str:
    if not v:
        return ""
    try:
        return base64.b64decode(v).decode("utf-8", "replace")
    except Exception:
        return ""


def verdict_to_policy(verdict, *, user_approved: bool = False) -> Dict[str, Any]:
    """把 ace_execpolicy.Verdict 翻译成协议里的 policy_decision。

    执行器会拿这个字段做第二道闸：宿主自己标 forbidden 的东西它绝不执行，
    标 prompt 而没带 approved 的同样拒绝。这不是冗余——宿主侧一处逻辑写错时，
    独立进程里的第二次判定是唯一还站得住的防线。
    """
    return {
        "decision": getattr(verdict, "decision", "prompt"),
        "rule_id": getattr(verdict, "rule", "") or "",
        "approved": bool(user_approved),
    }
