#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ace_http —— 模型 API 调用的重试与退避。

在这之前整个项目**零重试**：一次 429 或一次连接抖动就掀掉整个会话，
用户已经跑了十几轮的上下文全部作废。这是可用性上最廉价也最致命的一处缺口。

设计上和 ace_execpolicy 同一个套路：**判定是纯函数**。
`decide()` 不睡眠、不发请求、不看时钟（elapsed 由调用方传入），
所以"429 带 Retry-After: 3 应当等 3 秒"这种断言不需要真的限流一次才能测。
"""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Callable, ClassVar, Dict, Optional, Tuple

# —— 状态码分类 ——
#
# 只重试"再试一次可能会变"的失败。400/401/403/404/422 重试纯属浪费时间：
# 密钥不对、模型名写错、参数非法，等十秒答案还是一样，还把真正的错因埋进了延迟里。
RETRYABLE_STATUS = frozenset({
    408,  # Request Timeout
    425,  # Too Early
    429,  # Too Many Requests —— 最主要的场景
    500, 502, 503, 504,
    529,  # Anthropic 的过载码，不在标准里但实际会返回
})
FATAL_STATUS = frozenset({400, 401, 403, 404, 405, 406, 409, 410, 413, 415, 422})

# 异常类别。connect 是"请求没落地"，read 是"落地了但没等到回复"。
EXC_CONNECT = "connect"
EXC_READ_TIMEOUT = "read_timeout"
EXC_OTHER = "other"


@dataclass
class RetryPolicy:
    """重试预算。

    max_elapsed 存在的理由：只限次数不限总时长，5 次重试 × 300 秒超时能耗掉 25 分钟，
    对用户来说和挂死没有区别。次数与总时长必须同时封顶。
    """
    max_attempts: int = 4
    base_delay: float = 0.5
    max_delay: float = 30.0
    max_elapsed: float = 120.0
    respect_retry_after: bool = True
    # Retry-After 是服务端说的，但不能无条件照办：见过返回 3600 的实现，
    # 那等于让会话睡一小时。取上限后仍按服务端值优先。
    max_retry_after: float = 60.0

    # ClassVar 是必须的：dataclass 会把带类型标注的类属性当成**字段**，
    # 不加就等于给每个 RetryPolicy 实例塞了一个恒为 None 的 DEFAULT 字段，
    # 还会进 __init__ 签名和 repr。ClassVar 让它老老实实做类属性。
    DEFAULT: ClassVar[Optional["RetryPolicy"]] = None  # 见文件末尾赋值


@dataclass
class RetryDecision:
    should_retry: bool
    delay: float = 0.0
    reason: str = ""
    # source: retry_after | backoff | —— 用于日志与断言，区分"服务端指定"和"我们自己算"
    source: str = ""


def parse_retry_after(value: Any, now: Optional[float] = None) -> Optional[float]:
    """解析 Retry-After，同时支持"秒数"与"HTTP 日期"两种合法形式。

    只认秒数形式是常见的偷懒做法，而 Anthropic / Cloudflare 前置都可能返回日期形式，
    漏掉它的后果是退避退成 0 秒然后立刻再撞一次 429。
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        return max(0.0, float(s))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(s)
    except Exception:
        return None
    if when is None:
        return None
    try:
        target = when.timestamp()
    except Exception:
        return None
    base = now if now is not None else time.time()
    return max(0.0, target - base)


def compute_delay(attempt: int, policy: RetryPolicy,
                  retry_after: Optional[float] = None,
                  rand: Optional[Callable[[], float]] = None) -> Tuple[float, str]:
    """算出第 attempt 次失败后应当等待多久。attempt 从 1 开始。

    退避用**full jitter**（0 到上界之间均匀取值），不是"固定间隔"也不是"指数值本身"。
    理由是无抖动时并发的 N 个请求会同步重试，形成惊群，把刚缓过来的服务端再打回限流状态——
    抖动的作用是把重试打散，而不是让延迟"看起来随机"。
    """
    if retry_after is not None and policy.respect_retry_after:
        return min(float(retry_after), policy.max_retry_after), "retry_after"
    ceiling = min(policy.max_delay, policy.base_delay * (2 ** max(0, attempt - 1)))
    r = rand() if rand is not None else random.random()
    return ceiling * r, "backoff"


def decide(*, attempt: int, policy: RetryPolicy, elapsed: float,
           status: Optional[int] = None, exc_kind: Optional[str] = None,
           retry_after: Optional[Any] = None,
           rand: Optional[Callable[[], float]] = None,
           now: Optional[float] = None) -> RetryDecision:
    """纯判定：这次失败该不该重试、等多久。

    attempt 是**已经用掉**的尝试次数（第一次请求失败时 attempt=1）。
    """
    if attempt >= policy.max_attempts:
        return RetryDecision(False, reason=f"已用尽 {policy.max_attempts} 次尝试")
    if elapsed >= policy.max_elapsed:
        return RetryDecision(False, reason=f"累计耗时 {elapsed:.1f}s 超过预算 "
                                          f"{policy.max_elapsed:.0f}s")

    if status is not None:
        if status in FATAL_STATUS:
            return RetryDecision(False, reason=f"HTTP {status} 重试不会改变结果")
        if status not in RETRYABLE_STATUS and not (500 <= status < 600):
            return RetryDecision(False, reason=f"HTTP {status} 不在可重试集合内")
    elif exc_kind == EXC_OTHER:
        # 未知异常不盲目重试：可能是 JSON 解析失败、证书错误这类重试无益的问题。
        return RetryDecision(False, reason="非网络类异常，不重试")
    elif exc_kind is None:
        return RetryDecision(False, reason="既无状态码也无异常，无可重试的失败")

    ra = parse_retry_after(retry_after, now=now)
    delay, source = compute_delay(attempt, policy, retry_after=ra, rand=rand)

    # 别睡过总预算。宁可少睡一点立刻再试，也不要睡完发现预算没了、白等一场。
    remaining = policy.max_elapsed - elapsed
    if delay > remaining:
        if remaining <= 0:
            return RetryDecision(False, reason="退避时长已超出剩余预算")
        delay = remaining

    what = f"HTTP {status}" if status is not None else f"{exc_kind} 异常"
    return RetryDecision(True, delay=delay,
                         reason=f"{what}，第 {attempt} 次失败后退避 {delay:.2f}s",
                         source=source)


RetryPolicy.DEFAULT = RetryPolicy()


def classify_requests_exception(exc: Exception) -> str:
    """把 requests 的异常映射到 exc_kind。

    ConnectTimeout 必须在 Timeout 之前判：它同时是 ConnectionError 和 Timeout 的子类，
    顺序写反会把"根本没连上"错判成"连上了但没等到回复"。
    """
    try:
        import requests
    except ImportError:
        return EXC_OTHER
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return EXC_CONNECT
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return EXC_READ_TIMEOUT
    if isinstance(exc, requests.exceptions.ConnectionError):
        return EXC_CONNECT
    if isinstance(exc, requests.exceptions.Timeout):
        return EXC_READ_TIMEOUT
    if isinstance(exc, requests.exceptions.ChunkedEncodingError):
        return EXC_READ_TIMEOUT
    return EXC_OTHER


class RetryExhausted(RuntimeError):
    """重试预算用尽或遇到不可重试的失败。"""

    def __init__(self, message: str, *, status: Optional[int] = None,
                 attempts: int = 0, last_error: Optional[BaseException] = None):
        super().__init__(message)
        self.status = status
        self.attempts = attempts
        self.last_error = last_error


def request_with_retry(method: str, url: str, *,
                       policy: Optional[RetryPolicy] = None,
                       sleep: Callable[[float], None] = time.sleep,
                       clock: Callable[[], float] = time.monotonic,
                       on_retry: Optional[Callable[[RetryDecision, int], None]] = None,
                       **kwargs):
    """带重试的 requests 调用，返回状态已检查过的 Response。

    **只覆盖到"拿到响应状态"为止**。流式响应体在函数返回后才被消费，
    读到一半断流无法在这里重试——那时内容可能已经吐给用户了，重发会造成重复输出。
    需要处理中途断流的调用方必须自己判断"是否已经产出内容"，见 ai_code._stream_openai。
    """
    import requests

    policy = policy or RetryPolicy.DEFAULT
    started = clock()
    attempt = 0
    last_exc: Optional[BaseException] = None
    while True:
        attempt += 1
        status: Optional[int] = None
        retry_after = None
        try:
            resp = requests.request(method, url, **kwargs)
            status = resp.status_code
            if status < 400:
                return resp
            retry_after = resp.headers.get("Retry-After")
            last_exc = requests.HTTPError(f"HTTP {status} for {url}", response=resp)
            exc_kind = None
        except requests.RequestException as e:
            last_exc = e
            exc_kind = classify_requests_exception(e)

        d = decide(attempt=attempt, policy=policy, elapsed=clock() - started,
                   status=status, exc_kind=exc_kind, retry_after=retry_after)
        if not d.should_retry:
            if status is not None:
                # 状态类失败原样抛 HTTPError，让上层既有的降级逻辑
                # （比如 ai_code 里 400/404 → 关掉 tools 重试）继续生效。
                raise last_exc
            raise RetryExhausted(f"{url} 请求失败且不再重试：{d.reason}",
                                 status=status, attempts=attempt, last_error=last_exc)
        if on_retry is not None:
            on_retry(d, attempt)
        # 状态类失败要先把连接还回连接池，否则重试会不断新建连接。
        try:
            if status is not None:
                resp.close()
        except Exception:
            pass
        sleep(d.delay)


def urlopen_json_with_retry(req: "urllib.request.Request", *, timeout: int = 120,
                            policy: Optional[RetryPolicy] = None,
                            sleep: Callable[[float], None] = time.sleep,
                            clock: Callable[[], float] = time.monotonic,
                            on_retry: Optional[Callable[[RetryDecision, int], None]] = None
                            ) -> Dict:
    """标准库 urllib 版本，供不依赖 requests 的入口（agent_runner）使用。

    注意 urllib 把 4xx/5xx 抛成 HTTPError，而 HTTPError 本身是个 response 对象，
    Retry-After 要从 e.headers 取——从 e.reason 里是拿不到的。
    """
    policy = policy or RetryPolicy.DEFAULT
    started = clock()
    attempt = 0
    last_exc: Optional[BaseException] = None
    while True:
        attempt += 1
        status: Optional[int] = None
        retry_after = None
        exc_kind: Optional[str] = None
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_exc = e
            status = e.code
            try:
                retry_after = e.headers.get("Retry-After")
            except Exception:
                retry_after = None
        except urllib.error.URLError as e:
            last_exc = e
            # URLError 包着 socket.timeout 时是读超时，其余按连接失败处理。
            inner = getattr(e, "reason", None)
            exc_kind = EXC_READ_TIMEOUT if isinstance(inner, TimeoutError) else EXC_CONNECT
        except TimeoutError as e:
            last_exc = e
            exc_kind = EXC_READ_TIMEOUT

        d = decide(attempt=attempt, policy=policy, elapsed=clock() - started,
                   status=status, exc_kind=exc_kind, retry_after=retry_after)
        if not d.should_retry:
            if status is not None:
                raise last_exc
            raise RetryExhausted(f"请求失败且不再重试：{d.reason}",
                                 status=status, attempts=attempt, last_error=last_exc)
        if on_retry is not None:
            on_retry(d, attempt)
        sleep(d.delay)
