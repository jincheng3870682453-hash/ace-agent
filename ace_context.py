"""ace_context —— 上下文压缩的判定层。

为什么单独一个模块、且全是纯函数：
压缩的难点不在"调模型写摘要"，而在**决定压什么、保什么**。这个决定一旦错了，
表现是模型忘记自己在干什么、或者 API 直接 400，而不是一个干净的报错。
把判定和执行拆开，测试就能穷举各种历史形态（空历史、只有一轮、超长单条消息、
摘要失败）而完全不发一次网络请求 —— 和 ace_execpolicy / ace_http 同一个思路。

现状（改之前）：只有 `trim_messages` 按轮数硬截断。硬截断会把**第一条用户消息**
一起丢掉，也就是把"这次到底要做什么"丢掉。模型于是开始凭最近几轮的碎片猜任务，
越猜越偏 —— 这类失败很难归因，因为每一轮单独看都是合理的。

压缩后的历史结构：
    [第一条用户消息]  ← 任务锚点，永不丢弃
    [摘要消息]        ← 明确标注是摘要，不能伪装成模型自己说过的话
    [最近 N 轮原文]   ← 细节保真，模型正在处理的东西不能变成摘要
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

# 摘要消息的标记前缀。带标记的好处：压缩可以重复进行 —— 第二次压缩能认出
# 上一次的摘要并把它一起纳入新摘要，而不是把摘要当普通对话堆积下去。
SUMMARY_MARKER = "[上下文摘要]"

# 摘要失败时兜底用的提示。宁可让模型知道"这里丢了东西"，也不要静默失忆。
TRUNCATION_NOTICE = "[上下文因超长被截断，早期对话已丢失]"

_CJK_RANGES = (
    ("\u3040", "\u30ff"),   # 日文假名
    ("\u3400", "\u4dbf"),   # CJK 扩展 A
    ("\u4e00", "\u9fff"),   # CJK 基本区
    ("\uac00", "\ud7af"),   # 韩文
    ("\uff00", "\uffef"),   # 全角标点
)


def estimate_tokens(text: str) -> int:
    """估算 token 数。

    为什么不用 len(text)//4：那是英文经验值。中文一个字通常就是一个 token，
    按 4 字符折算会把中文历史低估到实际的四分之一 —— 于是"还没到阈值"，
    然后请求直接被服务端拒了。这个项目的对话主要是中文，低估是不能接受的方向。

    宁可高估：高估只是早压缩一点（多花一次模型调用），低估是会话直接失败。
    """
    if not text:
        return 0
    cjk = 0
    for ch in text:
        for lo, hi in _CJK_RANGES:
            if lo <= ch <= hi:
                cjk += 1
                break
    other = len(text) - cjk
    return cjk + (other + 3) // 4


def message_tokens(msg: Dict) -> int:
    """单条消息的估算开销，含 role 与协议本身的固定开销"""
    # 每条消息在各家 API 里都有几个 token 的固定包装开销（role、分隔符）。
    # 算上它，长对话里几十条消息的累积误差就不会被忽略。
    return estimate_tokens(str(msg.get("content", ""))) + 4


def measure(messages: Sequence[Dict]) -> int:
    return sum(message_tokens(m) for m in messages)


@dataclass
class CompactionPolicy:
    """压缩策略。

    context_window / reserve_output 是硬事实（模型能力），trigger_ratio 之后
    的都是取舍。默认值偏保守，因为这个项目要照顾本地小模型。
    """
    context_window: int = 32768
    # 留给模型输出的额度。不留就会出现"输入塞满、无法回答"的死局。
    reserve_output: int = 2048
    # 达到可用额度的多少比例就触发压缩。不要贴着上限触发：
    # 压缩本身要发一次请求，那次请求也得装得进窗口。
    trigger_ratio: float = 0.75
    # 保留最近多少轮原文（1 轮 = user + assistant）
    keep_recent_turns: int = 4
    # 摘要预算。摘要写得比原文还长就没有意义了。
    summary_max_tokens: int = 700
    # 中间段至少要有这么多条消息才值得压。压 1 条消息纯亏一次模型调用。
    min_summarize_messages: int = 4
    # 系统提示词等固定开销，由调用方测量后传进来
    fixed_overhead: int = 0

    def budget(self) -> int:
        """输入可用额度"""
        return max(0, self.context_window - self.reserve_output - self.fixed_overhead)

    def trigger_at(self) -> int:
        return int(self.budget() * self.trigger_ratio)


@dataclass
class CompactionPlan:
    """压缩计划。纯数据，不含任何副作用。"""
    should_compact: bool
    reason: str
    tokens_before: int = 0
    # 待摘要区间 [start, end)，用切片语义，避免闭区间的边界歧义
    summarize_start: int = 0
    summarize_end: int = 0
    head_keep: int = 0
    tokens_after_est: int = 0
    # 即使不压缩，也可能需要硬截断兜底（单条消息就超预算这种极端情况）
    force_truncate: bool = False
    dropped_messages: int = 0


def _first_user_index(messages: Sequence[Dict]) -> int:
    for i, m in enumerate(messages):
        if m.get("role") == "user":
            return i
    return -1


def _align_tail_to_user(messages: Sequence[Dict], tail_start: int) -> int:
    """把尾段起点前移到最近的 user 消息。

    为什么必须对齐：历史是 user→assistant 交替的。如果尾段从 assistant 开头，
    模型看到的就是"一句无来由的自己的回答"，很容易照着它接着编。
    """
    i = tail_start
    while i > 0 and messages[i].get("role") != "user":
        i -= 1
    return i


def plan_compaction(messages: Sequence[Dict],
                    policy: CompactionPolicy) -> CompactionPlan:
    """决定要不要压、压哪一段。纯函数。"""
    total = measure(messages)
    trigger = policy.trigger_at()

    if total <= trigger:
        return CompactionPlan(False, "未达触发阈值", tokens_before=total)

    head = _first_user_index(messages)
    if head < 0:
        # 连一条 user 消息都没有，说明历史结构异常，交给硬截断兜底，
        # 不要在这里猜结构。
        return CompactionPlan(False, "历史中没有用户消息，无法定位任务锚点",
                              tokens_before=total, force_truncate=True)
    head_keep = head + 1  # 锚点本身保留

    tail_len = max(2, policy.keep_recent_turns * 2)
    tail_start = max(head_keep, len(messages) - tail_len)
    tail_start = _align_tail_to_user(messages, tail_start)
    if tail_start < head_keep:
        tail_start = head_keep

    middle_count = tail_start - head_keep
    if middle_count < policy.min_summarize_messages:
        # 中间没什么可压的：要么对话本来就短，要么全部重量都在头尾。
        # 这时候超限只能靠硬截断，摘要救不了。
        return CompactionPlan(False,
                              f"可压缩区间过短（{middle_count} 条），摘要无收益",
                              tokens_before=total, force_truncate=True,
                              head_keep=head_keep)

    head_tokens = measure(messages[:head_keep])
    tail_tokens = measure(messages[tail_start:])
    after = head_tokens + policy.summary_max_tokens + 4 + tail_tokens

    if after >= total:
        # 摘要预算比被压掉的原文还大 —— 压了反而变长，白花一次调用。
        return CompactionPlan(False, "摘要预算不小于原文，压缩无收益",
                              tokens_before=total, force_truncate=True,
                              head_keep=head_keep)

    return CompactionPlan(
        True, "超出触发阈值，压缩中间段",
        tokens_before=total,
        summarize_start=head_keep,
        summarize_end=tail_start,
        head_keep=head_keep,
        tokens_after_est=after,
    )


def render_for_summary(messages: Sequence[Dict], limit_chars: int = 24000) -> str:
    """把待压缩消息渲染成给模型看的文本。

    limit_chars 是防呆：待压缩段本身可能已经巨大，直接整段塞进摘要请求会二次超限。
    从**尾部**保留（近期的更相关），并明确标注前面被截掉了。
    """
    parts = []
    for m in messages:
        role = m.get("role", "user")
        content = str(m.get("content", "")).strip()
        if not content:
            continue
        parts.append(f"[{role}] {content}")
    text = "\n\n".join(parts)
    if len(text) > limit_chars:
        text = "[...更早内容已省略...]\n\n" + text[-limit_chars:]
    return text


SUMMARY_INSTRUCTION = (
    "下面是一段 AI 编程助手与用户的历史对话。请压缩成一份交接说明，"
    "供后续对话继续使用。必须保留：\n"
    "1. 用户的目标与明确约束（尤其是否决过的方案）\n"
    "2. 已完成的改动：改了哪些文件、做了什么\n"
    "3. 未完成的事项与已知问题\n"
    "4. 关键结论与踩过的坑（避免重复犯错）\n"
    "不要写寒暄和评价，不要复述完整代码，只留能影响后续决策的信息。\n\n"
    "历史对话：\n"
)


def build_summary_message(summary: str) -> Dict:
    """摘要以 user 角色注入并显式标注。

    为什么不用 assistant 角色：那等于伪造模型说过的话，模型会把摘要里的推测
    当成自己已经确认过的结论。标成外部提供的上下文更诚实。
    """
    return {"role": "user",
            "content": f"{SUMMARY_MARKER}\n{summary.strip()}"}


def apply_compaction(messages: Sequence[Dict], plan: CompactionPlan,
                     summary: str) -> List[Dict]:
    """按计划生成新历史。纯函数，不修改入参。"""
    if not plan.should_compact:
        return list(messages)
    return (list(messages[:plan.head_keep])
            + [build_summary_message(summary)]
            + list(messages[plan.summarize_end:]))


def hard_truncate(messages: Sequence[Dict], policy: CompactionPolicy) -> List[Dict]:
    """兜底：从尾部保留能装下的部分，并保住第一条用户消息。

    这是摘要不可用时的退路，不是常规路径。关键是**结果不能为空** ——
    空历史会让下一次请求直接失败，把"上下文超限"变成"什么都不工作"。
    """
    budget = policy.budget()
    head_idx = _first_user_index(messages)
    anchor = [messages[head_idx]] if head_idx >= 0 else []
    anchor_tokens = measure(anchor)

    kept: List[Dict] = []
    used = anchor_tokens + estimate_tokens(TRUNCATION_NOTICE) + 4
    for m in reversed(messages[head_idx + 1:] if head_idx >= 0 else messages):
        cost = message_tokens(m)
        if used + cost > budget and kept:
            break
        kept.append(m)
        used += cost
    kept.reverse()

    start = _first_user_index(kept) if kept else -1
    if start > 0:
        # 丢掉尾段开头那些无来由的 assistant 消息（它们的提问已经被截掉了）
        kept = kept[start:]
    if not kept and messages:
        # 单条消息就超预算：也得留下它，否则历史为空。
        kept = [messages[-1]]
    return anchor + [{"role": "user", "content": TRUNCATION_NOTICE}] + kept


@dataclass
class CompactionOutcome:
    messages: List[Dict]
    plan: CompactionPlan
    compacted: bool = False
    truncated: bool = False
    summary: str = ""
    error: str = ""


def maybe_compact(messages: Sequence[Dict],
                  policy: CompactionPolicy,
                  summarize: Optional[Callable[[str], str]] = None
                  ) -> CompactionOutcome:
    """压缩入口。summarize 由调用方注入（一次模型调用），失败则退回硬截断。

    摘要失败必须降级而不是抛出：上下文超限是个可以缓解的问题，
    如果缓解手段本身会让整个会话崩掉，那它比不做更糟。
    """
    plan = plan_compaction(messages, policy)

    if not plan.should_compact:
        if plan.force_truncate:
            out = hard_truncate(messages, policy)
            return CompactionOutcome(out, plan, truncated=True,
                                     error=plan.reason)
        return CompactionOutcome(list(messages), plan)

    if summarize is None:
        out = hard_truncate(messages, policy)
        return CompactionOutcome(out, plan, truncated=True,
                                 error="未提供摘要函数")

    segment = render_for_summary(messages[plan.summarize_start:plan.summarize_end])
    try:
        summary = (summarize(SUMMARY_INSTRUCTION + segment) or "").strip()
    except Exception as e:  # 摘要是尽力而为的增强，不能拖垮会话
        out = hard_truncate(messages, policy)
        return CompactionOutcome(out, plan, truncated=True,
                                 error=f"摘要调用失败: {e}")

    if not summary:
        out = hard_truncate(messages, policy)
        return CompactionOutcome(out, plan, truncated=True,
                                 error="摘要为空")

    new_messages = apply_compaction(messages, plan, summary)
    return CompactionOutcome(new_messages, plan, compacted=True, summary=summary)
