#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.result —— 工具执行结果（从 execution_layer 拆出）"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Tuple


class DenialKind:
    """闸门拒绝的类型。分类轴是**模型的下一步动作**，不是"技术原因"。

    为什么需要它：`execution_layer` 以前靠在 `result.message` 里搜中文子串
    （"未获批准" / "密钥类文件" / "越界"…）反推是哪道闸门拦的，再据此拼给模型的
    `instruction`。这套东西改一个字就静默失效，而它管的正是"禁止模型把安全拦截
    当成权限问题去无效重试"。文案本来只该给人看，不该承载控制流。

    三档语义（新增取值必须先归入其中一档）：
    - 需要人：本轮不可能成功，再调一次还是问同一个人。
    - 换法可能成功：路径/写法/工具的问题。
    - 硬拒：永远不会成功，没有确认通道。
    """
    # —— 需要人 ——
    APPROVAL_UNAVAILABLE = "approval_unavailable"   # 需逐次确认但无审批通道（非交互）
    APPROVAL_DENIED = "approval_denied"             # 问过了，没放行
    APPROVAL_ERROR = "approval_error"               # 审批回调抛异常，按拒绝处理
    # —— 换法可能成功 ——
    PATH_OUT_OF_SCOPE = "path_out_of_scope"         # 路径越界 / 跨盘符 / 相对逃逸
    COMMAND_SHAPE = "command_shape"                 # 命令形态不合规（元字符、非只读子命令…）
    TOOL_CAPABILITY = "tool_capability"             # 这个工具的能力边界（换工具可能行）
    CODE_GATE = "code_gate"                         # AST / 表达式闸门
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"     # 沙箱档位不可用（换环境的事，不是模型的错）
    # 这台机器不具备该能力：可选依赖没装 / 外部程序不在 / 必需配置缺失。
    # 归"换法可能成功"而不是"硬拒"：硬拒是"这件事永远不许做"，而这一档是
    # "这条路今天走不通，隔壁那条能走"（toast 没 plyer → console/file 照样送到）。
    # 归它也不是"需要人"：那一档的语义是"再调一次还是问同一个人"，而这里模型
    # 不问任何人就能自己换一条 channel 完成任务，只在全都不可用时才需要人去装。
    DEPENDENCY_MISSING = "dependency_missing"
    # —— 硬拒 ——
    SECRET_FILE = "secret_file"                     # 密钥类文件 / 凭据目录
    NEVER_WRITABLE = "never_writable"               # 写侧永不可写黑名单
    NETWORK_PATH = "network_path"                   # UNC / 网络路径
    EXECUTABLE_LAUNCH = "executable_launch"         # 可执行类扩展名启动
    POLICY_FORBIDDEN = "policy_forbidden"           # 策略层判定 forbidden
    # —— 权限档位（唯一允许引导 request_permission 的一档）——
    PERMISSION_LEVEL = "permission_level"


class Denial(str):
    """带类型标签的拒绝理由。

    刻意做成 `str` 子类而不是新的值对象：闸门族的返回类型是 `Optional[str]`，
    被十几处 `ExecutionResult(..., message=gate)` 和一批 `"xxx" in message` 的
    断言消费。继承 `str` 让这些用法一个字都不用改，同时把 kind 带到构造点。
    """
    kind: str

    def __new__(cls, kind: str, message: str) -> "Denial":
        obj = super().__new__(cls, message)
        obj.kind = kind
        return obj


def denial_kind_of(message: Any) -> str:
    """从拒绝理由上取出 kind；普通字符串没有标签就返回空串。"""
    return getattr(message, "kind", "") or ""


# 多个闸门拒绝合并成一条 403 时，`denial_kind` 取哪一档。
#
# 放在这里而不是某个工具族里：它是 `DenialKind` 的**语义补充**（"两档同时命中时哪一档
# 说话"），只要还有第二处地方需要合并拒绝，定义留在 web_tools 就会被复制一份 ——
# 而两份排序表一旦漂移，同一组拒绝在两条路径上会得到不同的 instruction。
#
# 排序判据是**模型的下一步动作**，不是"技术原因谁更严重"：合并结果只有一个
# `denial_kind`，执行层只会据它发一条 instruction。给错档位的代价不对称 ——
# 把"永远不成"的硬边界说成"换个写法再试"，模型会围着一个不存在的出路反复调用；
# 反过来把"换法可能成功"说严，最坏只是少试一次，用户还能自己放宽清单。
# 所以越靠前 = 对模型的约束越强，合并时取靠前的那一档。
#
# `PERMISSION_LEVEL` 刻意排最后：它是唯一会引导 `request_permission` 的一档，
# 混档时给它等于让模型去申请一个对另一档毫无作用的提权 —— 提权批下来仍然被拒。
DENIAL_SEVERITY: Tuple[str, ...] = (
    # 硬拒：没有确认通道，重试永远拿到同一个结果
    DenialKind.POLICY_FORBIDDEN, DenialKind.SECRET_FILE, DenialKind.NEVER_WRITABLE,
    DenialKind.NETWORK_PATH, DenialKind.EXECUTABLE_LAUNCH,
    # 需要人：本轮不可能成功，换法也没用
    DenialKind.APPROVAL_DENIED, DenialKind.APPROVAL_ERROR,
    DenialKind.APPROVAL_UNAVAILABLE,
    # 换法/换环境可能成功。
    #
    # `SANDBOX_UNAVAILABLE` 排在这一组**最前**，判据是"谁改不动谁说话"：这一档说的是
    # 沙箱档位在这台机器上不可用，那是环境的事，模型改写命令、换路径、换工具都不会让它
    # 变得可用。它以前排在组尾，于是和 `COMMAND_SHAPE` 同时命中时发出去的指令是
    # "把命令写法改对"—— 模型会围着一个它改不动的东西反复改写，正是这张表声称要避免的
    # 那个死循环。反过来（沙箱压过命令形态）最坏只是让模型先去处理环境，而那一步无论
    # 如何都躲不掉。
    # 仍留在本组而不是挪进"需要人"：换环境（装上执行器 / 放宽档位）确实能让它成功，
    # 归到"找人"会让模型放弃一条其实走得通的路。
    DenialKind.SANDBOX_UNAVAILABLE,
    # 紧跟在沙箱后面，判据同样是"谁改不动谁说话"：可选依赖没装、外部程序不在、
    # 必需配置没填，这三件事模型改写参数、换路径都不会让它出现。它和
    # `COMMAND_SHAPE` / `PATH_OUT_OF_SCOPE` 同时命中时，发"把写法改对"会让模型
    # 围着一个它改不动的东西反复改写 —— 与沙箱那一档同一个死循环。
    # 排在 `SANDBOX_UNAVAILABLE` 之后而不是之前：沙箱不可用关掉的是整条执行通道，
    # 换工具也落到同一个执行器；依赖缺失只关掉一个能力（notify_send 的 toast），
    # 同一个工具换个 channel 就绕过去了 —— 前者的出路更少，先说前者。
    DenialKind.DEPENDENCY_MISSING,
    DenialKind.PATH_OUT_OF_SCOPE, DenialKind.COMMAND_SHAPE,
    DenialKind.TOOL_CAPABILITY, DenialKind.CODE_GATE,

    # 唯一允许引导提权的一档
    DenialKind.PERMISSION_LEVEL,
)


def denial_rank(kind: str) -> int:
    """严重度序号；未登记的取值排在所有已登记的之后。

    未登记不能当成"最轻"也不能当成"最重"：它的严重程度这里确实不知道，
    但绝不能让一个"忘了归档"的新取值压掉一个已知的硬拒。
    """
    try:
        return DENIAL_SEVERITY.index(kind)
    except ValueError:
        return len(DENIAL_SEVERITY)


def merge_denials(refusals: List[Tuple[str, Any]],
                  deny: Callable[[str, str, Dict[str, Any]], Denial]) -> Denial:
    """把多路闸门拒绝合并成**一个** `Denial`（带 kind 与 detail）。

    为什么不能直接 `"；".join(refusals)`：`Denial` 是 str 子类，join 的产物是
    普通 `str`，`kind` 和 `detail` 在那一刻就掉了。下游 `denial_kind_of()` 拿到
    空串，执行层落到兜底指令 —— 而这条 403 恰恰要禁止的就是"去调
    request_permission / 原样重试"，兜底指令说不出这一句。

    `detail` 按来源加前缀再合并：多路的 detail 键名是同一套（`hook_error` 等），
    直接 update 会让后一路静默覆盖前一路，排障时看不出是哪个引擎挂了。

    `deny` 由调用方注入（`ToolExecutorBase._deny`）而不是在这里直接 `Denial(...)`：
    "detail 怎么挂上去、值怎么转成可 json 的形状"只该有一份实现，本模块再写一遍
    就等于给同一件事留两个版本，改一处忘一处时 metadata 会静默变形。
    """
    message = "；".join(str(gate) for _, gate in refusals)
    kinds = [k for k in (denial_kind_of(gate) for _, gate in refusals) if k]
    kind = min(kinds, key=denial_rank) if kinds else ""
    detail: Dict[str, Any] = {}
    for source, gate in refusals:
        for k, v in (getattr(gate, "detail", None) or {}).items():
            detail[f"{source}.{k}"] = v
    if len(set(kinds)) > 1:
        # 合并把多档压成一档，被压掉的那些只有 metadata 这一条通道能留下。
        # 少了它，日志里看到的是"用户拒绝"，看不到另一路其实是硬边界。
        detail["merged_kinds"] = ", ".join(
            f"{source}={denial_kind_of(gate) or '-'}" for source, gate in refusals)
    return deny(kind, message, detail)



@dataclass
class ExecutionResult:
    """执行结果"""
    status: str = "success"           # success / error / guard_violation / bait_triggered / permission_denied
    data: Any = None
    error_code: str = ""
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    # 拒绝类型（见 DenialKind）。取值范围与 error_code 的对应关系：
    #   403 —— 闸门主动拒绝，一律带 kind（由 `_denied()` 收口）。
    #   501 —— "这台机器不具备该能力"，带 `DEPENDENCY_MISSING`。
    #   400/404/500/502/504 —— 一律留空，那些不是"谁拦的"问题。
    #
    # 501 也带 kind 是刻意的，不是把契约放宽了图省事：`execution_layer` 有两处按
    # 这个字段分派，而 501 在两处都需要走"带 kind"的那一支 ——
    #   1. `_note_tool_failure` 的熔断豁免：依赖没装不是模型能靠重试或改写解决的，
    #      计入熔断等于用"防原地打转"的机制禁掉整个工具（连同它本来能用的 channel）；
    #   2. `DENIAL_INSTRUCTIONS` 查表：这一档需要说的恰恰是"换 channel / 让用户去装"，
    #      而 400/500 那两条分支说不出这句。
    # 反过来说，凡是给 501 带上这一档的地方，都必须确认"换个用法真的可能成功"；
    # 只是内部坏了（`_internal_error` 那类）仍然走 500 且不带 kind。
    denial_kind: str = ""
