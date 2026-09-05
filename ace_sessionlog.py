#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ace_sessionlog —— 会话事件日志（借鉴 DSH session 子系统的分期落地第一步）

DSH 的第一原则是「模型可见 ⟺ 可记录」：任何到达模型的输入、任何模型输出、
任何工具往返，都必须能从一份 append-only 事件日志里重建。压缩、回滚、审计、
调试因此都站在同一份事实源上，而不是各自维护一份内存状态。

本模块实现该原则的**阶段 1**（核心，不依赖 surface 投影）：
- append-only JSONL 落盘：事件只追加不修改，崩溃不产生半截记录
- seq 连续契约：每事件一个递增序号，跳号即丢事件，消费方可检测
- 深冻结：payload 在追加点做 JSON 序列化校验，坏事件当场失败而不是落盘后才发现
- 线程安全：CLI 与执行层并发追加不交错

阶段 2（surface 投影 / 无损压缩）留给后续：先有"事实源"，再做"从事实源派生"。
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List

# 事件种类（与 DSH SessionEventMap 对齐的 ACE 子集）
K_USER_MESSAGE = "user/message"          # 到达模型的用户输入（含注入的记忆/目标续跑）
K_ASSISTANT_MESSAGE = "assistant/message"  # 模型本轮完整输出（原文，含协议/JSON）
K_REQUEST_SNAPSHOT = "request/snapshot"  # 每次模型请求的 envelope 摘要（可重建"模型看到了什么"）
K_SYSTEM_SNAPSHOT = "system/snapshot"    # 每次模型请求的完整系统提示词（含 AGENTS.md/记忆/目标）
K_TOOL_CALL = "tool/call"                # 模型发出的工具调用（原始参数）
K_TOOL_RESULT = "tool/result"            # 工具执行结果（状态 + 摘要）
K_PERMISSION = "permission/decision"    # 执行层权限裁决（allow/deny/confirm/grant）
K_GUARD = "guard/verdict"                # 守卫违规 / 诱饵 / AST 拦截
K_SNAPSHOT_CREATE = "snapshot/create"    # 写入前快照
K_SNAPSHOT_ROLLBACK = "snapshot/rollback"  # 回滚
K_GOAL_ROUND = "goal/round"              # 目标轮次推进
K_MODEL_ERROR = "model/error"            # 模型 API 调用失败
K_COMPACTION = "compaction/event"        # 上下文压缩
K_MODEL_SWITCH = "model/switch"          # 模型/提供商切换


class SessionLog:
    """append-only 会话事件日志。path 指向 .jsonl 文件。"""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._next_seq = 1
        self._load_seq()

    def _load_seq(self) -> None:
        """从已有文件恢复 seq：任何时刻重放都能接着写（跨进程续记）。"""
        try:
            if self.path.exists():
                with open(self.path, "r", encoding="utf-8") as f:
                    last = 0
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                            last = max(last, int(ev.get("seq", 0)))
                        except (json.JSONDecodeError, ValueError, TypeError):
                            continue   # 半截尾部（崩溃残留）跳过，不阻塞续记
                    self._next_seq = last + 1
        except OSError:
            pass

    def append(self, kind: str, payload: Dict[str, Any]) -> int:
        """追加一个事件，返回其 seq。payload 必须是可 JSON 序列化的 dict（深冻结）。"""
        with self._lock:
            try:
                line = json.dumps({
                    "seq": self._next_seq,
                    "kind": kind,
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    **payload,
                }, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError) as e:
                raise ValueError(f"事件 payload 不可序列化（kind={kind}）: {e}") from e
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            seq = self._next_seq
            self._next_seq += 1
            return seq

    def events(self) -> Iterator[Dict[str, Any]]:
        """按序重放全部事件（生成器，可流式消费）。"""
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        """最近 n 条事件（审计/排障用）。"""
        all_ev = list(self.events())
        return all_ev[-n:]

    def seq_contiguous(self) -> bool:
        """seq 是否从 1 连续无跳号（丢事件检测）。"""
        expect = 1
        for ev in self.events():
            if int(ev.get("seq", 0)) != expect:
                return False
            expect += 1
        return True

    def count(self) -> int:
        return sum(1 for _ in self.events())

    # ---------- 便捷记录方法（会话层调用） ----------

    def record_user(self, content: str) -> int:
        return self.append(K_USER_MESSAGE, {"content": content})

    def record_assistant(self, content: str) -> int:
        return self.append(K_ASSISTANT_MESSAGE, {"content": content})

    def record_request(self, *, model: str, base_url: str, permission: str,
                       system_len: int, messages_count: int,
                       subagent: str = "") -> int:
        """每次模型请求的 envelope 摘要：足够重建"这次请求模型看到了什么"的结构。
        subagent 非空表示这是子代理请求（spawn/fork），replay 时可区分。"""
        return self.append(K_REQUEST_SNAPSHOT, {
            "model": model, "base_url": base_url, "permission": permission,
            "system_len": system_len, "messages_count": messages_count,
            "subagent": subagent,
        })

    def record_tool_call(self, tool: str, params: Dict[str, Any]) -> int:
        return self.append(K_TOOL_CALL, {"tool": tool, "params": params})

    def record_tool_result(self, tool: str, status: str, message: str = "") -> int:
        return self.append(K_TOOL_RESULT, {
            "tool": tool, "status": status, "message": (message or "")[:300],
        })

    def record_goal_round(self, rounds_started: int, max_rounds: int) -> int:
        return self.append(K_GOAL_ROUND, {
            "rounds_started": rounds_started, "max_rounds": max_rounds})

    def record_system(self, system: str) -> int:
        """每次请求的完整系统提示词（含 AGENTS.md/记忆注入/目标——"模型看到了什么"的全文）。"""
        return self.append(K_SYSTEM_SNAPSHOT, {"system": system})

    def record_permission(self, tool: str, decision: str,
                          level: str, detail: str = "") -> int:
        return self.append(K_PERMISSION, {
            "tool": tool, "decision": decision, "level": level,
            "detail": (detail or "")[:200]})

    def record_guard(self, rule: str, action: str, detail: str = "") -> int:
        return self.append(K_GUARD, {"rule": rule, "action": action,
                                     "detail": (detail or "")[:200]})

    def record_snapshot(self, kind: str, snapshot_id: str, tag: str = "") -> int:
        return self.append(kind, {"snapshot_id": snapshot_id, "tag": tag})

    def record_model_error(self, err: str, hint: str = "") -> int:
        return self.append(K_MODEL_ERROR, {"error": (err or "")[:300],
                                           "hint": (hint or "")[:200]})

    def record_compaction(self, before: int, after: int, reason: str) -> int:
        return self.append(K_COMPACTION, {
            "before": before, "after": after, "reason": reason})

    # ---------- 从日志重建（DSH B2：消息历史 = 日志派生，不单独存储） ----------

    def replay_messages(self) -> List[Dict[str, str]]:
        """从事件日志重建模型看到的消息序列（user/assistant 交替，按 seq 排序）。

        阶段 2a 能力：消息历史是日志的派生视图 —— 审计、调试、未来的 resume
        重放重建都从这一份事实源来，而不是各自维护一份内存副本。
        """
        msgs: List[Dict[str, str]] = []
        for ev in self.events():
            kind = ev.get("kind")
            if kind == K_USER_MESSAGE:
                msgs.append({"role": "user", "content": ev.get("content", "")})
            elif kind == K_ASSISTANT_MESSAGE:
                msgs.append({"role": "assistant", "content": ev.get("content", "")})
        return msgs
