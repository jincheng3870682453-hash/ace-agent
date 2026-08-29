#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.goal_tools —— 持久化目标状态机（借鉴 DSH goal / goal-round-driver）

长任务可靠性的根基：把"Agent 正在干什么、干到哪、为什么停"变成可查询、可恢复、
可防旧状态覆盖新状态的状态机，而不是只靠一轮 prompt 里的口头约定。

核心设计（与 DSH goal 子系统对齐的务实子集）：
- **revision CAS**：每次变更必须携带期望 revision，stale 即拒绝（GOAL_STALE_REVISION）。
  防的是模型重试/并发时用旧状态覆盖新状态。
- **phase 状态机**：active / paused / blocked / complete。
  blocked 只能由 active 进入，且必须给出 机器 code + 人类 message；
  difficulty / uncertainty 这类"难但不是阻塞"的 code 会被拒绝。
- **armed / disarmed 分离**：重启后自动 disarmed（phase 保留但不会自动续跑），
  须人类显式 resume 才重新武装 —— 重启不会无授权地自己接着干。
- **轮次预算**：rounds_started < max_rounds 才允许 active 续跑。
- **JSON 持久化**：项目根 .ace_goals.json，原子写（临时文件 + rename）。
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.result import ExecutionResult

# phase 取值
PHASE_ACTIVE = "active"
PHASE_PAUSED = "paused"
PHASE_BLOCKED = "blocked"
PHASE_COMPLETE = "complete"
PHASES = (PHASE_ACTIVE, PHASE_PAUSED, PHASE_BLOCKED, PHASE_COMPLETE)

# 允许自报 blocked 的机器 code（reason_code 白名单）。
# "难""不确定""耗时"这类不算阻塞：它们不是无法继续，只是没有进展，
# 模型应当继续尝试或直接向用户汇报，而不是把问题甩给状态机。
BLOCKED_CODES = {
    "missing_dependency",   # 缺依赖且无法安装（无网/权限）
    "api_unavailable",      # 外部服务/API 不可达
    "permission_blocked",   # 权限被拒且无合法路径
    "invalid_input",        # 用户需求本身矛盾/无法满足
    "environment_broken",   # 环境损坏（编译器/解释器坏了）
}
# 明确不算阻塞的 code（difficulty/uncertainty 类），被拒时给明确理由
NOT_BLOCKED_CODES = {"difficulty", "uncertainty", "too_hard", "unsure"}

GOAL_FILE = ".ace_goals.json"


@dataclass
class Goal:
    id: str
    revision: int
    objective: str
    phase: str = PHASE_ACTIVE
    rounds_started: int = 0
    max_rounds: int = 20
    armed: bool = True
    blocked_reason_code: str = ""
    blocked_reason_message: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Goal":
        known = {f: d.get(f) for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in known.items() if v is not None})


class GoalError(RuntimeError):
    """goal 操作的业务错误（code 供工具层映射成稳定错误码）"""
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class GoalStore:
    """单个活动目标的持久化状态机。同一时刻只跟踪一个目标（简化：单目标足够）。"""

    def __init__(self, project_root: str) -> None:
        self.path = Path(project_root).resolve() / GOAL_FILE
        self._lock = threading.Lock()
        self._goal: Optional[Goal] = None
        self._load()

    # ---------- 持久化 ----------

    def _load(self) -> None:
        try:
            if self.path.exists():
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._goal = Goal.from_dict(data)
        except (json.JSONDecodeError, OSError, TypeError):
            self._goal = None   # 损坏文件不崩溃：当作没有目标，重新开始

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._goal.to_dict(), ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.replace(tmp, self.path)   # 原子替换，崩溃不产生半截文件

    # ---------- 查询 ----------

    def current(self) -> Optional[Goal]:
        with self._lock:
            return self._goal

    def snapshot(self) -> Optional[Dict[str, Any]]:
        g = self.current()
        return g.to_dict() if g else None

    # ---------- 变更（全部走 revision CAS） ----------

    def create(self, objective: str, max_rounds: int = 20) -> Goal:
        objective = (objective or "").strip()
        if not objective:
            raise GoalError("GOAL_EMPTY_OBJECTIVE", "目标内容为空")
        if not (1 <= int(max_rounds) <= 1000):
            raise GoalError("GOAL_BAD_ROUNDS", "max_rounds 应在 1~1000 之间")
        with self._lock:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            self._goal = Goal(
                id=f"{int(time.time() * 1000):x}{uuid.uuid4().hex[:4]}",
                revision=1, objective=objective, phase=PHASE_ACTIVE,
                max_rounds=int(max_rounds), armed=True,
                created_at=now, updated_at=now)
            self._save()
            return self._goal

    def update(self, goal_id: str, expected_revision: int, *,
               phase: Optional[str] = None,
               reason_code: str = "", reason_message: str = "") -> Goal:
        with self._lock:
            g = self._goal
            if g is None:
                raise GoalError("GOAL_NOT_FOUND", "当前没有活动目标（先用 goal_create 创建）")
            if g.id != goal_id:
                raise GoalError("GOAL_STALE_REVISION",
                                f"目标 id 不匹配（当前 {g.id}，传入 {goal_id}）")
            if g.revision != int(expected_revision):
                raise GoalError("GOAL_STALE_REVISION",
                                f"修订号过期（当前 {g.revision}，传入 {expected_revision}），"
                                "请重新读取 goal_status 后再更新")
            if phase is not None:
                self._apply_phase(g, phase, reason_code, reason_message)
            g.revision += 1
            g.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
            self._save()
            return g

    def _apply_phase(self, g: Goal, phase: str,
                     reason_code: str, reason_message: str) -> None:
        if phase not in PHASES:
            raise GoalError("GOAL_BAD_PHASE", f"未知 phase: {phase}（{PHASES}）")
        if phase == g.phase:
            return
        if phase == PHASE_BLOCKED:
            if g.phase != PHASE_ACTIVE:
                raise GoalError("GOAL_BAD_TRANSITION",
                                f"只有 active 目标可以自报 blocked（当前 {g.phase}）")
            code = (reason_code or "").strip().lower()
            msg = (reason_message or "").strip()
            if not code or not msg:
                raise GoalError("GOAL_BLOCKED_NEEDS_REASON",
                                "自报 blocked 必须同时给出机器 code（如 api_unavailable）"
                                "与人类可读的说明")
            if code in NOT_BLOCKED_CODES:
                raise GoalError("GOAL_NOT_A_BLOCKER",
                                f"'{code}' 不算阻塞（难度/不确定不是无法继续），"
                                "请继续尝试或向用户汇报")
            if code not in BLOCKED_CODES:
                raise GoalError("GOAL_UNKNOWN_CODE",
                                f"未知阻塞 code: '{code}'（可选: {sorted(BLOCKED_CODES)}）")
            g.phase = PHASE_BLOCKED
            g.blocked_reason_code = code
            g.blocked_reason_message = msg
            g.armed = False
            return
        if phase == PHASE_COMPLETE:
            if g.phase != PHASE_ACTIVE:
                raise GoalError("GOAL_BAD_TRANSITION",
                                f"只有 active 目标可以标记完成（当前 {g.phase}）")
            g.phase = PHASE_COMPLETE
            g.armed = False
            return
        if phase == PHASE_PAUSED:
            if g.phase not in (PHASE_ACTIVE,):
                raise GoalError("GOAL_BAD_TRANSITION",
                                f"只有 active 目标可以暂停（当前 {g.phase}）")
            g.phase = PHASE_PAUSED
            return
        if phase == PHASE_ACTIVE:
            if g.phase not in (PHASE_PAUSED, PHASE_BLOCKED):
                raise GoalError("GOAL_BAD_TRANSITION",
                                f"只有 paused/blocked 目标可以恢复 active（当前 {g.phase}）")
            if g.rounds_started >= g.max_rounds:
                raise GoalError("GOAL_ROUNDS_EXHAUSTED",
                                f"轮次预算已用完（{g.rounds_started}/{g.max_rounds}），无法继续")
            g.phase = PHASE_ACTIVE
            g.blocked_reason_code = ""
            g.blocked_reason_message = ""
            return

    # ---------- 轮次驱动 ----------

    def start_round(self) -> Optional[Goal]:
        """轮次驱动：active + armed + 预算内 → 记一轮并返回；否则返回 None。"""
        with self._lock:
            g = self._goal
            if g is None or g.phase != PHASE_ACTIVE or not g.armed:
                return None
            if g.rounds_started >= g.max_rounds:
                return None
            g.rounds_started += 1
            g.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
            self._save()
            return g

    def disarm(self) -> None:
        """重启/会话结束时调用：保留 phase，但不再自动续跑。"""
        with self._lock:
            if self._goal is not None:
                self._goal.armed = False
                self._save()

    def resume(self, goal_id: str, expected_revision: int) -> Goal:
        """人类显式恢复：重新武装（phase 必须是 paused/blocked 之外的 active，或任何可继续态）。"""
        with self._lock:
            g = self._goal
            if g is None or g.id != goal_id:
                raise GoalError("GOAL_NOT_FOUND", "目标不存在")
            if g.revision != int(expected_revision):
                raise GoalError("GOAL_STALE_REVISION",
                                f"修订号过期（当前 {g.revision}，传入 {expected_revision}）")
            if g.phase == PHASE_COMPLETE:
                raise GoalError("GOAL_DONE", "目标已完成，不能恢复")
            if g.rounds_started >= g.max_rounds:
                raise GoalError("GOAL_ROUNDS_EXHAUSTED",
                                f"轮次预算已用完（{g.rounds_started}/{g.max_rounds}）")
            g.armed = True
            g.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
            self._save()
            return g


class GoalTools:
    """goal_create / goal_update / goal_status 工具（挂在 ToolExecutor 上）"""

    def _goal_store(self) -> GoalStore:
        if getattr(self, "_goal_store_obj", None) is None:
            self._goal_store_obj = GoalStore(str(self.project_root))
        return self._goal_store_obj

    def _exec_goal_create(self, params: Dict) -> ExecutionResult:
        try:
            g = self._goal_store().create(
                str(params.get("objective", "")),
                int(params.get("max_rounds", 20) or 20))
        except GoalError as e:
            return ExecutionResult(status="error", error_code=e.code, message=e.message)
        except (TypeError, ValueError):
            return ExecutionResult(status="error", error_code="400",
                                   message="max_rounds 应为整数")
        return ExecutionResult(status="success", data={
            "goal": g.to_dict(),
            "message": f"目标已创建（{g.id}），每轮自动续跑，预算 {g.max_rounds} 轮",
        })

    def _exec_goal_update(self, params: Dict) -> ExecutionResult:
        try:
            g = self._goal_store().update(
                str(params.get("id", "")), int(params.get("revision", 0)),
                phase=str(params.get("phase", "")).strip() or None,
                reason_code=str(params.get("reason_code", "")),
                reason_message=str(params.get("reason_message", "")))
        except GoalError as e:
            return ExecutionResult(status="error", error_code=e.code, message=e.message)
        except (TypeError, ValueError):
            return ExecutionResult(status="error", error_code="400",
                                   message="revision 应为整数")
        return ExecutionResult(status="success", data={"goal": g.to_dict()})

    def _exec_goal_status(self, params: Dict) -> ExecutionResult:
        snap = self._goal_store().snapshot()
        if snap is None:
            return ExecutionResult(status="success", data={
                "goal": None, "message": "当前没有活动目标（可用 goal_create 创建）"})
        return ExecutionResult(status="success", data={"goal": snap})
