#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gateway_v2 —— L1/L2/L4/L5 四层网关（包结构）

  L1 意图识别  gateway_v2.intent     关键词分类（coding/writing/analysis/fiction/other）
  L2 技能推荐  gateway_v2.intent     按意图推荐技能（只推荐不决定，零误判）
  L4 本能守门  gateway_v2.guard      InstinctGuard 8 条规则检测输出合规性
  L5 反馈飞轮  gateway_v2.flywheel   违规数据自动收集（JSONL），用于 SFT 微调

原 L3「模型调用适配层」已移除：模型调用统一由 ai_code.ModelClient /
agent_runner 承担，网关这份 ModelAdapter 从未被调用，却在组合根里持有
api_key、并在 status() 里外泄「是否已配置模型」，纯负债。


对外保持兼容：
    from gateway_v2 import WordGateway, GuardViolation, Intent
"""

from typing import Any, Dict, List, Optional

from gateway_v2.intent import (DEFAULT_SKILLS, INTENT_KEYWORDS, INTENT_LABELS,
                               Intent, SkillRecommender)
from gateway_v2.guard import (FENCE_RE, SECRET_PLACEHOLDERS, SECRET_RE,
                              SQL_CONCAT_RE, SQL_TAUTOLOGY_RE, GuardResult,
                              GuardViolation, InstinctGuard)
from gateway_v2.flywheel import Flywheel

__all__ = [
    "DEFAULT_SKILLS", "INTENT_KEYWORDS", "INTENT_LABELS", "Intent",
    "SkillRecommender", "InstinctGuard", "GuardResult",
    "GuardViolation", "Flywheel", "WordGateway",
    "SECRET_RE", "SECRET_PLACEHOLDERS", "SQL_CONCAT_RE", "SQL_TAUTOLOGY_RE",
    "FENCE_RE",
]


class WordGateway:
    """L1/L2/L4/L5 网关组合根"""

    def __init__(self, config: Optional[Dict] = None) -> None:
        self.config = config or {}
        self.skills = SkillRecommender(self.config.get("skills"))
        self.guard = InstinctGuard(self.config.get("guard", {}))
        self.flywheel = Flywheel(self.config.get("flywheel_path"))


    def route(self, user_input: str) -> Dict[str, Any]:
        """L1 → L2 路由：意图识别 + 技能推荐"""
        intent = Intent(raw_input=user_input)
        return {
            "intent": intent.to_dict(),
            "skills": self.skills.recommend(intent),
            "guard_enabled": True,
        }

    def check_output(self, text: str) -> GuardResult:
        """L4 守门"""
        return self.guard.check(text)

    def status(self) -> Dict[str, Any]:
        return {
            "l1_intent": "ok",
            "l2_skills": "ok",
            "l4_rules": self.enabled_rules(),
            "l5_flywheel": self.flywheel.stats(),
        }

    def enabled_rules(self) -> List[str]:
        return [r for r, on in self.guard.enabled.items() if on]
