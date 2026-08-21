#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gateway_v2.intent —— L1 意图识别 + L2 技能推荐

  L1 意图识别：关键词分类（coding / writing / analysis / fiction / other）
  L2 技能推荐：按意图推荐技能（只推荐不决定，零误判）
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

INTENT_KEYWORDS: Dict[str, List[str]] = {
    "coding": [
        "写代码", "代码", "编程", "函数", "bug", "debug", "报错", "重构", "算法",
        "脚本", "python", "java", "前端", "后端", "接口", "api", "sql", "数据库",
        "类", "对象", "模块", "实现", "单元测试", "部署", "git", "爬虫",
    ],
    "writing": [
        "写文章", "文案", "写一篇", "作文", "报告", "总结", "邮件", "周报", "日报",
        "新闻稿", "软文", "标题", "大纲", "润色",
    ],
    "analysis": [
        "分析", "数据", "统计", "对比", "解读", "洞察", "趋势", "图表", "指标",
        "评估", "调研", "报表",
    ],
    "fiction": [
        "小说", "故事", "续写", "角色", "剧情", "世界观", "章节", "番外", "同人", "设定",
    ],
}

INTENT_LABELS: Dict[str, str] = {
    "coding": "编程开发",
    "writing": "文案写作",
    "analysis": "数据分析",
    "fiction": "小说创作",
    "other": "通用对话",
}


@dataclass
class Intent:
    """L1 意图识别结果"""

    raw_input: str
    intent: str = "other"
    confidence: float = 0.0
    matched_keywords: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._classify()

    def _classify(self) -> None:
        text = (self.raw_input or "").lower()
        scores: Dict[str, int] = {}
        matched: Dict[str, List[str]] = {}
        for name, keywords in INTENT_KEYWORDS.items():
            hits = [kw for kw in keywords if kw in text]
            scores[name] = len(hits)
            matched[name] = hits
        best = max(scores, key=lambda k: scores[k])
        if scores[best] > 0:
            self.intent = best
            self.matched_keywords = matched[best]
            total = sum(1 for s in scores.values() if s > 0)
            self.confidence = round(min(1.0, scores[best] / max(total, 1)), 3)
        else:
            self.intent = "other"
            self.confidence = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_input": self.raw_input,
            "intent": self.intent,
            "label": INTENT_LABELS.get(self.intent, "通用对话"),
            "confidence": self.confidence,
            "matched_keywords": self.matched_keywords,
        }


DEFAULT_SKILLS: Dict[str, List[str]] = {
    "coding": ["code_execute", "file_write", "terminal_exec", "search"],
    "writing": ["file_write", "search", "notify_send", "parse_document"],
    "analysis": ["db_query", "math_calc", "parse_document", "search"],
    "fiction": ["file_write", "search", "file_read"],
    "other": ["search", "file_read", "datetime_now"],
}


class SkillRecommender:
    """L2 技能推荐：只推荐、不替用户决定（零误判）"""

    def __init__(self, registry: Optional[Dict[str, List[str]]] = None) -> None:
        self.registry = dict(registry or DEFAULT_SKILLS)

    def recommend(self, intent: Intent, top_k: int = 4) -> List[str]:
        skills = self.registry.get(intent.intent, self.registry.get("other", []))
        return skills[:top_k]

    def add_skill(self, intent_name: str, skill: str) -> None:
        self.registry.setdefault(intent_name, []).append(skill)
