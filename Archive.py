#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Archive.py —— SimHash 记忆注入引擎

契约（execution_layer.py）：
    from Archive import MemoryArchive
    archive = MemoryArchive()
    archive.add(user_input)                  # 短输入保护：少于 10 字不存储
    archive.detect_topic_shift(user_input)   # -> "shifted" / "stable"
    archive.get_memory(top_k=3)              # -> 相关记忆列表（注入上下文用）
    archive.stats()                          # -> 统计

机制（与 system prompt 对齐）：
    · SimHash 指纹记录对话特征，主题相似度采用 token 包含系数（阈值 0.25）
    · 主题稳定时不注入记忆（节省 token），主题切换时注入相关记忆
    · 短输入保护：少于 10 字的对话不存入记忆
    · 紧急度信号：检测到催促词时提高记忆权重
"""

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

SIMHASH_BITS = 64
SHORT_INPUT_LEN = 10          # 少于 10 字的对话不存入记忆
SHIFT_THRESHOLD = 0.25        # SimHash 相似度低于该阈值 → 主题切换
URGENCY_KEYWORDS = ("快", "马上", "立刻", "立即", "尽快", "赶紧", "急",
                    "紧急", "速度", "asap", "urgent", "快点")
URGENCY_WEIGHT = 1.6          # 催促词记忆权重提升


@lru_cache(maxsize=8192)
def _tokenize(text: str) -> List[str]:
    """分词：拉丁单词 + 中文整段 + 中文二元组"""
    tokens: List[str] = []
    for w in re.findall(r"[a-z0-9_]+", text.lower()):
        tokens.append(f"w:{w}")
    for seg in re.findall(r"[\u4e00-\u9fff]+", text):
        tokens.append(f"c:{seg}")
        for i in range(len(seg) - 1):
            tokens.append(f"b:{seg[i:i+2]}")
    return tokens or ["empty"]


@lru_cache(maxsize=8192)
def simhash(text: str) -> int:
    """64 位 SimHash 指纹"""
    weights = [0] * SIMHASH_BITS
    for tok in _tokenize(text):
        h = int.from_bytes(hashlib.md5(tok.encode("utf-8")).digest()[:8], "big")
        for i in range(SIMHASH_BITS):
            weights[i] += 1 if (h >> i) & 1 else -1
    fp = 0
    for i in range(SIMHASH_BITS):
        if weights[i] > 0:
            fp |= 1 << i
    return fp


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def similarity(a: int, b: int) -> float:
    return 1.0 - hamming(a, b) / SIMHASH_BITS


def text_similarity(a: str, b: str) -> float:
    """主题相似度：token 集包含系数（对短中文文本比 64 位 SimHash 位差更稳定）"""
    ta = set(_tokenize(a or ""))
    tb = set(_tokenize(b or ""))
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / min(len(ta), len(tb))


@dataclass
class MemoryEntry:
    text: str
    simhash: int
    ts: float
    urgent: bool
    weight: float
    session: str = "default"


class MemoryArchive:
    """SimHash 记忆引擎（支持多会话隔离：不同 session_tag 互不污染）"""

    def __init__(self, path: Optional[str] = None,
                 threshold: float = SHIFT_THRESHOLD,
                 session_tag: str = "default") -> None:
        self.path = Path(path) if path else None
        self.threshold = threshold
        self.session_tag = session_tag
        self.entries: List[MemoryEntry] = []
        self.topic_anchors: Dict[str, Optional[int]] = {}   # 每会话独立主题锚点
        self.topic_texts: Dict[str, str] = {}
        self.shift_count = 0
        self._load()

    def set_session(self, tag: str) -> None:
        """切换当前会话标签（多会话并发时用不同 tag 隔离记忆）"""
        self.session_tag = tag or "default"

    # ---------- 记忆写入 ----------

    def add(self, text: str) -> bool:
        """写入一条记忆；短输入保护：少于 SHORT_INPUT_LEN 字不存储"""
        text = (text or "").strip()
        if len(text) < SHORT_INPUT_LEN:
            return False
        urgent = any(k in text for k in URGENCY_KEYWORDS)
        entry = MemoryEntry(
            text=text,
            simhash=simhash(text),
            ts=time.time(),
            urgent=urgent,
            weight=URGENCY_WEIGHT if urgent else 1.0,
            session=self.session_tag,
        )
        self.entries.append(entry)
        self._persist()
        return True

    # ---------- 主题切换检测（按会话隔离） ----------

    def detect_topic_shift(self, text: str) -> str:
        """检测主题是否切换：返回 "shifted" / "stable"（短输入恒为 stable）"""
        text = (text or "").strip()
        if len(text) < SHORT_INPUT_LEN:
            return "stable"
        fp = simhash(text)
        anchor = self.topic_anchors.get(self.session_tag)
        topic_text = self.topic_texts.get(self.session_tag, "")
        if anchor is None:
            self.topic_anchors[self.session_tag] = fp
            self.topic_texts[self.session_tag] = text
            return "stable"
        if text_similarity(text, topic_text) < self.threshold:
            self.topic_anchors[self.session_tag] = fp
            self.topic_texts[self.session_tag] = text
            self.shift_count += 1
            return "shifted"
        return "stable"

    # ---------- 记忆召回 / 注入 ----------

    def get_memory(self, query: Optional[str] = None, top_k: int = 5,
                   exclude_last: bool = False) -> List[Dict]:
        """按主题相似度 × 权重召回相关记忆（仅当前会话；exclude_last：排除刚写入的当前消息）"""
        if not self.entries:
            return []
        session_entries = [e for e in self.entries if e.session == self.session_tag]
        if exclude_last and len(session_entries) > 1:
            entries = list(session_entries[:-1])
        else:
            entries = list(session_entries)
        if not entries:
            return []
        anchor_text = query or self.topic_texts.get(self.session_tag, "") or ""
        ranked = []
        for e in entries:
            sim = text_similarity(e.text, anchor_text)
            ranked.append((sim * e.weight, sim, e))
        ranked.sort(key=lambda x: x[0], reverse=True)
        out: List[Dict] = []
        for score, sim, e in ranked[:top_k]:
            if score <= 0:
                break   # 无 token 交集的不相关记忆直接丢弃，不注入噪声
            out.append({
                **asdict(e),
                "similarity": round(sim, 4),
                "score": round(score, 4),
                "text": e.text[:200],
            })
        return out

    def inject_context(self, query: Optional[str] = None, top_k: int = 5) -> str:
        """生成可注入上下文的记忆文本"""
        mem = self.get_memory(query, top_k)
        if not mem:
            return ""
        lines = ["[记忆注入] 以下是相关的历史对话记忆："]
        for m in mem:
            mark = "⚡" if m["urgent"] else "·"
            lines.append(f"{mark} {m['text']}")
        return "\n".join(lines)

    # ---------- 统计与持久化 ----------

    def stats(self) -> Dict:
        session_entries = [e for e in self.entries if e.session == self.session_tag]
        return {
            "session": self.session_tag,
            "entries": len(session_entries),
            "total_entries": len(self.entries),
            "urgent_entries": sum(1 for e in session_entries if e.urgent),
            "shift_count": self.shift_count,
            "current_topic": self.topic_texts.get(self.session_tag, "")[:40],
            "threshold": self.threshold,
            "persist_path": str(self.path) if self.path else None,
        }

    def _persist(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "entries": [asdict(e) for e in self.entries],
            "topic_anchors": self.topic_anchors,
            "topic_texts": self.topic_texts,
            "shift_count": self.shift_count,
        }
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            entries = []
            for e in data.get("entries", []):
                e.setdefault("session", "default")
                entries.append(MemoryEntry(**e))
            self.entries = entries
            self.topic_anchors = data.get("topic_anchors", {})
            self.topic_texts = data.get("topic_texts", {})
            self.shift_count = data.get("shift_count", 0)
        except (json.JSONDecodeError, TypeError):
            self.entries = []


if __name__ == "__main__":
    a = MemoryArchive()
    for t in ["帮我写一段爬虫代码抓取新闻", "爬虫代码写好了吗", "给我写一篇关于夏天的小说开头"]:
        print(f"{t}  ->  {a.detect_topic_shift(t)}")
        a.add(t)
    print(json.dumps(a.stats(), ensure_ascii=False))
