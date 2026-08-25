#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gateway_v2.flywheel —— L5 反馈飞轮

违规数据自动收集（JSONL），用于 SFT 微调。
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from gateway_v2.intent import Intent


class Flywheel:
    """L5 反馈飞轮：违规数据自动收集（JSONL），用于 SFT 微调"""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._counts: Dict[str, int] = {}

    def log_violation(self, intent: Any, output_text: str, rule: str,
                      extra: Optional[Dict] = None) -> None:
        record = {
            "ts": time.time(),
            "datetime": time.strftime("%Y-%m-%d %H:%M:%S"),
            "intent": intent.to_dict() if isinstance(intent, Intent) else str(intent),
            "rule": rule,
            "output_snippet": (output_text or "")[:500],
            "extra": extra or {},
        }
        self._counts[rule] = self._counts.get(rule, 0) + 1
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def log_event(self, event: str, detail: Optional[Dict] = None) -> None:
        record = {"ts": time.time(),
                  "datetime": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "event": event, "detail": detail or {}}
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def stats(self) -> Dict[str, Any]:
        return {"violations": dict(self._counts),
                "total": sum(self._counts.values()),
                "path": str(self.path) if self.path else None}

    def export_for_sft(self) -> List[Dict[str, str]]:
        """导出违规样本，供 SFT 微调（坏样例：原始输出 → 违规规则说明）"""
        if not self.path or not self.path.exists():
            return []
        samples: List[Dict[str, str]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            samples.append({
                "prompt": rec.get("output_snippet", ""),
                "completion": f"该输出违反了规则 {rec.get('rule')}，已被守门拦截。",
                "rule": rec.get("rule", ""),
            })
        return samples
