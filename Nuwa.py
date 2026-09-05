#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nuwa.py —— POC 报告生成器（HTML + JSON 双格式）

契约（execution_layer.py）：
    from Nuwa import POCGenerator
    nuwa = POCGenerator()
    nuwa.add_metric(category, name, value, status)   # status: pass / fail / warn / info
    nuwa.add_rollback(reason)
    nuwa.title = "..."
    report = nuwa.generate_report()                  # report.html_path / report.json_path
"""

import html
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class POCReport:
    title: str
    html_path: str
    json_path: str
    generated_at: str
    summary: Dict[str, Any]


class POCGenerator:
    """POC 指标采集 + 报告生成"""

    def __init__(self, output_dir: str = ".poc_reports",
                 title: str = "Agent 执行层 POC 报告") -> None:
        self.output_dir = Path(output_dir)
        self.title = title
        self.metrics: List[Dict[str, Any]] = []
        self.rollback_count = 0

    # ---------- 指标采集 ----------

    def add_metric(self, category: str, name: str, value: Any,
                   status: str = "info") -> None:
        """记录一条指标。
        工具执行类指标用 value 表达结果（pass/fail），status 仅作展示修饰。"""
        self.metrics.append({
            "ts": time.time(),
            "category": category,
            "name": name,
            "value": str(value),
            "status": status,
        })

    def add_rollback(self, reason: str = "") -> None:
        self.rollback_count += 1
        self.add_metric("安全回滚", f"回滚 #{self.rollback_count}",
                        reason or "快照回滚", "warn")

    # ---------- 聚合 ----------

    def _aggregate(self) -> Dict[str, Any]:
        total_exec = 0
        passed = 0
        resp_times: List[float] = []
        by_category: Dict[str, Dict[str, int]] = {}
        for m in self.metrics:
            cat = m["category"]
            if cat == "响应时间":
                nums = re.findall(r"\d+(?:\.\d+)?", m["value"])
                if nums:
                    resp_times.append(float(nums[0]))
                continue
            c = by_category.setdefault(cat, {"total": 0, "pass": 0})
            c["total"] += 1
            if m["value"] == "pass" or m["status"] == "pass":
                c["pass"] += 1
            if cat == "工具执行":
                total_exec = c["total"]
                passed = c["pass"]
        pass_rate = round(passed / total_exec * 100, 1) if total_exec else 0.0
        avg_resp = round(sum(resp_times) / len(resp_times), 3) if resp_times else 0.0
        return {
            "title": self.title,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "metric_count": len(self.metrics),
            "tool_executions": total_exec,
            "pass_rate_pct": pass_rate,
            "avg_response_s": avg_resp,
            "rollback_count": self.rollback_count,
            "by_category": by_category,
        }

    # ---------- 报告生成 ----------

    def generate_report(self) -> POCReport:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        summary = self._aggregate()
        stamp = time.strftime("%Y%m%d_%H%M%S")
        json_path = self.output_dir / f"poc_report_{stamp}.json"
        html_path = self.output_dir / f"poc_report_{stamp}.html"
        json_path.write_text(
            json.dumps({"summary": summary, "metrics": self.metrics},
                       ensure_ascii=False, indent=2),
            encoding="utf-8")
        html_path.write_text(self._render_html(summary), encoding="utf-8")
        return POCReport(
            title=self.title,
            html_path=str(html_path),
            json_path=str(json_path),
            generated_at=summary["generated_at"],
            summary=summary,
        )

    def _render_html(self, s: Dict[str, Any]) -> str:
        rows = "\n".join(
            f"<tr><td>{html.escape(m['category'])}</td>"
            f"<td>{html.escape(m['name'])}</td>"
            f"<td>{html.escape(m['value'])}</td>"
            f"<td>{html.escape(m['status'])}</td></tr>"
            for m in self.metrics[-200:]
        )
        return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>{html.escape(s['title'])}</title>
<style>
 body {{ font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; margin: 24px; color: #1f2937; background: #f5f7fa; }}
 h1 {{ font-size: 22px; }}
 .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }}
 .card {{ background: #fff; border-radius: 10px; padding: 14px 18px; min-width: 150px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
 .card .v {{ font-size: 24px; font-weight: 700; }}
 .card .k {{ font-size: 12px; color: #6b7280; }}
 table {{ border-collapse: collapse; width: 100%; background: #fff; border-radius: 10px; overflow: hidden; }}
 th, td {{ border-bottom: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; font-size: 13px; }}
 th {{ background: #eef2f7; }}
 .ok {{ color: #16a34a; }} .warn {{ color: #d97706; }}
</style></head><body>
<h1>{html.escape(s['title'])}</h1>
<p style="color:#6b7280;">生成时间：{html.escape(s['generated_at'])}</p>
<div class="cards">
 <div class="card"><div class="k">工具执行数</div><div class="v">{s['tool_executions']}</div></div>
 <div class="card"><div class="k">通过率</div><div class="v ok">{s['pass_rate_pct']}%</div></div>
 <div class="card"><div class="k">平均响应</div><div class="v">{s['avg_response_s']}s</div></div>
 <div class="card"><div class="k">回滚次数</div><div class="v warn">{s['rollback_count']}</div></div>
 <div class="card"><div class="k">指标总数</div><div class="v">{s['metric_count']}</div></div>
</div>
<h2>指标明细（最近 200 条）</h2>
<table><tr><th>类别</th><th>名称</th><th>值</th><th>状态</th></tr>{rows}</table>
</body></html>"""


if __name__ == "__main__":
    n = POCGenerator(title="演示报告")
    n.add_metric("工具执行", "demo", "pass")
    n.add_metric("响应时间", "0.05s", "info")
    n.add_rollback("演示回滚")
    r = n.generate_report()
    print(f"HTML: {r.html_path}")
    print(f"JSON: {r.json_path}")
