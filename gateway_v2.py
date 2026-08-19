#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gateway_v2.py —— L1-L5 五层网关（V2 主网关）

  L1 意图识别  ：关键词分类（coding / writing / analysis / fiction / other）
  L2 Skill 推荐：按意图推荐技能（只推荐不决定，零误判）
  L3 模型调用  ：模型适配层（回调 或 OpenAI 兼容 HTTP API）
  L4 本能守门  ：InstinctGuard 8 条规则检测输出合规性
  L5 反馈飞轮  ：违规数据自动收集（JSONL），用于 SFT 微调

与 execution_layer.py 的契约：
    from gateway_v2 import WordGateway, GuardViolation, Intent
    gateway = WordGateway(config)
    gateway.guard.check(text)                        -> GuardResult
    gateway.flywheel.log_violation(intent, out, rule) -> None
    intent = Intent(raw_input=user_input)
"""

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


# ============================================================
# L1 意图识别
# ============================================================

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

INTENT_LABELS = {
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


# ============================================================
# L2 Skill 推荐
# ============================================================

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


# ============================================================
# L3 模型调用
# ============================================================

class ModelAdapter:
    """L3 模型调用：优先 callback，其次 OpenAI 兼容 HTTP API"""

    def __init__(self, callback: Optional[Callable] = None,
                 base_url: Optional[str] = None, api_key: Optional[str] = None,
                 model: Optional[str] = None, timeout: int = 60) -> None:
        self.callback = callback
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        if self.callback is not None:
            return str(self.callback(prompt, system))
        if self.base_url:
            return self._generate_http(prompt, system)
        raise RuntimeError(
            "L3 未接入模型：请提供 model_callback 或 base_url+api_key（OpenAI 兼容接口）"
        )

    def _generate_http(self, prompt: str, system: Optional[str]) -> str:
        try:
            import requests
        except ImportError as e:
            raise RuntimeError("L3 HTTP 调用需要 requests 库") from e
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = requests.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model or "default", "messages": messages},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    @property
    def available(self) -> bool:
        return self.callback is not None or bool(self.base_url)


# ============================================================
# L4 本能守门（InstinctGuard，8 条规则）
# ============================================================

@dataclass
class GuardResult:
    passed: bool
    failed_rule: str = ""
    action: str = ""          # block / warn
    details: str = ""
    checked_rules: Dict[str, bool] = field(default_factory=dict)


class GuardViolation(Exception):
    """守门违规异常"""

    def __init__(self, rule: str, action: str = "block", details: str = "") -> None:
        self.rule = rule
        self.action = action
        self.details = details
        super().__init__(f"守门违规: {rule} ({action}) {details}")


SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|passw(or)?d|pwd|access[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*['\"][^'\"]{8,}['\"]"
)
SECRET_PLACEHOLDERS = {"xxx", "changeme", "your-secret", "your_token",
                       "your_secret", "your-api-key", "<your-api-key>", "sk-xxx",
                       "replace-me", "password", "yourpassword", "testpass",
                       "secret", "123456", "12345678", "00000000", "abcdefgh",
                       "example", "placeholder"}

SQL_CONCAT_RE = re.compile(
    r"(?i)(select|insert|update|delete)\b.{0,120}?(\+\s*['\"]|['\"]\s*\+|\bf['\"]|\{[\w_]+\})",
    re.DOTALL,
)
SQL_TAUTOLOGY_RE = re.compile(r"(?i)['\"]\s*or\s*'1'\s*=\s*'1")

FENCE_RE = re.compile(r"```")


class InstinctGuard:
    """L4 本能守门：8 条规则自动检测输出合规性"""

    RULE_NAMES = (
        "type_hints",            # 函数必须有类型注解
        "try_except",            # IO 操作必须包异常处理
        "no_hardcoded_secrets",  # 禁止硬编码密钥
        "no_sql_injection",      # 禁止字符串拼接 SQL
        "markdown_clean",        # Markdown 格式规范
        "no_infinite_recursion", # 禁止无限递归
        "no_unused_import",      # 禁止未使用的导入
        "v1_ast_check",          # AST 行为检测（桥接 V1）
    )

    BLOCK_RULES = {"no_hardcoded_secrets", "no_sql_injection",
                   "no_infinite_recursion", "v1_ast_check"}

    # 代码风格规则：只对生成/写入的代码输出生效，读文件/最终回复跳过（防误拦）
    CODE_RULES = {"type_hints", "try_except", "no_infinite_recursion",
                  "no_unused_import", "v1_ast_check"}

    RULE_DESCRIPTIONS = {
        "type_hints": "函数缺少类型注解",
        "try_except": "IO 操作缺少异常处理",
        "no_hardcoded_secrets": "输出中包含硬编码密钥",
        "no_sql_injection": "输出中存在 SQL 拼接风险",
        "markdown_clean": "Markdown 代码围栏不配对",
        "no_infinite_recursion": "代码中存在自递归调用",
        "no_unused_import": "存在未使用的导入",
        "v1_ast_check": "AST 行为检测未通过",
    }

    def __init__(self, config: Optional[Dict] = None) -> None:
        self.config = config or {}
        self.enabled = {r: bool(self.config.get("rules", {}).get(r, True))
                        for r in self.RULE_NAMES}
        self._ast_detector = None
        try:
            from work import ASTDetector
            self._ast_detector = ASTDetector()
        except ImportError:
            self._ast_detector = None

    def check(self, text: str, code_rules: bool = True) -> GuardResult:
        text = text or ""
        checked: Dict[str, bool] = {}
        for rule in self.RULE_NAMES:
            if not self.enabled[rule]:
                continue
            if rule in self.CODE_RULES and not code_rules:
                continue   # 非代码输出跳过代码风格规则
            ok = self._check_rule(rule, text)
            checked[rule] = ok
            if not ok:
                action = "block" if rule in self.BLOCK_RULES else "warn"
                return GuardResult(False, rule, action,
                                   self.RULE_DESCRIPTIONS.get(rule, rule), checked)
        return GuardResult(True, "", "", "", checked)

    def _check_rule(self, rule: str, text: str) -> bool:
        return {
            "type_hints": self._type_hints_ok,
            "try_except": self._try_except_ok,
            "no_hardcoded_secrets": self._no_secrets_ok,
            "no_sql_injection": self._no_sql_ok,
            "markdown_clean": self._markdown_ok,
            "no_infinite_recursion": self._no_recursion_ok,
            "no_unused_import": self._no_unused_import_ok,
            "v1_ast_check": self._ast_ok,
        }[rule](text)

    @staticmethod
    def _looks_like_code(t: str) -> bool:
        return bool(re.search(r"\bdef\s+\w+\s*\(|\bimport\s+\w+|\bclass\s+\w+", t))

    def _type_hints_ok(self, t: str) -> bool:
        if "def " not in t:
            return True
        unannotated = re.findall(r"\bdef\s+\w+\s*\([^)]*\)\s*:", t)
        return not unannotated

    def _try_except_ok(self, t: str) -> bool:
        has_io = bool(re.search(r"\b(open|requests\.(get|post)|subprocess\.|socket\.)\b", t)) \
            or bool(re.search(r"\.(read|write|execute)\(", t))
        if not has_io:
            return True
        return "try" in t and "except" in t

    def _no_secrets_ok(self, t: str) -> bool:
        for m in SECRET_RE.finditer(t):
            value = m.group(0).split("=", 1)[-1].strip().strip("\"'")
            if value.lower() not in SECRET_PLACEHOLDERS and len(value) >= 8:
                return False
        return True

    def _no_sql_ok(self, t: str) -> bool:
        return not (SQL_CONCAT_RE.search(t) or SQL_TAUTOLOGY_RE.search(t))

    def _markdown_ok(self, t: str) -> bool:
        return len(FENCE_RE.findall(t)) % 2 == 0

    def _no_recursion_ok(self, t: str) -> bool:
        if not self._looks_like_code(t):
            return True
        for name in re.findall(r"\bdef\s+(\w+)\s*\(", t):
            # 仅当函数体就是单条自调用 return 时判定为无限递归
            # （正常递归如 fib/DFS 有终止分支，放行，避免误伤）
            if re.search(rf"def\s+{name}\s*\([^)]*\)\s*:\s*\n\s*return\s+{name}\s*\(", t):
                return False
        return True

    def _no_unused_import_ok(self, t: str) -> bool:
        if not self._looks_like_code(t):
            return True
        imports = re.findall(r"^import\s+([\w.]+)", t, re.M)
        imports += [x.strip() for line in
                    re.findall(r"^from\s+[\w.]+\s+import\s+(.+)$", t, re.M)
                    for x in line.split(",")]
        for imp in imports:
            name = imp.split(" as ")[-1].strip()
            if name and name != "*" and not name.startswith("_"):
                if len(re.findall(rf"\b{re.escape(name)}\b", t)) <= 1:
                    return False
        return True

    def _ast_ok(self, t: str) -> bool:
        if not self._looks_like_code(t):
            return True
        if self._ast_detector is None:
            return True
        report = self._ast_detector.check_all(t)
        return all(report.values())


# ============================================================
# L5 反馈飞轮
# ============================================================

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


# ============================================================
# 五层网关主入口
# ============================================================

class WordGateway:
    """L1-L5 五层网关"""

    def __init__(self, config: Optional[Dict] = None) -> None:
        self.config = config or {}
        self.skills = SkillRecommender(self.config.get("skills"))
        self.model = ModelAdapter(
            callback=self.config.get("model_callback"),
            base_url=self.config.get("base_url"),
            api_key=self.config.get("api_key"),
            model=self.config.get("model"),
        )
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
            "l3_model_available": self.model.available,
            "l4_rules": self.enabled_rules(),
            "l5_flywheel": self.flywheel.stats(),
        }

    def enabled_rules(self) -> List[str]:
        return [r for r, on in self.guard.enabled.items() if on]


if __name__ == "__main__":
    gw = WordGateway({})
    print(json.dumps(gw.route("帮我写一段 python 代码处理数据"),
                     ensure_ascii=False, indent=2))
    r = gw.guard.check('api_key = "abcdef1234567890"')
    print("守门测试:", r)
