#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gateway_v2.guard —— L4 本能守门（InstinctGuard，8 条规则）

  block 级：no_hardcoded_secrets / no_sql_injection / no_infinite_recursion / v1_ast_check
  warn 级：type_hints / try_except / markdown_clean / no_unused_import
"""

import re
from dataclasses import dataclass, field
from typing import Dict, Optional

SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|passw(or)?d|pwd|access[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*"
    r"(?:['\"]([^'\"]{8,})['\"]|([A-Za-z0-9_\-./]{8,}))"
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


class InstinctGuard:
    """L4 本能守门：8 条规则自动检测输出合规性"""

    # v1_ast_check 桥接时只要求安全规则通过；风格规则（类型注解/未用导入）不阻塞
    AST_SAFETY_RULES = {"hardcoded_secrets", "sql_injection",
                        "infinite_recursion", "circular_ref"}

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
            # 仅当函数体就是单行自调用 return 时判定为无限递归
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
        return all(v for k, v in report.items() if k in self.AST_SAFETY_RULES)
