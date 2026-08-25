#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
work.py —— V1 行为约束：诱饵工厂（BaitFactory）+ AST 行为检测（ASTDetector）

契约（execution_layer.py）：
    from work import BehaviorConstraint, BaitFactory, ASTDetector

    bait_factory = BaitFactory()
    baited_code, bait_meta = bait_factory.inject_bait(code)   # 注入语义诱饵
    fixed, reason = bait_factory.verify_fixed(code, bait_meta)  # 验证诱饵是否被修复

    report = ASTDetector().check_all(code)  # {rule: bool}，True = 通过
"""

import ast
import json
import random
import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


# ============================================================
# 诱饵工厂（BaitFactory）
# ============================================================

BAIT_TYPES = ("unused_import", "type_mismatch", "circular_ref",
              "infinite_recursion", "missing_return")

BAIT_DESCRIPTIONS = {
    "unused_import": "注入了一个从未使用的 import 语句",
    "type_mismatch": "注入了一个类型注解与赋值不匹配的变量",
    "circular_ref": "注入了一个自引用的数据结构（循环引用）",
    "infinite_recursion": "注入了一个直接调用自身的无限递归函数",
    "missing_return": "注入了一个声明了返回类型却没有 return 的函数",
}

BAIT_SNIPPETS = {
    "unused_import": "import _bait_unused_placeholder_module_xyz\n",
    "type_mismatch": '_bait_var: int = "bait-type-mismatch-string"\n',
    "circular_ref": "_bait_list = []\n_bait_list.append(_bait_list)\n",
    "infinite_recursion": "def _bait_infinite_rec():\n    return _bait_infinite_rec()\n",
    "missing_return": "def _bait_missing_return() -> int:\n    pass\n",
}


@dataclass
class BaitMeta:
    id: str
    type: str
    description: str
    snippet: str
    marker: str = "_bait_"

    def to_dict(self) -> Dict[str, str]:
        return {
            "id": self.id,
            "type": self.type,
            "description": self.description,
            "snippet": self.snippet,
            "marker": self.marker,
        }


class BaitFactory:
    """语义诱饵工厂：向代码注入可识别的语义缺陷，验证 Agent 能否识别并修复"""

    def __init__(self, seed: Optional[int] = None,
                 enabled_types: Optional[Tuple[str, ...]] = None) -> None:
        self._rng = random.Random(seed)
        self.enabled_types = tuple(enabled_types or BAIT_TYPES)

    def inject_bait(self, code: str, bait_type: Optional[str] = None) -> Tuple[str, BaitMeta]:
        """向代码顶部注入一个语义诱饵，返回 (注入后的代码, 诱饵元信息)"""
        type_ = bait_type or self._rng.choice(self.enabled_types)
        if type_ not in BAIT_SNIPPETS:
            raise ValueError(f"未知诱饵类型: {type_}，可选: {BAIT_TYPES}")
        meta = BaitMeta(
            id=uuid.uuid4().hex[:8],
            type=type_,
            description=BAIT_DESCRIPTIONS[type_],
            snippet=BAIT_SNIPPETS[type_].rstrip("\n"),
        )
        baited = BAIT_SNIPPETS[type_] + "\n" + (code or "")
        return baited, meta

    def verify_fixed(self, code: str, bait_meta: BaitMeta) -> Tuple[bool, str]:
        """验证 Agent 是否已修复诱饵：新代码中不能残留诱饵特征"""
        code = code or ""
        if bait_meta.marker in code:
            return False, f"代码中仍残留诱饵特征（{bait_meta.marker}），诱饵类型: {bait_meta.type}"
        type_specific = {
            "unused_import": "_bait_unused",
            "type_mismatch": "_bait_var",
            "circular_ref": "_bait_list",
            "infinite_recursion": "_bait_infinite_rec",
            "missing_return": "_bait_missing_return",
        }
        fragment = type_specific.get(bait_meta.type, bait_meta.marker)
        if fragment in code:
            return False, f"{bait_meta.type} 诱饵仍存在，请移除后重新提交"
        return True, "诱饵已修复"


# ============================================================
# AST 行为检测器（ASTDetector）
# ============================================================

SECRET_NAME_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|passw(or)?d|pwd|access[_-]?key|private[_-]?key)"
)
SECRET_PLACEHOLDERS = {"", "xxx", "changeme", "your-secret", "your_token",
                       "your_secret", "your-api-key", "<your-api-key>", "sk-xxx",
                       "replace-me", "password", "yourpassword", "testpass",
                       "secret", "123456", "12345678", "00000000", "abcdefgh",
                       "<token>", "...", "example", "placeholder", "null", "none"}
SQL_KEYWORD_RE = re.compile(r"(?i)\b(select|insert|update|delete|drop|create|alter)\b")


class ASTDetector:
    """AST 行为检测器：check_all(code) -> {rule: bool}，True = 通过"""

    RULES = ("unused_import", "type_hints", "infinite_recursion",
             "circular_ref", "hardcoded_secrets", "sql_injection")

    def __init__(self) -> None:
        self.last_error = ""

    def _parse(self, code: str) -> Optional[ast.AST]:
        try:
            return ast.parse(code or "")
        except SyntaxError as e:
            self.last_error = f"语法错误: {e.msg} (行 {e.lineno})"
            return None

    def check_all(self, code: str) -> Dict[str, bool]:
        tree = self._parse(code)
        if tree is None:
            return {r: False for r in self.RULES}
        return {r: self._check(tree, r) for r in self.RULES}

    def check_rule(self, code: str, rule: str) -> bool:
        tree = self._parse(code)
        return tree is not None and self._check(tree, rule)

    def _check(self, tree: ast.AST, rule: str) -> bool:
        return {
            "unused_import": self._unused_import_ok,
            "type_hints": self._type_hints_ok,
            "infinite_recursion": self._infinite_recursion_ok,
            "circular_ref": self._circular_ref_ok,
            "hardcoded_secrets": self._secrets_ok,
            "sql_injection": self._sql_ok,
        }[rule](tree)

    # ---------- 规则实现 ----------

    def _unused_import_ok(self, tree: ast.AST) -> bool:
        imported: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    if name != "*":
                        imported.add(name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    imported.add(alias.asname or alias.name)
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        return not (imported - used)

    def _type_hints_ok(self, tree: ast.AST) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue
                if node.returns is None:
                    return False
                for arg in node.args.args:
                    if arg.arg in ("self", "cls"):
                        continue
                    if arg.annotation is None:
                        return False
        return True

    def _call_graph(self, tree: ast.AST) -> Dict[str, Set[str]]:
        """构建函数调用图：函数名 -> 其内部调用的函数名集合"""
        calls: Dict[str, Set[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names: Set[str] = set()
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        f = sub.func
                        if isinstance(f, ast.Name):
                            names.add(f.id)
                        elif isinstance(f, ast.Attribute):
                            names.add(f.attr)
                calls[node.name] = names
        return calls

    def _func_nodes(self, tree: ast.AST) -> Dict[str, ast.AST]:
        return {n.name: n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    @staticmethod
    def _body_is_bare_call(func: ast.AST, name: Optional[str] = None) -> bool:
        """函数体仅由一条调用语句组成（无终止分支）；name 给定时要求调用自身"""
        body = [s for s in func.body if not isinstance(s, ast.Pass)]
        if len(body) != 1:
            return False
        stmt = body[0]
        call = None
        if isinstance(stmt, ast.Return):
            call = stmt.value
        elif isinstance(stmt, ast.Expr):
            call = stmt.value
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
            return False
        if name is not None:
            return call.func.id == name
        return True

    def _infinite_recursion_ok(self, tree: ast.AST) -> bool:
        # 仅拦截"函数体就是单条自调用"的明显无限递归；
        # 正常递归（fib/DFS，含终止分支）放行，避免系统性误报
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._body_is_bare_call(node, name=node.name):
                    return False
        return True

    def _circular_ref_ok(self, tree: ast.AST) -> bool:
        # 仅拦截"环内每个函数体都是单条调用语句"的互递归死循环；
        # 有终止分支的合法互递归（is_even/is_odd、递归下降解析器）放行
        graph = self._call_graph(tree)
        funcs = self._func_nodes(tree)
        bare = {n: self._body_is_bare_call(f) for n, f in funcs.items()}
        WHITE, GRAY, BLACK = 0, 1, 2
        color: Dict[str, int] = {n: WHITE for n in graph}
        stack_path: List[str] = []

        def dfs(n: str) -> bool:
            color[n] = GRAY
            stack_path.append(n)
            for m in graph[n]:
                if m not in color:
                    continue
                if color[m] == GRAY and m != n:
                    cycle = stack_path[stack_path.index(m):]
                    if all(bare.get(c, False) for c in cycle):
                        return False
                if color[m] == WHITE:
                    if not dfs(m):
                        return False
            stack_path.pop()
            color[n] = BLACK
            return True

        for n in list(graph):
            if color[n] == WHITE and not dfs(n):
                return False
        return True

    def _secrets_ok(self, tree: ast.AST) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name) and SECRET_NAME_RE.search(t.id):
                        val = node.value
                        if isinstance(val, ast.Constant) and isinstance(val.value, str):
                            if len(val.value) >= 8 and val.value.strip().lower() not in SECRET_PLACEHOLDERS:
                                return False
        return True

    def _contains_sql_const(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                    and SQL_KEYWORD_RE.search(sub.value):
                return True
        return False

    @staticmethod
    def _has_dynamic_operand(node: ast.AST) -> bool:
        """拼接表达式中是否存在非常量操作数（变量/调用/属性）"""
        for sub in ast.walk(node):
            if isinstance(sub, (ast.Name, ast.Call, ast.Attribute, ast.Subscript)):
                return True
        return False

    def _sql_ok(self, tree: ast.AST) -> bool:
        for node in ast.walk(tree):
            # execute/executemany 的参数存在拼接 → 真实注入场景
            if isinstance(node, ast.Call):
                f = node.func
                fname = f.attr if isinstance(f, ast.Attribute) else (
                    f.id if isinstance(f, ast.Name) else "")
                if fname in ("execute", "executemany"):
                    for arg in node.args:
                        if isinstance(arg, (ast.BinOp, ast.JoinedStr)) or (
                                isinstance(arg, ast.Call)
                                and isinstance(arg.func, ast.Attribute)
                                and arg.func.attr == "format"):
                            return False
            # SQL 关键字 + 变量拼接（如 "SELECT ..." + uid）
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) \
                    and self._contains_sql_const(node) \
                    and self._has_dynamic_operand(node):
                return False
            # f-string 含插值变量且含 SQL 关键字（如 f"SELECT ... {uid}"）
            if isinstance(node, ast.JoinedStr) and self._contains_sql_const(node) \
                    and any(isinstance(v, ast.FormattedValue) for v in node.values):
                return False
        return True


# ============================================================
# V1 行为约束桥接
# ============================================================

class BehaviorConstraint:
    """V1 行为约束桥接：一键校验全部规则，返回违规清单"""

    RULE_DESCRIPTIONS = {
        "unused_import": "未使用导入",
        "type_hints": "函数缺少类型注解",
        "infinite_recursion": "无限递归",
        "circular_ref": "循环引用",
        "hardcoded_secrets": "硬编码密钥",
        "sql_injection": "SQL 注入风险",
    }

    def __init__(self) -> None:
        self.detector = ASTDetector()

    def validate(self, code: str) -> Dict[str, Any]:
        report = self.detector.check_all(code)
        failed = [r for r, ok in report.items() if not ok]
        return {
            "passed": not failed,
            "failed": failed,
            "report": report,
            "descriptions": {r: self.RULE_DESCRIPTIONS[r] for r in failed},
        }


if __name__ == "__main__":
    ad = ASTDetector()
    bad_code = "import unused_xyz\n\ndef f(x):\n    return x + 1\n"
    print(json.dumps(ad.check_all(bad_code), ensure_ascii=False, indent=2))
    bf = BaitFactory(seed=1)
    baited, meta = bf.inject_bait("print(1)")
    print(baited)
    print(json.dumps(meta.to_dict(), ensure_ascii=False))
    print("verify_fixed(print(1)) ->", bf.verify_fixed("print(1)", meta))
