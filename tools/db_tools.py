#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.db_tools —— SQLite 工具（db_query / db_write）

安全口径：**正则不是边界，连接才是。**

db_query 的只读性由 `?mode=ro` 这个连接级开关保证，不靠"以 SELECT 开头"这条正则。
理由很直接：SQL 是一门完整语言，`CREATE TRIGGER`、`INSERT ... SELECT`、CTE 包一层写入、
`pragma_table_list` 这类表值函数……前缀匹配挡不住的写法列不完，而 SQLite 自己就有一个
真正的只读模式。正则留着，但它的职责降级成"给模型一个能读懂的报错"，不是安全闸门。

db_write 天生要写，拿不到连接级保护，所以那边仍然是黑名单 —— 并且明确承认它不闭合，
只挡已知的高危写法（DROP / ATTACH / PRAGMA / 触发器 / 改 sqlite_master / 多语句）。
"""

import re
import sqlite3
from typing import Dict, Optional

from tools.result import ExecutionResult

# 只读连接也挡不住的构造：ATTACH/DETACH 会把别的**文件**挂进来（mode=ro 只管当前库），
# load_extension 是加载本地 .so/.dll，writable_schema 是绕过 schema 保护的开关。
# 这三类与"能不能写当前库"无关，所以两条路都要挡。
_ESCAPE_SQL_RE = re.compile(
    r"(?i)(\b(attach|detach|load_extension)\b|\bwritable_schema\b)")

# 只有 db_write 才需要挡的写入构造。注意 `pragma` 后面跟 `_` 时 `\b` 不成立
# （`_` 是单词字符），所以 `pragma_table_list` 这种表值函数写法必须单独列出，
# 否则 `\bpragma\b` 形同虚设。触发器是"存起来以后再写"的写入原语，同样要挡。
_WRITE_DANGER_SQL_RE = re.compile(
    r"(?i)(\b(drop|pragma|vacuum|reindex)\b"
    r"|\bpragma_\w+"
    r"|\bcreate\s+(temp\s+|temporary\s+)?trigger\b"
    r"|\bsqlite_master\b|\bsqlite_schema\b)")

_DB_ROW_LIMIT = 100



def _strip_sql_comments(sql: str) -> str:
    """去掉 -- 行注释与 /* */ 块注释，供"语句里有没有分号"这类结构判断使用。

    不做词法分析：字符串字面量里的 `--` 会被误当注释。这个方向是安全的 ——
    误判只会让判断更保守（多认出一个"注释"从而少看见内容），不会放过东西。
    """
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    return re.sub(r"--[^\n]*", " ", sql)


def _multi_statement(sql: str) -> bool:
    """去掉注释与尾分号之后还剩分号 → 多语句。

    不能指望驱动兜着：`cur.execute` 拒绝多语句时抛的是 `sqlite3.Warning`，
    而 `sqlite3.Warning` **不是** `sqlite3.Error` 的子类，会穿过 `except sqlite3.Error`
    一路冒到通用兜底那里变成 500 —— 一个"你写错了"的问题被报成"服务端炸了"。
    """
    return ";" in _strip_sql_comments(sql).strip().rstrip(";")


class DbTools:
    def _db_path(self):
        return self.project_root / "agent.db"

    @staticmethod
    def _screen_sql(query: str, readonly: bool) -> Optional[str]:
        """结构性筛查：命中返回拒绝原因，通过返回 None。

        `readonly=True` 时只挡"连只读连接都拦不住"的那三类（ATTACH / load_extension /
        writable_schema）。**不**挡 `sqlite_master` 与 `pragma_*` —— 在 mode=ro 连接上
        读 schema 是正当且必要的（模型得知道有哪些表），挡掉只会让它去猜表名。
        """
        if _multi_statement(query):
            return "一次只允许一条 SQL 语句（检测到分号分隔的多语句）"
        m = _ESCAPE_SQL_RE.search(query)
        if m:
            return (f"拒绝危险 SQL 构造: {m.group(0).strip()}"
                    "（ATTACH/DETACH 会挂载其他数据库文件，load_extension 会加载本地库，"
                    "writable_schema 绕过 schema 保护 —— 只读连接也管不住这三类）")
        if readonly:
            return None
        m = _WRITE_DANGER_SQL_RE.search(query)
        if m:
            return (f"拒绝危险 SQL 构造: {m.group(0).strip()}"
                    "（DROP / PRAGMA / VACUUM / 触发器 / 直接改 sqlite_master 一律不放行）")
        return None


    def _exec_db_query(self, params: Dict) -> ExecutionResult:
        """SQLite 只读查询。只读由连接级 mode=ro 保证，正则只负责给出可读的报错。"""
        query = str(params.get("query", "")).strip()
        if not query:
            return ExecutionResult(status="error", error_code="400", message="query 参数为空")
        m = re.match(r"(?is)^\s*(select|with)\b", query)
        if not m:
            return ExecutionResult(status="error", error_code="403",
                                   message="db_query 仅允许只读查询（SELECT/WITH）")
        screen = self._screen_sql(query, readonly=True)
        if screen:
            return ExecutionResult(status="error", error_code="403", message=screen)
        db_path = self._db_path()
        if not db_path.exists():
            # mode=ro 不会建库，所以"库不存在"要自己答 404。
            # 反过来说这也是好事：只读查询不该顺手创建一个空库出来。
            return ExecutionResult(status="error", error_code="404",
                                   message=f"数据库不存在: {db_path}（先用 db_write 建表）")

        try:
            # mode=ro：真正的只读连接。任何写入尝试由 SQLite 自己拒绝，
            # 不依赖上面那条正则看懂这句 SQL 到底会不会写。
            conn = sqlite3.connect(f"{db_path.as_uri()}?mode=ro", uri=True, timeout=5)
            try:
                cur = conn.cursor()
                cur.execute(query)
                fetched = cur.fetchmany(_DB_ROW_LIMIT + 1)
                columns = [d[0] for d in cur.description] if cur.description else []
            finally:
                conn.close()
        except (sqlite3.Error, sqlite3.Warning) as e:
            return ExecutionResult(status="error", error_code="400", message=f"查询失败: {e}")
        truncated = len(fetched) > _DB_ROW_LIMIT
        rows = [list(r) for r in fetched[:_DB_ROW_LIMIT]]
        return ExecutionResult(status="success", data={
            "columns": columns, "rows": rows,
            "row_count": len(rows), "truncated": truncated, "db": str(db_path),
            "readonly": True,
        })

    def _exec_db_write(self, params: Dict) -> ExecutionResult:
        """SQLite 写入（INSERT/UPDATE/DELETE/REPLACE/CREATE/ALTER），危险构造拒绝。

        这里没有连接级保护可用 —— 它的工作就是写。所以这条路是黑名单，
        并且**不闭合**：`DELETE FROM t`（无 WHERE）、`REPLACE INTO`、
        `CREATE TABLE x AS SELECT` 都在放行范围内。真正的边界是权限档位
        （db_write 属于 PERM_WRITE）和 Guardian 快照，不是这几条正则。
        """
        query = str(params.get("query", "")).strip()
        if not query:
            return ExecutionResult(status="error", error_code="400", message="query 参数为空")
        if re.match(r"(?is)^\s*(select|with)\b", query):
            return ExecutionResult(status="error", error_code="400",
                                   message="只读查询请使用 db_query 工具")
        screen = self._screen_sql(query, readonly=False)

        if screen:
            return ExecutionResult(status="error", error_code="403", message=screen)
        if not re.match(r"(?is)^\s*(insert|update|delete|replace|create|alter)\b", query):
            return ExecutionResult(status="error", error_code="400",
                                   message="不支持的语句类型（支持 INSERT/UPDATE/DELETE/REPLACE/CREATE/ALTER）")
        db_path = self._db_path()
        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            try:
                cur = conn.cursor()
                cur.execute(query)
                conn.commit()
                affected = cur.rowcount
            finally:
                conn.close()
        except (sqlite3.Error, sqlite3.Warning) as e:
            return ExecutionResult(status="error", error_code="400", message=f"写入失败: {e}")
        return ExecutionResult(status="success", data={
            "affected_rows": affected, "db": str(db_path)})
