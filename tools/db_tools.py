#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.db_tools —— SQLite 工具（db_query / db_write）"""

import re
import sqlite3
from typing import Any, Dict

from tools.result import ExecutionResult


class DbTools:
    def _exec_db_query(self, params: Dict) -> ExecutionResult:
        """SQLite 只读查询（仅 SELECT/WITH），返回列名+行数据，上限 100 行"""
        query = str(params.get("query", "")).strip()
        if not query:
            return ExecutionResult(status="error", error_code="400", message="query 参数为空")
        m = re.match(r"(?is)^\s*(select|with)\b", query)
        if not m:
            return ExecutionResult(status="error", error_code="403",
                                   message="db_query 仅允许只读查询（SELECT/WITH）")
        if m.group(1).lower() == "with" and not re.search(r"(?is)\bselect\b", query):
            return ExecutionResult(status="error", error_code="403",
                                   message="db_query 的 WITH 必须包含 SELECT（禁止借道写入）")
        import sqlite3
        db_path = self.project_root / "agent.db"
        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            try:
                cur = conn.cursor()
                cur.execute(query)
                fetched = cur.fetchmany(101)
                columns = [d[0] for d in cur.description] if cur.description else []
            finally:
                conn.close()
        except sqlite3.Error as e:
            return ExecutionResult(status="error", error_code="400", message=f"查询失败: {e}")
        truncated = len(fetched) > 100
        rows = [list(r) for r in fetched[:100]]
        return ExecutionResult(status="success", data={
            "columns": columns, "rows": rows,
            "row_count": len(rows), "truncated": truncated, "db": str(db_path),
        })

    def _exec_db_write(self, params: Dict) -> ExecutionResult:
        """SQLite 写入（INSERT/UPDATE/DELETE/REPLACE/CREATE/ALTER），危险操作拒绝"""
        query = str(params.get("query", "")).strip()
        if not query:
            return ExecutionResult(status="error", error_code="400", message="query 参数为空")
        if re.match(r"(?is)^\s*(select|with)\b", query):
            return ExecutionResult(status="error", error_code="400",
                                   message="只读查询请使用 db_query 工具")
        if re.search(r"(?i)\b(drop|attach|detach|pragma|vacuum|reindex|load_extension)\b", query):
            return ExecutionResult(status="error", error_code="403",
                                   message="db_write 拒绝危险操作（DROP/ATTACH/PRAGMA/VACUUM 等）")
        if not re.match(r"(?is)^\s*(insert|update|delete|replace|create|alter)\b", query):
            return ExecutionResult(status="error", error_code="400",
                                   message="不支持的语句类型（支持 INSERT/UPDATE/DELETE/REPLACE/CREATE/ALTER）")
        import sqlite3
        db_path = self.project_root / "agent.db"
        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            try:
                cur = conn.cursor()
                cur.execute(query)
                conn.commit()
                affected = cur.rowcount
            finally:
                conn.close()
        except sqlite3.Error as e:
            return ExecutionResult(status="error", error_code="400", message=f"写入失败: {e}")
        return ExecutionResult(status="success", data={
            "affected_rows": affected, "db": str(db_path)})

