#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.db_tools —— SQLite 工具（db_query / db_write）"""

import re
import sqlite3
from typing import Any, Dict

from tools.result import DenialKind, ExecutionResult


# sqlite3 异常原文的**放行名单**，判据是"模型拿这段文本能不能做出更好的下一步"。
#
# 这三类异常的文本全部由"语句 + 模式名"生成 —— `no such table: t`、
# `no such column: x`、`syntax error near "FRO"`、`UNIQUE constraint failed: t.id`、
# `You can only execute one statement at a time.`。模型看到它们能直接改 SQL 重试，
# 而里面出现的表名/列名/语句片段本来就是模型自己刚传进来的，回显不新增任何信息。
# 把它们塞进 `_internal_error` 只剩一句"查询失败（OperationalError）"，模型除了
# 原样重试无事可做 —— 那是把可自愈的 400 变成了不可自愈的 400。
#
# 名单外（`DatabaseError` 裸抛的 `file is not a database`、`InterfaceError` 等）
# 一律走 `_internal_error`：它们描述的是**这个文件/这个连接**坏了，改 SQL 不解决，
# 文本却更可能带上文件名。
_SQL_TEXT_ERRORS = (sqlite3.OperationalError, sqlite3.IntegrityError,
                    sqlite3.ProgrammingError)


class DbTools:
    def _db_failed(self, what: str, exc: sqlite3.Error) -> ExecutionResult:
        """db 侧的失败出口。分界线见 `_SQL_TEXT_ERRORS`，另加一道路径护栏。

        为什么名单之外还要查一遍私有根：`OperationalError` 是混装的 ——
        `no such table` 在名单内是对的，但同一个类也扔
        `unable to open database file` / `disk I/O error`，某些平台与 sqlite 版本
        会把库文件名拼进去。

        护栏**复用 `tools.base` 的 `_mentions_private_root()`**，不再自己写一版
        `str(self.project_root) not in raw`：手写那版只认项目根的**一种**渲染形式，
        成对反斜杠（`%r` / JSON 转义的产物）、正斜杠、大小写不同的写法它一概认不出，
        而且完全不看家目录。判据只该有一份实现，两份必然漂移 —— 漂移的那一侧
        不会报错，只会静默放一条路径进模型上下文。

        这里刻意**只**套不变量那一道，不叠 `_model_safe_fragment` 的逐 token 过滤：
        放行分支要送出去的正是 `no such table: users`、`UNIQUE constraint failed:
        t.id` 这类文本，而表名/列名完全可能撞上家目录或项目根的某一级名字
        （`Users`、`Desktop`、项目目录名），逐 token 过滤会把模型唯一能据此改 SQL
        的那个名字打成"（路径已隐去）"。

        `code` 显式传 400 而不是吃 `_internal_error` 的默认 500：这两处的错误码
        是对外契约（`db_query`/`db_write` 的语句错误一直是 400，`execution_layer`
        据此给模型发"参数格式示例"那条 instruction）。脱敏不该顺手改掉它。
        """
        raw = str(exc)
        if isinstance(exc, _SQL_TEXT_ERRORS) and not self._mentions_private_root(raw):
            return ExecutionResult(
                status="error", error_code="400", message=f"{what}: {raw}",
                # 放行分支也写一份进 metadata：人侧的日志口径统一为"每条 db 失败
                # 都能查到异常类型"，否则排障时得先判断这条走了哪个分支。
                metadata={self.ERROR_METADATA_KEY: f"{type(exc).__name__}: {raw}"})
        return self._internal_error(what, exc, code="400")

    def _exec_db_query(self, params: Dict) -> ExecutionResult:
        """SQLite 只读查询（仅 SELECT/WITH），返回列名+行数据，上限 100 行"""
        query = str(params.get("query", "")).strip()
        if not query:
            return ExecutionResult(status="error", error_code="400", message="query 参数为空")
        m = re.match(r"(?is)^\s*(select|with)\b", query)
        if not m:
            # `TOOL_CAPABILITY` 而不是 `COMMAND_SHAPE`：这条拦的是**语句种类**，
            # 而这个种类有专门的工具（db_write）。TOOL_CAPABILITY 的指令正是
            # "换用能做这件事的工具"，模型收到后的正确下一步就是原样改调 db_write。
            # 落 COMMAND_SHAPE 会把模型引到"改写形式再试一次"上 —— 那一档的指令写的是
            # "拆成单条、无 shell 元字符的命令"，是 shell 语境的话，对 SQL 是误导，
            # 而"换个写法让 UPDATE 从 db_query 过去"恰好是这道闸门要防的事。
            return self._denied(self._deny(
                DenialKind.TOOL_CAPABILITY,
                "db_query 仅允许只读查询（SELECT/WITH）；写入请改用 db_write 工具",
                {"statement_head": query.split(None, 1)[0] if query.split() else ""}))
        if m.group(1).lower() == "with" and not re.search(r"(?is)\bselect\b", query):
            # 同上一档，理由也相同：能走到这里的 `WITH` 只有两种可能 ——
            # `WITH x AS (...) INSERT/UPDATE/DELETE`（借道写入，正解是换 db_write），
            # 或残缺语句（正解是补上 SELECT）。两条出路都不是"重试同一次调用"，
            # 而前一种是主要情形，所以跟着它归档。
            return self._denied(self._deny(
                DenialKind.TOOL_CAPABILITY,
                "db_query 的 WITH 必须包含 SELECT（禁止借道写入）；"
                "要写入请改用 db_write，要查询请补上 SELECT",
                {"statement_head": "with"}))

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
            return self._db_failed("查询失败", e)
        truncated = len(fetched) > 100
        rows = [list(r) for r in fetched[:100]]
        return ExecutionResult(status="success", data={
            "columns": columns, "rows": rows,
            "row_count": len(rows), "truncated": truncated,
            # `db` 是本层用 `project_root` 拼出来的绝对路径，而 `data` 整份进模型
            # 上下文（`agent_runner.render_result` 的白名单含它）—— 回显它等于每次
            # 查询都把用户名与项目位置抄一遍进上下文。`agent.db` 结构上永远在项目内，
            # 所以 `_model_path_label` 给的是相对路径，模型下一步想 file_read 它
            # 也正好要传相对路径，诊断能力一分不减。
            # 用 `_model_path_label` 而不是 `_launch_path_label`：这个字段没有
            # 拼 `file:///` 的消费者（`ai_code._print_clickables` 只认 open_file /
            # browser_screenshot / image_generate 三个工具），保留绝对路径没有收益。
            "db": self._model_path_label(db_path),
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
            # 同样落 `TOOL_CAPABILITY`：这一档的语义是"这个工具的能力边界"，
            # 而这批语句正是 db_write 刻意不做的那一类（ATTACH/load_extension 能把
            # 库外文件挂进来或加载任意扩展，DROP 不可回滚）。
            # 不落 `COMMAND_SHAPE`：那一档的指令是"换个写法/拆成简单命令后重试"，
            # 而这里换写法永远不会通过，只会让模型把一次拒绝变成三次重试直到熔断。
            # 也没有 `_denied` 之外的确认通道，所以 message 里直接把可行的替代路径
            # 说出来（message 进模型上下文，是它唯一能读到的"下一步"）：
            # 清空数据用 DELETE FROM，真要删表让用户自己执行。
            return self._denied(self._deny(
                DenialKind.TOOL_CAPABILITY,
                "db_write 拒绝危险操作（DROP/ATTACH/DETACH/PRAGMA/VACUUM/REINDEX/"
                "load_extension）：换写法也不会通过。清空数据请用 DELETE FROM；"
                "确实需要改表结构或删表，请把 SQL 交给用户自己执行",
                {"category": "危险 SQL 语句"}))

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
            return self._db_failed("写入失败", e)
        return ExecutionResult(status="success", data={
            # 同 db_query 的 `db`：绝对路径进 data 就等于进模型上下文。
            "affected_rows": affected, "db": self._model_path_label(db_path)})


