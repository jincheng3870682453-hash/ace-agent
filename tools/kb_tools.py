#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.kb_tools —— 自定义外挂知识库（kb_search / kb_add / kb_list）

用户自己的知识库：项目 `.ace_kb/` 或配置的外挂目录（`--kb <路径>` / config `kb_root`）。
模型可以全文检索知识库、往知识库添加笔记 —— 这是跨会话记忆的显式落点：
写进知识库的东西下次会话还能搜到，比对话历史更持久、更结构化。

与 grep 的区别：grep 检索**项目代码**（限制项目内，防路径逃逸）；kb_search 检索
**知识库**（用户显式指定的信任目录，允许外挂绝对路径）。两者的语义都是"检索用户
自己的资料"，所以检索结果同样按外部内容隔离注入（见 ace_isolation 的"知识库内容"）。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

from tools.result import ExecutionResult

_KB_MAX_RESULTS = 200
_KB_MAX_FILE_BYTES = 512 * 1024
_KB_MAX_MATCH_CHARS = 4000     # 正则只在行首这段里匹配（防灾难性回溯，同 grep）
_KB_MAX_LINE_CHARS = 500
_KB_MAX_FILES = 500
_KB_NAME_RE = re.compile(r"^[\w\-./]+\.\w{1,10}$")   # 文件名白名单（含子目录）

# 检索/写入时跳过的目录
_KB_SKIP_DIRS = {".git", ".guardian", ".agent_flywheel", ".ace_sessions",
                 "__pycache__", ".test_tmp", "node_modules"}


class KbTools:
    def _kb_root(self) -> Path:
        """知识库根目录：config kb_root（外挂）> 项目 .ace_kb（默认）。"""
        root = getattr(self, "kb_root", None)
        if root:
            p = Path(root).expanduser().resolve()
        else:
            p = self.project_root / ".ace_kb"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def _iter_kb_files(self, root: Path) -> List[Path]:
        out: List[Path] = []
        for f in root.rglob("*"):
            if not f.is_file():
                continue
            if any(part in _KB_SKIP_DIRS for part in f.relative_to(root).parts):
                continue
            if f.stat().st_size > _KB_MAX_FILE_BYTES:
                continue
            out.append(f)
            if len(out) >= _KB_MAX_FILES:
                break
        return out

    def _exec_kb_search(self, params: Dict) -> ExecutionResult:
        """在知识库中全文检索，返回 相对路径:行号: 内容（含匹配行上下文提示）"""
        pattern = str(params.get("query", "") or params.get("pattern", "")).strip()
        if not pattern:
            return ExecutionResult(status="error", error_code="400",
                                   message="kb_search 需要 query 参数（检索词或正则）")
        root = self._kb_root()
        try:
            regex = re.compile(pattern, 0 if params.get("case_sensitive") else re.IGNORECASE)
        except re.error as e:
            return ExecutionResult(status="error", error_code="400",
                                   message=f"正则表达式无效: {e}")
        try:
            max_results = min(int(params.get("max_results", 50)), _KB_MAX_RESULTS)
        except (TypeError, ValueError):
            max_results = 50

        matches: List[str] = []
        files_scanned = 0
        for f in self._iter_kb_files(root):
            files_scanned += 1
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "\0" in text[:4096]:
                continue
            rel = str(f.relative_to(root))
            for lineno, line in enumerate(text.splitlines(), 1):
                if regex.search(line[:_KB_MAX_MATCH_CHARS]):
                    matches.append(f"{rel}:{lineno}: {line.strip()[:_KB_MAX_LINE_CHARS]}")
                    if len(matches) >= max_results:
                        break
            if len(matches) >= max_results:
                break
        body = "\n".join(matches) if matches else f"（知识库无匹配：{pattern}）"
        if len(matches) >= max_results:
            body += f"\n... [已达 max_results={max_results}，可换更精确的关键词]"
        body += (f"\n\n[知识库: {root}，扫描 {files_scanned} 个文件。"
                 "知识库内容可用 kb_add 补充、kb_list 查看]")
        return ExecutionResult(status="success", data={
            "content": body, "matches": matches, "match_count": len(matches),
            "kb_root": str(root), "files_scanned": files_scanned,
        })

    def _exec_kb_add(self, params: Dict) -> ExecutionResult:
        """向知识库添加一条资料/笔记（filename + content），跨会话持久"""
        filename = str(params.get("filename", "")).strip()
        content = str(params.get("content", ""))
        if not filename:
            return ExecutionResult(status="error", error_code="400",
                                   message="kb_add 需要 filename 参数（如 notes/sql-tips.md）")
        if not content.strip():
            return ExecutionResult(status="error", error_code="400",
                                   message="content 参数为空（要写入的内容）")
        if len(content) > 200_000:
            return ExecutionResult(status="error", error_code="400",
                                   message="content 过长（上限 200KB）")
        if not _KB_NAME_RE.match(filename) or ".." in filename:
            return ExecutionResult(status="error", error_code="400",
                                   message="filename 含非法字符（仅允许 字母/数字/下划线/连字符/斜杠/点）")
        root = self._kb_root()
        target = (root / filename).resolve()
        # 防穿越：目标必须在知识库根内
        try:
            target.relative_to(root)
        except ValueError:
            return ExecutionResult(status="error", error_code="400",
                                   message="filename 越出知识库目录")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        except OSError as e:
            return ExecutionResult(status="error", error_code="500",
                                   message=f"知识库写入失败: {e}")
        return ExecutionResult(status="success", data={
            "path": str(target), "bytes": len(content),
            "kb_root": str(root),
            "hint": "已写入知识库。下次 kb_search 即可检索到；知识库是跨会话持久记忆",
        })

    def _exec_kb_list(self, params: Dict) -> ExecutionResult:
        """列出知识库文件（含大小与修改时间）"""
        root = self._kb_root()
        files = self._iter_kb_files(root)
        rows = []
        for f in files:
            rel = str(f.relative_to(root))
            rows.append(f"{rel}  ({f.stat().st_size}B)")
        if not rows:
            return ExecutionResult(status="success", data={
                "files": [], "kb_root": str(root),
                "hint": "知识库为空。用 kb_add 添加资料（filename + content），"
                        "或把文件放进 " + str(root)})
        return ExecutionResult(status="success", data={
            "files": rows, "count": len(rows), "kb_root": str(root)})
