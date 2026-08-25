#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.file_tools —— 文件与终端工具（file_* / terminal_* / open_file / edit_file）"""

import os
import re
import sys
import fnmatch
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from tools.base import (GIT_READONLY_SUBCOMMANDS, MAX_COMMAND_LENGTH,
                        READ_ONLY_COMMANDS, SHELL_META_RE,
                        VERSION_ONLY_COMMANDS, VERSION_SUBCOMMANDS,
                        sensitive_target)
from tools.docker_sandbox import DockerUnavailable
from tools.result import ExecutionResult


# Windows 无默认打开程序时，文本类扩展名回退记事本打开（.py 常无关联程序）
_TEXT_EXTENSIONS = {".py", ".txt", ".md", ".json", ".log", ".csv", ".ini", ".cfg",
                    ".yaml", ".yml", ".toml", ".xml", ".html", ".css", ".js",
                    ".ts", ".bat", ".cmd", ".ps1", ".sql", ".env"}

# —— grep / glob 检索参数 ——
# 跳过依赖与构建产物：搜进 node_modules/.venv 只有噪音，还会把遍历拖到分钟级。
_SEARCH_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules",
                     ".venv", "venv", ".idea", ".vscode", ".mypy_cache",
                     ".pytest_cache", "dist", "build", "site-packages",
                     ".ace_shots", ".ace_images", ".guardian"}
_SEARCH_MAX_FILE_BYTES = 2_000_000   # 超过 2MB 视为非源码，跳过
_SEARCH_MAX_FILES = 5_000            # 遍历文件数上限，防止指到巨大目录时卡死
_SEARCH_MAX_LINE_CHARS = 300         # 单条匹配行截断长度（避免压缩后的长行吃满上下文）
GREP_DEFAULT_MAX_RESULTS = 200
GLOB_DEFAULT_MAX_RESULTS = 200
# file_read 未显式传 limit 时的默认行数上限：整读大文件会吃满上下文
FILE_READ_DEFAULT_LIMIT = 2_000
# str_replace 上限：超过就该整文件重写或拆分，不在局部编辑工具里处理
_STR_REPLACE_MAX_BYTES = 5_000_000
_STR_REPLACE_MAX_DIFF_LINES = 200




class FileTools:
    # 可传绝对路径的写工具：绝对路径 = 用户明确意图（"放到桌面"），但意图不覆盖敏感目标
    _ABS_PATH_WRITE_TOOLS = ("file_write", "file_delete", "str_replace")

    def _resolve_target_path(self, tool_name: str, path_str: str):
        """解析并校验文件工具的目标路径。

        返回 (path, None) 或 (None, 错误结果)。file_write / file_delete / str_replace
        共用同一套口径：相对路径限项目内、绝对路径放行、敏感目标一律拒绝。
        """
        path = Path(os.path.expanduser(path_str))
        if self.confine_files:
            confined = self._confined(path)
            if confined is not None:
                path = confined
            elif tool_name == "file_read" and path.is_dir():
                # 只读目录列表允许越界（与 terminal_view ls 口径一致），
                # 防止"帮我看看桌面/主目录"这类问题因工具选择而失败
                pass
            elif path.is_absolute() and tool_name in self._ABS_PATH_WRITE_TOOLS:
                # 绝对路径（含 ~ 展开后） = 用户明确意图（如"放到桌面/主目录"），写工具放行；
                # 相对路径仍严格限项目内，防止穿越。读文件仍限项目内。
                path = path.resolve()
            else:
                return None, ExecutionResult(
                    status="error", error_code="403",
                    message="路径越界：相对路径仅允许在项目目录内；"
                            "写文件（file_write/file_delete/str_replace）可传绝对路径"
                            "（如 C:\\Users\\<用户名>\\Desktop\\文件名，"
                            "或 ~/Desktop/文件名）")
        elif not path.is_absolute():
            path = self.project_root / path

        # 敏感目标硬拦截：绝对路径放行是"用户明确意图"（写桌面），但意图不覆盖
        # 凭据文件与自启动入口（~/.ssh/authorized_keys、~/.bashrc、~/.ai_code.json）。
        if tool_name in self._ABS_PATH_WRITE_TOOLS:
            reason = sensitive_target(path)
            if reason:
                return None, ExecutionResult(
                    status="error", error_code="403",
                    message=f"拒绝写入/删除敏感目标（{reason}）: {path}。"
                            "如确需修改，请在终端手动操作。")
        return path, None

    def _exec_file_ops(self, tool_name: str, params: Dict) -> ExecutionResult:
        """文件操作（相对路径限制在项目目录内；绝对路径 = 用户明确意图，防路径穿越）"""
        path_str = str(params.get("path", "")).strip()
        if not path_str and tool_name != "file_move":
            # 小模型常漏 path 参数：明确 400（配示例），而不是把 Path("") 当目录写到 500
            return ExecutionResult(status="error", error_code="400",
                                   message=f"{tool_name} 需要 path 参数（示例: "
                                           f'{{"tool": "{tool_name}", "path": "文件路径"}})')
        path, err = self._resolve_target_path(tool_name, path_str)
        if err:
            return err


        try:
            if tool_name == "file_read":
                if not path.exists():
                    return ExecutionResult(status="error", error_code="404",
                                           message=f"文件不存在: {path}"
                                                   f"（若目标是目录，file_read 会直接返回目录列表）")
                if path.is_dir():
                    try:
                        items = sorted(os.listdir(path))
                    except Exception as e:
                        return ExecutionResult(status="error", error_code="500",
                                               message=f"目录读取失败: {e}")
                    return ExecutionResult(status="success", data={
                        "content": "\n".join(items),
                        "path": str(path),
                        "is_dir": True,
                        "listing": items,
                    })
                content = self._read_text_any(path)
                return self._file_read_payload(path, content, params)

            elif tool_name == "file_write":
                if path.is_dir():
                    return ExecutionResult(status="error", error_code="400",
                                           message=f"path 是目录: {path}，file_write 需要完整文件路径"
                                                   "（如 C:\\Users\\<用户名>\\Desktop\\文件.py）")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(params.get("content", ""), encoding="utf-8")
                return ExecutionResult(status="success", data={"path": str(path), "bytes_written": len(params.get("content", ""))})
            elif tool_name == "file_delete":
                if path.is_dir():
                    return ExecutionResult(status="error", error_code="400",
                                           message=f"path 是目录: {path}，file_delete 只删除文件")
                if path.exists():
                    path.unlink()
                return ExecutionResult(status="success", data={"deleted": str(path)})
            elif tool_name == "file_move":
                src = Path(os.path.expanduser(str(params.get("source", ""))))
                dest = Path(os.path.expanduser(str(params.get("dest", ""))))
                if not str(params.get("source", "")).strip() or not str(params.get("dest", "")).strip():
                    return ExecutionResult(status="error", error_code="400",
                                           message='file_move 需要 source 与 dest 参数'
                                                   '（示例: {"tool": "file_move", "source": "a.txt", "dest": "b.txt"}）')
                if self.confine_files:
                    src = self._confined(src) or (src.resolve() if src.is_absolute() else None)
                    dest = self._confined(dest) or (dest.resolve() if dest.is_absolute() else None)
                    if src is None or dest is None:
                        return ExecutionResult(status="error", error_code="403",
                                               message="路径越界：file_move 仅允许项目内相对路径"
                                                       "或绝对路径（绝对路径 = 明确意图）")
                else:
                    if not src.is_absolute():
                        src = self.project_root / src
                    if not dest.is_absolute():
                        dest = self.project_root / dest
                # file_move 同时是"删源 + 写目标"，两端都要过敏感目标拦截
                for p in (src, dest):
                    reason = sensitive_target(p)
                    if reason:
                        return ExecutionResult(
                            status="error", error_code="403",
                            message=f"拒绝移动敏感目标（{reason}）: {p}")
                if not src.exists():
                    return ExecutionResult(status="error", error_code="404",
                                           message=f"源文件不存在: {src}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                src.rename(dest)
                return ExecutionResult(status="success", data={"moved": str(src), "to": str(dest)})
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))

    # ------------------------------------------------------------------
    # file_read 分段读取
    # ------------------------------------------------------------------

    @staticmethod
    def _positive_int(params: Dict, key: str) -> Tuple[Optional[int], Optional[str]]:
        """取正整数参数；缺省返回 (None, None)，非法返回 (None, 错误说明)"""
        raw = params.get(key)
        if raw is None or raw == "":
            return None, None
        try:
            val = int(raw)
        except (TypeError, ValueError):
            return None, f"{key} 需要整数，收到: {raw!r}"
        if val < 1:
            return None, f"{key} 需要 ≥ 1，收到: {val}"
        return val, None

    def _file_read_payload(self, path: Path, content: str, params: Dict) -> ExecutionResult:
        """构造 file_read 返回值。

        - 不传 offset/limit 且文件不超过 FILE_READ_DEFAULT_LIMIT 行：返回原文（与旧行为一致）
        - 不传但超限：返回前 N 行 + 截断提示，避免大文件吃满上下文
        - 传了 offset/limit：返回带行号的片段（局部编辑需要精确行号定位）
        """
        offset, err = self._positive_int(params, "offset")
        if err:
            return ExecutionResult(status="error", error_code="400", message=err)
        limit, err = self._positive_int(params, "limit")
        if err:
            return ExecutionResult(status="error", error_code="400", message=err)

        lines = content.splitlines()
        total = len(lines)
        paged = offset is not None or limit is not None
        start = offset or 1
        count = limit or FILE_READ_DEFAULT_LIMIT
        segment = lines[start - 1:start - 1 + count]
        end = start + len(segment) - 1
        truncated = paged and end < total

        data: Dict[str, Any] = {"path": str(path), "total_lines": total}
        if paged:
            data["content"] = "\n".join(f"{start + i:>6}→{ln}" for i, ln in enumerate(segment))
            data.update({"offset": start, "limit": count, "truncated": truncated})
            if not segment:
                data["content"] = f"（offset={start} 超出文件末尾，文件共 {total} 行）"
        elif total > count:
            data["content"] = ("\n".join(segment) +
                               f"\n... [已截断：文件共 {total} 行，仅返回前 {count} 行。"
                               f"用 offset/limit 读取后续，如 offset={count + 1}]")
            data.update({"offset": 1, "limit": count, "truncated": True})
        else:
            data["content"] = content
            data["truncated"] = False
        return ExecutionResult(status="success", data=data)

    # ------------------------------------------------------------------
    # str_replace：局部替换（唯一匹配才写，失败不落盘）
    # ------------------------------------------------------------------

    @staticmethod
    def _norm_ws_line(line: str) -> str:
        """行级归一化：tab→4 空格、去行尾空白。**不动行首缩进的相对结构**。"""
        return line.replace("\t", "    ").rstrip()

    @staticmethod
    def _indent_width(line: str) -> int:
        return len(line) - len(line.lstrip())

    def _find_indent_tolerant(self, file_lines: List[str],
                              old_lines: List[str]) -> List[Tuple[int, int]]:
        """空白归一化定位：内容去缩进后逐行一致 + 块内相对缩进一致。

        返回 [(起始行下标, 该块在文件里的真实基准缩进)]。

        为什么这样设计：直接"忽略所有空白"去匹配，在 Python 里等于放弃缩进语义，
        很容易把 if 分支里的一行匹配到分支外。这里的容错只放开两件事——
        tab/空格混用、整块缩进层级偏移（模型最常犯的两种），块内部的相对缩进
        必须严格一致。而且归一化只用于**定位**：真正写入时用文件里的真实缩进
        当基准（见 _reindent_lines），所以模型给错的缩进不会被写进文件。
        """
        norm_old = [self._norm_ws_line(l) for l in old_lines]
        body_old = [l.strip() for l in norm_old]
        anchor = next((i for i, s in enumerate(body_old) if s), None)
        if anchor is None:
            return []  # old_string 全是空白：不做容错匹配，否则会命中任意空行
        base_old = self._indent_width(norm_old[anchor])
        rel_old = [None if not body_old[i] else self._indent_width(norm_old[i]) - base_old
                   for i in range(len(norm_old))]

        norm_file = [self._norm_ws_line(l) for l in file_lines]
        body_file = [l.strip() for l in norm_file]
        hits: List[Tuple[int, int]] = []
        m = len(norm_old)
        for start in range(0, len(norm_file) - m + 1):
            if body_file[start:start + m] != body_old:
                continue
            base = self._indent_width(norm_file[start + anchor])
            if all(rel_old[i] is None
                   or self._indent_width(norm_file[start + i]) - base == rel_old[i]
                   for i in range(m)):
                hits.append((start, base))
        return hits

    def _reindent_lines(self, new_lines: List[str], target_base: int) -> List[str]:
        """把 new_string 对齐到文件实际缩进：保留其内部相对缩进，整块平移到 target_base。

        这是"归一化匹配不引入缩进错误"的关键——基准来自文件而非模型输出。
        副作用：行尾空白会被清掉（对代码是好事；对刻意用行尾双空格的 Markdown 会丢失）。
        """
        norm = [l.replace("\t", "    ") for l in new_lines]
        anchor = next((i for i, l in enumerate(norm) if l.strip()), None)
        if anchor is None:
            return ["" for _ in norm]
        delta = target_base - self._indent_width(norm[anchor])
        out = []
        for l in norm:
            if not l.strip():
                out.append("")
                continue
            out.append(" " * max(0, self._indent_width(l) + delta) + l.strip())
        return out

    @staticmethod
    def _trim_blank_edges(lines: List[str]) -> List[str]:
        """去掉首尾的纯空白行（模型常在片段前后多写一个空行）"""
        out = list(lines)
        while out and not out[0].strip():
            out.pop(0)
        while out and not out[-1].strip():
            out.pop()
        return out

    @staticmethod
    def _multi_match_error(path: Path, work: str, old_s: str, count: int,
                           line_nos: Optional[List[int]] = None) -> ExecutionResult:
        """多匹配：一律不写，让模型带更多上下文重试（409 与 400 参数错误区分开）"""
        if line_nos is None:
            line_nos = []
            idx = work.find(old_s)
            while idx != -1 and len(line_nos) < 10:
                line_nos.append(work.count("\n", 0, idx) + 1)
                idx = work.find(old_s, idx + 1)
        return ExecutionResult(
            status="error", error_code="409",
            message=f"old_string 在 {path} 中匹配到 {count} 处（行 {line_nos}），"
                    f"未做任何修改。请在 old_string 前后各补 3-5 行唯一上下文后重试"
                    f"（可先用 file_read 的 offset/limit 读取该行附近拿到准确片段）；"
                    f"若确实要全部替换，传 replace_all=true。")

    def _exec_str_replace(self, params: Dict) -> ExecutionResult:
        """局部替换文件片段：精确匹配优先，0 命中时回退空白归一化匹配。

        语义（已定型）：
          - 唯一匹配 → 替换
          - 多匹配 + replace_all=false → 409，不写任何内容
          - 多匹配 + replace_all=true  → 全部替换
          - 0 匹配 → 404，不写任何内容
        """
        path_str = str(params.get("path", "")).strip()
        if not path_str:
            return ExecutionResult(status="error", error_code="400",
                                   message='str_replace 需要 path 参数（示例: '
                                           '{"tool":"str_replace","path":"a.py",'
                                           '"old_string":"原片段","new_string":"新片段"}）')
        old_raw = params.get("old_string")
        new_raw = params.get("new_string")
        if not isinstance(old_raw, str) or not old_raw:
            return ExecutionResult(status="error", error_code="400",
                                   message="str_replace 需要非空 old_string"
                                           "（要被替换的原文片段，建议带前后 3-5 行上下文以保证唯一）")
        if new_raw is None:
            new_raw = ""  # 省略 new_string = 删除该片段
        if not isinstance(new_raw, str):
            return ExecutionResult(status="error", error_code="400",
                                   message="new_string 必须是字符串（删除片段请传空串或省略）")
        if old_raw == new_raw:
            return ExecutionResult(status="error", error_code="400",
                                   message="old_string 与 new_string 相同，无需替换")

        path, err = self._resolve_target_path("str_replace", path_str)
        if err:
            return err
        if path.is_dir():
            return ExecutionResult(status="error", error_code="400",
                                   message=f"path 是目录: {path}，str_replace 需要文件路径")
        if not path.exists():
            return ExecutionResult(status="error", error_code="404",
                                   message=f"文件不存在: {path}（新建文件请用 file_write）")
        try:
            if path.stat().st_size > _STR_REPLACE_MAX_BYTES:
                return ExecutionResult(
                    status="error", error_code="400",
                    message=f"文件过大（>{_STR_REPLACE_MAX_BYTES // 1_000_000}MB），"
                            f"str_replace 不处理: {path}")
            content = self._read_text_any(path)
        except OSError as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))

        replace_all = bool(params.get("replace_all", False))
        # 换行风格：统一到 \n 比较，写回时还原，避免把 CRLF 文件整体改成 LF
        crlf = "\r\n" in content
        work = content.replace("\r\n", "\n")
        old_s = old_raw.replace("\r\n", "\n")
        new_s = new_raw.replace("\r\n", "\n")

        count = work.count(old_s)
        if count == 1:
            result_text, replaced, matched_by = work.replace(old_s, new_s, 1), 1, "exact"
        elif count > 1 and replace_all:
            result_text, replaced, matched_by = work.replace(old_s, new_s), count, "exact"
        elif count > 1:
            return self._multi_match_error(path, work, old_s, count)
        else:
            # 精确 0 命中 → 空白归一化容错（只放开 tab/空格与整块缩进偏移）
            file_lines = work.split("\n")
            old_lines = self._trim_blank_edges(old_s.split("\n"))
            if not old_lines:
                return ExecutionResult(status="error", error_code="400",
                                       message="old_string 只有空白内容，无法定位")
            hits = self._find_indent_tolerant(file_lines, old_lines)
            if not hits:
                return ExecutionResult(
                    status="error", error_code="404",
                    message=f"在 {path} 中未找到 old_string（精确匹配与空白归一化匹配均无命中），"
                            f"未做任何修改。请先用 grep 定位、再用 file_read 的 offset/limit "
                            f"读出带行号的真实片段，按原文重新构造 old_string。")
            if len(hits) > 1 and not replace_all:
                return self._multi_match_error(path, work, old_s, len(hits),
                                               line_nos=[s + 1 for s, _ in hits])
            matched_by = "whitespace_normalized"
            new_lines = self._trim_blank_edges(new_s.split("\n"))
            m = len(old_lines)
            out = list(file_lines)
            targets = hits if replace_all else hits[:1]
            for start, base in reversed(targets):
                out[start:start + m] = self._reindent_lines(new_lines, base)
            result_text, replaced = "\n".join(out), len(targets)

        if result_text == work:
            return ExecutionResult(status="error", error_code="400",
                                   message="替换后内容与原文一致，未做任何修改")

        import difflib
        diff = list(difflib.unified_diff(
            work.split("\n"), result_text.split("\n"),
            fromfile=f"a/{path.name}", tofile=f"b/{path.name}", lineterm="", n=3))
        if len(diff) > _STR_REPLACE_MAX_DIFF_LINES:
            diff = diff[:_STR_REPLACE_MAX_DIFF_LINES] + ["... [diff 已截断]"]

        try:
            path.write_text(result_text.replace("\n", "\r\n") if crlf else result_text,
                            encoding="utf-8")
        except OSError as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))
        return ExecutionResult(status="success", data={
            "path": str(path), "replaced": replaced, "matched_by": matched_by,
            "diff": "\n".join(diff),
            "content": (f"已替换 {replaced} 处（匹配方式: {matched_by}）\n" + "\n".join(diff)),
        })

    # ------------------------------------------------------------------
    # grep / glob：只读代码检索（原生实现，不经过 shell）
    # ------------------------------------------------------------------


    def _search_root(self, path_str: Any) -> Tuple[Optional[Path], Optional[ExecutionResult]]:
        """解析 grep/glob 的检索起点：始终限制在项目目录内。

        与 file_read 的"越界目录可列出"不同，检索工具不给越界能力——它属于 READ_TOOLS，
        readonly 会话也能调用，放开就等于给了全盘扫描凭据文件的能力。
        """
        raw = str(path_str or ".").strip() or "."
        resolved = self._confined(Path(os.path.expanduser(raw)))
        if resolved is None:
            return None, ExecutionResult(
                status="error", error_code="403",
                message=f"检索路径越界：仅允许项目目录（{self.project_root}）内的路径")
        if not resolved.exists():
            return None, ExecutionResult(status="error", error_code="404",
                                         message=f"路径不存在: {resolved}")
        return resolved, None

    def _rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.project_root).as_posix()
        except ValueError:
            return path.as_posix()

    def _iter_search_files(self, root: Path, name_filters: List[str]) -> Iterator[Path]:
        """遍历检索范围内的候选文件（跳过依赖/构建目录，限制总数）"""
        if root.is_file():
            yield root
            return
        seen = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SEARCH_SKIP_DIRS]
            for name in sorted(filenames):
                if name_filters and not any(fnmatch.fnmatch(name, pat) for pat in name_filters):
                    continue
                seen += 1
                if seen > _SEARCH_MAX_FILES:
                    return
                yield Path(dirpath) / name

    def _exec_grep(self, params: Dict) -> ExecutionResult:
        """按正则检索文件内容，返回 相对路径:行号: 内容"""
        pattern = str(params.get("pattern", "")).strip()
        if not pattern:
            return ExecutionResult(status="error", error_code="400",
                                   message='grep 需要 pattern 参数（示例: '
                                           '{"tool":"grep","pattern":"def _exec_","glob":"*.py"}）')
        try:
            regex = re.compile(pattern, 0 if params.get("case_sensitive") else re.IGNORECASE)
        except re.error as e:
            return ExecutionResult(status="error", error_code="400",
                                   message=f"正则表达式无效: {e}")
        root, err = self._search_root(params.get("path"))
        if err:
            return err
        max_results, perr = self._positive_int(params, "max_results")
        if perr:
            return ExecutionResult(status="error", error_code="400", message=perr)
        max_results = min(max_results or GREP_DEFAULT_MAX_RESULTS, 2_000)
        filters = [s.strip() for s in str(params.get("glob") or "").split(",") if s.strip()]

        matches: List[str] = []
        files_scanned = 0
        truncated = False
        for f in self._iter_search_files(root, filters):
            try:
                if f.stat().st_size > _SEARCH_MAX_FILE_BYTES:
                    continue
                text = self._read_text_any(f)
            except OSError:
                continue
            if "\0" in text[:4096]:  # 二进制文件（_read_text_any 会以 errors=ignore 兜底解码）
                continue
            files_scanned += 1
            rel = self._rel(f)
            for lineno, line in enumerate(text.splitlines(), 1):
                if regex.search(line):
                    matches.append(f"{rel}:{lineno}: {line.strip()[:_SEARCH_MAX_LINE_CHARS]}")
                    if len(matches) >= max_results:
                        truncated = True
                        break
            if truncated:
                break

        body = "\n".join(matches) if matches else f"（无匹配：{pattern}）"
        if truncated:
            body += f"\n... [已截断：达到 max_results={max_results}，请缩小范围或加 glob 过滤]"
        return ExecutionResult(status="success", data={
            "content": body, "matches": matches, "match_count": len(matches),
            "files_scanned": files_scanned, "truncated": truncated,
            "root": self._rel(root) or ".",
        })

    def _exec_glob(self, params: Dict) -> ExecutionResult:
        """按通配符查找文件路径（定位文件用，搜内容用 grep）"""
        pattern = str(params.get("pattern", "")).strip()
        if not pattern:
            return ExecutionResult(status="error", error_code="400",
                                   message='glob 需要 pattern 参数（示例: '
                                           '{"tool":"glob","pattern":"**/*.py"}）')
        if os.path.isabs(pattern) or re.match(r"^[a-zA-Z]:[\\/]", pattern):
            return ExecutionResult(status="error", error_code="400",
                                   message="glob 的 pattern 必须是相对通配符（如 **/*.py）；"
                                           "起点目录请用 path 参数")
        root, err = self._search_root(params.get("path"))
        if err:
            return err
        max_results, perr = self._positive_int(params, "max_results")
        if perr:
            return ExecutionResult(status="error", error_code="400", message=perr)
        max_results = min(max_results or GLOB_DEFAULT_MAX_RESULTS, 2_000)

        results: List[str] = []
        truncated = False
        try:
            for p in root.glob(pattern.replace("\\", "/")):
                if any(part in _SEARCH_SKIP_DIRS for part in p.parts):
                    continue
                if not p.is_file():
                    continue
                results.append(self._rel(p))
                if len(results) >= max_results:
                    truncated = True
                    break
        except (ValueError, IndexError, NotImplementedError, OSError) as e:
            return ExecutionResult(status="error", error_code="400",
                                   message=f"通配符无效: {e}")
        results.sort()
        body = "\n".join(results) if results else f"（无匹配文件：{pattern}）"
        if truncated:
            body += f"\n... [已截断：达到 max_results={max_results}]"
        return ExecutionResult(status="success", data={
            "content": body, "files": results, "file_count": len(results),
            "truncated": truncated, "root": self._rel(root) or ".",
        })

    # Windows 开关（tree /F、where /R）会被 os.path.isabs 误判成绝对路径
    _NT_SWITCH_RE = re.compile(r"^/[A-Za-z]+$")
    # DOS 版 dir 的开关白名单。用白名单而不是 "^/字母+$"：后者会把 Linux 上的
    # `dir /tmp` 当成开关吃掉。单字母开关可带 :参数（/a:d、/o:-s）。
    _DOS_DIR_SWITCH_RE = re.compile(r"^/[bsaopwdlnqrtxc4](?:[:\-]\w+)?$", re.IGNORECASE)


    def _escapes_project(self, token: str) -> bool:
        """这个命令行 token 是一个指向项目目录外的路径吗？不像路径、或在项目内则 False。"""
        if token.startswith("-"):
            return False
        if os.name == "nt" and self._NT_SWITCH_RE.match(token):
            return False
        expanded = os.path.expanduser(token)
        looks_like_path = (os.path.isabs(expanded)
                           or re.match(r"^[a-zA-Z]:[\\/]", expanded)
                           or ".." in Path(expanded).parts)
        if not looks_like_path:
            return False
        return self._confined(Path(expanded)) is None

    def _exec_terminal_view(self, params: Dict) -> ExecutionResult:

        """只读终端查看：白名单命令 + 无 shell 执行（修复：readonly 不再能执行任意命令）

        越界口径：读"目录名单"允许越界，读"文件内容"不允许。目录名单泄露的是文件名，
        文件内容泄露的是凭据本身，量级不同；ls 的越界是本文件 60-62 行记录的产品决定
        （"帮我看看桌面"不该因为工具选择而失败），cat 的越界只是漏检。
        """
        cmd = (params.get("command") or "").strip()
        if not cmd:
            # 小模型常漏 command 参数：缺省列出项目目录，避免 400 死循环
            cmd = "ls -la"
        if len(cmd) > MAX_COMMAND_LENGTH:
            return ExecutionResult(status="error", error_code="400", message="命令过长")
        if SHELL_META_RE.search(cmd):
            return ExecutionResult(status="error", error_code="403",
                                   message="terminal_view 检测到 shell 元字符，已拦截（只读工具禁止管道/重定向/连接符）")
        import shlex
        try:
            if os.name == "nt":
                # Windows 专用分词：双引号分组 + 保留反斜杠路径（shlex 会吃掉 \ 且在空格处断开）
                parts = self._split_cmd_windows(cmd)
            else:
                parts = shlex.split(cmd)
        except ValueError as e:
            return ExecutionResult(status="error", error_code="400", message=f"命令解析失败: {e}")
        if not parts:
            return ExecutionResult(status="error", error_code="400", message="命令为空")
        base = parts[0].lower()

        # —— 原生实现的只读内建命令（完全不经过 shell）——
        if base in ("ls", "dir"):
            # 忽略常见列表参数（ls 的 -l/-a/--all、dir 的 /b 等），支持 ~ 展开。
            # "/x" 是不是开关取决于命令方言、而不是当前系统：dir 是 DOS 风格，/b 是开关；
            # ls 是 POSIX 风格，"/" 开头就是绝对路径。按系统判会两头都错 ——
            # 之前按 "只要以 / 开头就丢掉" 处理，POSIX 上 ls /etc 会静默退化成 ls 项目根目录；
            # 改成按系统判又会让 Linux 上的 dir /b 把 /b 当成目录去列。
            dos_dialect = base == "dir"
            target_args = [p for p in parts[1:]
                           if not p.startswith("-")
                           and not (dos_dialect and self._DOS_DIR_SWITCH_RE.match(p))]

            target = target_args[0] if target_args else "."
            target = os.path.expanduser(target)
            # 支持通配符：ls *.py / dir /b *.py
            if any(ch in target for ch in "*?"):
                import glob
                pattern = target if os.path.isabs(target) else str(self.project_root / target)
                try:
                    matches = sorted(glob.glob(pattern))
                except Exception as e:
                    return ExecutionResult(status="error", error_code="500", message=str(e))
                lower_parts = [p.lower() for p in parts[1:]]
                bare = "/b" in lower_parts or "-1" in lower_parts
                if bare:
                    items = [os.path.basename(m) for m in matches]
                else:
                    items = [os.path.relpath(m, self.project_root)
                             if not os.path.isabs(target) else m
                             for m in matches]
                return ExecutionResult(status="success", data={
                    "stdout": "\n".join(items), "stderr": "", "returncode": 0})
            p = Path(target)
            if not p.is_absolute():
                p = self.project_root / p
            try:
                items = sorted(os.listdir(p))
            except FileNotFoundError:
                return ExecutionResult(status="error", error_code="404",
                                       message=f"目录不存在: {p}")
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=str(e))
            return ExecutionResult(status="success", data={"stdout": "\n".join(items),
                                                           "stderr": "", "returncode": 0})
        if base == "pwd":
            return ExecutionResult(status="success", data={"stdout": str(self.project_root),
                                                           "stderr": "", "returncode": 0})
        if base in ("cat", "type"):
            if len(parts) < 2:
                return ExecutionResult(status="error", error_code="400", message="cat/type 需要文件参数")
            p = Path(os.path.expanduser(parts[1]))
            if not p.is_absolute():
                p = self.project_root / p
            # 读文件内容一律限项目内，与 grep / file_read 同口径。这里以前只查
            # sensitive_target，等于用黑名单当边界：名单外的项目外文件（别人的源码、
            # 浏览器 profile、随手记的 token）readonly 会话照样读得走。
            if self.confine_files and self._confined(p) is None:
                return ExecutionResult(status="error", error_code="403",
                                       message=f"路径越界：cat/type 只能读项目目录内的文件: {p}"
                                               "（列目录可用 ls）")
            # confine_files=False 时仍要挡住凭据文件，否则 ~/.ai_code.json 里的
            # 明文 API key 会被只读会话读走。
            reason = sensitive_target(p)
            if reason:
                return ExecutionResult(status="error", error_code="403",
                                       message=f"拒绝读取敏感文件（{reason}）: {p}")
            try:
                content = self._read_text_any(p)
            except FileNotFoundError:
                return ExecutionResult(status="error", error_code="404", message=f"文件不存在: {p}")
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=str(e))
            return ExecutionResult(status="success", data={"stdout": content[:5000],
                                                           "stderr": "", "returncode": 0})
        if base == "echo":
            return ExecutionResult(status="success", data={"stdout": " ".join(parts[1:]),
                                                           "stderr": "", "returncode": 0})
        if base == "ver":
            import platform
            return ExecutionResult(status="success", data={"stdout": f"{platform.system()} {platform.release()}",
                                                           "stderr": "", "returncode": 0})
        if base in ("date", "time"):
            from datetime import datetime
            return ExecutionResult(status="success", data={"stdout": datetime.now().isoformat(),
                                                           "stderr": "", "returncode": 0})

        # —— 白名单外部命令 ——
        if base in VERSION_ONLY_COMMANDS:
            # 严格校验：只允许恰好两个 token 的版本查询，防止 "-v -c 代码" 注入
            if len(parts) != 2 or parts[1] not in VERSION_SUBCOMMANDS:
                return ExecutionResult(status="error", error_code="403",
                                       message=f"{base} 仅允许查询版本（--version / -V，且不允许附加任何参数）")
        elif base == "git":
            if len(parts) < 2 or parts[1].lower() not in GIT_READONLY_SUBCOMMANDS:
                return ExecutionResult(status="error", error_code="403",
                                       message=f"git 仅允许只读子命令: {sorted(GIT_READONLY_SUBCOMMANDS)}")
        elif base not in READ_ONLY_COMMANDS:
            return ExecutionResult(status="error", error_code="403",
                                   message=f"命令 '{base}' 不在 terminal_view 白名单中（只读工具）")
        # 白名单挡的是"命令名"，挡不住"参数指向哪"：tree C:\\Users 会递归列出主目录，
        # git diff --no-index A B 会直接打印两个项目外文件的内容。参数级检查在这里补。
        if self.confine_files:
            escaping = next((p for p in parts[1:] if self._escapes_project(p)), None)
            if escaping is not None:
                return ExecutionResult(status="error", error_code="403",
                                       message=f"路径越界：terminal_view 的路径参数必须在项目目录内: {escaping}")
        try:
            result = subprocess.run(parts, capture_output=True, text=True, timeout=30,
                                    cwd=str(self.project_root), shell=False,
                                    stdin=subprocess.DEVNULL)
            return ExecutionResult(status="success", data={
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            })
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504", message="命令执行超时（30 秒）")
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))

    # terminal_exec 破坏性/持久化命令模式。
    # 说明：shell 无法用白名单覆盖（编程场景要跑任意构建命令），所以这里只做
    # "已知高危动作"拦截，属于减小误伤面的止血层，不是完备边界。
    # 真正的隔离依赖两点：默认 readonly 权限 + 容器/低权限账户运行（见 README）。
    _DANGEROUS_CMD_PATTERNS = (
        # 递归删除只在目标是"根本身"时拦。
        # 拦：rm -rf /  rm -rf ~  rm -rf *  rm -rf .  rm -rf D:\
        # 放行：rm -rf node_modules / rm -rf D:\学习\build / rm -rf ~/proj/dist
        #       —— 这些是正常清理，误伤它们等于工具不可用。
        (r"\brm\s+(-[a-z]+\s+)*-[a-z]*[rf][a-z]*\s+(/|~|\*|\.|[a-z]:[\\/]?)(\s*$|\s|[\\/]?\*)",
         "递归删除根目录/主目录/通配目标"),
        (r"\b(del|rd)\s+(/[a-z]\s+)*([a-z]:[\\/]?\s*$|[a-z]:[\\/]\*)", "删除盘符根目录"),
        (r"\bformat\s+[a-z]:", "格式化磁盘"),
        (r"\bmkfs\b", "格式化文件系统"),
        (r"\bdd\s+.*\bof=/dev/", "裸设备写入"),
        # 要求处于命令位置，否则 git commit -m "fix reboot bug" 会被误伤
        (r"(^|&&|;|\|)\s*(shutdown|reboot|halt|poweroff)\b", "关机/重启"),
        (r"\breg\s+add\b.*currentversion.{0,2}run", "注册表自启动"),
        (r"\bschtasks\s+/create\b", "计划任务持久化"),
        (r"\b(curl|wget|iwr|invoke-webrequest)\b[^|]*\|\s*(sh|bash|zsh|python|powershell)",
         "下载后直接执行"),
        (r"\bpowershell\b[^|]*\s-e(nc|ncoded|ncodedcommand)?\s", "编码后的 PowerShell 命令"),
        (r"\bchmod\s+(-r\s+)?777\s+/(\s|$)", "放开根目录权限"),
        (r":\(\)\s*\{.*\}\s*;", "fork bomb"),
    )

    def _screen_exec_command(self, cmd: str) -> Optional[str]:
        """terminal_exec 前置筛查：命中敏感目标或已知破坏性动作时返回拒绝原因"""
        low = cmd.lower()
        for pattern, label in self._DANGEROUS_CMD_PATTERNS:
            if re.search(pattern, low):
                return f"命令包含高危动作（{label}）"
        # 敏感目标（凭据/自启动/系统目录）：逐 token 判定，覆盖未展开的
        # %USERPROFILE%\.ai_code.json、~/.ssh/authorized_keys 这类写法
        for token in re.split(r"[\s'\"=]+", cmd):
            if not token or len(token) < 3:
                continue
            reason = sensitive_target(token)
            if reason:
                return f"命令触及敏感目标（{reason}）: {token}"
        return None

    def _exec_terminal_exec(self, params: Dict) -> ExecutionResult:
        """写入权限下的真实终端执行（受权限门 + 前置筛查 + 快照回滚保护）"""
        cmd = (params.get("command") or "").strip()
        if not cmd:
            return ExecutionResult(status="error", error_code="400", message="command 参数为空")
        if len(cmd) > MAX_COMMAND_LENGTH:
            return ExecutionResult(status="error", error_code="400", message="命令过长")
        denied = self._screen_exec_command(cmd)
        if denied:
            return ExecutionResult(status="error", error_code="403",
                                   message=f"{denied}，已拦截。如确需执行请在终端手动操作。")
        # docker 沙箱：启用后命令跑在一次性容器里，宿主拿不到。这是这个工具唯一
        # 真正的边界——shell=True 的宿主分支靠 cwd 和正则黑名单是拦不住的。
        # 注意不做静默回退：沙箱开了但 docker 挂了就报 503，绝不偷偷改回宿主执行，
        # 否则用户以为在容器里跑，实际在自己机器上跑，而且毫无提示。
        if self.docker_sandbox is not None:
            try:
                out = self.docker_sandbox.run_shell(cmd)
            except DockerUnavailable as e:
                return ExecutionResult(
                    status="error", error_code="503",
                    message=(f"docker 沙箱不可用（{e}），已拒绝执行。"
                             "启动 Docker 后重试，或用 --sandbox off 显式改回宿主执行。"))
            if out["timeout"]:
                return ExecutionResult(status="error", error_code="504",
                                       message=out["stderr"])
            return ExecutionResult(status="success", data={
                "stdout": out["stdout"],
                "stderr": out["stderr"],
                "returncode": out["returncode"],
                "sandbox": {"kind": "docker", "image": self.docker_sandbox.image,
                            "network": self.docker_sandbox.network,
                            "mount": "/work"},
            })
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                    timeout=30, cwd=str(self.project_root),
                                    stdin=subprocess.DEVNULL)
            return ExecutionResult(status="success", data={
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            })
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504", message="命令执行超时（30 秒）")
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))


    def _exec_open_file(self, params: Dict) -> ExecutionResult:
        """对话内打开文件：默认返回可点击链接（用户点击后全屏查看）；
        auto_open=true 时立即用系统默认程序打开"""
        path_str = str(params.get("path", "")).strip()
        if not path_str:
            return ExecutionResult(status="error", error_code="400", message="path 参数为空")
        p = self._resolve_read_path(path_str)
        if not p.exists():
            return ExecutionResult(status="error", error_code="404", message=f"文件不存在: {p}")
        if p.is_dir():
            # 目录：立即在系统文件管理器中打开（如"打开桌面文件夹"）
            try:
                if os.name == "nt":
                    os.startfile(str(p))
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", str(p)])
                else:
                    subprocess.Popen(["xdg-open", str(p)])
            except Exception as e:
                return ExecutionResult(status="error", error_code="500",
                                       message=f"打开文件夹失败: {e}")
            return ExecutionResult(status="success", data={
                "path": str(p), "opened": True, "is_dir": True,
                "hint": "已在系统文件管理器中打开该文件夹"})
        if not bool(params.get("auto_open", False)):
            # 默认收起：只给链接，用户点击才打开
            return ExecutionResult(status="success", data={
                "path": str(p), "opened": False, "link": p.as_uri(),
                "hint": "已生成可点击链接，用户点击后即可全屏查看"})
        try:
            if os.name == "nt":
                os.startfile(str(p))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
        except Exception as e:
            # Windows 上 .py 等常无关联默认程序：文本类文件回退记事本
            if os.name == "nt" and p.suffix.lower() in _TEXT_EXTENSIONS:
                try:
                    subprocess.Popen(["notepad.exe", str(p)])
                    return ExecutionResult(status="success", data={
                        "path": str(p), "opened": True, "editor": "notepad",
                        "hint": "该类型无默认打开程序，已用记事本打开"})
                except Exception as e2:
                    return ExecutionResult(status="error", error_code="500",
                                           message=f"打开失败（记事本回退也失败）: {e2}")
            return ExecutionResult(status="error", error_code="500", message=f"打开失败: {e}")
        return ExecutionResult(status="success", data={"path": str(p), "opened": True})

    def _exec_edit_file(self, params: Dict) -> ExecutionResult:
        """对话内编辑文件：优先 VS Code（code 命令），否则回退系统默认程序"""
        path_str = str(params.get("path", "")).strip()
        if not path_str:
            return ExecutionResult(status="error", error_code="400", message="path 参数为空")
        p = self._resolve_read_path(path_str)
        if not p.exists():
            return ExecutionResult(status="error", error_code="404",
                                   message=f"文件不存在: {p}（可先用 file_write 创建）")
        if p.is_dir():
            # 目录：在系统文件管理器中打开
            try:
                if os.name == "nt":
                    os.startfile(str(p))
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", str(p)])
                else:
                    subprocess.Popen(["xdg-open", str(p)])
            except Exception as e:
                return ExecutionResult(status="error", error_code="500",
                                       message=f"打开文件夹失败: {e}")
            return ExecutionResult(status="success", data={
                "path": str(p), "opened": True, "is_dir": True,
                "hint": "已在系统文件管理器中打开该文件夹"})
        code = shutil.which("code")
        if code:
            try:
                subprocess.Popen([code, str(p)])
                return ExecutionResult(status="success",
                                       data={"path": str(p), "editor": "vscode"})
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=f"打开失败: {e}")
        try:
            if os.name == "nt":
                os.startfile(str(p))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
        except Exception as e:
            # Windows 上 .py 等常无关联默认程序：文本类文件回退记事本
            if os.name == "nt" and p.suffix.lower() in _TEXT_EXTENSIONS:
                try:
                    subprocess.Popen(["notepad.exe", str(p)])
                    return ExecutionResult(status="success", data={
                        "path": str(p), "editor": "notepad",
                        "hint": "该类型无默认打开程序，已用记事本打开"})
                except Exception as e2:
                    return ExecutionResult(status="error", error_code="500",
                                           message=f"打开失败（记事本回退也失败）: {e2}")
            return ExecutionResult(status="error", error_code="500", message=f"打开失败: {e}")
        return ExecutionResult(status="success", data={"path": str(p), "editor": "system_default"})

