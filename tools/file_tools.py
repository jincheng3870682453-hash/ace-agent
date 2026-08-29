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

import ace_execpolicy as execpolicy
from tools.base import (GIT_READONLY_SUBCOMMANDS, MAX_COMMAND_LENGTH,
                        READ_ONLY_COMMANDS, SHELL_META_RE,
                        VERSION_ONLY_COMMANDS, VERSION_SUBCOMMANDS,
                        sensitive_target)
from tools.docker_sandbox import DockerUnavailable
from tools.result import ExecutionResult


# Windows cmd 的内建命令：不是磁盘上的可执行文件，argv + shell=False 调不起来。
# terminal_exec 的 allow 档据此决定走 argv 还是走 shell（见 _exec_terminal_exec）。
_CMD_BUILTIN_BASES = {"echo", "dir", "type", "cd", "copy", "move", "ren", "rename",
                      "md", "mkdir", "rd", "rmdir", "del", "erase", "ver",
                      "time", "date", "cls", "set"}

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
# 单行参与正则匹配的字符上限。和上面那个是两件事：那个管"回给模型多长"，
# 这个管"让模型的正则最多啃多长" —— re 没有超时，输入长度是唯一能收的那道界。
_SEARCH_MAX_MATCH_CHARS = 4_000

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
                # 防止"帮我看看桌面/主目录"这类问题因工具选择而失败。
                # 但"允许列目录"不等于"允许列任何目录"：~/.ssh 的**文件名单**本身就是
                # 情报（哪些主机有密钥、密钥叫什么），所以敏感目录连名单都不给。
                reason = sensitive_target(path)
                if reason:
                    return None, ExecutionResult(
                        status="error", error_code="403",
                        message=f"拒绝列出敏感目录（{reason}）: {path}。"
                                "目录名单本身也是凭据情报，如确需查看请在终端手动操作。")

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
        elif self._confined(path) is None:
            # 读工具走到这里只有一种情况：confine_files=False（项目边界被关掉了）。
            # 那道边界一关，`~/.ai_code.json` 里的明文 API key 就成了一次 file_read
            # 的距离 —— 所以边界没了也要留这道敏感目标检查，和 terminal_view 的 cat
            # 分支同一个理由、同一个口径。
            # 只对**项目外**的路径查：项目内还查的话，仓库里一个叫 credentials 的
            # 普通文件会被 `_SENSITIVE_BASENAMES` 误伤。
            reason = sensitive_target(path)
            if reason:
                return None, ExecutionResult(
                    status="error", error_code="403",
                    message=f"拒绝读取敏感目标（{reason}）: {path}。"
                            "即便关闭了 confine_files，凭据文件仍不经由工具读取。")
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
            # 读-改-写必须用严格解码：`_read_text_any` 的 errors="ignore" 兜底会丢字节，
            # 而这条路径会把结果写回磁盘 —— 丢掉的字节就永久没了，且模型只看到"替换成功"。
            content, src_encoding = self._read_text_exact(path)
        except UnicodeDecodeError as e:
            return ExecutionResult(
                status="error", error_code="400",
                message=f"无法确定文件编码，拒绝改写（避免有损重编码）: {path}（{e}）。"
                        "请先把文件转成 UTF-8，或在终端手动修改。")
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
            # 用读进来时的那个编码写回去。硬写 utf-8 等于顺手把用户的 GBK 源码
            # 转了码 —— 那是模型没被要求做、也没在 diff 里体现的改动。
            path.write_text(result_text.replace("\n", "\r\n") if crlf else result_text,
                            encoding=src_encoding)
        except (OSError, UnicodeEncodeError) as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))
        return ExecutionResult(status="success", data={
            "path": str(path), "replaced": replaced, "matched_by": matched_by,
            "encoding": src_encoding,
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

    def _search_visible(self, path: Path) -> bool:
        """这条检索命中可以交出去吗？

        `_search_root` 只约束了**起点**，约束不了**落点**，而检索有两条绕过它的路：

        - `glob` 的 pattern 里带 `..`（`glob("../*.py")`）—— 起点合法，命中在项目外；
        - 项目内的软链接指向项目外（`link → ~/.ssh/id_rsa`）—— `os.walk` 不会下降到
          目录软链接，但文件软链接会被当成普通文件产出。

        两条都能让 readonly 会话把项目外的东西读走，而 grep/glob 属于 READ_TOOLS。
        所以每条命中都要在**解析软链接之后**重新确认落点（`_confined` 内部会 resolve）。

        项目内也可能躺着凭据（误提交的 .pem、复制进来的 .ai_code.json），所以还要过
        一遍 `sensitive_target` —— 与 terminal_view 的 cat 分支保持同一口径。
        """
        if self._confined(path) is None:
            return False
        return sensitive_target(path) is None

    def _iter_search_files(self, root: Path, name_filters: List[str],
                           stats: Optional[Dict] = None) -> Iterator[Path]:
        """遍历检索范围内的候选文件（跳过依赖/构建目录，限制总数）

        `stats` 是给调用方回传"为什么停下来"的出口：命中 `_SEARCH_MAX_FILES` 上限时
        置 `stats["file_cap"] = True`。没有这个出口的话，扫了一半就返回和扫完了在
        调用方看来一模一样，模型会把"没搜到"读成"这个符号不存在"。
        """
        if root.is_file():
            if self._search_visible(root):
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
                    if stats is not None:
                        stats["file_cap"] = True
                    return
                f = Path(dirpath) / name
                if not self._search_visible(f):
                    continue
                yield f


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
        stats: Dict[str, Any] = {}
        for f in self._iter_search_files(root, filters, stats):
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
                # 只在行首 _SEARCH_MAX_MATCH_CHARS 个字符里匹配。这是给模型自带正则
                # 上的一道时间界：Python 的 re 没有超时，灾难性回溯（`(a+)+$` 撞上长行）
                # 会把整个工具调用挂死，而 pattern 完全由模型给。限住输入长度不能消除
                # 回溯，但能把它的上界从"行有多长"压到一个常数。
                if regex.search(line[:_SEARCH_MAX_MATCH_CHARS]):
                    matches.append(f"{rel}:{lineno}: {line.strip()[:_SEARCH_MAX_LINE_CHARS]}")
                    if len(matches) >= max_results:
                        truncated = True
                        break
            if truncated:
                break

        # 两种截断要分开说：撞 max_results 是"结果太多"，撞文件数上限是"根本没扫完"。
        # 后者尤其要如实回报 —— 否则模型看到"（无匹配）"会得出"这个符号不存在"。
        file_cap = bool(stats.get("file_cap"))
        body = "\n".join(matches) if matches else f"（无匹配：{pattern}）"
        if truncated:
            body += f"\n... [已截断：达到 max_results={max_results}，请缩小范围或加 glob 过滤]"
        if file_cap:
            body += (f"\n... [扫描未完成：遍历文件数达到上限 {_SEARCH_MAX_FILES}，"
                     "本次结果不完整。请用 path 缩小起点或加 glob 过滤后重试]")
        return ExecutionResult(status="success", data={
            "content": body, "matches": matches, "match_count": len(matches),
            "files_scanned": files_scanned, "truncated": truncated or file_cap,
            "scan_incomplete": file_cap,
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
        # `..` 直接拒绝，不靠后面的落点复检兜着。复检会把越界命中静静丢掉，模型看到的
        # 是"没匹配到"，然后它会换个写法再试一次 —— 与其让它猜，不如告诉它这条路不通。
        if ".." in Path(pattern.replace("\\", "/")).parts:
            return ExecutionResult(status="error", error_code="403",
                                   message="glob 的 pattern 不允许包含 ..（检索不给越界能力）；"
                                           "起点目录请用 path 参数，且必须在项目目录内")
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
                # 落点复检：pattern 里的 `..` 已经在上面挡掉了，但软链接还能把命中带到
                # 项目外，而且 `_rel()` 越界时会退化成绝对路径原样输出。
                if not self._search_visible(p):
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

    # terminal_exec 的判定整体搬到了 ace_execpolicy（三值判定 + 纯函数），
    # 原来那张 _DANGEROUS_CMD_PATTERNS 表已被它的 _FORBIDDEN_RULES 覆盖并扩展
    # （多了卷影副本删除、bcdedit、账户/ACL 变更、certutil/bitsadmin/mshta 下载器、
    # 服务与 crontab 持久化、关闭 Defender/防火墙、注册表 hive 删除）。
    # 留在这里的只有 execpolicy 没有的那一层：敏感目标扫描，见 _evaluate_exec_command。


    def _evaluate_exec_command(self, cmd: str) -> "execpolicy.Verdict":
        """terminal_exec 判定：execpolicy 三值判定 + 敏感目标扫描

        两层是**互补**的，不是重复：

        - `ace_execpolicy` 管"这个动作本身有多坏"——不可逆删除、格式化、持久化、
          下载即执行、关闭防御。它是纯函数，所以每条拒绝路径都能被单测覆盖，
          不必真的把 `format C:` 跑起来。
        - `sensitive_target()` 管"这条命令碰的是什么"——凭据文件、私钥、自启动
          目录、系统目录。execpolicy 里**没有**这一层。

        所以不能整份换过去。`type %USERPROFILE%\\.ai_code.json` 在 execpolicy 眼里
        只是"含 shell 元字符"（`%`）→ prompt 档，人点一下 y 凭据就出去了；
        而它在这里必须是 forbidden —— 无论谁点头都不执行。
        """
        verdict = execpolicy.evaluate_command(cmd, str(self.project_root),
                                              sandbox=self.sandbox_policy)
        if verdict.forbidden:
            return verdict
        # 逐 token 判定，覆盖未展开的 %USERPROFILE%\.ai_code.json、
        # ~/.ssh/authorized_keys 这类写法（展开后再看就晚了）
        for token in re.split(r"[\s'\"=]+", cmd):
            if not token or len(token) < 3:
                continue
            reason = sensitive_target(token)
            if reason:
                return execpolicy.Verdict(
                    execpolicy.DECISION_FORBIDDEN,
                    f"命令触及敏感目标（{reason}）: {token}",
                    "sensitive_target",
                    normalized=verdict.normalized,
                    hits=list(verdict.hits) + [
                        ("sensitive_target", execpolicy.DECISION_FORBIDDEN, reason)])
        return verdict


    @staticmethod
    def _is_cmd_builtin(argv0: str) -> bool:
        """argv[0] 是不是 Windows cmd 的内建命令（因而只能经 shell 跑）。

        宿主分支和 Go 执行器分支都要问这一句，所以抽出来：两边答案不一致的话，
        同一条 `echo ok` 会在一条路上跑通、在另一条路上 spawn 失败。
        """
        if os.name != "nt":
            return False
        base = argv0.lower()
        if base.endswith(".exe"):
            base = base[:-4]
        return base in _CMD_BUILTIN_BASES

    def _exec_via_go(self, cmd: str, verdict: "execpolicy.Verdict",
                     approved: bool) -> Optional[ExecutionResult]:
        """把命令交给 Go 执行器执行。返回 None = 这条路走不了，由调用方决定后果。

        返回 ExecutionResult 的情况有两种，都不该被重试：执行成功，以及执行器
        **明确拒绝**（策略复检不通过、超时、沙箱不可用）。拿到拒绝之后回落到宿主
        重跑，等于绕过它刚刚给出的拒绝。
        """
        client = self._go_executor()
        if client is None:
            return None
        import ace_executor as _ax
        want_tier = _ax.TIER_JOB_OBJECT if self.sandbox_mode == "job" else None
        if want_tier and want_tier not in client.sandbox_available():
            return None   # 本平台没有 Tier-1（非 Windows），交回调用方

        # allow 档有干净的 argv，压根不经 shell。prompt 档（已获批准）往往正是靠
        # 管道/重定向才需要 shell，这时把整条字符串作为**单个** argv 元素交给平台
        # shell —— 让 shell 跑在边界**里面**。
        #
        # 这不是把命令注入放回来：这条字符串刚刚由人逐字看过并点头，而边界是 Job
        # Object，不是"没有 shell"。job 档下如果因为"执行器只收 argv"就把这类命令
        # 踢回宿主，边界就等于没有 —— 那比让 shell 在 Job 里跑坏得多。
        #
        # 例外是 cmd 内建命令（echo / dir / type ...）：它们不是磁盘上的可执行文件，
        # 执行器按 argv[0] 去 PATH 里找必然 E_SPAWN_FAILED。宿主分支早就有这一层
        # （见 _CMD_BUILTIN_BASES 与 _exec_terminal_exec 结尾），这里必须同样处理，
        # 否则 `echo ok` 这种最普通的 allow 档命令一进执行器就挂。
        if verdict.allowed and verdict.argv and not self._is_cmd_builtin(verdict.argv[0]):
            argv = list(verdict.argv)
        elif os.name == "nt":
            argv = ["cmd", "/c", cmd]
        else:
            argv = ["/bin/sh", "-c", cmd]

        try:
            out = client.exec_command(
                argv, cwd=str(self.project_root), tier=want_tier,
                # job 档不许降档：允许降档等于"用户要了 Job Object，实际拿到 tier0"，
                # 而他不会知道。off 档无所谓，那本来就没承诺任何边界。
                allow_weaker_tier=(self.sandbox_mode != "job"),
                policy=_ax.verdict_to_policy(verdict, user_approved=approved))
        except _ax.ExecutorError as e:
            if e.code == "E_TRANSPORT" and self.sandbox_mode != "job":
                # 会话本身断了，不是执行器在拒绝。off 档没承诺边界，回落到宿主。
                self.use_go_executor = False
                self._go_client = None
                return None
            if e.code == "E_SPAWN_FAILED" and self.sandbox_mode != "job":
                # 进程压根没起来（argv[0] 不在 PATH 上），既不是策略拒绝也不是边界失效，
                # 回落到宿主重跑不构成"绕过拒绝"——什么都还没执行。宿主的 shell=True
                # 能多认一些东西（.bat / .cmd / doskey），认不出来也会给出更好读的报错。
                # 注意这里**不**关掉执行器：这是单条命令的事，不是会话级故障。
                return None
            return ExecutionResult(

                status="error", error_code=e.http_like,
                message=f"Go 执行器拒绝或终止了该命令：{e.message}",
                metadata={"executor": {"code": e.code, "data": e.data}})
        except Exception:
            if self.sandbox_mode == "job":
                return None
            self.use_go_executor = False
            self._go_client = None
            return None

        if self.sandbox_mode == "job" and out.degraded:
            # 只部分生效就报错。给出一个自己都不确定的隔离保证，比明确说"做不到"更糟。
            return ExecutionResult(
                status="error", error_code="503",
                message=f"Job Object 只部分生效（{out.sandbox_applied}），已拒绝执行。")

        return ExecutionResult(status="success", data={
            "stdout": out.stdout,
            "stderr": out.stderr,
            "returncode": out.exit_code,
            "truncated": out.truncated,
            "executor": "go",
            "sandbox": out.sandbox_applied,
        })

    def _exec_terminal_exec(self, params: Dict) -> ExecutionResult:

        """写入权限下的真实终端执行（受权限门 + 三值判定 + 快照回滚保护）

        三条出口：
            forbidden → 403，任何审批都覆盖不了
            allow     → argv + shell=False 执行（不经 shell，元字符天然失效）
            prompt    → 问 approval_hook；无 hook 或被拒 → 403
        """
        cmd = (params.get("command") or "").strip()
        if not cmd:
            return ExecutionResult(status="error", error_code="400", message="command 参数为空")
        if len(cmd) > MAX_COMMAND_LENGTH:
            return ExecutionResult(status="error", error_code="400", message="命令过长")

        # 判定先行，且传的是原始 cmd：任何"先展开再判定"的顺序都会让判定看到的
        # 字符串与实际执行的不一致。
        verdict = self._evaluate_exec_command(cmd)
        if verdict.forbidden:
            return ExecutionResult(
                status="error", error_code="403",
                message=(f"命令被安全策略拒绝（{verdict.reason}），已拦截。"
                         f"如确需执行请在终端手动操作。"),
                metadata={"policy": {"decision": verdict.decision, "rule": verdict.rule}})

        approved = False
        if verdict.needs_approval:
            if self.approval_hook is None:
                # 无人可问 → 拒绝。方向必须朝安全：把非交互场景的默认答案写成 "y"
                # 正是 SEC-004 那类事故的成因。
                return ExecutionResult(
                    status="error", error_code="403",
                    message=(f"命令需要人工确认但当前无审批通道：{verdict.reason}。"
                             f"可改用只读的 terminal_view，或拆成不含 shell 元字符的单条命令。"),
                    metadata={"policy": {"decision": verdict.decision, "rule": verdict.rule,
                                         "approval": "unavailable"}})
            try:
                approved = bool(self.approval_hook(verdict))
            except Exception as e:
                # 只把异常**类型**给模型：hook 由上层注入，它的异常文本不受本层控制，
                # 完全可能把路径甚至凭据带进来（FileNotFoundError 的 str 就带路径）。
                return ExecutionResult(
                    status="error", error_code="500",
                    message=f"审批回调异常（{type(e).__name__}），按拒绝处理",
                    metadata={"error": {"action": "approval_hook",
                                        "type": type(e).__name__, "detail": str(e)},
                              "policy": {"decision": verdict.decision, "rule": verdict.rule}})
            if not approved:
                return ExecutionResult(
                    status="error", error_code="403",
                    message=f"用户拒绝执行：{verdict.reason}",
                    metadata={"policy": {"decision": verdict.decision, "rule": verdict.rule,
                                         "approval": "denied"}})

        ok, why = execpolicy.should_execute(verdict, self.approval_policy,
                                           user_approved=approved)
        if not ok:
            return ExecutionResult(
                status="error", error_code="403", message=f"命令未获执行许可：{why}",
                metadata={"policy": {"decision": verdict.decision, "rule": verdict.rule}})

        # docker 沙箱：启用后命令跑在一次性容器里，宿主拿不到。这是这个工具唯一
        # 真正的边界——shell=True 的宿主分支靠判定层是拦不住一切的。
        # 注意不做静默回退：沙箱开了但 docker 挂了就报 503，绝不偷偷改回宿主执行，
        # 否则用户以为在容器里跑，实际在自己机器上跑，而且毫无提示。
        # 容器只接受 shell 字符串，所以这里不分 allow / prompt 档。
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
            denied = bool(out.get("sandbox_denied"))
            return ExecutionResult(status="success", data={
                "stdout": out["stdout"],
                "stderr": out["stderr"],
                "returncode": out["returncode"],
                "sandbox_denied": denied,
                "sandbox": {"kind": "docker", "image": self.docker_sandbox.image,
                            "network": self.docker_sandbox.network,
                            "mount": "/work",
                            "denied_hint": ("沙箱策略拒绝（只读根文件系统/权限），"
                                            "不是命令失败——请改用不触碰该边界的方式"
                                            if denied else None)},
            })

        # Go 执行器：Tier-1 Job Object。docker 之后、宿主之前。
        #
        # 它解决的是 docker 解决不了的那个场景：docker 没装 / 没起来的机器上，
        # 宿主直跑连"把整棵进程树收干净"都做不到 —— Python 的 Process.Kill() 只杀
        # 直接子进程，孙进程会变孤儿继续跑。Job Object 是 OS 原语，Python 侧拿不到，
        # 这是把执行搬出进程的唯一理由；判定仍然在上面的 execpolicy 完成。
        if self.sandbox_mode == "job" or (verdict.allowed and verdict.argv):
            go_result = self._exec_via_go(cmd, verdict, approved)
            if go_result is not None:
                return go_result
            if self.sandbox_mode == "job":
                # job 档要的就是这个边界。拿不到就报错，绝不静默回落到宿主 ——
                # 和 docker 那条同一个原则：用户以为在 Job 里跑、实际在自己机器上跑，
                # 而且毫无提示，是最坏的一种"能用"。
                return ExecutionResult(
                    status="error", error_code="503",
                    message=("Job Object 沙箱不可用（执行器未编译、起不来，或本平台"
                             "不支持 Tier-1），已拒绝执行。在 executor/ 下跑 "
                             "`go build -o ace-executor.exe .`，或用 --sandbox off "
                             "显式改回宿主执行。"))


        # 不经 shell 则连"万一漏了一个元字符"的余地也没有。
        # 例外是 Windows 的 cmd 内建命令（echo / dir / type / copy / md ...）——
        # 它们不是可执行文件，argv + shell=False 会得到 FileNotFoundError。
        # 这类命令交给 shell 是安全的：元字符在第 2 关就已经被排除干净了。
        target: Any = cmd
        use_shell = True
        if verdict.allowed and verdict.argv and not self._is_cmd_builtin(verdict.argv[0]):
            target, use_shell = verdict.argv, False

        try:
            result = subprocess.run(target, shell=use_shell, capture_output=True, text=True,
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

