#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.code_tools —— 代码执行沙盒与计算工具（code_execute / math_calc / datetime_now）"""

import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict

from tools.base import MAX_CODE_LENGTH
from tools.docker_sandbox import DockerUnavailable
from tools.result import ExecutionResult



class CodeTools:
    DANGEROUS_CALLS = {
        "os.system", "os.popen", "os.spawnl", "os.spawnv", "os.execl", "os.execv",
        "subprocess.call", "subprocess.run", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "socket.socket", "socket.connect", "socket.create_connection",
        "shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    }
    # 整模块禁用导入（含别名导入、from x import y）。
    # 注意：黑名单枚举不可能闭合——补掉一批等价物只是抬高门槛，不是边界。
    # nt 是 CPython 内建（os.system 实际就是 nt.system）；pathlib 能绕过 open() 拦截
    # （Path.write_text）；runpy/webbrowser 都能触发外部执行。
    DANGEROUS_MODULES = {"subprocess", "socket", "ctypes", "os", "nt", "shutil",
                         "importlib", "pickle", "marshal", "multiprocessing",
                         "pty", "builtins", "sys", "pathlib", "runpy",
                         "webbrowser", "posix"}
    DANGEROUS_FUNCS = {"eval", "exec", "compile", "__import__",
                       "globals", "locals", "vars", "getattr", "setattr",
                       "delattr", "input", "breakpoint"}
    DANGEROUS_NAMES = {"__builtins__", "__loader__", "__spec__", "__import__"}
    DANGEROUS_ATTRS = {"__class__", "__bases__", "__subclasses__", "__globals__",
                       "__mro__", "__builtins__", "__code__", "__dict__"}

    @staticmethod
    def _qualname(node) -> str:
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))

    def _scan_dangerous_calls(self, code: str) -> str:
        """策略层沙箱 AST 扫描：拦截危险导入/调用/内建逃逸，返回拦截描述（空串 = 通过）

        注意：这是进程内静态策略层，不是 OS 级隔离；生产环境请配合容器/虚拟机使用。
        """
        try:
            import ast
            tree = ast.parse(code)
        except SyntaxError:
            return ""   # 语法错误交给 ASTDetector 报告
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in self.DANGEROUS_MODULES:
                        return f"沙箱禁止导入模块: {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in self.DANGEROUS_MODULES:
                    return f"沙箱禁止导入模块: {node.module}"
            elif isinstance(node, ast.Name):
                if node.id in self.DANGEROUS_NAMES:
                    return f"沙箱禁止访问内建对象: {node.id}"
            elif isinstance(node, ast.Attribute):
                if node.attr in self.DANGEROUS_ATTRS:
                    return f"沙箱禁止访问: .{node.attr}"
            elif isinstance(node, ast.Call):
                name = ""
                f = node.func
                if isinstance(f, ast.Name):
                    name = f.id
                elif isinstance(f, ast.Attribute):
                    name = self._qualname(f)
                if name in self.DANGEROUS_CALLS or name in self.DANGEROUS_FUNCS:
                    return f"沙箱禁止调用: {name}"
                if name == "open":
                    return "沙箱内禁止使用 open()（文件读写请使用 file_read/file_write 工具）"
        return ""

    def _exec_code_execute(self, params: Dict) -> ExecutionResult:
        """代码执行（受限沙箱：AST 危险调用拦截 + 临时目录 + 环境变量清洗 + 超时）"""
        lang = params.get("language", "python")
        code = params.get("code", "")
        if lang != "python":
            return ExecutionResult(status="error", error_code="400",
                                   message=f"暂不支持语言: {lang}")
        if not code.strip():
            return ExecutionResult(status="error", error_code="400", message="code 参数为空")
        if len(code) > MAX_CODE_LENGTH:
            return ExecutionResult(status="error", error_code="400", message="代码过长（上限 100KB）")

        # 沙箱 1：AST 危险调用拦截
        denied = self._scan_dangerous_calls(code)
        if denied:
            return ExecutionResult(status="error", error_code="403", message=denied)

        # docker 沙箱：整段代码丢进一次性容器，内存 / 进程数 / 网络都由内核约束。
        # 这里刻意保留上面的 AST 扫描：docker 可用性是运行时探测出来的，万一探测
        # 判断错了、或者镜像被换成没有隔离能力的东西，放宽黑名单就等于把一个检测
        # bug 直接变成逃逸口。两道一起留着，代价只是容器里也用不了 os/subprocess。
        if self.docker_sandbox is not None:
            try:
                out = self.docker_sandbox.run_python(code)
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
                            "memory": self.docker_sandbox.memory,
                            "timeout": self.docker_sandbox.timeout},
            })

        import subprocess

        import uuid
        base = Path(self.sandbox_base) if self.sandbox_base else Path(tempfile.gettempdir())
        sandbox_dir = base / f"agent_sandbox_{uuid.uuid4().hex[:8]}"
        try:
            sandbox_dir.mkdir(parents=True)
        except Exception as e:
            return ExecutionResult(status="error", error_code="500",
                                   message=f"沙箱目录创建失败: {e}")
        tmp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False,
                                             encoding="utf-8", dir=sandbox_dir) as f:
                f.write(code)
                tmp_file = f.name
            # 沙箱 2：最小环境变量（剥离密钥/代理等敏感信息）
            minimal_env = {
                "PATH": os.environ.get("PATH", ""),
                "SystemRoot": os.environ.get("SystemRoot", ""),
                "WINDIR": os.environ.get("WINDIR", ""),
                "TEMP": str(sandbox_dir),
                "TMP": str(sandbox_dir),
                "COMSPEC": os.environ.get("COMSPEC", ""),
                "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": "",
            }
            # 沙箱 3：临时工作目录（相对路径写入落在沙箱内）+ 超时
            result = subprocess.run(
                [sys.executable, tmp_file],
                capture_output=True, text=True, timeout=30,
                cwd=sandbox_dir, env=minimal_env, shell=False,
                stdin=subprocess.DEVNULL
            )
            return ExecutionResult(status="success", data={
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "sandbox": {"cwd": str(sandbox_dir), "env_stripped": True, "timeout": 30}
            })
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504", message="代码执行超时（30 秒）")
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))
        finally:
            if tmp_file:
                try:
                    os.unlink(tmp_file)
                except OSError:
                    pass
            try:
                shutil.rmtree(sandbox_dir, ignore_errors=True)
            except Exception:
                pass

    # ---------- 真实联网搜索（DuckDuckGo → Bing 兜底，无需 API Key） ----------

    def _exec_math_calc(self, params: Dict) -> ExecutionResult:
        expression = str(params.get("expression", ""))
        denied = self._scan_math_expression(expression)
        if denied:
            return ExecutionResult(status="error", error_code="403", message=denied)
        try:
            result = eval(expression, {"__builtins__": {}}, {})
            return ExecutionResult(status="success", data={"result": result, "expression": expression})
        except Exception as e:
            return ExecutionResult(status="error", error_code="400", message=str(e))

    @staticmethod
    def _scan_math_expression(expression: str) -> str:
        """白名单 AST 校验：只允许纯算术表达式，防任意代码执行与指数 DoS"""
        if not expression or len(expression) > 200:
            return "表达式为空或过长（上限 200 字符）"
        try:
            import ast as _ast
            tree = _ast.parse(expression, mode="eval")
        except SyntaxError:
            return ""   # 语法错误交给 eval 返回 400
        ALLOWED_NODES = (_ast.Expression, _ast.Constant)
        # 运算符节点放行（安全性由 BinOp/UnaryOp 级别的特判把关）
        ALLOWED_OPS = (_ast.Add, _ast.Sub, _ast.Mult, _ast.Div,
                       _ast.FloorDiv, _ast.Mod, _ast.Pow, _ast.UAdd, _ast.USub)
        for node in _ast.walk(tree):
            if isinstance(node, ALLOWED_NODES) or isinstance(node, ALLOWED_OPS):
                continue
            if isinstance(node, (_ast.BinOp, _ast.UnaryOp)):
                if isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.Pow):
                    def _small(n):
                        return (isinstance(n, _ast.Constant)
                                and isinstance(n.value, (int, float))
                                and abs(n.value) <= 100)
                    if _small(node.left) and _small(node.right) \
                            and abs(node.right.value) <= 1000:
                        continue
                    return "幂运算仅支持 100^1000 以内的常量运算"
                continue
            return f"math_calc 只允许纯算术表达式，禁止: {type(node).__name__}"
        return ""

    def _exec_datetime_now(self, params: Dict) -> ExecutionResult:
        from datetime import datetime
        fmt = params.get("format", "%Y-%m-%d %H:%M:%S")
        # 支持 prompt 中的 "YYYY-MM-DD HH:mm:ss" 友好格式
        fmt = (str(fmt)
               .replace("YYYY", "%Y").replace("DD", "%d").replace("HH", "%H")
               .replace("MM", "%m").replace("mm", "%M").replace("ss", "%S"))
        try:
            now = datetime.now().strftime(fmt)
        except ValueError as e:
            return ExecutionResult(status="error", error_code="400", message=str(e))
        return ExecutionResult(status="success", data={"datetime": now})

