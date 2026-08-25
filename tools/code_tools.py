#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.code_tools —— 代码执行沙盒与计算工具（code_execute / math_calc / datetime_now）"""

import ast
import math
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
from tools.result import DenialKind, ExecutionResult

# ---------------------------------------------------------------------------
# math_calc 的自实现 AST 求值器：把 `eval` 从进程里彻底删掉（ADR-002 收尾项）
#
# 原实现是「白名单 AST 校验 + eval」。那个组合当时站得住，但它的安全性依赖
# 「校验器枚举到的节点集合 == eval 实际会执行的节点集合」这条**人工维护的等式**：
# 校验器漏放一类节点，eval 就会照常执行它。Python 每升一个小版本都可能新增
# 表达式节点（f-string 的 FormattedValue、海象、模式匹配……），等式迟早失衡，
# 而失衡的方向永远是「多执行了一点」。
#
# 自实现求值器把方向反过来：**没有显式写进 dispatch 表的节点，根本没有执行路径**。
# 新节点类型的默认结局是 raise，而不是被执行。这不是多一层防护，而是换掉了
# 「安全靠不漏」的前提 —— 也顺手让 `eval` 这个词从整个 tools/ 里消失，
# 静态扫描（含本项目 code_execute 自己的 eval 拦截规则）不再需要为它开例外。
#
# 保留 _scan_math_expression 不是冗余：它先给出**可读的 403 拒绝理由**
# （"禁止: Call"），求值器只负责在真的走到那里时也不执行。判据重复、职责不同。
_MATH_BINOPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
}
_MATH_UNARYOPS = {
    ast.UAdd: lambda a: +a,
    ast.USub: lambda a: -a,
}
# 幂运算的上界与 _scan_math_expression 里一致（100^1000）。故意重复一遍：
# 前置校验器只在语法层看常量，求值器在值层再看一次 —— 少写一处也不能让 DoS 过去。
_MATH_POW_BASE_MAX = 100
_MATH_POW_EXP_MAX = 1000
# 递归深度上限。表达式已限长 200 字符，正常输入到不了这里（200 字符最多堆出
# 百来层嵌套）；它的作用是万一长度上限被改大，求值器自己仍不会打爆 Python 栈。
_MATH_MAX_DEPTH = 256
# 结果整数位宽上限（约 4200 位十进制），略低于 CPython 的 int→str 4300 位硬限制。
_MATH_MAX_RESULT_BITS = 14000


def eval_math_ast(node: ast.AST, depth: int = 0) -> Any:
    """纯算术求值：只认字面量数字与八种算符，其余一律 raise ValueError。"""
    if depth > _MATH_MAX_DEPTH:
        raise ValueError(f"表达式嵌套过深（上限 {_MATH_MAX_DEPTH} 层）")

    if isinstance(node, ast.Expression):
        return eval_math_ast(node.body, depth + 1)

    if isinstance(node, ast.Constant):
        # bool 是 int 的子类，得先挡掉：math_calc 只做数字，不做真假值运算。
        # str/bytes 也在这里挡掉 —— 否则 "a" * 10**8 就是一条内存 DoS。
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise ValueError(f"math_calc 只支持整数与浮点字面量，不支持 {type(node.value).__name__}")
        return node.value

    if isinstance(node, ast.UnaryOp):
        handler = _MATH_UNARYOPS.get(type(node.op))
        if handler is None:
            raise ValueError(f"math_calc 不支持一元运算符: {type(node.op).__name__}")
        return handler(eval_math_ast(node.operand, depth + 1))

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        left = eval_math_ast(node.left, depth + 1)
        right = eval_math_ast(node.right, depth + 1)
        if op_type is ast.Pow:
            if abs(left) > _MATH_POW_BASE_MAX or abs(right) > _MATH_POW_EXP_MAX:
                raise ValueError(
                    f"幂运算仅支持 {_MATH_POW_BASE_MAX}^{_MATH_POW_EXP_MAX} 以内的运算")
            return left ** right
        handler = _MATH_BINOPS.get(op_type)
        if handler is None:
            raise ValueError(f"math_calc 不支持二元运算符: {op_type.__name__}")
        return handler(left, right)

    raise ValueError(f"math_calc 只允许纯算术表达式，禁止: {type(node).__name__}")


class CodeTools:
    # SEC-003：导入从**黑名单**改为**白名单**。
    #
    # 黑名单被实测绕过了 11 种：asyncio（create_subprocess_shell 直接 RCE）、pathlib
    # （write_text 任意写）、io、codecs、runpy、webbrowser、urllib …… 根因是枚举式黑名单
    # 只能封住"想到的"，而 stdlib 里能间接拿到 os / 子进程 / 网络的路径远超十几个。
    # 白名单把"没想到"的默认归为拒绝，这是唯一可论证的方向。
    #
    # 入选标准：纯计算 / 纯数据结构 / 纯格式化，不提供文件、进程、网络、导入能力。
    ALLOWED_MODULES = {
        # 数值与数学
        "math", "cmath", "decimal", "fractions", "statistics", "numbers", "random",
        # 数据结构与迭代
        "collections", "itertools", "functools", "operator", "heapq", "bisect",
        "array", "copy", "enum", "dataclasses", "typing", "types",
        # 文本与格式
        "string", "textwrap", "re", "unicodedata", "difflib", "pprint", "json",
        # 时间（time.sleep 最坏情况被 30 秒超时兜住）
        "datetime", "time", "calendar", "zoneinfo",
        # 编码与摘要（不含 pickle/marshal：反序列化即执行；不含 codecs：可拿到 open）
        "hashlib", "hmac", "base64", "binascii", "struct",
        # 其他纯函数工具
        "uuid", "abc", "contextlib", "warnings", "traceback",
    }
    DANGEROUS_CALLS = {

        "os.system", "os.popen", "os.spawnl", "os.spawnv", "os.execl", "os.execv",
        "subprocess.call", "subprocess.run", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "socket.socket", "socket.connect", "socket.create_connection",
        "shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    }
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
        # SEC-003：先收集所有"被直接调用"的 Name 节点。
        #
        # 为什么需要这一步：危险内建原先只在**调用点**按名字比对，于是
        #     g = eval; g("__import__('os').system('whoami')")
        #     f = open; f(r"C:/.../pwn.txt", "w")
        # 两条都能通过 —— 赋值语句里的 `eval` 是 ast.Name 而不是 ast.Call，
        # 而后面 `g(...)` 的函数名是 `g`，不在任何黑名单里。子进程用的是完整
        # builtins（下面只清洗了环境变量），所以别名拿到的就是真的 eval/open。
        #
        # 修法：把"引用"也当成危险行为，而不只是"调用"。但要区分两种上下文：
        #   Load  且不是某个 Call 的 func  → 取别名，拒绝
        #   Store（`input = 5` 这类遮蔽）  → 放行，遮蔽反而销毁了内建
        # 只看 Load 而不看 Store，是为了不把 `input = params["x"]` 这种正常代码判死。
        _called_names = {
            id(n.func) for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        # 为什么把 input 排除在外：它的危险性只体现在"调用"（阻塞等输入），别名本身
        # 拿不到任何能力，沙箱也没有 stdin。而 `input = 5; print(input)` 是很自然的
        # 变量名冲突 —— 为一个不存在的风险去误伤正常代码不值得。
        # globals/locals/vars 则必须留着：它们的别名等于命名空间逃逸的入口。
        _alias_forbidden = (self.DANGEROUS_FUNCS - {"input"}) | {"open"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top not in self.ALLOWED_MODULES:
                        return f"沙箱仅允许白名单模块，不在名单内: {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                # from . import x / from .. import x：相对导入指向沙箱临时目录之外的包，
                # 拿不到顶层模块名无法判定，一律拒绝。
                if node.level and node.level > 0:
                    return "沙箱禁止相对导入"
                top = (node.module or "").split(".")[0]
                if top not in self.ALLOWED_MODULES:
                    return f"沙箱仅允许白名单模块，不在名单内: {node.module}"
            elif isinstance(node, ast.Name):
                if node.id in self.DANGEROUS_NAMES:
                    return f"沙箱禁止访问内建对象: {node.id}"
                if (node.id in _alias_forbidden
                        and isinstance(node.ctx, ast.Load)
                        and id(node) not in _called_names):
                    return f"沙箱禁止把危险内建赋给别名或作为值传递: {node.id}"
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
            # `CODE_GATE`：这一档的正确下一步是**改代码本身**，不是申请提权、
            # 也不是换个写法绕过扫描。以前这条 403 不带分类，上层只能给兜底指令，
            # 而兜底指令没有"别绕过"这句话 —— 缺的正是这一句。
            return self._denied(self._deny(DenialKind.CODE_GATE, denied))

        import subprocess
        import uuid
        base = Path(self.sandbox_base) if self.sandbox_base else Path(tempfile.gettempdir())
        sandbox_dir = base / f"agent_sandbox_{uuid.uuid4().hex[:8]}"
        try:
            sandbox_dir.mkdir(parents=True)
        except Exception as e:
            # 只给异常类型：`e` 的 str 里是沙箱目录的**完整路径**（系统临时目录 →
            # 含用户名），而这个路径不是模型给的、模型也用不上它 —— 它需要知道的
            # 只有"沙箱起不来，别原样重试"。全文进 metadata 供人排障。
            return self._internal_error("沙箱目录创建失败", e)
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
                # 曾经是 `str(sandbox_dir)`：系统临时目录的完整路径（含用户名）。
                # `data` 和 `message` 一样进模型上下文，所以这条成功返回比它下面那两条
                # 失败返回泄漏得更多 —— 而且这个目录在 finally 里就被删了，模型拿它
                # 什么也做不了。它需要知道的只有"跑在一个隔离目录里"，那由 env_stripped
                # 和这个标签一起说清。sandbox_base 配到项目内时会回显相对路径。
                "sandbox": {"cwd": self._model_path_label(sandbox_dir),
                            "env_stripped": True, "timeout": 30}
            })

        except subprocess.TimeoutExpired:
            return ExecutionResult(status="error", error_code="504", message="代码执行超时（30 秒）")
        except Exception as e:
            # 原来是裸的 `str(e)`：subprocess 起不来时抛的 FileNotFoundError /
            # PermissionError 的 str 就是那份临时脚本的完整路径（沙箱目录 → 用户名），
            # 于是"执行失败"这条比成功那条泄漏得更多。
            return self._internal_error("代码执行失败", e)
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
            # 同为表达式闸门 → `CODE_GATE`（枚举那一档的注释写的就是"AST / 表达式闸门"）。
            # 这里被拒的原因也在表达式本身：改表达式可能成功，申请提权永远不会。
            return self._denied(self._deny(DenialKind.CODE_GATE, denied))
        try:
            tree = ast.parse(expression, mode="eval")
            result = eval_math_ast(tree)
        except SyntaxError as e:
            # `e.msg`（"invalid syntax"）+ 位置是模型**能据此行动**的信息：改表达式再试
            # 就是正解，压成 `_internal_error` 的"（SyntaxError）"等于把可自愈的 400
            # 变成不可自愈的 400。所以这里保留文本，只把路径形状过滤掉 ——
            # 今天 `ast.parse(str, mode="eval")` 的 msg 里不会有路径，但那是这个异常类
            # 当前的渲染方式，不是本层能保证的事；判据必须挂在收口上。
            # 错误码是对外契约（一直是 400），脱敏不许顺手改。
            # 只保留 `msg`、不拼 `e.offset`：`ast.parse(..., mode="eval")` 给出的
            # offset 在这类输入上是 0/None（实测 "1 +" → offset 0），拼进去只是
            # 假精度，模型会照着一个不存在的位置改。
            return ExecutionResult(status="error", error_code="400",
                                   message=f"表达式语法错误: {self._sealed_fragment(e.msg)}")
        except (ArithmeticError, ValueError, TypeError, RecursionError) as e:
            # 同上：这一批的文本（"division by zero"、`eval_math_ast` 自己抛的
            # "幂运算仅支持 …"）全是模型改表达式的依据，留文本、过滤路径形状。
            return ExecutionResult(status="error", error_code="400",
                                   message=self._sealed_fragment(e))
        # 出口类型也要判一次：入口全是 int/float，出口未必。`(-8)**0.5` 出来的是
        # **complex**，`1e308*10` 是 inf，`1e400-1e400` 是 nan —— 这三个都能顺着
        # success 走出去，然后在上层 `json.dumps` 那里炸成 500（complex 不可序列化，
        # inf/nan 会被写成非法 JSON 字面量）。判入口不等于判出口，这条得单独写。
        if isinstance(result, bool) or not isinstance(result, (int, float)):
            return ExecutionResult(status="error", error_code="400",
                                   message=f"计算结果不是实数（{type(result).__name__}），"
                                           f"math_calc 只返回整数与浮点数")
        if isinstance(result, float) and not math.isfinite(result):
            return ExecutionResult(status="error", error_code="400",
                                   message="计算结果溢出或未定义（inf / nan）")
        # 结果位数上限：CPython 3.11+ 对 int→str 有 4300 位的硬限制，超了会在
        # **序列化阶段**抛 ValueError —— 那时已经出了本函数的 try，会变成 500。
        # 100^1000 只有 2001 位，正常算式碰不到；连乘堆出来的巨数在这里变成可读的 400。
        if isinstance(result, int) and result.bit_length() > _MATH_MAX_RESULT_BITS:
            return ExecutionResult(status="error", error_code="400",
                                   message="计算结果过大，无法表示（整数位数超出上限）")
        return ExecutionResult(status="success", data={"result": result, "expression": expression})

    @staticmethod
    def _scan_math_expression(expression: str) -> str:
        """白名单 AST 校验：只允许纯算术表达式，防任意代码执行与指数 DoS。

        这一层只负责给出**可读的拒绝理由**（403）；真正的"不执行"由
        eval_math_ast 的 dispatch 表保证（模块顶部有那段取舍说明）。
        """
        if not expression or len(expression) > 200:
            return "表达式为空或过长（上限 200 字符）"
        try:
            import ast as _ast
            tree = _ast.parse(expression, mode="eval")
        except SyntaxError:
            return ""   # 语法错误交给求值阶段返回 400
        # 运算符节点放行（安全性由 BinOp/UnaryOp 级别的特判把关）
        ALLOWED_OPS = (_ast.Add, _ast.Sub, _ast.Mult, _ast.Div,
                       _ast.FloorDiv, _ast.Mod, _ast.Pow, _ast.UAdd, _ast.USub)
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Expression) or isinstance(node, ALLOWED_OPS):
                continue
            if isinstance(node, _ast.Constant):
                # 只放数字字面量。放开字符串就等于放开 "a" * 10**8 这条内存 DoS，
                # bool 虽是 int 子类但不属于"算术"，一并挡在门外。
                if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
                    return f"math_calc 只支持整数与浮点字面量，禁止: {type(node.value).__name__}"
                continue
            if isinstance(node, (_ast.BinOp, _ast.UnaryOp)):
                if isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.Pow):
                    # 只要求**指数**是字面量数字：指数是表达式时（9**9**9）无法静态定界，
                    # 直接拒。底数放开给求值器在值层判（|底数| <= 100）—— 旧实现要求
                    # 两边都是字面量，把 (1+2)**3 这种正常算式也拒了，那是过紧而非安全需要。
                    try:
                        exponent = _ast.literal_eval(node.right)
                    except (ValueError, TypeError, SyntaxError, MemoryError):
                        exponent = None
                    if (isinstance(exponent, (int, float))
                            and not isinstance(exponent, bool)
                            and abs(exponent) <= _MATH_POW_EXP_MAX):
                        continue
                    return (f"幂的指数必须是不超过 {_MATH_POW_EXP_MAX} 的字面量数字"
                            f"（底数上限 {_MATH_POW_BASE_MAX}）")
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
            # strftime 的 ValueError（Windows 上的 "Invalid format string"）说的是
            # "这个格式串不行"，模型据此换格式重试就能成 —— 属于该留的语义。
            # 只把路径形状过滤掉：今天这条文本不回显 format，但那是平台 strftime
            # 当前的渲染方式，而 `format` 是模型可控的入参，未来回显它就等于
            # 把模型给的任意字符串原样送回上下文。错误码仍是 400（对外契约）。
            return ExecutionResult(status="error", error_code="400",
                                   message=f"时间格式无效: {self._sealed_fragment(e)}")
        return ExecutionResult(status="success", data={"datetime": now})

