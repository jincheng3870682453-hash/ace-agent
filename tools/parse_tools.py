#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.parse_tools —— 文档解析工具（parse_document）"""

from typing import Any, Dict

from tools.result import DenialKind, ExecutionResult


class ParseTools:
    def _exec_parse_document(self, params: Dict) -> ExecutionResult:
        """文档解析"""
        try:
            from universal_document_parser import parse_document
        except ImportError:
            return ExecutionResult(status="error", error_code="500",
                                   message="文档解析器未安装")
        file_path = params.get("path", "")
        force_ocr = params.get("force_ocr", False)
        # SEC-005：这里原本自己算路径（expanduser + 相对项目根）且完全不判越界，
        # 于是 parse_document 能把项目外任意 PDF/docx 的正文读进上下文 ——
        # 它和 file_read 读同一类东西，却少了 file_read 那道 _confined()。
        p = self._resolve_read_path(file_path)
        if p is None:
            # 分两档报，理由同 code_analyze：UNC 是硬拒（访问动作本身就外发凭据），
            # 越界是"换个项目内路径可能成"。旧写法把两者合成一句且不带 denial_kind，
            # 上层只能给兜底指令，而这两档的正确下一步是相反的。
            # `file_path` 是模型刚传进来的原参数，回显它不构成新泄漏 ——
            # 抹掉它反而让模型分不清是哪次调用被拒。
            if self._is_network_path(file_path):
                return self._denied(self._deny(
                    DenialKind.NETWORK_PATH,
                    "拒绝解析网络路径（UNC）：访问它会向对面主机发起 SMB 出网并交出凭据",
                    {"category": "网络路径", "target": file_path}))
            return self._denied(self._deny(
                DenialKind.PATH_OUT_OF_SCOPE,
                f"路径越界，拒绝解析: {file_path}（parse_document 仅限项目目录内）",
                {"category": "路径越界", "target": file_path}))
        if not p.exists():
            # 这里回显的曾是 `p` —— **resolve 之后**的绝对路径。它和上面那个
            # `file_path` 不是一回事：绝对前缀带用户名与项目在磁盘上的位置，
            # 关掉 confine_files 时还会把软链背后的真名（`id_rsa` 那类）送进
            # 模型上下文。模型改下一步只需要相对路径，完整路径进 metadata 给人。
            return ExecutionResult(status="error", error_code="404",
                                   message=f"文件不存在: {self._model_path_label(p)}"
                                           f"（可先 file_read 确认路径，或让用户提供正确路径）",
                                   metadata={"resolved_path": str(p)})
        result = parse_document(str(p), force_ocr=force_ocr)
        if result.success:
            return ExecutionResult(status="success", data=result.to_dict())
        else:
            # 解析器的 error 是**它**拼的，里面嵌着我们传进去的那份绝对路径
            # （`文件不存在: {file_path}`、`文本读取失败: {e}` 都是这个形状）。
            #
            # 这里曾是 `raw_error.replace(str(p), label)` —— 那是默认放行：只有解析器
            # 把路径原样字面量拼进 error 时才生效。而 `f"...: {e}"` 走的是异常的
            # `__str__`，`OSError` 用 `%r` 渲染文件名，Windows 上出来的是
            # `'C:\\Users\\…'`（反斜杠成对），跟 `str(p)` 不是同一个子串 —— replace
            # 静默失配，绝对路径原样进 message，而断言只要用了能命中的那种 fixture
            # 就一直是绿的。再补 repr / as_posix / 双反斜杠 只是多猜几种渲染。
            #
            # 现在不再"洗"这段文本，而是重新组织 message 的构成：
            #   1. 结构由本层的常量 + `_model_path_label(p)` 给（天然不含绝对路径）；
            #   2. 失败原因取自解析器文本，但过一道**默认拒绝**的 token 过滤
            #      （`_model_safe_fragment`，判据是路径形态而不是下游渲染方式）；
            #   3. 出厂前再过一次不变量兜底（`_sealed_message`：这条 message 里不许
            #      出现项目根 / 家目录，归一化后比对）。
            # 失败方向由此反了过来：认漏一种写法只会少说一个词，不会漏出路径。
            # 失败原因必须留下 —— 缺依赖 / 格式不支持 / 文件过大 / 权限不足正是模型
            # 下一步要用的东西；全文继续进 metadata 给人排障。
            raw_error = str(result.error or "")
            label = self._model_path_label(p)
            reason = self._model_safe_fragment(raw_error, related=(p,))
            message = (f"文档解析失败（{label}）: {reason}" if reason
                       else f"文档解析失败（{label}）：原因见日志")
            return ExecutionResult(status="error", error_code="500",
                                   message=self._sealed_message(
                                       message,
                                       f"文档解析失败（{label}）："
                                       f"错误原文含本机路径，未回显，全文见日志"),
                                   metadata={"parser_error": raw_error,
                                             "resolved_path": str(p)})

