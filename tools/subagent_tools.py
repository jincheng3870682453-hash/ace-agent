#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.subagent_tools —— 子代理工具（借鉴 DSH subagent 的 spawn/fork 语义，阶段 1）

把子任务交给一个**独立上下文**的模型会话执行，结果回传给父代理整合。

两种模式（与 DSH spawn/fork 对齐）：
- `spawn`：全新上下文（子代理只看到任务 prompt + 系统提示词）——适合研究、草案、
  独立验证，不受父会话历史干扰，也不把父会话的 token 预算吃进子任务。
- `fork`：继承父会话最近几轮上下文 + 任务 prompt——适合需要父会话信息的延续性任务。

阶段 1 子代理**不调工具**（纯生成：研究/草案/审查/解释）。阶段 2 才让子代理
拥有自己的工具执行循环与持久化会话（可中断/可恢复）。

实现上通过 `subagent_hook` 回调把真正的模型调用留给宿主（CLI）注入——执行层
不持有 LLM 客户端，与 approval_hook 同一种注入模式。
"""

from __future__ import annotations

from typing import Dict

from tools.result import ExecutionResult


class SubagentTools:
    def _exec_subagent(self, params: Dict) -> ExecutionResult:
        """把子任务交给独立上下文的子代理执行，返回其结果文本。"""
        mode = str(params.get("mode", "spawn")).strip().lower()
        if mode not in ("spawn", "fork"):
            return ExecutionResult(status="error", error_code="400",
                                   message=f"mode 只能是 spawn/fork，收到: {mode}")
        prompt = str(params.get("prompt", "")).strip()
        if not prompt:
            return ExecutionResult(status="error", error_code="400",
                                   message="prompt 参数为空（子任务说明必须写清楚）")
        if len(prompt) > 8000:
            return ExecutionResult(status="error", error_code="400",
                                   message="prompt 过长（上限 8000 字符）")
        hook = getattr(self, "subagent_hook", None)
        if hook is None:
            return ExecutionResult(status="error", error_code="501",
                                   message="子代理不可用：宿主未注入执行钩子"
                                           "（CLI 环境才有 subagent）")
        try:
            ok, text = hook(mode, prompt)
        except Exception as e:
            return ExecutionResult(status="error", error_code="500",
                                   message=f"子代理执行异常: {type(e).__name__}: {e}")
        if not ok:
            return ExecutionResult(status="error", error_code="500",
                                   message=text)
        return ExecutionResult(status="success", data={
            "mode": mode, "result": text,
            "hint": "以上是子代理的独立结果，请整合进主任务，不要原样转述",
        })
