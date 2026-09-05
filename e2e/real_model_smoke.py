#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
real_model_smoke.py —— 真实模型端到端冒烟（供 CI secret 门控任务，也可本机跑）

需要环境变量（与 agent_runner 的 --base-url/--api-key/--model 等价）：
    ACE_E2E_BASE_URL   OpenAI 兼容端点，如 https://api.deepseek.com/v1
    ACE_E2E_API_KEY    API Key
    ACE_E2E_MODEL      模型名，如 deepseek-chat
缺失任一 → 打印 SKIP 并以 0 退出（CI 任务级 if 通常已拦截，这里是双保险）。

跑通真实闭环：用户提问 → LLM 生成 <INTERNAL>/<EXTERNAL> → 执行层解析与权限裁决
→ 工具执行（模型需要时）→ 错误自动回喂 → 最终作答。断言从宽（模型输出非确定）：
退出码 0、stdout 含最终回复标记 🤖 Agent: 且回复非空。单次调用上限 240s。

用法：
    python e2e/real_model_smoke.py
"""

import os
import subprocess
import sys
from pathlib import Path

FOLDER = Path(__file__).resolve().parent.parent


def main() -> int:
    base = os.environ.get("ACE_E2E_BASE_URL") or os.environ.get("AGENT_BASE_URL")
    key = os.environ.get("ACE_E2E_API_KEY") or os.environ.get("AGENT_API_KEY")
    model = os.environ.get("ACE_E2E_MODEL") or os.environ.get("AGENT_MODEL")
    if not (base and key and model):
        print("SKIP: 缺少 ACE_E2E_BASE_URL / ACE_E2E_API_KEY / ACE_E2E_MODEL")
        return 0

    prompt = os.environ.get("ACE_E2E_PROMPT") or (
        "你现在是一个只读的沙盒编程助手。请先调用 datetime_now 工具获取今天的日期，"
        "然后用一句话回答今天的日期，不要编造。"
    )
    cmd = [sys.executable, "agent_runner.py",
           "--base-url", base, "--api-key", key, "--model", model,
           "--input", prompt, "--permission", "readonly", "--max-history", 8]
    print("运行 agent_runner（真实模型）…")
    try:
        proc = subprocess.run(cmd, cwd=FOLDER, capture_output=True, text=True,
                              timeout=240, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        print("FAIL: 真实模型调用超时（>240s）")
        return 1

    out = proc.stdout or ""
    err = proc.stderr or ""
    print("--- stdout 末尾 ---")
    print(out[-1500:])
    if err.strip():
        print("--- stderr 末尾 ---")
        print(err[-800:])
    if proc.returncode != 0:
        print(f"FAIL: agent_runner 退出码 {proc.returncode}")
        return 1
    if "🤖 Agent:" not in out:
        print("FAIL: 未找到最终回复标记 🤖 Agent:")
        return 1
    # 只提示是否发生过工具往返/裁决,不强制(小模型可能直接作答)
    hint = sum(out.count(k) for k in ("datetime_now", "terminal_", "SUCCESS", "403"))
    print(f"OK: 真实模型端到端闭环完成（exit=0；工具/裁决痕迹约 {hint} 处）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
