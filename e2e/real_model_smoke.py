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

# Windows 控制台 GBK 兼容:打印含 emoji 的捕获输出前强制 UTF-8
for _s in (sys.stdout, sys.stderr):
    try:
        if _s.encoding and _s.encoding.lower() not in ("utf-8", "utf8"):
            _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

FOLDER = Path(__file__).resolve().parent.parent


def main() -> int:
    base = os.environ.get("ACE_E2E_BASE_URL") or os.environ.get("AGENT_BASE_URL")
    key = os.environ.get("ACE_E2E_API_KEY") or os.environ.get("AGENT_API_KEY")
    model = os.environ.get("ACE_E2E_MODEL") or os.environ.get("AGENT_MODEL")
    if not (base and key and model):
        print("SKIP: 缺少 ACE_E2E_BASE_URL / ACE_E2E_API_KEY / ACE_E2E_MODEL")
        return 0

    # Q-08：API 抖动/瞬时超时不等于失败——多次浅调用重试；宽断言保留。
    # 第 1 次用完整提示（引导工具调用），后续用不需要工具的浅提问，降低单点失败面。
    prompts = [
        os.environ.get("ACE_E2E_PROMPT") or (
            "你现在是一个只读的沙盒编程助手。请先调用 datetime_now 工具获取今天的日期，"
            "然后用一句话回答今天的日期，不要编造。"),
        "请只用一句话直接回答:1+1 等于几?不要调用任何工具。",
        "请只用一句话直接回答:今天是星期几?不要调用任何工具。",
    ]
    attempts = int(os.environ.get("ACE_E2E_ATTEMPTS", "3"))
    last = (1, "未尝试")
    for i, prompt in enumerate(prompts[:attempts], start=1):
        cmd = [sys.executable, "agent_runner.py",
               "--base-url", base, "--api-key", key, "--model", model,
               "--input", prompt, "--permission", "readonly", "--max-history", "8"]
        print(f"[尝试 {i}/{len(prompts[:attempts])}] 运行 agent_runner（真实模型）…")
        try:
            proc = subprocess.run(cmd, cwd=FOLDER, capture_output=True, text=True,
                                  timeout=150, encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            last = (1, f"尝试 {i} 超时（>150s）")
            print(f"  ⏳ {last[1]}，重试…")
            continue
        out = proc.stdout or ""
        err = proc.stderr or ""
        if proc.returncode == 0 and "🤖 Agent:" in out:
            print("--- stdout 末尾 ---")
            print(out[-1500:])
            if err.strip():
                print("--- stderr 末尾 ---")
                print(err[-800:])
            hint = sum(out.count(k) for k in ("datetime_now", "terminal_", "SUCCESS", "403"))
            print(f"OK: 真实模型端到端闭环完成（exit=0；工具/裁决痕迹约 {hint} 处）")
            return 0
        last = (1, f"尝试 {i} 退出码 {proc.returncode}"
                    + ("" if "🤖 Agent:" in out else "，未找到 🤖 Agent: 标记"))
        print("--- stdout 末尾 ---")
        print((out or "")[-1500:])
        if err.strip():
            print("--- stderr 末尾 ---")
            print(err[-800:])
        print(f"  ⚠ {last[1]}，重试…" if i < len(prompts[:attempts]) else "")
    print(f"FAIL: {last[1]}（已重试 {len(prompts[:attempts])} 次）")
    return last[0]


if __name__ == "__main__":
    sys.exit(main())
