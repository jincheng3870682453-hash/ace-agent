#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent_runner.py —— Agent 交互循环（把 LLM 和执行层接起来）

职责：
    用户输入 → L3 模型生成 <INTERNAL>/<EXTERNAL> → ExecutionLayer 解析/裁决/执行
    → 结果回填模型 → 循环，直到模型给出最终回复（模式 B）

模型来源（优先级从高到低）：
    1. --mock                         脚本化假模型，离线演示完整循环
    2. --base-url / --api-key / --model  OpenAI 兼容 API（OpenAI/DeepSeek/Ollama/vLLM...）
    3. 环境变量 AGENT_BASE_URL / AGENT_API_KEY / AGENT_MODEL

用法：
    python agent_runner.py --mock                          # 离线演示（无需网络/密钥）
    python agent_runner.py --mock --verbose --input 现在几点了
    python agent_runner.py --base-url https://api.deepseek.com/v1 \
        --api-key sk-xxx --model deepseek-chat              # 接真实模型
    python agent_runner.py --base-url http://localhost:11434/v1 \
        --api-key ollama --model qwen2.5                    # 本地 Ollama
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Windows GBK 控制台兼容：强制 UTF-8 输出（否则 emoji 会 UnicodeEncodeError）
for _stream in (sys.stdout, sys.stderr):
    try:
        if _stream.encoding and _stream.encoding.lower() not in ("utf-8", "utf8"):
            _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(FOLDER))

from execution_layer import ExecutionLayer  # noqa: E402

SYSTEM_PROMPT_PATH = FOLDER / "agent_system_prompt_v7.md"
MAX_ROUNDS = 20


def load_system_prompt() -> str:
    if SYSTEM_PROMPT_PATH.exists():
        return SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    return "你是一个沙盒 AI Agent，按 <INTERNAL>/<EXTERNAL> 格式输出。"


class ModelProvider:
    """L3 模型接入：mock（离线演示）或 OpenAI 兼容 API"""

    def __init__(self, args) -> None:
        self.mode = "mock" if args.mock else "api"
        self.base_url = args.base_url or os.environ.get("AGENT_BASE_URL")
        self.api_key = args.api_key or os.environ.get("AGENT_API_KEY")
        self.model = args.model or os.environ.get("AGENT_MODEL") or "default"
        self.history: List[Dict[str, str]] = []
        self.mock_step = 0
        self.mock_tool_result: Optional[str] = None

    # ---------- 脚本化假模型（离线演示完整循环） ----------

    def generate_mock(self, prompt: str) -> str:
        self.mock_step += 1
        if self.mock_step == 1:
            # 第一轮：输出工具调用
            return (
                "<INTERNAL>\n[INTERNAL_THINKING]\n"
                "[PLAN] 演示：查询当前时间\n"
                "[REASON] datetime_now 可以直接获取时间\n"
                "[ACT] 调用 datetime_now\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
                "<EXTERNAL>\nanswer.\n"
                '{"tool":"datetime_now","format":"YYYY-MM-DD HH:mm:ss"}\n</EXTERNAL>'
            )
        # 第二轮：基于工具结果的最终回复
        result_text = self.mock_tool_result or "(未知)"
        return (
            "<INTERNAL>\n[INTERNAL_THINKING]\n"
            "[OBSERVE] 工具执行成功，拿到时间\n"
            "[REASON] 信息已足够，输出最终回复\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
            f"<EXTERNAL>\nanswer.\n当前时间是 {result_text}\n</EXTERNAL>"
        )

    # ---------- 真实模型 ----------

    def generate(self, prompt: str) -> str:
        if self.mode == "mock":
            return self.generate_mock(prompt)
        if not self.base_url:
            raise RuntimeError(
                "未配置模型：请使用 --mock 离线演示，或提供 --base-url/--api-key"
                "（或环境变量 AGENT_BASE_URL / AGENT_API_KEY / AGENT_MODEL）")
        try:
            import requests
        except ImportError as e:
            raise RuntimeError("HTTP 调用需要 requests 库：pip install requests") from e
        messages = ([{"role": "system", "content": load_system_prompt()}]
                    + self.history + [{"role": "user", "content": prompt}])
        resp = requests.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "messages": messages, "temperature": 0.2},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def render_result(r: Dict) -> str:
    """把执行层返回压缩成给模型看的文本（default=str 兜底 Path 等非 JSON 类型）"""
    keys = ("status", "message", "data", "tool", "instruction", "report",
            "bait_type", "baited_code", "rule", "memory_injected")
    d = {k: r[k] for k in keys if k in r}
    return json.dumps(d, ensure_ascii=False, default=str)


def run_conversation(provider: ModelProvider, el: ExecutionLayer,
                     user_input: str, verbose: bool = False) -> None:
    print(f"\n🧑 用户: {user_input}")
    # 每次会话重置 mock 状态，防止跨会话串号
    provider.mock_step = 0
    provider.mock_tool_result = None
    next_prompt = user_input
    for round_no in range(1, MAX_ROUNDS + 1):
        try:
            output = provider.generate(next_prompt)
        except KeyboardInterrupt:
            print("\n已中断")
            return
        except Exception as e:
            print(f"\n⚠ 模型调用失败: {e}")
            return
        if verbose:
            print(f"\n--- 第 {round_no} 轮模型输出 ---\n{output}")
        try:
            result = el.process_agent_output(output, user_input)
        except Exception as e:
            print(f"\n⚠ 执行层异常: {e}（已要求模型调整输出格式）")
            next_prompt = f"执行层抛出异常: {e}\n请调整输出格式后重新输出。"
            continue
        provider.history.append({"role": "user", "content": next_prompt})
        provider.history.append({"role": "assistant", "content": output})
        if verbose:
            print(f"\n--- 执行层返回 ---\n{json.dumps(result, ensure_ascii=False, indent=2)}")

        if result["status"] == "FINAL_REPLY":
            print(f"\n🤖 Agent: {result['message']}")
            return

        if result["status"] in ("FORMAT_ERROR", "GUARD_VIOLATION",
                                "BAIT_TRIGGERED", "AST_FAILED", "403"):
            # 把错误反馈给模型，让它修正后继续
            next_prompt = (
                f"执行层返回了错误，请修正后继续：\n{render_result(result)}\n"
                f"注意：必须严格按 <INTERNAL>/<EXTERNAL> 格式输出。")
            continue

        # 工具执行成功：结果回填模型，继续下一轮
        if provider.mode == "mock" and result["status"] == "SUCCESS":
            data = result.get("data") or {}
            provider.mock_tool_result = data.get("datetime") or json.dumps(data, ensure_ascii=False)
        next_prompt = (f"工具执行结果：\n{render_result(result)}\n"
                       f"请根据结果继续（输出下一条工具调用，或最终回复）。")
    print("\n⚠️ 达到最大轮数，Agent 未给出最终回复。")


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent 交互循环（LLM + 执行层）")
    parser.add_argument("--mock", action="store_true", help="使用脚本化假模型，离线演示")
    parser.add_argument("--base-url", help="OpenAI 兼容 API 地址")
    parser.add_argument("--api-key", help="API Key")
    parser.add_argument("--model", help="模型名")
    parser.add_argument("--project-root", default=".", help="Agent 工作目录")
    parser.add_argument("--permission", default="write", choices=["readonly", "write", "full"])
    parser.add_argument("--no-bait", action="store_true", help="关闭诱饵验证")
    parser.add_argument("--verbose", action="store_true", help="打印每轮原始输出")
    parser.add_argument("--input", help="直接传入一条用户消息（非交互模式）")
    args = parser.parse_args()

    provider = ModelProvider(args)
    el = ExecutionLayer(
        project_root=args.project_root,
        permission_level=args.permission,
        config={"bait": {"enabled": not args.no_bait, "frequency": 0},
                "sandbox_base": str(Path(args.project_root).resolve() / ".sandbox_tmp")},
    )
    print(f"Agent 已启动 | 模型: {provider.mode} | 权限: {args.permission} | 工作目录: {args.project_root}")
    if args.permission != "readonly":
        print("⚠ 当前为写权限：terminal_exec 可执行任意 shell 命令。生产环境建议 readonly 起步。")
    stats = el.get_stats()
    print(f"模块状态: v2_gateway={stats['v2_gateway']} v1={stats['v1_modules']} parser={stats['parser']}")

    if args.input:
        run_conversation(provider, el, args.input, args.verbose)
        return
    print("输入消息开始对话，输入 exit / quit 退出。")
    while True:
        try:
            user_input = input("你: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if user_input.lower() in ("exit", "quit", "退出"):
            break
        if not user_input:
            continue
        run_conversation(provider, el, user_input, args.verbose)


if __name__ == "__main__":
    main()
