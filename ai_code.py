#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_code.py —— ACE（AI Code Engine）命令行

    ❯ 输入提示符 / ◈ 流式输出 / 斜杠命令 / 状态统计 / 快照回滚 / 报告生成

配置优先级（从高到低）：
    1. 命令行参数
    2. ~/.ai_code.json            （AI Code 的配置文件）
    3. ~/.claude/settings.json    （本机已有模型配置，自动复用 ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN / model）
    4. 环境变量 AGENT_BASE_URL / AGENT_API_KEY / AGENT_MODEL

支持两种 API 格式（自动识别）：
    · OpenAI 兼容：  {base}/chat/completions
    · Anthropic 兼容：{base}/v1/messages

用法：
    ace                                        # cmd 全局命令（已注册到 PATH，随时唤醒）
    python ai_code.py                          # 交互模式
    python ai_code.py --mock                   # 离线演示
    python ai_code.py --input "现在几点了"      # 单次对话
    python ai_code.py --base-url https://api.deepseek.com/v1 --api-key sk-xxx --model deepseek-chat

斜杠命令（输入 / 或命令前缀会自动给出补全提示）：
    /help  /clear  /status  /stats  /memory  /snapshots  /undo  /rollback <id>
    /report  /permission [level]  /mock  /model [模型名]  /provider [编号|id] [api-key]
    /config  /open <路径>  /edit <路径>  /exit
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
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
from agent_runner import ModelProvider, load_system_prompt, render_result  # noqa: E402

CONFIG_PATH = Path.home() / ".ai_code.json"
LEGACY_CONFIG_PATH = Path.home() / ".agent_cli.json"
CLAUDE_SETTINGS_PATH = Path.home() / ".claude" / "settings.json"
MAX_ROUNDS = 20
SYSTEM_PROMPT = load_system_prompt()


class CommandCancelled(Exception):
    """交互子流程被用户取消（如 Ctrl+C），区别于致命异常：只中止当前命令，不退出整个 CLI"""


# ACE ASCII 品牌 logo（ANSI Shadow 字体）
ACE_LOGO = r"""
 █████╗  ██████╗ ███████╗
██╔══██╗██╔════╝ ██╔════╝
███████║██║      █████╗
██╔══██║██║      ██╔══╝
██║  ██║╚██████╗ ███████╗
╚═╝  ╚═╝ ╚═════╝ ╚══════╝""".strip("\n")


# AI 提供商注册表（参考本机 cli/AI-CLI-安装平台/lib/api.js，模型名 2026-08 调研整理）
PROVIDERS = [
    {"id": "zhipu", "name": "智谱 GLM（Anthropic 兼容端点）",
     "base_url": "https://open.bigmodel.cn/api/anthropic", "api_format": "anthropic",
     "models": ["glm-4.7-flash", "glm-4.6", "glm-4.5-air", "glm-4.7",
                "glm-5.2", "glm-4.5-flash"]},
    {"id": "zhipu-openai", "name": "智谱 GLM（OpenAI 兼容端点）",
     "base_url": "https://open.bigmodel.cn/api/paas/v4", "api_format": "openai",
     "models": ["glm-4.7-flash", "glm-4.6", "glm-4.5-air", "glm-4.7",
                "glm-5.2", "glm-4.5-flash"]},
    {"id": "deepseek", "name": "DeepSeek（深度求索）",
     "base_url": "https://api.deepseek.com/v1", "api_format": "openai",
     "models": ["deepseek-v4-pro", "deepseek-v4-flash", "deepseek-chat",
                "deepseek-reasoner"]},
    {"id": "moonshot", "name": "Kimi / Moonshot AI",
     "base_url": "https://api.moonshot.cn/v1", "api_format": "openai",
     "models": ["kimi-k2.7", "kimi-k2.7-code", "kimi-k2.6", "kimi-k2", "kimi-latest"]},
    {"id": "openai", "name": "OpenAI",
     "base_url": "https://api.openai.com/v1", "api_format": "openai",
     "models": ["gpt-5.5", "gpt-5.2", "gpt-4o", "o3", "o4-mini"]},
    {"id": "anthropic", "name": "Anthropic Claude",
     "base_url": "https://api.anthropic.com", "api_format": "anthropic",
     "models": ["claude-opus-4.7", "claude-sonnet-4.5", "claude-3.7-sonnet"]},
    {"id": "qwen", "name": "阿里通义 Qwen",
     "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "api_format": "openai",
     "models": ["qwen3-max", "qwen3-coder", "qwen3.6", "qwen2.5-coder"]},
    {"id": "siliconflow", "name": "硅基流动 SiliconFlow",
     "base_url": "https://api.siliconflow.cn/v1", "api_format": "openai",
     "models": ["deepseek-ai/DeepSeek-V3", "Qwen/Qwen3-235B-A22B", "zai-org/GLM-5.2"]},
    {"id": "openrouter", "name": "OpenRouter（聚合）",
     "base_url": "https://openrouter.ai/api/v1", "api_format": "openai",
     "models": ["deepseek/deepseek-chat", "openai/gpt-5.5",
                "anthropic/claude-opus-4.7", "z-ai/glm-5.2"]},
    {"id": "ollama", "name": "Ollama（本地模型）",
     "base_url": "http://localhost:11434/v1", "api_format": "openai",
     "models": ["qwen2.5", "llama3.2", "deepseek-r1"]},
]


def _find_provider(cfg: Dict) -> Optional[Dict]:
    """按 base_url 匹配当前提供商预设"""
    base = str(cfg.get("base_url", "")).rstrip("/")
    for p in PROVIDERS:
        if base == p["base_url"].rstrip("/"):
            return p
    return None


def _pip_install_with_fallbacks(target: str) -> bool:
    """智能安装：已装则跳过；默认源失败自动切换清华/阿里/豆瓣镜像；装完导入验证"""
    import importlib
    import subprocess as _sp
    try:
        importlib.import_module(target)
        return True   # 已安装，无需重复下载
    except ImportError:
        pass
    sources = [
        [],
        ["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"],
        ["-i", "https://mirrors.aliyun.com/pypi/simple"],
        ["-i", "https://pypi.doubanio.com/simple"],
    ]
    for src in sources:
        name = src[-1] if src else "默认源"
        print(f"  尝试 {name} ...")
        try:
            rc = _sp.run([sys.executable, "-m", "pip", "install", target] + src,
                         timeout=300).returncode
        except Exception:
            rc = 1
        if rc == 0:
            check = _sp.run([sys.executable, "-c", f"import {target}"])
            if check.returncode == 0:
                return True
    return False


def _looks_like_cli_command(line: str) -> bool:
    """防蠢检测：用户把 cmd 命令/参数误打进 REPL（如 ace --install-ui、--mock、pip install）"""
    s = line.strip().lower()
    return bool(re.match(r"^(ace|ai[-_ ]?code)\s+--", s)
                or re.match(r"^--[a-z-]+", s)
                or re.match(r"^pip(3)?\s", s))


def _config_sanity_hints(cfg: Dict) -> List[str]:
    """启动自检：配置防蠢提示（如 ZAI 别名模型直连 BigModel 不被识别）"""
    hints = []
    model = str(cfg.get("model", ""))
    base = str(cfg.get("base_url", ""))
    if model.startswith("deepseek-v4") and "bigmodel" in base:
        hints.append("检测到模型名是 ZAI 网关别名（deepseek-v4-*），直连 BigModel 不认，请用 /model glm-4.6 切换")
    return hints

# ---- ANSI 颜色（非 tty 或 NO_COLOR 时自动关闭，遵循 NO_COLOR 约定）----
ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
}
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
if os.name == "nt":
    try:
        os.system("")  # Windows 启用 ANSI 转义（其他平台无此需要）
    except Exception:
        pass


def c(color: str, text: str) -> str:
    return f"{ANSI[color]}{text}{ANSI['reset']}" if USE_COLOR else text


def _build_slash_completer(commands: Dict[str, str]):
    """构建 / 命令实时补全器（Claude Code 同款：按下 / 弹菜单，边打字边过滤）
    需要 prompt_toolkit；/open /edit 后面接文件路径补全。"""
    from prompt_toolkit.completion import Completer, Completion, PathCompleter
    from prompt_toolkit.document import Document as PTDocument

    class SlashCompleter(Completer):
        def __init__(self) -> None:
            self.commands = commands
            self._path = PathCompleter(only_directories=False, expanduser=True)

        def get_completions(self, document, complete_event):
            text = document.text_before_cursor
            if not text.startswith("/"):
                return
            # /open /edit 后面的路径做文件补全
            m = re.match(r"^/(open|edit)\s+(.*)$", text)
            if m:
                sub = PTDocument(m.group(2), cursor_position=len(m.group(2)))
                offset = len(text) - len(m.group(2))
                for comp in self._path.get_completions(sub, complete_event):
                    yield Completion(
                        comp.text,
                        start_position=comp.start_position + offset,
                        display=comp.display,
                        display_meta=comp.display_meta,
                    )
                return
            # 命令名前缀实时过滤
            prefix = text[1:]
            for name, desc in self.commands.items():
                if name.startswith("/" + prefix):
                    yield Completion(name, start_position=-len(text),
                                     display_meta=desc)

    return SlashCompleter()


def mask_secret(s: str) -> str:
    s = s or ""
    if len(s) <= 8:
        return "***"
    return f"{s[:6]}***{s[-4:]}"


# ============================================================
# 配置加载（优先 AI Code 配置，回退复用本机已有模型配置）
# ============================================================

def load_claude_settings() -> Dict:
    """读取 ~/.claude/settings.json，提取模型端点配置"""
    if not CLAUDE_SETTINGS_PATH.exists():
        return {}
    try:
        data = json.loads(CLAUDE_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    env = data.get("env", {}) if isinstance(data, dict) else {}
    return {
        "base_url": env.get("ANTHROPIC_BASE_URL") or "",
        "api_key": env.get("ANTHROPIC_AUTH_TOKEN") or "",
        "model": data.get("model") or "",
        "api_format": "anthropic",
    }


def load_cli_config() -> Dict:
    for path in (CONFIG_PATH, LEGACY_CONFIG_PATH):
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
    return {}


def merge_config(args) -> Dict:
    """配置合并：args > ~/.ai_code.json > ~/.claude/settings.json（本机已有配置） > 环境变量"""
    cfg: Dict = {}
    cfg.update(load_claude_settings())
    cfg.update(load_cli_config())
    cfg.update({k: v for k, v in {
        "base_url": args.base_url, "api_key": args.api_key, "model": args.model,
        "permission": args.permission, "project_root": args.project_root,
    }.items() if v})
    cfg.setdefault("base_url", os.environ.get("AGENT_BASE_URL", ""))
    cfg.setdefault("api_key", os.environ.get("AGENT_API_KEY", ""))
    cfg.setdefault("model", os.environ.get("AGENT_MODEL", "default"))
    cfg.setdefault("permission", "write")
    cfg.setdefault("project_root", ".")
    cfg.setdefault("bait", True)
    return cfg


def save_cli_config(cfg: Dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    print(c("green", f"配置已保存到 {CONFIG_PATH}"))


def detect_api_format(base_url: str) -> str:
    if not base_url:
        return "openai"
    if "/anthropic" in base_url:
        return "anthropic"
    return "openai"


# ============================================================
# 模型客户端（流式，支持 OpenAI / Anthropic 两种格式）
# ============================================================

class ModelClient:
    def __init__(self, cfg: Dict, mock: bool = False) -> None:
        self.mock = mock
        self.base_url = cfg.get("base_url", "").rstrip("/")
        self.api_key = cfg.get("api_key", "")
        self.model = cfg.get("model", "default")
        self.api_format = detect_api_format(self.base_url)
        self._mock_provider = ModelProvider(_MockArgs()) if mock else None

    def describe(self) -> str:
        if self.mock:
            return "mock（离线演示）"
        return (f"{self.model} @ {self.base_url} "
                f"(api: {self.api_format}, key: {mask_secret(self.api_key)})")

    def stream_generate(self, system: str, messages: List[Dict]) -> str:
        if self.mock:
            return self._stream_mock(messages)
        if not self.base_url or not self.api_key:
            raise RuntimeError(
                "未配置模型：用 --base-url/--api-key/--model 指定，"
                "或写入 ~/.ai_code.json；也可 --mock 离线演示")
        if self.api_format == "anthropic":
            return self._stream_anthropic(system, messages)
        return self._stream_openai(system, messages)

    def _stream_mock(self, messages: List[Dict]) -> str:
        text = self._mock_provider.generate(messages[-1]["content"])
        for line in text.splitlines():
            print(line)
            time.sleep(0.02)
        return text

    def _stream_openai(self, system: str, messages: List[Dict]) -> str:
        import requests
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}] + messages,
            "stream": True,
            "temperature": 0.2,
        }
        full = ""
        with requests.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json=payload, stream=True, timeout=300,
        ) as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if not line:
                    continue
                line = line.decode("utf-8", errors="ignore").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    obj = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                choices = obj.get("choices") or []
                delta = (choices[0] or {}).get("delta", {}) if choices else {}
                content = delta.get("content") if isinstance(delta, dict) else None
                if content:
                    full += content
                    print(content, end="", flush=True)
        print()
        return full

    def _anthropic_payload_variants(self, system: str, messages: List[Dict]) -> List[Dict]:
        """生成多组兼容变体：不同服务商对 system 字段格式 / 流式支持要求不一，逐个降级尝试"""
        base = {"model": self.model, "max_tokens": 8192, "messages": messages}
        msgs_blocks = [
            {"role": m.get("role", "user"),
             "content": [{"type": "text", "text": str(m.get("content", ""))}]}
            for m in messages
        ]
        sys_blocks = [{"type": "text", "text": system}]
        return [
            {**base, "system": system, "stream": True},
            {**base, "system": sys_blocks, "stream": True},
            {**base, "system": system, "messages": msgs_blocks, "stream": True},
            {**base, "system": sys_blocks, "messages": msgs_blocks, "stream": True},
            {**base, "system": system, "stream": False},
            {**base, "system": sys_blocks, "stream": False},
        ]

    def _post_anthropic(self, payload: Dict) -> str:
        """POST /v1/messages，自动处理流式（SSE）与非流式（JSON）两种响应"""
        import requests
        stream = bool(payload.get("stream"))
        with requests.post(
            f"{self.base_url}/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=payload, stream=stream, timeout=300,
        ) as r:
            r.raise_for_status()
            if not stream:
                data = r.json()
                blocks = data.get("content") or []
                full = "".join(b.get("text", "") for b in blocks
                               if isinstance(b, dict) and b.get("type") == "text")
                print(full, end="", flush=True)
                print()
                return full
            full = ""
            for line in r.iter_lines():
                if not line:
                    continue
                line = line.decode("utf-8", errors="ignore").strip()
                if not line.startswith("data:"):
                    continue
                try:
                    obj = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                if obj.get("type") == "content_block_delta":
                    delta = obj.get("delta") or {}
                    text = delta.get("text", "") if isinstance(delta, dict) else ""
                    if text:
                        full += text
                        print(text, end="", flush=True)
            print()
            return full

    def _stream_anthropic(self, system: str, messages: List[Dict]) -> str:
        """Anthropic Messages 调用：多格式变体自动降级，兼容不同服务商"""
        import requests
        last_err = ""
        for payload in self._anthropic_payload_variants(system, messages):
            try:
                return self._post_anthropic(payload)
            except requests.HTTPError as e:
                body = ""
                try:
                    body = (e.response.text or "")[:400]
                except Exception:
                    pass
                last_err = f"{e} | 响应体: {body}"
                # 常见错误码给出可操作提示（如智谱 1214 = 模型名不存在）
                try:
                    err_obj = json.loads(e.response.text or "{}")
                    code = str(err_obj.get("error", {}).get("code", ""))
                    msg = str(err_obj.get("error", {}).get("message", ""))
                    if code == "1214" or "modelCode" in msg or "不存在" in msg:
                        last_err += ("\n提示: 该端点不存在这个模型名。用 /model glm-4.6 切换"
                                     "（智谱真实模型码，如 glm-4.6 / glm-4.5-air），或用 /config 改端点")
                except Exception:
                    pass
                if e.response is not None and e.response.status_code != 400:
                    break   # 401/403/429/5xx 等不重试，避免浪费请求
            except requests.RequestException as e:
                last_err = str(e)
                break
        raise RuntimeError(f"模型 API 调用失败（已尝试多种请求格式）: {last_err}")


class _MockArgs:
    mock = True
    base_url = None
    api_key = None
    model = None


# ============================================================
# Agent CLI 主类
# ============================================================

class AgentCLI:
    def __init__(self, cfg: Dict, mock: bool = False) -> None:
        self.cfg = cfg
        self.client = ModelClient(cfg, mock=mock)
        self.messages: List[Dict] = []
        self.session = {"rounds": 0, "tools": 0, "violations": 0, "start": time.time()}
        self._init_execution_layer()

    def _init_execution_layer(self) -> None:
        self.el = ExecutionLayer(
            project_root=self.cfg["project_root"],
            permission_level=self.cfg["permission"],
            config={
                "bait": {"enabled": bool(self.cfg.get("bait", True)), "frequency": 0},
                "sandbox_base": str(Path(self.cfg["project_root"]).resolve() / ".sandbox_tmp"),
            },
        )

    # ---------- 对话循环 ----------

    def converse(self, user_input: str) -> None:
        print(f"\n{c('magenta', '❯')} {user_input}")
        t0 = time.time()
        next_user = user_input
        for _round in range(1, MAX_ROUNDS + 1):
            msgs = self.messages + [{"role": "user", "content": next_user}]
            print(c("blue", "◈"), end=" ", flush=True)
            try:
                output = self.client.stream_generate(SYSTEM_PROMPT, msgs)
            except KeyboardInterrupt:
                print("\n已中断")
                return
            except Exception as e:
                print(c("red", f"\n✗ 模型调用失败: {e}"))
                return
            self.messages = msgs + [{"role": "assistant", "content": output}]

            try:
                result = self.el.process_agent_output(output, user_input)
            except Exception as e:
                print(c("yellow", f"  ⚠ 执行层异常: {e}"))
                next_user = f"执行层抛出异常: {e}\n请调整输出格式后重新输出。"
                continue
            self.session["rounds"] += 1

            if result["status"] == "FINAL_REPLY":
                print(c("green", f"  ✓ 完成（{_round} 轮, {time.time() - t0:.1f}s）"))
                return

            if result["status"] in ("FORMAT_ERROR", "GUARD_VIOLATION",
                                    "BAIT_TRIGGERED", "AST_FAILED", "403"):
                self.session["violations"] += 1
                print(c("red", f"  ✗ {result['status']}: {result.get('message', '')[:80]}"))
                next_user = (f"执行层返回了错误，请修正后继续：\n{render_result(result)}\n"
                             f"注意：必须严格按 <INTERNAL>/<EXTERNAL> 格式输出。")
            else:
                self.session["tools"] += 1
                status_mark = c("green", "✓") if result["status"] == "SUCCESS" else c("yellow", "⚠")
                line = f"  ↳ 工具 {result.get('tool')} {status_mark} [{result['status']}]"
                if result["status"] == "SUCCESS":
                    elapsed = result.get("elapsed")
                    if isinstance(elapsed, (int, float)):
                        line += c("dim", f" · {elapsed:.2f}s")
                    if result.get("snapshot_id"):
                        line += c("dim", " · 已自动快照，/undo 一键回滚")
                print(line)
                if result.get("memory_injected"):
                    print(c("dim", f"  · 已自动注入 {len(result['memory_injected'])} 条相关记忆"))
                if self.client.mock and result["status"] == "SUCCESS":
                    data = result.get("data") or {}
                    self.client._mock_provider.mock_tool_result = (
                        data.get("datetime") or json.dumps(data, ensure_ascii=False))
                next_user = (f"工具执行结果：\n{render_result(result)}\n"
                             f"请根据结果继续（输出下一条工具调用，或最终回复）。")
        print(c("yellow", "⚠ 达到最大轮数，Agent 未给出最终回复。"))

    # ---------- 斜杠命令 ----------

    COMMANDS = {
        "/help": "显示帮助（输入 / 或任意前缀也会自动提示）",
        "/clear": "清空会话历史",
        "/status": "会话与执行层状态",
        "/stats": "执行层统计（模块/违规/诱饵）",
        "/memory": "查看记忆存档",
        "/snapshots": "列出快照",
        "/undo": "一键回滚到最近一次自动快照（无需记 id）",
        "/rollback": "回滚到指定快照（用法: /rollback <快照id>）",
        "/report": "生成 POC 报告（Nuwa）",
        "/permission": "查看/切换权限（用法: /permission [readonly|write|full]）",
        "/mock": "切换离线演示 / 真实模型模式（可来回切换）",
        "/model": "查看/自定义模型（用法: /model <名> | base-url <url> | api-key <key>）",
        "/provider": "查看/切换 AI 提供商（智谱/DeepSeek/Kimi/OpenAI/Qwen/本地…，用法: /provider [编号|id] [api-key]）",
        "/config": "交互式配置模型（向导）",
        "/open": "用系统默认程序打开文件（用法: /open <路径>）",
        "/edit": "用 VS Code（或默认编辑器）打开文件（用法: /edit <路径>）",
        "/search": "联网搜索（DuckDuckGo/Bing，用法: /search <关键词>）",
        "/exit": "退出",
    }

    def run_command(self, cmd: str) -> bool:
        """处理斜杠命令，返回 False 表示退出（支持前缀补全提示）"""
        parts = cmd.split()
        name = parts[0].lower() if parts else ""

        # 前缀补全：/ 或 /h 这类输入自动提示；唯一匹配直接执行
        if name not in self.COMMANDS:
            matches = [k for k in self.COMMANDS if k.startswith(name)] if name else list(self.COMMANDS)
            if not name:
                matches = list(self.COMMANDS)
            if len(matches) == 1:
                parts[0] = matches[0]
                name = matches[0]
            else:
                if matches:
                    print(c("dim", f"  你输入的是 {cmd or '/'}，可用的命令："))
                    for k in matches:
                        print(f"    {c('magenta', k):<26} {self.COMMANDS[k]}")
                else:
                    print(f"  没有以 '{name}' 开头的命令（输入 / 查看全部）")
                return True

        if name == "/help":
            print(c("bold", "\n可用命令:"))
            for k, v in self.COMMANDS.items():
                print(f"  {c('magenta', k):<22} {v}")
        elif name == "/clear":
            self.messages.clear()
            self._init_execution_layer()
            self.session.update(rounds=0, tools=0, violations=0, start=time.time())
            print(c("green", "会话已清空，执行层已重置。"))
        elif name == "/status":
            self._show_status()
        elif name == "/stats":
            print(json.dumps(self.el.get_stats(), ensure_ascii=False, indent=2))
        elif name == "/memory":
            self._show_memory()
        elif name == "/snapshots":
            snaps = self.el.guardian.list_snapshots() if self.el.guardian else []
            if not snaps:
                print("暂无快照")
            for s in snaps:
                print(f"  {s['id']}  {s.get('created_iso')}  {s.get('tag')}  ({s.get('file_count')} 文件)")
        elif name == "/undo":
            self._undo_last()
        elif name == "/rollback":
            if len(parts) < 2:
                print("用法: /rollback <快照id>（用 /snapshots 查看）")
            elif not re.match(r"^\d+_[\w\-]{1,60}$", parts[1]):
                print(c("red", "快照 id 格式非法（应为 时间戳_标签，用 /snapshots 查看）"))
            else:
                try:
                    answer = input(f"确认回滚到 {parts[1]}？这会覆盖当前文件状态 [y/N]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    print("已取消")
                    return True
                if answer == "y":
                    try:
                        ok = self.el.guardian.rollback(parts[1])
                        print(c("green", "回滚成功") if ok else c("red", "回滚不完整，备份已保留"))
                    except Exception as e:
                        print(c("red", f"回滚失败: {e}"))
                else:
                    print("已取消")
        elif name == "/report":
            path = self.el.generate_poc_report("Agent CLI 会话报告")
            print(c("green", f"报告已生成: {path}") if path else c("red", "Nuwa 未启用"))
        elif name == "/permission":
            if len(parts) >= 2 and parts[1] in ("readonly", "write", "full"):
                self.el.permission.upgrade(parts[1])
                self.cfg["permission"] = parts[1]
                print(c("green", f"权限已切换为 {parts[1]}"))
            else:
                print(json.dumps(self.el.permission.get_status(), ensure_ascii=False, indent=2))
        elif name == "/model":
            self._handle_model(parts)
        elif name == "/mock":
            self._toggle_mock()
        elif name == "/provider":
            self._handle_provider(parts)
        elif name == "/config":
            self._config_wizard()
        elif name == "/open":
            self._open_file(" ".join(parts[1:]), prefer_editor=False)
        elif name == "/edit":
            self._open_file(" ".join(parts[1:]), prefer_editor=True)
        elif name == "/search":
            self._search_web(" ".join(parts[1:]).strip())
        elif name in ("/exit", "/quit", "exit", "quit"):
            return False
        else:
            print(f"未知命令: {name}（输入 / 查看全部命令）")
        return True

    # ---------- 联网搜索（人可用的 /search，与 Agent 的 search 工具同源） ----------

    def _search_web(self, query: str) -> None:
        if not query:
            print("用法: /search <关键词>")
            return
        print(c("dim", f"  正在搜索「{query}」..."))
        res = self.el.executor.execute({"tool": "search", "query": query, "top_k": 5})
        if res.status != "success":
            print(c("red", f"  搜索失败: {res.message}"))
            return
        data = res.data
        print(c("dim", f"  引擎: {data.get('engine', '?')} · 网络: {data.get('network_status', '?')}"))
        for i, item in enumerate(data.get("results", []), 1):
            print(f"  {i}. {item.get('title', '')}")
            print(f"     {c('dim', item.get('url', ''))}")
            snippet = item.get("snippet", "")
            if snippet:
                print(f"     {c('dim', snippet[:120])}")

    # ---------- 文件打开（编辑器无关，裸终端可用） ----------

    def _resolve_local_path(self, path_str: str, create: bool = False) -> Optional[Path]:
        """把用户输入的路径解析到项目目录内的绝对路径"""
        p = Path(path_str)
        if not p.is_absolute():
            p = Path(self.cfg["project_root"]) / p
        p = p.resolve()
        if create and not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("", encoding="utf-8")
        if not p.exists():
            print(c("red", f"文件不存在: {p}"))
            return None
        return p

    def _open_file(self, path_str: str, prefer_editor: bool = False) -> None:
        """在系统默认程序（或 VS Code）中打开文件"""
        if not path_str.strip():
            print(f"用法: {'/edit' if prefer_editor else '/open'} <文件路径>")
            return
        p = self._resolve_local_path(path_str, create=prefer_editor)
        if p is None:
            return
        try:
            if prefer_editor:
                code = shutil.which("code")
                if code:
                    subprocess.Popen([code, str(p)])
                    print(c("green", f"已在 VS Code 中打开: {p}"))
                    return
            if os.name == "nt":
                os.startfile(str(p))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
            print(c("green", f"已打开: {p}"))
        except Exception as e:
            print(c("red", f"打开失败: {e}"))

    # ---------- 模型自定义 ----------

    def _reload_client(self) -> None:
        """配置变更后重建模型客户端（保留 mock 模式）"""
        was_mock = self.client.mock
        self.client = ModelClient(self.cfg, mock=was_mock)

    def _handle_model(self, parts: List[str]) -> None:
        if len(parts) == 1:
            print(f"  当前模型: {self.client.describe()}")
            prov = _find_provider(self.cfg)
            if prov:
                print(c("dim", f"  该提供商可选模型: {' / '.join(prov['models'][:8])}（/model <名> 切换）"))
            print(c("dim", "  切换: /model <模型名> | 换提供商: /provider | 设密钥: /model api-key <key>"))
            return
        if parts[1] == "base-url" and len(parts) >= 3:
            self.cfg["base_url"] = parts[2]
            save_cli_config(self.cfg)
            self._reload_client()
            print(c("green", f"端点已设置: {parts[2]}（自动识别为 {detect_api_format(parts[2])} 格式），已保存"))
        elif parts[1] == "api-key" and len(parts) >= 3:
            self.cfg["api_key"] = parts[2]
            save_cli_config(self.cfg)
            self._reload_client()
            print(c("green", f"密钥已更新: {mask_secret(parts[2])}，已保存"))
        else:
            model_name = " ".join(parts[1:]).strip()
            self.cfg["model"] = model_name
            save_cli_config(self.cfg)
            self._reload_client()
            print(c("green", f"模型已切换: {model_name}，已保存到 ~/.ai_code.json"))

    def _handle_provider(self, parts: List[str]) -> None:
        """查看/切换 AI 提供商：/provider 列清单，/provider <编号|id> [api-key] 一键切换"""
        if len(parts) == 1:
            print(c("bold", "\nAI 提供商（/provider <编号或id> [api-key] 一键切换）:"))
            for i, p in enumerate(PROVIDERS, 1):
                cur = self.cfg.get("base_url", "").rstrip("/") == p["base_url"].rstrip("/")
                mark = c("green", " ✓ 当前") if cur else ""
                print(f"  {c('magenta', str(i)):>3}. {p['name']}{mark}")
                print(f"      {c('dim', p['base_url'] + '   模型: ' + ' / '.join(p['models'][:6]))}")
            return

        arg = parts[1].lower()
        target = None
        if arg.isdigit() and 1 <= int(arg) <= len(PROVIDERS):
            target = PROVIDERS[int(arg) - 1]
        else:
            for p in PROVIDERS:
                if p["id"] == arg:
                    target = p
                    break
        if target is None:
            print(c("red", f"未知提供商: {parts[1]}（输入 /provider 查看列表）"))
            return

        self.cfg["base_url"] = target["base_url"]
        # 防蠢：当前模型不在新提供商列表里时自动切到它的第一个模型
        if self.cfg.get("model", "") not in target["models"]:
            self.cfg["model"] = target["models"][0]
        if len(parts) >= 3:
            self.cfg["api_key"] = parts[2]
        save_cli_config(self.cfg)
        self._reload_client()
        print(c("green", f"已切换提供商: {target['name']}"))
        print(f"  端点: {target['base_url']}（{target['api_format']} 格式）")
        print(f"  模型: {self.cfg['model']}（可选: {' / '.join(target['models'][:6])}，用 /model <名> 换）")
        if not self.cfg.get("api_key"):
            print(c("yellow", "  ⚠ 还没有该提供商的 API Key：用 /provider <id> <api-key> 或 /config 设置"))

    def _config_wizard(self) -> None:
        print(c("bold", "\n模型配置向导（回车跳过 = 保持原值，Ctrl+C 取消且不保存）"))

        def _ask(label: str, current: str, hidden: bool = False) -> Optional[str]:
            try:
                if hidden:
                    import getpass
                    answer = getpass.getpass(f"  {label} [{current}]: ").strip()
                else:
                    answer = input(f"  {label} [{current}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                raise CommandCancelled() from None
            return answer or None

        try:
            # ① 选提供商（一键换端点 + 自动选默认模型）
            print(c("bold", "① 选择 AI 提供商:"))
            for i, p in enumerate(PROVIDERS, 1):
                print(f"  {i}. {p['name']}  {c('dim', p['base_url'])}")
            choice = _ask("提供商编号（回车跳过）", "")
            if choice:
                if choice.isdigit() and 1 <= int(choice) <= len(PROVIDERS):
                    p = PROVIDERS[int(choice) - 1]
                    self.cfg["base_url"] = p["base_url"]
                    if self.cfg.get("model", "") not in p["models"]:
                        self.cfg["model"] = p["models"][0]
                else:
                    print(c("yellow", "编号无效，跳过（可用 /provider 重试）"))
            # ② 密钥（隐藏输入，不回显）
            key = _ask("API Key（输入时不显示）", mask_secret(self.cfg.get("api_key", "")), hidden=True)
            if key:
                self.cfg["api_key"] = key
            # ③ 模型
            prov = _find_provider(self.cfg)
            model_hint = ""
            if prov:
                model_hint = f"（可选: {' / '.join(prov['models'][:8])}）"
            model = _ask(f"模型名{model_hint}", self.cfg.get("model", ""))
            if model:
                self.cfg["model"] = model
        except CommandCancelled:
            print(c("yellow", "已取消，配置未保存。"))
            return
        save_cli_config(self.cfg)
        self._reload_client()
        print(c("green", "配置已保存，当前: " + self.client.describe()))

    def _handle_cli_mistype(self, line: str) -> None:
        """防蠢处理：识别并接管误打进 REPL 的命令行指令"""
        if "--install-ui" in line:
            print(c("yellow", "检测到你想安装实时补全依赖，正在自动安装（已装跳过 + 多镜像回退）..."))
            if _pip_install_with_fallbacks("prompt_toolkit"):
                print(c("green", "✅ 安装完成！输入 exit 退出后重新运行 ace 即可享受 / 弹窗补全"))
            else:
                print(c("red", "安装失败，请手动: "
                                "pip install prompt_toolkit -i https://pypi.tuna.tsinghua.edu.cn/simple"))
            return
        print(c("yellow", f"“{line.strip()}” 看起来是 ACE 的命令行参数/系统命令，不是发给 Agent 的话。"))
        print(c("dim", "  请先输入 exit 退出 ACE，再在 cmd 里直接运行它。"))

    # ---------- 登录页 / 首页（参考 AI-CLI 启动平台主菜单） ----------

    LANDING_ITEMS = [
        ("进入聊天", "开始与 Agent 对话", "chat"),
        ("配置向导", "提供商 → API Key → 模型", "wizard"),
        ("切换提供商 / 模型", "一键换 AI 提供商", "provider"),
        ("离线演示", "mock 模式，无需密钥", "mock"),
        ("状态与统计", "会话 / 快照 / 模块状态", "status"),
        ("帮助", "斜杠命令速查", "help"),
        ("退出", "再见", "exit"),
    ]

    @staticmethod
    def _clear_screen() -> None:
        if sys.stdout.isatty():
            sys.stdout.write("\x1b[2J\x1b[H")
            sys.stdout.flush()

    @staticmethod
    def _read_key() -> Optional[str]:
        """读取单次按键（↑/↓/数字/回车/Esc/q）；非 tty 返回 None"""
        if not sys.stdin.isatty():
            return None
        try:
            import msvcrt  # Windows
            first = msvcrt.getwch()
            if first in ("\x00", "\xe0"):
                second = msvcrt.getwch()
                return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(second, None)
            if first in ("\r", "\n"):
                return "enter"
            if first == "\x1b":
                return "esc"
            return first
        except ImportError:
            pass
        try:
            import termios
            import tty
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            try:
                ch = sys.stdin.read(1)
                if ch == "\x1b":
                    nxt = sys.stdin.read(2)
                    return {"[A": "up", "[B": "down"}.get(nxt, "esc")
                if ch in ("\r", "\n"):
                    return "enter"
                return ch
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except (ImportError, OSError):
            return input()

    def _wait_key(self) -> None:
        print(c("dim", "  按任意键返回..."))
        self._read_key()

    def _draw_landing(self, sel: int) -> None:
        self._clear_screen()
        for line in ACE_LOGO.split("\n"):
            print(c("magenta", " " + line))
        print(c("bold", " ACE v1.0 · AI Code Engine"))
        print()
        print(f"  {c('dim', '模型:')} {self.client.describe()}")
        print(f"  {c('dim', '权限:')} {self.cfg.get('permission', 'write')}   "
              f"{c('dim', '目录:')} {self.cfg.get('project_root', '.')}")
        if not self.cfg.get("api_key") and not self.client.mock:
            print(c("yellow", "  ⚠ 尚未配置 API Key —— 选择 2 配置向导完成首次登录"))
        print()
        for i, (label, desc, _action) in enumerate(self.LANDING_ITEMS, 1):
            if _action == "mock":
                # 根据当前模式动态显示：可来回切换
                if self.client.mock:
                    label, desc = "切换回真实模型", "回到真实 API 模式"
                else:
                    label, desc = "离线演示", "mock 模式，无需密钥"
            mark = c("magenta", "❯") if i - 1 == sel else " "
            print(f"  {mark} {i}. {label}   {c('dim', desc)}")
        print()
        print(c("dim", "  ↑/↓ 选择 · 数字直选 · Enter 确认 · Esc/q 退出"))

    def _toggle_mock(self) -> None:
        """切换离线演示 / 真实模型模式（可来回切换）"""
        if self.client.mock:
            self.client = ModelClient(self.cfg, mock=False)
            print(c("green", "已切换回真实模型模式: " + self.client.describe()))
            if not self.cfg.get("base_url") or not self.cfg.get("api_key"):
                print(c("yellow", "  ⚠ 尚未配置模型/密钥，请先用 /config 或首页配置向导设置"))
        else:
            self.client = ModelClient(self.cfg, mock=True)
            print(c("green", "已切换为离线演示模式（mock，无需密钥）"))

    def _run_landing_action(self, action: str) -> bool:
        """执行首页菜单动作；返回 True 表示整体退出"""
        if action == "exit":
            self._clear_screen()
            print(c("dim", "  再见，ACE 已退出。"))
            return True
        if action == "chat":
            self.repl(return_to_landing=True)
            return False   # 聊天退出后回到主界面，而不是直接退出程序
        if action == "wizard":
            try:
                self._config_wizard()
            except CommandCancelled:
                print(c("yellow", "已取消。"))
            return False
        if action == "provider":
            self._handle_provider(["/provider"])
            self._wait_key()
            return False
        if action == "mock":
            self._toggle_mock()
            self._wait_key()
            return False
        if action == "status":
            self._show_status()
            self._wait_key()
            return False
        if action == "help":
            self.run_command("/help")
            self._wait_key()
            return False
        return False

    def landing(self) -> None:
        """登录页：默认进入的欢迎界面（清屏 → logo → ❯ 光标菜单）"""
        sel = 0
        while True:
            self._draw_landing(sel)
            key = self._read_key()
            if key is None:
                # 非交互（管道/重定向）：跳过首页直接进聊天
                self.repl()
                return
            if key == "up":
                sel = (sel - 1) % len(self.LANDING_ITEMS)
            elif key == "down":
                sel = (sel + 1) % len(self.LANDING_ITEMS)
            elif key == "enter":
                if self._run_landing_action(self.LANDING_ITEMS[sel][2]):
                    return
            elif key == "esc" or key == "q":
                self._clear_screen()
                print(c("dim", "  再见，ACE 已退出。"))
                return
            elif key.isdigit() and 1 <= int(key) <= len(self.LANDING_ITEMS):
                if self._run_landing_action(self.LANDING_ITEMS[int(key) - 1][2]):
                    return

    # ---------- 无感回滚 ----------

    def _undo_last(self) -> None:
        """一键回滚到最近一次自动快照（无需记 id，写入操作前都会自动快照）"""
        if not self.el.guardian:
            print(c("red", "快照模块未启用"))
            return
        snaps = self.el.guardian.list_snapshots()
        if not snaps:
            print("暂无快照可回滚（每次写入操作前都会自动创建快照）")
            return
        latest = snaps[-1]
        try:
            ok = self.el.guardian.rollback(latest["id"])
            if ok:
                print(c("green", f"已回滚到最近快照 {latest['id']} "
                                 f"（{latest.get('created_iso')}，{latest.get('file_count')} 个文件）"))
            else:
                print(c("red", "回滚不完整，备份已保留"))
        except Exception as e:
            print(c("red", f"回滚失败: {e}"))

    def _show_status(self) -> None:
        stats = self.el.get_stats()
        elapsed = time.time() - self.session["start"]
        print(f"  会话: {self.session['rounds']} 轮 | 工具执行 {self.session['tools']} 次 | "
              f"违规 {self.session['violations']} 次 | 已运行 {elapsed:.0f}s")
        print(f"  权限: {stats['permission']['current_level']} | "
              f"违规累计 {stats['violation_count']} | 执行累计 {stats['execution_count']}")
        if self.el.guardian:
            snaps = self.el.guardian.list_snapshots()
            limit = getattr(self.el.guardian, "max_snapshots", 20)
            print(f"  快照: {len(snaps)} 个（自动清理上限 {limit}，/undo 一键回滚最近）")
        print(f"  模块: v2={stats['v2_gateway']} v1={stats['v1_modules']} parser={stats['parser']}")

    def _show_memory(self) -> None:
        if not self.el.archive:
            print("记忆引擎未启用")
            return
        print(f"  {json.dumps(self.el.archive.stats(), ensure_ascii=False)}")
        mem = self.el.archive.get_memory(top_k=5)
        if not mem:
            print("  暂无记忆")
        for m in mem:
            mark = "⚡" if m["urgent"] else "·"
            print(f"  {mark} {m['text'][:60]}  (sim={m['similarity']}, w={m['weight']})")

    # ---------- REPL ----------

    def repl(self, return_to_landing: bool = False) -> None:
        """聊天 REPL；return_to_landing=True 时退出聊天回到主界面，否则结束程序"""
        print(c("bold", "ACE") + c("dim", " v1.0 · AI Code Engine"))
        print(f"  模型: {self.client.describe()}")
        print(f"  权限: {self.cfg['permission']} | 目录: {self.cfg['project_root']}")
        if self.cfg["permission"] != "readonly":
            print(c("yellow", "  ⚠ 当前为写权限：terminal_exec 可执行任意 shell 命令。"
                               "生产环境建议 readonly 起步，按需用 /permission 切换。"))
        print(f"  输入 {c('magenta', '/help')} 查看命令，{c('magenta', '/exit')} 退出")

        # 启动自检：配置防蠢提示
        for hint in _config_sanity_hints(self.cfg):
            print(c("yellow", f"  ⚠ {hint}"))

        # 实时补全：有 prompt_toolkit 就上 Claude Code 同款弹窗菜单，没有则降级普通输入
        session = None
        try:
            from prompt_toolkit import PromptSession
            from prompt_toolkit.styles import Style
            from prompt_toolkit.key_binding import KeyBindings

            kb = KeyBindings()

            @kb.add("escape")
            def _exit_on_escape(event):
                # 空输入时按 ESC 直接退出（菜单打开时 ESC 优先关闭菜单）
                if not event.current_buffer.text.strip():
                    raise EOFError

            session = PromptSession(
                completer=_build_slash_completer(self.COMMANDS),
                complete_while_typing=True,
                key_bindings=kb,
                style=Style.from_dict({
                    "prompt": "ansimagenta bold",
                    "completion-menu.completion": "bg:#2b2b3c #ffffff",
                    "completion-menu.completion.current": "bg:#5f3dc4 #ffffff",
                    "completion-menu.completion.meta": "bg:#1e1e2e #aaaaaa",
                }),
            )
        except ImportError:
            print(c("dim", "  💡 提示: 运行 ace --install-ui 一键安装实时补全依赖（Claude Code 同款 / 弹窗菜单）"))

        while True:
            try:
                if session is not None:
                    line = session.prompt([("class:prompt", "❯ ")]).strip()
                else:
                    line = input(c("magenta", "❯ ")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            # 防蠢：用户把 cmd 命令/参数误打进 REPL 时本地拦截，不发给模型
            if _looks_like_cli_command(line):
                self._handle_cli_mistype(line)
                continue
            if line.startswith("/") or line.lower() in ("exit", "quit"):
                try:
                    if not self.run_command(line):
                        break
                except CommandCancelled:
                    print(c("yellow", "已取消。"))
                except KeyboardInterrupt:
                    print("\n已取消。")
                except Exception as e:
                    print(c("red", f"命令执行失败: {e}"))
                continue
            try:
                self.converse(line)
            except KeyboardInterrupt:
                print("\n已中断")
            except Exception as e:
                print(c("red", f"对话异常: {e}"))
        print(c("dim", "  已返回主界面。") if return_to_landing
              else c("dim", "  再见，ACE 已退出。"))


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Code —— AI Agent 命令行终端")
    parser.add_argument("--mock", action="store_true", help="离线演示（脚本化假模型）")
    parser.add_argument("--base-url", help="API 地址（OpenAI 或 Anthropic 兼容）")
    parser.add_argument("--api-key", help="API Key")
    parser.add_argument("--model", help="模型名")
    parser.add_argument("--project-root", help="工作目录")
    parser.add_argument("--permission", choices=["readonly", "write", "full"], help="权限等级")
    parser.add_argument("--no-bait", action="store_true", help="关闭诱饵验证")
    parser.add_argument("--input", help="单次对话（非交互）")
    parser.add_argument("--save-config", action="store_true", help="把当前参数保存到 ~/.ai_code.json")
    parser.add_argument("--install-ui", action="store_true",
                        help="一键安装实时补全依赖（prompt_toolkit，Claude Code 同款 / 弹窗菜单）")
    args = parser.parse_args()

    if args.install_ui:
        print("正在安装 prompt_toolkit（自动检测已装状态 + 多镜像回退）...")
        if _pip_install_with_fallbacks("prompt_toolkit"):
            print("✅ 安装完成，重新启动 ace 即可享受 / 实时自动补全菜单")
        else:
            print("❌ 安装失败，请手动运行: "
                  "pip install prompt_toolkit -i https://pypi.tuna.tsinghua.edu.cn/simple")
        return

    cfg = merge_config(args)
    if args.no_bait:
        cfg["bait"] = False
    if args.save_config:
        save_cli_config(cfg)

    cli = AgentCLI(cfg, mock=args.mock)
    if args.input:
        cli.converse(args.input)
        return
    if args.mock:
        cli.repl()          # 显式离线演示直接进聊天
        return
    cli.landing()           # 默认进入登录页（AI-CLI 启动平台同款首页菜单）


if __name__ == "__main__":
    main()
