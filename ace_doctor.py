#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ace_doctor.py —— 环境自检(纯 stdlib,只读诊断,不联网必须项)

用法:
    python ace_doctor.py          # 打印诊断;退出码恒 0(诊断本身失败也是信息)
    ACE_DOCTOR_NET=1 python ace_doctor.py   # 额外探测出网/模型端点(TCP 层,3s 超时)

用途:装好依赖/切机器/报 issue 前先跑一遍,把"哪一项没就绪"一次说清。
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        if _s.encoding and _s.encoding.lower() not in ("utf-8", "utf8"):
            _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = Path(__file__).resolve().parent


def ok(msg: str):
    print("  [\u2705] " + msg)


def warn(msg: str):
    print("  [\u26a0] " + msg)


def info(msg: str):
    print("  [\u2139] " + msg)


def main() -> int:
    print("ace doctor — 环境自检")
    print("  Python   :", platform.python_version(), platform.platform())
    print("  CWD      :", Path.cwd())
    print("  REPO     :", ROOT)

    # 依赖能力(可选)与核心文件
    for name in ("requests", "prompt_toolkit", "PIL"):
        try:
            __import__(name)
            ok(f"依赖 {name}: 已装")
        except Exception:
            warn(f"依赖 {name}: 未装(可选;缺哪个见 requirements.txt 注释)")
    for rel in ("prompts/agent_system_prompt_v8.md", "prompts/agent_system_prompt_tools.md",
                "locales/zh.json", "locales/en.json", "locales/ja.json",
                "tools/registry.py", "execution_layer.py"):
        p = ROOT / rel
        ok(f"文件 {rel}: 存在") if p.exists() else warn(f"文件 {rel}: 缺失")

    # Go 执行器(off 档可选增强;job 档必需)
    exe_names = ["ace-executor.exe", "ace-executor", "executor.exe"]
    found = next((ROOT / "executor" / n for n in exe_names if (ROOT / "executor" / n).exists()), None)
    if found:
        ok(f"Go 执行器: {found.name}(就地编译产物)")
    else:
        warn("Go 执行器: 未找到 → 可选项;--sandbox job 需先 cd executor && go build")

    # Docker(可选;--sandbox docker 档必需)
    if shutil.which("docker"):
        try:
            r = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                               capture_output=True, text=True, timeout=5)
            ok("Docker 守护进程: " + (r.stdout.strip() or "连接失败")) if r.returncode == 0 \
                else warn("docker CLI 存在但守护进程不可用(--sandbox docker 会诚实 503)")
        except subprocess.TimeoutExpired:
            warn("Docker 探测超时(未起守护进程?)")
    else:
        warn("docker 未安装(仅 --sandbox docker 需要)")

    # 用户配置
    cfg = Path.home() / ".ai_code.json"
    if cfg.exists():
        ok("~/.ai_code.json: 存在(ACE 与 ace.cmd 会读取;密钥以星号提示,不回显)")
    else:
        warn("~/.ai_code.json: 不存在 → 首次运行走 ai_code.py 配置向导,或用 --mock 离线演示")

    # 可选的出网探测
    if os.environ.get("ACE_DOCTOR_NET") == "1":
        import socket
        for host, port in (("api.github.com", 443), ("api.deepseek.com", 443),
                           ("localhost", 11434)):
            try:
                with socket.create_connection((host, port), timeout=3):
                    ok(f"网络可达: {host}:{port}")
            except OSError as e:
                warn(f"网络不可达: {host}:{port} ({e})")
    else:
        info("出网探测跳过;需检查时用 ACE_DOCTOR_NET=1 python ace_doctor.py")

    print("自检完成(退出码恒 0;⚠ 仅提示,不影响运行)。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
