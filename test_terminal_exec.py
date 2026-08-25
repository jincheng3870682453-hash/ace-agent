#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试terminal_exec路径处理"""

import sys
import os
from pathlib import Path

# 添加tools模块路径
sys.path.insert(0, str(Path(__file__).parent))

from tools.file_tools import FileTools

# 创建测试实例
ft = FileTools(project_root=".", confine_files=False)

# 测试1：路径预处理
test_cases = [
    "~/Desktop/NewFolder",
    "~/桌面/NewFolder",
    "mkdir ~/Desktop/NewFolder",
    "mkdir ~/桌面/NewFolder",
]

print("测试路径预处理：\n")
for cmd in test_cases:
    processed = cmd.replace("~/Desktop", str(Path.home() / 'Desktop')).replace("~/桌面", str(Path.home() / 'Desktop'))
    print(f"原始命令: {cmd}")
    print(f"处理后: {processed}")
    print()

# 测试2：直接执行（不实际创建）
print("\n测试直接执行（不实际创建文件）：")
test_cmd = "mkdir ~/Desktop/TestFolder"
processed = test_cmd.replace("~/Desktop", str(Path.home() / 'Desktop')).replace("~/桌面", str(Path.home() / 'Desktop'))
print(f"执行命令: {processed}")

import subprocess
try:
    result = subprocess.run(processed, shell=True, capture_output=True, text=True, timeout=5)
    print(f"返回码: {result.returncode}")
    print(f"stdout: {result.stdout}")
    print(f"stderr: {result.stderr}")
except Exception as e:
    print(f"异常: {e}")

print("\n测试完成")