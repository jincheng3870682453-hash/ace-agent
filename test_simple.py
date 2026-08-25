#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import os
from pathlib import Path

# 测试1：PowerShell中的~展开
print("测试1：PowerShell中~的展开")
cmd1 = "mkdir ~/Desktop/TestFolder"
print(f"命令: {cmd1}")

try:
    result = subprocess.run(cmd1, shell=True, capture_output=True, text=True, timeout=5)
    print(f"返回码: {result.returncode}")
    print(f"stdout: {result.stdout}")
    print(f"stderr: {result.stderr}")
except Exception as e:
    print(f"异常: {e}")

print("\n" + "="*50 + "\n")

# 测试2：Windows绝对路径
print("测试2：Windows绝对路径")
home = str(Path.home())
desktop = os.path.join(home, "Desktop")
cmd2 = f'mkdir "{desktop}\\TestFolder2"'
print(f"命令: {cmd2}")

try:
    result = subprocess.run(cmd2, shell=True, capture_output=True, text=True, timeout=5)
    print(f"返回码: {result.returncode}")
    print(f"stdout: {result.stdout}")
    print(f"stderr: {result.stderr}")
except Exception as e:
    print(f"异常: {e}")

print("\n" + "="*50 + "\n")

# 测试3：检查Desktop目录
print("测试3：检查Desktop目录")
print(f"Home: {home}")
print(f"Desktop: {desktop}")
print(f"Desktop存在: {os.path.exists(desktop)}")