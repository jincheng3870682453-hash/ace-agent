@echo off
rem ACE launcher: uses ~/.ai_code.json (DeepSeek API: deepseek-v4-flash)
rem 模型端点/密钥不写在这里 —— 明文密钥留在 .cmd 里正是 L4 要拦的事。
rem 改模型: 会话内 /model、/provider，或直接编辑 ~/.ai_code.json
rem Usage: ace [extra args]  e.g.  ace --input "what time is it"
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

rem 解释器探测（不再硬编码某台机器的路径；优先 python，其次 py -3 启动器）
set "_ACE_PY="
where python >nul 2>nul && set "_ACE_PY=python"
if not defined _ACE_PY (where py >nul 2>nul && set "_ACE_PY=py -3")
if not defined _ACE_PY (
    echo [ACE] 未找到 Python。请安装 Python 3.10+ 并勾选 "Add python.exe to PATH"，或把 ace.cmd 第 8 行改成你的解释器路径。
    pause
    exit /b 1
)
%_ACE_PY% ai_code.py --tools --max-history 12 %*
