@echo off
rem ACE launcher: uses ~/.ai_code.json (DeepSeek API: deepseek-v4-flash)
rem 模型端点/密钥不写在这里 —— 明文密钥留在 .cmd 里正是 L4 要拦的事。
rem 改模型: 会话内 /model、/provider，或直接编辑 ~/.ai_code.json
rem Usage: ace [extra args]  e.g.  ace --input "what time is it"
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
"C:\aider_env\Scripts\python.exe" ai_code.py --tools --max-history 12 %*
