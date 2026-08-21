@echo off
rem ACE launcher: local Ollama + Qwen2.5-Coder with native tools
rem Usage: ace [extra args]  e.g.  ace --input "what time is it"
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
"C:\aider_env\Scripts\python.exe" ai_code.py --tools --max-history 12 --base-url http://localhost:11434/v1 --api-key ollama --model Qwen2.5-coder:7b %*
