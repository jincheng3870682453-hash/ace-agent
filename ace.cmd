@echo off
rem ACE launcher: reads ~/.ai_code.json for model config. No secrets stored here.
rem Usage: ace [extra args]   e.g.  ace --input "what time is it"
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
if not defined ACE_DIRECT_CHAT set ACE_DIRECT_CHAT=1
cd /d "%~dp0"

rem Interpreter resolution order:
rem   1) ACE_PYTHON env var (explicit)
rem   2) C:\aider_env\Scripts\python.exe (local dev env, kept working)
rem   3) "python" on PATH, but only if it really launches (ignore MS Store stub)
rem   4) "py -3" launcher
set "_ACE_PY="
if defined ACE_PYTHON (set "_ACE_PY=%ACE_PYTHON%")
if not defined _ACE_PY (if exist "C:\aider_env\Scripts\python.exe" set "_ACE_PY=C:\aider_env\Scripts\python.exe")
if not defined _ACE_PY (where python >nul 2>nul && python -c "import sys" >nul 2>nul && set "_ACE_PY=python")
if not defined _ACE_PY (where py >nul 2>nul && set "_ACE_PY=py -3")
if not defined _ACE_PY (
    echo [ACE] Python not found. Install Python 3.10+ and add it to PATH,
    echo        or set ACE_PYTHON to the full path of your python.exe.
    pause
    exit /b 1
)
%_ACE_PY% ai_code.py --tools --max-history 12 %*
