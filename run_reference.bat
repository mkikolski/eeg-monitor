@echo off
setlocal

cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

call ".venv\Scripts\activate.bat"

python reference\emotiv_server.py

pause
