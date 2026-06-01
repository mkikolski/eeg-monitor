@echo off
cd /d "%~dp0"

REM Re-launch with admin privileges if not already elevated (needed for HID access)
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

call .venv\Scripts\activate.bat

REM Open browser after 3 s in background — gives the server time to start
start "" /B powershell -WindowStyle Hidden -Command "Start-Sleep 3; Start-Process 'http://localhost:2139'"

echo.
echo  EEG Monitor  ^|  http://localhost:2139
echo.
python visualizer.py
