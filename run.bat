@echo off
setlocal

cd /d "%~dp0"

:: Re-launch as admin if needed
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command ^
        "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Activate venv
call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo Failed to activate virtual environment.
    pause
    exit /b 1
)

:: Open browser after delay
start "" powershell -NoProfile -WindowStyle Hidden -Command ^
    "Start-Sleep -Seconds 3; Start-Process 'http://localhost:2139'"

echo.
echo EEG Monitor ^| http://localhost:2139
echo.

python visualizer.py

echo.
echo Python exited with code %errorlevel%
pause