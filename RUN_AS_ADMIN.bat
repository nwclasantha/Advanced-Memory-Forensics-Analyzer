@echo off
:: ============================================================
:: MEMORY FORENSICS ANALYZER - ADMIN LAUNCHER
:: ============================================================

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% == 0 (
    echo Running with Administrator privileges...
    cd /d "%~dp0"
    python memory_forensics_tool.py
    pause
    exit /b
)

:: Not admin - request elevation
echo.
echo ============================================================
echo   REQUESTING ADMINISTRATOR PRIVILEGES...
echo ============================================================
echo.
echo   A Windows prompt will appear.
echo   Click "Yes" to allow Administrator access.
echo.
pause

:: Re-run this script as admin
powershell -Command "Start-Process '%~f0' -Verb RunAs"
exit /b
