@echo off
:: ============================================================
:: AI-Powered IDS — Windows Setup Script
:: Run this ONCE to install everything needed.
:: ============================================================

echo.
echo ======================================================
echo  AI-Powered IDS — Windows Setup
echo ======================================================
echo.

:: ── Enable Windows Long Paths (needed for Jupyter) ──────────
echo [*] Enabling Windows Long Path support...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] Could not enable Long Paths (need Admin). Jupyter may fail to install.
    echo        To fix: run this script as Administrator.
) else (
    echo [OK] Long Path support enabled.
)

:: ── Check Python ────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found.
    echo         Download from https://www.python.org/downloads/
    echo         Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)
echo [OK] Python found:
python --version

:: ── Upgrade pip ─────────────────────────────────────────────
echo.
echo [*] Upgrading pip...
python -m pip install --upgrade pip -q

:: ── Install Python packages ──────────────────────────────────
echo.
echo [*] Installing Python packages (this may take a few minutes)...
python -m pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo [ERROR] Package installation failed. Check the error above.
    pause
    exit /b 1
)
echo [OK] Python packages installed.

:: ── Npcap check ─────────────────────────────────────────────
echo.
echo ======================================================
echo  IMPORTANT: Npcap Required for Live Traffic Capture
echo ======================================================
echo.
echo  Npcap is the Windows packet capture library used by Scapy.
echo  Without it, live traffic monitoring (--live flag) will fail.
echo.
echo  Steps:
echo    1. Open https://npcap.com  in your browser
echo    2. Download the latest Npcap installer
echo    3. Run the installer (keep default options)
echo    4. Reboot if prompted
echo.
echo  Already installed? You can skip this step.
echo.

set /p OPEN_NPCAP=Open Npcap download page now? (y/n):
if /i "%OPEN_NPCAP%"=="y" (
    start https://npcap.com/#download
)

:: ── Create .env if not exists ────────────────────────────────
echo.
if not exist .env (
    echo [*] Creating .env from template...
    copy .env.example .env >nul
    echo [OK] .env created — edit it to add your API keys (optional).
) else (
    echo [OK] .env already exists.
)

echo.
echo ======================================================
echo  Setup Complete!
echo ======================================================
echo.
echo  Run demos (no live capture):
echo    python ids_app.py
echo.
echo  Run with live traffic capture (requires Admin + Npcap):
echo    Right-click this folder -> Open PowerShell as Administrator
echo    python ids_app.py --live
echo    python ids_app.py --live --duration 120
echo.
echo  Run the Jupyter notebook:
echo    jupyter notebook "AI_Powered_IDS_Final (1).ipynb"
echo.
pause
