@echo off
:: ================================================================
:: setup_crewai.bat — one-time setup of Python 3.12 venv for CrewAI
:: Run this ONCE before using run_poc.bat
:: ================================================================
setlocal

set VENV_DIR=%~dp0crewai_env

echo.
echo  Setting up CrewAI environment with Python 3.12...
echo.

:: ── Verify py launcher finds 3.12 ────────────────────────────────
py -3.12 --version
if errorlevel 1 (
    echo.
    echo  [ERROR] Python 3.12 not found by the py launcher.
    echo.
    echo  Install it:
    echo    winget install Python.Python.3.12
    echo  Then close and reopen this terminal and run setup again.
    pause & exit /b 1
)

:: ── Confirm it's actually 3.12 ───────────────────────────────────
for /f "tokens=*" %%v in ('py -3.12 -c "import sys; print(sys.version_info[:2])"') do set PYVER=%%v
echo  Python version check: %PYVER%

:: ── Remove old venv if it exists ─────────────────────────────────
if exist "%VENV_DIR%" (
    echo  Removing old venv...
    rmdir /s /q "%VENV_DIR%"
)

:: ── Create fresh venv with Python 3.12 ───────────────────────────
echo  Creating venv at %VENV_DIR%...
py -3.12 -m venv "%VENV_DIR%"
if errorlevel 1 (
    echo  [ERROR] Failed to create venv.
    pause & exit /b 1
)

:: ── Activate and verify we're actually on 3.12 ───────────────────
call "%VENV_DIR%\Scripts\activate.bat"

for /f "tokens=*" %%v in ('python -c "import sys; print(sys.version)"') do set ACTIVE_VER=%%v
echo  Active Python in venv: %ACTIVE_VER%

:: Bail if somehow not 3.12
python -c "import sys; sys.exit(0 if sys.version_info[:2]==(3,12) else 1)"
if errorlevel 1 (
    echo.
    echo  [ERROR] venv is NOT using Python 3.12.
    echo  The py launcher may be mapping -3.12 to the wrong install.
    echo.
    echo  Try this instead — find the exact python3.12 path:
    echo    where python
    echo    py -3.12 -c "import sys; print(sys.executable)"
    echo  Then edit this script to use that full path directly.
    pause & exit /b 1
)

:: ── Upgrade pip ──────────────────────────────────────────────────
echo  Upgrading pip...
python -m pip install --upgrade pip --quiet

:: ── Pre-install problematic packages with pinned wheel versions ──
echo  Installing regex and tiktoken (pinned to wheel versions)...
pip install "regex==2026.5.9" "tiktoken==0.9.0" --only-binary :all:
if errorlevel 1 (
    echo.
    echo  [ERROR] Could not install pre-built wheels.
    echo  This usually means Python version mismatch or no internet.
    pause & exit /b 1
)

:: ── Install crewai and requests ──────────────────────────────────
echo  Installing crewai...
pip install crewai requests
:: Install full requirements if present (one level up)
if exist "%~dp0..\requirements.txt" (
    echo Installing from requirements.txt ...
    pip install -r "%~dp0..\requirements.txt"
)
:: Check for nmap (optional — needed for active recon stage)
where nmap >nul 2>&1
if errorlevel 1 (
    echo.
    echo [INFO] nmap not found. The NMAP active-recon stage will be disabled.
    echo        Install it to enable:  choco install nmap
    echo        Or run passive-only:   set ENABLE_NMAP=0
) else (
    echo [OK] nmap found - active recon stage available
)
if errorlevel 1 (
    echo.
    echo  [ERROR] crewai install failed. See errors above.
    pause & exit /b 1
)

:: ── Verify ───────────────────────────────────────────────────────
echo.
python -c "import crewai; print('  crewai version:', crewai.__version__)"
python -c "import regex; print('  regex: OK')"
python -c "import tiktoken; print('  tiktoken: OK')"
python -c "import requests; print('  requests: OK')"

echo.
echo  =========================================================
echo   Setup complete! Now run:
echo     run_poc.bat anthropic    (if using Claude)
echo     run_poc.bat              (if using OpenAI)
echo  =========================================================
echo.
pause
