@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment in .venv ...
  python -m venv .venv
  if errorlevel 1 (
    echo Python 3.11+ is required. Install it from https://www.python.org/downloads/ and retry.
    pause
    exit /b 1
  )
)

call ".venv\Scripts\activate.bat"
python -m pip install --disable-pip-version-check -q -r requirements.txt
python run.py %*
pause
