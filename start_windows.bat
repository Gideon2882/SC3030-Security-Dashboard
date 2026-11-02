@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  py -m venv .venv
  if errorlevel 1 goto :failed
)
echo Installing / verifying dependencies...
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto :failed
echo Starting local dashboard...
.venv\Scripts\python.exe -m streamlit run app.py
if errorlevel 1 goto :failed
exit /b 0
:failed
echo.
echo Could not start dashboard. See README.md for manual steps.
pause
exit /b 1
