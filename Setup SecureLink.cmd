@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  python -m venv .venv
  if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
echo Setup complete. Double-click Launch SecureLink.cmd to open the application.
pause
exit /b 0
:failed
echo Setup failed. Check the message above and ensure Python is installed.
pause
exit /b 1
