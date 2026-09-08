@echo off
setlocal
cd /d "%~dp0"
python -m pip install -r requirements.txt
python -m pip install pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --name CyberCalculatorWeb CyberCalculatorWeb_single.py
if exist "dist\CyberCalculatorWeb.exe" (
  echo.
  echo BUILD SUCCESS: dist\CyberCalculatorWeb.exe
) else (
  echo BUILD FAILED
)
pause
