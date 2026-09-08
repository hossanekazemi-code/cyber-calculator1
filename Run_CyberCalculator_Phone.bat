@echo off
title Cyber Calculator - Phone Server
cd /d "%~dp0"

echo.
echo ==============================================
echo      CYBER CALCULATOR - PHONE MODE
echo ==============================================
echo.
echo Requesting Windows Firewall permission...
echo.

netsh advfirewall firewall add rule name="Cyber Calculator Flask 5000" dir=in action=allow protocol=TCP localport=5000 >nul 2>&1

echo Starting server...
echo Keep this window OPEN while using the phone.
echo.
python app.py

pause
