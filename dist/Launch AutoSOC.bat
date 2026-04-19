@echo off
setlocal
cd /d "%~dp0"

set "APP=%~dp0AutoSOC.exe"

if not exist "%APP%" (
    echo AutoSOC.exe not found in "%~dp0".
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%APP%' -WorkingDirectory '%~dp0' -Verb RunAs"
if errorlevel 1 (
    echo Failed to start AutoSOC.exe with administrator rights.
    pause
    exit /b 1
)

exit /b 0
