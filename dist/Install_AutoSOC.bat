@echo off
setlocal EnableExtensions
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b
)

set "TARGET=%ProgramFiles%\AutoSOC"
if not exist "%TARGET%" mkdir "%TARGET%"

copy /Y "%~dp0AutoSOC.exe" "%TARGET%\AutoSOC.exe" >nul
copy /Y "%~dp0Launch AutoSOC.bat" "%TARGET%\Launch AutoSOC.bat" >nul

if exist "%~dp0ai_memory.json" copy /Y "%~dp0ai_memory.json" "%TARGET%\ai_memory.json" >nul
if exist "%~dp0soc_audit.db" copy /Y "%~dp0soc_audit.db" "%TARGET%\soc_audit.db" >nul
if exist "%~dp0.env.example" copy /Y "%~dp0.env.example" "%TARGET%\.env.example" >nul

powershell -NoProfile -ExecutionPolicy Bypass -Command "$desktop=[Environment]::GetFolderPath('Desktop'); $shell=New-Object -ComObject WScript.Shell; $shortcut=$shell.CreateShortcut((Join-Path $desktop 'AutoSOC.lnk')); $shortcut.TargetPath='%TARGET%\Launch AutoSOC.bat'; $shortcut.WorkingDirectory='%TARGET%'; $shortcut.IconLocation='%TARGET%\AutoSOC.exe,0'; $shortcut.Save()"

echo.
echo AutoSOC installed to: %TARGET%
echo Desktop shortcut created.
echo.

if exist "%ProgramFiles(x86)%\Nmap\nmap.exe" goto nmap_ok
if exist "%ProgramFiles%\Nmap\nmap.exe" goto nmap_ok

echo WARNING: Nmap is not installed.
echo Network scan features need Nmap. Install it separately, then reopen AutoSOC.
echo.

:nmap_ok
echo Optional components:
echo - Telegram bot token: create/edit "%TARGET%\.env"
echo - Ollama: only needed for local AI mode
echo.
echo Press any key to launch AutoSOC.
pause >nul

powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%TARGET%\AutoSOC.exe' -WorkingDirectory '%TARGET%' -Verb RunAs"
exit /b 0
