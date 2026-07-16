@echo off
REM Build the AutoSOC Windows executable and installer.
REM Prerequisites: Python 3.12+, and (for the installer) Inno Setup 6.
setlocal

echo ==^> Installing build dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt pyinstaller pyinstaller-hooks-contrib
if errorlevel 1 goto :error

echo ==^> Building AutoSOC.exe
python -m PyInstaller --clean --noconfirm main.spec
if errorlevel 1 goto :error

echo ==^> Building installer (requires Inno Setup 6)
set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if exist %ISCC% (
    %ISCC% installer\AutoSOC_Setup.iss
) else (
    echo Inno Setup not found; skipping installer. dist\AutoSOC.exe is ready.
)

echo.
echo ==^> Done. See dist\AutoSOC.exe and installer\AutoSOC_Setup.exe
goto :eof

:error
echo Build failed.
exit /b 1
