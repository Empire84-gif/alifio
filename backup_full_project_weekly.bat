@echo off
setlocal

set PROJECT_DIR=%~dp0
set TARGET_ROOT=E:\Alifio_Weekly_Backups

for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd_HH-mm-ss"') do set TIMESTAMP=%%i

set DEST_DIR=%TARGET_ROOT%\Alifio_%TIMESTAMP%

if not exist "%TARGET_ROOT%" (
    mkdir "%TARGET_ROOT%"
)

robocopy "%PROJECT_DIR%" "%DEST_DIR%" /E /XD "%PROJECT_DIR%backups" "%PROJECT_DIR%__pycache__" "%PROJECT_DIR%venv" "%PROJECT_DIR%env" ".git" /XF "*.pyc"

endlocal