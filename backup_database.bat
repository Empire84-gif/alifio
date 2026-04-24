@echo off
setlocal

set PROJECT_DIR=%~dp0
set DB_FILE=%PROJECT_DIR%database.db
set BACKUP_DIR=%PROJECT_DIR%backups

if not exist "%BACKUP_DIR%" (
    mkdir "%BACKUP_DIR%"
)

for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd_HH-mm-ss"') do set TIMESTAMP=%%i

copy "%DB_FILE%" "%BACKUP_DIR%\database_%TIMESTAMP%.db" >nul

forfiles /p "%BACKUP_DIR%" /m *.db /d -90 /c "cmd /c del /q @path"

endlocal