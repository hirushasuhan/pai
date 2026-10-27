@echo off
setlocal
set "SCRIPT_DIR=%~dp0"

if "%~1"=="progress" (
    python "%SCRIPT_DIR%tools\check_n_plus_1.py" %2 %3 %4 %5 %6 %7 %8 %9
    exit /b %ERRORLEVEL%
)

python "%SCRIPT_DIR%research\pai.py" %*
