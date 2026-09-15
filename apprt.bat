@echo off
:: apprt.bat — convenience launcher for apprt
:: Double-click or run from any terminal.
:: Forwards all arguments to run.py (which handles UAC elevation).

setlocal

:: Resolve the directory this .bat lives in
set "SCRIPT_DIR=%~dp0"

:: Use the Python interpreter on PATH (or specify full path if needed)
set "PYTHON=python"

echo.
echo  ======================================================
echo    apprt - Advanced Port Inspector
echo    Privileged Launcher
echo  ======================================================
echo.

%PYTHON% "%SCRIPT_DIR%run.py" %*

if errorlevel 1 (
    echo.
    echo  [apprt] Exited with an error. Check output above.
    pause
)

endlocal
