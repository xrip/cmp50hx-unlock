@echo off
rem ============================================================
rem  50HX Gen2 BYOVD unlock - register LOGON autostart (admin)
rem  Registers a scheduled task that runs the unlock at every
rem  logon with --selfclean (drivers auto-removed after unlock,
rem  so the system is left clean for games / anti-cheat).
rem ============================================================
setlocal
cd /d "%~dp0"

set "PYEXE=python"
if exist "C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe" set "PYEXE=C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe"

echo [1/3] verify driver files exist...
if not exist "drivers\ThrottleStop.sys" (echo   MISSING drivers\ThrottleStop.sys & goto :err)
if not exist "drivers\WinRing0x64.sys"  (echo   MISSING drivers\WinRing0x64.sys  & goto :err)
echo   ok

echo [2/3] register scheduled task "50HXGen2" (logon, highest)...
set "SCRIPT_CMD=cmd /c cd /d "%~dp0" && "%PYEXE%" 50hx_gen2_byovd.py --selfclean"
schtasks /Create /F /TN "50HXGen2" /TR "%SCRIPT_CMD%" /SC ONLOGON /RL HIGHEST /RU "%USERNAME%" 2>&1
if errorlevel 1 (echo   task create returned error) else (echo   ok)

echo [3/3] unlock once now to verify...
"%PYEXE%" 50hx_gen2_byovd.py --selfclean
echo.
echo Done.  remove autostart:  schtasks /Delete /TN "50HXGen2" /F
pause
exit /b 0
:err
echo Aborted - missing files.
pause
exit /b 1
