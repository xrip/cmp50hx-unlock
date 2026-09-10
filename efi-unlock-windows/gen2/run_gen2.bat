@echo off
rem ============================================================
rem  50HX Gen2 BYOVD unlock - run once (admin)
rem  Run as Administrator.  Deploys drivers, unlocks Gen2, keeps
rem  services running for inspection (run --selfclean to purge).
rem ============================================================
setlocal
cd /d "%~dp0"
set "PYEXE=python"
if exist "C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe" set "PYEXE=C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe"
echo [run] 50HX Gen2 BYOVD unlock...
"%PYEXE%" "%~dp050hx_gen2_byovd.py" %*
echo.
echo done. exit code above. log: %~dp050hx_gen2.log
pause
