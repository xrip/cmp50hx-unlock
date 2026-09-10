@echo off
rem ============================================================
rem  50HX Gen2 BYOVD unlock - remove autostart + purge drivers
rem ============================================================
setlocal
schtasks /Delete /TN "50HXGen2" /F 2>nul
sc stop ThrottleStop       >nul 2>&1
sc delete ThrottleStop     >nul 2>&1
sc stop WinRing0_1_2_0     >nul 2>&1
sc delete WinRing0_1_2_0   >nul 2>&1
del /f "%SystemRoot%\System32\drivers\ThrottleStop.sys" >nul 2>&1
del /f "%SystemRoot%\System32\drivers\WinRing0x64.sys"  >nul 2>&1
echo Cleaned: task removed, services deleted, driver files removed.
pause
