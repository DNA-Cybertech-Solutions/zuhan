@echo off
rem Starts the ZUHAN web UI. Closing this window stops it.
cd /d "%~dp0"
if exist "zuhan.exe" (
  "zuhan.exe" web
) else (
  "zuhan-windows-amd64.exe" web
)
pause
