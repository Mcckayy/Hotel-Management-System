@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 goto nonode
if not exist .env goto noenv
where vercel >nul 2>nul
if errorlevel 1 call npm install -g vercel
call node deploy.js
echo.
pause
exit /b 0
:nonode
echo Node.js is not installed. Install the LTS version from https://nodejs.org and run this again.
pause
exit /b 1
:noenv
echo No settings file yet. Double-click start.bat once first, then run this again.
pause
exit /b 1
