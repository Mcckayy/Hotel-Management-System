@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 goto nonode
if exist node_modules goto haveModules
echo Installing, this takes a minute or two...
call npm install
if errorlevel 1 goto installfail
:haveModules
if not exist .env call node setup.js --local
if not exist .env goto setupfail
start "" cmd /c "timeout /t 4 >nul & start http://localhost:3000"
echo.
echo HotelDesk is starting at http://localhost:3000  (close this window to stop it)
call npm start
echo.
echo The server stopped. Read the message above, and send it to me if it is an error.
pause
exit /b 0
:nonode
echo Node.js is not installed. Install the LTS version from https://nodejs.org and run this again.
pause
exit /b 1
:installfail
echo The install failed. Read the message above.
pause
exit /b 1
:setupfail
echo Setup did not finish, so the system cannot start. Run start.bat again.
pause
exit /b 1
