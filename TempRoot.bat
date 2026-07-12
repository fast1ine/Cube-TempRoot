@echo off
setlocal

set "ADB=C:\platform-tools\adb.exe"
if not exist "%ADB%" set "ADB=adb"

set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=192.168.0.40:5555"

if not exist "%~dp0cube_temp_root" (
  echo ERROR: cube_temp_root was not found next to this batch file.
  exit /b 2
)

"%ADB%" connect "%TARGET%" >nul 2>&1
"%ADB%" -s "%TARGET%" push "%~dp0cube_temp_root" /data/local/tmp/cube_temp_root
if errorlevel 1 exit /b 3

"%ADB%" -s "%TARGET%" shell chmod 755 /data/local/tmp/cube_temp_root
if errorlevel 1 exit /b 4

echo.
echo Type exit at the cube-root prompt to restore the temporary credentials.
echo SELinux remains Enforcing in this shell.
echo Do not disconnect power while the temporary root shell is active.
echo.
"%ADB%" -s "%TARGET%" shell -t /data/local/tmp/cube_temp_root root-shell
set "ROOT_RC=%ERRORLEVEL%"

"%ADB%" -s "%TARGET%" shell rm -f /data/local/tmp/cube_temp_root >nul 2>&1
exit /b %ROOT_RC%
