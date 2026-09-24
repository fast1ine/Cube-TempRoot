@echo off
setlocal

set "ADB=C:\platform-tools\adb.exe"
if not exist "%ADB%" set "ADB=adb"

set "TARGET=%~1"
if not defined TARGET (
  echo ERROR: an ADB serial or address is required.
  echo Usage: %~nx0 ADB_SERIAL_OR_ADDRESS
  echo Run "adb devices" to list connected targets.
  exit /b 1
)

if not exist "%~dp0temp_root" (
  echo ERROR: temp_root was not found next to this batch file.
  exit /b 2
)

"%ADB%" -s "%TARGET%" push "%~dp0temp_root" /data/local/tmp/temp_root
if errorlevel 1 exit /b 3

"%ADB%" -s "%TARGET%" shell chmod 755 /data/local/tmp/temp_root
if errorlevel 1 exit /b 4

echo.
echo Type exit at the root prompt to restore the temporary credentials.
echo SELinux remains Enforcing in this shell.
echo Do not disconnect power while the temporary root shell is active.
echo.
"%ADB%" -s "%TARGET%" shell -t /data/local/tmp/temp_root root-shell
set "ROOT_RC=%ERRORLEVEL%"

"%ADB%" -s "%TARGET%" shell rm -f /data/local/tmp/temp_root >nul 2>&1
exit /b %ROOT_RC%
