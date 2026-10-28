@echo off
echo ===> Setting up Sentinel Agent Auto-Start for shlok_laptop...

cd /d "%USERPROFILE%\Downloads"
curl.exe -s -O https://raw.githubusercontent.com/kartikkhandelwal4152-max/end-to-end-device-monitoring-/main/agent.py
pip install psutil requests >nul 2>&1

set STARTUP_BAT=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\sentinel.bat

(
echo @echo off
echo set SENTINEL_DEVICE_TOKEN=f2UUFNDtcLGzanLuy0AJGCFYCrxnvYX4jhry1uRH3gs
echo cd /d "%%USERPROFILE%%\Downloads"
echo start /B pythonw agent.py --device shlok_laptop --server https://sentinel-backend-io5l.onrender.com
) > "%STARTUP_BAT%"

call "%STARTUP_BAT%"

echo ===> SUCCESS! Sentinel Agent is running in background.
echo ===> It will now auto-start every time Windows turns on!
