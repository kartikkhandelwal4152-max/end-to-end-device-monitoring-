@echo off
title Sentinel Agent Watchdog (Anti-Tamper Protection)
echo ============================================================
echo   ◈ SENTINEL WATCHDOG ACTIVE DEFENSE (Windows Anti-Tamper)
echo   ◈ Auto-Restart Enabled: Agent cannot be killed
echo ============================================================

:loop
echo [%date% %time%] Starting Sentinel Agent...
python agent.py %*
echo.
echo [!] SENTINEL AGENT TERMINATED OR KILLED!
echo [*] Anti-Tamper Watchdog is restarting agent in 2 seconds...
timeout /t 2 /nobreak >nul
goto loop
