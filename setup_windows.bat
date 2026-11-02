@echo off
python "%~dp0install_agent.py" %*
exit /b %errorlevel%
