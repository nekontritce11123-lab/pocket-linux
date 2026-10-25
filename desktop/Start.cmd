@echo off
chcp 65001 >nul
"%~dp0runtime\python-3.12.14\python.exe" -X utf8 -I -B "%~dp0start.py" %*
if errorlevel 1 pause
