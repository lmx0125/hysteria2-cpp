@echo off
rem One-click commit + push for hysteria2-cpp. Chinese output comes from commit.ps1.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0commit.ps1" %*
echo.
pause
