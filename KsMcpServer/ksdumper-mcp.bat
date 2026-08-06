@echo off
title KsDumper MCP Server (Auto-Restart)
echo [KsDumper] MCP Server starting...
echo [KsDumper] Press Ctrl+C to stop.
echo.

:loop
"%~dp0KsMcpServer.exe" %*
set exitcode=%errorlevel%

if %exitcode% equ 0 (
    echo [KsDumper] Server exited cleanly.
    exit /b 0
)

echo [KsDumper] Server exited with code %exitcode%. Restarting in 2 seconds...
timeout /t 2 /nobreak >nul
echo [KsDumper] Restarting...
goto loop
