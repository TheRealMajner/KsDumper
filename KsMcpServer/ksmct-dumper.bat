@echo off
title KsMCT Dumper - MCP Server (Auto-Restart)
echo [KsMCT Dumper] MCP Server starting...
echo [KsMCT Dumper] Press Ctrl+C to stop.
echo.

:loop
"%~dp0KsMcpServer.exe" %*
set exitcode=%errorlevel%

if %exitcode% equ 0 (
    echo [KsMCT Dumper] Server exited cleanly.
    exit /b 0
)

echo [KsMCT Dumper] Server exited with code %exitcode%. Restarting in 2 seconds...
timeout /t 2 /nobreak >nul
echo [KsMCT Dumper] Restarting...
goto loop
