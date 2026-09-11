@echo off
title fw2sbom - Firmware SBOM Generator
cd /d "%~dp0"
echo [fw2sbom] starting local service...
echo.
"%~dp0python.exe" "%~dp0service.py"
echo.
echo (service stopped - press any key to close this window)
pause >nul
