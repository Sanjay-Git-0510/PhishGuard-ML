@echo off
title AegisThreat - Phishing Detection System Launcher
echo ===================================================================
echo     AEGISTHREAT - ML-POWERED PHISHING DETECTION SYSTEM
echo     Static Lexical URL Intelligence & SOC Dashboard
echo ===================================================================
echo.
echo [*] Launching Backend Server (FastAPI on http://127.0.0.1:8000)...
start "AegisThreat Backend API" cmd /k "%~dp0start_backend.bat"

echo [*] Launching Frontend SOC Dashboard (Vite on http://localhost:5173)...
start "AegisThreat Frontend Dashboard" cmd /k "%~dp0start_frontend.bat"

echo.
echo ===================================================================
echo   Both services are launching in separate terminal windows!
echo   - Backend Swagger Docs: http://127.0.0.1:8000/docs
echo   - Frontend SOC Feed:   http://localhost:5173
echo ===================================================================
echo.
pause
