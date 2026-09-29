@echo off
title AegisThreat - SOC Dashboard Frontend
echo ========================================================
echo   Starting AegisThreat SOC Frontend Dashboard
echo   Vite + React on http://localhost:5173
echo ========================================================
echo.
cd /d "%~dp0\frontend"
npm run dev
pause
