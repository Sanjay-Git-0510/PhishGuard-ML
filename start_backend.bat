@echo off
title AegisThreat - Phishing Detection Backend
echo ========================================================
echo   Starting AegisThreat Static ML Backend Server
echo   FastAPI + Uvicorn on http://127.0.0.1:8000
echo ========================================================
echo.
cd /d "%~dp0\backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Trying fallback with virtual environment...
    ..\venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
)
pause

