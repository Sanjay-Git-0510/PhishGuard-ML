@echo off
title AegisThreat - System Test Suite
echo ========================================================
echo   Running Backend Pytest Suite (14 Unit & Integration Tests)
echo ========================================================
.\venv\Scripts\pytest
if %ERRORLEVEL% NEQ 0 (
    echo [!] Backend tests failed!
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ========================================================
echo   Running Frontend Code Analysis & Oxlint
echo ========================================================
cd frontend
call npm run lint
if %ERRORLEVEL% NEQ 0 (
    echo [!] Frontend linting failed!
    cd ..
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ========================================================
echo   Building Frontend Production Bundle
echo ========================================================
call npm run build
if %ERRORLEVEL% NEQ 0 (
    echo [!] Frontend build failed!
    cd ..
    pause
    exit /b %ERRORLEVEL%
)
cd ..

echo.
echo ========================================================
echo   [SUCCESS] All backend & frontend tests passed cleanly!
echo ========================================================
pause
