@echo off
REM Startup script for NFC Mnemonic Backup System

echo ================================================
echo NFC 助记词离线备份系统
echo ================================================
echo.

REM Check if Python 3 is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python 3 is not installed. Please install Python 3.7 or higher.
    pause
    exit /b 1
)

echo ✓ Python found
python --version

REM Check if dependencies are installed
echo.
echo Checking dependencies...
python -c "import aiohttp" >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing dependencies...
    pip install -r requirements.txt
)

echo ✓ Dependencies installed

echo.
echo ================================================
echo Starting server...
echo ================================================
echo.
echo Server will be available at: http://127.0.0.1:8080
echo.
echo ⚠️  IMPORTANT SECURITY NOTES:
echo   • Server only listens on 127.0.0.1 (localhost)
echo   • All data is stored in memory only
echo   • Data is cleared when you close the browser or restart the server
echo   • For security, disconnect from the internet before use
echo.
echo Press Ctrl+C to stop the server
echo.

REM Run the server
python server.py
