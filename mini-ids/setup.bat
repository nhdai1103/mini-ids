@echo off
REM Mini IDS - Setup and Demo Script for Windows

echo.
echo ╔════════════════════════════════════════════════════════╗
echo ║     Mini IDS - Intrusion Detection System Setup      ║
echo ║                  Windows Edition                       ║
echo ╚════════════════════════════════════════════════════════╝
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://www.python.org
    pause
    exit /b 1
)

echo ✅ Python found
echo.
echo 📦 Installing dependencies...
echo.

REM Install requirements
pip install -r requirements.txt

if errorlevel 1 (
    echo ❌ Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo ✅ Dependencies installed successfully!
echo.
echo 🎯 Running demo...
echo.

REM Run demo
python demo.py

echo.
echo ╔════════════════════════════════════════════════════════╗
echo ║             Setup Complete! 🎉                         ║
echo ║                                                         ║
echo ║ Next steps:                                             ║
echo ║   1. Run dashboard: python app.py                      ║
echo ║   2. Open: http://localhost:5000                       ║
echo ║   3. In another terminal: python monitor.py            ║
echo ║                                                         ║
echo ║ For more info, see QUICKSTART.md                       ║
echo ╚════════════════════════════════════════════════════════╝
echo.

pause
