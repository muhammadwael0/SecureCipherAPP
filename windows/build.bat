@echo off
chcp 65001 > NUL
title Automated Python Setup and Executable Builder

echo ===================================================
echo  1. Checking Python installation...
echo ===================================================

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed. Downloading Python installer...
    
    :: Download Python 3.11 installer using PowerShell
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile 'python_installer.exe'"
    
    echo [!] Installing Python silently and adding to PATH...
    start /wait python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    
    del python_installer.exe
    
    :: Update current session PATH variables
    set "PATH=%ProgramFiles%\Python311;%ProgramFiles%\Python311\Scripts;%LOCALAPPDATA%\Programs\Python\Python311;%LOCALAPPDATA%\Programs\Python\Python311\Scripts;%PATH%"
    
    echo [+] Python installed successfully!
) else (
    echo [+] Python is already installed.
)

echo.
echo ===================================================
echo  2. Installing Required Packages (PyInstaller)...
echo ===================================================

:: Note: base64, ctypes, hashlib, hmac, secrets, sys, tkinter are built-in standard libraries.
python -m pip install --upgrade pip
python -m pip install pyinstaller

echo.
echo ===================================================
echo  3. Building EXE File with PyInstaller...
echo ===================================================

python -m PyInstaller --noconfirm --onefile --noconsole secure_cipher.py

if %errorlevel% equ 0 (
    echo.
    echo ===================================================
    echo  SUCCESS! Your EXE file is in the 'dist' folder.
    echo ===================================================
    explorer dist
) else (
    echo.
    echo [ERROR] Build failed! Check the output messages above.
)

pause