#!/bin/bash

echo "==================================================="
echo " 🚀 Starting macOS Build Process..."
echo "==================================================="

# 1. Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed. Installing Python 3..."
    if ! command -v brew &> /dev/null; then
        echo "[!] Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install python
else
    echo "[+] Python 3 is installed: $(python3 --version)"
fi

echo ""
echo "==================================================="
echo " 2. Installing and updating PyInstaller..."
echo "==================================================="
python3 -m pip install --upgrade pip
python3 -m pip install pyinstaller

echo ""
echo "==================================================="
echo " 3. Cleaning up previous build artifacts..."
echo "==================================================="
rm -rf build dist *.spec

echo ""
echo "==================================================="
echo " 4. Building macOS Application Bundle (.app)..."
echo "==================================================="

# Build standalone GUI application bundle
python3 -m PyInstaller \
    --noconfirm \
    --onedir \
    --windowed \
    --name "SecureCipherStudio" \
    secure_cipher.py

if [ $? -eq 0 ]; then
    echo ""
    echo "==================================================="
    echo " ✅ Build successful!"
    echo " 📦 Your app bundle is ready: SecureCipherStudio.app"
    echo " 📂 Located in folder: dist"
    echo "==================================================="
    open dist
else
    echo ""
    echo "[❌] Build failed! Please check error output above."
fi