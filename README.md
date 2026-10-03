# 🔒 Secure Cipher Studio

A secure cross-platform GUI application for encrypting and decrypting messages using PBKDF2 key derivation and HMAC-SHA256 keystream authentication.

## ✨ Features
- **High Security**: Authenticated encryption using PBKDF2 & HMAC-SHA256.
- **Native macOS & Windows UI**: Clean interface optimized for Retina/High-DPI displays.
- **Cross-Platform**: Built using Python & Tkinter.

## 🚀 How to Run from Source

1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/SecureCipherStudio.git](https://github.com/YOUR_USERNAME/SecureCipherStudio.git)
   cd SecureCipherStudio
   ```

2. Run the application:
   ```bash
   python3 secure_cipher_mac.py
   ```

## 📦 Building Executables

- **macOS**: Run `./build_mac.sh`
- **Windows**: Run `build_win.bat` (or `pyinstaller --onefile --windowed --name SecureCipherStudio main.py`)

## 📥 Downloads
Pre-compiled binaries for Windows (`.exe`) and macOS (`.app`) are available in the **[Releases](https://github.com/muhammadwael0/SecureCipherStudio/releases)** section.
