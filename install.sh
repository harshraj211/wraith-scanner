#!/bin/bash

echo "=============================================="
echo "  VulnScanner Installation Script"
echo "=============================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "[!] Please do not run as root"
    exit 1
fi

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip3 install -r requirements.txt --user

# Install package
echo "[+] Installing VulnScanner..."
pip3 install -e . --user

# Check if Node.js is installed (for web terminal)
if command -v node &> /dev/null; then
    echo "[+] Node.js found. Installing web terminal dependencies..."
    cd scanner-terminal
    npm install
    cd ..
else
    echo "[!] Node.js not found. Web terminal will not be available."
    echo "    Install Node.js to use the web interface."
fi

echo ""
echo "=============================================="
echo "  Installation Complete!"
echo "=============================================="
echo ""
echo "Usage:"
echo "  CLI Mode:  python3 main.py --url <target>"
echo "  Web Mode:  python3 api_server.py"
echo ""