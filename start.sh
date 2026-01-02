#!/bin/bash
# Startup script for NFC Mnemonic Backup System

echo "================================================"
echo "NFC 助记词离线备份系统"
echo "================================================"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

echo "✓ Python 3 found: $(python3 --version)"

# Check if dependencies are installed
echo ""
echo "Checking dependencies..."
if ! python3 -c "import aiohttp" &> /dev/null; then
    echo "Installing dependencies..."
    pip3 install -r requirements.txt
fi

echo "✓ Dependencies installed"

# Check for PC/SC daemon (optional)
echo ""
if command -v pcscd &> /dev/null; then
    echo "✓ PC/SC daemon found"
    # Start pcscd if not running
    if ! pgrep -x pcscd > /dev/null; then
        echo "  Starting PC/SC daemon..."
        sudo pcscd
    fi
else
    echo "⚠️  PC/SC daemon not found. NFC reader may not work."
    echo "   Install with: sudo apt-get install pcscd (Linux)"
fi

echo ""
echo "================================================"
echo "Starting server..."
echo "================================================"
echo ""
echo "Server will be available at: http://127.0.0.1:8080"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "  • Server only listens on 127.0.0.1 (localhost)"
echo "  • All data is stored in memory only"
echo "  • Data is cleared when you close the browser or restart the server"
echo "  • For security, disconnect from the internet before use"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the server
python3 server.py
