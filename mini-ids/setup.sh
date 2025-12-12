#!/bin/bash

# Mini IDS - Setup and Demo Script for Linux

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║     Mini IDS - Intrusion Detection System Setup      ║"
echo "║                  Linux Edition                         ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed"
    echo "Please install: sudo apt-get install python3 python3-pip"
    exit 1
fi

echo "✅ Python3 found: $(python3 --version)"
echo ""
echo "📦 Installing dependencies..."
echo ""

# Install requirements
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""
echo "✅ Dependencies installed successfully!"
echo ""
echo "🎯 Running demo..."
echo ""

# Run demo
python3 demo.py

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║             Setup Complete! 🎉                         ║"
echo "║                                                         ║"
echo "║ Next steps:                                             ║"
echo "║   1. Run dashboard: python3 app.py                     ║"
echo "║   2. Open: http://localhost:5000                       ║"
echo "║   3. In another terminal: python3 monitor.py           ║"
echo "║                                                         ║"
echo "║ For more info, see QUICKSTART.md                       ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
