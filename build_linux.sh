#!/bin/bash

# 1. Install PyInstaller if not present
if ! command -v pyinstaller &> /dev/null; then
    echo "PyInstaller not found. Installing..."
    pip install pyinstaller
fi

# 2. Build the executable
# --onefile: Bundles everything into a single binary
# --name: Sets the output filename
echo "Building Perfect Trio executable..."
pyinstaller --onefile --name perfect_trio --clean main.py

echo "-------------------------------------------------------"
echo "Build complete! Executable found at: dist/perfect_trio"
echo "Make sure 'config.json' is in the same directory as the executable when running."