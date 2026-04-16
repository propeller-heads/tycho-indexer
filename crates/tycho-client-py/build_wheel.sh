#!/bin/bash

# Install required Python packages
echo "Installing required Python packages..."
pip install --upgrade setuptools wheel build || { echo "Failed to install required Python packages."; exit 1; }

# Build the package using the build command
echo "Building the package..."
python -m build || { echo "Build failed."; exit 1; }

echo "Build completed. The package is located in the 'dist' directory."