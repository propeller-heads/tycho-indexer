#!/bin/bash
# To run: ./setup_env.sh
set -e

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check each dependency is installed
deps=("git" "rustc" "gcc" "openssl" "conda" "pip" "pg_config")
names=("git" "rust" "gcc" "openssl" "conda" "pip" "libpq")
for i in "${!deps[@]}"; do
    if ! command_exists "${deps[$i]}"; then
        echo "Error: '${names[$i]}' is not installed."
        exit 1
    fi
done

echo "All dependencies are installed. Proceeding with setup..."

# Variables
ENV_NAME="tycho-protocol-sdk-testing"
PYTHON_VERSION="3.9"
# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"  # Assuming the script is in a subdirectory of the root
REQUIREMENTS_FILE="$ROOT_DIR/testing/requirements.txt"

# Create conda environment
echo "Creating conda environment ${ENV_NAME} with Python ${PYTHON_VERSION}..."
conda create --name $ENV_NAME python=$PYTHON_VERSION -y

# Activate the environment
echo "Activating the environment..."
eval "$(conda shell.bash hook)"
conda activate $ENV_NAME

# Install the requirements
echo "Installing the requirements from ${REQUIREMENTS_FILE}..."
pip install -r $REQUIREMENTS_FILE --index-url https://pypi.org/simple
conda activate $ENV_NAME

echo "----------------------------------------"
echo "SETUP COMPLETE."
echo "Run 'conda activate $ENV_NAME' to activate the environment."
