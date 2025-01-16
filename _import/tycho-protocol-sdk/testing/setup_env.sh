#!/bin/bash
# To run: ./setup_env.sh

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Map of dependencies to their binaries (used to check if they are installed)
declare -A dependencies=(
    ["git"]="git"
    ["rust"]="rustc"
    ["gcc"]="gcc"
    ["openssl"]="openssl"
    ["pkg-config"]="pkg-config"
    ["conda"]="conda"
    ["pip"]="pip"
    ["libpq"]="pg_config"
)

# Check each dependency
for dep in "${!dependencies[@]}"; do
    binary=${dependencies[$dep]}
    if ! command_exists "$binary"; then
        echo "Error: '$dep' is not installed."
        exit 1
    fi
done

echo "All dependencies are installed. Proceeding with setup..."

# Variables
ENV_NAME="tycho-protocol-sdk-testing"
PYTHON_VERSION="3.9"
REQUIREMENTS_FILE="requirements.txt"

# Create conda environment
echo "Creating conda environment ${ENV_NAME} with Python ${PYTHON_VERSION}..."
conda create --name $ENV_NAME python=$PYTHON_VERSION -y

# Activate the environment
echo "Activating the environment..."
source activate $ENV_NAME

# Install the requirements
echo "Installing the requirements from ${REQUIREMENTS_FILE}..."
pip install -r $REQUIREMENTS_FILE --index-url https://pypi.org/simple
conda activate $ENV_NAME

echo "Setup complete."
echo "Run 'conda activate $ENV_NAME' to activate the environment."