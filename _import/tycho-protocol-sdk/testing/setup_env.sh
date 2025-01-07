#!/bin/bash

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
source ./pre_build.sh
pip install -r $REQUIREMENTS_FILE
conda activate $ENV_NAME

echo "Setup complete."