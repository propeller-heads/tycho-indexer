#!/bin/bash

# Variables
ENV_NAME="propeller-protocol-lib-testing"
PYTHON_VERSION="3.9"
REQUIREMENTS_FILE="requirements.txt"
PRE_BUILD_SCRIPT="pre_build.sh"

# Allow to run either from root or from inside testing folder.
if [ -f "./$REQUIREMENTS_FILE" ]; then
    # If the requirements file is found in the current directory, do nothing
    SCRIPT_DIR="."
elif [ -f "testing/$REQUIREMENTS_FILE" ]; then
    # If the requirements file is found in testing/, adjust the paths
    SCRIPT_DIR="testing"
else
    echo "Error: Script must be run from the propeller-protocol-lib or propeller-protocol-lib/testing directory."
    exit 1
fi

# Create conda environment
echo "Creating conda environment ${ENV_NAME} with Python ${PYTHON_VERSION}..."
conda create --name $ENV_NAME python=$PYTHON_VERSION -y

# Activate the environment
echo "Activating the environment..."
source activate $ENV_NAME

# Install the requirements
echo "Installing the requirements from ${SCRIPT_DIR}/${REQUIREMENTS_FILE}..."
./${SCRIPT_DIR}/${PRE_BUILD_SCRIPT}
pip install -r ${SCRIPT_DIR}/${REQUIREMENTS_FILE}
conda activate $ENV_NAME

echo "Setup complete."