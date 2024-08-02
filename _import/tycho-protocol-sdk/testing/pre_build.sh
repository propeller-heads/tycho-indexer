#!/bin/bash

# Enable automatic export of all defined variables
set -a

# Source the .env file
source .env

# Disable automatic export (optional, if you want to stop exporting variables)
set +a

# Check if DOMAIN_OWNER is set
if [ -z "$DOMAIN_OWNER" ]; then
  echo "DOMAIN_OWNER environment variable is not set."
  return 1
fi

# Fetch the CODEARTIFACT_AUTH_TOKEN
CODEARTIFACT_AUTH_TOKEN=$(aws --region eu-central-1 codeartifact get-authorization-token --domain propeller --domain-owner $DOMAIN_OWNER --query authorizationToken --output text --duration 1800)

# Set the PIP_INDEX_URL
PIP_INDEX_URL="https://aws:${CODEARTIFACT_AUTH_TOKEN}@propeller-${DOMAIN_OWNER}.d.codeartifact.eu-central-1.amazonaws.com/pypi/protosim/simple/"

# Export the variables
export CODEARTIFACT_AUTH_TOKEN
export PIP_INDEX_URL