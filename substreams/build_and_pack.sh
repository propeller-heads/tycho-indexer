#!/bin/bash

# This script builds the Wasm file and then packs it into a Substreams package.
#
# Usage: ./build_and_pack.sh <path-to-substreams-configs>
# e.g. ./build_and_pack.sh ./evm-uniswap-v2/ethereum-uniswap-v2.yaml
#
# Note: you may need to temporarily add `substreams/evm-{protocol}` to the workspace 
# members list in the main project’s Cargo.toml.

# Check if the package path argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <path-to-substreams-package>"
  exit 1
fi

PACKAGE_PATH="$1"
PACKAGE_DIR=$(dirname "$PACKAGE_PATH")

# Check if the wasm32-unknown-unknown target is installed
if ! rustup target list --installed | grep -q "wasm32-unknown-unknown"; then
  echo "Installing wasm32-unknown-unknown target..."
  rustup target add wasm32-unknown-unknown
  if [ $? -ne 0 ]; then
    echo "Failed to install wasm32-unknown-unknown target."
    exit 1
  fi
fi

# Build the Wasm file
echo "Building Wasm file..."
cd "$PACKAGE_DIR" || { echo "Failed to navigate to package directory."; exit 1; }
cargo build --target wasm32-unknown-unknown --profile substreams
cd - || { echo "Failed to return to original directory."; exit 1; }

# Check if the build was successful
if [ $? -ne 0 ]; then
  echo "Wasm build failed."
  exit 1
fi

# Pack the Substreams package using the provided path
echo "Packing Substreams package..."
substreams pack "$PACKAGE_PATH"

# Check if packing was successful
if [ $? -ne 0 ]; then
  echo "Substreams packing failed."
  exit 1
fi

echo "Build and pack process completed successfully."
