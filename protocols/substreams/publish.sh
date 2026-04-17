#!/bin/bash

# Manual publish script for substream packages.
# Builds, packs, and publishes a substream package to the public S3 repository.
# Usage: ./publish.sh <package-name> <yaml-name>
#   package-name: The name of the package to build
#   yaml-name: The name of the YAML file (without .yaml extension)
# The version will be automatically fetched from the package's Cargo.toml

# Check if required arguments are provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Error: package name and yaml name are required!"
    echo "Usage: $0 <package-name> <yaml-name>"
    exit 1
fi

package=$1
yaml_name=$2

# Fetch version from Cargo.toml
cargo_version=$(cargo pkgid -p "$package" | cut -d# -f2 | cut -d: -f2)
version="v${cargo_version}"

# Construct the YAML file path
yaml_file="./$package/$yaml_name.yaml"

# Validate that the YAML file exists
if [[ ! -f "$yaml_file" ]]; then
    echo "Error: manifest reader: unable to stat input file $yaml_file: file does not exist."
    exit 1
fi

# Determine the version prefix based on the YAML file name
if [ "$yaml_name" = "substreams" ]; then
    version_prefix="$package"
else
    version_prefix="${yaml_name}"
fi

set -e  # Exit the script if any command fails

echo ""
echo "Substreams package: $package"
echo "YAML config: $yaml_file"
echo "Version: $version"
echo ""

# Ask for confirmation before proceeding
read -p "Is this information correct? Do you want to proceed? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

set -e  # Exit the script if any command fails

# Build the package
cargo build --target wasm32-unknown-unknown --release -p "$package"

# Create output directory
mkdir -p ./target/spkg/

# Pack and upload the substreams package
REPOSITORY=${REPOSITORY:-"s3://repo.propellerheads-propellerheads/substreams"}
repository_path="$REPOSITORY/$package/$version_prefix-$version.spkg"
output_file="./target/spkg/$version_prefix-$version.spkg"

substreams pack "$yaml_file" -o "$output_file"

# Check if the file already exists in S3 before uploading
# Extract bucket and key from the S3 path (format: s3://bucket/key)
s3_path="${repository_path#s3://}"
bucket="${s3_path%%/*}"
key="${s3_path#*/}"

if aws s3api head-object --bucket "$bucket" --key "$key" >/dev/null 2>&1; then
    echo "Error: File already exists in S3: $repository_path"
    echo "Upload aborted to prevent overwriting existing file."
    exit 1
fi

aws s3 cp "$output_file" "$repository_path"

echo "------------------------------------------------------"
echo "PUBLISHED SUBSTREAMS PACKAGE: '$repository_path'"
echo "------------------------------------------------------"

