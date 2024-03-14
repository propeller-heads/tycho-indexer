#!/bin/bash

# Allows releasing multiple substream packages within the same repo.
# To trigger a release simply create a tag with [package-name]-[semver].
# The script will look for these tags, then infer which package needs to be built and
# released.

# Try to get the tag name associated with the current HEAD commit
current_tag=$(git describe --tags --exact-match HEAD 2>/dev/null)

if [ -n "$current_tag" ]; then
    # If the HEAD is at a tag, extract the prefix and version
    if [[ $current_tag =~ ^([a-zA-Z-]*-)?([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
        # Prefix without the trailing hyphen (if any)
        package="${BASH_REMATCH[1]%?}"
        # Semantic version
        version="${BASH_REMATCH[2]}"

        cargo_version=$(cargo pkgid -p ethereum-balancer | cut -d# -f2 | cut -d: -f2)
        if [[ "$cargo_version" != "$version" ]]; then
          echo "Error: Cargo version: ${cargo_version} does not match tag version: ${version}!"
          exit 1
        fi
        # Check if the Git repository is dirty
        if [ -n "$(git status --porcelain)" ]; then
          echo "Error: The repository is dirty. Please commit or stash your changes."
          exit 1
        fi
    else
        echo "Error: Current tag ($current_tag) does not match the expected format."
        exit 1
    fi
else
    # If the HEAD is not at a tag, construct the tag name with the pre-release postfix
    if [ -z "$1" ]; then
        echo "Error: package argument is required to create a pre release!"
        exit 1
    fi
    package=$1

    version_prefix=$(git describe --tags --match "$package-*" --abbrev=0 2>/dev/null)
    if [ -z "$version_prefix" ]; then
        # If no tags are found in the history, default to version 0.0.1
        version_prefix="0.0.1"
    fi

    # Get the short commit hash of the current HEAD
    commit_hash=$(git rev-parse --short HEAD)
    version="${version_prefix}-pre.${commit_hash}"
fi

REPOSITORY=${REPOSITORY:-"s3://repo.propellerheads/substreams"}
repository_path="$REPOSITORY/$package/$package-$version.spkg"

cargo build --target wasm32-unknown-unknown --release -p "$package"
mkdir -p ./target/spkg/
substreams pack $package/substreams.yaml -o ./target/spkg/$package-$version.spkg
aws s3 cp ./target/spkg/$package-$version.spkg $repository_path

echo "Released substreams package: '$repository_path'"