#!/usr/bin/env bash
# Migrate an open PR from a source repo to the monorepo.
# Usage: ./scripts/migrate-pr.sh <source-repo-path> <crate-name> <branch-name>
# Example: ./scripts/migrate-pr.sh ../tycho-simulation tycho-simulation ah/my-feature
#
# For PRs touching multiple crates (e.g. tycho-common + tycho-simulation), run once
# per crate with a shared branch name. The second run appends onto the same branch.
set -euo pipefail

SOURCE_REPO=${1:?Usage: $0 <source-repo-path> <crate-name> <branch-name>}
CRATE_NAME=${2:?}
BRANCH=${3:?}
CRATE_PATH="crates/${CRATE_NAME}"
PATCH_DIR=$(mktemp -d)

echo "Exporting patches from ${SOURCE_REPO} branch ${BRANCH}..."
(cd "$SOURCE_REPO" && git format-patch main.."$BRANCH" -o "$PATCH_DIR")

PATCH_COUNT=$(ls "$PATCH_DIR"/*.patch 2>/dev/null | wc -l | tr -d ' ')
if [ "$PATCH_COUNT" -eq 0 ]; then
  echo "No commits between main and ${BRANCH}. Nothing to migrate."
  rm -rf "$PATCH_DIR"
  exit 0
fi
echo "Found ${PATCH_COUNT} patches. Rewriting paths to ${CRATE_PATH}/..."

for patch in "$PATCH_DIR"/*.patch; do
  perl -i -pe \
    "s|^(diff --git) a/|\"\\$1 a/${CRATE_PATH}/\"|e; s|^(---|\+\+\+) (a|b)/|\"\\$1 \\$2/${CRATE_PATH}/\"|e" \
    "$patch"
done

if ! git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
  echo "Creating branch ${BRANCH}..."
  git checkout -b "$BRANCH"
else
  echo "Branch ${BRANCH} already exists, appending commits..."
  git checkout "$BRANCH"
fi

echo "Applying patches..."
git am "$PATCH_DIR"/*.patch

rm -rf "$PATCH_DIR"
echo ""
echo "Done. Push with: git push origin ${BRANCH}"
echo "Then open a PR against the monorepo and close the original PR with a link."
