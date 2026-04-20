#!/usr/bin/env bash
# Migrate an open PR from a source repo to the monorepo.
#
# Usage:
#   ./scripts/migrate-pr.sh <source-repo-path> <branch-name> [extra-src:dst ...]
#
# Path mappings are looked up automatically from the source repo name.
# Pass extra "src:dst" arguments to add or override mappings (e.g. for CI files).
#
# Known repo mappings:
#   tycho-protocol-sdk  substreams→protocols/substreams,
#                       evm→protocols/adapter-integration/evm,
#                       protocol-testing→protocols/testing
#   tycho-simulation    → crates/tycho-simulation  (prefix all paths)
#   tycho-execution     → crates/tycho-execution   (prefix all paths)
#
# Examples:
#   ./scripts/migrate-pr.sh ../tycho-protocol-sdk ah/ENG-5053/fluid-indexing
#   ./scripts/migrate-pr.sh ../tycho-simulation ah/my-feature
#
# Notes:
#   - Diff blocks for paths not covered by any src:dst mapping are stripped
#     automatically (e.g. .github/workflows/ from protocol-sdk PRs).
#   - Prefix-only maps (no colon) apply to all paths, so nothing is stripped.
#   - Cargo.lock diffs are stripped and must be regenerated: cargo check --workspace
#   - Cargo.toml / source file context mismatches: git am retries with --reject,
#     writing <file>.rej for failed hunks. Use `wiggle --merge` to apply them and
#     get inline conflict markers for anything that still doesn't resolve cleanly.
#   - include_str!() and similar path literals on added lines are rewritten
#     automatically alongside the diff headers (e.g. ../../evm/ → ../../adapter-integration/evm/).
#   - For PRs touching multiple crates in a single-crate repo, run once per
#     crate with the same branch name; the second run appends onto the branch.
set -euo pipefail

SOURCE_REPO=${1:?Usage: $0 <source-repo-path> <branch-name> [extra-src:dst ...]}
BRANCH=${2:?}
shift 2
EXTRA_MAPS=("$@")

# ---------------------------------------------------------------------------
# Hardcoded mappings per known source repo. Each entry is a "src:dst" pair;
# a plain "prefix" (no colon) prepends that prefix to all paths.
# ---------------------------------------------------------------------------
REPO_NAME=$(basename "$SOURCE_REPO")
DEFAULT_MAPS=()
case "$REPO_NAME" in
  tycho-protocol-sdk)
    DEFAULT_MAPS=(
      "substreams:protocols/substreams"
      "evm:protocols/adapter-integration/evm"
      "protocol-testing:protocols/testing"
    )
    ;;
  tycho-simulation)
    DEFAULT_MAPS=("crates/tycho-simulation")
    ;;
  tycho-execution)
    DEFAULT_MAPS=("crates/tycho-execution")
    ;;
  *)
    if [ ${#EXTRA_MAPS[@]} -eq 0 ]; then
      echo "Error: no hardcoded mappings for '${REPO_NAME}'." >&2
      echo "Pass explicit src:dst arguments or add '${REPO_NAME}' to the mapping table in this script." >&2
      exit 1
    fi
    ;;
esac

# Build MAPS from defaults + any extras, guarding against empty-array expansion
# under set -u by checking length before appending.
MAPS=()
if [ "${#DEFAULT_MAPS[@]}" -gt 0 ]; then
  MAPS+=("${DEFAULT_MAPS[@]}")
fi
if [ "${#EXTRA_MAPS[@]}" -gt 0 ]; then
  MAPS+=("${EXTRA_MAPS[@]}")
fi

# ---------------------------------------------------------------------------
# Export patches
# ---------------------------------------------------------------------------
PATCH_DIR=$(mktemp -d)

echo "Exporting patches from ${SOURCE_REPO} (${REPO_NAME}) branch ${BRANCH}..."
(cd "$SOURCE_REPO" && git format-patch main.."$BRANCH" -o "$PATCH_DIR")

PATCH_COUNT=$(find "$PATCH_DIR" -maxdepth 1 -name '*.patch' | wc -l | tr -d ' ')
if [ "$PATCH_COUNT" -eq 0 ]; then
  echo "No commits between main and ${BRANCH}. Nothing to migrate."
  rm -rf "$PATCH_DIR"
  exit 0
fi
echo "Found ${PATCH_COUNT} patches. Rewriting paths with mappings: ${MAPS[*]}"

# ---------------------------------------------------------------------------
# Build a perl expression that rewrites paths for all mappings.
#
# Use , as delimiter throughout — | would conflict with | in (---|\+\+\+).
#
# Two rewrite categories per src:dst map:
#   1. Diff headers  — lines starting with "diff --git", "---", "+++"
#   2. Added content — lines starting with "+" (but not "+++"), for string
#      literals such as include_str!() that embed relative repo paths.
#      These are rewritten as bare path segments (e.g. ../evm/ → ../adapter-integration/evm/)
#      so cross-file references stay correct after remapping.
#
# Map forms:
#   "dest-prefix"   prepend dest-prefix/ to all paths (no colon)
#   "src:dst"       replace src/ prefix with dst/ (colon-separated)
# ---------------------------------------------------------------------------
HAS_PREFIX_MAP=false
DST_PREFIXES=()
PERL_EXPR=""
for map in "${MAPS[@]}"; do
  if [[ "$map" == *:* ]]; then
    src="${map%%:*}"
    dst="${map##*:}"
    DST_PREFIXES+=("$dst")
    # Diff headers
    PERL_EXPR+="s,^(diff --git a/)${src}/,\${1}${dst}/,; "
    PERL_EXPR+="s,^(diff --git \\S+) b/${src}/,\${1} b/${dst}/,; "
    PERL_EXPR+="s,^((---|\+\+\+) [ab]/)${src}/,\${1}${dst}/,; "
    # Added content lines — rewrite bare path segments like ../../evm/ or /evm/
    PERL_EXPR+="s,^(\\+[^+].*)/${src}/,\${1}/${dst}/,g; "
  else
    HAS_PREFIX_MAP=true
    prefix="$map"
    PERL_EXPR+="s,^(diff --git a/),\${1}${prefix}/,; "
    PERL_EXPR+="s,^(diff --git \\S+) b/,\${1} b/${prefix}/,; "
    PERL_EXPR+="s,^((---|\+\+\+) [ab]/),\${1}${prefix}/,; "
  fi
done

for patch in "$PATCH_DIR"/*.patch; do
  perl -i -pe "$PERL_EXPR" "$patch"
done

# ---------------------------------------------------------------------------
# Strip diff blocks for unmapped paths (only when all maps are src:dst).
# Unmapped blocks (e.g. .github/workflows/) would cause git am to fail if
# those paths don't exist in the monorepo.
# ---------------------------------------------------------------------------
if [ "$HAS_PREFIX_MAP" = false ] && [ "${#DST_PREFIXES[@]}" -gt 0 ]; then
  # Build alternation pattern from dst prefixes, escaping / for use in regex.
  DST_REGEX=""
  for prefix in "${DST_PREFIXES[@]}"; do
    escaped="${prefix//\//\\/}"
    DST_REGEX="${DST_REGEX:+${DST_REGEX}|}${escaped}"
  done
  echo "Stripping unmapped diff blocks (keeping paths matching: ${DST_PREFIXES[*]})..."
  for patch in "$PATCH_DIR"/*.patch; do
    perl -0777 -i -pe "
      my (\$header, \$rest) = /\A(.*?)(?=^diff --git )/ms
        ? (\$1, \$')
        : ('', \$_);
      my @blocks = split /(?=^diff --git )/m, \$rest;
      @blocks = grep { /^diff --git a\\/(?:${DST_REGEX})\// } @blocks;
      \$_ = \$header . join('', @blocks);
    " "$patch"
  done
fi

# Strip Cargo.lock diff blocks from all patches — lock files must be regenerated
# after migration (cargo check --workspace) and always conflict due to repo divergence.
echo "Stripping Cargo.lock diff blocks (regenerate with: cargo check --workspace)..."
for patch in "$PATCH_DIR"/*.patch; do
  perl -0777 -i -pe '
    my @parts = split /(?=^diff --git )/m, $_;
    @parts = grep { /^diff --git / ? !/^diff --git a\/.*Cargo\.lock / : 1 } @parts;
    $_ = join("", @parts);
  ' "$patch"
done

# ---------------------------------------------------------------------------
# Apply patches. On failure, retry with --reject so git applies every hunk
# it can and writes <file>.rej for the rest. Resolving .rej files with
# `wiggle --merge` produces inline conflict markers for any remaining gaps.
# ---------------------------------------------------------------------------
if ! git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
  echo "Creating branch ${BRANCH}..."
  git checkout -b "$BRANCH"
else
  echo "Branch ${BRANCH} already exists, appending commits..."
  git checkout "$BRANCH"
fi

echo "Applying patches..."
if git am "$PATCH_DIR"/*.patch; then
  rm -rf "$PATCH_DIR"
  echo ""
  echo "Done. Push with: git push origin ${BRANCH}"
  echo "Then open a PR against the monorepo and close the original PR with a link."
else
  echo ""
  echo "Some hunks failed. Retrying with --reject so partial application is preserved..."
  git am --abort
  git am --reject "$PATCH_DIR"/*.patch || true
  rm -rf "$PATCH_DIR"
  echo ""
  echo "Resolve .rej files with wiggle, then continue:"
  echo "  brew install wiggle  # if not installed"
  echo "  find . -name '*.rej' | while read -r r; do wiggle --merge \"\${r%.rej}\" \"\$r\" && rm \"\$r\"; done"
  echo "  git add <resolved-files> && git am --continue"
  echo "(or 'git am --skip' to drop a patch, 'git am --abort' to start over)"
  exit 1
fi
