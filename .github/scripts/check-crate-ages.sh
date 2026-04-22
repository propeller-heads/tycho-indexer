#!/usr/bin/env bash
set -euo pipefail

# Compares old and new Cargo.lock files, extracts updated crates,
# and checks each was published at least MIN_AGE_DAYS ago on crates.io.
#
# Outputs too-recent crates as "crate old_version" lines to a file so the
# caller can pin them back with `cargo update -p <crate> --precise <old_version>`.
#
# Usage: check-crate-ages.sh <old-lockfile> <new-lockfile> <output-file> [min-age-days]
#
# Exit codes:
#   0 — all crates are old enough (output file empty)
#   2 — some crates are too recent (output file has entries)

OLD_LOCK="${1:?Usage: check-crate-ages.sh <old-lock> <new-lock> <output-file> [min-age-days]}"
NEW_LOCK="${2:?Usage: check-crate-ages.sh <old-lock> <new-lock> <output-file> [min-age-days]}"
OUTPUT_FILE="${3:?Usage: check-crate-ages.sh <old-lock> <new-lock> <output-file> [min-age-days]}"
MIN_AGE_DAYS="${4:-3}"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required but not found" >&2
    exit 1
fi

# Extract name+version pairs from a Cargo.lock as "name version" lines.
extract_packages() {
    awk '/^\[\[package\]\]/{name=""; ver=""} /^name = /{gsub(/"/, "", $3); name=$3} /^version = /{gsub(/"/, "", $3); ver=$3; if(name!="") print name, ver}' "$1"
}

OLD_PKGS=$(extract_packages "$OLD_LOCK" | sort)
NEW_PKGS=$(extract_packages "$NEW_LOCK" | sort)

# Packages added or whose version changed (present in new but not old).
CHANGED=$(diff <(echo "$OLD_PKGS") <(echo "$NEW_PKGS") | grep '^>' | sed 's/^> //' || true)

if [[ -z "$CHANGED" ]]; then
    echo "No package changes detected."
    : > "$OUTPUT_FILE"
    exit 0
fi

echo "Updated packages:"
echo "$CHANGED"
echo ""

# Build a lookup of old versions: old_versions[crate]=version
declare -A OLD_VERSIONS
while IFS=' ' read -r name ver; do
    OLD_VERSIONS["$name"]="$ver"
done <<< "$OLD_PKGS"

NOW=$(date +%s)
TOO_RECENT=()

while IFS=' ' read -r crate version; do
    RESPONSE=$(curl -sf -H "User-Agent: tycho-indexer-ci (cargo-update)" \
        "https://crates.io/api/v1/crates/${crate}/${version}" 2>/dev/null) || {
        echo "WARNING: Could not fetch info for ${crate}@${version} (may be a path/git dep), skipping"
        continue
    }

    CREATED_AT=$(echo "$RESPONSE" | jq -r '.version.created_at // empty')
    if [[ -z "$CREATED_AT" ]]; then
        echo "WARNING: No created_at for ${crate}@${version}, skipping"
        continue
    fi

    # Parse ISO 8601 timestamp to epoch (Linux date -d handles ISO 8601 natively)
    CREATED_EPOCH=$(date -d "${CREATED_AT}" +%s 2>/dev/null) || \
    CREATED_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${CREATED_AT%%.*}" +%s 2>/dev/null) || {
        echo "WARNING: Could not parse date '${CREATED_AT}' for ${crate}@${version}, skipping"
        continue
    }

    AGE_DAYS=$(( (NOW - CREATED_EPOCH) / 86400 ))

    if (( AGE_DAYS < MIN_AGE_DAYS )); then
        old_ver="${OLD_VERSIONS[$crate]:-}"
        if [[ -n "$old_ver" ]]; then
            echo "TOO RECENT: ${crate}@${version} (${AGE_DAYS}d old) -> reverting to ${old_ver}"
            TOO_RECENT+=("${crate} ${old_ver}")
        else
            echo "TOO RECENT: ${crate}@${version} (${AGE_DAYS}d old) — new dep, no old version to pin"
        fi
    else
        echo "OK:   ${crate}@${version} published ${AGE_DAYS}d ago"
    fi

    # Rate-limit: crates.io allows 1 req/sec for unauthenticated clients
    sleep 1
done <<< "$CHANGED"

: > "$OUTPUT_FILE"
if (( ${#TOO_RECENT[@]} > 0 )); then
    echo ""
    echo "========================================="
    echo "${#TOO_RECENT[@]} crate(s) more recent than ${MIN_AGE_DAYS} days will be pinned back:"
    for entry in "${TOO_RECENT[@]}"; do
        echo "  - $entry"
        echo "$entry" >> "$OUTPUT_FILE"
    done
    echo "========================================="
    exit 2
fi

echo ""
echo "All updated crates are at least ${MIN_AGE_DAYS} days old."
