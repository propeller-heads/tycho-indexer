#!/usr/bin/env bash
set -euo pipefail

# Compares old and new Cargo.lock files, extracts updated crates,
# and checks each was published at least MIN_AGE_DAYS ago on crates.io.
#
# Outputs too-recent crates as "crate safe_version" lines to a file so the
# caller can pin them back with `cargo update -p <crate> --precise <safe_version>`.
# The safe version is the latest release published at least MIN_AGE_DAYS ago.
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

# Find the latest version of a crate published at least MIN_AGE_DAYS ago.
# Queries the crates.io versions list and returns the first match.
latest_safe_version() {
    local crate="$1"
    local min_age="$2"
    local now="$3"
    local threshold=$((min_age * 86400))

    local resp
    resp=$(curl -sf -H "User-Agent: tycho-indexer-ci (cargo-update)" \
        "https://crates.io/api/v1/crates/${crate}/versions" 2>/dev/null) || return 1

    # Versions are returned newest-first. Find the first non-yanked
    # version published at least min_age days ago.
    echo "$resp" | jq -r --argjson now "$now" --argjson threshold "$threshold" '
        [.versions[] | select(.yanked == false)] |
        map(select(
            (.created_at | sub("\\.[0-9]+.*"; "") | strptime("%Y-%m-%dT%H:%M:%S") | mktime) as $t |
            ($now - $t) >= $threshold
        )) |
        first | .num // empty
    '
}

NOW=$(date +%s)
: > "$OUTPUT_FILE"
too_recent_count=0

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

    # Parse ISO 8601 timestamp to epoch (Linux date -d, macOS date -j fallback)
    CREATED_EPOCH=$(date -d "${CREATED_AT}" +%s 2>/dev/null) || \
    CREATED_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${CREATED_AT%%.*}" +%s 2>/dev/null) || {
        echo "WARNING: Could not parse date '${CREATED_AT}' for ${crate}@${version}, skipping"
        continue
    }

    AGE_DAYS=$(( (NOW - CREATED_EPOCH) / 86400 ))

    if (( AGE_DAYS < MIN_AGE_DAYS )); then
        safe_ver=$(latest_safe_version "$crate" "$MIN_AGE_DAYS" "$NOW")
        sleep 1  # rate-limit the extra API call
        if [[ -n "$safe_ver" ]]; then
            echo "TOO RECENT: ${crate}@${version} (${AGE_DAYS}d old) -> pinning to ${safe_ver}"
            echo "${crate} ${safe_ver}" >> "$OUTPUT_FILE"
            too_recent_count=$((too_recent_count + 1))
        else
            echo "TOO RECENT: ${crate}@${version} (${AGE_DAYS}d old) — no safe version found, skipping"
        fi
    else
        echo "OK:   ${crate}@${version} published ${AGE_DAYS}d ago"
    fi

    # Rate-limit: crates.io allows 1 req/sec for unauthenticated clients
    sleep 1
done <<< "$CHANGED"

if (( too_recent_count > 0 )); then
    echo ""
    echo "========================================="
    echo "${too_recent_count} crate(s) more recent than ${MIN_AGE_DAYS} days will be pinned back:"
    while IFS=' ' read -r c v; do
        echo "  - ${c} ${v}"
    done < "$OUTPUT_FILE"
    echo "========================================="
    exit 2
fi

echo ""
echo "All updated crates are at least ${MIN_AGE_DAYS} days old."
