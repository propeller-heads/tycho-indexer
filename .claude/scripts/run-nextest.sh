#!/usr/bin/env bash
set -euo pipefail

# Wrapper around cargo nextest that encapsulates filter expressions.
# Filter expressions contain parentheses which break Claude Code's
# allowed-tools pattern matching, so we keep them in this script.

PROFILE="${1:-help}"

case "$PROFILE" in
  unit)
    cargo nextest run --workspace --all-targets --all-features \
      -E 'not test(serial_db)' --no-fail-fast
    ;;
  serial-db)
    cargo nextest run --workspace --all-targets --all-features \
      -E 'test(serial_db)' --no-fail-fast
    ;;
  no-db)
    cargo nextest run --workspace --all-targets --all-features \
      -E 'not test(serial_db) & not package(tycho-storage) & not test(diesel)' \
      --no-fail-fast
    ;;
  *)
    echo "Usage: $0 {unit|serial-db|no-db}"
    exit 1
    ;;
esac
