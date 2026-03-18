#!/usr/bin/env bash
set -euo pipefail

# Wrapper around cargo nextest that encapsulates filter expressions.
# Filter expressions contain parentheses which break Claude Code's
# allowed-tools pattern matching, so we keep them in this script.
#
# Usage: run-nextest.sh <profile> [--include-ignored]
#   --include-ignored  Also run #[ignore]-d tests (requires RPC_URL)

PROFILE="${1:-help}"
IGNORED_FLAG=""
if [[ "${2:-}" == "--include-ignored" ]]; then
  IGNORED_FLAG="--run-ignored all"
fi

case "$PROFILE" in
  unit)
    cargo nextest run --workspace --all-targets --all-features \
      -E 'not test(serial_db)' --no-fail-fast $IGNORED_FLAG
    ;;
  serial-db)
    cargo nextest run --workspace --all-targets --all-features \
      -E 'test(serial_db)' --no-fail-fast $IGNORED_FLAG
    ;;
  no-db)
    cargo nextest run --workspace --all-targets --all-features \
      -E 'not test(serial_db) & not package(tycho-storage) & not test(diesel)' \
      --no-fail-fast $IGNORED_FLAG
    ;;
  *)
    echo "Usage: $0 {unit|serial-db|no-db} [--include-ignored]"
    exit 1
    ;;
esac
