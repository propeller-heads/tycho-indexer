#!/bin/bash
set -e

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 test1 [test2 ...]"
  exit 1
fi

for test in "$@"; do
  echo "Running test: /app/substreams/$test"
  tycho-protocol-sdk --package-path "/app/substreams/$test" --db-url "$DATABASE_URL"
done
