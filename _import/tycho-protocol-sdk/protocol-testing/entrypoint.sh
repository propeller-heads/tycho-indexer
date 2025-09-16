#!/bin/bash
set -e

# Check arguments
if [ "$#" -lt 1 ]; then
	echo "Usage: $0 protocol1[=filter] [protocol2 ...] or \"$0 'protocol1[=filter] protocol2'\""
	exit 1
fi
if [ "$#" -eq 1 ] && [[ "$1" == *" "* ]]; then
	IFS=' ' read -r -a args <<< "$1"
else
	args=("$@")
fi

# Check required binaries
errors=()
for bin in tycho-indexer tycho-protocol-sdk substreams forge cast; do
    if command -v "$bin" >/dev/null 2>&1; then
        "$bin" --version || echo "$bin does not support --version"
    else
        errors+=("Binary '$bin' not found in PATH")
    fi
done
if [ "${#errors[@]}" -ne 0 ]; then
    for err in "${errors[@]}"; do
        echo "$err"
    done
    exit 1
fi

# Run tests
for test in "${args[@]}"; do
	protocol="${test%%=*}"
	filter="${test#*=}"
	echo "Running tests for protocol: $protocol with filter: $filter"
	if [[ "$test" == *"="* ]]; then
		tycho-protocol-sdk --package "$protocol" --db-url "$DATABASE_URL" --match-test "$filter"
	else
	  tycho-protocol-sdk --package "$protocol" --db-url "$DATABASE_URL"
	fi
done
