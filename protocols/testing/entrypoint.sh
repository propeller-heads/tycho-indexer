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

# Infer the chain from the protocol name prefix.
infer_chain() {
    local protocol="$1"
    case "$protocol" in
        base-*)     echo "base" ;;
        arbitrum-*) echo "arbitrum" ;;
        unichain-*) echo "unichain" ;;
        bsc-*)      echo "bsc" ;;
        *)          echo "ethereum" ;;
    esac
}

# Return the appropriate RPC URL for the given protocol.
# Chain-specific URLs fall back to the generic RPC_URL if not set.
get_rpc_url() {
    local protocol="$1"
    case "$protocol" in
        base-*)     echo "${BASE_RPC_URL:-$RPC_URL}" ;;
        arbitrum-*) echo "${ARBITRUM_RPC_URL:-$RPC_URL}" ;;
        unichain-*) echo "${UNICHAIN_RPC_URL:-$RPC_URL}" ;;
        bsc-*)      echo "${BSC_RPC_URL:-$RPC_URL}" ;;
        *)          echo "$RPC_URL" ;;
    esac
}

# Run tests
for test in "${args[@]}"; do
	protocol="${test%%=*}"
	filter="${test#*=}"
	chain=$(infer_chain "$protocol")
	rpc_url=$(get_rpc_url "$protocol")
	export RPC_URL="$rpc_url"
	echo "Running tests for protocol: $protocol (chain: $chain)"
	if [[ "$test" == *"="* ]]; then
		tycho-protocol-sdk range --package "$protocol" --chain "$chain" --rpc-url "$rpc_url" \
			--db-url "$DATABASE_URL" --match-test "$filter"
	else
		tycho-protocol-sdk range --package "$protocol" --chain "$chain" --rpc-url "$rpc_url" \
			--db-url "$DATABASE_URL"
	fi
done
