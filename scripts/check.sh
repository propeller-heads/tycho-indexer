#!/usr/bin/env bash
set -euo pipefail

cargo +nightly fmt --all --check
cargo clippy --workspace --all --all-features --all-targets -- -D warnings
cargo nextest run --workspace --all-targets --all-features -E 'not test(serial_db)'
cargo nextest run --workspace --all-targets --all-features -E 'test(serial_db)'

(cd crates/tycho-execution/contracts && forge fmt --check)
(cd crates/tycho-execution/contracts && forge test)
(cd adapters/evm && forge fmt --check)
(cd adapters/evm && forge test)
(cd crates/tycho-simulation/token-proxy-contracts && forge fmt --check)
(cd crates/tycho-simulation/token-proxy-contracts && forge test)
