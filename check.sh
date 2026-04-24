#!/usr/bin/env bash
set -e

cargo +nightly fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features -E 'not test(serial_db)'
cargo nextest run --workspace --all-features -E 'test(serial_db)'
