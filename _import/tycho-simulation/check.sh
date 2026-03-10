set -e

cargo +nightly fmt --all --check
cargo clippy --workspace --lib --all-targets --all-features -- -D warnings
cargo nextest run --workspace --lib --all-targets --all-features
