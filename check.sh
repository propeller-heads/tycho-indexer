set -e 

cargo +nightly fmt -- --check
cargo +nightly clippy --locked --all --all-features --all-targets -- -D warnings
cargo nextest run --workspace --locked --all-targets --all-features --bin tycho-indexer -E 'not test(serial_db)'
cargo nextest run --workspace --locked --all-targets --all-features --bin tycho-indexer -E 'test(serial_db)'
