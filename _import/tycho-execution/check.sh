set -e 

cargo +nightly fmt --all --check
cargo clippy --workspace --lib --all-targets --all-features -- -D clippy::dbg-macro
cargo nextest run --workspace --lib --all-targets
(cd foundry && forge fmt --check)
(cd foundry && forge test)
