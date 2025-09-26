Continuously simulate swaps in all chains and protocols. By default, tests the ethereum chain, but the binary can be
configured to test multiple chains in parallel.

## How to run

```bash
export RPC_URL=...
export PRIVATE_KEY=...
cargo run --package tycho-integration-test

# To test multiple chains
cargo run --package tycho-integration-test -- --chains ethereum --chains unichain
```
