Continuously simulate swaps in all chains and protocols. By default, the binary tests the ethereum chain.

## How to run

```bash
export RUST_LOG=tycho_integration_test=info,error
export TYCHO_URL=tycho-dev.propellerheads.xyz
export RPC_URL=...
cargo run --package tycho-integration-test
```
