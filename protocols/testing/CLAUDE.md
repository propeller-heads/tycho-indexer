# protocols/testing/

Rust binary (`protocol-testing`) that runs end-to-end integration tests for Substreams protocol
implementations. Spins up a full indexer stack, indexes a block range from each protocol's
`integration_test.tycho.yaml`, then validates resulting state via `tycho-simulation`.

IS in the monorepo `[workspace.members]` (unlike `protocols/substreams/`).

## Running

Requires: `RPC_URL`, `SUBSTREAMS_API_TOKEN`, Postgres (`DATABASE_URL`, default
`postgres://postgres:mypassword@localhost:5431/tycho_indexer_0`).

```bash
cargo run -- range --package "ethereum-balancer-v2"          # block range from yaml
cargo run -- full  --package "ethereum-balancer-v2"          # creation block to latest
cargo run -- range --package "base-aerodrome-slipstreams" --chain base
```

Docker Compose is available for isolated runs — see `README.md`.
