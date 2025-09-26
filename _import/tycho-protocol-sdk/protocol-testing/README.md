# Protocol Testing

Rust-based integration testing framework for Tycho protocol implementations. See our full
docs [here](https://docs.propellerheads.xyz/tycho/for-dexs/protocol-integration/3.-testing).

## How to Run Locally

```bash
# Setup Environment Variables
export RPC_URL=..
export SUBSTREAMS_API_TOKEN=..
export RUST_LOG=protocol_testing=info,tycho_client=error

# Build Substreams wasm for BalancerV2
cd substreams
cargo build --release --package ethereum-balancer-v2 --target wasm32-unknown-unknown
cd ../protocol-testing

# Run Postgres DB using Docker compose
docker compose -f ./docker-compose.yaml up -d db

# Run test
cargo run -- --package ethereum-balancer-v2 
```

## How to Run with Docker

```bash
# Build the images, from the project root dir
docker buildx build -f protocol-testing/postgres.Dockerfile -t protocol-testing-db:latest --load .
docker buildx build -f protocol-testing/run.Dockerfile -t protocol-testing-test-runner:latest --load .

# Export necessary env vars
export RPC_URL=..
export SUBSTREAMS_API_TOKEN=..
export PROTOCOLS="ethereum-balancer-v2=weighted_legacy_creation ethereum-ekubo-v2"

# Start and show the test logs only
docker compose up -d && docker compose logs test-runner --follow

# Clean up
docker compose down
```
