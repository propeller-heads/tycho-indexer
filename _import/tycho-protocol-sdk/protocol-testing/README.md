# Protocol Testing

Rust-based integration testing framework for Tycho protocol implementations.

## How to Run

```bash
# Export necessary env vars
export RPC_URL=..
export SUBSTREAMS_API_TOKEN=..
export AUTH_API_KEY=..
export PROTOCOLS="ethereum-balancer-v2=weighted_legacy_creation ethereum-ekubo-v2"

# Start and show the test logs only
docker compose up -d && docker compose logs test-runner --follow

# Clean up
docker compose down
```

## Test Output Formatting

The test runner outputs results similar to:

```
Running 2 tests ...

--------------------------------

TEST 1: balancer_weighted_pool_test

✅ Protocol component validation passed.

✅ Token balance validation passed.

Amount out for 0x5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014: calculating for tokens "BAL"/"WETH"
Spot price "BAL"/"WETH": 0.123456

✅ Simulation validation passed.

✅ balancer_weighted_pool_test passed.

--------------------------------

Tests finished! 
RESULTS: 2/2 passed.
```

## Module-specific Logging
```bash
# Enable debug logs for specific modules
export RUST_LOG=protocol_testing=debug,tycho_client=info

# Disable logs for noisy modules
export RUST_LOG=info,hyper=warn,reqwest=warn
```

## Running with Different Log Levels
```bash
# Standard test run with progress output
RUST_LOG=info cargo run -- --package uniswap-v2

# Detailed debug output
RUST_LOG=debug cargo run -- --package uniswap-v2

# Minimal output (errors only)
RUST_LOG=error cargo run -- --package uniswap-v2
```

## Test Configuration

Tests are configured via YAML files located in the substreams package directory:
- Test configuration: `../substreams/<package>/integration_test.tycho.yaml`
- Substreams configuration: `../substreams/<package>/substreams.yaml`

## What the Tests Do

1. **Component Validation**: Verifies that all expected protocol components are present in Tycho after indexing
2. **State Validation**: Compares indexed component states against expected values
3. **Balance Verification**: Validates token balances by querying the blockchain directly (can be skipped)
4. **Simulation Testing**: Runs Tycho simulation engine to verify protocol functionality

## Troubleshooting

- **Database Connection Issues**: Ensure PostgreSQL is running via `docker-compose up -d`
- **RPC Errors**: Verify `RPC_URL` is set and accessible
- **Missing Substreams**: Check that the package directory exists in `../substreams/<package>/`
- **Build Failures**: Ensure all dependencies are installed and environment variables are set
