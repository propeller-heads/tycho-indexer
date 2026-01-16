# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build & Release
```bash
# Build all packages in release mode
cargo build --release

# Build tycho-indexer with unstable tokio features (for production)
RUSTFLAGS="--cfg tokio_unstable" cargo build --package tycho-indexer --release
```

### Testing
```bash
# Run standard tests (excludes serial database tests)
cargo nextest run --workspace --locked --all-targets --all-features --bin tycho-indexer -E 'not test(serial_db)'

# Run serial database tests (must be run separately)
cargo nextest run --workspace --locked --all-targets --all-features --bin tycho-indexer -E 'test(serial_db)'
```

### Code Quality
```bash
# Format code (requires nightly toolchain)
cargo +nightly fmt

# Check formatting
cargo +nightly fmt -- --check

# Lint with clippy
cargo +nightly clippy --locked --all --all-features --all-targets -- -D warnings

# Run all checks (format + clippy + tests)
./check.sh
```

### Database Operations
```bash
# Start PostgreSQL service
docker-compose up -d db

# Run database migrations
diesel migration run --migration-dir ./tycho-storage/migrations

# Redo last migration (useful for testing)
diesel migration redo --migration-dir ./tycho-storage/migrations

# Update schema.rs after migrations
diesel print-schema --config-file ./tycho-storage/diesel.toml > ./tycho-storage/src/postgres/schema.rs
```

### Running Tycho Indexer
```bash
# Run indexer for all extractors in extractors.yaml
cargo run --bin tycho-indexer -- index

# Run indexer for a single extractor
cargo run --bin tycho-indexer -- run

# Run token analyzer cronjob
cargo run --bin tycho-indexer -- analyze-tokens

# Run only the RPC server
cargo run --bin tycho-indexer -- rpc
```

## Architecture Overview

Tycho is a multi-crate Rust workspace designed for indexing and processing DEX/DeFi protocol data from blockchains. The system follows an extractor-service architecture where extractors process incoming blockchain data and services distribute data to clients.

### Core Crates
- **tycho-indexer**: Main indexing logic, extractor management, RPC services, and WebSocket subscriptions
- **tycho-storage**: Database layer with PostgreSQL backend, migrations, and versioned data storage
- **tycho-common**: Shared types, traits, and DTOs used across all crates
- **tycho-client**: Consumer-facing client library and CLI for streaming protocol data
- **tycho-client-py**: Python bindings for the Rust client (currently not maintained/outdated)
- **tycho-ethereum**: Ethereum-specific blockchain integration and token analysis

### Data Flow Architecture
1. **Substreams** send fork-aware blockchain messages to tycho-indexer
2. **Extractors** process incoming data, maintain protocol state, and emit deltas
3. **Services** distribute real-time data via WebSocket and provide historical data via RPC
4. **Storage** persists versioned protocol states and component data in PostgreSQL

### Key Architectural Concepts
- **Protocol Components**: Static configuration of protocol pools/contracts
- **Protocol State**: Dynamic attributes that change per block (reserves, balances, etc.)
- **Reorg Handling**: Automatic chain reorganization detection and revert message emission
- **Versioning System**: Historical data tracking with valid_to timestamps
- **Delta Streaming**: Lightweight state change messages for real-time updates

### Special Attributes System
- `manual_updates`: Controls automatic vs manual component updates
- `update_marker`: Signals component state changes for manual update components
- `balance_owner`: Specifies token balance ownership for components
- `stateless_contract_addr/_code`: References to stateless contracts needed for simulations

### Development Environment
- Requires PostgreSQL (via docker-compose or local installation)
- Uses Diesel for database migrations and ORM
- Employs nextest for parallel test execution with special handling for database tests
- Follows Conventional Commits format for automated versioning

### Testing Strategy
- Standard tests run in parallel
- Database tests (`serial_db`) run sequentially to avoid interference
- Integration tests can use tycho-client to generate test fixtures
- Mock data available in various test directories