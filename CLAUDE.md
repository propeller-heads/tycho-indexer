# CLAUDE.md

## Development Environment
- Requires PostgreSQL (via `docker-compose up -d db`)
- Uses Diesel for ORM and migrations
- Uses `nextest` for parallel test execution; DB tests tagged `serial_db` run sequentially
- Follows Conventional Commits for automated versioning (see `release.config.js`)

## Testing Conventions
- For `rstest` parameterized tests, **name each case** with `#[case::descriptive_name(...)]` — test names should be self-documenting so failures are immediately identifiable
- Keep test function names concise; avoid suffixes that restate what parameters already express
- Don't nest `mod` wrappers inside `#[cfg(test)] mod test` unless there's a concrete isolation benefit

## Commands

### Testing
```bash
# Run standard tests (excludes serial database tests)
cargo nextest run --workspace --locked --all-targets --all-features --bin tycho-indexer -E 'not test(serial_db)'

# Run serial database tests (must be run separately)
cargo nextest run --workspace --locked --all-targets --all-features --bin tycho-indexer -E 'test(serial_db)'

# Run a single test by name
cargo nextest run --workspace --locked --all-targets --all-features -E 'test(my_test_name)'

# Run all tests in a specific crate
cargo nextest run --package tycho-storage --locked --all-targets --all-features
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

## Architecture Overview

Tycho is a multi-crate Rust workspace for indexing DEX/DeFi protocol data from blockchains, streaming real-time state to solvers via WebSocket deltas and HTTP snapshots.

### Core Crates
- **tycho-indexer**: Main indexing engine, extractor management, RPC + WebSocket services
- **tycho-storage**: PostgreSQL backend with Diesel ORM, versioned data, migrations
- **tycho-common**: Shared domain types, storage/blockchain traits, DTOs
- **tycho-client**: Consumer library — HTTP snapshot client + WebSocket delta client
- **tycho-ethereum**: Ethereum specific implementations: RPC, token analysis, EVM account/trace extraction
- **tycho-client-py**: Python bindings (not maintained)

### End-to-End Data Flow

```
── INGESTION ──────────────────────────────────────────────────────────────────

  Substreams gRPC                                    Ethereum RPC
       │                                                   │
       ▼                                                   │
  ProtocolExtractor                                        │
  ├─ Deserialize BlockScopedData (protobuf)                │
  ├─ PartialBlockBuffer: accumulate sub-block msgs         │
  │  until full-block signal arrives                       │
  ├─ TokenPreProcessor: for each unknown token address ────┘
  │  fetch metadata (symbol, decimals) via eth_call
  └─ Produce BlockChanges (tx-level state/balance/token deltas)
       │
       ▼
  ReorgBuffer (extractor-owned, one per ProtocolExtractor)
  ├─ Insert BlockChanges for every new block
  ├─ On BlockUndoSignal: purge blocks after reverted hash,
  │  emit revert messages (revert=true) — no DB rollback needed
  └─ Drain to DB when count_blocks_before(finalized_block_height)
       >= commit_batch_size  ← only finalized blocks ever reach DB
       │
       ▼ (drained blocks only)
  BlockChanges → BlockAggregatedChanges
  │  merge all tx-level deltas into one state per component/account;
  │  new_tokens, new_protocol_components, component_balances included
  │
  ├─ DB write (CachedGateway → Postgres)
  │  upsert blocks, tokens, protocol components, state, balances
  │  sets db_committed_block_height on outgoing message
  │
  └─ Broadcast BlockAggregatedChanges on internal channel
       │ (all blocks, including pending/non-committed)
       │
── SERVER ─────────────────────────────────────────────────────────────────────
       │
       ├──► WebSocket subscribers (tycho-indexer/src/services/ws.rs)
       │    emit message directly; revert flag signals chain reorg
       │
       └──► PendingDeltasBuffer (tycho-indexer/src/services/deltas_buffer.rs)
            per-extractor ReorgBuffer of BlockAggregatedChanges
            ├─ Insert every full block (partial blocks skipped)
            ├─ Auto-drain blocks ≤ db_committed_block_height
            │  (they're in DB, no longer "pending")
            └─ Used by RPC handlers: DB snapshot + pending deltas
               = consistent view of latest state for HTTP queries

── CLIENT (tycho-client) ──────────────────────────────────────────────────────

  StateSynchronizer (one per extractor subscription)
  ├─ 1. Subscribe to WebSocket stream (WsDeltasClient)
  ├─ 2. On first message: query HTTP snapshot (HttpRPCClient)
  │     fetches protocol_state / contract_state at that block height
  └─ 3. Buffer WebSocket deltas received before snapshot arrives;
        apply buffered deltas on top of snapshot to catch up

  BlockSynchronizer (across all extractors)
  ├─ Tracks state per synchronizer: Ready / Delayed / Stale
  ├─ Delayed synchronizers consume buffered messages to catch up
  └─ When all synchronizers reach the same block: emit FeedMessage
     (unified view of all protocol state at that block) to consumer
```

