<!-- docs-synced-at: 680cf887 -->
# Tycho Codebase Guide

Low-latency, reorg-aware indexer that streams DEX liquidity state from on-chain data to solvers.

## What is Tycho

Tycho indexes EVM blockchain state for DeFi protocols. It consumes Substreams (blockchain data
pipelines), processes fork-aware messages through extractors, persists finalized state to Postgres,
and serves real-time deltas over WebSocket plus snapshots over HTTP RPC. Consumers reconstruct
protocol component state to simulate swaps.

Key properties:
- **Reorg-aware**: blocks stay in a memory buffer until finalized; reverts never reach the DB
- **Real-time**: WebSocket subscribers receive deltas within the same block they're processed
- **Temporal**: every mutable DB row carries `valid_from`/`valid_to` for time-travel queries
- **Multi-protocol**: a single instance runs N extractors concurrently (one per protocol)

## Workspace Module Map

### Shared Domain

| Crate | Description |
|---|---|
| [`tycho-common`](../tycho-common/CLAUDE.md) | Domain types (`Chain`, `Block`, `ProtocolComponent`, `Token`), DTOs, async gateway/extraction traits, simulation abstractions (`SwapQuoter`) |

**Features**: `diesel` (Diesel derives), `test-utils` (mockall mocks).

### Ingestion & Extraction

| Crate / Module | Description |
|---|---|
| [`tycho-indexer/extractor`](../tycho-indexer/CLAUDE.md) | `ProtocolExtractor` processes Substreams messages, `ReorgBuffer` handles finality, `ProtocolMemoryCache` for in-process state, DCI plugin for VM tracing |
| [`tycho-ethereum`](../tycho-ethereum/CLAUDE.md) | Ethereum RPC client (alloy), `AccountExtractor`, `TokenPreProcessor`, `TokenAnalyzer`, `EntryPointTracer` |

### Services (HTTP + WS)

| Crate / Module | Description |
|---|---|
| [`tycho-indexer/services`](../tycho-indexer/CLAUDE.md) | HTTP RPC endpoints, WebSocket broadcaster, `PendingDeltasBuffer` for RPC consistency, access control, plan restrictions, compression |

### Storage

| Crate | Description |
|---|---|
| [`tycho-storage`](../tycho-storage/CLAUDE.md) | Postgres backend (Diesel): `CachedGateway` (buffered writes), `DirectGateway` (testing), temporal versioning, FK-safe write ordering |

### Consumer

| Crate | Description |
|---|---|
| [`tycho-client`](../tycho-client/CLAUDE.md) | Rust library + CLI: `TychoStreamBuilder`, snapshot+delta sync, block alignment across extractors, TVL/ID filtering |
| `tycho-client-py` | Python bindings (maturin/PyO3) wrapping tycho-client |

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

## Key Architectural Patterns

### Extractor-per-protocol

Each protocol runs as a separate `ExtractorRunner` tokio task. Config in `extractors.yaml`.
Extractors are stateful: they track components, state history, and Substreams cursor.

### Implementation types: Custom, VM, and Hybrid

The `ImplementationType` enum has two variants (`Custom`, `Vm`), but three patterns exist:

- **Custom**: State fully described by Substreams output (reserves, fees). Uniswap V2/V3.
- **VM**: Requires full contract storage for simulation. Tracks code, storage slots, balances.
  Balancer V2, Curve. Often paired with DCI for dynamic contract discovery.
- **Hybrid**: Combines explicit protocol state attributes (from Substreams) with contract storage
  tracking. Simulation uses both: decoded state for known fields, raw storage for on-chain VM
  execution. Runtime pattern, not a separate enum variant.

### ReorgBuffer + finality

Blocks enter `ReorgBuffer` immediately but only reach the DB via
`drain_blocks_until(finalized_height)`. The DB always reflects canonical chain state. Pending
blocks are served to RPC via `PendingDeltasBuffer`.

### Temporal versioning

Every mutable Postgres entity carries `valid_from`/`valid_to`. `apply_versioning()` sets
`valid_to` on the previous row when a new version is inserted. Historical rows are never mutated.

### Dual runtime

The `index` command runs two tokio runtimes: extraction (CPU-bound) and server/gateway (I/O-bound).
Configurable via `EXTRACTION_WORKER_THREADS` (default 2) and `MAIN_WORKER_THREADS` (default 3).

## Configuration

### Environment variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Postgres connection string |
| `RPC_URL` | Ethereum JSON-RPC endpoint |
| `AUTH_API_KEY` | API key for RPC access control |
| `SUBSTREAMS_API_TOKEN` | Substreams gRPC auth |
| `EXTRACTION_WORKER_THREADS` | Extraction runtime threads (default 2) |
| `MAIN_WORKER_THREADS` | Server runtime threads (default 3) |
| `OTLP_EXPORTER_ENDPOINT` | OpenTelemetry trace exporter |
| `RUST_LOG` | Tracing filter (e.g. `tycho_indexer=debug`) |

### CLI commands

| Command | Purpose |
|---|---|
| `index` | Run all extractors from `extractors.yaml` + HTTP/WS server |
| `run` | Run a single extractor (testing / debugging) |
| `analyze-tokens` | Token quality analysis cron job |
| `rpc` | HTTP RPC server only (no extractors) |

### Feature flags

| Crate | Feature | Effect |
|---|---|---|
| `tycho-common` | `diesel` | Diesel derives on `Bytes` and model types |
| `tycho-common` | `test-utils` | `mockall` auto-mocks on trait abstractions |

No other crate-level features. Runtime behavior controlled via CLI args, env vars, and YAML config.

## Testing

- `cargo test` for standard tests
- DB serial tests: name must include `serial_db` (nextest test group, sequential)
- DB harness: `run_against_db` (tycho-storage) manages setup/teardown
- Archive RPC tests: `#[ignore]`-d
- Lint: `cargo clippy --workspace --lib --all-targets --all-features`
- Format: `cargo +nightly fmt --check`

## Related Repositories

- **tycho-protocol-sdk**: Substreams modules producing the protobuf messages Tycho consumes
- **tycho-simulation**: Protocol-specific swap simulators (consumed via tycho-client)
- **tycho-execution**: Swap encoding and execution against Tycho router contracts
