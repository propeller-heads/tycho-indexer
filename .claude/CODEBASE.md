<!-- docs-synced-at: 58d9900b -->
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

#### Ingestion

1. Substreams gRPC delivers `BlockScopedData` (protobuf) to `ProtocolExtractor`
2. `ProtocolExtractor` deserializes into `BlockChanges` (tx-level state/balance/token deltas)
   - `PartialBlockBuffer` accumulates sub-block messages until full-block signal arrives
   - `TokenPreProcessor` fetches metadata (symbol, decimals) via Ethereum RPC for unknown tokens
3. `BlockChanges` inserted into `ReorgBuffer` (one per `ProtocolExtractor`)
   - On `BlockUndoSignal`: purge blocks after reverted hash, emit revert messages — no DB rollback needed
   - Drain to DB when `count_blocks_before(finalized_block_height) >= commit_batch_size` — only finalized blocks ever reach DB
4. Drained blocks: `BlockChanges` → `BlockAggregatedChanges` (merge all tx-level deltas into one state per component/account)
5. DB write via `CachedGateway` → Postgres (upsert blocks, tokens, components, state, balances); sets `db_committed_block_height` on outgoing message
6. Broadcast `BlockAggregatedChanges` on internal channel (all blocks, including pending/non-committed)

#### Server

7. WebSocket subscribers (`services/ws.rs`) receive broadcast directly; revert flag signals chain reorg
8. `PendingDeltasBuffer` (`services/deltas_buffer.rs`) receives broadcast
   - Inserts every full block (partial blocks skipped)
   - Auto-drains blocks ≤ `db_committed_block_height` (already in DB, no longer "pending")
   - RPC handlers query DB snapshot + pending deltas = consistent view of latest state

#### Client (tycho-client)

9. `StateSynchronizer` (one per extractor subscription):
   - Subscribes to WebSocket stream via `WsDeltasClient`
   - On first message: fetches HTTP snapshot via `HttpRPCClient` at that block height
   - Buffers WebSocket deltas received before snapshot arrives; applies them on top to catch up
10. `BlockSynchronizer` (across all extractors):
    - Tracks state per synchronizer: `Ready` / `Delayed` / `Stale`
    - Delayed synchronizers consume buffered messages to catch up
    - When all synchronizers reach the same block: emits `FeedMessage` (unified view of all protocol state at that block) to consumer

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
