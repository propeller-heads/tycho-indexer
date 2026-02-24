# tycho-indexer

Main indexing engine: connects to Substreams, processes block data, persists finalized state, and
serves it over HTTP/WebSocket.

## Module Map

```
main.rs                     CLI entry point; account initialisation; extractor startup
cli/                        Command definitions: Index, Run, AnalyzeTokens, Rpc

extractor/
  protocol_extractor.rs     ProtocolExtractor — core message processor (see below)
  runner.rs                 ExtractorRunner: drives the Substreams stream; ExtractorHandle for control
  reorg_buffer.rs           ReorgBuffer — finality-aware block queue; chain-reorg purge
  models.rs                 BlockChanges, BlockAggregatedChanges, TxWithChanges
  protocol_cache.rs         ProtocolMemoryCache — in-process token/component metadata cache
  chain_state.rs            ChainState — tracks current tip and finality horizon
  token_analysis_cron.rs    Background job: token quality / tax analysis
  protobuf_deserialisation.rs  Substreams protobuf → BlockChanges conversion
  dynamic_contract_indexer/ DCI optional extension (see below)
  post_processors/          Optional block-level post-processing hooks

services/
  mod.rs                    ServicesBuilder — wires extractors, gateway, and server together
  rpc.rs                    HTTP endpoints: state snapshots, component queries
  ws.rs                     WebSocket broadcaster — emits BlockAggregatedChanges per block
  deltas_buffer.rs          PendingDeltasBuffer — pending-block state for RPC consistency
  cache.rs                  HTTP response cache
  access_control.rs         API-key authentication middleware

substreams/                 gRPC client for Substreams streaming API
pb/                         Auto-generated protobuf bindings (Substreams + Firehose)
```

## ProtocolExtractor

`ProtocolExtractor<G, T, E>` is generic over gateway `G`, token pre-processor `T`, and optional
extension `E`. It is the single point that turns raw Substreams messages into typed block data.

### Normal (full-block) path

1. Deserialize `BlockScopedData` → `BlockChanges` (tx-level state/balance deltas).
2. Run post-processor if configured.
3. Call `E::process_block_update()` (DCI — see below).
4. Fetch metadata for any new token addresses via `T` (ERC-20 symbol / decimals over RPC).
5. Insert `BlockChanges` into `ReorgBuffer`.
6. When `ReorgBuffer` has `>= commit_batch_size` blocks before `finalized_block_height`, drain them
   and schedule a DB write (see Persistence).
7. Aggregate all tx-level deltas → `BlockAggregatedChanges`; compute TVL.
8. Broadcast `Arc<BlockAggregatedChanges>` to subscribers.

### Partial-block path

Some chains (e.g. Base) emit multiple partial messages per block. While
`partial_block_index.is_some()`, each message is merged into `PartialBlockBuffer` (a single
`Option<BlockChanges>`). An aggregated message is broadcast immediately for WebSocket consumers,
but the block is **not** inserted into `ReorgBuffer` or written to DB until the full-block signal
arrives (clearing the buffer).

### DCI (Dynamic Contract Indexer) — optional

`ExtractorExtension::process_block_update()` is called on the accumulated `BlockChanges` before
aggregation. The DCI uses entry-point tracing results (`trace_results`) to extract additional
contract state and injects it back into `BlockChanges`. Two implementations exist:
`DynamicContractIndexer` (generic EVM tracing) and a `UniswapV4Hooks`-specific variant. When no
DCI is configured the call is a no-op.

### Revert handling

On `BlockUndoSignal(target_hash)` from Substreams:

1. `ReorgBuffer::purge(target_hash)` removes all buffered blocks after the common ancestor.
2. A `BlockAggregatedChanges` with `revert = true` is broadcast.
3. **No DB rollback is needed** — only finalized blocks ever reach the DB, so the persisted state
   is always on the canonical chain.

`PendingDeltasBuffer` (RPC side) mirrors this: it uses its own `ReorgBuffer` and discards
non-canonical pending blocks on the same broadcast.

## Persistence

`CachedGateway` enqueues `WriteOp` messages; `DBCacheWriteExecutor` flushes them when the next
block batch arrives. Writes follow a fixed FK-safe order (block → tx → contracts → tokens →
components → state → entry points → cursor). Every mutable row is versioned with `valid_from` /
`valid_to` — historical rows are never mutated (see `tycho-storage/CLAUDE.md`).

**Trigger:** `ReorgBuffer::drain_blocks_until(finalized_height)` — blocks are only committed once
they are provably behind the finality horizon.

## Why extractor messages must be broadcast to the RPC service

HTTP snapshot endpoints must reflect the latest state, including blocks not yet committed to DB.
Every `BlockAggregatedChanges` message is sent to `PendingDeltasBuffer` (in addition to WebSocket
clients). When an RPC query arrives, the handler fetches the DB snapshot then applies in-memory
pending deltas on top, giving a consistent view up to the chain tip. Without this feed the RPC
would lag by however many blocks remain in `ReorgBuffer` awaiting finalization.

`db_committed_block_height` on each message tells `PendingDeltasBuffer` when a block has been
written; it auto-drains those blocks so memory usage stays bounded.

## Connections

```
ExtractorRunner (runner.rs)
  ├─ SubstreamsStream (substreams/) → ProtocolExtractor (protocol_extractor.rs)
  │    ├─ ReorgBuffer (reorg_buffer.rs) → CachedGateway → DB
  │    ├─ ProtocolMemoryCache (protocol_cache.rs)
  │    └─ DCIPlugin (dynamic_contract_indexer/) [optional]
  └─ broadcast Arc<BlockAggregatedChanges>
       ├─ WsService (services/ws.rs) → WebSocket clients
       └─ PendingDeltasBuffer (services/deltas_buffer.rs)
            └─ RpcHandlers (services/rpc.rs) → HTTP responses
```
