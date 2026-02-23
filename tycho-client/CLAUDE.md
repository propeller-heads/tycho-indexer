# tycho-client

Consumer library implementing the snapshot + deltas pattern for real-time protocol state.

## Module Map

```
rpc.rs              HTTP snapshot client — fetches protocol state at a block height
deltas.rs           WebSocket client — streams real-time state deltas
stream.rs           Builder entry point — wires RPC + WS clients into a TychoStream
feed/
  mod.rs            BlockSynchronizer — aligns N synchronizers by block, emits FeedMessage
  synchronizer.rs   ProtocolStateSynchronizer — manages snapshot + delta sync for one extractor
  component_tracker.rs  Filters components by TVL threshold or explicit ID list
  block_history.rs  Validates block chain continuity; classifies incoming blocks
cli.rs / main.rs    CLI binary for manual testing
```

## Connections

```
TychoStreamBuilder (stream.rs)
  └─ creates ProtocolStateSynchronizer per extractor (feed/synchronizer.rs)
       ├─ ComponentTracker (feed/component_tracker.rs) → HttpRPCClient (rpc.rs)
       ├─ WsDeltasClient (deltas.rs) for live deltas
       └─ StateSyncMessage → BlockSynchronizer (feed/mod.rs)
            ├─ BlockHistory (feed/block_history.rs) for chain validation
            └─ FeedMessage → consumer channel
```

## Sync Lifecycle

1. `WsDeltasClient` subscribes; first message determines snapshot block
2. `HttpRPCClient` fetches snapshot at that block; deltas buffer until it arrives
3. `BlockSynchronizer` waits for all synchronizers, then emits a `FeedMessage` per block
4. Synchronizers classified as `Ready | Delayed | Stale | Advanced | Ended`; stale ones are kept but skipped
