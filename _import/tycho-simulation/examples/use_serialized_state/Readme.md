# Using Serialized State

This example demonstrates how to deserialize pool state from JSON and create `ProtocolSim` instances directly from it.

## Use Case

Serializing and deserializing protocol state is useful for:

- **Reproducible Tests**: Create deterministic tests that don't depend on external API calls or live blockchain state
- **Offline Development**: Work with realistic pool data without network access
- **Debugging**: Share exact pool states when investigating issues

## How It Works

The `typetag` crate handles polymorphic deserialization, automatically selecting the correct protocol implementation based on the `"protocol"` field in JSON.

## How to Run

```bash
cargo run --example use_serialized_state
```

## Supported Protocols

**Serializable protocols:**

| Protocol | State Type |
|----------|-----------|
| Uniswap V2 | `UniswapV2State` |
| Uniswap V3 | `UniswapV3State` |
| PancakeSwap V2 | `PancakeswapV2State` |
| Aerodrome Slipstreams | `AerodromeSlipstreamsState` |
| Velodrome Slipstreams | `VelodromeSlipstreamsState` |
| Lido | `LidoState` |
| RocketPool | `RocketPoolState` |
| ERC4626 Vaults | `ERC4626State` |
| Fluid V1 | `FluidV1` |
| CoW AMM | `CowAmmState` |
| Ekubo | `EkuboState` |
| Ekubo V3 | `EkuboV3State` |

**Not supported (EVM-dependent):**

| Protocol | Reason |
|----------|--------|
| Generic VM Protocols (`EVMPoolState`) | Requires VM state and database interface |
| Uniswap V4 | Hook handlers contain VM dependencies |

These protocols cannot be serialized because they depend on EVM state that cannot be captured in a static JSON snapshot.
