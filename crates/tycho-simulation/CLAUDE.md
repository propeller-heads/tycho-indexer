# tycho-simulation

Off-chain DeFi protocol simulation library. Computes swap outputs, spot prices, and price impact
for any protocol indexed by Tycho.

## Key Modules (`src/`)

- **`protocol/`**: Core traits and models — `ProtocolSim`, `ProtocolComponent`, `Update`
- **`evm/simulation.rs`**: `SimulationEngine` — runs EVM transactions via `revm`
- **`evm/engine_db/`**: Database backends (`SimulationDB` in-memory, `TychoDB` RPC-backed)
- **`evm/stream.rs`**: Tycho feed integration — decodes live `FeedMessage` state into protocol
  instances ready for simulation
- **`evm/protocol/`**: Protocol implementations
  - **Native** (`uniswap_v2/`, `uniswap_v3/`, `uniswap_v4/`, `ekubo/`, `cowamm/`, `fluid/`,
    `aerodrome_v1/`, `aerodrome_slipstreams/`, `pancakeswap_v2/`, `etherfi/`, `erc4626/`,
    `rocketpool/`, `cpmm/`, `clmm/`): Pure Rust math, no EVM execution
  - **VM** (`vm/`): Generic Solidity adapter (`TychoSimulationContract`) executed in `revm` for
    protocols without a native implementation
- **`rfq/`**: RFQ client for off-chain market makers (WebSocket-based quote streaming)

## Simulation Approaches

Order of preference when integrating a new protocol:

1. **Native** — pure Rust math; fastest, preferred for simple AMMs (Uniswap V2/V3 forks)
2. **VM** — Solidity adapter in `revm`; works for any EVM protocol, slower
3. **RFQ** — off-chain quotes via API; for protocols that can't be simulated on-chain

## Features

| Feature | Default | Contents |
|---------|---------|----------|
| `evm` | yes | `revm`, `SimulationEngine`, all EVM protocol impls |
| `rfq` | yes | RFQ WebSocket client and protocol adapters |
| `network_tests` | no | Gates tests that require live network access |

## Conventions

- `cargo +nightly fmt` for formatting; stable toolchain for everything else
- `rstest`: name each parametrised case with `#[case::descriptive_name(...)]`
- `network_tests` feature gates any test that hits external services — do not leave network calls
  in tests without this gate
