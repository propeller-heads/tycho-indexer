# Aqua0 RFQ

Aqua0 is exposed to Tycho as `rfq:aqua0`. It is an indicatively priced RFQ component, not an
on-chain indexed AMM. Aqua0's backend selects the JIT ranges, reserves the backing, and signs the
Uniswap V4 hook data. Tycho reconstructs the advertised levels and executes a binding quote through
its existing Router V3 and Uniswap V4 executor.

## Supported execution chains

| Chain | Chain ID | Pinned Router V3 | V4 executor |
|---|---:|---|---|
| Base | 8453 | `0x9bA632d83e9eF57571256Cf4cc951b8aF1158e9C` | `0x78db9684220541601E9215bB16b219e5DF6cF0fb` |
| Arbitrum | 42161 | `0x8A8Ba3973C84252BF7D357E4C0244b7EedB8B658` | `0xdb696336F7A5F9048252664A3475C194dAe0e62f` |
| Polygon | 137 | `0x0C85409014d6c8cAEF60C837198c931246BD6296` | `0x32bB33AfB193e16df121cdc2D87c44f015D325DA` |
| Robinhood Chain | 4663 | `0x345e48768a65Ae596ac6A2Aee71202753C4866F5` | `0xe781c1869c9D8E60dDfcD8F8fb5213Ed8Ad07366` |

Avalanche, Celo, and Monad are Aqua0 chains, but the Tycho revision pinned by this integration has no
matching chain configuration and execution deployment for them. Aqua0 state can still be read from the
backend on those chains, but `Aqua0Client` refuses to construct an executable Tycho market there.

Tycho's hosted data endpoints are a separate concern. Their smaller chain list does not determine where
an RFQ client can use a deployed Router V3.

Tycho release `0.397.0` lists newer Router V3 deployments in `router_addresses.json`. Aqua0's current
fillers and V4-adapter allowlists are bound to the still-active routers in the table above. The encoder
must keep using those pinned routers. Moving to a newer router requires a matching filler deployment
and a new Aqua0 adapter allowlist operation; changing only the local Tycho default will make execution
revert.

## Backend API

The client base URL ends at `/api/tycho/rfq` and exposes:

- `GET /chains`: support and router map.
- `GET /state`: a short-lived full snapshot for one `(chainId, poolId, classId)` market. It contains
  fully backed sampled levels, backend-selected ranges, and serialized route plans. Active global
  backing and withdrawal reservations are subtracted before levels are built.
- `POST /quote`: an exact-input binding request. It re-quotes, atomically reserves backing through
  Aqua0's existing fleet ledger, and returns adapter-valid `hookData` signed for the configured Router
  V3.

State reads use `X-API-Key`. Binding quotes use `X-Operator-Key` because they reserve capital and mint a
short-lived signature.

## Client registration

Each client represents one pool and class. Add more clients when a solver wants more Aqua0 markets.

```rust
use tycho_common::models::Chain;
use tycho_simulation::rfq::{
    protocols::aqua0::{
        client_builder::Aqua0ClientBuilder,
        models::Aqua0Market,
        state::Aqua0State,
    },
    stream::RFQStreamBuilder,
};

let market = Aqua0Market {
    pool_id: "0xbf948948cda5a93e50edb496cf32e565c46d8c7335c6bac7854a8d95eab25375".into(),
    class_id: "1".into(),
    amount0_samples: vec!["1000000000000000".into(), "10000000000000000".into()],
    amount1_samples: vec!["1000000".into(), "10000000".into()],
};

let aqua0 = Aqua0ClientBuilder::new(
    Chain::Base,
    "https://api.example.com/api/tycho/rfq".into(),
    market,
)
.credentials(read_key, operator_key)
.build()?;

let rfq_stream = RFQStreamBuilder::new()
    .set_tokens(token_metadata)
    .await
    .add_client::<Aqua0State>("aqua0", Box::new(aqua0));
```

When a snapshot is decoded from serialized Tycho state, the decoder reads
`AQUA0_RFQ_API_KEY` and `AQUA0_RFQ_OPERATOR_KEY` for its reconstructed binding client.

## Routing constraints

The current Aqua0 V4 authorization binds an exact input amount and the Router V3 address. Therefore:

- Exact input only.
- Same chain only.
- Aqua0 must be the first hop or the only hop.
- One Aqua0 leg per solution.
- Amounts above the largest fully backed sample are rejected rather than extrapolated.
- Expired state is rejected before simulation or binding.

`Aqua0SwapEncoder` obtains the binding quote at encoding time, reads its `hook_data`, and delegates byte
packing to Tycho's existing `UniswapV4SwapEncoder`. The configured executor address is the existing
Uniswap V4 executor. No custom router or Solidity executor is introduced.

## Deployment requirement

The Aqua0 adapter defaults to a closed router allowlist. An Aqua0 admin must allow the official Router
V3 on every enabled chain:

```solidity
adapter.setJitTriggerRouterAllowed(tychoRouterV3, true);
```

The Aqua0 contracts repository's `ConfigureV4Router` timelock script supports Tycho's delegatecall
shape. Set `V4_EXECUTOR` to Router V3 and `V4_DELEGATE_EXECUTOR` to Tycho's Uniswap V4 executor. The
script verifies that the delegated executor is active in Router V3 and that its PoolManager matches the
Aqua0 adapter before it schedules the allowlist operation.

The deployed Aqua0 V4 adapters are:

| Chain | Aqua0 V4 adapter |
|---|---|
| Base | `0xACaF2945890AB6caea62bDa459d1922532A500C8` |
| Arbitrum | `0xEa0ff3277279cf94dC8A5B9923dD7bb1a30e80C8` |
| Polygon | `0xEE71fFDCE0691790E814342d22E0ED2d75D8C0c8` |
| Robinhood Chain | `0xAc343B8A43f59Ca513D0C126B6BaED5A3452c0C8` |

On 2026-09-10, read-only mainnet calls confirmed that all four adapters have the JIT router allowlist
enabled and allow their pinned Router V3.

UniswapX V3 uses one deployed `UniswapXFiller` per chain. Each filler is immutable-bound to that
chain's V3 Dutch reactor and pinned Router V3:

| Chain | V3 Dutch reactor | Aqua0 filler |
|---|---|---|
| Base | `0x000000008a8330B5d1F43A62Bf4C673A49f27ba0` | `0x9ea548dc4E45Fe0C0Ed616daD53662D158c03fb1` |
| Arbitrum | `0xB274d5F4b833b61B340b654d600A864fB604a87c` | `0x0C6036274688379E8C4b95F62DDba15B28E2B40B` |
| Polygon | `0x00000000bAB6E234db8AD638B6A6395b7c499Bc4` | `0xE2Ad574B76F57c25C5373cD012527cDD89F5CC43` |
| Robinhood Chain | `0x000000007A1C8e570011EeDF86A2A35593013cBA` | `0x65Bb39eB5a0cD38C4bE5a7BC219a525202f4F39B` |

Read-only calls also confirmed that all four fillers grant `EXECUTOR_ROLE` to the Aqua0 worker
`0xB1C4bA83057A0cB78c69cB1586024f40Fe835382` and that every V4 executor is active in its pinned
Router V3.

## Focused verification

```bash
cargo +1.91.1 test -p tycho-simulation rfq::protocols::aqua0 --lib
cargo +1.91.1 test -p tycho-execution aqua0 --lib

cd crates/tycho-execution/contracts
forge test --match-path test/Aqua0TychoBaseFork.t.sol --use 0.8.33 -vv
```

The fork suite submits signed V3 Dutch orders through the real deployed reactor and Aqua0 filler, then
executes the swap through the pinned Router V3, V4 executor, and real PoolManager on Base, Arbitrum,
Polygon, and Robinhood Chain. Nothing is broadcast. The Aqua0 contracts repository also contains a
composed Base proof with a local adapter and vault fleet that validates signed JIT injection and
settlement.
