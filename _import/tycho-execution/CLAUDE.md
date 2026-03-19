# Tycho Contracts

DeFi swap execution framework: Solidity smart contracts (TychoRouter) + Rust encoding library. Multi-protocol token swaps with fee-taking, vault-based accounting, and 15+ DEX integrations.

**Docs**: https://docs.propellerheads.xyz/tycho
**License**: BUSL-1.1 (Solidity), MIT (Rust)

## Solidity Architecture

```
TychoRouter (entry point)
  inherits AccessControl           -- role-based admin (add executors, set fees)
  inherits Dispatcher              -- executor dispatch via delegatecall
    inherits TransferManager       -- input/output transfers, Permit2/ERC20/Vault funding
      inherits Vault (ERC6909)     -- multi-token vault, transient storage deltas
  inherits EIP712                  -- client fee signature verification

FeeCalculator (separate contract, called via staticcall -- read only)
```

### Swap Flow (end-to-end)

```
Entry (e.g. splitSwap)
  → input transfer (_transfer)
  → for each swap hop:
      balance snapshot (balanceOf before)
      → delegatecall executor.swap()
      balance snapshot (balanceOf after)
      → amountOut = diff (single source of truth)
      → if outputToRouter: forward to receiver via _transferOut
  → _takeFees (deduct client fee + router fees, credit vault balances)
  → _maybeAddClientContribution (cap slippage contribution)
  → _settleOutput (transfer/credit final amount to receiver or vault)
  → _finalizeBalances (verify all transient deltas settled)
```

### Core Contracts (`foundry/src/`)

| Contract | Purpose |
|---|---|
| `TychoRouter.sol` | Entry point. 3 swap strategies (single/sequential/split) x 3 funding modes (transferFrom/Permit2/vault) = 9 public methods. `_takeFees()` deducts fees, `_settleOutput()` transfers/credits final output to receiver or vault |
| `Vault.sol` | ERC6909 multi-token vault (see subsection below) |
| `Dispatcher.sol` | Executor dispatch. 3-day timelock on new executors. Balance-diff verification of swap outputs. Queries transfer data via staticcall, executes swaps via delegatecall |
| `TransferManager.sol` | Caps transferFrom to the declared input amount. `_transferOut` for output transfers (handles FoT/rebasing tokens via balance-diff). 6 transfer scenarios depending on context |
| `FeeCalculator.sol` | Dual fee system: router fee on output + router fee on client fee. Per-client custom rates. Upgradeable without redeploying router |

Interfaces (`foundry/interfaces/`): `IExecutor` (swap [void], getTransferData [returns transferType, receiver, tokenIn, tokenOut, outputToRouter], fundsExpectedAddress), `ICallback` (handleCallback, verifyCallback, getCallbackTransferData), `IFeeCalculator` (calculateFee [takes amountIn, client, clientFeeBps], getEffectiveRouterFeeOnOutput).

### Vault (`Vault.sol`)

ERC6909 multi-token vault with dual storage:

**Transient storage** (tload/tstore, ~100 gas per op): Tracks per-token deltas (credits/debits) during a swap. Positive delta when tokens arrive at the router, negative when they leave. `nonZeroDeltaCount` tracks unsettled deltas.

**Persistent storage** (ERC6909 balances): User token balances for deposits, withdrawals, and fee credits. Token IDs are `uint256(uint160(tokenAddress))`. Custom `_vaultBalances` mapping with `_mintWithoutEvent`/`_burnWithoutEvent` skips ERC6909 Transfer events during swaps (gas savings).

**Settlement** (`_finalizeBalances`): Called at the end of every swap. Validates:
- Non-vault swaps: all deltas must be zero (`nonZeroDeltaCount == 0`)
- Vault-funded swaps: at most one negative delta (the input token), which gets burned from the user's vault balance

**External methods**: `deposit(token, amount)` and `withdraw(token, amount)`. Supports native ETH via `address(0)`.

**Fee accounting**: Fees credited directly to fee receivers' vault balances via `_creditVault()` -- persistent storage writes (~22k gas each) but no ERC20 transfers.

**Why transient storage is kept** (even with balance-diff verification): The delta system is a cheap (~100 gas per op) safety guardrail that catches routing logic bugs and exploits. Example: a malicious encoder inserts a third split through a compromised protocol whose callback tells TransferManager to transfer PEPE instead of the expected token. The router would lose PEPE, but transient storage detects the negative PEPE delta and reverts. It also prevents overpayment in vault-funded split swaps where split percentages don't sum to 100%.

### Fee System (`FeeCalculator.sol`)

Three fee layers, deducted from swap output:

1. **Client fee** (EIP-712 signed): Passed per-swap via `ClientFeeParams` struct containing `clientFeeBps`, `clientFeeReceiver`, `maxClientContribution`, `deadline`, and `clientSignature`. The client signs these params with their own key; the router verifies the EIP-712 signature on-chain before applying any fee. The `clientFeeReceiver` address doubles as the client identifier. `maxClientContribution` caps how much positive slippage the client absorbs (prevents the client from claiming all surplus). Passing zero `ClientFeeParams` is allowed (no fee, no client tracking).
2. **Router fee on output** (stored): `_routerFeeOnOutputBps` -- Tycho's cut of the swap output amount.
3. **Router fee on client fee** (stored): `_routerFeeOnClientFeeBps` -- Tycho's cut of the client fee (deducted from the client's portion, not from the user).

**Per-client overrides**: Both router fees can be overridden per client address via `_customRouterFees` mapping (`CustomFees` struct, single storage slot). If set, the custom rate replaces the default for that client. Can be removed to revert to defaults.

**Deduction order**: client fee calculated first, then router's cut of client fee subtracted from it, then router fee on output. `amountOut = amountIn - clientPortion - totalRouterFee`.

**Accounting**: FeeCalculator only computes amounts (called via staticcall). Actual distribution happens in TychoRouter's `_takeFees()`, which credits fee receivers' vault balances via `_creditVault()`. `_settleOutput()` then handles the remaining output (transfer to receiver or vault credit).

### Executors (`foundry/src/executors/`)

Each executor implements `IExecutor` (`swap` [void], `getTransferData`, `fundsExpectedAddress`). Transfer types, receivers, and `outputToRouter` are hardcoded per-executor -- not encodable in calldata. Executors are intentionally simple: they just call the protocol. All balance tracking, output verification, and transfer logic lives in the Dispatcher/TransferManager.

Supported: UniswapV2, UniswapV3, UniswapV4, BalancerV2, BalancerV3, Curve, Ekubo, EkuboV3, Slipstreams, MaverickV2, Bebop (RFQ), Hashflow (RFQ), FluidV1, Rocketpool, ERC4626, Etherfi, WETH.

### Executor Flow, Callbacks & Output Verification

**Balance-diff verification**: The Dispatcher independently verifies every swap output. It measures `balanceOf(measureAt, tokenOut)` before and after every `swap()` delegatecall. The measured diff becomes the single source of truth for fees, delta accounting, and sequential chaining. This eliminates trust in protocol-reported amounts and handles fee-on-transfer/rebasing tokens universally.

**Two output categories** (via `outputToRouter` flag from `getTransferData()`):

| Category | Executors | `outputToRouter` | Behavior |
|---|---|---|---|
| **Direct-to-receiver** | UniswapV2, UniswapV3, UniswapV4, BalancerV2, BalancerV3, Ekubo, EkuboV3, Slipstreams, MaverickV2, ERC4626, FluidV1 | `false` | Dispatcher measures balance at receiver |
| **Output-lands-at-router** | Curve, WETH, Rocketpool, Etherfi, Bebop, Hashflow | `true` | Dispatcher measures at `address(this)`, then forwards via `_transferOut()` if receiver != router |

**Two input categories**:

**Direct-transfer** (UniswapV2, BalancerV2, Curve): Dispatcher staticcalls `getTransferData()` to get the `TransferType`, receiver, tokenIn, tokenOut, and outputToRouter. Performs the transfer, then delegatecalls `swap()`.

**Callback-based** (UniswapV3, UniswapV4, BalancerV3, Ekubo): Also implement `ICallback`. Flow:

1. `getTransferData()` returns `None` (no pre-swap transfer)
2. `swap()` calls the protocol pool
3. Pool calls back to TychoRouter's `fallback()`
4. `fallback()` routes to `_callHandleCallbackOnExecutor()` in Dispatcher
5. Dispatcher delegatecalls `getCallbackTransferData()` -- returns transfer details and amount owed
6. Dispatcher performs the transfer
7. Dispatcher delegatecalls `handleCallback()` to complete the interaction

`_currentSwappingExecutor` is stored in transient storage so `fallback()` knows which executor to route to. Cleared after the callback to prevent re-entrancy.

Transfer types returned by executors:

```
enum TransferType {
    Transfer,                 // Router sends its balance to the pool
    TransferNativeInExecutor, // ETH sent as msg.value in executor (Fluid, Rocketpool, Curve, etc.)
    ProtocolWillDebit,        // Protocol pulls from router via approval
    None                      // Callback handles it, or tokens already in place
}
```

### Transfer and Receiver Resolution

**Transfer resolution** (`_callSwapOnExecutor`): Before every swap, the Dispatcher **staticcalls** `getTransferData()` on the current executor. Returns a hardcoded `TransferType`, receiver address, `tokenIn`, `tokenOut`, and `outputToRouter`. `_transfer()` handles 6 scenarios based on (TransferType, isFirstSwap, isSplitSwap, isCallback).

**Output settlement** (in TychoRouter): After all swaps complete, `_takeFees()` deducts fees and credits fee receivers' vault balances. Then `_settleOutput()` updates delta accounting and either credits the user's vault balance or transfers tokens to the receiver.

**Receiver resolution** (`_sequentialSwap`): For sequential routes (A -> Pool1 -> Pool2 -> D), the Dispatcher determines each swap's output receiver by peeking ahead and **staticcalling** `fundsExpectedAddress()` on the **next** executor. Returns either:
- The pool address (direct-transfer protocols -- tokens go straight to pool)
- `address(this)` (callback protocols -- tokens stay in router)

Last swap's receiver is the final user/vault address.

## Rust Encoding Pipeline (`src/encoding/`)

Encodes a `Solution` into EVM calldata through three trait layers:

```
TychoEncoder (trait)                     -- public API, validates Solution
  └─ TychoRouterEncoder                 -- selects strategy, auto-inserts WETH swaps
       └─ StrategyEncoder (trait)        -- encodes swap structure (single/sequential/split)
            └─ SwapEncoder (trait)       -- encodes protocol-specific pool data
```

### TychoEncoder / TychoRouterEncoder

**TychoEncoder** (`tycho_encoder.rs`): Public trait. `encode_solutions(Vec<Solution>)` returns `Vec<EncodedSolution>` with raw swap bytes, function signature, and optional Permit2 data.

**TychoRouterEncoder** (`evm/tycho_encoders.rs`): Owns all three strategy encoders. Per Solution:
1. Validates (exact input only, has swaps, no invalid cycles)
2. Auto-inserts WETH wrap/unwrap swaps where ETH<->WETH bridges are missing
3. Selects strategy:
   - **Single** -- 1 swap, or all swaps from one groupable protocol with no splits
   - **Sequential** -- multiple swaps, all with `split == 0.0`
   - **Split** -- any swap has `split > 0.0`
4. Delegates to the selected `StrategyEncoder`
5. Appends Permit2 data if configured

**TychoExecutorEncoder**: Simplified encoder for direct executor calls (bypasses TychoRouter). Groups swaps, validates only 1 group, encodes via SwapEncoder directly.

### StrategyEncoder

Three implementations (`evm/strategy_encoder/`), each targeting a TychoRouter method family:

| Strategy | Router methods | Encoding |
|---|---|---|
| `SingleSwapStrategyEncoder` | `singleSwap` / `Permit2` / `UsingVault` | Groups swaps, encodes via SwapEncoder, prepends executor address |
| `SequentialSwapStrategyEncoder` | `sequentialSwap` / `Permit2` / `UsingVault` | Validates path connectivity, groups by protocol, PLE-encodes each group with executor header |
| `SplitSwapStrategyEncoder` | `splitSwap` / `Permit2` / `UsingVault` | Builds token array [tokenIn, intermediaries, tokenOut], encodes token indices + split percentages (U24) + executor + protocol data |

### SwapEncoder

**SwapEncoder trait** (`swap_encoder.rs` + `evm/swap_encoder/`): Each protocol implements `encode_swap(&Swap, &EncodingContext) -> Vec<u8>`, encoding pool-specific data (pool ID, fee tiers, direction flags) into packed bytes. Each encoder holds its executor address.

**SwapEncoderRegistry** (`swap_encoder_registry.rs`): Creates encoders by protocol system name. Reads executor addresses from `config/executor_addresses.json`. Protocol name prefixes: `vm:` (simulation-backed, e.g. `vm:balancer_v2`, `vm:curve`), `rfq:` (request-for-quote, e.g. `rfq:bebop`), bare (on-chain, e.g. `uniswap_v2`, `fluid_v1`).

### Supporting Modules

**Swap grouping** (`evm/group_swaps.rs`): Batches consecutive swaps on the same groupable protocol (UniswapV4, BalancerV3, Ekubo) into a single `SwapGroup` for one delegatecall.

**PLE encoding** (`evm/utils.rs`): Prefix-length encoding: `[len: u16][data][len: u16][data]...`. Combines swap data within groups and groups within strategies. Ekubo uses concatenation instead (`NON_PLE_ENCODED_PROTOCOLS`).

**Permit2** (`evm/approvals/permit2.rs`): Fetches on-chain nonce/expiration, constructs `PermitSingle`, signs via EIP-712.

**Client fee params**: There is no `ClientFeeParams` struct on the Rust side. The Solidity struct is encoded as a raw ABI tuple `(uint16,address,uint256,uint256,bytes)` embedded in the function signature strings within each strategy encoder. The caller provides the pre-signed bytes; the Rust encoder just passes them through.

### Key Models (`models.rs`)

- `Solution`: sender, receiver, token_in/out, amount_in, min_amount_out, `Vec<Swap>`, fee config
- `Swap`: component (protocol pool metadata), token_in/out, split (0.0-1.0), optional user_data
- `EncodedSolution`: swap bytes, function signature, router address, optional Permit2 permit
- `UserTransferType`: `TransferFromPermit2` | `TransferFrom` | `UseVaultsFunds`
- `EncodingContext`: exact_out, router_address, group token_in/out -- passed to SwapEncoders

## Build & Test

### Solidity (Foundry)

```bash
cd foundry
forge build                     # compile
forge test -vvv                 # run all tests
forge fmt --check               # check formatting
forge fmt                       # auto-format
forge snapshot                  # gas snapshots
```

Config: `foundry/foundry.toml` -- Cancun EVM, optimizer 200 runs (default) / 1000 runs (production), via_ir enabled. Line length 80.

Tests fork Ethereum mainnet via `RPC_URL` and Base via `BASE_RPC_URL` env vars.

### Rust

```bash
cargo build --features evm      # build with EVM support
cargo test                      # unit tests (no fork)
cargo test --features fork-tests # integration tests (requires RPC_URL)
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

Features: `evm` (default, enables alloy + reqwest), `fork-tests` (mainnet fork tests), `test-utils` (test helpers).

### CI

- **evm-foundry-ci.yml**: Format check + forge test + gas snapshot on PRs and main pushes
- **slither.yml**: Static analysis

## Adding a New Executor

1. Create `foundry/src/executors/NewProtocolExecutor.sol` implementing `IExecutor`
2. `swap()` returns void -- just call the protocol. No balance tracking, no output transfers, no amount validation needed (the Dispatcher handles all of this via balance-diff)
3. Hardcode the correct `TransferType`, `tokenOut`, and `outputToRouter` in `getTransferData()` -- do NOT make them encodable. Set `outputToRouter = true` if the protocol sends output to `msg.sender` rather than accepting a receiver param
4. Return the correct `fundsExpectedAddress()` (pool address for direct-transfer protocols, `address(this)` for pull-based)
5. Add Rust encoder in `src/encoding/evm/swap_encoder/` and register in `swap_encoder_registry.rs`
6. Add integration tests in both `foundry/test/protocols/` and `tests/`
7. Add test setup in `foundry/test/TychoRouterTestSetup.sol`

## Conventions

### Solidity

- Solidity ^0.8.26, BUSL-1.1 license
- OpenZeppelin for AccessControl, SafeERC20, ERC6909, ReentrancyGuard, Pausable
- Prefix private/internal state with underscore: `_feeCalculator`, `_ALLOWED_DUST`
- Transient storage slots use keccak256 of descriptive names
- Custom errors with contract-prefixed names: `TychoRouter__EmptySwaps`, `Vault__AmountZero`
- Format with `forge fmt` (80 char line length)
- Slither `// slither-disable-next-line` annotations where false positives occur

### Rust

- Edition 2021, `alloy` for EVM types, `BigUint` for amounts
- `thiserror` for error types
- `rstest` for parameterized tests
- Protocol-specific logic in separate files under `swap_encoder/`

### Testing

- Foundry tests use `TychoRouterTestSetup.sol` as the shared base
- Fork tests require mainnet RPC -- use real on-chain state
- Rust integration tests use `common/` module for shared fixtures
- Test naming: `test_<description>` in Rust, `test<Description>` in Solidity

### Git

- Submodules for Solidity dependencies (`foundry/lib/`)
- Checkout with `--recursive` to get all submodules