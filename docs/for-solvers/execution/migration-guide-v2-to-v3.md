# Migration Guide: V2 to V3

This guide covers the breaking changes between V2 and V3 from the perspective of users who consume the Rust encoding library or interact with the TychoRouter contracts.

### Encoding Changes

#### Solution Struct

**Renamed fields:**

| V2               | V3               | Notes                            |
| ---------------- | ---------------- | -------------------------------- |
| `given_token`    | `token_in`       | The token being sold             |
| `given_amount`   | `amount_in`      | Amount of the input token        |
| `checked_token`  | `token_out`      | The token being bought           |
| `checked_amount` | `min_amount_out` | Minimum acceptable output amount |

**Removed fields:**

| Field                                 | Replacement                                                                                                                                                            |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `native_action: Option<NativeAction>` | No longer needed. The encoder automatically inserts WETH wrap/unwrap swaps (see [Wrapping and Unwrapping](encoding/native-token-handling-wrapping-and-unwrapping.md)). |
| `exact_out: bool`                     | Only exact-in was ever supported. Removed for simplicity.                                                                                            |

**New fields:**

| Field                     | Type               | Description                                                                                                      |
| ------------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `user_transfer_type`      | `UserTransferType` | How user funds enter the router. Moved here from the encoder builder.                                            |
| `client_fee_bps`          | `u16`              | Fee in basis points charged by the client (0–10000).                                                             |
| `client_fee_receiver`     | `Bytes`            | Address to receive the client fee.                                                                               |
| `max_client_contribution` | `BigUint`          | Maximum amount the client will subsidize from their vault if slippage reduces the output below `min_amount_out`. |

**Private fields with getters/setters:**

In V2, `Solution` fields were `pub`. In V3, all fields are private. Use the constructor and builder methods:

```rust
// V2
let solution = Solution {
    sender: addr,
    receiver: addr,
    given_token: token_a,
    given_amount: amount,
    checked_token: token_b,
    checked_amount: min_out,
    swaps: vec![swap],
    exact_out: false,
    native_action: Some(NativeAction::Wrap),
};

// V3
let solution = Solution::new(
    addr,        // sender
    addr,        // receiver
    token_a,     // token_in
    token_b,     // token_out
    amount,      // amount_in
    min_out,     // min_amount_out
    vec![swap],  // swaps
)
.with_user_transfer_type(UserTransferType::TransferFrom)
.with_client_fee_bps(50)
.with_client_fee_receiver(fee_addr)
.with_max_client_contribution(BigUint::from(0u64));
```

#### UserTransferType Moved to Solution

In V2, `UserTransferType` was set on the encoder builder. In V3, it is a field on each `Solution`, allowing different solutions in the same batch to use different funding methods.

```rust
// V2
let encoder = TychoRouterEncoderBuilder::new()
    .chain(chain)
    .user_transfer_type(UserTransferType::TransferFrom)  // set here
    .swap_encoder_registry(registry)
    .build()?;

// V3
let encoder = TychoRouterEncoderBuilder::new()
    .chain(chain)
    .swap_encoder_registry(registry)
    .build()?;

let solution = Solution::new(/* ... */)
    .with_user_transfer_type(UserTransferType::TransferFrom);  // set here
```

The `UserTransferType::None` variant has been renamed to `UserTransferType::UseVaultsFunds`, reflecting the new vault-based architecture.

#### Swap Struct

**Builder methods renamed** (added `with_` prefix for consistency):

| V2                             | V3                                  |
| ------------------------------ | ----------------------------------- |
| `.split(0.5)`                  | `.with_split(0.5)`                  |
| `.user_data(data)`             | `.with_user_data(data)`             |
| `.protocol_state(state)`       | `.with_protocol_state(state)`       |
| `.estimated_amount_in(amount)` | `.with_estimated_amount_in(amount)` |

**Getter methods renamed** (dropped `get_` prefix):

| V2                           | V3                       |
| ---------------------------- | ------------------------ |
| `.get_split()`               | `.split()`               |
| `.get_user_data()`           | `.user_data()`           |
| `.get_protocol_state()`      | `.protocol_state()`      |
| `.get_estimated_amount_in()` | `.estimated_amount_in()` |

#### EncodedSolution Struct

Fields are now private with getter methods, matching the pattern used elsewhere:

```rust
// V2
let swaps = encoded_solution.swaps;
let sig = encoded_solution.function_signature;

// V3
let swaps = encoded_solution.swaps();
let sig = encoded_solution.function_signature();
```

The `function_signature` field now reflects both the swap strategy and the funding mode. For example, `splitSwapUsingVault(...)` for a split swap using vault funds.

#### Wrapping and Unwrapping

V2 used a `NativeAction` enum on the `Solution` with `Wrap` and `Unwrap` variants. The router had dedicated wrap/unwrap flags.

**V3 removes this entirely.** Instead, a WETH executor handles wrapping and unwrapping as regular swap steps. The encoder automatically inserts these swaps when it detects ETH↔WETH gaps in the swap path.

```rust
// V2
let solution = Solution {
    given_token: eth_address,
    checked_token: dai_address,
    native_action: Some(NativeAction::Wrap),
    swaps: vec![weth_to_dai_swap],
    ..
};

// V3 — just set token_in to ETH; the encoder adds a WETH wrap swap automatically
let solution = Solution::new(
    sender,
    receiver,
    eth_address,   // token_in is ETH
    dai_address,   // token_out is DAI
    amount,
    min_out,
    vec![weth_to_dai_swap],  // first swap expects WETH — encoder bridges the gap
);
```

This also works for mid-path bridging (e.g., if one swap outputs ETH and the next expects WETH) and at the end of a path. See more in [Wrapping & Unwrapping](encoding/native-token-handling-wrapping-and-unwrapping.md).

#### Encoder Builder

**Removed options:**

| V2 option                  | Notes                             |
| -------------------------- | --------------------------------- |
| `.user_transfer_type(...)` | Moved to `Solution`.              |
| `.swapper_pk(...)`         | Removed. Sign Permit2 externally. |
| `.historical_trade()`      | Removed. No longer needed.        |

The V3 builder only requires `chain` and `swap_encoder_registry`:

```rust
// V3
let encoder = TychoRouterEncoderBuilder::new()
    .chain(Chain::Ethereum)
    .swap_encoder_registry(registry)
    .build()?;
```

#### Transaction and encode\_full\_calldata Removed

The `Transaction` struct and `encode_full_calldata` method have been removed entirely. In V2, `encode_full_calldata` was already deprecated. V3 only supports `encode_solutions`, which returns `EncodedSolution` objects.

You are responsible for constructing the full method call, including execution-critical parameters like `min_amount_out`, `receiver`, and fee configuration.

#### SwapEncoderRegistry

`SwapEncoderRegistry::new` now requires a `Chain` parameter:

```rust
// V2
let registry = SwapEncoderRegistry::new()
    .add_default_encoders(executors_addresses)?;

// V3
let registry = SwapEncoderRegistry::new(Chain::Ethereum)
    .add_default_encoders(executors_addresses)?;
```

### Execution Changes

#### Router Function Signatures

The TychoRouter V3 methods now include a `ClientFeeParams` struct in their signatures:

```solidity
struct ClientFeeParams {
    uint16 clientFeeBps;
    address clientFeeReceiver;
    uint256 maxClientContribution;
    uint256 deadline;
    bytes clientSignature;
}
```

When constructing calldata yourself (recommended), encode this struct as part of the function arguments. Even if you are not charging fees, you must pass this parameter with zero values.

#### Vault Integration

The TychoRouter now includes an ERC6909 vault. Key changes:

* **`UseVaultsFunds`** replaces the old `None` transfer type. Tokens deposited in the vault are tracked per-user and can be used for swaps or withdrawn.
* Deposit tokens via `router.deposit(token, amount)` before swapping with vault funds.
* Fees (both client and router fees) are credited to the receiver's vault balance rather than transferred immediately.

For more see [Vault](vault.md).

#### No More Wrap/Unwrap Flags

The router no longer accepts `wrap` or `unwrap` boolean flags. If your calldata construction includes these parameters, remove them. The WETH executor handles wrapping and unwrapping as part of the swap path. See [native-token-handling-wrapping-and-unwrapping.md](encoding/native-token-handling-wrapping-and-unwrapping.md "mention").

#### Method Variants

Each swap strategy (single, sequential, split) now has three variants instead of two, with a new UsingVault variant:

| V2                       | V3                          |
| ------------------------ | --------------------------- |
| `singleSwap(...)`        | `singleSwap(...)`           |
| `singleSwapPermit2(...)` | `singleSwapPermit2(...)`    |
| —                        | `singleSwapUsingVault(...)` |

The same pattern applies for `sequentialSwap` and `splitSwap`. The `EncodedSolution.function_signature` tells you which variant to call.
