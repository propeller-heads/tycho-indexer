---
description: How to integrate Tycho in different execution venues.
---

# Execution Venues

## Cow Protocol

To solve orders on [CoW Protocol](https://docs.cow.fi/cow-protocol/tutorials/solvers), you'll need to prepare your solution following specific formatting requirements.

First, initialize the encoder:

```rust
let swap_encoder_registry = SwapEncoderRegistry::new(Chain::Ethereum)
    .add_default_encoders(None)
    .expect("Failed to get default SwapEncoderRegistry");
    
let encoder = TychoRouterEncoderBuilder::new()
    .chain(Chain::Ethereum)
    .user_transfer_type(UserTransferType::TransferFrom)
    .swap_encoder_registry(swap_encoder_registry)
    .build()
    .expect("Failed to build encoder");
```

When solving for CoW Protocol, you need to return a [Solution object](https://docs.cow.fi/cow-protocol/reference/core/auctions/schema#solutions-output) that contains a list of interactions to be executed in sequence.

To solve with the Tycho Router you only need one custom interaction where:

1. `callData` is the full encoded method calldata using the encoded solution returned from `encoder.encode_solutions(...)`
2. `allowances` is a list with one entry where the allowance for the token in and amount in is set for spender to be the Tycho Router. This is necessary for the `transferFrom` to work.

## Uniswap X

To help you fill Uniswap X orders using Tycho, we provide an example [`UniswapXFiller`](https://github.com/propeller-heads/tycho-execution/blob/main/foundry/src/uniswap_x/UniswapXFiller.sol) contract. This contract is a starting point—you should adapt it to fit your use case.

The example contract:

* Inherits from `IReactorCallback` and implements `execute` and `reactorCallback`
* Calls the `TychoRouter` from `reactorCallback` to execute swaps
* Uses standard token approvals to allow `TychoRouter` to pull funds; you can replace this with Permit2 easily (you need to change the encoding accordingly though).
* Approves the UniswapX Reactor contract to transfer tokens out after execution
* Only supports solving one order at a time; you can extend it to support batching by implementing `executeBatch` and updating `reactorCallback`
* Can safely hold tokens. The Uniswap X Reactor only transfers out the required amount. If your solution is more efficient, any surplus stays in the filler contract
* Is not audited—use at your own risk

See how to encode the `callbackData` for `TychoRouter` [here](https://github.com/propeller-heads/tycho-execution/tree/main/examples/uniswapx-encoding-example).

<details>

<summary>How to deploy the Uniswap X Filler</summary>

The current [script](https://github.com/propeller-heads/tycho-execution/blob/main/foundry/scripts/deploy-uniswap-x-filler.js) deploys an Uniswap X filler and verifies it in the corresponding blockchain explorer.

Make sure to run `unset HISTFILE` in your terminal before setting the private key. This will prevent the private key from being stored in the shell history.

1. Set the following environment variables:

```
export RPC_URL=<chain-rpc-url>
export PRIVATE_KEY=<deploy-wallet-private-key>
export BLOCKCHAIN_EXPLORER_API_KEY=<blockchain-explorer-api-key>
```

2. Confirm that the variables `tychoRouter`, `uniswapXReactor` and `nativeToken` are correctly set in the script. Make sure that the Uniswap X Reactor address matches the reactor you are targeting.
3. Run `npx hardhat run scripts/deploy-uniswap-x-filler.js --network NETWORK`.

</details>

For more on filling Uniswap X orders, see their [docs](https://docs.uniswap.org/contracts/uniswapx/guides/mainnet/createfiller) and [examples](https://github.com/marktoda/uniswapx-artemis).

## Other competition venues

For other venues, like 1inch Fusion, please contact us.
