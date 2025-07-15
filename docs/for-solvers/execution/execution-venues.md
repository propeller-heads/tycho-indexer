---
description: How to integrate Tycho in different execution venues.
---

# Execution Venues

## Cow Protocol

To solve orders on [CoW Protocol](https://docs.cow.fi/cow-protocol/tutorials/solvers), you'll need to prepare your solution following specific formatting requirements.

First, initialize the encoder:

```rust
let encoder = TychoRouterEncoderBuilder::new()
    .chain(Chain::Ethereum)
    .build()
    .expect("Failed to build encoder");
```

Since you are not passing the `swapper_pk`, the `TychoRouter` will use a `transferFrom` to transfer the token in as opposed to using permit2.

When solving for CoW Protocol, you need to return a [Solution object](https://docs.cow.fi/cow-protocol/reference/core/auctions/schema#solutions-output) that contains a list of interactions to be executed in sequence.

To solve with the Tycho Router you only need one custom interaction where:

1. `callData` is the full encoded method calldata using the encoded solution returned from `encoder.encode_solutions(...)`&#x20;
2. `allowances` is a list with one entry where the allowance for the token in and amount in is set for spender to be the Tycho Router. This is necessary for the `transferFrom` to work.

## Other competition venues

For other venues, like UniswapX or 1inch Fusion, please contact us.
