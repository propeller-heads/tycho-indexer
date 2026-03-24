# Native Token Handling (Wrapping & Unwrapping)

Wrapping and unwrapping use a dedicated WETH executor, the same mechanism as any other protocol swap. The encoding library automatically inserts WETH wrap/unwrap swaps wherever an ETH/WETH bridge is needed:

* At the start: if `token_in` is ETH but the first swap expects WETH, a wrapping swap is prepended.
* Between swaps: if one swap outputs ETH and the next expects WETH (or vice versa), a bridging swap is inserted.
* At the end: if the last swap outputs ETH but token\_out is WETH (or vice versa), an unwrapping swap is appended.

Set `token_in` and `token_out` to the actual tokens the user holds and expects to receive (native ETH or WETH), and the encoder handles the rest.

This approach supports wrapping/unwrapping at any position in the swap path (not just first and last) and works with protocols like Uniswap V4 that support native ETH swaps directly.
