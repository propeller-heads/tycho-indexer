# Native Token Handling (Wrapping & Unwrapping)

The encoder automatically bridges ETH↔WETH gaps anywhere in the swap path — at the start, end, or between swaps — using a dedicated WETH executor. Set `token_in` and `token_out` to the tokens the user actually holds and expects to receive, and the encoder inserts wrap/unwrap steps as needed.

This works with protocols like Uniswap V4 that accept native ETH directly, with no extra configuration required.
