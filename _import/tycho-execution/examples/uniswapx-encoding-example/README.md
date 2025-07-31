# UniswapX Encoding Example

This guide enables you to:

1. Create a Solution object
2. Create callback data for executing a UniswapX Order

Note: This guide only encodes the callback data for you. You will still have to encode the call to the
`execute` method of the filler, which also includes the encoded UniswapX order.

## How to run

```bash
cargo run --release --example uniswapx-encoding-example
```