# Price Printer

This example allows you to list all pools over a certain tvl threshold and explore
quotes from each pool.

## How to run

```bash
export ETH_RPC_URL=<your-node-rpc-url>
cargo run --release --example price_printer -- --tvl-threshold 1000 --chain <ethereum | base>
```
