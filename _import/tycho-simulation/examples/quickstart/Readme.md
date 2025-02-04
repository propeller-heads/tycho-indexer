# QuickStart

This quickstart guide enables you to:

1. Retrieve data from the Tycho Indexer.
2. Leverage Tycho Simulation to get the best amount out of a trade.

## How to run

```bash
export RPC_URL=<your-eth-rpc-url>
cargo run --release --example quickstart
```

By default, the example will trade 1 WETH -> USDC. If you want a different trade you can do:

```bash
cargo run --release --example quickstart -- --sell-token "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" --buy-token "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599" --sell-amount 10000
```

for 10000 USDC -> WBTC.

See [here](https://docs.propellerheads.xyz/tycho/for-solvers/tycho-quickstart) a complete guide on how to run the
Quickstart example.