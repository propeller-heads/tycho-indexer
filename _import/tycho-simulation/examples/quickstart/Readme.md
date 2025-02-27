# QuickStart

This quickstart guide enables you to:

1. Retrieve data from the Tycho Indexer.
2. Leverage Tycho Simulation to get the best amount out of a trade.

## How to run

```bash
export ETH_RPC_URL=<your-eth-rpc-url>
cargo run --release --example quickstart
```

By default, the example will trade 1 WETH -> USDC. If you want a different trade you can do:

```bash
cargo run --release --example quickstart -- --sell-token "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" --buy-token "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" --sell-amount 10
```

for 10000 USDC -> WBTC.

To be able to execute or simulate the best swap, you need to pass your private key:

```bash
cargo run --release --example quickstart -- --swapper-pk <your-private-key>
```

See [here](https://docs.propellerheads.xyz/tycho/for-solvers/tycho-quickstart) a complete guide on how to run the
Quickstart example.