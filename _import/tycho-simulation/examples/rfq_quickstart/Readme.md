# RFQ QuickStart with Bebop

This quickstart guide enables you to:

1. Connect to the Bebop RFQ WebSocket stream for real-time pricing data.
2. Leverage Tycho Simulation to get the best quoted prices from Bebop's market makers.
3. Compare Bebop RFQ quotes with traditional AMM pools (for educational purposes).

## How to run

You need to set up Bebop WebSocket credentials to access live pricing data:

```bash
export BEBOP_WS_USER=<your-bebop-ws-username>
export BEBOP_WS_KEY=<your-bebop-ws-key>
cargo run --release --example rfq_quickstart
```

By default, the example will request quotes for 10 USDC -> WETH on Ethereum Mainnet from Bebop's market makers.

If you want a different trade or chain, you can do:

```bash
export BEBOP_WS_USER=<your-bebop-ws-username>
export BEBOP_WS_KEY=<your-bebop-ws-key>
cargo run --release --example rfq_quickstart -- --sell-token "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" --buy-token "0x4200000000000000000000000000000000000006" --sell-amount 10 --chain "base"
```

for 10 USDC -> WETH on Base.

## Important Notes

- **Credentials**: Contact Bebop to obtain WebSocket API credentials for accessing live market maker quotes

## What you'll see

The example will:
1. Connect to Bebop's WebSocket API using your credentials
2. Stream live price quotes from market makers for your specified token pair
3. Display the best available quotes with pricing information

See [here](https://docs.propellerheads.xyz/tycho/for-solvers/tycho-quickstart) a complete guide on how to run the
Quickstart example.