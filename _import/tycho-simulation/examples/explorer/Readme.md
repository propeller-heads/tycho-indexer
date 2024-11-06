# Price Printer

This example allows you to list all pools over a certain tvl threshold and explore 
quotes from each pool.


## How to run

```bash
export TYCHO_API_TOKEN=sampletoken
RUST_LOG=info cargo run --example explorer -- --tvl-threshold 1000
```