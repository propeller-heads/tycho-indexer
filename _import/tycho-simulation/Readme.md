# Tycho Simulation

![Tycho Simulation](./assets/tycho-simulation.png)

Moves slow on-chain computations off-chain to solve optimization problems.

This crate allows simulating a set of supported protocols off-chain. Currently, it has a focus on token exchange
protocols, but it is not necessarily limited to this.
To get started, see our Quickstart guide [here](./examples/quickstart/Readme.md).

> **See also:**
> The `evm` module allows for simulating _any_ transaction; it is agnostic to protocol. See module's
> documentation.

## Currently supported protocols:

- Uniswap V2 and Forks
- Uniswap V3
- VM enabled protocols: Balancer V2 and Curve

## Adding a new Protocol

To add a new protocol, you will need to complete the following high-level steps:

#### Native protocol:

1. Create a protocol state struct that implements the `ProtocolSim` trait.
2. Create a tycho decoder for the protocol state: i.e. implement `TryFrom` for `ComponentWithState` to your new
   protocol state.

Each native protocol should have its own module under `tycho-simulation/src/protocol`.

#### VM protocol:

1. Add the associated adapter runtime file to `tycho-simulations/src/protocol/assets`. In
   `evm/protocol/vm/constants.rs`, load the file as a bytes constant and add a corresponding entry
   to `get_adapter_file()`.

### 1\. Adding state & behaviour

Simply implement a struct that contains the state of the protocol. Only the attributes that are necessary to fulfill
the `ProtocolSim` trait are required. Then, implement the `ProtocolSim` trait (in `src/protocol/state.rs`).

### Local development

1. Please also make sure that the following commands pass if you have changed the code:

```sh
cargo check --all
cargo test --all --all-features
cargo +nightly fmt -- --check
cargo +nightly clippy --workspace --all-features --all-targets -- -D warnings
```

We are using the stable toolchain for building and testing, but the nightly toolchain for formatting and linting, as it
allows us to use the latest features of rustfmt and clippy.

If you are working in VSCode, we recommend you install the [rust-analyzer](https://rust-analyzer.github.io/) extension,
and use the following VSCode user settings:

```json
"editor.formatOnSave": true,
"rust-analyzer.rustfmt.extraArgs": ["+nightly"],
"rust-analyzer.check.overrideCommand": [
"cargo",
"+nightly",
"clippy",
"--workspace",
"--all-features",
"--all-targets",
"--message-format=json"
],
"[rust]": {
"editor.defaultFormatter": "rust-lang.rust-analyzer"
}
```
