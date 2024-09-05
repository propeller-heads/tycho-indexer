# Tycho Indexer

![Asteroid Belt](./assets/belt.webp)

Low latency indexer for onchain and offchain financial protocols, Tycho allows clients to connect to a stream of delta
messages that describe state changes of the underlying financial protocols. It also provides an RPC to request
historical state at any given tick, timestamp, or block.

Clients do not have to be aware of forks. In case the underlying chain experiences a fork, Tycho will automatically
resolve the fork and emit events. These events allow the clients to "revert" (through usual updates) to the correct
state as quickly as possible.

Here's how a typical connection with Tycho works:

- Clients connect to Tycho's real-time delta messages and start buffering them.
- Next, they will request a historical state.
- Once the historical state has been fully retrieved, the buffered changes are applied on top of that state.
- Now the client possesses the latest state of all protocols it is interested in.
- New incoming messages can now be applied directly to the existing state.

With Tycho, clients stay updated with the latest state of **all** protocols they are interested in. If they can handle
all, they can get all.

## Supported implementations

Tycho supports two major types of protocol implementation strategies:

- **Custom Protocol implementations:** A custom struct is defined that represents the onchain state. Typically, this
  struct is more closely aligned with the state layout within smart contract languages, such as Solidity. State
  transitions have to be handled by processing events or method calls.
- **Virtual Machine (VM) implementations:** In this strategy, state representation aligns more closely with the
  underlying VM. For instance, we extract and update the storage and other attributes associated with a smart contract.
  This state is then passed to a VM instance for further functionality.

For both strategies, Tycho ensures seamless execution and integration with the overall system.

### Note

Each state allows annotation of TVL (Total Value Locked) and Inertias. These annotations help clients to filter down
protocol components that are of particular interest to them.

This means users can easily focus on the aspects of the protocol components relevant to their needs, enhancing usability
and efficiency.

## Protocol Systems and Components

Tycho extracts state for whole protocol systems including dynamically created protocol components. This means that
components like Uniswap pairs, which were not predetermined, are included in the indexing logic. They are automatically
added and indexed upon their creation/detection.

## Message types

To achieve the previously mentioned functionalities, Tycho uses the following message types:

- **EntityChange:** This message type is emitted for protocols that use a custom implementation. It describes how to
  change the attributes of an entity.
- **ContractChange:** This message type is emitted for protocols that use a VM (Virtual Machine) implementation. It
  contains changes to a contract's code, balances, and storage.
- **ComponentChange:** This message type is emitted whenever a new protocol component is added or removed. This allows
  clients to update their state as required.

# Development

## Getting started

You will need to have rust, rustup, docker and docker-compose installed before getting started.

### Substreams

1. Install [substreams-cli](https://thegraph.com/docs/en/substreams/getting-started/installing-the-cli/)
2. Retrieve an API key from https://app.streamingfast.io/
3. Set the api key as described below:

```bash
export STREAMINGFAST_KEY=server_123123 # Use your own API key
export SUBSTREAMS_API_TOKEN=$(curl https://auth.streamingfast.io/v1/auth/issue -s --data-binary '{"api_key":"'$STREAMINGFAST_KEY'"}' | jq -r .token)
```

4. Substreams compiles to wasm, so you need the corresponding toolchain:

```bash
rustup target add wasm32-unknown-unknown
```

5. To compile protobuf files please install [buf](https://docs.buf.build/installation). To generate protobuf definition
   for a substream crate:

```bash
cd substreams/ethereum-ambient
substreams protogen substreams.yaml --exclude-paths="sf/substreams,google"
cd ../..
```

6. To compile the substreams into a spkgs, run the build script:

```bash
./stable-build.sh
```

or alternatively:

```bash
cargo build --package substreams-ethereum-ambient --target wasm32-unknown-unknown --profile substreams
substreams pack substreams/ethereum-ambient/substreams.yaml
```

7. Run `tycho-indexer` locally using cli:

We currently support 4 commands:

- `index` : Run every extractor set in `./extractors.yaml`
- `run` : Run a single extractor
- `analyze-tokens` : Run token analyzer cronjob
- `rpc` : Run only the http rpc server

Each command can be used with the following:

```bash
RUST_LOG=info cargo run --bin tycho-indexer -- \
    {your-command}
```

For more informations about flags can run

```bash
RUST_LOG=info cargo run --bin tycho-indexer -- \
    {your-command} --help
```

#### Quickly run a spkg from our repository:

Sometimes it is useful to quickly debug the messages from a production spkgs. The command
below will create a presigned url for the spkgs on the fly so it can be fetched by the
substreams cli:

```
substreams gui $(./signed_spkg_url.sh ethereum-uniswap-v3/ethereum-uniswap-v3-v0.1.0.spkg) map_pool_events --start-block 19459803
```

The `substreams-api-token` and `database-url` default to their respective environment variables. You can also specify
them as command line arguments. More info about tycho cli:

```bash
$ cargo run -- --help
Tycho Indexer using Substreams

Extracts state from the Ethereum blockchain and stores it in a Postgres database.

Usage: tycho-indexer [OPTIONS] --endpoint <endpoint> --substreams-api-token <SUBSTREAMS_API_TOKEN> --database-url <DATABASE_URL> --spkg <SPKG> --module <MODULE>

Options:
      --endpoint <endpoint>
          Substreams API endpoint URL

      --substreams-api-token <SUBSTREAMS_API_TOKEN>
          Substreams API token

          Defaults to SUBSTREAMS_API_TOKEN env var.

          [env: SUBSTREAMS_API_TOKEN]

      --database-url <DATABASE_URL>
          DB Connection Url

          Defaults to DATABASE_URL env var.

          [env: DATABASE_URL]

      --spkg <SPKG>
          Substreams Package file

      --module <MODULE>
          Substreams Module name

      --start-block <START_BLOCK>
          Substreams start block

          [default: 17361664]

      --stop-block <STOP_BLOCK>
          Substreams stop block

          If prefixed with a `+` the value is interpreted as an increment to the start block.

          [default: 17362664]

      --rpc-url <RPC_URL>
          Blockchain RPC Connection Url.

          Defaults to RPC_URL env var.

          [env: RPC_URL]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

### Protobuf

We use protobuf mainly to communicate with substreams. You can use
the [language support extension](https://marketplace.visualstudio.com/items?itemName=pbkit.vscode-pbkit) and for
formatting use the [buf extension for VS Code](https://marketplace.visualstudio.com/items?itemName=bufbuild.vscode-buf).

1. To communicate with substreams, we always want to use their latest protobuf images. Usually the sf module is already
   committed but in case there was an update we can pull the latest version into the repo with:

```
buf export buf.build/streamingfast/substreams -o ./proto
```

2. Now that we have all our protobuf modules together we can generate the respective Rust code for them:

```
buf generate
```

3. This will update the autogenerated files in `tycho-indexer/src/pb`. Our substream package also needs to be updated.
   Copy the new `tycho.evm.v1.rs` file to the `src/pb/` directory of each substream in the substreams package.

##### Protobuf Linting

1. To install the linter execute:

```
brew install bufbuild/buf/buf@1.28.1
```

2. Linting the files works like:

```
buf lint
```

It will return a list of errors that you need to fix. If not, then all the changes you made conform to the linter.

### Local development

1. Please also make sure that the following commands pass if you have changed the code:

```sh
# alternatively use ./check.sh
cargo check --all
cargo nextest run --workspace --all-targets --all-features -E 'not test(serial_db)'
cargo nextest run --workspace --all-targets --all-features -E 'test(serial_db)'
cargo +nightly fmt -- --check
cargo +nightly clippy --all --all-features --all-targets -- -D warnings
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

# Architecture

The logical diagram below illustrates the architecture of the system. Each component will be discussed individually:

[![Logical Architecture Diagram](./assets/logical.drawio.png)](https://drive.google.com/file/d/1mhbARX2ipAh-YUDfm4gPN3Is4sLvyJxM/view?usp=sharing)

## Substreams

For on-chain data sources, Tycho utilizes [substreams](https://thegraph.com/docs/en/substreams/README/). With
substreams, information can be quickly retrieved from (historical) blocks using Rust handlers that execute in parallel
over a specified block range. Events are then emitted in a linear fashion. Once a substream has caught up with the
current state of the underlying chain, it switches into a low latency mode, continuing to emit the same events for each
new block.

Substream handlers, which extract the actual information for each block are implemented in Rust, compiled to WebAssembly
and sent to a Firehose node where execution takes place near the data. Handlers emit messages that are streamed back to
the client.

A very early example of how a substream package is implemented can be seen [here](./substreams/ethereum-ambient/). In
this example all storage changes for the Ambient protocol are extracted.

## Extractors

Extractors are tasked with archiving states and providing normalized change streams: They receive fork-aware messages
from substreams and must apply these to the current state. If necessary, they create a corresponding delta message and
then immediately forward it to any subscriptions.

As stateful components, extractors manage protocol components, protocol state, its history, and archive messages they
have emitted. In addition, they need to remember where they stopped processing the substream. This is typically achieved
by saving a cursor. When passed to a substream, the cursor instructs the stream to continue to emit events from
precisely the point where it left off, guaranteeing consistent state.

### Note

Tycho runs each extractor in a separate thread. Therefore, it's anticipated that multiple extractors may run
concurrently within a single process. To avoid increasing system latency, extractors should not engage in heavy
processing if it can be avoided.

## Service

Last but not least, the service manages real-time subscriptions to extractors and handles requests from RPC clients for
historical data.

In future iterations, the service might be enhanced with the capability to stream historical events. This feature would
enable complex backtesting use cases.

## DB

Tycho is an indexer designed to process and store data, necessitating the saving of state. Currently, it supports
Postgres as a storage backend. Below is the Entity Relationship (ER) diagram illustrating the tables planned for this
project:

[![Entity Relation Diagram](./assets/er.drawio.png)](https://drive.google.com/file/d/1mhbARX2ipAh-YUDfm4gPN3Is4sLvyJxM/view?usp=sharing)

### Note

This ER diagram includes only the most significant attributes for each entity. Triggers support much of the versioning
logic. For precise details, please ensure to look at the actual [create.sql](./migrations_/create.sql) file.

# Other Chains

Before moving to other chains the following things should be taken care of:

- Correctly implement ChainState struct to return the latest block by querying the chains rpc.
- Potentially fix assumption about fixed block times in the `tycho_client::feed`.
