# Subtreams packages

This directory contains all substream packages that are used to index integrated protocols across different blockchains.

## Adding a new package

To add a new package add a folder. The naming convention is `[CHAIN]-[PROTOCOL_SYSTEM]`. 

### Manifest
In this new folder add a manifest file `substreams.yaml`. You can use the template below to get started:

```yaml
specVersion: v0.1.0
package:
  name: 'substreams_[CHAIN]_[PROTOCOL_SYSTEM]'
  version: v0.1.0

protobuf:
  files:
    - vm.proto
    - common.proto
    # You can specify any internal proto files here
  importPaths:
    - ../../proto/tycho/evm/v1/
    # Any private message types only used in internal modules 
    # can remain local to the folder.
    - ./proto

binaries:
  default:
    type: wasm/rust-v1
    # this points to the workspace target directory we use a special 
    # substreams build profile to optimise wasm binaries
    file: ../../target/wasm32-unknown-unknown/substreams/substreams_[CHAIN]_[PROTOCOL_SYSTEM].wasm

modules:
  - name: map_changes
    kind: map
    inputs:
      - source: sf.ethereum.type.v2.Block
    output:
      type: proto:tycho.evm.state.v1.BlockContractChanges
```

Substreams packages are Rust crates so we also need a `cargo.toml`.
The example from the official docs will serve us just well:

```toml
[package]
name = "substreams_[CHAIN]_[PROTOCOL_SYSTEM]"
version = "0.1.0"
edition = "2021"

[lib]
name = "substreams_[CHAIN]_[PROTOCOL_SYSTEM]"
crate-type = ["cdylib"]

[dependencies]
substreams = "0.5"
substreams-ethereum = "0.9"
prost = "0.11"

```

There are already some generated rust files in the `src/pb` directory. These are generated 
from the protobuf files in the `/proto/tycho/evm/v1` directory. They specify the output protobuf messages
we want to generate. The input Block is specified by the subtreams crate, specifically the [sf.ethereum.type.v2.Block](https://github.com/streamingfast/substreams-ethereum/blob/develop/core/src/pb/sf.ethereum.type.v2.rs) message.

You can define your own protobuf messages, make a new directory `/substreams/[CHAIN]-[PROTOCOL]/proto` for them.


Now we can generate the Rust protobuf code:

```
substreams protogen substreams.yaml --exclude-paths="sf/substreams,google"
```

The command above should put the generate rust files under `/src/pb`. You
can start using these now in your module handlers: See
the [official substreams documentation](https://thegraph.com/docs/en/substreams/getting-started/quickstart/#create-substreams-module-handlers)
on
how to implement module handlers.

You can also look into already existing substreams packages to see how it
is done. E.g. [ethereum-ambient](./ethereum-ambient/) provides a pretty good
example of how to get access to raw contract storage.

# Tests

To create a block test asset for ethereum do the following:

- Follow [this tutorial](https://substreams.streamingfast.io/tutorials/overview/map_block_meta_module). Make sure you
  set up the substreams-explorer repo in the same directory as this repo.
    - Comment out `image: ./ethereum.png` in `ethereum-explorer/substreams.yaml`
    - Add `prost-types = "0.11.0"` to `ethereum-explorer/Cargo.toml`
- Make sure you set up your key env vars.
- Run `sh scripts/download-ethereum-block-to-s3 BLOCK_NUMBER`

Do not commit the block files (they are quite big).