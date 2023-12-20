# Subtreams packages

This directory contains all substream packages that are used by the extractors to access certain data from diffrent
blockchains.

## Adding a new package

To add a new package add folder. The naming convention is `[CHAIN]-[PROTOCOL_SYSTEM]`. In this new folder add a manifest
file `substreams.yaml`. You can use the template below to get started:

```yaml
specVersion: v0.1.0
package:
  name: 'substreams_[CHAIN]_[PROTOCOL_SYSTEM]'
  version: v0.1.0

protobuf:
  files:
    - vm.proto
    - common.proto
  importPaths:
    # This is different compared to the substreams example, 
    # we need to share protobuf definitions with tycho you 
    # are invited to reuse existing definitions if they are 
    # useful to you.
    - ../../proto/evm/v1
    # any private message types only used in internal modules 
    # can remain local to the crate.
    - ./proto

binaries:
  default:
    type: wasm/rust-v1
    # this points to the workspace target directory we use a special 
    # substreams build profile to optimise wasm binaries
    file: ../../target/wasm32-unknown-unknown/substreams/substreams_[CHAIN]_[PROTOCOL_SYSTEM].wasm

modules:
  # sample module provides access to blocks.
  - name: map_block
    kind: map
    inputs:
      - source: sf.ethereum.type.v2.Block
    output:
      type: proto:acme.block_meta.v1.BlockMeta
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