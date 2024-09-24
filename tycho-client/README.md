# Tycho Client

Tycho Client is the main consumer-facing component of the Tycho indexing system. This guide covers the CLI application, although all functionality is also available as a Rust library.

## Installation

### Using the Installation Script

An installation script is provided for convenience. It optionally accepts a version argument; if not provided, the latest available version (ignoring pre releases) will be installed. The script will automatically detect your operating system and architecture, download the appropriate binary, unpack it, and move it to a directory in your PATH.

To install Tycho Client using the script:

```bash
./get-tycho.sh [VERSION]
```
- VERSION: The specific version you want to install (e.g., `0.9.2`). If omitted, the script will install the latest available version.

Note: The script requires a writable directory in your PATH to install the binary. It will check the following directories for write permissions:

- `/usr/local/bin`
- `/usr/bin`
- `/bin`
- `$HOME/bin`

If none of these directories are writable, you may need to create one or modify the permissions of an existing directory.

### Manual Installation

Alternatively, you can manually download the correct binary from the [latest release](https://github.com/propeller-heads/tycho-indexer/releases) on GitHub.

Once you have downloaded the binary, follow these steps to install it:

1. Unpack the tarball:
```bash
tar -xvzf tycho-client-aarch64-apple-darwin-{VERSION}.tar.gz
```
2. Bypass macOS quarantine (macOS users only):
```bash
xattr -d com.apple.quarantine tycho-client || true
```
3. Move the binary to a directory in your PATH:
```bash
mv tycho-client /usr/local/bin/
```

### Verify Installation

After installing, you can verify that the client is available from your command line:

```bash
tycho-client -V
```

This should display the version of the Tycho client installed.

## Quickstart

To use the Tycho Client, you will need a connection to the Tycho Indexer. Once you have a connection to an indexer instance, you can simply create a stream using:

```
tycho-client \
    --exchange uniswap_v2 \
    --exchange uniswap_v3 \
    --exchange vm:ambient \
    --exchange vm:balancer \
    --min-tvl 100
    --tycho-rpc-url {TYCHO_INDEXER_RPC_URL}
    --tycho-ws-url {TYCHO_INDEXER_WS_URL}
```
 - TYCHO_INDEXER_URL defaults to `localhost:4242`

## Usage

The main use case of the Tycho Client is to provide a stream of protocol components,
snapshots, their state changes and associated tokens.

If you choose to stream from multiple extractors, the client will try to align the
messages by their block. You can use the `--block-time` parameter to fine tune this behaviour. This is the maximum time we will wait for another extractor before emitting a message. If any other extractor has not replied within this time it is considered as delayed. If an extractor is marked as delayed for too long, it is considered stale and the client will exit with an error message.

Note: *We do currently not provide support to stream from different chains.*

### State tracking

Tycho Client provides automatic state tracking. This is done using two core models: snapshots and deltas.

The client will first query Tycho Indexer for all components that match the filter
criteria. Once received, a full snapshot of the state of these components is requested, which the client will forward to the user. Thereafter, the client will collect and forward state changes (deltas) for all tracked components.

The delta messages will also include any new tokens that the client consumer has not
seen yet as well as a map of components that should be removed because the client
stopped tracking them.

#### Component Filtering

You can request individual pools, or use a minimum TVL threshold to filter the components. If you choose minimum TVL tracking, tycho-client will automatically add snapshots for any components that start passing the TVL threshold, e.g. because more liquidity was provided. It will also remove any components that fall below the TVL threshold.

##### To track a single pool:

```bash
tycho-client --exchange uniswap_v3-0x....
```

This will stream all relevant messages for this particular uniswap v3 pool.

##### To filter by TVL:
If you wish to track all pools with a minimum TVL (denominated in native token), you have 2 options:
  1) Set an exact tvl boundary:
```bash
tycho-client --min-tvl 100 --exchange uniswap_v3 --exchange uniswap_v2
```
This will stream updates for all components whose TVL exceeds the minimum threshold set. Note: if a pool fluctuates in tvl close to this boundary the client will emit a message to add/remove that pool every time it crosses that boundary. To mitegate this please use the ranged tvl boundary decribed below.

  2) Set a ranged TVL boundary:
```bash
tycho-client --remove-tvl-threshold 95 --add-tvl-threshold 100 --exchange uniswap_v3
```

This will stream state updates for all components whose TVL exceeds the add-tvl-threshold. It will continue to track already added components if they drop below the add-tvl-threshold, only emitting a message to remove them if they drop below remove-tvl-threshold.

### Message types

For each block, the tycho-client will emit a FeedMessage. Each message is emitted as a single JSON line to stdout.

#### FeedMessage

The main outer message type. It contains both the individual SynchronizerState (one per extractor) and the StateSyncMessage (also one per extractor). Each extractor is supposed to emit one message per block even if no changes happened in that block.

and metadata about the extractors block synchronisation state. The latter
allows consumers to handle delayed extractors gracefully. 

[Link to structs](https://github.com/propeller-heads/tycho-indexer/blob/main/tycho-client/src/feed/mod.rs#L305)

#### SynchronizerState

This struct contains metadata about the extractors block synchronisation state. It
allows consumers to handle delayed extractors gracefully. Extractors can have any of the following states:

- `Ready`: the extractor is in sync with the expected block
- `Advanced`: the extractor is ahead of the expected block
- `Delayed`: the extractor has fallen behind on recent blocks, but is still active and trying to catch up
- `Stale`: the extractor has made no progress for a significant amount of time and is flagged to be deactivated
- `Ended`: the synchronizer has ended, usually due to a termination or an error

[Link to structs](https://github.com/propeller-heads/tycho-indexer/blob/main/tycho-client/src/feed/mod.rs#L106)

#### StateSyncMessage

This struct, as the name states, serves to synchronize the state of any consumer to be up-to-date with the blockchain.

The attributes of this struct include the header (block information), snapshots, deltas and removed components. 

 - *Snapshots* are provided for any components that have NOT been observed yet by the client. A snapshot contains the entire state at the header.
 - Deltas contain state updates, observed after or at the snapshot. Any components
mentioned in the snapshots and in deltas within the same StateSynchronization message,
must have the deltas applied to their snapshot to arrive at a correct state for the
current header.
- Removed components is map of components that should be removed by consumers. Any components mentioned here will not appear in any further messages/updates.

[Link to structs](https://github.com/propeller-heads/tycho-indexer/blob/main/tycho-client/src/feed/synchronizer.rs#L80)

#### Snapshots

Snapshots are simple messages that contain the complete state of a component (ComponentWithState) along with the related contract data (ResponseAccount). Contract data is only emitted for protocols that require vm simulations, it is omitted for more simple protocols such as uniswap v2 etc.

[Link to structs](https://github.com/propeller-heads/tycho-indexer/blob/main/tycho-client/src/feed/synchronizer.rs#L63)

##### ComponentWithState

Tycho differentiates between *component* and *component state*.

The *component* itself is static: it describes, for example, which tokens are involved or how much fees are charged (if this value is static).

The *component state* is dynamic: it contains attributes that can change at any block, such as reserves, balances, etc.

[Link to structs](https://github.com/propeller-heads/tycho-indexer/blob/main/tycho-client/src/feed/synchronizer.rs#L57)

##### ResponseAccount

This contains all contract data needed to perform simulations. This includes the contract address, code, storage slots, native balance, etc.

[Link to structs](https://github.com/propeller-heads/tycho-indexer/blob/main/tycho-core/src/dto.rs#L569)

#### Deltas

Deltas contain only targeted changes to the component state. They are designed to be
lightweight and always contain absolute new values. They will never contain delta values so that clients have an easy time updating their internal state.

Deltas include the following few special attributes:

- `state_updates`: Includes attribute changes, given as a component to state key-value mapping, with keys being strings and values being bytes.
- `account_updates`: Includes contract storage changes given as a contract storage key-value mapping for each involved contract address. Here both keys and values are bytes.
- `new_protocol_components`: Components that were created on this block. Must not necessarily pass the tvl filter to appear here.
- `deleted_protocol_components`: Any components mentioned here have been removed from
  the protocol and are not available anymore.
- `new_tokens`: Token metadata of all newly created components.
- `component_balances`: Balances changes are emitted for every tracked protocol component.
- `component_tvl`: If there was a balance change in a tracked component, the new tvl for the component is emitted.

Note: exact byte encoding might differ depending on the protocol, but as a general guideline integers are big-endian encoded.

[Link to structs](https://github.com/propeller-heads/tycho-indexer/blob/main/tycho-core/src/dto.rs#L215)

## Debugging

Since all messages are sent directly to stdout in a single line, logs are saved to a
file: `./logs/dev_logs.log`. You can configure the directory with the `--log-dir` option.

### Tail Logs in Real Time:

```bash
tail -f ./logs/dev_logs.log
```

### Modify Log Verbosity:

```bash
RUST_LOG=tycho_client=trace tycho-client ...
```

### Improve Message Readability

To get a pretty printed representation of all messages emitted by tycho-client you can
stream the messages into a formatter tool such as `jq`:

```bash
tycho-client --exchange uniswap_v3 ... | jq
```

### Stream Messages to a File

For debugging, it is often useful to stream everything into files, both logs and
messages, then use your own tools to browse those files.

```bash
RUST_LOG=tycho_client=debug tycho-client ... --log-dir /logs/run01.log > messages.jsonl &
# To view the logs
tail -f logs/run01.log
# To view latest emitted messages pretty printed
tail -f -n0 message.jsonl | jq 
# To view and browse the 3rd message pretty printed
sed '3q;d' message.jsonl | jq | less
```

To only stream a preset amount of messages you can use the `-n` flag. This is useful to create a single snapshot for test fixtures:

```bash
tycho-client -n 1 --exchange uniswap_v3:0x.... > debug_usv3.json
```

If you wish to create an integration test, you can also stream multiple messages into a
[jsonl](https://jsonlines.org/) file:

```bash
tycho-client -n 100 --exchange uniswap_v3:0x....  > integration.jsonl
# or with compression
tycho-client -n 1000 --exchange uniswap_v3:0x....  | gzip -c - > 1kblocks.jsonl.gz
```

This file can then be used as mock input to an integration test or a benchmark script.

### Historical state

Tycho also provides access to historical snapshots. Unfortunately we do not have this
exposed on the tycho-client yet. If you need to retrieve the historical state of a
component you will have to use the RPC for this.

Tycho exposes an openapi docs for its RPC endpoints. If you are running tycho locally you can find them under: http://localhost:4242/docs/

## Light mode

For use cases that do not require snapshots or state updates, we provide a light mode.
In this mode tycho will not emit any snapshots or state updates, it will only emit
newly created component, associated tokens, tvl changes, balance changes and removed
components. This mode can be turned on via the `--no-state` flag.
