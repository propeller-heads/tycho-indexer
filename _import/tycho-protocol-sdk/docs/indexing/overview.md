# Overview

This page gives an overview over the data model required to ingest protocol state into the PropellerHeads solver.&#x20;

To integrate a protocol PropellerHeads rely on either native or vm logic. Most integration will likely choose to use the VM, as this is usually less effort, the guide will focus mostly on providing state for vm integrations.&#x20;

Native integration should operate following exactly the same pattern, just that they should emit changed attributes instead of changes contract storage slots.&#x20;

### Understanding the Data Model

PropellerHeads ingest all data versioned by block and transaction. This helps maintain a low latency feed and deal correctly with chains that can experience reverts.

This means each state change that is communicated must be communicated with its respective transaction that caused the change.

Next, for each emitted transactions that carries state changes, the corresponding block must be provided as well.

So basically when processing a block we need to emit the block itself, all transactions that introduced protocol state changes and last but not least the state changes themselves, associated to their corresponding transaction.

**The data model that encodes changes, transaction and blocks in messages, can be found** [**here**](https://github.com/propeller-heads/propeller-protocol-lib/tree/main/proto/tycho/evm/v1)**.**&#x20;

#### Models

The models below are used for communication between Substreams and Tycho indexer, as well as between Substreams modules.

Our indexer expects to receive a `BlockChanges` output from your Substreams package.

{% @github-files/github-code-block url="https://github.com/propeller-heads/propeller-protocol-lib/blob/main/proto/tycho/evm/v1/common.proto" %}

Please be aware that changes need to be aggregated on the transaction level, it is considered an error to emit `BlockChanges` with duplicated transactions present in the `changes` attributes.

#### Integer Byte encoding

Many of the types above are variable length bytes. This allows for flexibility across blockchains but require agreeing on an informal interface, so later applications know how to interpret these bytes.

**Integers:** especially integers used to communicate balances, should always be encoded as unsigned big-endian integer. This is simply because balances serve multiple purposes within the system and need to be decoded in multiple location of the messages journey.

**Strings**: If you need to store strings, please use utf-8 encoding to store them as bytes.

**Attributes:** the value encoding for attributes is variable. It depends on the use case. Since the attributes are highly dynamic they are only used by the corresponding logic components, so the encoding can be tailored to the logic implementation: E.g. since Rust uses little endian one may choose to use little endian encoding for integers if the native logic module is written in Rust.

#### Special attribute names

Certain attribute names are reserved exclusively for specific purposes in our simulation process. Please use them only for their intended functions. See the [list of reserved attributes](./reserved-attributes.md)

### Changes of interest

PropellerHeads integrations should at least communicate the following changes:

- Any changes to the protocol state, for VM integrations that usually means contract storage changes of all contracts whose state may be accessed during a swap operation.
- Any newly added protocol component such as a pool, pair, market, etc. Basically anything that signifies that a new operation can be executed now using the protocol.
- ERC20 Balances, whenever the balances of one contracts involved with the protocol change, this change should be communicated in terms of absolute balances.

Please see the getting started page to see how to actually implement an integration.
