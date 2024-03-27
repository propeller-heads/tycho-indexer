# Substreams Integration

This page describes the data model required to ingest protocol state into the PropellerHeads solver.&#x20;

To integrate a protocol PropellerHeads rely on either native or vm logic. Most integration will likely choose to use the VM, as this is usually less effort, the guide will focus mostly on providing state for vm integrations.&#x20;

Native integration should operate following exactly the same pattern, just that they should emit changed attributes instead of changes contract storage slots.&#x20;

### Understanding the Data Model

PropellerHeads ingest all data versioned by block and transaction. This helps maintain a low latency feed and deal correctly with chains that can experience reverts.

This means each state change that is communicated must be communicated with its respective transaction that caused the change.

Next, for each emitted transactions that carries state changes, the corresponding block must be provided as well.

So basically when processing a block we need to emit the block itself, all transactions that introduced protocol state changes and last but not least the state changes themselves, associated to their corresponding transaction.

**The data model that encodes changes, transaction and blocks in messages, can be found** [**here**](https://github.com/propeller-heads/propeller-protocol-lib/tree/main/proto/tycho/evm/v1)**.**&#x20;

#### Common Models

The following models are shared for both vm and native integrations.

{% @github-files/github-code-block url="https://github.com/propeller-heads/propeller-protocol-lib/blob/main/proto/tycho/evm/v1/common.proto" %}

#### VM Specific Models

The models shown below are specific to vm integrations:

{% @github-files/github-code-block url="https://github.com/propeller-heads/propeller-protocol-lib/blob/main/proto/tycho/evm/v1/vm.proto" %}

Please be aware that changes need to be aggregated on the transaction level, it is considered an error to emit `BlockContractChanges` with duplicated transactions present in the `changes` attributes.

All attributes are expected to be set in the final message unless the docs (in the comments) indicate otherwise.

#### Native Integration Models

The models below are very similar to the vm integration models but have a few modifications necessary to support native integrations.

{% @github-files/github-code-block url="https://github.com/propeller-heads/propeller-protocol-lib/blob/main/proto/tycho/evm/v1/entity.proto" %}

Once again changes must be aggregated on a transaction level, emitting these models with duplicated transaction as the final output would be considered an error.

#### Integer Byte encoding

Many of the types above are variable length bytes. This allows for flexibility across blockchains but require agreeing on an informal interface, so later applications know how to interpret these bytes.

**Integers:** especially integers used to communicate balances, should always be encoded as unsigned big-endian integer. This is simply because balances serve multiple purposes within the system and need to be decoded in multiple location of the messages journey.

**Strings**: If you need to store strings, please use utf-8 encoding to store them as bytes.

**Attributes:** the value encoding for attributes in the native implementation messages is variable. It depends on the use case. Since the attributes are highly dynamic they are only used by the corresponding logic components, so the encoding can be tailored to the logic implementation: E.g. since Rust uses little endian one may choose to use little endian encoding for integers if the native logic module is written in Rust.



### Changes of interest

PropellerHeads integration should at least communicate the following changes:

* Any changes to the protocol state, for VM integrations that usually means contract storage changes of all contracts whose state may be accessed during a swap operation.
* Any newly added protocol component such as a pool, pair, market, etc. Basically anything that signifies that a new operation can be executed now using the protocol.
* ERC20 Balances, whenever the balances of one contracts involved with the protocol change, this change should be communicated in terms of absolute balances.

In the next section we will show a few common techniques that can be leveraged to quickly implement an integration.

### How to Integrate

Before starting, it is important to be aware of the protocol we are aiming to integrate functions.

It is especially important to know:

* Which contracts are involved in the protocol and what functions do they serve. How do they affect the behaviour of the component being integrated?
* What conditions (e.g. oracle update) or what kind of method calls can lead to a relevant state change on the protocol, which ultimately changes the protocols behaviour if observed externally.
* Are there components added or removed, and how are they added. Most protocols use either a factory contract, which can be used to deploy new components, or they use a method call that provisiona a new component within the overall system.

Once the workings of the protocol are clear the implementation can start.

#### Setup

PropellerHeads indexing integrations are provided as [substreams](https://substreams.streamingfast.io/) skpg files. If you do not know substreams yet, make sure to go check them out and set up their [cli](https://substreams.streamingfast.io/documentation/consume/installing-the-cli) before continuing.

Please start a new package for your integration, by copying the `ethereum-template` to a new name. The convention is: `[CHAIN]-[PROTOCOL_SYSTEM]` please make sure to also adjust: `cargo.toml` as well as `substreams.yaml` accordingly.

It should be possible now to generate the necessary protobuf code:

```
substreams protogen substreams.yaml --exclude-paths="sf/substreams,google"
```

You are ready to start coding. Please refer to the substreams documentation for more information on the available tools such as handlers and stores.

#### Tracking Components

Usually the first step consists in detecting the creation of new components and store their contract addresses in a store, so they can be properly tracked further downstream.

Later we'll have to emit balance and state changes based on the set of  currently tracked components.

{% hint style="info" %}
Note that emitting state changes of components that have not been previously announced  is considered an error.
{% endhint %}

Newly created components are detected by mapping over the `sf.ethereum.type.v2.Block model`.&#x20;

The output message should usually contain as much information about the component available at that time as well as the transaction that created the protocol component.

We have found that using the final model prefilled with only component changes is usually good enough since it holds all the information that will be necessary at the end.&#x20;

For VM Integrations the final model is `BlockContractChanges`:

```protobuf
// A set of changes aggregated by transaction.
message TransactionContractChanges {
  // The transaction instance that results in the changes.
  Transaction tx = 1;
  // Contains the changes induced by the above transaction, aggregated on a per-contract basis.
  // Must include changes to every contract that is tracked by all ProtocolComponents.
  repeated ContractChange contract_changes = 2;
  // An array of any component changes.
  repeated ProtocolComponent component_changes = 3;
  // An array of balance changes to components.
  repeated BalanceChange balance_changes = 4;
}

// A set of transaction changes within a single block.
message BlockContractChanges {
  // The block for which these changes are collectively computed.
  Block block = 1;
  // The set of transaction changes observed in the specified block.
  repeated TransactionContractChanges changes = 2;
}
```

Note that a single transaction may emit multiple newly created components. In this case it is expected that the `TransactionContractChanges.component_changes`, contains multiple `ProtocolComponents`.

Once emitted, the protocol components should be stored in a Store, since we will later have to use this store to decide whether a contract is interesting to us or not.

#### Tracking Absolute Balances

Tracking balances can be tricky since often balance information is only available in relative values.&#x20;

This means the relative values have to be aggregated by component, to arrive at an absolute value. Additionally throughout this aggregation we need to track the balance change inducing transaction.

Since this is challenging the following approach is recommended:

* Use a handler to process a block and emit the `BalanceDeltas` struct. Make sure to sort the balance deltas by `component_id, token_address`
* Aggregate the BalanceDelta messages using a `BigIntAddStore`.
* In a final handler, use as inputs: A `DeltaStore` input from step 2 and the `BalanceDeltas` from step 1. You can now zip the deltas from the store with the balance deltas from step 1. The store deltas contains the aggregated (absolute) balance at each version and the balance deltas contain the corresponding transaction.

#### Tracking State Changes

To track contract changes, you can simply use the `extract_contract_changes` function (see balancer implementation). This function will extract all relevant contract storage changes given the full block model and a store that flags contract addresses as relevant.

