# Dynamic Contract Indexing (DCI)

Substreams relies on witnessing contract creations to provide a contract's entire storage. Unless the system witnesses the creation and identifies at that point that the contract is relevant to the protocol, it cannot be indexed or used in simulations.

The Dynamic Contract Indexing (DCI) system is a Tycho feature that addresses this limitation by dynamically identifying and indexing dependency contracts - such as oracles and price feeds - whose creation events are not observable. This may be because:

* the contracts were created long before the protocol's first indexed block (`startBlock` on the substreams configuration file)
* the dependency is updatable and which contracts are called may change during the protocol's lifetime. For example: a protocol switches oracle provider.

Using predefined tracing information (known as entry points), Tycho's DCI assumes responsibility for these edge cases, with Substreams supplying only the core subset of the data for simulation.

### Understanding Entry Points

DCI relies on the substreams package to supply tracing information for it to analyse and detect dependency contracts. It is important to understand the protocol being integrated and know where it might make external calls during simulations (swaps, price etc). These external calls need to be able to be defined fully by the combination of 'Entry Points' and 'Tracing Parameters'. See [limitations](./#motivation-1) below for more information on what is not covered by the current DCI implementation.

When an entry point is traced, all subsequent calls to other external contracts are automatically traced. Only the initial entry point needs to be supplied.

#### Entry Point

An entry point defines an external call in very simple terms:

* **address** of the contract called
* **signature** of the function called on that contract

#### Tracing Parameters

This defines how the entry point should be analysed and provides extra data needed for that analysis. Currently only one approach is supported:

*   **RPC Trace**

    This uses an RPC to simulate the defined external call (entry point) using sample call data. The sample data/parameters that can be defined for this trace include: **caller** and **call data**.\
    Any new contracts detected by these traces are fetched at the current block—both code and relevant storage—using an RPC as well. Once the contract is known, further updates are extracted by the DCI from the substream message's block storage\_changes (see implementation step 2 below).\
    Note: This approach may cause a temporary indexing delay whenever a new trace is conducted: ie. when new entry points or new tracing parameters are added. The delay depends on the complexity/depth of the trace.

### Retracing

A retrace of an entry point occurs in one of two situations:

1. New trace parameters are added to the entry point.
2. A retrigger is triggered. Retriggers are storage slots automatically flagged by the DCI for their potential to influence a trace result. Every time one those identified storage slots are updated, the trace is redone.

### Implementation Steps <a href="#motivation" id="motivation"></a>

To use the DCI system, you will need to extend your substream package to emit the following:

#### 1. Data to perform a trace <a href="#motivation" id="motivation"></a>

For successful tracing we need to define:\
\- An '**Entry Point'** for each call made to an external contract during a simulation action (swap, price calculation, etc.).\
\- **Tracing parameters** for the entry point. For every entry point defined, at least 1 set of tracing parameters must be supplied.\
\
It is vital that every component that uses an entry point is explicitly linked to that entry point.\
\
Some useful helper functions are provided to facilitate building the entry point messages:

*   To create a new entry point, use: `tycho_substreams::entrypoint::create_entrypoint`. Add the returned entry point and entry point parameter messages to the `TransactionChangesBuilder` using `add_entrypoint` and `add_entrypoint_params` respectively. They should be added to the transaction builder for the transaction the linked component was created.

    ```rust
    use tycho_substreams::entrypoint::create_entrypoint;

    // defined example trace data
    let trace_data = TraceData::Rpc(RpcTraceData{
        caller: None, // None means a default caller will be used
        calldata: "0xabcd123400000000000012345678901234567890", // 0xabcd1234 - function selector, 00000000000012345678901234567890 - input address
    });

    let entrypoint, entrypoint_params = create_entrypoint(
        target: target_address,
        signature: "getFees(fromAddress)",
        component_id: "pool_id",
        trace_data,
    )

    // use the TransactionChangesBuilder for the tx where component [pool_id] was created
    builder.add_entrypoint(&entrypoint);
    builder.add_entrypoint_params(&entrypoint_params);
    ```

#### **2. All contract changes that occurred on the current block** <a href="#motivation" id="motivation"></a>

The `tycho_substreams::block_storage::get_block_storage_changes` helper function simplifies this process by collecting all relevant changes for you. These changes need to be added to the `storage_changes` field of the final `BlockChanges` message emitted by the substream package.

```rust
use tycho_substreams::block_storage::get_block_storage_changes;

let block_storage_changes = get_block_storage_changes(&block);

...

Ok(BlockChanges {
    block: Some((&block).into()),
    ...
    storage_changes: block_storage_changes,
})
```

This will be used by the DCI to extract and index contract storage updates for all contracts it identifies.

### Limitations <a href="#motivation" id="motivation"></a>

DCI is currently limited to only support cases that can be covered by explicitly defined example trace parameters (i,e callers and call data). This means it cannot cover:

* Arbitrary call data: the automatic generation of call data, or fuzzing, is not supported. For example, external calls that take swap amounts as input - example amounts will not be auto generated and must be explicitly supplied as a Tracing Parameter.
* External signatures: calls that require externally created signatures (like Permit2 signatures). DCI cannot automatically generate valid cryptographic signatures and therefore can only support cases where a valid signature can be defined as a Tracing Parameter.
* Call data from external sources: input parameters that need to be fetched or derived from a separate trace are not supported. Only call data available within the Substreams package context can be processed.

### Frequently Asked Questions <a href="#motivation" id="motivation"></a>

**Q: Is it okay to redefine the same entry point multiple times?**\
A: _Yes. Tycho will deduplicate entry points, allowing you to add the same entry point for every new component without needing to track which ones already exist. Using storage on a substreams module affects the performance of the module so should be avoided where possible._
