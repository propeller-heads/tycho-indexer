# Protocol Integration

[Tycho Protocol SDK ](https://github.com/propeller-heads/tycho-protocol-sdk)is a library to integrate liquidity layer protocols (DEXs, Staking, Lending etc.) into Tycho.

## Integration Process

Integrating with Tycho requires three components:

1. **Indexing**: Provide the protocol state/data needed for simulation and execution
2. **Simulation:** Implement the protocol's logic for simulations
3. **Execution**: Define how to encode and execute swaps against your protocol

A comprehensive testing suite is provided to ensure the above are correctly integrated. A passing test suite is essential for an integration to be considered complete.

### Indexing

Provide a [substreams](https://substreams.streamingfast.io/) package that emits a specified set of messages. If your protocol already has a [substreams package](https://github.com/messari/substreams), you can adjust it to emit the required messages.

Important: Simulation happens entirely off-chain. This means everything needed during simulation must be explicitly indexed.

### Simulation

Tycho offers two integration modes:

* **VM Integration:** Implement an adapter interface in a language that compiles to VM bytecode. This SDK provides a Solidity interface ([**read more here**](simulation/ethereum-solidity.md)**).** Simulations run in an empty VM loaded only with the indexed contracts, storage and token balances.&#x20;
* **Native Rust Integration:** Implement a Rust trait that defines the protocol logic. Values used in this logic must be indexed as state attributes.

### Execution

To enable swap execution, implement:

1. **SwapEncoder**: A Rust struct that formats input/output tokens, pool addresses, and other parameters correctly for the `Executor` contract.
2. **Executor**: A Solidity contract that handles the execution of swaps over your protocol's liquidity pools.&#x20;

## Integration Criteria

Tycho supports many protocol designs, however certain architectures present indexing challenges.

Before integrating, consider these unsupported designs:

* Protocols where any operation that Tycho should support requires off-chain data, such as signed prices.
