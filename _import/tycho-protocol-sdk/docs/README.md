# Propeller Protocol Lib

Protocol lib is a library used by Propellerheads.xyz solvers to integrate decentralized protocols. Currently, only swap/exchange protocols are supported.

## Integration Process

To integrate with PropellerHeads solvers, two components need to be provided:

* **Protocol logic:** Provides simulations of the protocols logic.
* **Indexing**: Provides access to the protocol state used by the simulation. This component is optional if your protocol is stateless.

To propose an integration, create a pull request in this repository with the above components implemented.

### Protocol Logic

PropellerHeads currently exposes two integration modes to specify the protocols' underlying logic:

* **VM Integration:** This integration type requires implementing an adapter interface in any language that compiles to the respective vm byte code. This SDK provides the interface only in Solidity. [**Read more here.**](logic/vm-integration/)
* **Native Rust Integration:** Coming soon, this integration type requires implementing a Rust trait that describes the protocol logic.

While VM integration is certainly the quickest and probably most accessible one for protocol developers, native implementations are much faster and allow us to consider the protocol for more time-sensitive use cases - e.g. quoting.

### Indexing

For indexing purposes, it is required that you provide a [substreams](https://substreams.streamingfast.io/) package that emits a specified set of messages. If your protocol already has a [substreams package](https://github.com/messari/substreams) for indexing implemented, you can adjust it to emit the required messages.

**VM Integration** Currently the only supported integration is for EVM protocols in order to complement the Solidity protocol logic. [**Read more here.**](https://github.com/propeller-heads/propeller-venue-lib/blob/main/docs/indexing/vm-integration/README.md) **Custom Entity Integration** Coming soon, this integration will complement the upcoming native Rust protocol logic.

### Execution

For execution purposes, the implementation of the `SwapExecutor` and `SwapStructEncoder` interfaces is required. Without these components, trades cannot be executed on-chain, making them critical parts of the integration.

**SwapExecutor**: The SwapExecutor is responsible for performing swaps by interacting with the underlying liquidity pools, handling token approvals, managing input/output amounts, and ensuring gas-efficient and secure execution. Each protocol must implement its own `SwapExecutor` (Solidity contract), tailored to its specific logic and requirements.

**SwapStructEncoder**: The `SwapStructEncoder` encodes the necessary data structures required for the `SwapExecutor` to perform swaps. It ensures that the swap details, including input/output tokens, pool addresses, and other protocol-specific parameters, are correctly formatted and encoded before being passed to the `SwapExecutor`. Each protocol must implement its own `SwapStructEncoder` Python class and ensure compatibility with its `SwapExecutor`.

