# Propeller Protocol Lib

Protocol lib is a library used by Propellerheads.xyz solvers to integrate decentralized protocols. Currently, only swap/exchange protocols are supported.

## Integration Process

To integrate with PropellerHeads solvers, two components need to be provided:

* **Protocol logic:** Provides simulations of the protocols logic.
* **Indexing**: Provides access to the protocol state used by the simulation. This component is optional if your protocol is stateless.

To propose an integration, create a pull request in this repository with the above components implemented.

### Protocol Logic

PropellerHeads currently exposes two integration modes to specify the protocols' underlying logic:

* **VM Integration:** This integration type requires implementing an adapter interface in any language that compiles to the respective vm byte code. This SDK provides the interface only in Solidity. **[Read more here.](logic/vm-integration/README.md)**
* **Native Rust Integration:** Coming soon, this integration type requires implementing a Rust trait that describes the protocol logic.

While VM integration is certainly the quickest and probably most accessible one for protocol developers, native implementations are much faster and allow us to consider the protocol for more time-sensitive use cases - e.g. quoting.

### Indexing

For indexing purposes, it is required that you provide a [substreams](https://thegraph.com/docs/en/substreams/) package that emits a specified set of messages. If your protocol already has a [substreams](https://thegraph.com/docs/en/substreams/) package for indexing implemented, you can adjust it to emit the required messages.

_Specifications coming soon._

