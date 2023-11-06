# Propeller Protocol Lib

Protocol lib is a library used by Propellerheads.xyz solvers to integrate decentralised protocols. Currently only swap/exchange protocols are supported.

### Integration Process Overview

To integrate with PropellerHeads solvers, two components need to be provided:

* **Protocol logic:** Provides simualtions, of the protocols logic.
* **Indexing**: Provides access to the protocol state used by the simulation. This component is optional if your protocol is stateless.

#### Protocol Logic

PropellerHeads currently exposes two integration modes to specify the protocols underlying logic:

* **VM Integration:** This integration type requires implementing an adapter interface in any language that compiles to the respective vm byte code. Currently only Solidity is supported.
* **Native Rust Integration:** Coming soon, this integration type requires implementing a Rust trait that describes the protocols logic.

While VM integration is certainly the quickest and probably most accessible one for protocol developers, native implementations are much faster and allow us to consider the protocol for more time sensitive use cases - e.g. quoting.

#### Indexing

For indexing purposes it is required that you provide a [substreams](https://thegraph.com/docs/en/substreams/) package that emits a specified set of messages. Most new protocols will already have a [substreams](https://thegraph.com/docs/en/substreams/) package for indexing implemented this will only need to be adjusted to emit the required messages for.

_Specifications coming soon._

