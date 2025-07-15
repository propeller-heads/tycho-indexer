# Motivation

Tycho indexes on-chain liquidity, with a current focus on token swaps. Future development can include other liquidity provisioning, lending, and derivatives.

### The DeFi Fragmentation Challenge

The rapid innovation in DeFi protocols has created a fragmented ecosystem without standardized interfaces for fundamental operations like swaps, liquidity provisioning, etc.&#x20;

Tycho aims to provide a standardized interface across those operations.

With a focus on fast local simulations on top of the latest known state of the chain and settlements through tycho-execution.

### Key Challenges in Liquidity Indexing

Before Tycho, you might face the following issues if you want to settle on onchain protocols:

#### Technical Complexity

* Rewrite protocol-specific mathematics in your application programming language to simulate fast locally.
* Develop protocol-specific indexing to supply data for local simulations.
* Watch and filter out user-created token pairs with unusual or malicious behavior.
* Navigate an enormous search space of liquidity sources with effective filtering heuristics.

#### Blockchain-Specific Issues

* Chain reorganizations ("reorgs") that alter transaction history must be handled with care.
* Block propagation delays caused by peer-to-peer network topology and geographic distribution.
* Continuous maintenance of node infrastructure, such as updating client versions (especially during hard forks), updating storage space, etc.

### Push-Based Architecture

#### Problems with Traditional RPC Polling

Traditional indexers rely on node client RPC interfaces, which have significant limitations:

* Data must be requested from nodes, introducing latency and potential for error.
* Multiple requests are often needed to assemble a complete view of the data.
* Complex query contracts may be required for comprehensive data extraction (e.g., to get all Uniswap V3 ticks) whose execution adds additional latency to data retrieval.
* Load-balanced RPC endpoints can expose inconsistent state views during reorgs, making it hard to scale across many node clients.
* May involve maintaining and running multiple instances of modified node clients.

#### The Streaming Solution

Tycho adopts a fundamentally different approach:

* Data is pushed/streamed as a block is processed by the node client.
* Current implementation leverages Substreams as the primary data source.
* Alternative data sources can be integrated if they provide comparable richness.
* State changes are communicated to clients through streaming interfaces.

### User Experience Philosophy

#### Abstraction by Default

* Non-blockchain-native users shouldn't need to understand chain-specific concepts.
* Reorgs and optimistic state changes remain invisible to users by default.
* Users perceive only that state has changed, regardless of underlying mechanism.

#### Optional Transparency

* Advanced users can access detailed information about state changes when needed.
* Granular visibility allows inspection of upcoming state changes.
* Applications can track specific liquidity pair changes for specialized use cases.
