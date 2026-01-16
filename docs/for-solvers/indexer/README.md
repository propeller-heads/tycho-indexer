---
description: Stream real-time onchain liquidity data
---

# Indexer

<figure><img src="../../.gitbook/assets/indexer (1).png" alt=""><figcaption></figcaption></figure>

Tycho Indexer gives you a low-latency, reorg-aware stream of all attributes you need to simulate swaps over DEX and other onchain liquidity.

### Native and VM indexing

Tycho can track protocols in two ways:

* **For Native Simulation**: Tycho gives structured data that mirrors on-chain states, so you can simulate protocol logic outside the VM (e.g. in your own Rust rewrite of Uni v2 swap function). Useful for example if you solve analytically over the trading curves.
* **Virtual Machine (VM) Compatibility**: Tycho tracks the state of all protocol contracts so you can simulate calls over it with no network overhead (locally on revm). Used by [Protocol Simulation](../simulation.md) to simulate key protocol functions (swap, price, derivatives etc.).

Native integrations are more effort, but run faster (\~1-5 microseconds or less per simulation), VM integrations are easier to do but run slower (\~100–1000 microseconds per simulation).

#### What Makes Tycho Unique?

* **Complete Protocol Systems**: Tycho doesn’t just track standalone data; it indexes whole systems, like Uniswap pools or Balancer components, even detecting new elements as they’re created.
* **Detailed Component Data**: For each tracked protocol component, Tycho records not just static values (like fees or token pairs) but also dynamic state changes, ensuring you have all you need to replicate the onchain state.

#### Leveraging Substreams

Tycho Indexer leverages Substreams, a robust and scalable indexing framework by StreamingFast.&#x20;

While Tycho currently uses Substreams to deliver high-performance indexing, our architecture is designed to be flexible, supporting future integrations with other data sources.

### A Simple Setup

Setting up using Tycho is simple with the [tycho client](tycho-client/).

Available as a CLI binary, rust crate, or python package.

