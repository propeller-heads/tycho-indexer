---
description: Execute swaps through any protocol.
---

# Execution

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Tycho Execution provides tools for **encoding and executing swaps** against Tycho routers and protocol executors. It is divided into two main components:

* **Encoding**: A Rust crate that encodes swaps and generates calldata for execution.
* **Executing**: Solidity contracts for executing trades on-chain.

The source code for **Tycho Execution** is available [here](https://github.com/propeller-heads/tycho-execution). For a practical example of its usage, please refer to our [Quickstart](../../).

## Token allowances

You can authorize token transfers in one of three ways with Tycho Execution:

* Permit2
* Standard ERC20 Approvals
* Direct Transfers

### Permit2

Tycho Execution leverages **Permit2** for token approvals. Before executing a swap via our router, you must approve the **Permit2 contract** for the specified token and amount. This ensures the router has the necessary permissions to execute trades on your behalf.&#x20;

When encoding a transaction, we provide functionality to build the `Permit` struct. However, you are responsible for signing the permit.

For more details on Permit2 and how to use it, see the [**Permit2 official documentation**](https://docs.uniswap.org/contracts/permit2/overview).

### **Standard ERC20 Approvals**

Tycho also supports traditional ERC20 approvals. In this model, you explicitly call `approve` on the token contract to grant the router permission to transfer tokens on your behalf. This is widely supported and may be preferred in environments where Permit2 is not yet available.

### **Direct Transfers**

It is possible to bypass approvals altogether by directly transferring the input token to the router within the same transaction. When using this option, the router must be funded  during execution.

⚠️ **Warning**: This feature is intended for advanced users only. The Tycho Router is not designed to securely hold funds — any tokens left in the router are considered lost. Ensure you have appropriate security measures in place to guarantee that funds pass through the router safely and cannot be intercepted or lost.

## Security and Audits

The Tycho Router has been audited by [Maximilian Krüger](https://snd.github.io/). We continuously work to improve security and welcome feedback from the community. The current audits are [here](https://github.com/propeller-heads/tycho-execution/tree/main/docs/audits).

If you discover potential security issues or have suggestions for improvements, please reach out through our official channels.
