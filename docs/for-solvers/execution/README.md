---
description: Execute swaps through any protocol.
---

# Execution

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Tycho Execution provides tools for **encoding and executing swaps** against Tycho Router and protocol executors. It is divided into two main components:

* **Encoding**: A Rust crate that encodes swaps and generates calldata for execution.
* **Executing**: Solidity contracts for executing trades on-chain.

The source code for **Tycho Execution** is available [here](https://github.com/propeller-heads/tycho-execution). For a practical example of its usage, please refer to our [Quickstart](../../).

## Token transfers

You can transfer tokens in one of three ways with Tycho Execution:

* Permit2
* Standard ERC20 Approvals
* Using Vault funds

See how to change between these options when encoding [here](encoding/#usertransfertype).

### Permit2

Tycho Execution leverages **Permit2** for token approvals. Before executing a swap via our router, you must approve the **Permit2 contract** for the specified token and amount. This ensures the router has the necessary permissions to execute trades on your behalf.

When encoding a transaction, we provide functionality to build the `Permit` struct. However, you are responsible for signing the permit.

For more details on Permit2 and how to use it, see the [**Permit2 official documentation**](https://docs.uniswap.org/contracts/permit2/overview).

### **Standard ERC20 Approvals**

Tycho also supports traditional ERC20 approvals. In this model, you explicitly call `approve` on the token contract to grant the router permission to transfer tokens on your behalf. This is widely supported and may be preferred in environments where Permit2 is not yet available.

### Using the Vault

The TychoRouter includes a built-in vault ([ERC6909](https://eips.ethereum.org/EIPS/eip-6909)) that lets you deposit, hold, and withdraw tokens directly in the router contract. The vault tracks per-user balances, so your tokens are only accessible by you.

The router draws from your deposited balance instead of performing a `transferFrom` on your wallet. This saves gas (no approval or external transfer needed) and lets you use fees, proceeds from previous trades, or pre-positioned liquidity directly.

Fees earned through the fee-taking system are automatically credited to the fee receiver's vault balance, making them immediately available for future swaps or withdrawals.

More on the Vault [here](vault.md).

## Security and Audits

The Tycho Router has been audited by [Maximilian Krüger](https://snd.github.io/). We continuously work to improve security and welcome feedback from the community. The current audits are [here](https://github.com/propeller-heads/tycho-execution/tree/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/docs/audits).

If you discover potential security issues or have suggestions for improvements, please reach out through our official channels.
