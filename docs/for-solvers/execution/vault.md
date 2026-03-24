# Vault

The TychoRouter V3 holds user funds through an integrated vault <mark style="color:$danger;">(TODO: link vault code)</mark> built on the [ERC6909](https://eips.ethereum.org/EIPS/eip-6909) multi-token standard. This replaces the "direct transfer" pattern from V2, where any tokens sent to the router were at risk of being lost.

## How It Works

The vault uses a dual-storage architecture:

* Transient storage tracks balance changes ("deltas") during a swap. Credits are recorded when tokens arrive at the router; debits when they leave. This is cheap (\~100 gas per operation) and automatically clears at the end of each transaction.
* Persistent storage (ERC6909 balances) holds final user balances across transactions. These are updated only after a swap is fully validated.

At the end of every swap, `_finalizeBalances` validates the transient state before committing:

* For wallet-funded swaps: all deltas must net to zero.
* For vault-funded swaps: at most one negative delta is allowed (the input token), which is burned from the user's vault balance.

This design catches encoding errors and balance mismatches before any persistent state is modified.

## Depositing and Withdrawing

```solidity
// Deposit ERC-20 tokens 
router.deposit(tokenAddress, amount);

// Deposit native ETH 
router.deposit{value: amount}(address(0), amount);

// Withdraw 
router.withdraw(tokenAddress, amount);
```

Tokens deposited into the vault can be used for swaps by setting `user_transfer_type: UseVaultsFunds` in the [Solution](encoding/#solution-struct). They can also be withdrawn at any time.

## Crediting Output to the Vault

By default, output tokens are sent to the receiver address after a swap. If you set the receiver to the TychoRouter address, the output tokens are credited to the caller's vault balance instead of being transferred out.

This works with all swap types — single, sequential, and split — and with both wallet-funded and vault-funded swaps.

This enables vault rebalancing: converting one token in your vault to another without the tokens ever leaving the contract. For example, a solver holding WETH in the vault can convert it to USDC in a single transaction, with both the debit (WETH) and credit (USDC) happening entirely within the vault.

It also supports cyclical arbitrage, where you route through multiple pools and end up with more of the same token you started with — all settled within the vault.

## Why a Vault?

The vault serves three purposes:

1. Gas savings for repeat users. Solvers and market makers who route volume through Tycho can keep tokens in the contract, avoiding repeated approval and transfer costs.
2. In-contract rebalancing. Users can convert between tokens in their vault without additional ERC-20 transfers or approvals, since both input and output stay in the router.
3. Fee accounting. Both client fees and router fees are credited directly to the receiver's vault balance. No additional ERC-20 transfers are needed at fee-taking time — just a persistent storage write.

## Security Guarantees

* Vault balances are scoped per user. The router only permits the owner of funds to use them (via `msg.sender` or signature checks on swaps and withdrawals). This is enforced at the contract level and cannot be overridden through encoding.
* When output tokens are credited to the vault, they are always credited to `msg.sender` — not to the receiver parameter. This prevents a malicious encoder from redirecting output into someone else's vault.
* Tokens sent to the router without calling `deposit()` are considered lost. The vault does not credit balances from raw transfers.
