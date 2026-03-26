# Executing

Once you have calldata from [Encoding](executing.md#encoding-a-solution), you can execute your trade via the Tycho Router.

## Tycho Router

Send the encoded calldata to the TychoRouter [contract](https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/TychoRouter.sol#L90) (see contract addresses [here](contract-addresses.md)). Setup depends on the `user_transfer_type` in your `Solution`:

* `TransferFrom`: Approve the TychoRouter to spend your input token via `approve()` before submitting the transaction.
* `TransferFromPermit2`: Approve the Permit2 contract, then create and sign the permit yourself. Use the public `Permit2` utility from the encoding crate to build the `PermitSingle`. The encoder does not produce the permit — you handle this externally.
* `UseVaultsFunds`: No approval or transfer needed. The router draws from your pre-deposited vault balance. Ensure you have deposited sufficient funds.

For an example of how to execute trades using the Tycho Router, refer to the [Quickstart](../../#id-5.-simulate-or-execute-the-best-swap).

### Fee Taking

The TychoRouter V3 supports a dual fee system:

* Client fees: Set `client_fee_bps` and `client_fee_receiver` in the `Solution` to charge a percentage of the output amount. Fees are credited to the receiver's vault balance.
* Router fees: Configured on-chain by Propeller Heads. These are mandatory and cannot be bypassed through encoding. The router can charge a fee on the output amount and/or a percentage of the client fee.

### Client Contribution (Slippage Subsidy)

If the swap output falls below `min_amount_out`, the router can draw from the client's vault balance (up to `max_client_contribution`) to cover the difference. If the shortfall exceeds `max_client_contribution`, the transaction reverts. This lets solvers subsidize slippage-affected trades without a separate transaction. Be careful when setting `max_client_contribution`; a value exceeding the cost of a separate on-chain transaction may expose you to sandwich attacks.
