# Executing

Once you have the calldata from [Encoding](executing.md#encoding-a-solution), you can execute your trade via the Tycho Router.

## Tycho Router

Send the encoded calldata to the TychoRouter [contract](https://github.com/propeller-heads/tycho-execution/blob/main/foundry/src/TychoRouter.sol#L68) (see contract addresses [here](contract-addresses.md)). The setup depends on the `user_transfer_type` you specified in your `Solution`:

* `TransferFrom`: Approve the TychoRouter to spend your input token via a standard ERC-20 `approve()` call before submitting the transaction.
* `TransferFromPermit2`: Approve the Permit2 contract, then include the signed permit in your transaction. The `EncodedSolution` will contain the permit field with the data you need to sign.
* `UseVaultsFunds`: No approval or transfer setup is needed. The router draws from your pre-deposited vault balance. Make sure you have deposited sufficient funds before executing.

For an example of how to execute trades using the Tycho Router, refer to the [Quickstart](../../#id-5.-simulate-or-execute-the-best-swap).

### Fee Taking

The TychoRouter V3 supports a dual fee system:

* Client fees: Set `client_fee_bps` and `client_fee_receiver` in the `Solution` to charge a percentage of the output amount. Fees are credited to the receiver's vault balance.
* Router fees: Configured on-chain by the Propeller Heads. These are mandatory and cannot be bypassed through encoding. The router can charge a fee on the output amount and/or a percentage of the client fee.

### Client Contribution (Slippage Subsidy)

If the actual swap output falls below `min_amount_out`, the router can draw from the client's vault balance (up to `max_client_contribution`) to make up the difference. If the shortfall exceeds `max_client_contribution`, the transaction reverts. This lets solvers subsidize trades affected by slippage without requiring a separate transaction. Be mindful when setting max\_client\_contribution — a value that exceeds the cost of a separate on-chain transaction may expose you to sandwich attacks.
