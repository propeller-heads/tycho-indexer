# Changelog

## v0.1.0

Initial EtherFi integration. Indexes two components from raw storage slots:

- `eETH` (`0x35fA...8ac2`) — ETH deposits through the LiquidityPool and eETH redemptions
  through the RedemptionManager, including the `ethBucketLimiter` redemption rate limit.
- `weETH` (`0xCd5f...b7ee`) — eETH wrap and unwrap.

Balances come from the protocol's own share accounting, so the integration test runs with
`skip_balance_check`.
