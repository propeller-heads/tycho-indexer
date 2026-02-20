// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {IPartyPool} from "./IPartyPool.sol";

interface IPartyInfo {
    /// @notice returns true iff the pool is not killed and has been initialized
    /// with liquidity.
    function working(IPartyPool pool) external view returns (bool);

    /// @notice Infinitesimal out-per-in marginal price for swap base->quote as
    /// Q128.128, not adjusted for token decimals.
    /// @dev Returns p_base / p_quote in Q128.128 format, scaled to external
    /// units by (denom_quote / denom_base). This aligns with the swap kernel so
    /// that, fee-free, avg(out/in) ≤ price(base, quote) for exact-in trades.
    /// @param baseTokenIndex index of the input (base) asset
    /// @param quoteTokenIndex index of the output (quote) asset
    /// @return price Q128.128 value equal to out-per-in (j per i)
    function price(
        IPartyPool pool,
        uint256 baseTokenIndex,
        uint256 quoteTokenIndex
    ) external view returns (uint256);
}
