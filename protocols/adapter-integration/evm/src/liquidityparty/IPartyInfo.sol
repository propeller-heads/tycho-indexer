// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IPartyPool} from "./IPartyPool.sol";

interface IPartyInfo {
    /// @notice returns true iff the pool is not killed and has been initialized
    /// with liquidity.
    function working(IPartyPool pool) external view returns (bool);

    /// @notice Infinitesimal out-per-in marginal price for swap base->quote as
    /// Q128.128, not adjusted for token decimals.
    /// @param baseTokenIndex index of the input (base) asset
    /// @param quoteTokenIndex index of the output (quote) asset
    /// @return price Q128.128 value equal to out-per-in (j per i)
    function price(
        IPartyPool pool,
        uint256 baseTokenIndex,
        uint256 quoteTokenIndex
    ) external view returns (uint256);

    /// @notice Quote an exact-input swap.
    /// @param pool             pool being quoted
    /// @param inputTokenIndex  index of token being sold
    /// @param outputTokenIndex index of token being bought
    /// @param maxAmountIn      maximum gross input (inclusive of fee)
    /// @return amountIn gross input to transfer, amountOut output user
    /// receives, inFee fee taken from input
    function swapAmounts(
        IPartyPool pool,
        uint256 inputTokenIndex,
        uint256 outputTokenIndex,
        uint256 maxAmountIn
    ) external view returns (uint256 amountIn, uint256 amountOut, uint256 inFee);
}
