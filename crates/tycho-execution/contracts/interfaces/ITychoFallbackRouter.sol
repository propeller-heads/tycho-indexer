// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/// @title ITychoFallbackRouter
/// @notice The subset of `TychoFallbackRouter` that `FallbackExecutor` calls.
interface ITychoFallbackRouter {
    /// @notice One swap leg: what goes in, what comes out, and who receives it.
    struct Leg {
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        address receiver;
    }

    /// @notice Runs `pamm` and, only if it fails, `fallbackSwap`. A failing fallback reverts the
    /// swap; there is no third attempt.
    /// @dev Only callers holding `CALLER_ROLE` (the TychoRouter). Push-payment: the caller MUST
    /// transfer `leg.amountIn` of `leg.tokenIn` here first. Native ETH is not supported.
    /// `fallbackSwap` is `[venue: uint8][venue data]`, and no venue kind is a pAMM.
    /// @return amountOut The `leg.tokenOut` balance increase measured at `leg.receiver`.
    function swap(Leg calldata leg, address pamm, bytes calldata fallbackSwap)
        external
        returns (uint256 amountOut);
}
