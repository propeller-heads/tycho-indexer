// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/**
 * @title Curve Router Interface
 * @notice Interface for interacting with Curve's router contract for token swaps across various Curve pools
 * @dev This interface allows for executing swaps through Curve's router, which can handle different pool types
 */
interface ICurveRouter {
    /**
     * @notice Executes a token swap through Curve pools
     * @dev This function handles the routing of tokens through one or more Curve pools
     * @dev The parameters are encoded in the `CurveRouterParams` struct
     * @return Amount of output tokens received from the swap
     */
    function exchange(
        address[11] memory route,
        uint256[5][5] memory swapParams,
        uint256 amountIn,
        uint256 minAmountOut,
        address[5] memory pools,
        address receiver
    ) external payable returns (uint256);
}

 

