// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/**
 * @title Curve Router Interface
 * @notice Interface for interacting with Curve's router contract for token swaps across various Curve pools
 * @dev This interface allows for executing swaps through Curve's router, which can handle different pool types
 */
interface ICurveRouter {

    /**
     * @notice Parameters for executing a swap through the Curve router
     * @dev This struct encapsulates all necessary parameters for a Curve swap
     * @param route Array of addresses representing the swap path (tokens and pools)
     * @param swapParams 2D array containing swap parameters for each hop:
     *        [0]: tokenIn index in the pool
     *        [1]: tokenOut index in the pool
     *        [2]: swap type (1 for regular swap)
     *        [3]: pool type (1-4 depending on the Curve pool implementation)
     *        [4]: number of coins in the pool
     * @param amountIn Amount of input token to swap
     * @param minAmountOut Minimum amount of output token to receive
     * @param pools Array of pool addresses involved in the swap
     * @param receiver Address to receive the output tokens
     */
    struct CurveRouterParams {
        address[11] route;
        uint256[5][5] swapParams;
        uint256 amountIn;
        uint256 minAmountOut;
        address[5] pools;
        address receiver;
    }

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

 

