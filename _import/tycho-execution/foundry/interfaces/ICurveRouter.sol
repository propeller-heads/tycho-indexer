// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

interface ICurveRouter {
    function exchange(
        address[11] memory route,
        uint256[5][5] memory swapParams,
        uint256 amountIn,
        uint256 minAmountOut,
        address[5] memory pools,
        address receiver
    ) external payable returns (uint256);

    // slither-disable-next-line naming-convention
    function get_dy(
        address[] memory route,
        uint256[] memory swapParams,
        uint256 amountIn,
        address[] memory pools
    ) external view returns (uint256);

    
}

 struct CurveRouterParams {
        address[11] route;
        uint256[5][5] swapParams;
        uint256 amountIn;
        uint256 minAmountOut;
        address[5] pools;
        address receiver;
    }

