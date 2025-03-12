// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@interfaces/ICurveRouter.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract CurveExecutor is IExecutor {
    using SafeERC20 for IERC20;

    ICurveRouter public immutable curveRouter;

    constructor(address _curveRouter) {
        curveRouter = ICurveRouter(_curveRouter);
    }

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256)
    {
        CurveRouterParams memory params = _decodeData(data);
        IERC20(params.route[0]).approve(address(curveRouter), amountIn);
        return curveRouter.exchange(
            params.route,
            params.swapParams,
            amountIn,
            params.minAmountOut,
            params.pools,
            params.receiver
        );
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (CurveRouterParams memory params)
    {
        return abi.decode(data, (CurveRouterParams));
    }
}
