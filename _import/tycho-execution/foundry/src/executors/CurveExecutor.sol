// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@interfaces/ICurveRouter.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

error CurveExecutor__InvalidAddresses();

contract CurveExecutor is IExecutor {
    using SafeERC20 for IERC20;

    ICurveRouter public immutable curveRouter;
    address public immutable nativeTokens;

    constructor(address _curveRouter, address _nativeTokens) {
        if (_curveRouter == address(0) || _nativeTokens == address(0)) {
            revert CurveExecutor__InvalidAddresses();
        }
        curveRouter = ICurveRouter(_curveRouter);
        nativeTokens = _nativeTokens;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256)
    {
        ICurveRouter.CurveRouterParams memory params = _decodeData(data);
        if (params.route[0] != nativeTokens) {
            // slither-disable-next-line unused-return
            IERC20(params.route[0]).approve(address(curveRouter), amountIn);

            return curveRouter.exchange(
                params.route,
                params.swapParams,
                amountIn,
                params.minAmountOut,
                params.pools,
                params.receiver
            );
        } else {
            return curveRouter.exchange{value: amountIn}(
                params.route,
                params.swapParams,
                amountIn,
                params.minAmountOut,
                params.pools,
                params.receiver
            );
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (ICurveRouter.CurveRouterParams memory params)
    {
        return abi.decode(data, (ICurveRouter.CurveRouterParams));
    }
}
