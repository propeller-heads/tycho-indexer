// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@interfaces/ICurveRouter.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

error CurveExecutor__InvalidAddresses();

contract CurveExecutor is IExecutor {
    using SafeERC20 for IERC20;

    ICurveRouter public immutable curveRouter;
    address public immutable nativeToken;

    struct SwapParams {
        address[11] route;
        uint256[5][5] swapParams;
        uint256 minAmountOut;
        address receiver;
        bool needsApproval;
    }

    constructor(address _curveRouter, address _nativeToken) {
        if (_curveRouter == address(0) || _nativeToken == address(0)) {
            revert CurveExecutor__InvalidAddresses();
        }
        curveRouter = ICurveRouter(_curveRouter);
        nativeToken = _nativeToken;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256)
    {
        SwapParams memory params = _decodeData(data);

        if (params.needsApproval) {
            // slither-disable-next-line unused-return
            IERC20(params.route[0]).approve(
                address(curveRouter), type(uint256).max
            );
        }
        // slither-disable-next-line uninitialized-local
        address[5] memory pools;
        return curveRouter.exchange{
            value: params.route[0] == nativeToken ? amountIn : 0
        }(
            params.route,
            params.swapParams,
            amountIn,
            params.minAmountOut,
            pools,
            params.receiver
        );
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (SwapParams memory params)
    {
        return abi.decode(data, (SwapParams));
    }
}
