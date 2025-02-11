// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {
    Currency, CurrencyLibrary
} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {V4Router} from "@uniswap/v4-periphery/src/V4Router.sol";
import {Actions} from "@uniswap/v4-periphery/src/libraries/Actions.sol";
import {IV4Router} from "@uniswap/v4-periphery/src/interfaces/IV4Router.sol";
import {PathKey} from "@uniswap/v4-periphery/src/libraries/PathKey.sol";

error UniswapV4Executor__InvalidDataLength();
error UniswapV4Executor__SwapFailed();

contract UniswapV4Executor is IExecutor, V4Router {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;

    constructor(IPoolManager _poolManager) V4Router(_poolManager) {}

    function swap(uint256, bytes calldata data)
        external
        payable
        returns (uint256 amountOut)
    {
        (address tokenOut, address receiver, bool isExactInput, uint256 amount)
        = _decodeData(data);

        uint256 balanceBefore = IERC20(tokenOut).balanceOf(receiver);

        this.executeActions(data);

        uint256 balanceAfter = IERC20(tokenOut).balanceOf(receiver);

        if (isExactInput) {
            amountOut = balanceAfter - balanceBefore;
        } else {
            amountOut = amount;
        }

        // Checks if the amountOut is not 0.
        // Slither does not allow strict equality checks.
        if (amountOut < 1) {
            revert UniswapV4Executor__SwapFailed();
        }
        return amountOut;
    }

    function executeActions(bytes calldata actions) public {
        _executeActions(actions);
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address tokenOut,
            address receiver,
            bool isExactInput,
            uint256 amount
        )
    {
        (bytes memory actions, bytes[] memory params) =
            abi.decode(data, (bytes, bytes[]));

        // First byte of actions determines the swap type
        uint8 action = uint8(bytes1(actions[0]));

        // Get receiver from params[2] for all cases
        (, receiver,) = abi.decode(params[2], (Currency, address, uint256));

        if (action == uint8(Actions.SWAP_EXACT_IN_SINGLE)) {
            IV4Router.ExactInputSingleParams memory swapParams =
                abi.decode(params[0], (IV4Router.ExactInputSingleParams));

            tokenOut = swapParams.zeroForOne
                ? address(uint160(swapParams.poolKey.currency1.toId()))
                : address(uint160(swapParams.poolKey.currency0.toId()));
            isExactInput = true;
            amount = swapParams.amountIn;
        } else if (action == uint8(Actions.SWAP_EXACT_OUT_SINGLE)) {
            IV4Router.ExactOutputSingleParams memory swapParams =
                abi.decode(params[0], (IV4Router.ExactOutputSingleParams));

            tokenOut = swapParams.zeroForOne
                ? address(uint160(swapParams.poolKey.currency1.toId()))
                : address(uint160(swapParams.poolKey.currency0.toId()));
            isExactInput = false;
            amount = swapParams.amountOut;
        } else if (action == uint8(Actions.SWAP_EXACT_IN)) {
            IV4Router.ExactInputParams memory swapParams =
                abi.decode(params[0], (IV4Router.ExactInputParams));

            PathKey memory lastPath =
                swapParams.path[swapParams.path.length - 1];
            tokenOut = address(uint160(lastPath.intermediateCurrency.toId()));
            isExactInput = true;
            amount = swapParams.amountIn;
        } else if (action == uint8(Actions.SWAP_EXACT_OUT)) {
            IV4Router.ExactOutputParams memory swapParams =
                abi.decode(params[0], (IV4Router.ExactOutputParams));

            tokenOut = address(uint160(swapParams.currencyOut.toId()));
            isExactInput = false;
            amount = swapParams.amountOut;
        }
    }

    function _pay(Currency token, address payer, uint256 amount)
        internal
        override
    {
        token.transfer(payer, amount);
    }

    function msgSender() public view override returns (address) {
        return msg.sender;
    }
}
