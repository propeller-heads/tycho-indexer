// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {V4Router} from "@uniswap/v4-periphery/src/V4Router.sol";
import {Actions} from "@uniswap/v4-periphery/src/libraries/Actions.sol";
import {IV4Router} from "@uniswap/v4-periphery/src/interfaces/IV4Router.sol";
import "forge-std/console.sol";

error UniswapV4Executor__InvalidDataLength();
error UniswapV4Executor__SwapFailed();

contract UniswapV4Executor is IExecutor, V4Router {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;

    constructor(IPoolManager _poolManager) V4Router(_poolManager) {}

    function swap(
        uint256,
        bytes calldata data
    ) external payable returns (uint256 amountOut) {
        (, address tokenOut, , address receiver, , ) = _decodeData(data);

        uint256 balanceBefore = IERC20(tokenOut).balanceOf(receiver);

        this.executeActions(data);

        amountOut = IERC20(tokenOut).balanceOf(receiver) - balanceBefore;
        if (amountOut == 0) revert UniswapV4Executor__SwapFailed();

        return amountOut;
    }

    function executeActions(bytes calldata actions) public {
        _executeActions(actions);
    }

    function _decodeData(
        bytes calldata data
    )
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver,
            bool zeroForOne,
            uint24 tickSpacing
        )
    {
        (, bytes[] memory params) = abi.decode(data, (bytes, bytes[]));

        IV4Router.ExactInputSingleParams memory swapParams = abi.decode(
            params[0],
            (IV4Router.ExactInputSingleParams)
        );

        (, address _receiver, ) = abi.decode(
            params[2],
            (Currency, address, uint256)
        );

        tokenIn = swapParams.zeroForOne
            ? address(uint160(swapParams.poolKey.currency0.toId()))
            : address(uint160(swapParams.poolKey.currency1.toId()));
        tokenOut = swapParams.zeroForOne
            ? address(uint160(swapParams.poolKey.currency1.toId()))
            : address(uint160(swapParams.poolKey.currency0.toId()));
        fee = swapParams.poolKey.fee;
        receiver = _receiver;
        zeroForOne = swapParams.zeroForOne;
        tickSpacing = uint24(swapParams.poolKey.tickSpacing);
    }

    function _pay(
        Currency token,
        address payer,
        uint256 amount
    ) internal override {
        token.transfer(payer, amount);
    }

    function msgSender() public view override returns (address) {
        return msg.sender;
    }
}
