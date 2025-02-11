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
import "forge-std/console.sol";

error UniswapV4Executor__InvalidDataLength();
error UniswapV4Executor__SwapFailed();

contract UniswapV4Executor is IExecutor, V4Router {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;

    constructor(IPoolManager _poolManager) V4Router(_poolManager) {}

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 amountOut)
    {
        (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver,
            bool zeroForOne,
            uint24 tickSpacing
        ) = _decodeData(data);

        uint128 amountIn128 = uint128(amountIn);
        uint256 balanceBefore = IERC20(tokenOut).balanceOf(receiver);

        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(zeroForOne ? tokenIn : tokenOut),
            currency1: Currency.wrap(zeroForOne ? tokenOut : tokenIn),
            fee: fee,
            tickSpacing: int24(tickSpacing),
            hooks: IHooks(address(0))
        });

        bytes memory actions = abi.encodePacked(
            uint8(Actions.SWAP_EXACT_IN_SINGLE),
            uint8(Actions.SETTLE_ALL),
            uint8(Actions.TAKE)
        );

        bytes[] memory params = new bytes[](3);

        params[0] = abi.encode(
            IV4Router.ExactInputSingleParams({
                poolKey: key,
                zeroForOne: zeroForOne,
                amountIn: amountIn128,
                amountOutMinimum: 0,
                hookData: bytes("")
            })
        );

        params[1] = abi.encode(key.currency0, amountIn128);
        params[2] = abi.encode(key.currency1, receiver, 0);

        this.executeActions(abi.encode(actions, params));

        amountOut = IERC20(tokenOut).balanceOf(receiver) - balanceBefore;

        if (amountOut == 0) revert UniswapV4Executor__SwapFailed();

        return amountOut;
    }

    function executeActions(bytes calldata actions) public {
        _executeActions(actions);
    }

    function _decodeData(bytes calldata data)
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
        if (data.length != 67) {
            revert UniswapV4Executor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[:20]));
        tokenOut = address(bytes20(data[20:40]));
        fee = uint24(bytes3(data[40:43]));
        receiver = address(bytes20(data[43:63]));
        zeroForOne = uint8(bytes1(data[63])) > 0;
        tickSpacing = uint24(bytes3(data[64:67]));
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
