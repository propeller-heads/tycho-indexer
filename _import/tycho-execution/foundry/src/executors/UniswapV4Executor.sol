// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@interfaces/IExecutor.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/interfaces/IPoolManager.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/types/Currency.sol";
import {PoolKey} from "@uniswap/v4-core/types/PoolKey.sol";
import {BalanceDelta} from "@uniswap/v4-core/types/BalanceDelta.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {IHooks} from "@uniswap/v4-core/interfaces/IHooks.sol";

error UniswapV4Executor__InvalidDataLength();
error UniswapV4Executor__SwapFailed();

contract UniswapV4Executor is IExecutor {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;
    using SafeCast for int128;
    using SafeCast for int256;

    uint256 private constant MIN_SQRT_RATIO = 4295128739;
    uint256 private constant MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

    // slither-disable-next-line locked-ether
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
            address target,
            bool zeroForOne
        ) = _decodeData(data);

        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(zeroForOne ? tokenIn : tokenOut),
            currency1: Currency.wrap(zeroForOne ? tokenOut : tokenIn),
            fee: fee,
            tickSpacing: 60, // Standard tick spacing
            hooks: IHooks(address(0))  // No hooks needed for basic swaps
        });

        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: int256(amountIn),
            sqrtPriceLimitX96: uint160(zeroForOne ? MIN_SQRT_RATIO + 1 : MAX_SQRT_RATIO - 1)
        });

        IPoolManager poolManager = IPoolManager(target);
        
        try poolManager.swap(key, params, abi.encode(key)) returns (BalanceDelta delta) {
            if (zeroForOne) {
                amountOut = delta.amount1() < 0 ? (-delta.amount1()).toUint256() : 0;
            } else {
                amountOut = delta.amount0() < 0 ? (-delta.amount0()).toUint256() : 0;
            }

            if (receiver != address(this)) {
                IERC20(tokenOut).safeTransfer(receiver, amountOut);
            }
        } catch {
            revert UniswapV4Executor__SwapFailed();
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver,
            address target,
            bool zeroForOne
        )
    {
        if (data.length != 84) {
            revert UniswapV4Executor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        fee = uint24(bytes3(data[40:43]));
        receiver = address(bytes20(data[43:63]));
        target = address(bytes20(data[63:83]));
        zeroForOne = uint8(data[83]) > 0;
    }

    
}
