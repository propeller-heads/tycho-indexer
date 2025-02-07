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
import {IUnlockCallback} from
    "@uniswap/v4-core/interfaces/callback/IUnlockCallback.sol";
import {TransientStateLibrary} from
    "@uniswap/v4-core/libraries/TransientStateLibrary.sol";

error UniswapV4Executor__InvalidDataLength();
error UniswapV4Executor__SwapFailed();
error UniswapV4Executor__InsufficientOutput();
error UniswapV4Executor__ManagerMismatch();

contract UniswapV4Executor is IExecutor, IUnlockCallback {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;
    using SafeCast for int128;
    using SafeCast for int256;
    using TransientStateLibrary for IPoolManager;

    uint256 private constant MIN_SQRT_RATIO = 4295128739;
    uint256 private constant MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

    struct SwapCallbackData {
        PoolKey key;
        IPoolManager.SwapParams params;
        address tokenIn;
        address tokenOut;
        address receiver;
    }

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
            hooks: IHooks(address(0)) // No hooks needed for basic swaps
        });

        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: int256(amountIn),
            sqrtPriceLimitX96: uint160(
                zeroForOne ? MIN_SQRT_RATIO + 1 : MAX_SQRT_RATIO - 1
            )
        });

        // TODO: Find a better place
        IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenIn).approve(target, amountIn);

        SwapCallbackData memory callbackData = SwapCallbackData({
            key: key,
            params: params,
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            receiver: receiver
        });

        IPoolManager poolManager = IPoolManager(target);

        try poolManager.unlock(abi.encode(callbackData)) returns (
            bytes memory result
        ) {
            amountOut = abi.decode(result, (uint256));

            if (amountOut == 0) revert UniswapV4Executor__InsufficientOutput();

            // Transfer output tokens to receiver if not this contract
            if (receiver != address(this)) {
                IERC20(tokenOut).safeTransfer(receiver, amountOut);
            }
        } catch {
            revert UniswapV4Executor__SwapFailed();
        }
    }

    // Dev notes: This is inspired by the Uniswap V4 PoolSwapTest.sol
    function unlockCallback(bytes calldata rawData)
        external
        returns (bytes memory)
    {
        SwapCallbackData memory data = abi.decode(rawData, (SwapCallbackData));

        IPoolManager poolManager = IPoolManager(msg.sender);

        // Check initial balances
        (,, int256 deltaBefore0) = _fetchBalances(
            data.key.currency0, data.receiver, address(this), poolManager
        );
        (,, int256 deltaBefore1) = _fetchBalances(
            data.key.currency1, data.receiver, address(this), poolManager
        );

        require(deltaBefore0 == 0, "deltaBefore0 not zero");
        require(deltaBefore1 == 0, "deltaBefore1 not zero");

        BalanceDelta delta = poolManager.swap(data.key, data.params, "");

        // Check final balances and validate based on swap direction
        (,, int256 deltaAfter0) = _fetchBalances(
            data.key.currency0, data.receiver, address(this), poolManager
        );
        (,, int256 deltaAfter1) = _fetchBalances(
            data.key.currency1, data.receiver, address(this), poolManager
        );

        uint256 amountOut;
        if (data.params.zeroForOne) {
            if (data.params.amountSpecified < 0) {
                // exact input, 0 for 1
                require(
                    deltaAfter0 >= data.params.amountSpecified,
                    "insufficient input amount"
                );
                require(delta.amount0() == deltaAfter0, "delta mismatch");
                require(deltaAfter1 >= 0, "negative output amount");
                amountOut = deltaAfter1 > 0 ? uint256(deltaAfter1) : 0;
            } else {
                // exact output, 0 for 1
                require(deltaAfter0 <= 0, "positive input amount");
                require(delta.amount1() == deltaAfter1, "delta mismatch");
                require(
                    deltaAfter1 <= data.params.amountSpecified,
                    "excessive output amount"
                );
                amountOut = uint256((-delta.amount1()).toUint256());
            }
        } else {
            if (data.params.amountSpecified < 0) {
                // exact input, 1 for 0
                require(
                    deltaAfter1 >= data.params.amountSpecified,
                    "insufficient input amount"
                );
                require(delta.amount1() == deltaAfter1, "delta mismatch");
                require(deltaAfter0 >= 0, "negative output amount");
                amountOut = deltaAfter0 > 0 ? uint256(deltaAfter0) : 0;
            } else {
                // exact output, 1 for 0
                require(deltaAfter1 <= 0, "positive input amount");
                require(delta.amount0() == deltaAfter0, "delta mismatch");
                require(
                    deltaAfter0 <= data.params.amountSpecified,
                    "excessive output amount"
                );
                amountOut = uint256((-delta.amount0()).toUint256());
            }
        }

        if (deltaAfter0 < 0) {
            poolManager.settle{
                value: data.key.currency0.isAddressZero()
                    ? uint256(-deltaAfter0)
                    : 0
            }();
            if (!data.key.currency0.isAddressZero()) {
                IERC20(Currency.unwrap(data.key.currency0)).transfer(
                    address(poolManager), uint256(-deltaAfter0)
                );
            }
        }
        if (deltaAfter1 < 0) {
            poolManager.settle{
                value: data.key.currency1.isAddressZero()
                    ? uint256(-deltaAfter1)
                    : 0
            }();
            if (!data.key.currency1.isAddressZero()) {
                IERC20(Currency.unwrap(data.key.currency1)).transfer(
                    address(poolManager), uint256(-deltaAfter1)
                );
            }
        }
        if (deltaAfter0 > 0) {
            poolManager.take(
                data.key.currency0, data.receiver, uint256(deltaAfter0)
            );
        }
        if (deltaAfter1 > 0) {
            poolManager.take(
                data.key.currency1, data.receiver, uint256(deltaAfter1)
            );
        }

        // Handle any remaining ETH balance
        uint256 ethBalance = address(this).balance;
        if (ethBalance > 0) {
            CurrencyLibrary.ADDRESS_ZERO.transfer(data.receiver, ethBalance);
        }

        return abi.encode(amountOut);
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

    function _fetchBalances(
        Currency currency,
        address user,
        address deltaHolder,
        IPoolManager manager
    )
        internal
        view
        returns (uint256 userBalance, uint256 poolBalance, int256 delta)
    {
        userBalance = currency.balanceOf(user);
        poolBalance = currency.balanceOf(address(manager));
        delta = manager.currencyDelta(deltaHolder, currency);
    }
}
