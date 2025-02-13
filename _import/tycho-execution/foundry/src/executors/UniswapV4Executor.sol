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
import "lib/forge-std/src/console.sol";

error UniswapV4Executor__InvalidDataLength();
error UniswapV4Executor__SwapFailed();

contract UniswapV4Executor is IExecutor, V4Router {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;

    struct UniswapV4Pool {
        address intermediaryToken;
        uint24 fee;
        int24 tickSpacing;
    }

    constructor(IPoolManager _poolManager) V4Router(_poolManager) {}

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        (
            address tokenIn,
            address tokenOut,
            uint256 amountOutMin,
            bool zeroForOne,
            address callbackExecutor,
            bytes4 callbackSelector,
            UniswapV4Executor.UniswapV4Pool[] memory pools
        ) = _decodeData(data);

        bytes memory fullData;
        if (pools.length == 0) {
            console.log("problem"); // raise error
        } else if (pools.length == 1) {
            PoolKey memory key = PoolKey({
                currency0: Currency.wrap(zeroForOne ? tokenIn : tokenOut),
                currency1: Currency.wrap(zeroForOne ? tokenOut : tokenIn),
                fee: pools[0].fee,
                tickSpacing: pools[0].tickSpacing,
                hooks: IHooks(address(0))
            });
            bytes memory actions = abi.encodePacked(
                uint8(Actions.SWAP_EXACT_IN_SINGLE),
                uint8(Actions.SETTLE_ALL),
                uint8(Actions.TAKE_ALL)
            );

            bytes[] memory params = new bytes[](3);

            params[0] = abi.encode(
                IV4Router.ExactInputSingleParams({
                    poolKey: key,
                    zeroForOne: zeroForOne,
                    amountIn: uint128(amountIn),
                    amountOutMinimum: uint128(amountOutMin),
                    hookData: bytes("")
                })
            );
            params[1] = abi.encode(key.currency0, amountIn);
            params[2] = abi.encode(key.currency1, 0);
            bytes memory swapData = abi.encode(actions, params);
            fullData =
                abi.encodePacked(callbackExecutor, callbackSelector, swapData);
        } else {
            console.log("do later");
        }

        uint256 tokenOutBalanceBefore;

        tokenOutBalanceBefore = tokenOut == address(0)
            ? address(this).balance
            : IERC20(tokenOut).balanceOf(address(this));

        executeActions(fullData);

        uint256 tokenOutBalanceAfter;

        tokenOutBalanceAfter = tokenOut == address(0)
            ? address(this).balance
            : IERC20(tokenOut).balanceOf(address(this));

        calculatedAmount = tokenOutBalanceAfter - tokenOutBalanceBefore;

        return calculatedAmount;
    }

    // necessary to convert bytes memory to bytes calldata
    function executeActions(bytes memory unlockData) public {
        poolManager.unlock(unlockData);
    }

    function _decodeData(bytes calldata data)
        public
        pure
        returns (
            address tokenIn,
            address tokenOut,
            uint256 amountOutMin,
            bool zeroForOne,
            address callbackExecutor,
            bytes4 callbackSelector,
            UniswapV4Pool[] memory pools
        )
    {
        require(data.length >= 97, "Invalid data length");

        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        amountOutMin = uint256(bytes32(data[40:72]));
        zeroForOne = (data[72] != 0);
        callbackExecutor = address(bytes20(data[73:93]));
        callbackSelector = bytes4(data[93:97]);

        uint256 poolsLength = (data.length - 97) / 26; // 26 bytes per pool object
        pools = new UniswapV4Pool[](poolsLength);
        bytes memory poolsData = data[97:];
        uint256 offset = 0;
        for (uint256 i = 0; i < poolsLength; i++) {
            address intermediaryToken;
            uint24 fee;
            int24 tickSpacing;

            assembly {
                intermediaryToken := mload(add(poolsData, add(offset, 20)))
                fee := shr(232, mload(add(poolsData, add(offset, 52))))
                tickSpacing := shr(232, mload(add(poolsData, add(offset, 55))))
            }
            pools[i] = UniswapV4Pool(intermediaryToken, fee, tickSpacing);
            offset += 26;
        }
    }

    function _pay(Currency token, address payer, uint256 amount)
        internal
        override
    {
        IERC20(Currency.unwrap(token)).safeTransfer(
            address(poolManager), amount
        );
    }

    function msgSender() public view override returns (address) {
        return address(this);
    }
}
