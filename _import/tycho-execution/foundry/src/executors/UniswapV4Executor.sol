// SPDX-License-Identifier: BUSL-1.1
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
import {ICallback} from "@interfaces/ICallback.sol";
import {TokenTransfer} from "./TokenTransfer.sol";

error UniswapV4Executor__InvalidDataLength();

contract UniswapV4Executor is IExecutor, V4Router, ICallback, TokenTransfer {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;

    struct UniswapV4Pool {
        address intermediaryToken;
        uint24 fee;
        int24 tickSpacing;
    }

    constructor(IPoolManager _poolManager, address _permit2)
        V4Router(_poolManager)
        TokenTransfer(_permit2)
    {}

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        (
            address tokenIn,
            address tokenOut,
            bool zeroForOne,
            TransferType transferType,
            address receiver,
            UniswapV4Executor.UniswapV4Pool[] memory pools
        ) = _decodeData(data);

        // TODO move this into callback when we implement callback transfer type support
        _transfer(
            tokenIn,
            msg.sender,
            // Receiver can never be the pool, since the pool expects funds in the router contract
            // Thus, this call will only ever be used to transfer funds from the user into the router.
            address(this),
            amountIn,
            transferType
        );

        bytes memory swapData;
        if (pools.length == 1) {
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
                uint8(Actions.TAKE)
            );

            bytes[] memory params = new bytes[](3);

            params[0] = abi.encode(
                IV4Router.ExactInputSingleParams({
                    poolKey: key,
                    zeroForOne: zeroForOne,
                    amountIn: uint128(amountIn),
                    amountOutMinimum: uint128(0),
                    hookData: bytes("")
                })
            );
            params[1] = abi.encode(tokenIn, amountIn); // currency to settle
            params[2] = abi.encode(tokenOut, receiver, uint256(0)); // currency to take. 0 means to take the full amount
            swapData = abi.encode(actions, params);
        } else {
            PathKey[] memory path = new PathKey[](pools.length);
            for (uint256 i = 0; i < pools.length; i++) {
                path[i] = PathKey({
                    intermediateCurrency: Currency.wrap(pools[i].intermediaryToken),
                    fee: pools[i].fee,
                    tickSpacing: pools[i].tickSpacing,
                    hooks: IHooks(address(0)),
                    hookData: bytes("")
                });
            }

            bytes memory actions = abi.encodePacked(
                uint8(Actions.SWAP_EXACT_IN),
                uint8(Actions.SETTLE_ALL),
                uint8(Actions.TAKE)
            );

            bytes[] memory params = new bytes[](3);

            Currency currencyIn = Currency.wrap(tokenIn);
            params[0] = abi.encode(
                IV4Router.ExactInputParams({
                    currencyIn: currencyIn,
                    path: path,
                    amountIn: uint128(amountIn),
                    amountOutMinimum: uint128(0)
                })
            );
            params[1] = abi.encode(currencyIn, amountIn);
            params[2] =
                abi.encode(Currency.wrap(tokenOut), receiver, uint256(0));
            swapData = abi.encode(actions, params);
        }
        uint256 tokenOutBalanceBefore;

        tokenOutBalanceBefore = tokenOut == address(0)
            ? receiver.balance
            : IERC20(tokenOut).balanceOf(receiver);

        executeActions(swapData);

        uint256 tokenOutBalanceAfter;

        tokenOutBalanceAfter = tokenOut == address(0)
            ? receiver.balance
            : IERC20(tokenOut).balanceOf(receiver);

        calculatedAmount = tokenOutBalanceAfter - tokenOutBalanceBefore;

        return calculatedAmount;
    }

    // necessary to convert bytes memory to bytes calldata
    function executeActions(bytes memory unlockData) public {
        // slither-disable-next-line unused-return
        poolManager.unlock(unlockData);
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            bool zeroForOne,
            TransferType transferType,
            address receiver,
            UniswapV4Pool[] memory pools
        )
    {
        if (data.length < 88) {
            revert UniswapV4Executor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        zeroForOne = (data[40] != 0);
        transferType = TransferType(uint8(data[41]));
        receiver = address(bytes20(data[42:62]));

        uint256 poolsLength = (data.length - 62) / 26; // 26 bytes per pool object
        pools = new UniswapV4Pool[](poolsLength);
        bytes memory poolsData = data[62:];
        uint256 offset = 0;
        for (uint256 i = 0; i < poolsLength; i++) {
            address intermediaryToken;
            uint24 fee;
            int24 tickSpacing;

            // slither-disable-next-line assembly
            assembly {
                intermediaryToken := mload(add(poolsData, add(offset, 20)))
                fee := shr(232, mload(add(poolsData, add(offset, 52))))
                tickSpacing := shr(232, mload(add(poolsData, add(offset, 55))))
            }
            pools[i] = UniswapV4Pool(intermediaryToken, fee, tickSpacing);
            offset += 26;
        }
    }

    function handleCallback(bytes calldata data)
        external
        returns (bytes memory)
    {
        verifyCallback(data);
        return _unlockCallback(data);
    }

    function verifyCallback(bytes calldata) public view onlyPoolManager {}

    function _pay(Currency token, address, uint256 amount) internal override {
        IERC20(Currency.unwrap(token)).safeTransfer(
            address(poolManager), amount
        );
    }

    function msgSender() public view override returns (address) {
        return address(this);
    }
}
