// SPDX-License-Identifier: UNLICENCED
pragma solidity ^0.8.0;

import "../interfaces/ISwapExecutor.sol";
import "./interfaces/ICurvePool.sol";
import "./interfaces/ICurvePoolNoReturn.sol";
import "./interfaces/ICurveCryptoPool.sol";
import "./interfaces/ICurvePoolNoReturn.sol";
import "./interfaces/ICurvePoolWithReturn.sol";
import {
    IERC20,
    SafeERC20
} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import "src/libraries/EfficientERC20.sol";

interface IWETH is IERC20 {
    function deposit() external payable;

    function withdraw(uint256) external;
}

contract CurveSwapExecutor is ISwapExecutor, ISwapExecutorErrors {
    using EfficientERC20 for IERC20;

    IWETH private constant weth =
        IWETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address private constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    function _decodeParams(bytes calldata data)
        internal
        pure
        returns (
            IERC20 tokenOut,
            address target,
            address receiver,
            uint8 poolType,
            int128 i,
            int128 j,
            bool tokenApprovalNeeded
        )
    {
        tokenOut = IERC20(address(bytes20(data[0:20])));
        target = address(bytes20(data[20:40]));
        receiver = address(bytes20(data[40:60]));
        poolType = uint8(data[60]);
        i = int128(uint128(uint8(data[61])));
        j = int128(uint128(uint8(data[62])));
        tokenApprovalNeeded = data[63] != 0;
    }

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 res)
    {
        (
            IERC20 tokenOut,
            address target,
            address receiver,
            uint8 poolType,
            int128 i,
            int128 j,
            bool tokenApprovalNeeded
        ) = _decodeParams(data);

        // Approve the token for the pool's address if `tokenApprovalNeeded` is
        // true
        if (tokenApprovalNeeded) {
            address tokenIn;
            // pool type 6 has a different function signature to get the coins
            if (poolType == 6) {
                tokenIn = ICurvePoolNoReturn(target).underlying_coins(int128(i));
            } else {
                tokenIn = ICurvePool(target).coins(uint256(uint128(i)));
            }
            IERC20(tokenIn).forceApprove(target, type(uint256).max);
        }
        if (poolType == 0) {
            // simple exchange with int128
            // e.g. AAVE, EURS
            res = ICurvePoolWithReturn(target).exchange(i, j, amountIn, 0);
            if (receiver != address(this)) {
                tokenOut.safeTransfer(receiver, res);
            }
        } else if (poolType == 1) {
            // simple exchange with int128 but no amountOut,
            // e.g. BUSD, HBTC, PAX, renBTC, sBTC, SUSD, USDT, Y, 3pool
            uint256 tokenOutBalanceBeforeSwap =
                tokenOut.balanceOf(address(this));
            ICurvePoolNoReturn(target).exchange(i, j, amountIn, 0);
            uint256 tokenOutBalanceAfterSwap = tokenOut.balanceOf(address(this));
            res = tokenOutBalanceAfterSwap - tokenOutBalanceBeforeSwap;
            if (receiver != address(this)) {
                tokenOut.safeTransfer(receiver, res);
            }
        } else if (poolType == 3) {
            // tricrypto case
            uint256 tokenOutBalanceBeforeSwap =
                tokenOut.balanceOf(address(this));
            ICurveCryptoPool(target).exchange(
                uint256(uint128(i)),
                uint256(uint128(j)),
                amountIn,
                0,
                false //TODO: Check if we can call the entrypoint without
                    // 'use_eth' as it's false by default.
            );
            uint256 tokenOutBalanceAfterSwap = tokenOut.balanceOf(address(this));
            res = tokenOutBalanceAfterSwap - tokenOutBalanceBeforeSwap;
            if (receiver != address(this)) {
                tokenOut.safeTransfer(receiver, res);
            }
        } else if (poolType == 4) {
            // (payable) ether based stableswaps - so far no liquidity
            // e.g. sETH, stETH, rETH, etc
            ICurveCryptoPool pool = ICurveCryptoPool(target);
            if (pool.coins(uint256(uint128(i))) == ETH) {
                weth.withdraw(amountIn);
                res = pool.exchange{value: amountIn}(i, j, amountIn, 0);
            } else {
                res = pool.exchange(i, j, amountIn, 0);
            }

            if (pool.coins(uint256(uint128(j))) == ETH) {
                weth.deposit{value: res}();
            }
            if (receiver != address(this)) {
                tokenOut.safeTransfer(receiver, res);
            }
        } else if (poolType == 5) {
            // metapool or lending pool interface using int128
            // e.g. AAVE
            res = ICurvePoolWithReturn(target).exchange_underlying(
                i, j, amountIn, 0
            );
            if (receiver != address(this)) {
                tokenOut.safeTransfer(receiver, res);
            }
        } else if (poolType == 6) {
            // metapool or lending pool interface using int128 no amountOut
            // returned
            // e.g. Y, Compound
            uint256 tokenOutBalanceBeforeSwap =
                tokenOut.balanceOf(address(this));
            ICurvePoolNoReturn(target).exchange_underlying(i, j, amountIn, 0);
            uint256 tokenOutBalanceAfterSwap = tokenOut.balanceOf(address(this));
            res = tokenOutBalanceAfterSwap - tokenOutBalanceBeforeSwap;
            if (receiver != address(this)) {
                tokenOut.safeTransfer(receiver, res);
            }
        } else if (poolType == 7) {
            // cryptov2 pool with two tokens
            // e.g. LDO/ETH
            res = ICurvePoolWithReturn(target).exchange(
                uint256(uint128(i)),
                uint256(uint128(j)),
                amountIn,
                0,
                false,
                receiver
            );
        } else if (poolType == 8) {
            // cryptov2 two tokens not factory pools ETH/CRV and ETH/CVX
            res = ICurvePoolWithReturn(target).exchange(
                uint256(uint128(i)), uint256(uint128(j)), amountIn, 0, false
            );
            if (receiver != address(this)) {
                tokenOut.safeTransfer(receiver, res);
            }
        } else {
            revert UnknownPoolType(poolType);
        }
    }
}
