// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {TransferManager} from "../TransferManager.sol";
import {TychoRouter} from "../TychoRouter.sol";

error CurveExecutor__AddressZero();
error CurveExecutor__InvalidDataLength();

interface CryptoPool {
    function exchange(uint256 i, uint256 j, uint256 dx, uint256 minDy)
        external
        payable;
}

interface StablePool {
    function exchange(int128 i, int128 j, uint256 dx, uint256 minDy)
        external
        payable;
}

interface CryptoPoolETH {
    function exchange(
        uint256 i,
        uint256 j,
        uint256 dx,
        uint256 minDy,
        bool useEth
    ) external payable;
}

contract CurveExecutor is IExecutor {
    using SafeERC20 for IERC20;

    address public immutable nativeToken;
    address public immutable stEthAddress;
    bool public immutable hasStETH;

    constructor(address nativeToken_, address stEthAddress_) {
        if (nativeToken_ == address(0)) {
            revert CurveExecutor__AddressZero();
        }
        nativeToken = nativeToken_;

        if (stEthAddress_ != address(0)) {
            hasStETH = true;
        } else {
            hasStETH = false;
        }
        stEthAddress = stEthAddress_;
    }

    function fundsExpectedAddress(
        bytes calldata /* data */
    )
        external
        view
        returns (address receiver)
    {
        return msg.sender;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 amountOut, address tokenOut)
    {
        if (data.length != 63) {
            revert CurveExecutor__InvalidDataLength();
        }
        address tokenIn;
        address pool;
        uint8 poolType;
        int128 i;
        int128 j;
        (tokenIn, tokenOut, pool, poolType, i, j) = _decodeData(data);

        /// Inspired by Curve's router contract: https://github.com/curvefi/curve-router-ng/blob/9ab006ca848fc7f1995b6fbbecfecc1e0eb29e2a/contracts/Router.vy#L44
        uint256 balanceBefore = _balanceOf(tokenOut);

        uint256 ethAmount = 0;
        if (tokenIn == nativeToken) {
            ethAmount = amountIn;
        }

        if (poolType == 1 || poolType == 10) {
            // stable and stable_ng
            // slither-disable-next-line arbitrary-send-eth
            StablePool(pool).exchange{value: ethAmount}(i, j, amountIn, 0);
        } else {
            // crypto or llamma
            if (tokenIn == nativeToken || tokenOut == nativeToken) {
                // slither-disable-next-line arbitrary-send-eth
                CryptoPoolETH(pool).exchange{value: ethAmount}(
                    uint256(int256(i)), uint256(int256(j)), amountIn, 0, true
                );
            } else {
                CryptoPool(pool)
                    .exchange(
                        uint256(int256(i)), uint256(int256(j)), amountIn, 0
                    );
            }
        }

        uint256 balanceAfter = _balanceOf(tokenOut);
        amountOut = balanceAfter - balanceBefore;

        uint256 castRemainderWei = 0;

        if (receiver != address(this)) {
            if (tokenOut == nativeToken) {
                Address.sendValue(payable(receiver), amountOut);
            } else {
                // Due to rounding errors, 1 wei might get lost
                IERC20(tokenOut).safeTransfer(receiver, amountOut);
            }

            if (hasStETH && tokenOut == stEthAddress) {
                castRemainderWei = IERC20(stEthAddress).balanceOf(address(this))
                    - balanceBefore;

                amountOut -= castRemainderWei;
            }
        }

        // This is necessary because Curve's native token is 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE and TychoRouter
        // uses the address(0) instead. The tokenOut is then later used on some internal accounting across the entire
        // swap by the TychoRouter, so it is relevant that we are consistent.
        if (tokenOut == nativeToken) {
            tokenOut = address(0);
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            address pool,
            uint8 poolType,
            int128 i,
            int128 j
        )
    {
        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        pool = address(bytes20(data[40:60]));
        poolType = uint8(data[60]);
        i = int128(uint128(uint8(data[61])));
        j = int128(uint128(uint8(data[62])));
    }

    /**
     * @dev Even though this contract is mostly called through delegatecall, we still want to be able to receive ETH.
     * This is needed when using the executor directly and it makes testing easier.
     * There are some curve pools that take ETH directly.
     */
    receive() external payable {
        require(msg.sender.code.length != 0);
    }

    function _balanceOf(address token) internal view returns (uint256 balance) {
        balance = token == nativeToken
            ? address(this).balance
            : IERC20(token).balanceOf(address(this));
    }

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        tokenIn = address(bytes20(data[0:20]));
        if (tokenIn == nativeToken) {
            // ETH transfers are handled in the Executor, so we need to set the transferType to TransferNativeInExecutor
            // to update the delta accounting accordingly.
            tokenIn = address(0);
            transferType = TransferManager.TransferType.TransferNativeInExecutor;
        } else {
            transferType = TransferManager.TransferType.ProtocolWillDebit;
        }
        // The receiver of the funds will be the pool contract. This is only relevant
        // for performing an approval in the case of ProtocolWillDebit.
        receiver = address(bytes20(data[40:60]));
    }
}
