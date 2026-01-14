// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

error CurveExecutor__AddressZero();
error CurveExecutor__InvalidDataLength();

interface CryptoPool {
    // slither-disable-next-line naming-convention
    function exchange(uint256 i, uint256 j, uint256 dx, uint256 minDy)
        external
        payable;
}

interface StablePool {
    // slither-disable-next-line naming-convention
    function exchange(int128 i, int128 j, uint256 dx, uint256 minDy)
        external
        payable;
}

interface CryptoPoolETH {
    // slither-disable-start naming-convention
    function exchange(
        uint256 i,
        uint256 j,
        uint256 dx,
        uint256 minDy,
        bool useEth
    ) external payable;
    // slither-disable-end naming-convention
}

contract CurveExecutor is IExecutor {
    using SafeERC20 for IERC20;

    address public immutable NATIVE_TOKEN;

    constructor(address _nativeToken) {
        if (_nativeToken == address(0)) {
            revert CurveExecutor__AddressZero();
        }
        NATIVE_TOKEN = _nativeToken;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount, address tokenOut, address receiver)
    {
        if (data.length != 85) {
            revert CurveExecutor__InvalidDataLength();
        }
        address tokenIn;
        address pool;
        uint8 poolType;
        int128 i;
        int128 j;
        bool approvalNeeded;
        (tokenIn, tokenOut, pool, poolType, i, j, approvalNeeded, receiver) =
            _decodeData(data);

        if (approvalNeeded && tokenIn != NATIVE_TOKEN) {
            // slither-disable-next-line unused-return
            IERC20(tokenIn).forceApprove(address(pool), type(uint256).max);
        }

        /// Inspired by Curve's router contract: https://github.com/curvefi/curve-router-ng/blob/9ab006ca848fc7f1995b6fbbecfecc1e0eb29e2a/contracts/Router.vy#L44
        uint256 balanceBefore = _balanceOf(tokenOut);

        uint256 ethAmount = 0;
        if (tokenIn == NATIVE_TOKEN) {
            ethAmount = amountIn;
        }

        if (poolType == 1 || poolType == 10) {
            // stable and stable_ng
            // slither-disable-next-line arbitrary-send-eth
            StablePool(pool).exchange{value: ethAmount}(i, j, amountIn, 0);
        } else {
            // crypto or llamma
            if (tokenIn == NATIVE_TOKEN || tokenOut == NATIVE_TOKEN) {
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
        uint256 amountOut = balanceAfter - balanceBefore;

        if (receiver != address(this)) {
            if (tokenOut == NATIVE_TOKEN) {
                Address.sendValue(payable(receiver), amountOut);
            } else {
                IERC20(tokenOut).safeTransfer(receiver, amountOut);
            }
        }
        calculatedAmount = amountOut;
        if (tokenOut == NATIVE_TOKEN) {
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
            int128 j,
            bool approvalNeeded,
            address receiver
        )
    {
        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        pool = address(bytes20(data[40:60]));
        poolType = uint8(data[60]);
        i = int128(uint128(uint8(data[61])));
        j = int128(uint128(uint8(data[62])));
        approvalNeeded = data[63] != 0;
        receiver = address(bytes20(data[65:85]));
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
        balance = token == NATIVE_TOKEN
            ? address(this).balance
            : IERC20(token).balanceOf(address(this));
    }

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        tokenIn = address(bytes20(data[0:20]));
        transferType = RestrictTransferFrom.TransferType(uint8(data[64]));
        // Since the curve pool withdraws the funds from the msg.sender, the user's funds need to sent to the
        // TychoRouter initially (address(this))
        receiver = address(this);
    }
}
