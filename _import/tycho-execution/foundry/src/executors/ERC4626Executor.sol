// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

error ERC4626Executor__InvalidDataLength();
error ERC4626Executor__InvalidTarget();

contract ERC4626Executor is IExecutor {
    using SafeERC20 for IERC20;

    constructor() {}

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 amountOut, address tokenOut, address receiver)
    {
        address target;
        IERC20 tokenIn;

        (tokenIn, target, receiver) = _decodeData(data);

        if (address(tokenIn) == target) {
            // shares --> asset
            tokenOut = IERC4626(target).asset();
            amountOut =
                IERC4626(target).redeem(amountIn, receiver, address(this));
        } else if (address(tokenIn) == IERC4626(target).asset()) {
            // asset --> shares
            tokenOut = target;
            amountOut = IERC4626(target).deposit(amountIn, receiver);
        } else {
            revert ERC4626Executor__InvalidTarget();
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (IERC20 tokenIn, address target, address receiver)
    {
        if (data.length != 60) {
            revert ERC4626Executor__InvalidDataLength();
        }
        tokenIn = IERC20(address(bytes20(data[0:20])));
        target = address(bytes20(data[20:40]));
        receiver = address(bytes20(data[40:60]));
    }

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType baseTransferType,
            address receiver,
            address tokenIn
        )
    {
        if (data.length != 60) {
            revert ERC4626Executor__InvalidDataLength();
        }
        tokenIn = address(bytes20(data[0:20]));
        receiver = address(bytes20(data[20:40]));
        baseTransferType = RestrictTransferFrom.TransferType.ProtocolWillDebit;
    }
}
