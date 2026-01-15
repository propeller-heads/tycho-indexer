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
        returns (uint256 calculatedAmount, address tokenOut, address receiver)
    {
        address target;
        receiver;
        IERC20 tokenIn;
        bool approvalNeeded;

        (tokenIn, target, receiver, approvalNeeded) = _decodeData(data);
        if (approvalNeeded) {
            // slither-disable-next-line unused-return
            tokenIn.forceApprove(target, type(uint256).max);
        }

        if (address(tokenIn) == target) {
            // shares --> asset
            tokenOut = IERC4626(target).asset();
            calculatedAmount =
                IERC4626(target).redeem(amountIn, receiver, address(this));
        } else if (address(tokenIn) == IERC4626(target).asset()) {
            // asset --> shares
            tokenOut = target;
            calculatedAmount = IERC4626(target).deposit(amountIn, receiver);
        } else {
            revert ERC4626Executor__InvalidTarget();
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            IERC20 tokenIn,
            address target,
            address receiver,
            bool approvalNeeded
        )
    {
        if (data.length != 62) {
            revert ERC4626Executor__InvalidDataLength();
        }
        tokenIn = IERC20(address(bytes20(data[0:20])));
        target = address(bytes20(data[20:40]));
        receiver = address(bytes20(data[40:60]));
        approvalNeeded = data[61] != 0;
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
        if (data.length != 62) {
            revert ERC4626Executor__InvalidDataLength();
        }
        tokenIn = address(bytes20(data[0:20]));
        // Since the ERC4626 vault withdraws the funds from the msg.sender, the user's funds need to sent to the
        // TychoRouter initially (address(this))
        receiver = address(this);
        transferType = RestrictTransferFrom.TransferType(uint8(data[60]));
    }
}
