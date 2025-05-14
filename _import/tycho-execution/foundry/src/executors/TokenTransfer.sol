// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";

error TokenTransfer__AddressZero();
error TokenTransfer__InvalidTransferType();

contract TokenTransfer {
    using SafeERC20 for IERC20;

    IAllowanceTransfer public immutable permit2;

    enum TransferType {
        // Assume funds are in the TychoRouter - transfer into the pool
        TRANSFER_TO_PROTOCOL,
        // Assume funds are in msg.sender's wallet - transferFrom into the pool
        TRANSFER_FROM_TO_PROTOCOL,
        // Assume funds are in msg.sender's wallet - permit2TransferFrom into the pool
        TRANSFER_PERMIT2_TO_PROTOCOL,
        // Assume funds are in msg.sender's wallet - but the pool requires it to be
        // in the router contract when calling swap - transferFrom into the router
        // contract
        TRANSFER_FROM_TO_ROUTER,
        // Assume funds are in msg.sender's wallet - but the pool requires it to be
        // in the router contract when calling swap - transferFrom into the router
        // contract using permit2
        TRANSFER_PERMIT2_TO_ROUTER,
        // Assume funds have already been transferred into the pool. Do nothing.
        NONE
    }

    constructor(address _permit2) {
        if (_permit2 == address(0)) {
            revert TokenTransfer__AddressZero();
        }
        permit2 = IAllowanceTransfer(_permit2);
    }

    function _transfer(
        address tokenIn,
        address sender,
        address receiver,
        uint256 amount,
        TransferType transferType
    ) internal {
        if (transferType == TransferType.NONE) {
            return;
        } else if (transferType == TransferType.TRANSFER_TO_PROTOCOL) {
            if (tokenIn == address(0)) {
                payable(receiver).transfer(amount);
            } else {
                IERC20(tokenIn).safeTransfer(receiver, amount);
            }
        } else if (transferType == TransferType.TRANSFER_FROM_TO_PROTOCOL) {
            // slither-disable-next-line arbitrary-send-erc20
            IERC20(tokenIn).safeTransferFrom(sender, receiver, amount);
        } else if (transferType == TransferType.TRANSFER_PERMIT2_TO_PROTOCOL) {
            // Permit2.permit is already called from the TychoRouter
            permit2.transferFrom(sender, receiver, uint160(amount), tokenIn);
        } else if (transferType == TransferType.TRANSFER_FROM_TO_ROUTER) {
            // slither-disable-next-line arbitrary-send-erc20
            IERC20(tokenIn).safeTransferFrom(sender, address(this), amount);
        } else if (transferType == TransferType.TRANSFER_PERMIT2_TO_ROUTER) {
            // Permit2.permit is already called from the TychoRouter
            permit2.transferFrom(
                sender, address(this), uint160(amount), tokenIn
            );
        } else {
            revert TokenTransfer__InvalidTransferType();
        }
    }
}
