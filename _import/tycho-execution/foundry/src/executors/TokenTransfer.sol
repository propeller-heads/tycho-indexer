// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";

error TokenTransfer__InvalidPermit2();

contract TokenTransfer {
    using SafeERC20 for IERC20;

    IAllowanceTransfer public immutable permit2;

    enum TransferType {
        // Assume funds are in the TychoRouter - transfer into the pool
        TRANSFER,
        // Assume funds are in msg.sender's wallet - transferFrom into the pool
        TRANSFERFROM,
        // Assume funds are in msg.sender's wallet - permit2TransferFrom into the pool
        TRANSFERPERMIT2,
        // Assume funds have already been transferred into the pool. Do nothing.
        NONE
    }

    constructor(address _permit2) {
        if (_permit2 == address(0)) {
            revert TokenTransfer__InvalidPermit2();
        }
        permit2 = IAllowanceTransfer(_permit2);
    }

    function _transfer(
        IERC20 tokenIn,
        address sender,
        address receiver,
        uint256 amount,
        TransferType transferType
    ) internal {
        if (transferType == TransferType.TRANSFER) {
            tokenIn.safeTransfer(receiver, amount);
        } else if (transferType == TransferType.TRANSFERFROM) {
            // slither-disable-next-line arbitrary-send-erc20
            tokenIn.safeTransferFrom(sender, receiver, amount);
        } else if (transferType == TransferType.TRANSFERPERMIT2) {
            // Permit2.permit is already called from the TychoRouter
            permit2.transferFrom(
                sender, receiver, uint160(amount), address(tokenIn)
            );
        }
    }
}
