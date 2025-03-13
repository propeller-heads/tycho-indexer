// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";

error ExecutorTransferMethods__InvalidPermit2();

contract ExecutorTransferMethods {
    using SafeERC20 for IERC20;

    IAllowanceTransfer public immutable permit2;

    enum TransferMethod {
        TRANSFER,
        TRANSFERFROM,
        TRANSFERPERMIT2,
        NONE
    }

    constructor(address _permit2) {
        if (_permit2 == address(0)) {
            revert ExecutorTransferMethods__InvalidPermit2();
        }
        permit2 = IAllowanceTransfer(_permit2);
    }

    function _transfer(
        IERC20 tokenIn,
        address sender,
        address receiver,
        uint256 amount,
        TransferMethod method
    ) internal {
        if (method == TransferMethod.TRANSFER) {
            tokenIn.safeTransfer(receiver, amount);
        } else if (method == TransferMethod.TRANSFERFROM) {
            tokenIn.safeTransferFrom(msg.sender, receiver, amount);
        } else if (method == TransferMethod.TRANSFERPERMIT2) {
            // Permit2.permit is called from the TychoRouter
            permit2.transferFrom(
                sender,
                receiver, // Does this work if receiver is not address(this)?
                uint160(amount),
                address(tokenIn)
            );
        } else {
            // Funds are likely already in pool. Do nothing.
        }
    }
}
