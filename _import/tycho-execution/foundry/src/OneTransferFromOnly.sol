// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";

error TokenTransfer__AddressZero();

contract OneTransferFromOnly {
    using SafeERC20 for IERC20;

    // this is a stupid name but the compiler was complaining that we already had a permit2 variable in TychoRouter
    IAllowanceTransfer public immutable permit2lal;
    uint256 private constant _TOKEN_IN_SLOT = 123;
    uint256 private constant _AMOUNT_IN_SLOT = 124;
    uint256 private constant _IS_PERMIT2_SLOT = 125;
    uint256 private constant _SENDER_SLOT = 126;
    uint256 private constant _IS_TRANSFER_EXECUTED_SLOT = 127;

    constructor(address _permit2) {
        if (_permit2 == address(0)) {
            revert TokenTransfer__AddressZero();
        }
        permit2lal = IAllowanceTransfer(_permit2);
    }

    function tstoreTransferFromInfo(
        address tokenIn,
        address amountIn,
        bool isPermit2,
        address sender
    ) internal {
        assembly {
            tstore(_TOKEN_IN_SLOT, tokenIn)
            tstore(_AMOUNT_IN_SLOT, amountIn)
            tstore(_IS_PERMIT2_SLOT, isPermit2)
            tstore(_SENDER_SLOT, sender)
            tstore(_IS_TRANSFER_EXECUTED_SLOT, false)
        }
    }

    function _transfer(address receiver)
        // we could pass the amount and address too and compare to what is in the slots?
        internal
    {
        address tokenIn;
        uint256 amount;
        bool isPermit2;
        address sender;
        bool isTransferExecuted;
        assembly {
            tokenIn := tload(_TOKEN_IN_SLOT)
            amount := tload(_AMOUNT_IN_SLOT)
            isPermit2 := tload(_IS_PERMIT2_SLOT)
            sender := tload(_SENDER_SLOT)
            isTransferExecuted := tload(_IS_TRANSFER_EXECUTED_SLOT)
        }
        if (isTransferExecuted) {
            return; // or revert?
        }

        if (isPermit2) {
            // Permit2.permit is already called from the TychoRouter
            permit2lal.transferFrom(sender, receiver, uint160(amount), tokenIn);
            assembly {
                tstore(_IS_TRANSFER_EXECUTED_SLOT, true)
            }
        } else {
            // slither-disable-next-line arbitrary-send-erc20
            IERC20(tokenIn).safeTransferFrom(sender, receiver, amount);
            assembly {
                tstore(_IS_TRANSFER_EXECUTED_SLOT, true)
            }
        }
    }
}
