// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";

error RestrictTransferFrom__AddressZero();
error RestrictTransferFrom__ExceededTransferFromAllowance();
error RestrictTransferFrom__UnknownTransferType();

/**
 * @title RestrictTransferFrom - Restrict transferFrom upto allowed amount of token
 * @dev Restricts to one `transferFrom` (using `permit2` or regular `transferFrom`)
 * per swap, while ensuring that the `transferFrom` is only performed on the input
 * token upto input amount, from the msg.sender's wallet that calls the main swap
 * method. Reverts if `transferFrom`s are attempted above this allowed amount.
 */
contract RestrictTransferFrom {
    using SafeERC20 for IERC20;

    IAllowanceTransfer public immutable permit2;
    // keccak256("Dispatcher#TOKEN_IN_SLOT")
    uint256 private constant _TOKEN_IN_SLOT =
        0x66f353cfe8e3cbe0d03292348fbf0fca32e6e07fa0c2a52b4aac22193ac3b894;
    // keccak256("Dispatcher#AMOUNT_ALLOWED_SLOT")
    uint256 private constant _AMOUNT_ALLOWED_SLOT =
        0xc76591aca92830b1554f3dcc7893e7519ec7c57bd4e64fec0c546d9078033291;
    // keccak256("Dispatcher#IS_PERMIT2_SLOT")
    uint256 private constant _IS_PERMIT2_SLOT =
        0x3162c9d1175ca0ca7441f87984fdac41bbfdb13246f42c8bb4414d345da39e2a;
    // keccak256("Dispatcher#SENDER_SLOT")
    uint256 private constant _SENDER_SLOT =
        0x5dcc7974be5cb30f183f878073999aaa6620995b9e052ab5a713071ff60ae9b5;
    // keccak256("Dispatcher#AMOUNT_SPENT_SLOT")
    uint256 private constant _AMOUNT_SPENT_SLOT =
        0x56044a5eb3aa5bd3ad908b7f15d1e8cb830836bb4ad178a0bf08955c94c40d30;

    constructor(address _permit2) {
        if (_permit2 == address(0)) {
            revert RestrictTransferFrom__AddressZero();
        }
        permit2 = IAllowanceTransfer(_permit2);
    }

    enum TransferType {
        TransferFrom,
        Transfer,
        None
    }

    // slither-disable-next-line assembly
    function _tstoreTransferFromInfo(
        address tokenIn,
        uint256 amountIn,
        bool isPermit2
    ) internal {
        assembly {
            tstore(_TOKEN_IN_SLOT, tokenIn)
            tstore(_AMOUNT_IN_SLOT, amountIn)
            tstore(_IS_PERMIT2_SLOT, isPermit2)
            tstore(_SENDER_SLOT, caller())
            tstore(_IS_TRANSFER_EXECUTED_SLOT, false)
        }
    }

    // slither-disable-next-line assembly
    function _transfer(
        address receiver,
        TransferType transferType,
        address tokenIn,
        uint256 amount
    ) internal {
        if (transferType == TransferType.TransferFrom){
            bool isPermit2;
            address sender;
            bool isTransferExecuted;
            assembly {
                tokenIn := tload(_TOKEN_IN_SLOT)
                amountPermitted := tload(_AMOUNT_IN_SLOT)
                isPermit2 := tload(_IS_PERMIT2_SLOT)
                sender := tload(_SENDER_SLOT)
                amountSpent := tload(_IS_TRANSFER_EXECUTED_SLOT)
            }
            if (amount + amountSpent > amountPermitted) {
                revert RestrictTransferFrom__ExceededTransferFromAllowance();
            }
            assembly {
                tstore(_AMOUNT_SPENT_SLOT, amount)
            }
            if (isPermit2) {
                // Permit2.permit is already called from the TychoRouter
                permit2.transferFrom(sender, receiver, uint160(amount), tokenIn);
            } else {
                // slither-disable-next-line arbitrary-send-erc20
                IERC20(tokenIn).safeTransferFrom(sender, receiver, amount);
            }
        } else if (transferType == TransferType.Transfer) {
            if (tokenIn == address(0)) {
                Address.sendValue(payable(receiver), amount);
            } else {
                IERC20(tokenIn).safeTransfer(receiver, amount);
            }
        } else if (transferType == TransferType.None) {
            return;
        } else {
            revert RestrictTransferFrom__UnknownTransferType();
        }
    }
}
