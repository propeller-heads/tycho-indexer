// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";

error OneTransferFromOnly__AddressZero();
error OneTransferFromOnly__MultipleTransferFrom();

/**
 * @title OneTransferFromOnly - Restrict to one transferFrom on approved params per swap
 * @dev Restricts to one `transferFrom` (using `permit2` or regular `transferFrom`)
 * per swap, while ensuring that the `transferFrom` is only performed on the input
 * token and the input amount, from the msg.sender's wallet that calls the main swap
 * method. Reverts if multiple `transferFrom`s are attempted.
 */
contract OneTransferFromOnly {
    using SafeERC20 for IERC20;

    IAllowanceTransfer public immutable permit2;
    // keccak256("Dispatcher#TOKEN_IN_SLOT")
    uint256 private constant _TOKEN_IN_SLOT =
        0x66f353cfe8e3cbe0d03292348fbf0fca32e6e07fa0c2a52b4aac22193ac3b894;
    // keccak256("Dispatcher#AMOUNT_IN_SLOT")
    uint256 private constant _AMOUNT_IN_SLOT =
        0x1f40aa2d23d66d03722685ce02e5d3a95545dfc8e7c56d1026790aa30be48937;
    // keccak256("Dispatcher#IS_PERMIT2_SLOT")
    uint256 private constant _IS_PERMIT2_SLOT =
        0x3162c9d1175ca0ca7441f87984fdac41bbfdb13246f42c8bb4414d345da39e2a;
    // keccak256("Dispatcher#SENDER_SLOT")
    uint256 private constant _SENDER_SLOT =
        0x5dcc7974be5cb30f183f878073999aaa6620995b9e052ab5a713071ff60ae9b5;
    // keccak256("Dispatcher#IS_TRANSFER_EXECUTED_SLOT")
    uint256 private constant _IS_TRANSFER_EXECUTED_SLOT =
        0x1c64085c839fc2ff0f0aad20613eb6d056a1024e5990211e9eb30824dcd128c2;

    constructor(address _permit2) {
        if (_permit2 == address(0)) {
            revert OneTransferFromOnly__AddressZero();
        }
        permit2 = IAllowanceTransfer(_permit2);
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
    function _transfer(address receiver) internal {
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
            revert OneTransferFromOnly__MultipleTransferFrom();
        }
        assembly {
            tstore(_IS_TRANSFER_EXECUTED_SLOT, true)
        }
        if (isPermit2) {
            // Permit2.permit is already called from the TychoRouter
            permit2.transferFrom(sender, receiver, uint160(amount), tokenIn);
        } else {
            // slither-disable-next-line arbitrary-send-erc20
            IERC20(tokenIn).safeTransferFrom(sender, receiver, amount);
        }
    }
}
