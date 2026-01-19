// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    IAllowanceTransfer
} from "@permit2/src/interfaces/IAllowanceTransfer.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Vault} from "./Vault.sol";

error RestrictTransferFrom__AddressZero();
error RestrictTransferFrom__ExceededTransferFromAllowance(
    uint256 allowedAmount, uint256 amountAttempted
);
error RestrictTransferFrom__DifferentTokenIn(
    address tokenIn, address tokenInStorage
);
error RestrictTransferFrom__UnknownTransferType();

/**
 * @title RestrictTransferFrom - Restrict transferFrom upto allowed amount of token
 * @dev Restricts `transferFrom` (using `permit2` or regular `transferFrom`) upto
 * allowed amount of token in per swap, while ensuring that the `transferFrom` is
 * only performed on the input token upto input amount, from the msg.sender's wallet
 * that calls the main swap method. Reverts if `transferFrom`s are attempted above
 * this allowed amount.
 */
contract RestrictTransferFrom is Vault {
    using SafeERC20 for IERC20;

    IAllowanceTransfer public immutable permit2;
    // keccak256("RestrictTransferFrom#TOKEN_IN_SLOT")
    uint256 private constant _TOKEN_IN_SLOT =
        0x25712b2458c26c244401cacab2c4d40a337e6c15af51d98c87ca8c05ed74935f;
    // keccak256("RestrictTransferFrom#AMOUNT_ALLOWED_SLOT")
    uint256 private constant _AMOUNT_ALLOWED_SLOT =
        0x9042309497172c3d7a894cb22c754029d2b44522a8039afc41f7d5ad87a35cb5;
    // keccak256("RestrictTransferFrom#IS_PERMIT2_SLOT")
    uint256 private constant _IS_PERMIT2_SLOT =
        0x8b09772a37ddaa0009affae61f4c227f5ae294cb166289f28313bcce05ea5358;
    // keccak256("RestrictTransferFrom#SENDER_SLOT")
    uint256 private constant _SENDER_SLOT =
        0x6249046ac25ba4612871a1715b1abd1de7cf9c973c5045a9b08ce3f441ce6e3a;

    constructor(address _permit2) {
        if (_permit2 == address(0)) {
            revert RestrictTransferFrom__AddressZero();
        }
        permit2 = IAllowanceTransfer(_permit2);
    }

    enum TransferType {
        TransferFrom,
        TransferFromAndProtocolWillDebit,
        Transfer,
        TransferNativeInMsgValue,
        ProtocolWillDebit,
        None
    }

    /**
     * @dev This function is used to store the transfer information in the
     * contract's storage. This is done as the first step in the swap process in TychoRouter.
     */
    // slither-disable-next-line assembly
    function _tstoreTransferFromInfo(
        address tokenIn,
        uint256 amountIn,
        bool isPermit2,
        bool isTransferFromAllowed
    ) internal {
        uint256 amountAllowed = amountIn;
        if (!isTransferFromAllowed) {
            amountAllowed = 0;
        }
        assembly {
            tstore(_TOKEN_IN_SLOT, tokenIn)
            tstore(_AMOUNT_ALLOWED_SLOT, amountAllowed)
            tstore(_IS_PERMIT2_SLOT, isPermit2)
            tstore(_SENDER_SLOT, caller())
        }
    }

    /**
     * @dev This function is used to transfer the tokens from the sender to the receiver.
     * This function is called within the Dispatcher before calling executors.
     * Handles 6 transfer scenarios:
     * - TransferFrom: Transfer from user wallet to protocol
     * - TransferFromAndProtocolWillDebit: Transfer from user wallet to router, protocol takes it
     * - Transfer: Transfer from router balance to protocol (could be from vault or previous swap)
     * - TransferNativeInMsgValue: Native ETH sent via msg.value (hardcoded in executor for security)
     * - ProtocolWillDebit: Protocol takes from router/vault
     * - None: Funds already transferred from previous pool
     */
    // slither-disable-next-line assembly
    function _transfer(
        address receiver,
        TransferType transferType,
        address tokenIn,
        uint256 amount
    ) internal {
        address sender;
        assembly {
            sender := tload(_SENDER_SLOT)
        }
        if (transferType == TransferType.TransferFrom) {
            _restrictTransferFrom(sender, amount, tokenIn);
            bool isPermit2;
            assembly {
                isPermit2 := tload(_IS_PERMIT2_SLOT)
            }
            if (isPermit2) {
                // Permit2.permit is already called from the TychoRouter
                // slither-disable-next-line calls-loop
                permit2.transferFrom(sender, receiver, uint160(amount), tokenIn);
            } else {
                // slither-disable-next-line arbitrary-send-erc20
                IERC20(tokenIn).safeTransferFrom(sender, receiver, amount);
            }
        } else if (
            transferType == TransferType.TransferFromAndProtocolWillDebit
        ) {
            _restrictTransferFrom(sender, amount, tokenIn);
            bool isPermit2;
            assembly {
                isPermit2 := tload(_IS_PERMIT2_SLOT)
            }
            if (isPermit2) {
                // Permit2.permit is already called from the TychoRouter
                // slither-disable-next-line calls-loop
                permit2.transferFrom(
                    sender, address(this), uint160(amount), tokenIn
                );
            } else {
                // slither-disable-next-line arbitrary-send-erc20
                IERC20(tokenIn).safeTransferFrom(sender, address(this), amount);
            }
            if (tokenIn != address(0)) {
                // Approve receiver (usually a pool/vault/router) to use the TychoRouter's funds
                IERC20(tokenIn).forceApprove(receiver, amount);
            }
        } else if (transferType == TransferType.Transfer) {
            // Transfer using the user's router balance.
            // This could mean the funds come from the user's vault (first swap)
            // or funds are in the router from the previous swap.
            _updateDeltaAccounting(tokenIn, -int256(amount));
            if (tokenIn == address(0)) {
                Address.sendValue(payable(receiver), amount);
            } else {
                IERC20(tokenIn).safeTransfer(receiver, amount);
            }
        } else if (transferType == TransferType.TransferNativeInMsgValue) {
            // Protocols like Fluid or Lido require us to send the ETH as
            // msg.value when calling the swap function from inside the executor.
            // This transfer type must be encoded from the executor for security purposes
            _updateDeltaAccounting(tokenIn, -int256(amount));
        } else if (transferType == TransferType.ProtocolWillDebit) {
            // Funds are either in the router from the previous swap, or will
            // be taken from our vault (in the case of the first swap).
            _updateDeltaAccounting(tokenIn, -int256(amount));
            if (tokenIn != address(0)) {
                IERC20(tokenIn).forceApprove(receiver, amount);
            }
        } else if (transferType == TransferType.None) {
            return;
        } else {
            revert RestrictTransferFrom__UnknownTransferType();
        }
    }

    // Assembly required for transient storage operations (tload/tstore)
    // slither-disable-next-line assembly
    function _restrictTransferFrom(
        address sender,
        uint256 amount,
        address tokenIn
    ) internal {
        //  This is important to prevent badly encoded split swaps from taking
        //  more than the input amount out of the user's wallet or vault balance.
        address tokenInStorage;
        uint256 amountAllowed;

        assembly {
            tokenInStorage := tload(_TOKEN_IN_SLOT)
            amountAllowed := tload(_AMOUNT_ALLOWED_SLOT)
        }
        if (amount > amountAllowed) {
            revert RestrictTransferFrom__ExceededTransferFromAllowance(
                amountAllowed, amount
            );
        }
        if (tokenIn != tokenInStorage) {
            revert RestrictTransferFrom__DifferentTokenIn(
                tokenIn, tokenInStorage
            );
        }
        amountAllowed -= amount;
        assembly {
            tstore(_AMOUNT_ALLOWED_SLOT, amountAllowed)
        }
    }
}
