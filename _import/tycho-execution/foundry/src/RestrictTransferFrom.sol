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
error RestrictTransferFrom__NotAContract(address addr);
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
        if (_permit2.code.length == 0) {
            revert RestrictTransferFrom__NotAContract(_permit2);
        }
        permit2 = IAllowanceTransfer(_permit2);
    }

    enum TransferType {
        Transfer,
        TransferNativeInExecutor,
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
        bool useVault
    ) internal {
        uint256 amountAllowed;
        uint256 useVaultValue;

        if (useVault) {
            // Don't allow any transferFrom, and allow vault usage
            amountAllowed = 0;
            useVaultValue = 1;
        } else {
            // Allow transferFrom for the input amount
            amountAllowed = amountIn;
            useVaultValue = 0;
        }

        assembly {
            tstore(_TOKEN_IN_SLOT, tokenIn)
            tstore(_AMOUNT_ALLOWED_SLOT, amountAllowed)
            tstore(_IS_PERMIT2_SLOT, isPermit2)
            tstore(_SENDER_SLOT, caller())
            tstore(_USE_VAULT_SLOT, useVaultValue)
        }
    }

    /**
     * @dev Transfers tokens based on the transfer type and swap context.
     * This function is called within the Dispatcher before calling executors or in callbacks.
     *
     * The function determines the appropriate transfer strategy based on:
     * - transferType: The base transfer requirement from the executor
     * - isFirstSwap: Whether this is the first swap or subsequent
     * - isSplitSwap: Whether this is part of a split swap strategy
     * - inCallback: Whether being called from within a callback (e.g., UniswapV3)
     * - useVault: Whether using vault funds
     *
     * Handles 6 transfer scenarios (in order of execution):
     * 1. None - no transfer needed
     * 2. Native ETH sent via executor - perform accounting but do no transfers
     * 3. TransferFrom user wallet to router, then approve protocol to debit
     * 4. Protocol debits from router/vault (with approval if needed). No transferFrom needed
     * 5. TransferFrom user wallet directly to protocol
     * 6. Transfer from router balance to protocol (either from vault or previous swap funds)
     */
    function _transfer(
        address receiver,
        TransferType transferType,
        address tokenIn,
        uint256 amount,
        bool isFirstSwap,
        bool isSplitSwap,
        bool inCallback
    ) internal {
        // Scenario 1: No transfer needed. Likely called from outside the callback,
        // when funds are only transferred in callback for this protocol (e.g.
        // UniswapV3).
        if (transferType == TransferType.None) {
            return;
        }

        // Scenario 2: Native ETH sent via executor - accounting only
        if (transferType == TransferType.TransferNativeInExecutor) {
            // Protocols like Fluid or Lido require us to send the ETH as
            // msg.value when calling the swap function from inside the executor.
            _updateDeltaAccounting(tokenIn, -int256(amount));
            return;
        }

        // Determine if we need to transfer from user wallet (first swap + not using vault)
        bool useVault;
        // slither-disable-next-line assembly
        assembly {
            useVault := tload(_USE_VAULT_SLOT)
        }
        bool needsTransferFromUser = isFirstSwap && !useVault;

        // Scenario 3 & 4: Protocol will debit tokens from router
        if (transferType == TransferType.ProtocolWillDebit) {
            if (needsTransferFromUser) {
                // Scenario 3: First swap with user funds - transfer to router, then approve
                _transferFromUser(tokenIn, address(this), amount);
                _approveIfNeeded(tokenIn, receiver, amount);
            } else {
                // Scenario 4: Funds already in router (from vault or previous swap)
                _updateDeltaAccounting(tokenIn, -int256(amount));
                _approveIfNeeded(tokenIn, receiver, amount);
            }
            return;
        }

        if (transferType == TransferType.Transfer) {
            // Scenario 1 optimization: Tokens already at pool from previous swap.
            // This optimization assumes that the previous swap sent tokens
            // directly to the current pool (e.g. UniswapV2: Pool1 -> Pool2 -> Pool3).
            // We must NOT apply this optimization when in a callback context, because
            // callback-constrained protocols (UniswapV3, BalancerV3, etc.) hold tokens in the
            // router between swaps, and do not account for transfers before the callback.
            bool canUseSequentialSwapOptimization =
                !isFirstSwap && !isSplitSwap && !inCallback;
            if (canUseSequentialSwapOptimization) {
                return;
            }

            if (needsTransferFromUser) {
                // Scenario 5: First swap with user funds - transfer directly to pool
                _transferFromUser(tokenIn, receiver, amount);
            } else {
                // Scenario 6: Transfer from router balance to pool
                // This could mean the funds come from the user's vault (first swap with vault)
                // or funds are in the router from the previous swap.
                _updateDeltaAccounting(tokenIn, -int256(amount));
                IERC20(tokenIn).safeTransfer(receiver, amount);
            }
            return;
        }

        revert RestrictTransferFrom__UnknownTransferType();
    }

    /**
     * @dev Approves a receiver to spend tokens if receiver is not this contract.
     * For special cases like Rocketpool, the contract burns the user's balance
     * without physically transferring the input token, so an approval is not
     * always needed.
     */
    function _approveIfNeeded(address token, address receiver, uint256 amount)
        internal
    {
        if (receiver != address(this)) {
            IERC20(token).forceApprove(receiver, amount);
        }
    }

    /**
     * @dev Transfers tokens from user wallet using either Permit2 or regular transferFrom.
     * Validates the transfer doesn't exceed allowed amount and updates allowance tracking.
     */
    function _transferFromUser(address token, address receiver, uint256 amount)
        internal
    {
        // Validate and track allowance to prevent badly encoded split swaps from
        // taking more than the input amount out of the user's wallet
        address tokenInStorage;
        uint256 amountAllowed;
        address sender;
        bool isPermit2;

        // slither-disable-next-line assembly
        assembly {
            tokenInStorage := tload(_TOKEN_IN_SLOT)
            amountAllowed := tload(_AMOUNT_ALLOWED_SLOT)
            sender := tload(_SENDER_SLOT)
            isPermit2 := tload(_IS_PERMIT2_SLOT)
        }

        if (amount > amountAllowed) {
            revert RestrictTransferFrom__ExceededTransferFromAllowance(
                amountAllowed, amount
            );
        }
        if (token != tokenInStorage) {
            revert RestrictTransferFrom__DifferentTokenIn(token, tokenInStorage);
        }

        // Update remaining allowance
        amountAllowed -= amount;
        assembly {
            tstore(_AMOUNT_ALLOWED_SLOT, amountAllowed)
        }

        // Perform the actual transfer
        if (isPermit2) {
            // Permit2.permit is already called from the TychoRouter
            // slither-disable-next-line calls-loop
            permit2.transferFrom(sender, receiver, uint160(amount), token);
        } else {
            // slither-disable-next-line arbitrary-send-erc20
            IERC20(token).safeTransferFrom(sender, receiver, amount);
        }
    }
}
