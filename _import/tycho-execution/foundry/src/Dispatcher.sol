// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {RestrictTransferFrom} from "./RestrictTransferFrom.sol";

error Dispatcher__UnapprovedExecutor(address executor);
error Dispatcher__NonContractExecutor();
error Dispatcher__InvalidDataLength();
error Dispatcher__AddressZero();

/**
 * @title Dispatcher - Dispatch execution to external contracts
 * @dev Provides the ability to delegate execution of swaps to external
 *  contracts. This allows dynamically adding new supported protocols
 *  without needing to upgrade any contracts. External contracts will
 *  be called using delegatecall so they can share state with the main
 *  contract if needed.
 *
 *  Note: Executor contracts need to implement the IExecutor interface unless
 *  an alternate selector is specified.
 */
contract Dispatcher is RestrictTransferFrom {
    mapping(address => bool) public executors;

    // keccak256("Dispatcher#CURRENTLY_SWAPPING_EXECUTOR_SLOT")
    uint256 private constant _CURRENTLY_SWAPPING_EXECUTOR_SLOT =
        0x098a7a3b47801589e8cdf9ec791b93ad44273246946c32ef1fc4dbe45390c80e;
    // keccak256("Dispatcher#IS_SPLIT_SWAP_SLOT")
    uint256 private constant _IS_SPLIT_SWAP_SLOT =
        0x7b3c4e5f6a8d9e0f1c2b3a4d5e6f7c8d9e0f1c2b3a4d5e6f7c8d9e0f1c2b3a4d;

    event ExecutorSet(address indexed executor);
    event ExecutorRemoved(address indexed executor);

    constructor(address _permit2) RestrictTransferFrom(_permit2) {
        if (_permit2 == address(0)) {
            revert Dispatcher__AddressZero();
        }
    }

    /**
     * @dev Adds or replaces an approved executor contract address if it is a
     *  contract.
     * @param target address of the executor contract
     */
    function _setExecutor(address target) internal {
        if (target.code.length == 0) {
            revert Dispatcher__NonContractExecutor();
        }
        executors[target] = true;
        emit ExecutorSet(target);
    }

    /**
     * @dev Removes an approved executor contract address
     * @param target address of the executor contract
     */
    function _removeExecutor(address target) internal {
        delete executors[target];
        emit ExecutorRemoved(target);
    }

    /**
     * @dev Calls an executor, assumes swap.protocolData contains
     *  protocol-specific data required by the executor.
     */
    // slither-disable-next-line delegatecall-loop,assembly,controlled-delegatecall
    function _callSwapOnExecutor(
        address executor,
        uint256 amount,
        bytes calldata data,
        bool isFirstSwap,
        bool isSplitSwap,
        address receiver
    ) internal returns (uint256 calculatedAmount) {
        if (!executors[executor]) {
            revert Dispatcher__UnapprovedExecutor(executor);
        }

        assembly {
            tstore(_CURRENTLY_SWAPPING_EXECUTOR_SLOT, executor)
            tstore(_IS_FIRST_SWAP_SLOT, isFirstSwap)
            tstore(_IS_SPLIT_SWAP_SLOT, isSplitSwap)
        }

        // slither-disable-next-line calls-loop
        (bool transferDataSuccess, bytes memory transferData) = executor.staticcall(
            abi.encodeWithSelector(IExecutor.getTransferData.selector, data)
        );

        if (!transferDataSuccess) {
            revert(
                string(
                    transferData.length > 0
                        ? transferData
                        : abi.encodePacked("Getting transfer data failed")
                )
            );
        }

        (
            RestrictTransferFrom.TransferType baseType,
            address transferReceiver,
            address tokenIn
        ) = abi.decode(
            transferData, (RestrictTransferFrom.TransferType, address, address)
        );

        // Determine TransferType based on executor characteristics (not from callback)
        RestrictTransferFrom.TransferType transferType =
            _determineTransferType(baseType, isFirstSwap, isSplitSwap, false);
        _transfer(transferReceiver, transferType, tokenIn, amount);

        // slither-disable-next-line controlled-delegatecall,low-level-calls,calls-loop
        (bool success, bytes memory result) = executor.delegatecall(
            abi.encodeWithSelector(
                IExecutor.swap.selector, amount, data, receiver
            )
        );

        // Clear transient storage in case no callback was performed
        assembly {
            tstore(_CURRENTLY_SWAPPING_EXECUTOR_SLOT, 0)
            tstore(_IS_FIRST_SWAP_SLOT, 0)
            tstore(_IS_SPLIT_SWAP_SLOT, 0)
        }

        if (!success) {
            revert(
                string(
                    result.length > 0
                        ? result
                        : abi.encodePacked("Execution failed")
                )
            );
        }

        address tokenOut;
        (calculatedAmount, tokenOut) = abi.decode(result, (uint256, address));

        // Update delta accounting (transient storage) if tokens stayed in router
        if (receiver == address(this)) {
            // slither-disable-next-line calls-loop
            _updateDeltaAccounting(tokenOut, int256(calculatedAmount));
        }
    }

    // keccak256("Dispatcher#IS_FIRST_SWAP_SLOT")
    uint256 private constant _IS_FIRST_SWAP_SLOT =
        0x8c47a7e3f4c2e1b5a6d9f0e8c7b3a2d1e4f5c6b7a8d9e0f1c2b3a4d5e6f7c8d9;

    /**
     * @dev Determines the appropriate TransferType based on executor characteristics and context.
     * @param baseType The base transfer type from the executor (None, ProtocolWillDebit, or Transfer)
     * @param isFirstSwap True if this is the first swap in a sequence (funds come from user), false if subsequent (funds already in router)
     * @param isSplitSwap True if this is part of a split swap strategy
     * @param inCallback True if being called from within a callback (e.g., UniswapV3 callback), false if called before swap
     * @return transferType The determined transfer type
     */
    function _determineTransferType(
        RestrictTransferFrom.TransferType baseType,
        bool isFirstSwap,
        bool isSplitSwap,
        bool inCallback
    ) internal view returns (RestrictTransferFrom.TransferType) {
        // If base type is None or TransferNativeInExecutor, return as-is
        if (
            baseType == RestrictTransferFrom.TransferType.None
                || baseType
                    == RestrictTransferFrom.TransferType
                    .TransferNativeInExecutor
        ) {
            return baseType;
        }

        // Check if we're using vault funds (tokens already in router)
        // We must load from transient storage, since, if we call via callback
        // there's no other way to know which top-level method called this (i.e.
        // singleSwap, splitSwapPermit2, etc...)
        bool useVault;
        // slither-disable-next-line assembly
        assembly {
            useVault := tload(_USE_VAULT_SLOT)
        }

        // Determine if we need to use TransferFrom variant (user wallet funds)
        bool needsTransferFromUser = isFirstSwap && !useVault;

        // Determine transfer type based on base type and context
        if (baseType == RestrictTransferFrom.TransferType.ProtocolWillDebit) {
            // Protocol expects tokens in router and will debit
            if (needsTransferFromUser) {
                // First swap with user funds: transfer from user to router, then approve protocol
                return RestrictTransferFrom.TransferType
                    .TransferFromAndProtocolWillDebit;
            }
        } else if (baseType == RestrictTransferFrom.TransferType.Transfer) {
            // Protocol expects tokens to be transferred to pool
            if (!isFirstSwap && !isSplitSwap && !inCallback) {
                // Sequential swap optimization - tokens already at pool from previous swap.
                // This optimization assumes that in a sequential swap, the previous swap sent tokens
                // directly to the current pool (e.g., UniswapV2 style: Pool1 -> Pool2 -> Pool3).
                // CRITICAL: We must NOT apply this optimization when in a callback context, because
                // callback-constrained protocols (UniswapV3, BalancerV3, etc.) hold tokens in the
                // router between swaps, not at the pool. In callbacks, tokens must be transferred
                // from router to pool, so we need to respect the base Transfer type.
                return RestrictTransferFrom.TransferType.None;
            } else if (needsTransferFromUser) {
                // First swap with user funds: transfer from user directly to pool
                return RestrictTransferFrom.TransferType.TransferFrom;
            }
        }

        return baseType;
    }

    // slither-disable-next-line assembly
    function _callHandleCallbackOnExecutor(bytes calldata data)
        internal
        returns (bytes memory)
    {
        address executor;
        bool isFirstSwap;
        bool isSplitSwap;
        assembly {
            executor := tload(_CURRENTLY_SWAPPING_EXECUTOR_SLOT)
            isFirstSwap := tload(_IS_FIRST_SWAP_SLOT)
            isSplitSwap := tload(_IS_SPLIT_SWAP_SLOT)
        }

        if (!executors[executor]) {
            revert Dispatcher__UnapprovedExecutor(executor);
        }

        (bool transferDataSuccess, bytes memory transferData) = executor.delegatecall(
            abi.encodeWithSelector(
                ICallback.getCallbackTransferData.selector, data
            )
        );

        if (!transferDataSuccess) {
            revert(
                string(
                    transferData.length > 0
                        ? transferData
                        : abi.encodePacked("Getting transfer data failed")
                )
            );
        }

        (
            RestrictTransferFrom.TransferType baseType,
            address receiver,
            address tokenIn,
            uint256 amount
        ) = abi.decode(
            transferData,
            (RestrictTransferFrom.TransferType, address, address, uint256)
        );

        // Determine TransferType for callback (called from callback context)
        RestrictTransferFrom.TransferType transferType =
            _determineTransferType(baseType, isFirstSwap, isSplitSwap, true);
        _transfer(receiver, transferType, tokenIn, amount);

        // slither-disable-next-line controlled-delegatecall,low-level-calls
        (bool success, bytes memory result) = executor.delegatecall(
            abi.encodeWithSelector(ICallback.handleCallback.selector, data)
        );

        if (!success) {
            revert(
                string(
                    result.length > 0
                        ? result
                        : abi.encodePacked("Callback failed")
                )
            );
        }

        // to prevent multiple callbacks
        assembly {
            tstore(_CURRENTLY_SWAPPING_EXECUTOR_SLOT, 0)
            tstore(_IS_FIRST_SWAP_SLOT, 0)
            tstore(_IS_SPLIT_SWAP_SLOT, 0)
        }

        // The final callback result should not be ABI encoded. That is why we are decoding here.
        // ABI encoding is very gas expensive and we want to avoid it if possible.
        // The result from `handleCallback` is always ABI encoded.
        bytes memory decodedResult = abi.decode(result, (bytes));
        return decodedResult;
    }

    function _callCanReceiveFromPreviousSwap(
        address executor,
        bytes calldata data
    ) internal returns (bool isOptimizable, address receiver) {
        if (!executors[executor]) {
            revert Dispatcher__UnapprovedExecutor(executor);
        }
        // slither-disable-next-line calls-loop
        (bool success, bytes memory optimizableData) = executor.staticcall(
            abi.encodeWithSelector(
                IExecutor.canReceiveFromPreviousSwap.selector, data
            )
        );

        if (!success) {
            revert(
                string(
                    optimizableData.length > 0
                        ? optimizableData
                        : abi.encodePacked(
                            "Getting protocol optimizable data failed"
                        )
                )
            );
        }

        (isOptimizable, receiver) = abi.decode(optimizableData, (bool, address));
    }
}
