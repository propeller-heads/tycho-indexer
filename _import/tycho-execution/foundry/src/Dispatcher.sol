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
abstract contract Dispatcher is RestrictTransferFrom {
    mapping(address => bool) public executors;

    // keccak256("Dispatcher#CURRENTLY_SWAPPING_EXECUTOR_SLOT")
    uint256 private constant _CURRENTLY_SWAPPING_EXECUTOR_SLOT =
        0x098a7a3b47801589e8cdf9ec791b93ad44273246946c32ef1fc4dbe45390c80e;

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

    function _updateDeltaAccounting(address token, int256 deltaChange)
        internal
        virtual;

    /**
     * @dev Calls an executor, assumes swap.protocolData contains
     *  protocol-specific data required by the executor.
     */
    // slither-disable-next-line delegatecall-loop,assembly,controlled-delegatecall
    function _callSwapOnExecutor(
        address executor,
        uint256 amount,
        bytes calldata data
    ) internal returns (uint256 calculatedAmount) {
        if (!executors[executor]) {
            revert Dispatcher__UnapprovedExecutor(executor);
        }

        assembly {
            tstore(_CURRENTLY_SWAPPING_EXECUTOR_SLOT, executor)
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
            RestrictTransferFrom.TransferType transferType,
            address transferReceiver,
            address tokenIn
        ) = abi.decode(
            transferData, (RestrictTransferFrom.TransferType, address, address)
        );
        _transfer(transferReceiver, transferType, tokenIn, amount);

        // slither-disable-next-line controlled-delegatecall,low-level-calls,calls-loop
        (bool success, bytes memory result) = executor.delegatecall(
            abi.encodeWithSelector(IExecutor.swap.selector, amount, data)
        );

        // Clear transient storage in case no callback was performed
        assembly {
            tstore(_CURRENTLY_SWAPPING_EXECUTOR_SLOT, 0)
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
        address receiver;
        (calculatedAmount, tokenOut, receiver) =
            abi.decode(result, (uint256, address, address));

        // Credit vault if tokens stayed in router
        if (receiver == address(this)) {
            // slither-disable-next-line calls-loop
            _updateDeltaAccounting(tokenOut, int256(calculatedAmount));
        }
    }

    // slither-disable-next-line assembly
    function _callHandleCallbackOnExecutor(bytes calldata data)
        internal
        returns (bytes memory)
    {
        address executor;
        assembly {
            executor := tload(_CURRENTLY_SWAPPING_EXECUTOR_SLOT)
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
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn,
            uint256 amount
        ) = abi.decode(
            transferData,
            (RestrictTransferFrom.TransferType, address, address, uint256)
        );
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
        }

        // The final callback result should not be ABI encoded. That is why we are decoding here.
        // ABI encoding is very gas expensive and we want to avoid it if possible.
        // The result from `handleCallback` is always ABI encoded.
        bytes memory decodedResult = abi.decode(result, (bytes));
        return decodedResult;
    }
}
