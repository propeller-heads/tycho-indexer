// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {IFeeCalculator} from "@interfaces/IFeeCalculator.sol";
import {FeeRecipient} from "../lib/FeeStructs.sol";
import {RestrictTransferFrom} from "./RestrictTransferFrom.sol";

error Dispatcher__UnapprovedExecutor(address executor);
error Dispatcher__ExecutorIsTimelocked(address executor);
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
    mapping(address => uint256) public executorsActivationTimestamp;

    // keccak256("Dispatcher#CURRENTLY_SWAPPING_EXECUTOR_SLOT")
    uint256 private constant _CURRENTLY_SWAPPING_EXECUTOR_SLOT =
        0x098a7a3b47801589e8cdf9ec791b93ad44273246946c32ef1fc4dbe45390c80e;
    // keccak256("Dispatcher#IS_SPLIT_SWAP_SLOT")
    uint256 private constant _IS_SPLIT_SWAP_SLOT =
        0x7b3c4e5f6a8d9e0f1c2b3a4d5e6f7c8d9e0f1c2b3a4d5e6f7c8d9e0f1c2b3a4d;
    // keccak256("Dispatcher#IS_FIRST_SWAP_SLOT")
    uint256 private constant _IS_FIRST_SWAP_SLOT =
        0x8c47a7e3f4c2e1b5a6d9f0e8c7b3a2d1e4f5c6b7a8d9e0f1c2b3a4d5e6f7c8d9;

    uint256 public constant DELAY_EXECUTOR_ACTIVATION = 3 days;

    event ExecutorSet(address indexed executor, uint256 timelockExpiresAt);
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

        uint256 timelockExpiresAt = block.timestamp + DELAY_EXECUTOR_ACTIVATION;
        executorsActivationTimestamp[target] = uint256(timelockExpiresAt);
        emit ExecutorSet(target, timelockExpiresAt);
    }

    /**
     * @dev Removes an approved executor contract address
     * @param target address of the executor contract
     */
    function _removeExecutor(address target) internal {
        delete executorsActivationTimestamp[target];
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
        uint256 activationTimestamp = executorsActivationTimestamp[executor];

        // slither-disable-next-line incorrect-equality
        if (activationTimestamp == 0) {
            revert Dispatcher__UnapprovedExecutor(executor);
        }
        if (block.timestamp < activationTimestamp) {
            revert Dispatcher__ExecutorIsTimelocked(executor);
        }

        assembly {
            tstore(_CURRENTLY_SWAPPING_EXECUTOR_SLOT, executor)
            tstore(_IS_FIRST_SWAP_SLOT, isFirstSwap)
            tstore(_IS_SPLIT_SWAP_SLOT, isSplitSwap)
        }

        // slither-disable-next-line calls-loop
        (bool transferDataSuccess, bytes memory transferData) = executor
            .staticcall(
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
                transferData,
                (RestrictTransferFrom.TransferType, address, address)
            );

        _transfer(
            transferReceiver,
            transferType,
            tokenIn,
            amount,
            isFirstSwap,
            isSplitSwap,
            false
        );

        // slither-disable-next-line controlled-delegatecall,low-level-calls,calls-loop
        (bool success, bytes memory result) = executor.delegatecall(
            abi.encodeWithSelector(
                IExecutor.swap.selector,
                amount,
                data,
                receiver
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

    // slither-disable-next-line assembly
    function _callHandleCallbackOnExecutor(
        bytes calldata data
    ) internal returns (bytes memory) {
        address executor;
        bool isFirstSwap;
        bool isSplitSwap;
        assembly {
            executor := tload(_CURRENTLY_SWAPPING_EXECUTOR_SLOT)
            isFirstSwap := tload(_IS_FIRST_SWAP_SLOT)
            isSplitSwap := tload(_IS_SPLIT_SWAP_SLOT)
        }

        uint256 activationTimestamp = executorsActivationTimestamp[executor];

        // slither-disable-next-line incorrect-equality
        if (activationTimestamp == 0) {
            revert Dispatcher__UnapprovedExecutor(executor);
        }
        if (block.timestamp < activationTimestamp) {
            revert Dispatcher__ExecutorIsTimelocked(executor);
        }

        (bool transferDataSuccess, bytes memory transferData) = executor
            .delegatecall(
                abi.encodeWithSelector(
                    ICallback.getCallbackTransferData.selector,
                    data
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

        _transfer(
            receiver,
            transferType,
            tokenIn,
            amount,
            isFirstSwap,
            isSplitSwap,
            true
        );

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

    function _callFundsExpectedAddress(
        address executor,
        bytes calldata data
    ) internal view returns (address receiver) {
        uint256 activationTimestamp = executorsActivationTimestamp[executor];

        // slither-disable-next-line incorrect-equality
        if (activationTimestamp == 0) {
            revert Dispatcher__UnapprovedExecutor(executor);
        }
        if (block.number < activationTimestamp) {
            revert Dispatcher__ExecutorIsTimelocked(executor);
        }

        // slither-disable-next-line calls-loop,low-level-calls
        (bool success, bytes memory receiverData) = executor.staticcall(
            abi.encodeWithSelector(
                IExecutor.fundsExpectedAddress.selector,
                data
            )
        );

        if (!success) {
            revert(
                string(
                    receiverData.length > 0
                        ? receiverData
                        : abi.encodePacked(
                            "Getting protocol expected address failed"
                        )
                )
            );
        }

        receiver = abi.decode(receiverData, (address));
    }

    function _callGetEffectiveRouterFeeOnOutput(
        address feeCalculator
    ) internal view returns (uint16 routerFeeOnOutputBps) {
        // slither-disable-next-line calls-loop,low-level-calls
        (bool success, bytes memory feeData) = feeCalculator.staticcall(
            abi.encodeWithSelector(
                IFeeCalculator.getEffectiveRouterFeeOnOutput.selector,
                msg.sender
            )
        );

        if (!success) {
            revert(
                string(
                    feeData.length > 0
                        ? feeData
                        : abi.encodePacked("Getting router fee failed")
                )
            );
        }

        routerFeeOnOutputBps = abi.decode(feeData, (uint16));
    }

    function _callCalculateFee(
        address feeCalculator,
        uint256 amountIn,
        uint16 clientFeeBps,
        address clientFeeReceiver
    )
        internal
        view
        returns (uint256 amountOut, FeeRecipient[] memory feeRecipients)
    {
        // slither-disable-next-line calls-loop,low-level-calls
        (bool success, bytes memory feeData) = feeCalculator.staticcall(
            abi.encodeWithSelector(
                IFeeCalculator.calculateFee.selector,
                amountIn,
                msg.sender,
                clientFeeBps,
                clientFeeReceiver
            )
        );

        if (!success) {
            revert(
                string(
                    feeData.length > 0
                        ? feeData
                        : abi.encodePacked("Calculating fee failed")
                )
            );
        }

        (amountOut, feeRecipients) = abi.decode(
            feeData,
            (uint256, FeeRecipient[])
        );
    }
}
