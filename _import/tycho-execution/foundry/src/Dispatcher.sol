// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@interfaces/ICallback.sol";

error Dispatcher__UnapprovedExecutor(address executor);
error Dispatcher__NonContractExecutor();
error Dispatcher__InvalidDataLength();

/**
 * @title Dispatcher - Dispatch execution to external contracts
 * @author PropellerHeads Devs
 * @dev Provides the ability to delegate execution of swaps to external
 *  contracts. This allows dynamically adding new supported protocols
 *  without needing to upgrade any contracts. External contracts will
 *  be called using delegatecall so they can share state with the main
 *  contract if needed.
 *
 *  Note: Executor contracts need to implement the IExecutor interface unless
 *  an alternate selector is specified.
 */
contract Dispatcher {
    mapping(address => bool) public executors;

    event ExecutorSet(address indexed executor);
    event ExecutorRemoved(address indexed executor);

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
    // slither-disable-next-line delegatecall-loop
    function _callExecutor(
        address executor,
        uint256 amount,
        bytes calldata data
    ) internal returns (uint256 calculatedAmount) {
        if (!executors[executor]) {
            revert Dispatcher__UnapprovedExecutor(executor);
        }

        // slither-disable-next-line controlled-delegatecall,low-level-calls
        (bool success, bytes memory result) = executor.delegatecall(
            abi.encodeWithSelector(IExecutor.swap.selector, amount, data)
        );

        if (!success) {
            revert(
                string(
                    result.length > 0
                        ? result
                        : abi.encodePacked("Execution failed")
                )
            );
        }

        calculatedAmount = abi.decode(result, (uint256));
    }

    function _handleCallback(bytes calldata data) internal {
        address executor = address(uint160(bytes20(data[data.length - 20:])));

        if (!executors[executor]) {
            revert Dispatcher__UnapprovedExecutor(executor);
        }

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
    }
}
