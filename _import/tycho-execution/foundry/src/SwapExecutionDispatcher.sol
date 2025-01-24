// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@interfaces/ISwapExecutor.sol";

error SwapExecutionDispatcher__UnapprovedExecutor();
error SwapExecutionDispatcher__NonContractExecutor();

/**
 * @title SwapExecutionDispatcher - Dispatch swap execution to external contracts
 * @author PropellerHeads Devs
 * @dev Provides the ability to delegate execution of swaps to external
 *  contracts. This allows dynamically adding new supported protocols
 *  without needing to upgrade any contracts. External contracts will
 *  be called using delegatecall so they can share state with the main
 *  contract if needed.
 *
 *  Note Executor contracts need to implement the ISwapExecutor interface unless
 *  an alternate selector is specified.
 */
contract SwapExecutionDispatcher {
    mapping(address => bool) public swapExecutors;

    event ExecutorSet(address indexed executor);
    event ExecutorRemoved(address indexed executor);

    /**
     * @dev Adds or replaces an approved swap executor contract address if it is a
     *  contract.
     * @param target address of the swap executor contract
     */
    function _setSwapExecutor(address target) internal {
        if (target.code.length == 0) {
            revert SwapExecutionDispatcher__NonContractExecutor();
        }
        swapExecutors[target] = true;
        emit ExecutorSet(target);
    }

    /**
     * @dev Removes an approved swap executor contract address
     * @param target address of the swap executor contract
     */
    function _removeSwapExecutor(address target) internal {
        delete swapExecutors[target];
        emit ExecutorRemoved(target);
    }

    /**
     * @dev Calls an executor, assumes swap.protocolData contains
     *  protocol-specific data required by the executor.
     */
    // slither-disable-next-line dead-code
    function _callSwapExecutor(uint256 amount, bytes calldata data)
        internal
        returns (uint256 calculatedAmount)
    {
        address executor;
        bytes4 decodedSelector;
        bytes memory protocolData;

        (executor, decodedSelector, protocolData) =
            _decodeExecutorAndSelector(data);

        if (!swapExecutors[executor]) {
            revert SwapExecutionDispatcher__UnapprovedExecutor();
        }

        bytes4 selector = decodedSelector == bytes4(0)
            ? ISwapExecutor.swap.selector
            : decodedSelector;

        // slither-disable-next-line low-level-calls
        (bool success, bytes memory result) = executor.delegatecall(
            abi.encodeWithSelector(selector, amount, protocolData)
        );

        if (!success) {
            revert(
                string(
                    result.length > 0
                        ? result
                        : abi.encodePacked("Swap execution failed")
                )
            );
        }

        calculatedAmount = abi.decode(result, (uint256));
    }

    // slither-disable-next-line dead-code
    function _decodeExecutorAndSelector(bytes calldata data)
        internal
        pure
        returns (address executor, bytes4 selector, bytes memory protocolData)
    {
        require(data.length >= 24, "Invalid data length");
        executor = address(uint160(bytes20(data[:20])));
        selector = bytes4(data[20:24]);
        protocolData = data[24:];
    }
}
