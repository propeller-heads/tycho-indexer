// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/**
 * @title SwapExecutionDispatcher - Dispatch swap execution to external contracts
 * @author PropellerHeads Devs
 * @dev Provides the ability to delegate execution of swaps to external
 *  contracts. This allows dynamically adding new supported protocols
 *  without needing to upgrade any contracts. External contracts will
 *  be called using delegatecall so they can share state with the main
 *  contract if needed.
 *
 *  Note Executor contracts need to implement the ISwapExecutor interface
 */
contract SwapExecutionDispatcher {
    mapping(address => bool) public swapExecutors;
}
