// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@src/SwapExecutionDispatcher.sol";
import "./TychoRouterTestSetup.sol";


contract SwapExecutionDispatcherExposed is SwapExecutionDispatcher {
    function exposedDecodeExecutorAndSelector(bytes calldata data)
        external
        pure
        returns (address executor, bytes4 selector, bytes memory protocolData)
    {
        return _decodeExecutorAndSelector(data);
    }
}

contract SwapExecutionDispatcherTest is TychoRouterTestSetup {
    SwapExecutionDispatcherExposed dispatcherExposed;

    function setupExecutionDispatcher() public {
        dispatcherExposed = new SwapExecutionDispatcherExposed();
    }

    function testDecodeExecutorAndSelector() public {
        setupExecutionDispatcher();
        bytes memory data =
            hex"6611e616d2db3244244a54c754a16dd3ac7ca7a2aabbccdd1111111111111111";
        (address executor, bytes4 selector, bytes memory protocolData) =
            dispatcherExposed.exposedDecodeExecutorAndSelector(data);
        assert(executor == address(0x6611e616d2db3244244A54c754A16dd3ac7cA7a2));
        assert(selector == bytes4(0xaabbccdd));
        // Direct bytes comparison not supported - must use keccak
        assert(keccak256(protocolData) == keccak256(hex"1111111111111111"));
    }
}
