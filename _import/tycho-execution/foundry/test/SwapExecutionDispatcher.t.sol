// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@src/SwapExecutionDispatcher.sol";
import "./TychoRouterTestSetup.sol";

contract SwapExecutionDispatcherExposed is SwapExecutionDispatcher {
    function exposedCallSwapExecutor(uint256 amount, bytes calldata data)
        external
        returns (uint256 calculatedAmount)
    {
        return _callSwapExecutor(amount, data);
    }

    function exposedDecodeExecutorAndSelector(bytes calldata data)
        external
        pure
        returns (address executor, bytes4 selector, bytes memory protocolData)
    {
        return _decodeExecutorAndSelector(data);
    }

    function setSwapExecutor(address target) external {
        swapExecutors[target] = true;
    }
}

contract SwapExecutionDispatcherTest is TychoRouterTestSetup {
    SwapExecutionDispatcherExposed dispatcherExposed;

    function setupExecutionDispatcher() public {
        uint256 forkBlock = 20673900;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        dispatcherExposed = new SwapExecutionDispatcherExposed();
        dispatcherExposed.setSwapExecutor(
            address(0xe592557AB9F4A75D992283fD6066312FF013ba3d)
        );
        deal(WETH_ADDR, address(dispatcherExposed), 15000000000000000000);
    }

    function testCallSwapExecutor1() public {
        // Test case taken from existing transaction
        // 0x755d603962b30f416cf3eefae8d55204d6ffdf746465b2a94aca216faab63804
        setupExecutionDispatcher();
        bytes memory data =
            hex"e592557AB9F4A75D992283fD6066312FF013ba3dbd0625ab5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72fc8c39af7983bf329086de522229a7be5fc4e41cc51c72848c68a965f66fa7a88855f9f7784502a7f2606beffe61000613d6a25b5bfef4cd7652aa94777d4a46b39f2e206411280a12c9344b769ff1066c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000d02ab486cedc0000000000000000000000000000000000000000000000000000000000082ec8ad1b0000000000000000000000000000000000000000000000000000000066d7b65800000000000000000000000000000000000000000000000000000191ba9f843c125000064000640000d52de09955f0ffffffffffffff00225c389e595fe9000001fcc910754b349f821e4bb5d8444822a63920be943aba6f1b31ee14ef0fc6840b6d28d604e04a78834b668dba24a6c082ffb901e4fffa9600649e8d991af593c81c";
        uint256 givenAmount = 15000000000000000000;
        uint256 amount =
            dispatcherExposed.exposedCallSwapExecutor(givenAmount, data);
        assert(amount == 35144641819);
    }

    function testCallSwapExecutorNoSelector() public {
        // Test case taken from existing transaction
        // 0x755d603962b30f416cf3eefae8d55204d6ffdf746465b2a94aca216faab63804
        // No selector is passed, so the standard swap selector should be used
        setupExecutionDispatcher();
        bytes memory data =
            hex"e592557AB9F4A75D992283fD6066312FF013ba3d000000005615dEB798BB3E4dFa0139dFa1b3D433Cc23b72fc8c39af7983bf329086de522229a7be5fc4e41cc51c72848c68a965f66fa7a88855f9f7784502a7f2606beffe61000613d6a25b5bfef4cd7652aa94777d4a46b39f2e206411280a12c9344b769ff1066c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000d02ab486cedc0000000000000000000000000000000000000000000000000000000000082ec8ad1b0000000000000000000000000000000000000000000000000000000066d7b65800000000000000000000000000000000000000000000000000000191ba9f843c125000064000640000d52de09955f0ffffffffffffff00225c389e595fe9000001fcc910754b349f821e4bb5d8444822a63920be943aba6f1b31ee14ef0fc6840b6d28d604e04a78834b668dba24a6c082ffb901e4fffa9600649e8d991af593c81c";
        uint256 givenAmount = 15000000000000000000;
        uint256 amount =
            dispatcherExposed.exposedCallSwapExecutor(givenAmount, data);
        assert(amount == 35144641819);
    }

    function testCallSwapExecutorCallFailed() public {
        // Bad data is provided to an approved swap executor - causing the call to fail
        setupExecutionDispatcher();
        bytes memory data =
            hex"e592557AB9F4A75D992283fD6066312FF013ba3dbd0625ab5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72fc8c39af7983bf329086de522229a7be5fc4e41cc51c72848c68a965f66fa7a88855f9f7784502a7f2606beffe61000613d6a25b5bfef4cd7652aa94777d4a46b39f2e206411280a12c9344b769ff1066c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000d02ab486cedc0000000000000000000000000000000000000000000000000000000000082ec8ad1b0000000000000000000000000000000000000000000000000000000066d7b65800000000000000000000000000000000000000000000000000000191ba9f843c125000064000640000d52de09955f0ffffffffffffff00225c389e595fe9000001fcc910754b349f821e4bb5d8444822a63920be943aba6f1b31ee14ef0fc6840b6d28d604e04a78834b668dba24a6c082ffb901e4fffa9600649e8d991af593";
        vm.expectRevert();
        dispatcherExposed.exposedCallSwapExecutor(0, data);
    }

    function testCallSwapExecutorUnapprovedExecutor() public {
        setupExecutionDispatcher();
        bytes memory data =
            hex"5d622C9053b8FFB1B3465495C8a42E603632bA70aabbccdd1111111111111111";
        vm.expectRevert();
        dispatcherExposed.exposedCallSwapExecutor(0, data);
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
