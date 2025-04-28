// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/Dispatcher.sol";
import "./TychoRouterTestSetup.sol";

contract DispatcherExposed is Dispatcher {
    function exposedCallExecutor(
        address executor,
        uint256 amount,
        bytes calldata data
    ) external returns (uint256 calculatedAmount) {
        return _callSwapOnExecutor(executor, amount, data);
    }

    function exposedSetExecutor(address target) external {
        _setExecutor(target);
    }

    function exposedRemoveExecutor(address target) external {
        _removeExecutor(target);
    }
}

contract DispatcherTest is Constants {
    DispatcherExposed dispatcherExposed;

    event ExecutorSet(address indexed executor);
    event ExecutorRemoved(address indexed executor);

    function setUp() public {
        uint256 forkBlock = 20673900;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        dispatcherExposed = new DispatcherExposed();
        deal(WETH_ADDR, address(dispatcherExposed), 15 ether);
        deployDummyContract();
    }

    function testSetValidExecutor() public {
        vm.expectEmit();
        // Define the event we expect to be emitted at the next step
        emit ExecutorSet(DUMMY);
        dispatcherExposed.exposedSetExecutor(DUMMY);
        assert(dispatcherExposed.executors(DUMMY) == true);
    }

    function testRemoveExecutor() public {
        dispatcherExposed.exposedSetExecutor(DUMMY);
        vm.expectEmit();
        // Define the event we expect to be emitted at the next step
        emit ExecutorRemoved(DUMMY);
        dispatcherExposed.exposedRemoveExecutor(DUMMY);
        assert(dispatcherExposed.executors(DUMMY) == false);
    }

    function testRemoveUnSetExecutor() public {
        dispatcherExposed.exposedRemoveExecutor(BOB);
        assert(dispatcherExposed.executors(BOB) == false);
    }

    function testSetExecutorNonContract() public {
        vm.expectRevert(
            abi.encodeWithSelector(Dispatcher__NonContractExecutor.selector)
        );
        dispatcherExposed.exposedSetExecutor(BOB);
    }

    function testCallExecutor() public {
        // Test case taken from existing transaction
        // 0x755d603962b30f416cf3eefae8d55204d6ffdf746465b2a94aca216faab63804
        // For this test, we can use any executor and any calldata that we know works
        // for this executor. We don't care about which calldata/executor, since we are
        // only testing the functionality of the delegatecall and not the inner
        // workings of the executor.
        // Thus, we chose a previously-deployed Hashflow executor for simplicity. To
        // change this test, we can find any of our transactions that succeeded, and
        // obtain the calldata passed to the executor via Tenderly.
        dispatcherExposed.exposedSetExecutor(
            address(0xe592557AB9F4A75D992283fD6066312FF013ba3d)
        );
        bytes memory data =
            hex"5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72fc8c39af7983bf329086de522229a7be5fc4e41cc51c72848c68a965f66fa7a88855f9f7784502a7f2606beffe61000613d6a25b5bfef4cd7652aa94777d4a46b39f2e206411280a12c9344b769ff1066c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000d02ab486cedc0000000000000000000000000000000000000000000000000000000000082ec8ad1b0000000000000000000000000000000000000000000000000000000066d7b65800000000000000000000000000000000000000000000000000000191ba9f843c125000064000640000d52de09955f0ffffffffffffff00225c389e595fe9000001fcc910754b349f821e4bb5d8444822a63920be943aba6f1b31ee14ef0fc6840b6d28d604e04a78834b668dba24a6c082ffb901e4fffa9600649e8d991af593c81c";
        uint256 givenAmount = 15 ether;
        uint256 amount = dispatcherExposed.exposedCallExecutor(
            0xe592557AB9F4A75D992283fD6066312FF013ba3d, givenAmount, data
        );
        assert(amount == 35144641819);
    }

    function testCallExecutorNoSelector() public {
        // Test case taken from existing transaction
        // 0x755d603962b30f416cf3eefae8d55204d6ffdf746465b2a94aca216faab63804
        // No selector is passed, so the standard swap selector should be used

        // For this test, we can use any executor and any calldata that we know works
        // for this executor. We don't care about which calldata/executor, since we are
        // only testing the functionality of the delegatecall and not the inner
        // workings of the executor.
        // Thus, we chose a previously-deployed Hashflow executor for simplicity. To
        // change this test, we can find any of our transactions that succeeded, and
        // obtain the calldata passed to the executor via Tenderly.
        dispatcherExposed.exposedSetExecutor(
            address(0xe592557AB9F4A75D992283fD6066312FF013ba3d)
        );
        bytes memory data =
            hex"5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72fc8c39af7983bf329086de522229a7be5fc4e41cc51c72848c68a965f66fa7a88855f9f7784502a7f2606beffe61000613d6a25b5bfef4cd7652aa94777d4a46b39f2e206411280a12c9344b769ff1066c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000d02ab486cedc0000000000000000000000000000000000000000000000000000000000082ec8ad1b0000000000000000000000000000000000000000000000000000000066d7b65800000000000000000000000000000000000000000000000000000191ba9f843c125000064000640000d52de09955f0ffffffffffffff00225c389e595fe9000001fcc910754b349f821e4bb5d8444822a63920be943aba6f1b31ee14ef0fc6840b6d28d604e04a78834b668dba24a6c082ffb901e4fffa9600649e8d991af593c81c";
        uint256 givenAmount = 15 ether;
        uint256 amount = dispatcherExposed.exposedCallExecutor(
            0xe592557AB9F4A75D992283fD6066312FF013ba3d, givenAmount, data
        );
        assert(amount == 35144641819);
    }

    function testCallExecutorCallFailed() public {
        // Bad data is provided to an approved executor - causing the call to fail
        dispatcherExposed.exposedSetExecutor(
            address(0xe592557AB9F4A75D992283fD6066312FF013ba3d)
        );
        bytes memory data =
            hex"5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72fc8c39af7983bf329086de522229a7be5fc4e41cc51c72848c68a965f66fa7a88855f9f7784502a7f2606beffe61000613d6a25b5bfef4cd7652aa94777d4a46b39f2e206411280a12c9344b769ff1066c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000d02ab486cedc0000000000000000000000000000000000000000000000000000000000082ec8ad1b0000000000000000000000000000000000000000000000000000000066d7b65800000000000000000000000000000000000000000000000000000191ba9f843c125000064000640000d52de09955f0ffffffffffffff00225c389e595fe9000001fcc910754b349f821e4bb5d8444822a63920be943aba6f1b31ee14ef0fc6840b6d28d604e04a78834b668dba24a6c082ffb901e4fffa9600649e8d991af593";
        vm.expectRevert();
        dispatcherExposed.exposedCallExecutor(
            0xe592557AB9F4A75D992283fD6066312FF013ba3d, 0, data
        );
    }

    function testCallExecutorUnapprovedExecutor() public {
        bytes memory data = hex"aabbccdd1111111111111111";
        vm.expectRevert();
        dispatcherExposed.exposedCallExecutor(
            0x5d622C9053b8FFB1B3465495C8a42E603632bA70, 0, data
        );
    }
}
