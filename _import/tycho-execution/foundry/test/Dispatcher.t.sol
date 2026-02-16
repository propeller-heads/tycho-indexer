// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/Dispatcher.sol";
import "./TychoRouterTestSetup.sol";

contract DispatcherExposed is Dispatcher {
    constructor(address _permit2) Dispatcher(_permit2) {}

    function exposedCallExecutor(
        address executor,
        uint256 amount,
        bytes calldata data,
        bool isFirstSwap,
        bool isSplitSwap,
        address receiver
    ) external returns (uint256 calculatedAmount) {
        return _callSwapOnExecutor(
            executor, amount, data, isFirstSwap, isSplitSwap, receiver
        );
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

    event ExecutorSet(address indexed executor, uint256 timelockExpiresAt);
    event ExecutorRemoved(address indexed executor);

    function setUp() public {
        uint256 forkBlock = 20673900;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        dispatcherExposed = new DispatcherExposed(PERMIT2_ADDRESS);
        deal(WETH_ADDR, address(dispatcherExposed), 15 ether);
        deployDummyContract();
    }

    function testSetValidExecutor() public {
        vm.expectEmit();
        // Define the event we expect to be emitted at the next step
        uint256 timelockExpiresAt =
            block.timestamp + dispatcherExposed.DELAY_EXECUTOR_ACTIVATION();
        emit ExecutorSet(DUMMY, timelockExpiresAt);
        dispatcherExposed.exposedSetExecutor(DUMMY);

        assert(dispatcherExposed.executorsActivationTimestamp(DUMMY) > 0);
    }

    function testRemoveExecutor() public {
        dispatcherExposed.exposedSetExecutor(DUMMY);
        vm.expectEmit();
        // Define the event we expect to be emitted at the next step
        emit ExecutorRemoved(DUMMY);
        dispatcherExposed.exposedRemoveExecutor(DUMMY);
        assert(dispatcherExposed.executorsActivationTimestamp(DUMMY) == 0);
    }

    function testRemoveUnSetExecutor() public {
        dispatcherExposed.exposedRemoveExecutor(BOB);
        assert(dispatcherExposed.executorsActivationTimestamp(BOB) == 0);
    }

    function testCallTimelockedExecutor() public {
        // Executor is set but timelocked
        address executor = 0xe592557AB9F4A75D992283fD6066312FF013ba3d;
        dispatcherExposed.exposedSetExecutor(executor);
        bytes memory data = hex"aabbccdd1111111111111111";

        vm.expectRevert(
            abi.encodeWithSelector(
                Dispatcher__ExecutorIsTimelocked.selector, executor
            )
        );

        dispatcherExposed.exposedCallExecutor(
            executor, 0, data, true, false, address(0)
        );
    }

    function testSetExecutorNonContract() public {
        vm.expectRevert(
            abi.encodeWithSelector(Dispatcher__NonContractExecutor.selector)
        );
        dispatcherExposed.exposedSetExecutor(BOB);
    }

    function testSetExistingExecutor() public {
        uint256 forkBlock = 20673900;
        address executor = 0xe592557AB9F4A75D992283fD6066312FF013ba3d;
        uint256 forkBlockTime = vm.getBlockTimestamp();
        vm.warp(forkBlockTime - _SETUP_TIME_OFFSET_ETHEREUM);
        dispatcherExposed.exposedSetExecutor(executor);
        vm.warp(forkBlockTime);

        vm.expectRevert(
            abi.encodeWithSelector(
                Dispatcher__ExecutorAlreadyExists.selector, executor
            )
        );

        dispatcherExposed.exposedSetExecutor(executor);
    }

    function testCallExecutorCallFailed() public {
        // Bad data is provided to an approved executor - causing the call to fail
        // Make sure the executor is not timelocked
        uint256 forkBlock = 20673900;
        address executor = 0xe592557AB9F4A75D992283fD6066312FF013ba3d;
        uint256 forkBlockTime = vm.getBlockTimestamp();
        vm.warp(forkBlockTime - _SETUP_TIME_OFFSET_ETHEREUM);
        dispatcherExposed.exposedSetExecutor(executor);
        vm.warp(forkBlockTime);
        bytes memory data =
            hex"5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72fc8c39af7983bf329086de522229a7be5fc4e41cc51c72848c68a965f66fa7a88855f9f7784502a7f2606beffe61000613d6a25b5bfef4cd7652aa94777d4a46b39f2e206411280a12c9344b769ff1066c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000d02ab486cedc0000000000000000000000000000000000000000000000000000000000082ec8ad1b0000000000000000000000000000000000000000000000000000000066d7b65800000000000000000000000000000000000000000000000000000191ba9f843c125000064000640000d52de09955f0ffffffffffffff00225c389e595fe9000001fcc910754b349f821e4bb5d8444822a63920be943aba6f1b31ee14ef0fc6840b6d28d604e04a78834b668dba24a6c082ffb901e4fffa9600649e8d991af593";
        vm.expectRevert(bytes("Getting transfer data failed"));
        dispatcherExposed.exposedCallExecutor(
            executor, 0, data, true, false, address(0)
        );
    }

    function testCallExecutorUnapprovedExecutor() public {
        bytes memory data = hex"aabbccdd1111111111111111";
        address executor = 0x5d622C9053b8FFB1B3465495C8a42E603632bA70;

        vm.expectRevert(
            abi.encodeWithSelector(
                Dispatcher__UnapprovedExecutor.selector, executor
            )
        );

        dispatcherExposed.exposedCallExecutor(
            0x5d622C9053b8FFB1B3465495C8a42E603632bA70,
            0,
            data,
            true,
            false,
            address(0)
        );
    }
}
