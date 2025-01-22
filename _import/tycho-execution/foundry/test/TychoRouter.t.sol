// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {TychoRouter} from "@src/TychoRouter.sol";
import "./TestTemplate.sol";

contract TychoRouterTest is TychoRouterTestTemplate {
    bytes32 public constant EXECUTOR_SETTER_ROLE =
        0x6a1dd52dcad5bd732e45b6af4e7344fa284e2d7d4b23b5b09cb55d36b0685c87;
    bytes32 public constant FEE_SETTER_ROLE =
        0xe6ad9a47fbda1dc18de1eb5eeb7d935e5e81b4748f3cfc61e233e64f88182060;
    bytes32 public constant PAUSER_ROLE =
        0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a;
    bytes32 public constant FUND_RESCUER_ROLE =
        0x912e45d663a6f4cc1d0491d8f046e06c616f40352565ea1cdb86a0e1aaefa41b;

    event ExecutorSet(address indexed executor);
    event CallbackVerifierSet(address indexed callbackVerifier);

    function setupTychoRouter() public {
        deployTychoRouter();
    }

    function testSetValidExecutor() public {
        setupTychoRouter();
        deployDummyContract();

        vm.startPrank(executorSetter);
        vm.expectEmit();
        // Define the event we expect to be emitted at the next step
        emit ExecutorSet(DUMMY);

        tychoRouter.setSwapExecutor(DUMMY);
        vm.stopPrank();

        assert(tychoRouter.swapExecutors(DUMMY) == true);
    }

    function testRemoveExecutor() public {
        setupTychoRouter();
        deployDummyContract();

        vm.startPrank(executorSetter);
        tychoRouter.setSwapExecutor(DUMMY);
        tychoRouter.removeSwapExecutor(DUMMY);
        vm.stopPrank();
        assert(tychoRouter.swapExecutors(DUMMY) == false);
    }

    function testRemoveUnSetExecutor() public {
        setupTychoRouter();
        deployDummyContract();

        vm.startPrank(executorSetter);
        tychoRouter.removeSwapExecutor(BOB);
        vm.stopPrank();
        assert(tychoRouter.swapExecutors(BOB) == false);
    }

    function testRemoveExecutorMissingSetterRole() public {
        setupTychoRouter();
        deployDummyContract();
        vm.expectRevert();
        tychoRouter.removeSwapExecutor(BOB);
    }

    function testSetExecutorMissingSetterRole() public {
        setupTychoRouter();
        deployDummyContract();

        vm.expectRevert();
        tychoRouter.setSwapExecutor(DUMMY);
    }

    function testSetExecutorNonContract() public {
        setupTychoRouter();
        deployDummyContract();

        vm.startPrank(executorSetter);
        vm.expectRevert(
            abi.encodeWithSelector(TychoRouter__NonContractExecutor.selector)
        );
        tychoRouter.setSwapExecutor(BOB);
        vm.stopPrank();
    }

    function testSetValidVerifier() public {
        setupTychoRouter();
        deployDummyContract();

        vm.startPrank(executorSetter);
        vm.expectEmit();
        // Define the event we expect to be emitted at the next step
        emit CallbackVerifierSet(DUMMY);

        tychoRouter.setCallbackVerifier(DUMMY);
        vm.stopPrank();

        assert(tychoRouter.callbackVerifiers(DUMMY) == true);
    }

    function testRemoveVerifier() public {
        setupTychoRouter();
        deployDummyContract();

        vm.startPrank(executorSetter);
        tychoRouter.setCallbackVerifier(DUMMY);
        tychoRouter.removeCallbackVerifier(DUMMY);
        vm.stopPrank();
        assert(tychoRouter.callbackVerifiers(DUMMY) == false);
    }

    function testRemoveUnSetVerifier() public {
        setupTychoRouter();
        deployDummyContract();

        vm.startPrank(executorSetter);
        tychoRouter.removeCallbackVerifier(BOB);
        vm.stopPrank();
        assert(tychoRouter.callbackVerifiers(BOB) == false);
    }

    function testRemoveVerifierMissingSetterRole() public {
        setupTychoRouter();
        deployDummyContract();
        vm.expectRevert();
        tychoRouter.removeCallbackVerifier(BOB);
    }

    function testSetVerifierMissingSetterRole() public {
        setupTychoRouter();
        deployDummyContract();

        vm.expectRevert();
        tychoRouter.setCallbackVerifier(DUMMY);
    }

    function testSetVerifierNonContract() public {
        setupTychoRouter();
        deployDummyContract();

        vm.startPrank(executorSetter);
        vm.expectRevert(
            abi.encodeWithSelector(TychoRouter__NonContractVerifier.selector)
        );
        tychoRouter.setCallbackVerifier(BOB);
        vm.stopPrank();
    }
}
