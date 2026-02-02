// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {TychoRouter} from "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";

contract TychoRouterTest is TychoRouterTestSetup {
    bytes32 public constant EXECUTOR_SETTER_ROLE =
        0x6a1dd52dcad5bd732e45b6af4e7344fa284e2d7d4b23b5b09cb55d36b0685c87;
    bytes32 public constant PAUSER_ROLE =
        0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a;

    event CallbackVerifierSet(address indexed callbackVerifier);
    event Withdrawal(
        address indexed token, uint256 amount, address indexed receiver
    );

    function testSetExecutorsValidRole() public {
        // Set single executor
        address[] memory executors = new address[](1);
        executors[0] = DUMMY;
        vm.startPrank(EXECUTOR_SETTER);
        tychoRouter.setExecutors(executors);
        vm.stopPrank();
        assert(tychoRouter.executors(DUMMY) == true);

        // Set multiple executors
        address[] memory executors2 = new address[](2);
        executors2[0] = DUMMY2;
        executors2[1] = DUMMY3;
        vm.startPrank(EXECUTOR_SETTER);
        tychoRouter.setExecutors(executors2);
        vm.stopPrank();
        assert(tychoRouter.executors(DUMMY2) == true);
        assert(tychoRouter.executors(DUMMY3) == true);
    }

    function testRemoveExecutorValidRole() public {
        vm.startPrank(EXECUTOR_SETTER);
        address[] memory executors = new address[](1);
        executors[0] = DUMMY;
        tychoRouter.setExecutors(executors);
        tychoRouter.removeExecutor(DUMMY);
        vm.stopPrank();
        assert(tychoRouter.executors(DUMMY) == false);
    }

    function testRemoveExecutorMissingSetterRole() public {
        vm.expectRevert();
        tychoRouter.removeExecutor(BOB);
    }

    function testSetExecutorsMissingSetterRole() public {
        vm.expectRevert();
        address[] memory executors = new address[](1);
        executors[0] = DUMMY;
        tychoRouter.setExecutors(executors);
    }

    function testPause() public {
        vm.startPrank(PAUSER);
        assertEq(tychoRouter.paused(), false);
        tychoRouter.pause();
        assertEq(tychoRouter.paused(), true);
        vm.stopPrank();

        vm.startPrank(UNPAUSER);
        tychoRouter.unpause();
        assertEq(tychoRouter.paused(), false);
        vm.stopPrank();

        vm.startPrank(UNPAUSER);
        vm.expectRevert();
        tychoRouter.unpause();
        vm.stopPrank();
    }

    function testPauseNonRole() public {
        vm.startPrank(BOB);
        vm.expectRevert();
        tychoRouter.pause();
        vm.stopPrank();
    }

    function testEmptySwapsRevert() public {
        uint256 amountIn = 10 ** 18;
        bytes memory swaps = "";
        vm.expectRevert(TychoRouter__EmptySwaps.selector);
        tychoRouter.exposedSplitSwap(amountIn, 2, swaps, address(0), false);
    }

    // FEE CALCULATOR TESTS
    function testSetFeeCalculator() public {
        vm.prank(FEE_SETTER);
        tychoRouter.setFeeCalculator(FEE_CALCULATOR);
        assertEq(tychoRouter.getFeeCalculator(), FEE_CALCULATOR);
    }

    function testSetFeeCalculatorZeroAddress() public {
        vm.prank(FEE_SETTER);
        vm.expectRevert(TychoRouter__AddressZero.selector);
        tychoRouter.setFeeCalculator(address(0));
    }

    function testSetFeeCalculatorUnauthorized() public {
        vm.prank(ALICE);
        vm.expectRevert();
        tychoRouter.setFeeCalculator(FEE_CALCULATOR);
    }

    function testSetFeeCalculatorUpdatesCorrectly() public {
        address newFeeCalculator = address(0x999);
        vm.startPrank(FEE_SETTER);
        tychoRouter.setFeeCalculator(FEE_CALCULATOR);
        assertEq(tychoRouter.getFeeCalculator(), FEE_CALCULATOR);

        tychoRouter.setFeeCalculator(newFeeCalculator);
        vm.stopPrank();

        assertEq(tychoRouter.getFeeCalculator(), newFeeCalculator);
    }
}
