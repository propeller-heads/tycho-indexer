// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";

contract TychoRouterFeeTest is TychoRouterTestSetup {
    address feeReceiver = BOB;

    // ROUTER FEE ON OUTPUT TESTS
    function testSetRouterFeeOnOutputUnauthorized() public {
        vm.prank(ALICE);
        vm.expectRevert();
        tychoRouter.setRouterFeeOnOutput(100);
    }

    function testSetRouterFeeOnOutput() public {
        // Set initial fee
        vm.prank(FEE_SETTER);
        tychoRouter.setRouterFeeOnOutput(100);
        assertEq(tychoRouter.getRouterFeeOnOutput(), 100);

        // Update fee
        vm.prank(FEE_SETTER);
        tychoRouter.setRouterFeeOnOutput(200);
        assertEq(tychoRouter.getRouterFeeOnOutput(), 200);
    }

    function testSetCustomRouterFeeOnOutput() public {
        // Set default fee
        vm.prank(FEE_SETTER);
        uint16 defaultFee = 50;
        tychoRouter.setRouterFeeOnOutput(100);

        // Set custom fee for user
        uint16 userFee = 50;

        vm.prank(FEE_SETTER);
        tychoRouter.setCustomRouterFeeOnOutput(BOB, userFee);

        // Check user gets custom fee
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(BOB), defaultFee);

        // Check other users still get default fee
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(ALICE), 100);
    }

    function testSetCustomRouterFeeOnOutputUnauthorized() public {
        vm.prank(ALICE);
        vm.expectRevert();
        tychoRouter.setCustomRouterFeeOnOutput(ALICE, 50);
    }

    function testSetCustomRouterFeeOnOutputWithoutDefault() public {
        // Set custom fee for user without setting default first
        uint16 userFee = 75;
        vm.prank(FEE_SETTER);
        tychoRouter.setCustomRouterFeeOnOutput(ALICE, userFee);
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(ALICE), userFee);
    }

    function testRemoveCustomRouterFeeOnOutput() public {
        // Set default and custom fee
        vm.startPrank(FEE_SETTER);
        tychoRouter.setRouterFeeOnOutput(100);
        tychoRouter.setCustomRouterFeeOnOutput(ALICE, 50);
        vm.stopPrank();

        assertEq(tychoRouter.getCustomRouterFeeOnOutput(ALICE), 50);

        // Remove custom fee
        vm.prank(FEE_SETTER);
        tychoRouter.removeCustomRouterFeeOnOutput(ALICE);

        // Should now return default fee
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(ALICE), 100);
    }

    function testRemoveCustomRouterFeeOnOutputUnauthorized() public {
        vm.prank(ALICE);
        vm.expectRevert();
        tychoRouter.removeCustomRouterFeeOnOutput(ALICE);
    }

    // ROUTER FEE ON SOLVER FEE TESTS
    function testSetRouterFeeOnSolverFeeUnauthorized() public {
        vm.prank(ALICE);
        vm.expectRevert();
        tychoRouter.setRouterFeeOnSolverFee(1000);
    }

    function testSetRouterFeeOnSolverFee() public {
        // Set initial fee
        vm.prank(FEE_SETTER);
        tychoRouter.setRouterFeeOnSolverFee(500);
        assertEq(tychoRouter.getRouterFeeOnSolverFee(), 500);

        // Update fee
        vm.prank(FEE_SETTER);
        tychoRouter.setRouterFeeOnSolverFee(1000);
        assertEq(tychoRouter.getRouterFeeOnSolverFee(), 1000);
    }

    function testSetCustomRouterFeeOnSolverFee() public {
        // Set default fee
        vm.prank(FEE_SETTER);
        tychoRouter.setRouterFeeOnSolverFee(1000);

        // Set custom fee for user
        uint16 userFee = 500;

        vm.prank(FEE_SETTER);
        tychoRouter.setCustomRouterFeeOnSolverFee(BOB, userFee);

        // Check user gets custom fee
        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(BOB), userFee);

        // Check other users still get default fee
        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(ALICE), 1000);
    }

    function testSetCustomRouterFeeOnSolverFeeUnauthorized() public {
        vm.prank(ALICE);
        vm.expectRevert();
        tychoRouter.setCustomRouterFeeOnSolverFee(ALICE, 500);
    }

    function testSetCustomRouterFeeOnSolverFeeWithoutDefault() public {
        // Set custom fee for user without setting default first
        uint16 userFee = 750;

        vm.prank(FEE_SETTER);
        tychoRouter.setCustomRouterFeeOnSolverFee(ALICE, userFee);

        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(ALICE), userFee);
    }

    function testRemoveCustomRouterFeeOnSolverFee() public {
        // Set default and custom fee
        vm.startPrank(FEE_SETTER);
        tychoRouter.setRouterFeeOnSolverFee(1000);
        tychoRouter.setCustomRouterFeeOnSolverFee(ALICE, 500);
        vm.stopPrank();

        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(ALICE), 500);

        // Remove custom fee
        vm.prank(FEE_SETTER);
        tychoRouter.removeCustomRouterFeeOnSolverFee(ALICE);

        // Should now return default fee
        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(ALICE), 1000);
    }

    function testRemoveCustomRouterFeeOnSolverFeeUnauthorized() public {
        vm.prank(ALICE);
        vm.expectRevert();
        tychoRouter.removeCustomRouterFeeOnSolverFee(ALICE);
    }

    // FEE TAKER TESTS
    function testSetFeeTaker() public {
        vm.prank(FEE_SETTER);
        tychoRouter.setFeeTaker(FEE_TAKER);
        assertEq(tychoRouter.getFeeTaker(), FEE_TAKER);
    }

    function testSetFeeTakerZeroAddress() public {
        vm.prank(FEE_SETTER);
        vm.expectRevert(TychoRouter__AddressZero.selector);
        tychoRouter.setFeeTaker(address(0));
    }

    function testSetFeeTakerUnauthorized() public {
        vm.prank(ALICE);
        vm.expectRevert();
        tychoRouter.setFeeTaker(FEE_TAKER);
    }

    function testSetFeeTakerUpdatesCorrectly() public {
        address newFeeTaker = address(0x999);
        vm.startPrank(FEE_SETTER);
        tychoRouter.setFeeTaker(FEE_TAKER);
        assertEq(tychoRouter.getFeeTaker(), FEE_TAKER);

        tychoRouter.setFeeTaker(newFeeTaker);
        vm.stopPrank();

        assertEq(tychoRouter.getFeeTaker(), newFeeTaker);
    }

    // FEE RECEIVER TESTS
    function testSetRouterFeeReceiver() public {
        vm.prank(FEE_SETTER);
        tychoRouter.setRouterFeeReceiver(feeReceiver);
        assertEq(tychoRouter.getRouterFeeReceiver(), feeReceiver);
    }

    function testSetRouterFeeReceiverZeroAddressReverts() public {
        vm.prank(FEE_SETTER);
        vm.expectRevert(TychoRouter__AddressZero.selector);
        tychoRouter.setRouterFeeReceiver(address(0));
    }

    function testSetRouterFeeReceiverUnauthorized() public {
        vm.prank(ALICE);
        vm.expectRevert();
        tychoRouter.setRouterFeeReceiver(feeReceiver);
    }

    function testSetRouterFeeReceiverUpdatesCorrectly() public {
        address newReceiver = address(0x888);

        vm.startPrank(FEE_SETTER);
        tychoRouter.setRouterFeeReceiver(feeReceiver);
        assertEq(tychoRouter.getRouterFeeReceiver(), feeReceiver);

        tychoRouter.setRouterFeeReceiver(newReceiver);
        vm.stopPrank();

        assertEq(tychoRouter.getRouterFeeReceiver(), newReceiver);
    }

    // MULTIPLE USER AND EDGE CASE TESTS
    function testMultipleUserCustomFees() public {
        address user1 = DUMMY;
        address user2 = DUMMY2;
        address user3 = DUMMY3;

        // Set default fees
        vm.startPrank(FEE_SETTER);
        tychoRouter.setRouterFeeOnOutput(100);
        tychoRouter.setRouterFeeOnSolverFee(1000);

        // Set custom fees for different users
        tychoRouter.setCustomRouterFeeOnOutput(user1, 50);
        tychoRouter.setCustomRouterFeeOnSolverFee(user1, 500);

        tychoRouter.setCustomRouterFeeOnOutput(user2, 150);
        tychoRouter.setCustomRouterFeeOnSolverFee(user2, 1500);
        vm.stopPrank();

        // Verify each user has correct fees
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(user1), 50);
        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(user1), 500);

        assertEq(tychoRouter.getCustomRouterFeeOnOutput(user2), 150);
        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(user2), 1500);

        // User3 should get default fees
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(user3), 100);
        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(user3), 1000);
    }

    function testUpdateDefaultFeeDoesNotAffectCustomFees() public {
        // Set initial default fee
        vm.startPrank(FEE_SETTER);
        tychoRouter.setRouterFeeOnOutput(100);

        // Set custom fee for user
        tychoRouter.setCustomRouterFeeOnOutput(BOB, 50);

        // Update default fee
        tychoRouter.setRouterFeeOnOutput(200);
        vm.stopPrank();

        // User should still have custom fee
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(BOB), 50);

        // Other users should get new default
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(ALICE), 200);
    }

    function testDefaultValues() public view {
        // Default fees should be zero
        assertEq(tychoRouter.getRouterFeeOnOutput(), 0);
        assertEq(tychoRouter.getRouterFeeOnSolverFee(), 0);
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(ALICE), 0);
        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(ALICE), 0);
        // Taker should be zero if not explicitly set
        assertEq(tychoRouter.getFeeTaker(), address(0));
        // Default fee receiver should be the contract deployer if not
        // explicitly set. This prevents fee tokens from getting stuck on the
        // router by mistake.
        assertEq(tychoRouter.getRouterFeeReceiver(), ADMIN);
    }

    function testMaximumFee() public {
        uint16 maxFee = type(uint16).max;

        vm.startPrank(FEE_SETTER);
        tychoRouter.setRouterFeeOnOutput(maxFee);
        tychoRouter.setRouterFeeOnSolverFee(maxFee);
        vm.stopPrank();

        assertEq(tychoRouter.getRouterFeeOnOutput(), maxFee);
        assertEq(tychoRouter.getRouterFeeOnSolverFee(), maxFee);
    }
}
