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
        uint16 defaultFee = 100;
        tychoRouter.setRouterFeeOnOutput(defaultFee);

        // Set custom fee for user
        uint16 userFee = 50;
        vm.prank(FEE_SETTER);
        tychoRouter.setCustomRouterFeeOnOutput(BOB, userFee);

        // Check user gets custom fee
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(BOB), userFee);

        // Check other users still get default fee
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(ALICE), defaultFee);
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
        uint16 defaultFee = 100;
        uint16 customFee = 50;
        tychoRouter.setRouterFeeOnOutput(defaultFee);
        tychoRouter.setCustomRouterFeeOnOutput(ALICE, customFee);
        vm.stopPrank();

        assertEq(tychoRouter.getCustomRouterFeeOnOutput(ALICE), customFee);

        // Remove custom fee
        vm.prank(FEE_SETTER);
        tychoRouter.removeCustomRouterFeeOnOutput(ALICE);

        // Should now return default fee
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(ALICE), defaultFee);
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
        uint16 defaultFee = 500;
        uint16 updatedFee = 1000;

        vm.prank(FEE_SETTER);
        tychoRouter.setRouterFeeOnSolverFee(defaultFee);
        assertEq(tychoRouter.getRouterFeeOnSolverFee(), defaultFee);

        // Update fee
        vm.prank(FEE_SETTER);
        tychoRouter.setRouterFeeOnSolverFee(updatedFee);
        assertEq(tychoRouter.getRouterFeeOnSolverFee(), updatedFee);
    }

    function testSetCustomRouterFeeOnSolverFee() public {
        // Set default fee
        vm.prank(FEE_SETTER);
        uint16 defaultFee = 1000;
        tychoRouter.setRouterFeeOnSolverFee(defaultFee);

        // Set custom fee for user
        uint16 customFee = 500;

        vm.prank(FEE_SETTER);
        tychoRouter.setCustomRouterFeeOnSolverFee(BOB, customFee);

        // Check user gets custom fee
        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(BOB), customFee);

        // Check other users still get default fee
        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(ALICE), defaultFee);
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
        uint16 defaultFee = 1000;
        uint16 customFee = 500;
        tychoRouter.setRouterFeeOnSolverFee(defaultFee);
        tychoRouter.setCustomRouterFeeOnSolverFee(ALICE, customFee);
        vm.stopPrank();

        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(ALICE), customFee);

        // Remove custom fee
        vm.prank(FEE_SETTER);
        tychoRouter.removeCustomRouterFeeOnSolverFee(ALICE);

        // Should now return default fee
        assertEq(tychoRouter.getCustomRouterFeeOnSolverFee(ALICE), defaultFee);
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

        uint16 defaultRouterFeeOnOutput = 100;
        uint16 defaultRouterFeeOnSolverFee = 1000;

        uint16 user1FeeOnOutput = 50;
        uint16 user1FeeOnSolverFee = 500;

        uint16 user2FeeOnOutput = 150;
        uint16 user2FeeOnSolverFee = 1500;

        // Set default fees
        vm.startPrank(FEE_SETTER);
        tychoRouter.setRouterFeeOnOutput(defaultRouterFeeOnOutput);
        tychoRouter.setRouterFeeOnSolverFee(defaultRouterFeeOnSolverFee);

        // Set custom fees for different users
        tychoRouter.setCustomRouterFeeOnOutput(user1, user1FeeOnOutput);
        tychoRouter.setCustomRouterFeeOnSolverFee(user1, user1FeeOnSolverFee);

        tychoRouter.setCustomRouterFeeOnOutput(user2, user2FeeOnOutput);
        tychoRouter.setCustomRouterFeeOnSolverFee(user2, user2FeeOnSolverFee);
        vm.stopPrank();

        // Verify each user has correct fees
        assertEq(
            tychoRouter.getCustomRouterFeeOnOutput(user1), user1FeeOnOutput
        );
        assertEq(
            tychoRouter.getCustomRouterFeeOnSolverFee(user1),
            user1FeeOnSolverFee
        );

        assertEq(
            tychoRouter.getCustomRouterFeeOnOutput(user2), user2FeeOnOutput
        );
        assertEq(
            tychoRouter.getCustomRouterFeeOnSolverFee(user2),
            user2FeeOnSolverFee
        );

        // User3 should get default fees
        assertEq(
            tychoRouter.getCustomRouterFeeOnOutput(user3),
            defaultRouterFeeOnOutput
        );
        assertEq(
            tychoRouter.getCustomRouterFeeOnSolverFee(user3),
            defaultRouterFeeOnSolverFee
        );
    }

    function testUpdateDefaultFeeDoesNotAffectCustomFees() public {
        // Set initial default fee
        vm.startPrank(FEE_SETTER);
        uint16 defaultFee = 100;
        uint16 bobFee = 50;
        uint16 updatedDefaultFee = 200;

        tychoRouter.setRouterFeeOnOutput(defaultFee);

        // Set custom fee for user
        tychoRouter.setCustomRouterFeeOnOutput(BOB, bobFee);

        // Update default fee
        tychoRouter.setRouterFeeOnOutput(updatedDefaultFee);
        vm.stopPrank();

        // User should still have custom fee
        assertEq(tychoRouter.getCustomRouterFeeOnOutput(BOB), bobFee);

        // Other users should get new default
        assertEq(
            tychoRouter.getCustomRouterFeeOnOutput(ALICE), updatedDefaultFee
        );
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
