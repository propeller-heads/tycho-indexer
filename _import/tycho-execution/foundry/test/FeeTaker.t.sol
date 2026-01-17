// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/FeeTaker.sol";
import "./Constants.sol";

contract FeeTakerTest is Constants {
    FeeTaker feeTaker;

    bytes32 public constant ROUTER_FEE_SETTER_ROLE =
        0x9939157be7760e9462f1d5a0dcad88b616ddc64138e317108b40b1cf55601348;

    function setUp() public {
        feeTaker = new FeeTaker();
        feeTaker.grantRole(ROUTER_FEE_SETTER_ROLE, FEE_SETTER);
    }

    function testCalculateOnlyRouterFeeOnOutput() public {
        // Set router fee on output and receiver
        vm.startPrank(FEE_SETTER);
        feeTaker.setRouterFeeReceiver(ALICE);
        feeTaker.setRouterFeeOnOutput(100); // 1%
        vm.stopPrank();

        uint256 amountIn = 1 ether;

        // The user is BOB - he doesn't get any router fee discounts.
        (
            uint256 amountOut,
            uint256 routerFee,
            address returnedRouterFeeReceiver,
            uint256 solverFee
        ) = feeTaker.calculateFee(amountIn, BOB, 0);

        // routerFeeOnOutput = 1 ether * 100 / 10000 = 0.01 ether
        // amountOut = 1 ether - 0.01 ether = 0.99 ether
        assertEq(amountOut, 0.99 ether);
        assertEq(routerFee, 0.01 ether);
        assertEq(returnedRouterFeeReceiver, ALICE);
        assertEq(solverFee, 0);
    }

    function testCalculateOnlyRouterFeeOnSolverFee() public {
        // Test with only router fee on solver fee set (requires solver fee to be set too)
        vm.prank(FEE_SETTER);
        feeTaker.setRouterFeeOnSolverFee(1000); // 10% of solver fee

        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 200; // 2%

        (
            uint256 amountOut,
            uint256 routerFee,
            address returnedRouterFeeReceiver,
            uint256 solverFee
        ) = feeTaker.calculateFee(amountIn, BOB, solverFeeBps);

        // solverFee = 1 ether * 200 / 10000 = 0.02 ether
        // routerFeeOnSolverFee = 0.02 ether * 1000 / 10000 = 0.002 ether
        // solverPortion = 0.02 - 0.002 = 0.018 ether
        // amountOut = 1 ether - 0.02 ether = 0.98 ether
        assertEq(amountOut, 0.98 ether);
        assertEq(routerFee, 0.002 ether);
        assertEq(returnedRouterFeeReceiver, address(this));
        assertEq(solverFee, 0.018 ether);
    }

    function testCalculateWithCustomUserFee() public {
        // Set default router fee
        vm.startPrank(FEE_SETTER);
        feeTaker.setRouterFeeOnOutput(100); // 1%

        // Set custom fee for BOB
        feeTaker.setCustomRouterFeeOnOutput(BOB, 50); // 0.5%
        vm.stopPrank();

        uint256 amountIn = 1 ether;

        // ALICE should get default fee
        (uint256 amountOutAlice, uint256 routerFeeAlice,,) =
            feeTaker.calculateFee(amountIn, ALICE, 0);
        assertEq(amountOutAlice, 0.99 ether);
        assertEq(routerFeeAlice, 0.01 ether);

        // BOB should get custom fee
        (uint256 amountOutBob, uint256 routerFeeBob,,) =
            feeTaker.calculateFee(amountIn, BOB, 0);
        assertEq(amountOutBob, 0.995 ether); // 0.5% fee
        assertEq(routerFeeBob, 0.005 ether);
    }

    function testCalculateNoFeesSet() public view {
        // No fees set, should return full amount
        uint256 amountIn = 1 ether;

        (
            uint256 amountOut,
            uint256 routerFee,
            address returnedRouterFeeReceiver,
            uint256 solverFee
        ) = feeTaker.calculateFee(amountIn, ALICE, 0);

        assertEq(amountOut, 1 ether);
        assertEq(routerFee, 0);
        assertEq(returnedRouterFeeReceiver, address(this));
        assertEq(solverFee, 0);
    }

    function testCalculateOnlySolverFee() public view {
        // Test with only solver fee set, no router fees
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 150; // 1.5%

        // BOB is the user - but this is irrelevant since
        // there are no router fees to overwrite with custom user fees
        (
            uint256 amountOut,
            uint256 routerFee,
            address returnedRouterFeeReceiver,
            uint256 solverFee
        ) = feeTaker.calculateFee(amountIn, BOB, solverFeeBps);

        // solverFee = 1 ether * 150 / 10000 = 0.015 ether
        // amountOut = 1 ether - 0.015 ether = 0.985 ether
        assertEq(amountOut, 0.985 ether);
        assertEq(routerFee, 0);
        assertEq(returnedRouterFeeReceiver, address(this));
        assertEq(solverFee, 0.015 ether);
    }

    function testCalculateAllFeesSet() public {
        vm.startPrank(FEE_SETTER);
        feeTaker.setRouterFeeOnOutput(50); // 0.5%
        feeTaker.setRouterFeeOnSolverFee(500); // 5% of solver fee
        vm.stopPrank();

        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 200; // 2%

        (
            uint256 amountOut,
            uint256 routerFee,
            address returnedRouterFeeReceiver,
            uint256 solverFee
        ) = feeTaker.calculateFee(amountIn, BOB, solverFeeBps);

        // 1. solverFee = 1 ether * 200 / 10000 = 0.02 ether
        //    routerFeeOnSolverFee = 0.02 ether * 500 / 10000 = 0.001 ether
        //    solverPortion = 0.02 - 0.001 = 0.019 ether
        //    amountAfterSolverFee = 1 ether - 0.02 ether = 0.98 ether
        // 2. routerFeeOnOutput = 0.98 ether * 50 / 10000 = 0.0049 ether
        //    amountOut = 0.98 ether - 0.0049 ether = 0.9751 ether
        //    totalRouterFee = 0.001 + 0.0049 = 0.0059 ether
        assertEq(amountOut, 0.9751 ether);
        assertEq(routerFee, 0.0059 ether);
        assertEq(returnedRouterFeeReceiver, address(this));
        assertEq(solverFee, 0.019 ether);
    }

    function testCalculateCombinedFeeTooHigh() public {
        // Test with solver fee + router fee on output > 100%
        vm.prank(FEE_SETTER);
        feeTaker.setRouterFeeOnOutput(5000); // 50%

        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 5001; // 50.01% - combined makes 100.01%

        vm.expectRevert(abi.encodeWithSelector(FeeTaker__FeeTooHigh.selector));
        feeTaker.calculateFee(amountIn, BOB, solverFeeBps);
    }

    function testCalculateRouterFeeOnSolverFeeTooHigh() public {
        // Set router fee on solver fee > 100%
        vm.prank(FEE_SETTER);
        feeTaker.setRouterFeeOnSolverFee(10001); // 100.01%

        uint256 amountIn = 1 ether;

        vm.expectRevert(abi.encodeWithSelector(FeeTaker__FeeTooHigh.selector));
        feeTaker.calculateFee(amountIn, ALICE, 100);
    }

    function testCalculateWithCustomRouterFeeReceiver() public {
        // Set custom router fee receiver
        vm.startPrank(FEE_SETTER);
        feeTaker.setRouterFeeReceiver(BOB);
        feeTaker.setRouterFeeOnOutput(100); // 1%
        vm.stopPrank();

        uint256 amountIn = 1 ether;

        (,, address returnedRouterFeeReceiver,) =
            feeTaker.calculateFee(amountIn, ALICE, 0);

        assertEq(returnedRouterFeeReceiver, BOB);
    }

    function testCalculateCustomRouterFeeOnSolverFee() public {
        // Test that custom router fee on solver fee overrides default
        vm.startPrank(FEE_SETTER);
        feeTaker.setRouterFeeOnSolverFee(1000); // 10% default
        feeTaker.setCustomRouterFeeOnSolverFee(ALICE, 500); // 5% custom for ALICE
        vm.stopPrank();

        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 200; // 2%

        // ALICE should get custom router fee on solver fee (5%)
        (
            uint256 amountOutAlice,
            uint256 routerFeeAlice,
            address routerFeeReceiverAlice,
            uint256 solverFeeAlice
        ) = feeTaker.calculateFee(amountIn, ALICE, solverFeeBps);

        // routerFeeOnSolverFee = 0.02 * 500 / 10000 = 0.001 ether
        assertEq(amountOutAlice, 0.98 ether); // 1 - 0.02 solver fee
        assertEq(routerFeeAlice, 0.001 ether);
        assertEq(routerFeeReceiverAlice, address(this));
        assertEq(solverFeeAlice, 0.019 ether); // 0.02 - 0.001 router cut

        // BOB should get default router fee on solver fee (10%)
        (
            uint256 amountOutBob,
            uint256 routerFeeBob,
            address routerFeeReceiverBob,
            uint256 solverFeeBob
        ) = feeTaker.calculateFee(amountIn, BOB, solverFeeBps);

        // routerFeeOnSolverFee = 0.02 * 1000 / 10000 = 0.002 ether
        assertEq(amountOutBob, 0.98 ether); // 1 - 0.02 solver fee
        assertEq(routerFeeBob, 0.002 ether);
        assertEq(routerFeeReceiverBob, address(this));
        assertEq(solverFeeBob, 0.018 ether); // 0.02 - 0.002 router cut
    }

    function testCalculateBothCustomFeesSet() public {
        // Test that both custom fees work together
        vm.startPrank(FEE_SETTER);
        feeTaker.setRouterFeeOnOutput(100); // 1% default
        feeTaker.setRouterFeeOnSolverFee(1000); // 10% default
        feeTaker.setCustomRouterFeeOnOutput(ALICE, 50); // 0.5% custom
        feeTaker.setCustomRouterFeeOnSolverFee(ALICE, 500); // 5% custom
        vm.stopPrank();

        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 200; // 2%

        (
            uint256 amountOut,
            uint256 routerFee,
            address routerFeeReceiver,
            uint256 solverFee
        ) = feeTaker.calculateFee(amountIn, ALICE, solverFeeBps);

        // 1. solverFee = 1 ether * 200 / 10000 = 0.02 ether
        //    routerFeeOnSolverFee = 0.02 * 500 / 10000 = 0.001 ether (custom 5%)
        //    amountAfterSolverFee = 1 ether - 0.02 = 0.98 ether
        // 2. routerFeeOnOutput = 0.98 * 50 / 10000 = 0.0049 ether (custom 0.5%)
        //    amountOut = 0.98 - 0.0049 = 0.9751 ether
        //    totalRouterFee = 0.001 + 0.0049 = 0.0059 ether
        assertEq(amountOut, 0.9751 ether);
        assertEq(routerFee, 0.0059 ether);
        assertEq(routerFeeReceiver, address(this));
        assertEq(solverFee, 0.019 ether); // 0.02 - 0.001 router cut
    }
}

// Tests relating to setting the fee values themselves with proper access control,
// but not performing calculations using these values.
contract FeeTakerConfigTest is Constants {
    FeeTaker feeTaker;

    bytes32 public constant ROUTER_FEE_SETTER_ROLE =
        0x9939157be7760e9462f1d5a0dcad88b616ddc64138e317108b40b1cf55601348;

    function setUp() public {
        feeTaker = new FeeTaker();
        feeTaker.grantRole(ROUTER_FEE_SETTER_ROLE, FEE_SETTER);
    }

    // ROUTER FEE ON OUTPUT TESTS
    function testSetRouterFeeOnOutputUnauthorized() public {
        vm.prank(BOB);
        vm.expectRevert();
        feeTaker.setRouterFeeOnOutput(100);
    }

    function testSetRouterFeeOnOutput() public {
        // Set initial fee
        vm.prank(FEE_SETTER);
        feeTaker.setRouterFeeOnOutput(100);
        assertEq(feeTaker.getRouterFeeOnOutput(), 100);

        // Update fee
        vm.prank(FEE_SETTER);
        feeTaker.setRouterFeeOnOutput(200);
        assertEq(feeTaker.getRouterFeeOnOutput(), 200);
    }

    function testSetCustomRouterFeeOnOutput() public {
        // Set default fee
        vm.prank(FEE_SETTER);
        uint16 defaultFee = 100;
        feeTaker.setRouterFeeOnOutput(defaultFee);

        // Set custom fee for user
        uint16 userFee = 50;
        vm.prank(FEE_SETTER);
        feeTaker.setCustomRouterFeeOnOutput(BOB, userFee);

        // Check user gets custom fee
        assertEq(feeTaker.getCustomRouterFeeOnOutput(BOB), userFee);

        // Check other users still get default fee
        assertEq(feeTaker.getCustomRouterFeeOnOutput(ALICE), defaultFee);
    }

    function testSetCustomRouterFeeOnOutputUnauthorized() public {
        vm.prank(BOB);
        vm.expectRevert();
        feeTaker.setCustomRouterFeeOnOutput(BOB, 50);
    }

    function testSetCustomRouterFeeOnOutputWithoutDefault() public {
        // Set custom fee for user without setting default first
        uint16 userFee = 75;
        vm.prank(FEE_SETTER);
        feeTaker.setCustomRouterFeeOnOutput(ALICE, userFee);
        assertEq(feeTaker.getCustomRouterFeeOnOutput(ALICE), userFee);
    }

    function testRemoveCustomRouterFeeOnOutput() public {
        // Set default and custom fee
        vm.startPrank(FEE_SETTER);
        uint16 defaultFee = 100;
        uint16 customFee = 50;
        feeTaker.setRouterFeeOnOutput(defaultFee);
        feeTaker.setCustomRouterFeeOnOutput(ALICE, customFee);
        vm.stopPrank();

        assertEq(feeTaker.getCustomRouterFeeOnOutput(ALICE), customFee);

        // Remove custom fee
        vm.prank(FEE_SETTER);
        feeTaker.removeCustomRouterFeeOnOutput(ALICE);

        // Should now return default fee
        assertEq(feeTaker.getCustomRouterFeeOnOutput(ALICE), defaultFee);
    }

    function testRemoveCustomRouterFeeOnOutputUnauthorized() public {
        vm.prank(BOB);
        vm.expectRevert();
        feeTaker.removeCustomRouterFeeOnOutput(ALICE);
    }

    // ROUTER FEE ON SOLVER FEE TESTS
    function testSetRouterFeeOnSolverFeeUnauthorized() public {
        vm.prank(BOB);
        vm.expectRevert();
        feeTaker.setRouterFeeOnSolverFee(1000);
    }

    function testSetRouterFeeOnSolverFee() public {
        uint16 defaultFee = 500;
        uint16 updatedFee = 1000;

        vm.prank(FEE_SETTER);
        feeTaker.setRouterFeeOnSolverFee(defaultFee);
        assertEq(feeTaker.getRouterFeeOnSolverFee(), defaultFee);

        // Update fee
        vm.prank(FEE_SETTER);
        feeTaker.setRouterFeeOnSolverFee(updatedFee);
        assertEq(feeTaker.getRouterFeeOnSolverFee(), updatedFee);
    }

    function testSetCustomRouterFeeOnSolverFee() public {
        // Set default fee
        vm.prank(FEE_SETTER);
        uint16 defaultFee = 1000;
        feeTaker.setRouterFeeOnSolverFee(defaultFee);

        // Set custom fee for user
        uint16 customFee = 500;

        vm.prank(FEE_SETTER);
        feeTaker.setCustomRouterFeeOnSolverFee(BOB, customFee);

        // Check user gets custom fee
        assertEq(feeTaker.getCustomRouterFeeOnSolverFee(BOB), customFee);

        // Check other users still get default fee
        assertEq(feeTaker.getCustomRouterFeeOnSolverFee(ALICE), defaultFee);
    }

    function testSetCustomRouterFeeOnSolverFeeUnauthorized() public {
        vm.prank(BOB);
        vm.expectRevert();
        feeTaker.setCustomRouterFeeOnSolverFee(ALICE, 500);
    }

    function testSetCustomRouterFeeOnSolverFeeWithoutDefault() public {
        // Set custom fee for user without setting default first
        uint16 userFee = 750;

        vm.prank(FEE_SETTER);
        feeTaker.setCustomRouterFeeOnSolverFee(ALICE, userFee);

        assertEq(feeTaker.getCustomRouterFeeOnSolverFee(ALICE), userFee);
    }

    function testRemoveCustomRouterFeeOnSolverFee() public {
        // Set default and custom fee
        vm.startPrank(FEE_SETTER);
        uint16 defaultFee = 1000;
        uint16 customFee = 500;
        feeTaker.setRouterFeeOnSolverFee(defaultFee);
        feeTaker.setCustomRouterFeeOnSolverFee(ALICE, customFee);
        vm.stopPrank();

        assertEq(feeTaker.getCustomRouterFeeOnSolverFee(ALICE), customFee);

        // Remove custom fee
        vm.prank(FEE_SETTER);
        feeTaker.removeCustomRouterFeeOnSolverFee(ALICE);

        // Should now return default fee
        assertEq(feeTaker.getCustomRouterFeeOnSolverFee(ALICE), defaultFee);
    }

    function testRemoveCustomRouterFeeOnSolverFeeUnauthorized() public {
        vm.prank(BOB);
        vm.expectRevert();
        feeTaker.removeCustomRouterFeeOnSolverFee(ALICE);
    }

    // FEE RECEIVER TESTS
    function testSetRouterFeeReceiver() public {
        vm.prank(FEE_SETTER);
        feeTaker.setRouterFeeReceiver(BOB);
        assertEq(feeTaker.getRouterFeeReceiver(), BOB);
    }

    function testSetRouterFeeReceiverZeroAddressReverts() public {
        vm.prank(FEE_SETTER);
        vm.expectRevert(FeeTaker__AddressZero.selector);
        feeTaker.setRouterFeeReceiver(address(0));
    }

    function testSetRouterFeeReceiverUnauthorized() public {
        vm.prank(BOB);
        vm.expectRevert();
        feeTaker.setRouterFeeReceiver(BOB);
    }

    function testSetRouterFeeReceiverUpdatesCorrectly() public {
        address newReceiver = address(0x888);

        vm.startPrank(FEE_SETTER);
        feeTaker.setRouterFeeReceiver(BOB);
        assertEq(feeTaker.getRouterFeeReceiver(), BOB);

        feeTaker.setRouterFeeReceiver(newReceiver);
        vm.stopPrank();

        assertEq(feeTaker.getRouterFeeReceiver(), newReceiver);
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
        feeTaker.setRouterFeeOnOutput(defaultRouterFeeOnOutput);
        feeTaker.setRouterFeeOnSolverFee(defaultRouterFeeOnSolverFee);

        // Set custom fees for different users
        feeTaker.setCustomRouterFeeOnOutput(user1, user1FeeOnOutput);
        feeTaker.setCustomRouterFeeOnSolverFee(user1, user1FeeOnSolverFee);

        feeTaker.setCustomRouterFeeOnOutput(user2, user2FeeOnOutput);
        feeTaker.setCustomRouterFeeOnSolverFee(user2, user2FeeOnSolverFee);
        vm.stopPrank();

        // Verify each user has correct fees
        assertEq(feeTaker.getCustomRouterFeeOnOutput(user1), user1FeeOnOutput);
        assertEq(
            feeTaker.getCustomRouterFeeOnSolverFee(user1), user1FeeOnSolverFee
        );

        assertEq(feeTaker.getCustomRouterFeeOnOutput(user2), user2FeeOnOutput);
        assertEq(
            feeTaker.getCustomRouterFeeOnSolverFee(user2), user2FeeOnSolverFee
        );

        // User3 should get default fees
        assertEq(
            feeTaker.getCustomRouterFeeOnOutput(user3), defaultRouterFeeOnOutput
        );
        assertEq(
            feeTaker.getCustomRouterFeeOnSolverFee(user3),
            defaultRouterFeeOnSolverFee
        );
    }

    function testUpdateDefaultFeeDoesNotAffectCustomFees() public {
        // Set initial default fee
        vm.startPrank(FEE_SETTER);
        uint16 defaultFee = 100;
        uint16 bobFee = 50;
        uint16 updatedDefaultFee = 200;

        feeTaker.setRouterFeeOnOutput(defaultFee);

        // Set custom fee for user
        feeTaker.setCustomRouterFeeOnOutput(BOB, bobFee);

        // Update default fee
        feeTaker.setRouterFeeOnOutput(updatedDefaultFee);
        vm.stopPrank();

        // User should still have custom fee
        assertEq(feeTaker.getCustomRouterFeeOnOutput(BOB), bobFee);

        // Other users should get new default
        assertEq(feeTaker.getCustomRouterFeeOnOutput(ALICE), updatedDefaultFee);
    }

    function testDefaultValues() public view {
        // Default fees should be zero
        assertEq(feeTaker.getRouterFeeOnOutput(), 0);
        assertEq(feeTaker.getRouterFeeOnSolverFee(), 0);
        assertEq(feeTaker.getCustomRouterFeeOnOutput(ALICE), 0);
        assertEq(feeTaker.getCustomRouterFeeOnSolverFee(ALICE), 0);
        // Default fee receiver should be the contract deployer
        assertEq(feeTaker.getRouterFeeReceiver(), address(this));
    }

    function testMaximumFee() public {
        uint16 maxFee = type(uint16).max;

        vm.startPrank(FEE_SETTER);
        feeTaker.setRouterFeeOnOutput(maxFee);
        feeTaker.setRouterFeeOnSolverFee(maxFee);
        vm.stopPrank();

        assertEq(feeTaker.getRouterFeeOnOutput(), maxFee);
        assertEq(feeTaker.getRouterFeeOnSolverFee(), maxFee);
    }
}
