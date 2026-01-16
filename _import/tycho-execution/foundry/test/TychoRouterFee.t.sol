// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";

contract TychoRouterFeeTest is TychoRouterTestSetup {
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

    function testDefaultFeeTaker() public view {
        // Taker should be zero if not explicitly set
        assertEq(tychoRouter.getFeeTaker(), address(0));
    }
}
