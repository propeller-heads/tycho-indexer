// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {TychoRouter} from "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";

contract TychoRouterTest is TychoRouterTestSetup {
    bytes32 public constant EXECUTOR_SETTER_ROLE =
        0x6a1dd52dcad5bd732e45b6af4e7344fa284e2d7d4b23b5b09cb55d36b0685c87;
    bytes32 public constant FEE_SETTER_ROLE =
        0xe6ad9a47fbda1dc18de1eb5eeb7d935e5e81b4748f3cfc61e233e64f88182060;
    bytes32 public constant PAUSER_ROLE =
        0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a;
    bytes32 public constant FUND_RESCUER_ROLE =
        0x912e45d663a6f4cc1d0491d8f046e06c616f40352565ea1cdb86a0e1aaefa41b;

    event CallbackVerifierSet(address indexed callbackVerifier);
    event Withdrawal(
        address indexed token, uint256 amount, address indexed receiver
    );

    function testSetExecutorValidRole() public {
        vm.startPrank(executorSetter);
        tychoRouter.setSwapExecutor(DUMMY);
        vm.stopPrank();
        assert(tychoRouter.swapExecutors(DUMMY) == true);
    }

    function testRemoveExecutorMissingSetterRole() public {
        vm.expectRevert();
        tychoRouter.removeSwapExecutor(BOB);
    }

    function testSetExecutorMissingSetterRole() public {
        vm.expectRevert();
        tychoRouter.setSwapExecutor(DUMMY);
    }

    function testSetValidVerifier() public {
        vm.startPrank(executorSetter);
        vm.expectEmit();
        // Define the event we expect to be emitted at the next step
        emit CallbackVerifierSet(DUMMY);

        tychoRouter.setCallbackVerifier(DUMMY);
        vm.stopPrank();

        assert(tychoRouter.callbackVerifiers(DUMMY) == true);
    }

    function testRemoveVerifier() public {
        vm.startPrank(executorSetter);
        tychoRouter.setCallbackVerifier(DUMMY);
        tychoRouter.removeCallbackVerifier(DUMMY);
        vm.stopPrank();
        assert(tychoRouter.callbackVerifiers(DUMMY) == false);
    }

    function testRemoveUnSetVerifier() public {
        vm.startPrank(executorSetter);
        tychoRouter.removeCallbackVerifier(BOB);
        vm.stopPrank();
        assert(tychoRouter.callbackVerifiers(BOB) == false);
    }

    function testRemoveVerifierMissingSetterRole() public {
        vm.expectRevert();
        tychoRouter.removeCallbackVerifier(BOB);
    }

    function testSetVerifierMissingSetterRole() public {
        vm.expectRevert();
        tychoRouter.setCallbackVerifier(DUMMY);
    }

    function testSetVerifierNonContract() public {
        vm.startPrank(executorSetter);
        vm.expectRevert(
            abi.encodeWithSelector(TychoRouter__NonContractVerifier.selector)
        );
        tychoRouter.setCallbackVerifier(BOB);
        vm.stopPrank();
    }

    function testWithdrawNative() public {
        vm.startPrank(FUND_RESCUER);
        // Send 100 ether to tychoRouter
        assertEq(address(tychoRouter).balance, 0);
        assertEq(FUND_RESCUER.balance, 0);
        vm.deal(address(tychoRouter), 100 ether);
        vm.expectEmit();
        emit Withdrawal(address(0), 100 ether, FUND_RESCUER);
        tychoRouter.withdrawNative(FUND_RESCUER);
        assertEq(address(tychoRouter).balance, 0);
        assertEq(FUND_RESCUER.balance, 100 ether);
        vm.stopPrank();
    }

    function testWithdrawNativeFailures() public {
        vm.deal(address(tychoRouter), 100 ether);
        vm.startPrank(FUND_RESCUER);
        vm.expectRevert(TychoRouter__AddressZero.selector);
        tychoRouter.withdrawNative(address(0));
        vm.stopPrank();

        // Not role FUND_RESCUER
        vm.startPrank(BOB);
        vm.expectRevert();
        tychoRouter.withdrawNative(FUND_RESCUER);
        vm.stopPrank();
    }

    function testWithdrawERC20Tokens() public {
        vm.startPrank(BOB);
        mintTokens(100 ether, address(tychoRouter));
        vm.stopPrank();

        vm.startPrank(FUND_RESCUER);
        IERC20[] memory tokensArray = new IERC20[](3);
        tokensArray[0] = IERC20(address(tokens[0]));
        tokensArray[1] = IERC20(address(tokens[1]));
        tokensArray[2] = IERC20(address(tokens[2]));
        tychoRouter.withdraw(tokensArray, FUND_RESCUER);

        // Check balances after withdrawing
        for (uint256 i = 0; i < tokens.length; i++) {
            // slither-disable-next-line calls-loop
            assertEq(tokens[i].balanceOf(address(tychoRouter)), 0);
            // slither-disable-next-line calls-loop
            assertEq(tokens[i].balanceOf(FUND_RESCUER), 100 ether);
        }
        vm.stopPrank();
    }

    function testWithdrawERC20TokensFailures() public {
        mintTokens(100 ether, address(tychoRouter));
        IERC20[] memory tokensArray = new IERC20[](3);
        tokensArray[0] = IERC20(address(tokens[0]));
        tokensArray[1] = IERC20(address(tokens[1]));
        tokensArray[2] = IERC20(address(tokens[2]));

        vm.startPrank(FUND_RESCUER);
        vm.expectRevert(TychoRouter__AddressZero.selector);
        tychoRouter.withdraw(tokensArray, address(0));
        vm.stopPrank();

        // Not role FUND_RESCUER
        vm.startPrank(BOB);
        vm.expectRevert();
        tychoRouter.withdraw(tokensArray, FUND_RESCUER);
        vm.stopPrank();
    }

    function testFeeSetting() public {
        vm.startPrank(FEE_SETTER);
        assertEq(tychoRouter.fee(), 0);
        tychoRouter.setFee(100);
        assertEq(tychoRouter.fee(), 100);
        vm.stopPrank();

        vm.startPrank(BOB);
        vm.expectRevert();
        tychoRouter.setFee(200);
        vm.stopPrank();
    }

    function testFeeReceiverSetting() public {
        vm.startPrank(FEE_SETTER);
        assertEq(tychoRouter.feeReceiver(), address(0));
        tychoRouter.setFeeReceiver(FEE_RECEIVER);
        assertEq(tychoRouter.feeReceiver(), FEE_RECEIVER);
        vm.stopPrank();

        vm.startPrank(BOB);
        vm.expectRevert();
        tychoRouter.setFeeReceiver(FEE_RECEIVER);
        vm.stopPrank();
    }
}
