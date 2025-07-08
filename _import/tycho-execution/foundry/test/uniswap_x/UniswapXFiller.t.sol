// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "@src/uniswap_x/UniswapXFiller.sol";
import "../TychoRouterTestSetup.sol";

contract UniswapXFillerTest is Test, TychoRouterTestSetup {
    address EXECUTOR = makeAddr("executor");
    address REACTOR = address(0x00000011F84B9aa48e5f8aA8B9897600006289Be);

    UniswapXFiller filler;
    address fillerAddr;

    event CallbackVerifierSet(address indexed callbackVerifier);
    event Withdrawal(
        address indexed token, uint256 amount, address indexed receiver
    );

    function fillerSetup() public {
        vm.startPrank(ADMIN);
        filler = new UniswapXFiller(tychoRouterAddr, REACTOR);
        fillerAddr = address(filler);
        filler.grantRole(keccak256("EXECUTOR_ROLE"), EXECUTOR);
        vm.stopPrank();
    }

    function testTychoAddressZeroTychoRouter() public {
        vm.expectRevert(UniswapXFiller__AddressZero.selector);
        filler = new UniswapXFiller(address(0), REACTOR);
    }

    function testTychoAddressZeroReactor() public {
        vm.expectRevert(UniswapXFiller__AddressZero.selector);
        filler = new UniswapXFiller(tychoRouterAddr, address(0));
    }

    function testWithdrawNative() public {
        fillerSetup();
        vm.startPrank(ADMIN);
        // Send 100 ether to filler
        assertEq(fillerAddr.balance, 0);
        assertEq(ADMIN.balance, 0);
        vm.deal(fillerAddr, 100 ether);
        vm.expectEmit();
        emit Withdrawal(address(0), 100 ether, ADMIN);
        filler.withdrawNative(ADMIN);
        assertEq(fillerAddr.balance, 0);
        assertEq(ADMIN.balance, 100 ether);
        vm.stopPrank();
    }

    function testWithdrawNativeAddressZero() public {
        fillerSetup();
        vm.deal(fillerAddr, 100 ether);
        vm.startPrank(ADMIN);
        vm.expectRevert(UniswapXFiller__AddressZero.selector);
        filler.withdrawNative(address(0));
        vm.stopPrank();
    }

    function testWithdrawNativeMissingRole() public {
        fillerSetup();
        vm.deal(fillerAddr, 100 ether);
        // Not role ADMIN
        vm.startPrank(BOB);
        vm.expectRevert();
        filler.withdrawNative(ADMIN);
        vm.stopPrank();
    }

    function testWithdrawERC20Tokens() public {
        fillerSetup();

        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(WETH_ADDR);
        tokens[1] = IERC20(USDC_ADDR);
        for (uint256 i = 0; i < tokens.length; i++) {
            deal(address(tokens[i]), fillerAddr, 100 ether);
        }

        vm.startPrank(ADMIN);
        filler.withdraw(tokens, ADMIN);

        // Check balances after withdrawing
        for (uint256 i = 0; i < tokens.length; i++) {
            // slither-disable-next-line calls-loop
            assertEq(tokens[i].balanceOf(fillerAddr), 0);
            // slither-disable-next-line calls-loop
            assertEq(tokens[i].balanceOf(ADMIN), 100 ether);
        }
        vm.stopPrank();
    }

    function testWithdrawERC20TokensAddressZero() public {
        fillerSetup();

        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(WETH_ADDR);
        tokens[1] = IERC20(USDC_ADDR);
        for (uint256 i = 0; i < tokens.length; i++) {
            deal(address(tokens[i]), fillerAddr, 100 ether);
        }

        vm.startPrank(ADMIN);
        vm.expectRevert(UniswapXFiller__AddressZero.selector);
        filler.withdraw(tokens, address(0));
        vm.stopPrank();
    }

    function testWithdrawERC20TokensAddressMissingRole() public {
        fillerSetup();

        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(WETH_ADDR);
        tokens[1] = IERC20(USDC_ADDR);
        for (uint256 i = 0; i < tokens.length; i++) {
            deal(address(tokens[i]), fillerAddr, 100 ether);
        }

        // Not role ADMIN
        vm.startPrank(BOB);
        vm.expectRevert();
        filler.withdraw(tokens, ADMIN);
        vm.stopPrank();
    }
}
