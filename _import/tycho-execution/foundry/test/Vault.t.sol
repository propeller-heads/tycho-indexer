// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/Vault.sol";
import {TestUtils} from "./TestUtils.sol";
import {Constants} from "./Constants.sol";

contract TestVault is Vault {
    function applyDelta(address token, int256 initialDelta, int256 change)
        external
        returns (int256 beforeChange, int256 afterChange, uint256 negativeCount)
    {
        _setDelta(token, initialDelta);
        if (initialDelta < 0) {
            _setNegativeDeltaCount(_getNegativeDeltaCount() + 1);
        }
        beforeChange = _getDelta(token);

        _updateDeltaAccounting(token, change);

        afterChange = _getDelta(token);

        negativeCount = _getNegativeDeltaCount();
    }

    function creditVaultForTest(address user, address token, uint256 amount)
        external
    {
        _creditVault(user, token, amount);
    }

    function debitVaultForTest(address user, address token, uint256 amount)
        external
    {
        _debitVault(user, token, amount);
    }
}

contract VaultTest is Constants, TestUtils {
    TestVault public vault;

    function setUp() public {
        uint256 forkBlock = 24218176;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        vault = new TestVault();
    }

    function testDepositERC20() public {
        uint256 amount = 1_000_000_000;
        deal(USDC_ADDR, ALICE, amount);
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(address(vault), amount);
        vault.deposit(USDC_ADDR, amount);

        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 0);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(vault)), amount);
        assertEq(vault.balanceOf(ALICE, uint256(uint160(USDC_ADDR))), amount);
    }

    function testDepositETH() public {
        uint256 amount = 1 ether;
        deal(ALICE, amount);
        uint256 balanceBefore = address(vault).balance;
        vm.startPrank(ALICE);
        vault.deposit{value: amount}(address(0), amount);

        assertEq(ALICE.balance, 0);
        assertEq(address(vault).balance - balanceBefore, amount);
        assertEq(vault.balanceOf(ALICE, uint256(uint160(address(0)))), amount);
    }

    function testWithdrawERC20() public {
        uint256 amount = 1_000_000_000;
        deal(USDC_ADDR, ALICE, amount);
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(address(vault), amount);
        vault.deposit(USDC_ADDR, amount);

        uint256 amountToWithdraw = amount / 2;
        vault.withdraw(USDC_ADDR, amountToWithdraw);
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), amountToWithdraw);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(vault)), amountToWithdraw);
        assertEq(
            vault.balanceOf(ALICE, uint256(uint160(USDC_ADDR))),
            amountToWithdraw
        );
    }

    function testWithdrawETH() public {
        address user = makeAddr("brand-new-user");
        uint256 amount = 1 ether;
        deal(user, amount);
        uint256 balanceBefore = address(vault).balance;
        vm.startPrank(user);
        vault.deposit{value: amount}(address(0), amount);

        uint256 amountToWithdraw = amount / 2;
        vault.withdraw(address(0), amountToWithdraw);

        assertEq(user.balance, amountToWithdraw);
        assertEq(address(vault).balance - balanceBefore, amountToWithdraw);
        assertEq(
            vault.balanceOf(user, uint256(uint160(address(0)))),
            amountToWithdraw
        );
    }
}
