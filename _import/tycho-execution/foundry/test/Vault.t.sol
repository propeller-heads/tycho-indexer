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

    function testUpdateDeltaZero() public {
        (int256 beforeChange, int256 afterChange, uint256 negativeCount) =
            vault.applyDelta(address(0), 100, 0);
        assertEq(beforeChange, afterChange);
        assertEq(negativeCount, 0);
    }

    function testUpdateDeltaZeroInNegative() public {
        (int256 beforeChange, int256 afterChange, uint256 negativeCount) =
            vault.applyDelta(address(0), -100, 0);
        assertEq(beforeChange, afterChange);
        assertEq(negativeCount, 1);
    }

    function testUpdateDeltaIncreaseInPositive() public {
        (int256 beforeChange, int256 afterChange, uint256 negativeCount) =
            vault.applyDelta(address(0), 100, 200);
        assertEq(beforeChange, 100);
        assertEq(afterChange, 300);
        assertEq(negativeCount, 0);
    }

    function testUpdateDeltaIncreaseInNegative() public {
        (int256 beforeChange, int256 afterChange, uint256 negativeCount) =
            vault.applyDelta(address(0), -100, 15);
        assertEq(beforeChange, -100);
        assertEq(afterChange, -85);
        assertEq(negativeCount, 1);
    }

    function testUpdateDeltaIncreaseToPositive() public {
        (int256 beforeChange, int256 afterChange, uint256 negativeCount) =
            vault.applyDelta(address(0), -100, 200);
        assertEq(beforeChange, -100);
        assertEq(afterChange, 100);
        assertEq(negativeCount, 0);
    }

    function testUpdateDeltaDecreaseInPositive() public {
        (int256 beforeChange, int256 afterChange, uint256 negativeCount) =
            vault.applyDelta(address(0), 300, -100);
        assertEq(beforeChange, 300);
        assertEq(afterChange, 200);
        assertEq(negativeCount, 0);
    }

    function testUpdateDeltaDecreaseToNegative() public {
        (int256 beforeChange, int256 afterChange, uint256 negativeCount) =
            vault.applyDelta(address(0), 50, -120);
        assertEq(beforeChange, 50);
        assertEq(afterChange, -70);
        assertEq(negativeCount, 1);
    }

    function testUpdateDeltaDecreaseInNegative() public {
        (int256 beforeChange, int256 afterChange, uint256 negativeCount) =
            vault.applyDelta(address(0), -50, -120);
        assertEq(beforeChange, -50);
        assertEq(afterChange, -170);
        assertEq(negativeCount, 1);
    }

    function testCreditVault() public {
        uint256 amount = 1_000_000_000;

        uint256 id = uint256(uint160(USDC_ADDR));

        uint256 balanceBefore = vault.balanceOf(BOB, id);
        vault.creditVaultForTest(BOB, USDC_ADDR, amount);

        uint256 balance = vault.balanceOf(BOB, id);

        assertEq(balance, amount);
        assertEq(balance - balanceBefore, amount);
    }

    function testCreditVaultNonEmpty() public {
        uint256 amount = 1_000_000_000;

        uint256 id = uint256(uint160(USDC_ADDR));

        vault.creditVaultForTest(BOB, USDC_ADDR, amount);

        uint256 balanceBefore = vault.balanceOf(BOB, id);
        vault.creditVaultForTest(BOB, USDC_ADDR, amount);

        uint256 balance = vault.balanceOf(BOB, id);

        assertEq(balance, 2_000_000_000);
        assertEq(balance - balanceBefore, amount);
    }

    function testDebitVault() public {
        uint256 amount = 1_000_000_000;
        uint256 amount_to_debit = 2_000_000;

        uint256 id = uint256(uint160(USDC_ADDR));

        vault.creditVaultForTest(BOB, USDC_ADDR, amount);

        uint256 balanceBefore = vault.balanceOf(BOB, id);
        vault.debitVaultForTest(BOB, USDC_ADDR, amount_to_debit);

        uint256 balance = vault.balanceOf(BOB, id);

        assertEq(balance, 998_000_000);
        assertEq(balanceBefore - balance, amount_to_debit);
    }

    function testDebitVaultTooHigh() public {
        uint256 amount = 900_000_000;
        uint256 amount_to_debit = 1_000_000_000;

        uint256 id = uint256(uint160(USDC_ADDR));

        vault.creditVaultForTest(BOB, USDC_ADDR, amount);

        uint256 balanceBefore = vault.balanceOf(BOB, id);

        vm.expectRevert(
            abi.encodeWithSelector(
                Vault__InsufficientBalance.selector,
                BOB,
                USDC_ADDR,
                amount_to_debit,
                balanceBefore
            )
        );

        vault.debitVaultForTest(BOB, USDC_ADDR, amount_to_debit);
    }
}
