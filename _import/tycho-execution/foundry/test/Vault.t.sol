// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/Vault.sol";
import {TestUtils} from "./TestUtils.sol";
import {Constants} from "./Constants.sol";

contract VaultExposed is Vault {
    function setDelta(address token, int256 initialDelta) external {
        _setDelta(token, initialDelta);
    }

    function getDelta(address token) external view returns (int256 delta) {
        delta = _getDelta(token);
    }

    function getNegativeDeltaCount() external view returns (uint256 count) {
        count = _getNegativeDeltaCount();
    }

    function setNegativeDeltaCount(uint256 count) external {
        _setNegativeDeltaCount(count);
    }

    function updateDeltaAccounting(address token, int256 change) external {
        _updateDeltaAccounting(token, change);
    }

    function creditVault(address user, address token, uint256 amount) external {
        _creditVault(user, token, amount);
    }

    function debitVault(address user, address token, uint256 amount) external {
        _debitVault(user, token, amount);
    }

    function finalizeBalances(
        address user,
        address inputToken,
        uint256 inputAmount
    ) external {
        _finalizeBalances(user, inputToken, inputAmount);
    }

    function setUseVault(bool useVault) external {
        assembly {
            tstore(_USE_VAULT_SLOT, useVault)
        }
    }
}

contract VaultTest is Constants, TestUtils {
    VaultExposed public vault;

    function setUp() public {
        uint256 forkBlock = 24218176;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        vault = new VaultExposed();
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

    function testUpdateDeltaZeroPositiveToPositive() public {
        address token = address(0);
        int256 initialDelta = 100;
        int256 change = 0;
        uint256 negativeCountInitial = 0;

        vault.setDelta(token, initialDelta);
        vault.setNegativeDeltaCount(negativeCountInitial);
        int256 beforeChange = vault.getDelta(token);

        vault.updateDeltaAccounting(token, change);

        int256 afterChange = vault.getDelta(token);
        uint256 negativeCount = vault.getNegativeDeltaCount();

        assertEq(beforeChange, afterChange);
        assertEq(negativeCount, 0);
    }

    function testUpdateDeltaZeroNegativeToNegative() public {
        address token = address(0);
        int256 initialDelta = -100;
        int256 change = 0;
        uint256 negativeCountInitial = 1;

        vault.setDelta(token, initialDelta);
        vault.setNegativeDeltaCount(negativeCountInitial);

        int256 beforeChange = vault.getDelta(token);

        vault.updateDeltaAccounting(token, change);

        int256 afterChange = vault.getDelta(token);
        uint256 negativeCount = vault.getNegativeDeltaCount();

        assertEq(beforeChange, afterChange);
        assertEq(negativeCount, 1);
    }

    function testUpdateDeltaIncreasePositiveToPositive() public {
        address token = address(0);
        int256 initialDelta = 100;
        int256 change = 200;
        uint256 negativeCountInitial = 0;

        vault.setDelta(token, initialDelta);
        vault.setNegativeDeltaCount(negativeCountInitial);

        int256 beforeChange = vault.getDelta(token);

        vault.updateDeltaAccounting(token, change);

        int256 afterChange = vault.getDelta(token);
        uint256 negativeCount = vault.getNegativeDeltaCount();

        assertEq(beforeChange, 100);
        assertEq(afterChange, 300);
        assertEq(negativeCount, 0);
    }

    function testUpdateDeltaIncreaseNegativeToNegative() public {
        address token = address(0);
        int256 initialDelta = -100;
        int256 change = 15;
        uint256 negativeCountInitial = 1;

        vault.setDelta(token, initialDelta);
        vault.setNegativeDeltaCount(negativeCountInitial);

        int256 beforeChange = vault.getDelta(token);

        vault.updateDeltaAccounting(token, change);

        int256 afterChange = vault.getDelta(token);
        uint256 negativeCount = vault.getNegativeDeltaCount();

        assertEq(beforeChange, -100);
        assertEq(afterChange, -85);
        assertEq(negativeCount, 1);
    }

    function testUpdateDeltaIncreaseNegativeToPositive() public {
        address token = address(0);
        int256 initialDelta = -100;
        int256 change = 200;
        uint256 negativeCountInitial = 1;

        vault.setDelta(token, initialDelta);
        vault.setNegativeDeltaCount(negativeCountInitial);

        int256 beforeChange = vault.getDelta(token);

        vault.updateDeltaAccounting(token, change);

        int256 afterChange = vault.getDelta(token);
        uint256 negativeCount = vault.getNegativeDeltaCount();

        assertEq(beforeChange, -100);
        assertEq(afterChange, 100);
        assertEq(negativeCount, 0);
    }

    function testUpdateDeltaDecreasePositiveToPositive() public {
        address token = address(0);
        int256 initialDelta = 300;
        int256 change = -100;
        uint256 negativeCountInitial = 0;

        vault.setDelta(token, initialDelta);
        vault.setNegativeDeltaCount(negativeCountInitial);

        int256 beforeChange = vault.getDelta(token);

        vault.updateDeltaAccounting(token, change);

        int256 afterChange = vault.getDelta(token);
        uint256 negativeCount = vault.getNegativeDeltaCount();

        assertEq(beforeChange, 300);
        assertEq(afterChange, 200);
        assertEq(negativeCount, 0);
    }

    function testUpdateDeltaDecreasePositiveToNegative() public {
        address token = address(0);
        int256 initialDelta = 50;
        int256 change = -120;
        uint256 negativeCountInitial = 0;

        vault.setDelta(token, initialDelta);
        vault.setNegativeDeltaCount(negativeCountInitial);

        int256 beforeChange = vault.getDelta(token);

        vault.updateDeltaAccounting(token, change);

        int256 afterChange = vault.getDelta(token);
        uint256 negativeCount = vault.getNegativeDeltaCount();

        assertEq(beforeChange, 50);
        assertEq(afterChange, -70);
        assertEq(negativeCount, 1);
    }

    function testUpdateDeltaDecreaseNegativeToNegative() public {
        address token = address(0);
        int256 initialDelta = -50;
        int256 change = -120;
        uint256 negativeCountInitial = 1;

        vault.setDelta(token, initialDelta);
        vault.setNegativeDeltaCount(negativeCountInitial);

        int256 beforeChange = vault.getDelta(token);

        vault.updateDeltaAccounting(token, change);

        int256 afterChange = vault.getDelta(token);
        uint256 negativeCount = vault.getNegativeDeltaCount();

        assertEq(beforeChange, -50);
        assertEq(afterChange, -170);
        assertEq(negativeCount, 1);
    }

    function testCreditVault() public {
        uint256 amount = 1_000_000_000;

        uint256 id = uint256(uint160(USDC_ADDR));

        uint256 balanceBefore = vault.balanceOf(BOB, id);
        vault.creditVault(BOB, USDC_ADDR, amount);

        uint256 balance = vault.balanceOf(BOB, id);

        assertEq(balance, amount);
        assertEq(balance - balanceBefore, amount);
    }

    function testCreditVaultNonEmpty() public {
        uint256 amount = 1_000_000_000;

        uint256 id = uint256(uint160(USDC_ADDR));

        vault.creditVault(BOB, USDC_ADDR, amount);

        uint256 balanceBefore = vault.balanceOf(BOB, id);
        vault.creditVault(BOB, USDC_ADDR, amount);

        uint256 balance = vault.balanceOf(BOB, id);

        assertEq(balance, 2_000_000_000);
        assertEq(balance - balanceBefore, amount);
    }

    function testDebitVault() public {
        uint256 amount = 1_000_000_000;
        uint256 amount_to_debit = 2_000_000;

        uint256 id = uint256(uint160(USDC_ADDR));

        vault.creditVault(BOB, USDC_ADDR, amount);

        uint256 balanceBefore = vault.balanceOf(BOB, id);
        vault.debitVault(BOB, USDC_ADDR, amount_to_debit);

        uint256 balance = vault.balanceOf(BOB, id);

        assertEq(balance, 998_000_000);
        assertEq(balanceBefore - balance, amount_to_debit);
    }

    function testDebitVaultTooHigh() public {
        uint256 amount = 900_000_000;
        uint256 amount_to_debit = 1_000_000_000;

        uint256 id = uint256(uint160(USDC_ADDR));

        vault.creditVault(BOB, USDC_ADDR, amount);

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

        vault.debitVault(BOB, USDC_ADDR, amount_to_debit);
    }

    function testFinalizeBalancesNegativeCountTooHigh() public {
        uint256 inputAmount = 1_000_000;
        uint256 negativeCount = 3;

        vault.setNegativeDeltaCount(negativeCount);

        vm.expectRevert(
            abi.encodeWithSelector(
                Vault__UnexpectedNegativeCount.selector, negativeCount
            )
        );

        vault.finalizeBalances(BOB, USDC_ADDR, inputAmount);
    }

    function testFinalizeBalancesNegativeCountZero() public {
        uint256 inputAmount = 1_000_000;
        uint256 negativeCount = 0;

        vault.setNegativeDeltaCount(negativeCount);
        vault.creditVault(BOB, USDC_ADDR, 3_000_000);

        uint256 balanceStart = vault.balanceOf(BOB, uint256(uint160(USDC_ADDR)));

        vault.finalizeBalances(BOB, USDC_ADDR, inputAmount);

        uint256 balanceEnd = vault.balanceOf(BOB, uint256(uint160(USDC_ADDR)));

        assertEq(balanceStart, balanceEnd);
    }

    function testFinalizeBalancesInputAmountDoesNotMatchDelta() public {
        uint256 inputAmount = 1_000_000;
        int256 inputDelta = -2_000_000;
        uint256 negativeCount = 1;

        vault.setUseVault(true);
        vault.setNegativeDeltaCount(negativeCount);
        vault.setDelta(USDC_ADDR, inputDelta);
        vault.creditVault(BOB, USDC_ADDR, 3_000_000);

        vm.expectRevert(
            abi.encodeWithSelector(
                Vault__UnexpectedInputDelta.selector, inputDelta
            )
        );

        vault.finalizeBalances(BOB, USDC_ADDR, inputAmount);
    }

    function testFinalizeBalancesSuccess() public {
        uint256 inputAmount = 2_000_000;
        int256 inputDelta = -2_000_000;
        uint256 negativeCount = 1;

        vault.setUseVault(true);
        vault.setNegativeDeltaCount(negativeCount);
        vault.setDelta(USDC_ADDR, inputDelta);
        vault.creditVault(BOB, USDC_ADDR, 3_000_000);
        uint256 balanceStart = vault.balanceOf(BOB, uint256(uint160(USDC_ADDR)));

        vault.finalizeBalances(BOB, USDC_ADDR, inputAmount);

        uint256 balanceEnd = vault.balanceOf(BOB, uint256(uint160(USDC_ADDR)));

        assertEq(balanceStart - balanceEnd, inputAmount);
        assertEq(balanceEnd, 1_000_000);
    }
}
