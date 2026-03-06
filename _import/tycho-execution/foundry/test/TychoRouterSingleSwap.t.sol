// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter, ClientFeeParams} from "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";
import {Vault__InsufficientBalance} from "@src/Vault.sol";

contract TychoRouterSingleSwapTest is TychoRouterTestSetup {
    function testSingleSwapPermit2() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2 using Permit2
        // 1 WETH   ->   DAI
        //       (USV2)
        vm.startPrank(ALICE);

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        tychoRouter.singleSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            2008817438608734439722,
            ALICE,
            noClientFee(),
            permitSingle,
            signature,
            swap
        );

        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, 2018817438608734439722);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSingleSwapTransferFrom() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2000 * 1e18;
        uint256 amountOut = tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            noClientFee(),
            swap
        );

        uint256 expectedAmount = 2018817438608734439722;
        assertEq(amountOut, expectedAmount);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, expectedAmount);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSingleSwapUndefinedMinAmount() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        vm.expectRevert(TychoRouter__UndefinedMinAmountOut.selector);
        tychoRouter.singleSwap(
            amountIn, WETH_ADDR, DAI_ADDR, 0, ALICE, noClientFee(), swap
        );
    }

    function testSingleSwapInsufficientApproval() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn - 1);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2600 * 1e18;
        vm.expectRevert();
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            noClientFee(),
            swap
        );
    }

    function testSingleSwapNegativeSlippageFailure() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 5600 * 1e18;

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector,
                2018817438608734439722, // actual amountOut
                minAmountOut
            )
        );
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            noClientFee(),
            swap
        );
    }

    function testSingleSwapClientContribution() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // The minAmountOut is higher than the output amount from the pool
        // The client contribution is sent with the final amount out to the receiver (not optimized last transfer)
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        // The client will contribute to this swap with their own funds
        uint256 maxContribution = 20 * 1e18;
        deal(DAI_ADDR, ALICE, maxContribution);
        IERC20(DAI_ADDR).approve(address(tychoRouterAddr), maxContribution);

        tychoRouter.deposit(DAI_ADDR, maxContribution);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2020 * 1e18;
        ClientFeeParams memory feeParams = ClientFeeParams({
            clientFeeBps: 0,
            clientFeeReceiver: ALICE,
            maxClientContribution: maxContribution,
            deadline: block.timestamp + 1 hours,
            clientSignature: new bytes(0)
        });
        feeParams.clientSignature =
            signClientFee(feeParams, tychoRouterAddr, ALICE_PK);

        uint256 amountOut = tychoRouter.singleSwap(
            amountIn, WETH_ADDR, DAI_ADDR, minAmountOut, ALICE, feeParams, swap
        );

        assertEq(amountOut, minAmountOut);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, minAmountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);
        uint256 swapAmount = 2018817438608734439722;
        assertEq(
            tychoRouter.balanceOf(ALICE, uint256(uint160(DAI_ADDR))),
            maxContribution - (minAmountOut - swapAmount)
        );

        vm.stopPrank();
    }

    function testSingleSwapClientContributionNotEnough() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // The minAmountOut is higher than the output amount from the pool
        // and there won't be enough client contribution to cover the difference.
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2020 * 1e18;
        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector,
                2018817438608734439722, // actual amountOut
                minAmountOut
            )
        );

        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            noClientFee(),
            swap
        );

        vm.stopPrank();
    }

    function testSingleSwapClientContributionNotEnoughFunds() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // The minAmountOut is higher than the output amount from the pool
        // the client contribution is high enough but there won't be enough funds in the vault
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2020 * 1e18;
        uint256 swapAmount = 2018817438608734439722;
        vm.expectRevert(
            abi.encodeWithSelector(
                Vault__InsufficientBalance.selector,
                0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2,
                0x6B175474E89094C44Da98b954EedeAC495271d0F,
                minAmountOut - swapAmount,
                0
            )
        );

        ClientFeeParams memory feeParams =
            makeClientFeeParams(0, 20 * 1e18, tychoRouterAddr, ALICE_PK);

        tychoRouter.singleSwap(
            amountIn, WETH_ADDR, DAI_ADDR, minAmountOut, ALICE, feeParams, swap
        );

        vm.stopPrank();
    }

    function testSingleSwapClientContributionDirectlyToReceiver() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // The minAmountOut is higher than the output amount from the pool
        // The client contribution is sent separately to the user (the last transfer is optimized)
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        // The client will contribute to this swap with their own funds
        uint256 maxContribution = 20 * 1e18;
        deal(DAI_ADDR, ALICE, maxContribution);
        IERC20(DAI_ADDR).approve(address(tychoRouterAddr), maxContribution);

        tychoRouter.deposit(DAI_ADDR, maxContribution);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2020 * 1e18;
        ClientFeeParams memory feeParams =
            makeClientFeeParams(0, maxContribution, tychoRouterAddr, ALICE_PK);

        uint256 amountOut = tychoRouter.singleSwap(
            amountIn, WETH_ADDR, DAI_ADDR, minAmountOut, ALICE, feeParams, swap
        );

        assertEq(amountOut, minAmountOut);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, minAmountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);
        uint256 swapAmount = 2018817438608734439722;
        assertEq(
            tychoRouter.balanceOf(ALICE, uint256(uint160(DAI_ADDR))),
            maxContribution - (minAmountOut - swapAmount)
        );

        vm.stopPrank();
    }

    function testSingleSwapFeeOnTransferToken() public {
        // Before fix: reverted with TychoRouter__AmountOutNotFullyReceived
        // because the executor returned the calculated amount (not accounting
        // for the transfer fee), but the receiver got less.
        address ZKML_ADDR = address(0xE92344b4eDF545F3209094B192E46600A19E7C2D);
        address ZKML_WETH_UNIV2_POOL =
            0x315Ed60258702F8d159b98dF4C0DBEb1D7D776dF;

        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(ZKML_WETH_UNIV2_POOL, WETH_ADDR, ZKML_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 amountOut = tychoRouter.singleSwap(
            amountIn, WETH_ADDR, ZKML_ADDR, 1, ALICE, noClientFee(), swap
        );

        assertGt(amountOut, 0);
        assertEq(IERC20(ZKML_ADDR).balanceOf(ALICE), amountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSingleSwapFeeOnTransferTokenInput() public {
        // Before fix: reverted with "UniswapV2: K" because the executor
        // calculated amountOut based on the full amountIn, but the pool
        // only received amountIn minus the transfer fee.
        address ZKML_ADDR = address(0xE92344b4eDF545F3209094B192E46600A19E7C2D);
        address ZKML_WETH_UNIV2_POOL =
            0x315Ed60258702F8d159b98dF4C0DBEb1D7D776dF;

        uint256 amountIn = 1000 ether;

        deal(ZKML_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(ZKML_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(ZKML_WETH_UNIV2_POOL, ZKML_ADDR, WETH_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 amountOut = tychoRouter.singleSwap(
            amountIn, ZKML_ADDR, WETH_ADDR, 1, ALICE, noClientFee(), swap
        );

        assertGt(amountOut, 0);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), amountOut);

        vm.stopPrank();
    }

    function testSingleSwapIntegration() public {
        // Tests swapping WETH -> DAI on a USV2 pool with regular approvals
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData = loadCallDataFromFile(
            "test_single_swap_strategy_encoder_transfer_from"
        );
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 2018817438608734439722);
    }

    function testSingleSwapIntegrationPermit2() public {
        // Tests swapping WETH -> DAI on a USV2 pool with permit2
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_single_swap_strategy_encoder");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 2018817438608734439722);
    }
}
