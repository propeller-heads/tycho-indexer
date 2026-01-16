// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter} from "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";
import {
    RestrictTransferFrom__ExceededTransferFromAllowance
} from "@src/RestrictTransferFrom.sol";

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

        bytes memory protocolData = encodeUniswapV2Swap(
            DAI_WETH_UNIV2_POOL,
            ALICE,
            false,
            RestrictTransferFrom.TransferType.TransferFrom
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        tychoRouter.singleSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            2008817438608734439722,
            ALICE,
            0,
            address(0),
            permitSingle,
            signature,
            swap
        );

        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, 2018817438608734439722);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSingleSwapNoPermit2() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            DAI_WETH_UNIV2_POOL,
            ALICE,
            false,
            RestrictTransferFrom.TransferType.TransferFrom
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2000 * 1e18;
        uint256 amountOut = tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            true,
            0,
            address(0),
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

        bytes memory protocolData = encodeUniswapV2Swap(
            DAI_WETH_UNIV2_POOL,
            ALICE,
            false,
            RestrictTransferFrom.TransferType.None
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        vm.expectRevert(TychoRouter__UndefinedMinAmountOut.selector);
        tychoRouter.singleSwap(
            amountIn, WETH_ADDR, DAI_ADDR, 0, ALICE, true, 0, address(0), swap
        );
    }

    function testSingleSwapInsufficientApproval() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn - 1);

        bytes memory protocolData = encodeUniswapV2Swap(
            DAI_WETH_UNIV2_POOL,
            ALICE,
            false,
            RestrictTransferFrom.TransferType.TransferFrom
        );

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
            true,
            0,
            address(0),
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

        bytes memory protocolData = encodeUniswapV2Swap(
            DAI_WETH_UNIV2_POOL,
            ALICE,
            false,
            RestrictTransferFrom.TransferType.TransferFrom
        );

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
            true,
            0,
            address(0),
            swap
        );
    }

    function testSingleSwapNoTransferNeededIllegalTransfer() public {
        // Tokens are already in the router, there is no need to transfer them.
        // Failure because there will be an attempt on an illegal transfer.
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, address(tychoRouter), amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            DAI_WETH_UNIV2_POOL,
            ALICE,
            false,
            RestrictTransferFrom.TransferType.TransferFrom
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        vm.expectRevert(
            abi.encodeWithSelector(
                RestrictTransferFrom__ExceededTransferFromAllowance.selector,
                0, // allowed amount
                amountIn // attempted amount
            )
        );
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            2000 * 1e18,
            ALICE,
            false,
            0,
            address(0),
            swap
        );

        vm.stopPrank();
    }

    function testSingleSwapIntegration() public {
        // Tests swapping WETH -> DAI on a USV2 pool with regular approvals
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData = loadCallDataFromFile(
            "test_single_swap_strategy_encoder_no_permit2"
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
