// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter} from "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";
import "./executors/UniswapV4Utils.sol";
import {SafeCallback} from "@uniswap/v4-periphery/src/base/SafeCallback.sol";

contract TychoRouterSequentialSwapTest is TychoRouterTestSetup {
    function _getSequentialSwaps(bool permit2)
        internal
        view
        returns (bytes[] memory)
    {
        // Trade 1 WETH for USDC through DAI with 2 swaps on Uniswap V2
        // 1 WETH   ->   DAI   ->   USDC
        //       (univ2)     (univ2)

        TokenTransfer.TransferType transferType = permit2
            ? TokenTransfer.TransferType.TRANSFER_PERMIT2_TO_PROTOCOL
            : TokenTransfer.TransferType.TRANSFER_FROM_TO_PROTOCOL;

        bytes[] memory swaps = new bytes[](2);
        // WETH -> DAI
        swaps[0] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false, transferType
            )
        );

        // DAI -> USDC
        swaps[1] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                DAI_ADDR,
                DAI_USDC_POOL,
                ALICE,
                true,
                TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
            )
        );
        return swaps;
    }

    function testSequentialSwapPermit2() public {
        // Trade 1 WETH for USDC through DAI - see _getSequentialSwaps for more info
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes[] memory swaps = _getSequentialSwaps(true);
        tychoRouter.sequentialSwapPermit2(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1000_000000, // min amount
            false,
            false,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(ALICE);
        assertEq(usdcBalance, 2644659787);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSequentialSwapNoPermit2() public {
        // Trade 1 WETH for USDC through DAI - see _getSequentialSwaps for more info
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);

        bytes[] memory swaps = _getSequentialSwaps(false);
        tychoRouter.sequentialSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1000_000000, // min amount
            false,
            false,
            ALICE,
            pleEncode(swaps)
        );

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(ALICE);
        assertEq(usdcBalance, 2644659787);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSequentialSwapUndefinedMinAmount() public {
        // Trade 1 WETH for USDC through DAI - see _getSequentialSwaps for more info
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);

        bytes[] memory swaps = _getSequentialSwaps(false);
        vm.expectRevert(TychoRouter__UndefinedMinAmountOut.selector);
        tychoRouter.sequentialSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            0, // min amount
            false,
            false,
            ALICE,
            pleEncode(swaps)
        );
    }

    function testSequentialSwapInsufficientApproval() public {
        // Trade 1 WETH for USDC through DAI - see _getSequentialSwaps for more info
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn - 1);

        bytes[] memory swaps = _getSequentialSwaps(false);
        vm.expectRevert();
        tychoRouter.sequentialSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            0, // min amount
            false,
            false,
            ALICE,
            pleEncode(swaps)
        );
    }

    function testSequentialSwapNegativeSlippageFailure() public {
        // Trade 1 WETH for USDC through DAI - see _getSequentialSwaps for more info

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes[] memory swaps = _getSequentialSwaps(true);

        uint256 minAmountOut = 3000 * 1e18;

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector,
                2644659787, // actual amountOut
                minAmountOut
            )
        );
        tychoRouter.sequentialSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            false,
            false,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );
        vm.stopPrank();
    }

    function testSequentialSwapWrapETH() public {
        uint256 amountIn = 1 ether;
        deal(ALICE, amountIn);
        vm.startPrank(ALICE);

        IAllowanceTransfer.PermitSingle memory emptyPermitSingle =
        IAllowanceTransfer.PermitSingle({
            details: IAllowanceTransfer.PermitDetails({
                token: address(0),
                amount: 0,
                expiration: 0,
                nonce: 0
            }),
            spender: address(0),
            sigDeadline: 0
        });

        bytes[] memory swaps = new bytes[](2);
        // WETH -> DAI
        swaps[0] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR,
                WETH_DAI_POOL,
                tychoRouterAddr,
                false,
                TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
            )
        );

        // DAI -> USDC
        swaps[1] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                DAI_ADDR,
                DAI_USDC_POOL,
                tychoRouterAddr,
                true,
                TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
            )
        );

        uint256 amountOut = tychoRouter.sequentialSwapPermit2{value: amountIn}(
            amountIn,
            address(0),
            USDC_ADDR,
            1000_000000,
            true,
            false,
            ALICE,
            emptyPermitSingle,
            "",
            pleEncode(swaps)
        );
        uint256 expectedAmount = 2644659787;
        assertEq(amountOut, expectedAmount);
        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(ALICE);
        assertEq(usdcBalance, expectedAmount);
        assertEq(ALICE.balance, 0);

        vm.stopPrank();
    }

    function testSequentialSwapUnwrapETH() public {
        // Trade 3k DAI for WETH with 1 swap on Uniswap V2 and unwrap it at the end

        uint256 amountIn = 3_000 * 10 ** 6;
        deal(USDC_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);

        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(USDC_ADDR, tychoRouterAddr, amountIn);

        bytes[] memory swaps = new bytes[](2);

        // USDC -> DAI
        swaps[0] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                USDC_ADDR,
                DAI_USDC_POOL,
                tychoRouterAddr,
                false,
                TokenTransfer.TransferType.TRANSFER_PERMIT2_TO_PROTOCOL
            )
        );

        // DAI -> WETH
        swaps[1] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                DAI_ADDR,
                WETH_DAI_POOL,
                tychoRouterAddr,
                true,
                TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
            )
        );

        uint256 amountOut = tychoRouter.sequentialSwapPermit2(
            amountIn,
            USDC_ADDR,
            address(0),
            1 * 10 ** 18, // min amount
            false,
            true,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 expectedAmount = 1111174255471849849; // 1.11 ETH
        assertEq(amountOut, expectedAmount);
        assertEq(ALICE.balance, expectedAmount);

        vm.stopPrank();
    }

    function testCyclicSequentialSwap() public {
        // This test has start and end tokens that are the same
        // The flow is:
        // USDC --(USV3)--> WETH --(USV3)--> USDC
        uint256 amountIn = 100 * 10 ** 6;
        deal(USDC_ADDR, tychoRouterAddr, amountIn);

        bytes memory usdcWethV3Pool1ZeroOneData = encodeUniswapV3Swap(
            USDC_ADDR,
            WETH_ADDR,
            tychoRouterAddr,
            USDC_WETH_USV3,
            true,
            TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
        );

        bytes memory usdcWethV3Pool2OneZeroData = encodeUniswapV3Swap(
            WETH_ADDR,
            USDC_ADDR,
            tychoRouterAddr,
            USDC_WETH_USV3_2,
            false,
            TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
        );

        bytes[] memory swaps = new bytes[](2);
        // USDC -> WETH
        swaps[0] = encodeSequentialSwap(
            address(usv3Executor), usdcWethV3Pool1ZeroOneData
        );
        // WETH -> USDC
        swaps[1] = encodeSequentialSwap(
            address(usv3Executor), usdcWethV3Pool2OneZeroData
        );

        tychoRouter.exposedSequentialSwap(amountIn, pleEncode(swaps));
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 99889294);
    }
}
