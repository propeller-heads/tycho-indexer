// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter} from "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";
import "./executors/UniswapV4Utils.sol";
import {SafeCallback} from "@uniswap/v4-periphery/src/base/SafeCallback.sol";

contract TychoRouterSequentialSwapTest is TychoRouterTestSetup {
    function _getSequentialSwaps() internal view returns (bytes[] memory) {
        // Trade 1 WETH for USDC through DAI with 2 swaps on Uniswap V2
        // 1 WETH   ->   DAI   ->   USDC
        //       (univ2)     (univ2)

        bytes[] memory swaps = new bytes[](2);
        // WETH -> DAI
        swaps[0] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR,
                WETH_DAI_POOL,
                DAI_USDC_POOL, // receiver (direct to next pool)
                false,
                RestrictTransferFrom.TransferType.TransferFrom // transfer to protocol from router
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
                RestrictTransferFrom.TransferType.None // funds already sent to pool
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

        bytes[] memory swaps = _getSequentialSwaps();
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
        assertEq(usdcBalance, 2005810530);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSequentialSwapNoPermit2() public {
        // Trade 1 WETH for USDC through DAI - see _getSequentialSwaps for more info
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);

        bytes[] memory swaps = _getSequentialSwaps();
        tychoRouter.sequentialSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1000_000000, // min amount
            false,
            false,
            ALICE,
            true,
            pleEncode(swaps)
        );

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(ALICE);
        assertEq(usdcBalance, 2005810530);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSequentialSwapUndefinedMinAmount() public {
        // Trade 1 WETH for USDC through DAI - see _getSequentialSwaps for more info
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);

        bytes[] memory swaps = _getSequentialSwaps();
        vm.expectRevert(TychoRouter__UndefinedMinAmountOut.selector);
        tychoRouter.sequentialSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            0, // min amount
            false,
            false,
            ALICE,
            true,
            pleEncode(swaps)
        );
    }

    function testSequentialSwapInsufficientApproval() public {
        // Trade 1 WETH for USDC through DAI - see _getSequentialSwaps for more info
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn - 1);

        bytes[] memory swaps = _getSequentialSwaps();
        vm.expectRevert();
        tychoRouter.sequentialSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            0, // min amount
            false,
            false,
            ALICE,
            true,
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

        bytes[] memory swaps = _getSequentialSwaps();

        uint256 minAmountOut = 3000 * 1e18;

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector,
                2005810530, // actual amountOut
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
                DAI_USDC_POOL,
                false,
                RestrictTransferFrom.TransferType.Transfer
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
                RestrictTransferFrom.TransferType.None
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
        uint256 expectedAmount = 2005810530;
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
                RestrictTransferFrom.TransferType.TransferFrom
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
                RestrictTransferFrom.TransferType.Transfer
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

        uint256 expectedAmount = 1466332452295613768; // 1.11 ETH
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
            RestrictTransferFrom.TransferType.Transfer
        );

        bytes memory usdcWethV3Pool2OneZeroData = encodeUniswapV3Swap(
            WETH_ADDR,
            USDC_ADDR,
            tychoRouterAddr,
            USDC_WETH_USV3_2,
            false,
            RestrictTransferFrom.TransferType.Transfer
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
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 99792554);
    }

    function testSequentialSwapIntegrationPermit2() public {
        // Performs a split swap from WETH to USDC though WBTC and DAI using USV2 pools
        //
        //   WETH ──(USV2)──> WBTC ───(USV2)──> USDC
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(USDC_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_sequential_swap_strategy_encoder");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 1951856272);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSequentialSwapIntegration() public {
        // Performs a split swap from WETH to USDC though WBTC and DAI using USV2 pools
        //
        //   WETH ──(USV2)──> WBTC ───(USV2)──> USDC
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(USDC_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData = loadCallDataFromFile(
            "test_sequential_swap_strategy_encoder_no_permit2"
        );
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 1951856272);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSequentialCyclicSwapIntegration() public {
        // USDC -> WETH -> USDC  using two pools
        deal(USDC_ADDR, ALICE, 100 * 10 ** 6);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_sequential_strategy_cyclic_swap");
        (bool success,) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 99792554);

        vm.stopPrank();
    }

    function testUSV3USV2Integration() public {
        // Performs a sequential swap from WETH to USDC though WBTC and DAI using USV3 and USV2 pools
        //
        //   WETH ──(USV3)──> WBTC ───(USV2)──> USDC
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(USDC_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_uniswap_v3_uniswap_v2");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 1952973189);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testUSV3USV3Integration() public {
        // Performs a sequential swap from WETH to USDC though WBTC using USV3 pools
        //
        //   WETH ──(USV3)──> WBTC ───(USV3)──> USDC
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(USDC_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_uniswap_v3_uniswap_v3");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 2015740345);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testUSV3CurveIntegration() public {
        // Performs a sequential swap from WETH to USDT though WBTC using USV3 and Curve pools
        //
        //   WETH ──(USV3)──> WBTC ───(USV3)──> USDT
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(USDT_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData = loadCallDataFromFile("test_uniswap_v3_curve");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(USDT_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 2018869128);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testBalancerV2USV2Integration() public {
        // Performs a sequential swap from WETH to USDC though WBTC using Balancer v2 and USV2 pools
        //
        //   WETH ──(balancer)──> WBTC ───(USV2)──> USDC
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(USDT_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_balancer_v2_uniswap_v2");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 1949668893);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testBebopUSV2Integration() public {
        // Performs a sequential swap from USDC to WETH though Bebop and USV2 pools
        //
        //   USDC ──(bebop)──> WETH ───(USV2)──> USDC
        deal(USDC_ADDR, ALICE, 1000 * 10 ** 6);
        uint256 balanceBefore = IERC20(USDC_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData = loadCallDataFromFile("test_encode_bebop_single");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        // Expected amount would need to be determined from actual integration test
        assertGt(balanceAfter, balanceBefore, "Should receive some tokens");
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 0);
    }
}
