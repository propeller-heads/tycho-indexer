// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter} from "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";
import "./executors/UniswapV4Utils.sol";
import {SafeCallback} from "@uniswap/v4-periphery/src/base/SafeCallback.sol";

contract TychoRouterSplitSwapTest is TychoRouterTestSetup {
    function _getSplitSwaps(bool permit2)
        private
        view
        returns (bytes[] memory)
    {
        // Trade 1 WETH for USDC through DAI and WBTC with 4 swaps on Uniswap V2
        //          ->   DAI   ->
        // 1 WETH                   USDC
        //          ->   WBTC  ->
        //       (univ2)     (univ2)
        bytes[] memory swaps = new bytes[](4);

        TokenTransfer.TransferType inTransferType = permit2
            ? TokenTransfer.TransferType.TRANSFER_PERMIT2_TO_PROTOCOL
            : TokenTransfer.TransferType.TRANSFER_FROM_TO_PROTOCOL;

        // WETH -> WBTC (60%)
        swaps[0] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100, // 60%
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR,
                WETH_WBTC_POOL,
                tychoRouterAddr,
                false,
                inTransferType
            )
        );
        // WBTC -> USDC
        swaps[1] = encodeSplitSwap(
            uint8(1),
            uint8(2),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(
                WBTC_ADDR,
                USDC_WBTC_POOL,
                ALICE,
                true,
                TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
            )
        );
        // WETH -> DAI
        swaps[2] = encodeSplitSwap(
            uint8(0),
            uint8(3),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false, inTransferType
            )
        );

        // DAI -> USDC
        swaps[3] = encodeSplitSwap(
            uint8(3),
            uint8(2),
            uint24(0),
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

    function testSplitSwapInternalMethod() public {
        // Trade 1 WETH for USDC through DAI and WBTC - see _getSplitSwaps for more info

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);
        bytes[] memory swaps = _getSplitSwaps(false);
        tychoRouter.exposedSplitSwap(amountIn, 4, pleEncode(swaps));
        vm.stopPrank();

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(ALICE);
        assertEq(usdcBalance, 1989737355);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSplitSwapPermit2() public {
        // Trade 1 WETH for USDC through DAI and WBTC - see _getSplitSwaps for more info

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes[] memory swaps = _getSplitSwaps(true);

        tychoRouter.splitSwapPermit2(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1, // min amount
            false,
            false,
            4,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(ALICE);
        assertEq(usdcBalance, 1989737355);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSplitSwapNoPermit2() public {
        // Trade 1 WETH for USDC through DAI and WBTC - see _getSplitSwaps for more info
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);

        bytes[] memory swaps = _getSplitSwaps(false);

        tychoRouter.splitSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1000_000000, // min amount
            false,
            false,
            4,
            ALICE,
            pleEncode(swaps)
        );

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(ALICE);
        assertEq(usdcBalance, 1989737355);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);
    }

    function testSplitSwapUndefinedMinAmount() public {
        // Min amount should always be non-zero. If zero, swap attempt should revert.
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes[] memory swaps = _getSplitSwaps(false);

        vm.expectRevert(TychoRouter__UndefinedMinAmountOut.selector);
        tychoRouter.splitSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            0, // min amount
            false,
            false,
            4,
            ALICE,
            pleEncode(swaps)
        );
        vm.stopPrank();
    }

    function testSplitSwapInsufficientApproval() public {
        // Trade 1 WETH for USDC through DAI and WBTC - see _getSplitSwaps for more info
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve less than the amountIn
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn - 1);
        bytes[] memory swaps = _getSplitSwaps(false);

        vm.expectRevert();
        tychoRouter.splitSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1000_000000, // min amount
            false,
            false,
            2,
            ALICE,
            pleEncode(swaps)
        );

        vm.stopPrank();
    }

    function testSplitSwapNegativeSlippageFailure() public {
        // Trade 1 WETH for USDC through DAI and WBTC - see _getSplitSwaps for more info

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes[] memory swaps = _getSplitSwaps(true);

        uint256 minAmountOut = 3000 * 1e18;

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector,
                1989737355, // actual amountOut
                minAmountOut
            )
        );
        tychoRouter.splitSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            false,
            false,
            4,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );
        vm.stopPrank();
    }

    function testSplitSwapWrapETH() public {
        // Trade 1 ETH (and wrap it) for DAI with 1 swap on Uniswap V2

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
        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR,
            WETH_DAI_POOL,
            ALICE,
            false,
            TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.splitSwapPermit2{value: amountIn}(
            amountIn,
            address(0),
            DAI_ADDR,
            2008817438608734439722,
            true,
            false,
            2,
            ALICE,
            emptyPermitSingle,
            "",
            pleEncode(swaps)
        );
        uint256 expectedAmount = 2018817438608734439722;
        assertEq(amountOut, expectedAmount);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, expectedAmount);
        assertEq(ALICE.balance, 0);

        vm.stopPrank();
    }

    function testSplitSwapUnwrapETH() public {
        // Trade 3k DAI for WETH with 1 swap on Uniswap V2 and unwrap it at the end

        uint256 amountIn = 3_000 * 10 ** 18;
        deal(DAI_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);

        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(DAI_ADDR, tychoRouterAddr, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            DAI_ADDR,
            WETH_DAI_POOL,
            tychoRouterAddr,
            true,
            TokenTransfer.TransferType.TRANSFER_PERMIT2_TO_PROTOCOL
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.splitSwapPermit2(
            amountIn,
            DAI_ADDR,
            address(0),
            1465644707225677606,
            false,
            true,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 expectedAmount = 1475644707225677606; // 1.12 ETH
        assertEq(amountOut, expectedAmount);
        assertEq(ALICE.balance, expectedAmount);

        vm.stopPrank();
    }

    function testEmptySwapsRevert() public {
        uint256 amountIn = 10 ** 18;
        bytes memory swaps = "";
        vm.expectRevert(TychoRouter__EmptySwaps.selector);
        tychoRouter.exposedSplitSwap(amountIn, 2, swaps);
    }

    function testSplitInputCyclicSwapInternalMethod() public {
        // This test has start and end tokens that are the same
        // The flow is:
        //            ┌─ (USV3, 60% split) ──> WETH ─┐
        //            │                              │
        // USDC ──────┤                              ├──(USV2)──> USDC
        //            │                              │
        //            └─ (USV3, 40% split) ──> WETH ─┘
        uint256 amountIn = 100 * 10 ** 6;
        deal(USDC_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the TychoRouter to spend USDC
        IERC20(USDC_ADDR).approve(tychoRouterAddr, amountIn);

        bytes memory usdcWethV3Pool1ZeroOneData = encodeUniswapV3Swap(
            USDC_ADDR,
            WETH_ADDR,
            tychoRouterAddr,
            USDC_WETH_USV3,
            true,
            TokenTransfer.TransferType.TRANSFER_FROM_TO_PROTOCOL
        );

        bytes memory usdcWethV3Pool2ZeroOneData = encodeUniswapV3Swap(
            USDC_ADDR,
            WETH_ADDR,
            tychoRouterAddr,
            USDC_WETH_USV3_2,
            true,
            TokenTransfer.TransferType.TRANSFER_FROM_TO_PROTOCOL
        );

        bytes memory wethUsdcV2OneZeroData = encodeUniswapV2Swap(
            WETH_ADDR,
            USDC_WETH_USV2,
            tychoRouterAddr,
            false,
            TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
        );

        bytes[] memory swaps = new bytes[](3);
        // USDC -> WETH (60% split)
        swaps[0] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100, // 60%
            address(usv3Executor),
            usdcWethV3Pool1ZeroOneData
        );
        // USDC -> WETH (40% remainder)
        swaps[1] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv3Executor),
            usdcWethV3Pool2ZeroOneData
        );
        // WETH -> USDC
        swaps[2] = encodeSplitSwap(
            uint8(1),
            uint8(0),
            uint24(0),
            address(usv2Executor),
            wethUsdcV2OneZeroData
        );
        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));
        vm.stopPrank();
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 99654537);
    }

    function testSplitOutputCyclicSwapInternalMethod() public {
        // This test has start and end tokens that are the same
        // The flow is:
        //                        ┌─── (USV3, 60% split) ───┐
        //                        │                         │
        // USDC ──(USV2) ── WETH──|                         ├─> USDC
        //                        │                         │
        //                        └─── (USV3, 40% split) ───┘

        uint256 amountIn = 100 * 10 ** 6;
        deal(USDC_ADDR, tychoRouterAddr, amountIn);

        bytes memory usdcWethV2Data = encodeUniswapV2Swap(
            USDC_ADDR,
            USDC_WETH_USV2,
            tychoRouterAddr,
            true,
            TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
        );

        bytes memory usdcWethV3Pool1OneZeroData = encodeUniswapV3Swap(
            WETH_ADDR,
            USDC_ADDR,
            tychoRouterAddr,
            USDC_WETH_USV3,
            false,
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

        bytes[] memory swaps = new bytes[](3);
        // USDC -> WETH
        swaps[0] = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), usdcWethV2Data
        );
        // WETH -> USDC
        swaps[1] = encodeSplitSwap(
            uint8(1),
            uint8(0),
            (0xffffff * 60) / 100,
            address(usv3Executor),
            usdcWethV3Pool1OneZeroData
        );

        // WETH -> USDC
        swaps[2] = encodeSplitSwap(
            uint8(1),
            uint8(0),
            uint24(0),
            address(usv3Executor),
            usdcWethV3Pool2OneZeroData
        );

        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 99444510);
    }

    // Base Network Tests
    // Make sure to set the RPC_URL to base network
    function testSplitSwapInternalMethodBase() public {
        vm.skip(true);
        vm.rollFork(26857267);
        uint256 amountIn = 10 * 10 ** 6;
        deal(BASE_USDC, tychoRouterAddr, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            BASE_USDC,
            USDC_MAG7_POOL,
            tychoRouterAddr,
            true,
            TokenTransfer.TransferType.TRANSFER_FROM_TO_PROTOCOL
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));
        assertGt(IERC20(BASE_MAG7).balanceOf(tychoRouterAddr), 1379830606);
    }

    function testSplitSwapIntegration() public {
        // Performs a split swap from WETH to USDC though WBTC and DAI using USV2 pools
        //
        //         ┌──(USV2)──> WBTC ───(USV2)──> USDC
        //   WETH ─┤
        //         └──(USV2)──> DAI  ───(USV2)──> USDC
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(USDC_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_split_swap_strategy_encoder");
        (bool success,) = tychoRouterAddr.call(callData);
        vm.stopPrank();

        uint256 balanceAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertGe(balanceAfter - balanceBefore, 26173932);

        // All input tokens are transferred to the router at first. Make sure we used
        // all of it (and thus our splits are correct).
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSplitInputCyclicSwapIntegration() public {
        deal(USDC_ADDR, ALICE, 100 * 10 ** 6);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_split_input_cyclic_swap");
        (bool success,) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 99654537);

        vm.stopPrank();
    }

    function testSplitOutputCyclicSwapIntegration() public {
        deal(USDC_ADDR, ALICE, 100 * 10 ** 6);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_split_output_cyclic_swap");
        (bool success,) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 99444510);

        vm.stopPrank();
    }
}
