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
        assertEq(usdcBalance, 2615491639);
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
        assertEq(usdcBalance, 2615491639);
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
        assertEq(usdcBalance, 2615491639);
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
                2615491639, // actual amountOut
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
            2659881924818443699780,
            true,
            false,
            2,
            ALICE,
            emptyPermitSingle,
            "",
            pleEncode(swaps)
        );
        uint256 expectedAmount = 2659881924818443699787;
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
            1120007305574805920,
            false,
            true,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 expectedAmount = 1120007305574805922; // 1.12 ETH
        assertEq(amountOut, expectedAmount);
        assertEq(ALICE.balance, expectedAmount);

        vm.stopPrank();
    }

    function testSplitSwapSingleUSV3Permit2() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V3 using Permit2
        // Tests entire USV3 flow including callback
        // 1 WETH   ->   DAI
        //       (USV3)
        vm.startPrank(ALICE);
        uint256 amountIn = 10 ** 18;
        deal(WETH_ADDR, ALICE, amountIn);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, tychoRouterAddr, amountIn);

        uint256 expAmountOut = 1205_128428842122129186; //Swap 1 WETH for 1205.12 DAI
        bool zeroForOne = false;
        bytes memory protocolData = encodeUniswapV3Swap(
            WETH_ADDR,
            DAI_ADDR,
            ALICE,
            DAI_WETH_USV3,
            zeroForOne,
            TokenTransfer.TransferType.TRANSFER_PERMIT2_TO_PROTOCOL
        );
        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv3Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.splitSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            expAmountOut - 1,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 finalBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertGe(finalBalance, expAmountOut);

        vm.stopPrank();
    }

    function testEmptySwapsRevert() public {
        uint256 amountIn = 10 ** 18;
        bytes memory swaps = "";
        vm.expectRevert(TychoRouter__EmptySwaps.selector);
        tychoRouter.exposedSplitSwap(amountIn, 2, swaps);
    }

    function testSplitSwapSingleUSV4CallbackPermit2() public {
        vm.startPrank(ALICE);
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, ALICE, amountIn);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(USDE_ADDR, tychoRouterAddr, amountIn);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](1);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(100),
            tickSpacing: int24(1)
        });

        bytes memory protocolData = UniswapV4Utils.encodeExactInput(
            USDE_ADDR,
            USDT_ADDR,
            true,
            TokenTransfer.TransferType.TRANSFER_PERMIT2_TO_ROUTER,
            ALICE,
            pools
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv4Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.splitSwapPermit2(
            amountIn,
            USDE_ADDR,
            USDT_ADDR,
            99943850,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        assertEq(IERC20(USDT_ADDR).balanceOf(ALICE), 99943852);
        vm.stopPrank();
    }

    function testSplitSwapMultipleUSV4Callback() public {
        // This test has two uniswap v4 hops that will be executed inside of the V4 pool manager
        // USDE -> USDT -> WBTC
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, tychoRouterAddr, amountIn);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](2);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(100),
            tickSpacing: int24(1)
        });
        pools[1] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: WBTC_ADDR,
            fee: uint24(3000),
            tickSpacing: int24(60)
        });

        bytes memory protocolData = UniswapV4Utils.encodeExactInput(
            USDE_ADDR,
            WBTC_ADDR,
            true,
            TokenTransfer.TransferType.NONE,
            ALICE,
            pools
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv4Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));

        assertEq(IERC20(WBTC_ADDR).balanceOf(ALICE), 102718);
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
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 99574171);
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
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 99525908);
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
}
