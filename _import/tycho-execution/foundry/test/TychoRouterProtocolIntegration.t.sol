// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "./TychoRouterTestSetup.sol";
import "./executors/UniswapV4Utils.sol";

contract TychoRouterTestProtocolIntegration is TychoRouterTestSetup {
    function testSingleSwapUSV4CallbackPermit2() public {
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
            RestrictTransferFrom.TransferType.TransferFrom,
            ALICE,
            pools
        );

        bytes memory swap =
            encodeSingleSwap(address(usv4Executor), protocolData);

        tychoRouter.singleSwapPermit2(
            amountIn,
            USDE_ADDR,
            USDT_ADDR,
            99943850,
            false,
            false,
            ALICE,
            permitSingle,
            signature,
            swap
        );

        assertEq(IERC20(USDT_ADDR).balanceOf(ALICE), 99963618);
        vm.stopPrank();
    }

    function testSplitSwapMultipleUSV4Callback() public {
        // This test has two uniswap v4 hops that will be executed inside of the V4 pool manager
        // USDE -> USDT -> WBTC
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, ALICE, amountIn);

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
            RestrictTransferFrom.TransferType.TransferFrom,
            ALICE,
            pools
        );

        bytes memory swap =
            encodeSingleSwap(address(usv4Executor), protocolData);

        vm.startPrank(ALICE);
        IERC20(USDE_ADDR).approve(tychoRouterAddr, amountIn);
        tychoRouter.singleSwap(
            amountIn, USDE_ADDR, WBTC_ADDR, 118280, false, false, ALICE, swap
        );

        assertEq(IERC20(WBTC_ADDR).balanceOf(ALICE), 118281);
    }

    function testSingleUSV4IntegrationGroupedSwap() public {
        // Test created with calldata from our router encoder.

        // Performs a single swap from USDC to PEPE though ETH using two
        // consecutive USV4 pools. It's a single swap because it is a consecutive grouped swaps
        //
        //   USDC ──(USV4)──> ETH ───(USV4)──> PEPE
        //
        deal(USDC_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(PEPE_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_usv4_grouped_swap"
        );
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(PEPE_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 123172000092711286554274694);
    }

    function testMultiProtocolIntegration() public {
        // Test created with calldata from our router encoder.
        //
        //  DAI ─(USV2)─> WETH ─(bal)─> WBTC ─(curve)─> USDT ─(ekubo)─> ETH ─(USV4)─> USDC

        deal(DAI_ADDR, ALICE, 1500 ether);
        uint256 balanceBefore = address(ALICE).balance;

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(DAI_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData = loadCallDataFromFile("test_multi_protocol");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = address(ALICE).balance;

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 732214216964381330);
    }

    function testSingleUSV4IntegrationInputETH() public {
        // Test created with calldata from our router encoder.

        // Performs a single swap from ETH to PEPE without wrapping or unwrapping
        //
        //   ETH ───(USV4)──> PEPE
        //
        deal(ALICE, 1 ether);
        uint256 balanceBefore = IERC20(PEPE_ADDR).balanceOf(ALICE);

        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_usv4_eth_in");
        (bool success,) = tychoRouterAddr.call{value: 1 ether}(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(PEPE_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 235610487387677804636755778);
    }

    function testSingleUSV4IntegrationOutputETH() public {
        // Test created with calldata from our router encoder.

        // Performs a single swap from USDC to ETH without wrapping or unwrapping
        //
        //   USDC ───(USV4)──> ETH
        //
        deal(USDC_ADDR, ALICE, 3000_000000);
        uint256 balanceBefore = ALICE.balance;

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);

        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_usv4_eth_out");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = ALICE.balance;

        assertTrue(success, "Call Failed");
        console.logUint(balanceAfter - balanceBefore);
        assertEq(balanceAfter - balanceBefore, 1474406268748155809);
    }

    function testSingleMaverickIntegration() public {
        vm.stopPrank();

        deal(GHO_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(USDC_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(GHO_ADDR).approve(tychoRouterAddr, type(uint256).max);

        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_maverick");
        (bool success,) = tychoRouterAddr.call(callData);

        uint256 balanceAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertGe(balanceAfter - balanceBefore, 999725);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSingleEkuboIntegration() public {
        vm.stopPrank();

        deal(ALICE, 1 ether);
        uint256 balanceBefore = IERC20(USDC_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_ekubo");
        (bool success,) = tychoRouterAddr.call{value: 1 ether}(callData);

        uint256 balanceAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertGe(balanceAfter - balanceBefore, 26173932);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSingleCurveIntegration() public {
        deal(UWU_ADDR, ALICE, 1 ether);

        vm.startPrank(ALICE);
        IERC20(UWU_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_curve");
        (bool success,) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 2877855391767);

        vm.stopPrank();
    }

    function testSingleSwapUSV3Permit2() public {
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
            RestrictTransferFrom.TransferType.TransferFrom
        );
        bytes memory swap =
            encodeSingleSwap(address(usv3Executor), protocolData);

        tychoRouter.singleSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            expAmountOut - 1,
            false,
            false,
            ALICE,
            permitSingle,
            signature,
            swap
        );

        uint256 finalBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertGe(finalBalance, expAmountOut);

        vm.stopPrank();
    }
}
