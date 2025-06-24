// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "./TychoRouterTestSetup.sol";
import "./protocols/UniswapV4Utils.sol";
import "@src/executors/BebopExecutor.sol";

contract TychoRouterTestProtocolIntegration is TychoRouterTestSetup {
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

    function testSingleBebopIntegration() public {
        // The calldata swaps 200 USDC for ONDO
        // The receiver in the order is 0xc5564C13A157E6240659fb81882A28091add8670
        address orderTaker = 0xc5564C13A157E6240659fb81882A28091add8670;
        address maker = 0xCe79b081c0c924cb67848723ed3057234d10FC6b;
        deal(USDC_ADDR, orderTaker, 200 * 10 ** 6); // 200 USDC
        uint256 expAmountOut = 237212396774431060000; // Expected ONDO amount from calldata

        // Fund the maker with ONDO and approve settlement
        deal(ONDO_ADDR, maker, expAmountOut);
        vm.prank(maker);
        IERC20(ONDO_ADDR).approve(BEBOP_SETTLEMENT, expAmountOut);

        uint256 ondoBefore = IERC20(ONDO_ADDR).balanceOf(orderTaker);

        vm.startPrank(orderTaker);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, type(uint256).max);

        // Load calldata from file
        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_bebop");

        (bool success,) = tychoRouterAddr.call(callData);

        // Check the receiver's balance (not ALICE, since the order specifies a different receiver)
        uint256 ondoReceived =
            IERC20(ONDO_ADDR).balanceOf(orderTaker) - ondoBefore;
        assertTrue(success, "Call Failed");
        assertEq(ondoReceived, expAmountOut);
        assertEq(
            IERC20(USDC_ADDR).balanceOf(tychoRouterAddr),
            0,
            "USDC left in router"
        );

        vm.stopPrank();
    }

    function testBebopAggregateIntegration() public {
        // Based on real transaction: https://etherscan.io/tx/0xec88410136c287280da87d0a37c1cb745f320406ca3ae55c678dec11996c1b1c
        address orderTaker = 0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6; // This is both taker and receiver in the order
        uint256 ethAmount = 9850000000000000; // 0.00985 WETH
        uint256 expAmountOut = 17969561; // 17.969561 USDC expected output

        // Fund the two makers from the real transaction with USDC
        address maker1 = 0x67336Cec42645F55059EfF241Cb02eA5cC52fF86;
        address maker2 = 0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE;

        deal(USDC_ADDR, maker1, 10607211); // Maker 1 provides 10.607211 USDC
        deal(USDC_ADDR, maker2, 7362350); // Maker 2 provides 7.362350 USDC

        // Makers approve settlement contract
        vm.prank(maker1);
        IERC20(USDC_ADDR).approve(BEBOP_SETTLEMENT, type(uint256).max);
        vm.prank(maker2);
        IERC20(USDC_ADDR).approve(BEBOP_SETTLEMENT, type(uint256).max);

        // Fund ALICE with ETH as it will send the transaction
        vm.deal(ALICE, ethAmount);
        vm.startPrank(ALICE);

        // Load calldata from file
        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_bebop_aggregate"
        );

        // Execute the swap
        (bool success,) = tychoRouterAddr.call{value: ethAmount}(callData);
        uint256 finalBalance = IERC20(USDC_ADDR).balanceOf(orderTaker);

        assertTrue(success, "Call Failed");
        assertEq(finalBalance, expAmountOut);
        assertEq(address(tychoRouterAddr).balance, 0, "ETH left in router");

        vm.stopPrank();
    }
}
