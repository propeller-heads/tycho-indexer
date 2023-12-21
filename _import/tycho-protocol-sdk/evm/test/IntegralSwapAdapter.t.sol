// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";
import "src/integral/IntegralSwapAdapterFix.sol";

contract IntegralSwapAdapterTest is Test, ISwapAdapterTypes {
    using FractionMath for Fraction;

    IntegralSwapAdapter adapter;
    IERC20 constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address constant USDC_WETH_PAIR = 0x2fe16Dd18bba26e457B7dD2080d5674312b026a2;
    address constant relayerAddress = 0xd17b3c9784510E33cD5B87b490E79253BcD81e2E;

    uint256 constant TEST_ITERATIONS = 100;

    function setUp() public {
        uint256 forkBlock = 18835309;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        adapter = new IntegralSwapAdapter(relayerAddress);

        vm.label(address(WETH), "WETH");
        vm.label(address(USDC), "USDC");
        vm.label(address(USDC_WETH_PAIR), "USDC_WETH_PAIR");

    }


    function testPriceFuzzIntegral(uint256 amount0, uint256 amount1) public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory limits = adapter.getLimits(pair, USDC, WETH);
        vm.assume(amount0 < limits[0]);
        vm.assume(amount1 < limits[1]);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amount0;
        amounts[1] = amount1;

        Fraction[] memory prices = adapter.price(pair, WETH, USDC, amounts);

        for (uint256 i = 0; i < prices.length; i++) {
            assertGt(prices[i].numerator, 0);
            assertGt(prices[i].denominator, 0);
        }
    }


    function testPriceDecreasingIntegral() public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 1000 * i * 10 ** 6;
        }

        Fraction[] memory prices = adapter.price(pair, USDC, WETH, amounts);

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertEq(prices[i].compareFractions(prices[i + 1]), 1);
            assertGt(prices[i].denominator, 0);
            assertGt(prices[i + 1].denominator, 0);
        }
    }


    function testSwapBuyWethIntegral(uint256 specifiedAmount) public {
        OrderSide side = OrderSide.Buy;

        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));

        uint256[] memory limits = adapter.getLimits(pair, USDC, WETH);

        vm.assume(specifiedAmount < limits[1]);
        vm.assume(specifiedAmount > limits[3]);

        deal(address(USDC), address(this), type(uint256).max);
        USDC.approve(address(adapter), type(uint256).max);

        uint256 usdc_balance_before = USDC.balanceOf(address(this));
        uint256 weth_balance_before = WETH.balanceOf(address(this));

        Trade memory trade = adapter.swap(pair, USDC, WETH, side, specifiedAmount);

        if (trade.calculatedAmount > 0) {
            assertEq(specifiedAmount,
                WETH.balanceOf(address(this)) + weth_balance_before
            );

            assertEq(
                trade.calculatedAmount,
                usdc_balance_before - USDC.balanceOf(address(this))
            );
        }

    }


    function testSwapSellUsdcIntegral(uint256 specifiedAmount) public {
        OrderSide side = OrderSide.Sell;

        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));

        uint256[] memory limits = adapter.getLimits(pair, USDC, WETH);

        vm.assume(specifiedAmount < limits[0]);
        vm.assume(specifiedAmount > limits[2]);

        deal(address(USDC), address(this), type(uint256).max);
        USDC.approve(address(adapter), type(uint256).max);

        uint256 usdc_balance_before = USDC.balanceOf(address(this));
        uint256 weth_balance_before = WETH.balanceOf(address(this));

        Trade memory trade = adapter.swap(pair, USDC, WETH, side, specifiedAmount);

        if (trade.calculatedAmount > 0) {
            assertEq(specifiedAmount,
                usdc_balance_before - USDC.balanceOf(address(this))
            );

            assertEq(
                trade.calculatedAmount,
                weth_balance_before + WETH.balanceOf(address(this))
            );
        }
        
    }


    function testSwapFuzzIntegral(uint256 specifiedAmount, bool isBuy) public {
        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;

        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory limits = new uint256[](4);

        if (side == OrderSide.Buy) {
            limits = adapter.getLimits(pair, USDC, WETH);
            vm.assume(specifiedAmount < limits[1]);
            vm.assume(specifiedAmount > limits[3]);

            deal(address(USDC), address(this), type(uint256).max);
            USDC.approve(address(adapter), type(uint256).max);
        } 
        else {
            limits = adapter.getLimits(pair, USDC, WETH);
            vm.assume(specifiedAmount < limits[0]);
            vm.assume(specifiedAmount > limits[2]);

            deal(address(USDC), address(this), type(uint256).max);
            USDC.approve(address(adapter), specifiedAmount);
            
        }

        uint256 usdc_balance_before = USDC.balanceOf(address(this));
        uint256 weth_balance_before = WETH.balanceOf(address(this));

        Trade memory trade = adapter.swap(pair, USDC, WETH, side, specifiedAmount);
        
        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {

                assertEq(
                    specifiedAmount,
                    WETH.balanceOf(address(this)) + weth_balance_before
                );

                assertEq(
                    trade.calculatedAmount,
                    usdc_balance_before - USDC.balanceOf(address(this))
                );

            } else {

                assertEq(
                    specifiedAmount,
                    usdc_balance_before - USDC.balanceOf(address(this))
                );

                assertEq(
                    trade.calculatedAmount,
                    weth_balance_before + WETH.balanceOf(address(this))
                );
            }
        }
        
    }

}
