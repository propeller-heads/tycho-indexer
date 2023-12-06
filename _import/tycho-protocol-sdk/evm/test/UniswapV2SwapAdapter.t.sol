// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import "src/uniswap-v2/UniswapV2SwapAdapter.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";

contract UniswapV2PairFunctionTest is Test, ISwapAdapterTypes {
    using FractionMath for Fraction;

    UniswapV2SwapAdapter pairFunctions;
    IERC20 constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address constant USDC_WETH_PAIR = 0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc;

    uint256 constant TEST_ITERATIONS = 100;

    function setUp() public {
        uint256 forkBlock = 17000000;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        pairFunctions = new
            UniswapV2SwapAdapter(0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f);

        vm.label(address(pairFunctions), "UniswapV2SwapAdapter");
        vm.label(address(WETH), "WETH");
        vm.label(address(USDC), "USDC");
        vm.label(address(USDC_WETH_PAIR), "USDC_WETH_PAIR");
    }

    function testPriceFuzz(uint256 amount0, uint256 amount1) public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory limits = pairFunctions.getLimits(pair, USDC, WETH);
        vm.assume(amount0 < limits[0]);
        vm.assume(amount1 < limits[0]);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amount0;
        amounts[1] = amount1;

        Fraction[] memory prices =
            pairFunctions.price(pair, WETH, USDC, amounts);

        for (uint256 i = 0; i < prices.length; i++) {
            assertGt(prices[i].numerator, 0);
            assertGt(prices[i].denominator, 0);
        }
    }

    function testPriceDecreasing() public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 1000 * i * 10 ** 6;
        }

        Fraction[] memory prices =
            pairFunctions.price(pair, WETH, USDC, amounts);

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertEq(prices[i].compareFractions(prices[i + 1]), 1);
            assertGt(prices[i].denominator, 0);
            assertGt(prices[i + 1].denominator, 0);
        }
    }

    function testSwapFuzz(uint256 specifiedAmount, bool isBuy) public {
        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;

        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory limits = pairFunctions.getLimits(pair, USDC, WETH);

        if (side == OrderSide.Buy) {
            vm.assume(specifiedAmount < limits[1]);

            // sellAmount is not specified for buy orders
            deal(address(USDC), address(this), type(uint256).max);
            USDC.approve(address(pairFunctions), type(uint256).max);
        } else {
            vm.assume(specifiedAmount < limits[0]);

            deal(address(USDC), address(this), specifiedAmount);
            USDC.approve(address(pairFunctions), specifiedAmount);
        }

        uint256 usdc_balance = USDC.balanceOf(address(this));
        uint256 weth_balance = WETH.balanceOf(address(this));

        Trade memory trade =
            pairFunctions.swap(pair, USDC, WETH, side, specifiedAmount);

        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(
                    specifiedAmount,
                    WETH.balanceOf(address(this)) - weth_balance
                );
                assertEq(
                    trade.calculatedAmount,
                    usdc_balance - USDC.balanceOf(address(this))
                );
            } else {
                assertEq(
                    specifiedAmount,
                    usdc_balance - USDC.balanceOf(address(this))
                );
                assertEq(
                    trade.calculatedAmount,
                    WETH.balanceOf(address(this)) - weth_balance
                );
            }
        }
    }

    function testSwapSellIncreasing() public {
        executeIncreasingSwaps(OrderSide.Sell);
    }

    function executeIncreasingSwaps(OrderSide side) internal {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));

        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);
        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 1000 * i * 10 ** 6;
        }

        Trade[] memory trades = new Trade[](TEST_ITERATIONS);
        uint256 beforeSwap;
        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            beforeSwap = vm.snapshot();

            deal(address(USDC), address(this), amounts[i]);
            USDC.approve(address(pairFunctions), amounts[i]);

            trades[i] = pairFunctions.swap(pair, USDC, WETH, side, amounts[i]);
            vm.revertTo(beforeSwap);
        }

        for (uint256 i = 1; i < TEST_ITERATIONS - 1; i++) {
            assertLe(trades[i].calculatedAmount, trades[i + 1].calculatedAmount);
            assertLe(trades[i].gasUsed, trades[i + 1].gasUsed);
            assertEq(trades[i].price.compareFractions(trades[i + 1].price), 1);
        }
    }

    function testSwapBuyIncreasing() public {
        executeIncreasingSwaps(OrderSide.Buy);
    }

    function testGetCapabilities(bytes32 pair, address t0, address t1) public {
        Capability[] memory res =
            pairFunctions.getCapabilities(pair, IERC20(t0), IERC20(t1));

        assertEq(res.length, 3);
    }

    function testGetLimits() public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory limits = pairFunctions.getLimits(pair, USDC, WETH);

        assertEq(limits.length, 2);
    }
}
