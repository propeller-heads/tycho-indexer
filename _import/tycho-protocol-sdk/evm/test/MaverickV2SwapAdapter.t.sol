// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "./AdapterTest.sol";
import "forge-std/Test.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";
import "src/maverick-v2/MaverickV2SwapAdapter.sol";

contract MaverickV2SwapAdapterTest is AdapterTest {
    using FractionMath for Fraction;

    MaverickV2SwapAdapter adapter;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant QUOTER = 0xb40AfdB85a07f37aE217E7D6462e609900dD8D7A;
    address constant FACTORY = 0x0A7e848Aca42d879EF06507Fca0E7b33A0a63c1e;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant GHO = 0x40D16FC0246aD3160Ccc09B8D0D3A2cD28aE6C2f;
    address constant GHO_USDC_POOL = 0x14Cf6D2Fe3E1B326114b07d22A6F6bb59e346c67;

    uint256 constant TEST_ITERATIONS = 10;

    uint256 constant GHO_BALANCE = 100_000 * 1e18;
    uint256 constant USDC_BALANCE = 100_000 * 1e6;

    function setUp() public {
        uint256 forkBlock = 22096000;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        adapter = new MaverickV2SwapAdapter(FACTORY, QUOTER);

        vm.label(address(adapter), "MaverickV2SwapAdapter");
        vm.label(WETH, "WETH");
        vm.label(QUOTER, "Quoter");
        vm.label(FACTORY, "Factory");
        vm.label(USDC, "USDC");
        vm.label(GHO, "GHO");
        vm.label(GHO_USDC_POOL, "GHO_USDC_POOL");
    }

    function testGetLimits() public view {
        bytes32 pair = bytes32(bytes20(GHO_USDC_POOL));
        uint256[] memory limits = adapter.getLimits(pair, GHO, USDC);

        assertEq(limits.length, 2);
        assertGt(limits[0], 0, "Limit for sell token should be greater than 0");
        assertGt(limits[1], 0, "Limit for buy token should be greater than 0");
    }

    function testPriceFuzz(uint256 amount0, uint256 amount1) public {
        bytes32 pair = bytes32(bytes20(GHO_USDC_POOL));
        uint256[] memory limits = adapter.getLimits(pair, GHO, USDC);
        vm.assume(amount0 < limits[0]);
        vm.assume(amount1 < limits[0]);
        vm.assume(amount0 > 1e16);
        vm.assume(amount1 > 1e16);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amount0;
        amounts[1] = amount1;

        Fraction[] memory prices = adapter.price(pair, GHO, USDC, amounts);

        for (uint256 i = 0; i < prices.length; i++) {
            assertGt(prices[i].numerator, 0);
            assertGt(prices[i].denominator, 0);
        }
    }

    function testPrice() public {
        bytes32 pair = bytes32(bytes20(GHO_USDC_POOL));
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10e18; // 10 GHO

        Fraction[] memory prices = adapter.price(pair, GHO, USDC, amounts);

        assertEq(prices.length, 1);
        assertGt(
            prices[0].numerator, 0, "Price numerator should be greater than 0"
        );
        assertGt(
            prices[0].denominator,
            0,
            "Price denominator should be greater than 0"
        );
    }

    function testPriceDecreasing() public {
        bytes32 pair = bytes32(bytes20(GHO_USDC_POOL));
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 100 * (i + 1) * 10 ** 18;
        }

        Fraction[] memory prices = adapter.price(pair, GHO, USDC, amounts);

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertGe(prices[i].compareFractions(prices[i + 1]), 1); // same bin
                // price are same
            assertGt(prices[i].denominator, 0);
            assertGt(prices[i + 1].denominator, 0);
        }
    }

    function testSwapSell() public {
        bytes32 pair = bytes32(bytes20(GHO_USDC_POOL));
        uint256 amount = 10e18; // 10 GHO

        deal(GHO, address(this), GHO_BALANCE);
        deal(USDC, address(this), USDC_BALANCE);

        // Approve adapter to spend WETH
        vm.prank(address(this));
        IERC20(GHO).approve(address(adapter), amount);

        Trade memory trade =
            adapter.swap(pair, GHO, USDC, OrderSide.Sell, amount);

        assertGt(
            trade.calculatedAmount,
            0,
            "Calculated amount should be greater than 0"
        );
        assertGt(
            trade.price.numerator, 0, "Price numerator should be greater than 0"
        );
        assertGt(
            trade.price.denominator,
            0,
            "Price denominator should be greater than 0"
        );
        assertGt(trade.gasUsed, 0, "Gas used should be greater than 0");
    }

    function testSwapBuy() public {
        bytes32 pair = bytes32(bytes20(GHO_USDC_POOL));
        uint256 amount = 100e18; // buy 100 GHO

        deal(GHO, address(this), GHO_BALANCE);
        deal(USDC, address(this), USDC_BALANCE);

        // Approve adapter to spend USDC
        vm.prank(address(this));
        IERC20(USDC).approve(address(adapter), USDC_BALANCE);

        Trade memory trade =
            adapter.swap(pair, USDC, GHO, OrderSide.Buy, amount);

        assertGt(
            trade.calculatedAmount,
            0,
            "Calculated amount should be greater than 0"
        );
        assertGt(
            trade.price.numerator, 0, "Price numerator should be greater than 0"
        );
        assertGt(
            trade.price.denominator,
            0,
            "Price denominator should be greater than 0"
        );
        assertGt(trade.gasUsed, 0, "Gas used should be greater than 0");
    }

    function testSwapFuzz(uint256 specifiedAmount, bool isBuy) public {
        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;

        bytes32 pair = bytes32(bytes20(GHO_USDC_POOL));
        uint256[] memory limits = adapter.getLimits(pair, GHO, USDC);

        if (side == OrderSide.Buy) {
            // specify buy usdc amount
            vm.assume(specifiedAmount < limits[1]);

            deal(GHO, address(this), type(uint256).max);
            IERC20(GHO).approve(address(adapter), type(uint256).max);
        } else {
            // specify sell gho amount
            vm.assume(specifiedAmount < limits[0]);

            deal(GHO, address(this), specifiedAmount);
            IERC20(GHO).approve(address(adapter), specifiedAmount);
        }

        uint256 usdc_balance = IERC20(USDC).balanceOf(address(this));
        uint256 gho_balance = IERC20(GHO).balanceOf(address(this));

        Trade memory trade =
            adapter.swap(pair, GHO, USDC, side, specifiedAmount);

        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(
                    specifiedAmount,
                    IERC20(USDC).balanceOf(address(this)) - usdc_balance
                );
                assertEq(
                    trade.calculatedAmount,
                    gho_balance - IERC20(GHO).balanceOf(address(this))
                );
            } else {
                assertEq(
                    specifiedAmount,
                    gho_balance - IERC20(GHO).balanceOf(address(this))
                );
                assertEq(
                    trade.calculatedAmount,
                    IERC20(USDC).balanceOf(address(this)) - usdc_balance
                );
            }
        }
    }

    function testSwapSellIncreasing() public {
        executeIncreasingSwaps(OrderSide.Sell);
    }

    function testSwapBuyIncreasing() public {
        executeIncreasingSwaps(OrderSide.Buy);
    }

    function executeIncreasingSwaps(OrderSide side) internal {
        bytes32 pair = bytes32(bytes20(GHO_USDC_POOL));

        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);
        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            if (side == OrderSide.Sell) {
                amounts[i] = 100 * (i + 1) * 10 ** 6; // specify sell usdc
            } else {
                amounts[i] = 100 * (i + 1) * 10 ** 18; // specify buy gho
            }
        }

        deal(GHO, address(this), GHO_BALANCE);
        deal(USDC, address(this), USDC_BALANCE);

        Trade[] memory trades = new Trade[](TEST_ITERATIONS);
        uint256 beforeSwap;
        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            beforeSwap = vm.snapshot();

            IERC20(USDC).approve(address(adapter), USDC_BALANCE);

            trades[i] = adapter.swap(pair, USDC, GHO, side, amounts[i]);
            vm.revertTo(beforeSwap);
        }

        for (uint256 i = 1; i < TEST_ITERATIONS - 1; i++) {
            assertLe(trades[i].calculatedAmount, trades[i + 1].calculatedAmount);
            assertLe(trades[i].gasUsed, trades[i + 1].gasUsed);
            assertEq(trades[i].price.compareFractions(trades[i + 1].price), 1);
        }
    }

    function testGetCapabilities() public view {
        bytes32 pair = bytes32(bytes20(GHO_USDC_POOL));
        Capability[] memory capabilities =
            adapter.getCapabilities(pair, GHO, USDC);

        assertEq(capabilities.length, 3);
        assertEq(uint256(capabilities[0]), uint256(Capability.SellOrder));
        assertEq(uint256(capabilities[1]), uint256(Capability.BuyOrder));
        assertEq(uint256(capabilities[2]), uint256(Capability.PriceFunction));
    }

    function testGetTokens() public view {
        bytes32 pair = bytes32(bytes20(GHO_USDC_POOL));
        address[] memory tokens = adapter.getTokens(pair);

        assertEq(tokens.length, 2);
        assertEq(tokens[0], GHO);
        assertEq(tokens[1], USDC);
    }

    function testGetPoolIds() public view {
        uint256 offset = 0;
        uint256 limit = 10;
        bytes32[] memory poolIds = adapter.getPoolIds(offset, limit);

        assertLe(
            poolIds.length,
            limit,
            "Number of pool IDs should be less than or equal to limit"
        );
        if (poolIds.length > 0) {
            assertGt(uint256(poolIds[0]), 0, "Pool ID should be greater than 0");
        }
    }

    function testMavV2PoolBehaviour() public {
        bytes32[] memory poolIds = new bytes32[](1);
        poolIds[0] = bytes32(bytes20(GHO_USDC_POOL));
        runPoolBehaviourTest(adapter, poolIds);
    }
}
