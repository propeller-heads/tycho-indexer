// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";

contract AdapterTest is Test, ISwapAdapterTypes {
    using FractionMath for Fraction;

    bytes32 mockData = bytes32(abi.encodePacked(false));
    uint256 constant pricePrecision = 10e24;
    string[] public stringPctgs = ["0%", "0.1%", "50%", "100%"];

    // @notice Test the behavior of a swap adapter for a list of pools
    // @dev Computes limits, prices, and swaps on the pools on both directions
    // for different
    // sell amounts. Asserts that the prices behaves as expected.
    // @param adapter The swap adapter to test
    // @param poolIds The list of pool ids to test
    function runPoolBehaviourTest(
        ISwapAdapter adapter,
        bytes32[] memory poolIds
    ) public {
        bool hasPriceImpact = !hasCapability(
            adapter.getCapabilities(poolIds[0], address(0), address(0)),
            Capability.ConstantPrice
        );
        for (uint256 i = 0; i < poolIds.length; i++) {
            address[] memory tokens = adapter.getTokens(poolIds[i]);
            IERC20(tokens[0]).approve(address(adapter), type(uint256).max);
            IERC20(tokens[1]).approve(address(adapter), type(uint256).max);

            testPricesForPair(
                adapter, poolIds[i], tokens[0], tokens[1], hasPriceImpact
            );
            testPricesForPair(
                adapter, poolIds[i], tokens[1], tokens[0], hasPriceImpact
            );
        }
    }

    // Prices should:
    // 1. Be monotonic decreasing
    // 2. Be positive
    // 3. Always be >= the executed price and >= the price after the swap
    function testPricesForPair(
        ISwapAdapter adapter,
        bytes32 poolId,
        address tokenIn,
        address tokenOut,
        bool hasPriceImpact
    ) internal {
        uint256 sellLimit = adapter.getLimits(poolId, tokenIn, tokenOut)[0];
        assertGt(sellLimit, 0, "Sell limit should be greater than 0");

        console2.log(
            "TEST: Testing prices for pair %s -> %s. Sell limit: %d",
            tokenIn,
            tokenOut,
            sellLimit
        );

        bool hasMarginalPrices = hasCapability(
            adapter.getCapabilities(poolId, tokenIn, tokenOut),
            Capability.MarginalPrice
        );
        uint256[] memory amounts =
            calculateTestAmounts(sellLimit, hasMarginalPrices);
        Fraction[] memory prices =
            adapter.price(poolId, tokenIn, tokenOut, amounts);
        assertGt(
            fractionToInt(prices[0]),
            fractionToInt(prices[prices.length - 1]),
            "Price at limit should be smaller than price at 0"
        );
        console2.log(
            "TEST: Price at 0: %d, price at sell limit: %d",
            fractionToInt(prices[0]),
            fractionToInt(prices[prices.length - 1])
        );

        console2.log("TEST: Testing behavior for price at 0");
        assertGt(prices[0].numerator, 0, "Nominator shouldn't be 0");
        assertGt(prices[0].denominator, 0, "Denominator shouldn't be 0");
        uint256 priceAtZero = fractionToInt(prices[0]);
        console2.log("TEST: Price at 0: %d", priceAtZero);

        Trade memory trade;
        deal(tokenIn, address(this), 5 * amounts[amounts.length - 1]);

        uint256 initialState = vm.snapshot();

        for (uint256 j = 1; j < amounts.length; j++) {
            console2.log(
                "TEST: Testing behavior for price at %s of limit.",
                stringPctgs[j],
                amounts[j]
            );
            uint256 priceAtAmount = fractionToInt(prices[j]);

            console2.log("TEST: Swapping %d of %s", amounts[j], tokenIn);
            trade = adapter.swap(
                poolId, tokenIn, tokenOut, OrderSide.Sell, amounts[j], mockData
            );
            uint256 executedPrice =
                trade.calculatedAmount * pricePrecision / amounts[j];
            uint256 priceAfterSwap = fractionToInt(trade.price);
            console2.log("TEST:  - Executed price:   %d", executedPrice);
            console2.log("TEST:  - Price at amount:  %d", priceAtAmount);
            console2.log("TEST:  - Price after swap: %d", priceAfterSwap);

            if (hasPriceImpact) {
                assertGe(
                    executedPrice,
                    priceAtAmount,
                    "Price should be greated than executed price."
                );
                assertGt(
                    executedPrice,
                    priceAfterSwap,
                    "Executed price should be greater than price after swap."
                );
                assertGt(
                    priceAtZero,
                    executedPrice,
                    "Price should be greated than price after swap."
                );
            } else {
                assertGe(
                    priceAtZero,
                    priceAfterSwap,
                    "Executed price should be or equal to price after swap."
                );
                assertGe(
                    priceAtZero,
                    priceAtAmount,
                    "Executed price should be or equal to price after swap."
                );
                assertGe(
                    priceAtZero,
                    executedPrice,
                    "Price should be or equal to price after swap."
                );
            }

            vm.revertTo(initialState);
        }
        uint256 amountAboveLimit = sellLimit * 105 / 100;

        bool hasHardLimits = hasCapability(
            adapter.getCapabilities(poolId, tokenIn, tokenOut),
            Capability.HardLimits
        );

        if (hasHardLimits) {
            testRevertAboveLimit(
                adapter, poolId, tokenIn, tokenOut, amountAboveLimit
            );
        } else {
            testOperationsAboveLimit(
                adapter, poolId, tokenIn, tokenOut, amountAboveLimit
            );
        }

        console2.log("TEST: All tests passed.");
    }

    function testRevertAboveLimit(
        ISwapAdapter adapter,
        bytes32 poolId,
        address tokenIn,
        address tokenOut,
        uint256 amountAboveLimit
    ) internal {
        console2.log(
            "TEST: Testing revert behavior above the sell limit: %d",
            amountAboveLimit
        );
        uint256[] memory aboveLimitArray = new uint256[](1);
        aboveLimitArray[0] = amountAboveLimit;

        try adapter.price(poolId, tokenIn, tokenOut, aboveLimitArray) {
            revert(
                "Pool shouldn't be able to fetch prices above the sell limit"
            );
        } catch Error(string memory s) {
            console2.log(
                "TEST: Expected error when fetching price above limit: %s", s
            );
        }
        try adapter.swap(
            poolId,
            tokenIn,
            tokenOut,
            OrderSide.Sell,
            aboveLimitArray[0],
            mockData
        ) {
            revert("Pool shouldn't be able to swap above the sell limit");
        } catch Error(string memory s) {
            console2.log(
                "TEST: Expected error when swapping above limit: %s", s
            );
        }
    }

    function testOperationsAboveLimit(
        ISwapAdapter adapter,
        bytes32 poolId,
        address tokenIn,
        address tokenOut,
        uint256 amountAboveLimit
    ) internal {
        console2.log(
            "TEST: Testing operations above the sell limit: %d",
            amountAboveLimit
        );
        uint256[] memory aboveLimitArray = new uint256[](1);
        aboveLimitArray[0] = amountAboveLimit;

        adapter.price(poolId, tokenIn, tokenOut, aboveLimitArray);
        adapter.swap(
            poolId,
            tokenIn,
            tokenOut,
            OrderSide.Sell,
            aboveLimitArray[0],
            mockData
        );
    }

    function calculateTestAmounts(uint256 limit, bool hasMarginalPrices)
        internal
        pure
        returns (uint256[] memory)
    {
        uint256[] memory amounts = new uint256[](4);
        amounts[0] = hasMarginalPrices ? 0 : limit / 10000;
        amounts[1] = limit / 1000;
        amounts[2] = limit / 2;
        amounts[3] = limit;
        return amounts;
    }

    function fractionToInt(Fraction memory price)
        public
        pure
        returns (uint256)
    {
        return price.numerator * pricePrecision / price.denominator;
    }

    function hasCapability(
        Capability[] memory capabilities,
        Capability capability
    ) internal pure returns (bool) {
        for (uint256 i = 0; i < capabilities.length; i++) {
            if (capabilities[i] == capability) {
                return true;
            }
        }

        return false;
    }
}
