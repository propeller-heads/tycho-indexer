// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    IERC20
} from "../lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {
    IERC20Metadata
} from "../lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {FractionMath} from "../src/libraries/FractionMath.sol";
import {IPartyInfo} from "../src/liquidityparty/IPartyInfo.sol";
import {IPartyPlanner} from "../src/liquidityparty/IPartyPlanner.sol";
import {IPartyPool} from "../src/liquidityparty/IPartyPool.sol";
import {
    LiquidityPartySwapAdapter
} from "../src/liquidityparty/LiquidityPartySwapAdapter.sol";
import {AdapterTest} from "./AdapterTest.sol";

contract LiquidityPartyFunctionTest is AdapterTest {
    using FractionMath for Fraction;

    IPartyPlanner internal constant PLANNER =
        IPartyPlanner(0xe6C22aA3e1B3e11AA6C1C6E3086883b3C5071071);
    IPartyInfo internal constant INFO =
        IPartyInfo(0x5f1B901f2955CAD0B28978eF6f0D3054C102F244);
    address internal constant MINT_IMPL =
        0xDF2535B88D97Bf52649D87D41986e4C5B7aB60f5;
    address internal constant EXTRA_IMPL =
        0x5f34B189ca58EeC3B6c1Ac432f3D5F85058ACbf7;
    IPartyPool internal constant POOL =
        IPartyPool(0x353D535b9febe7C0Ff261c9e55aD941f712F54ae);
    bytes32 internal constant POOL_ID = bytes32(bytes20(address(POOL)));
    uint256 internal constant FORK_BLOCK = 25088884;

    LiquidityPartySwapAdapter internal adapter;
    uint256 internal constant TEST_ITERATIONS = 10;

    address[] internal tokens;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant AAVE = 0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9;

    address private constant INPUT_TOKEN = WETH;
    uint8 private constant INPUT_INDEX = 1;
    address private constant OUTPUT_TOKEN = AAVE;
    uint8 private constant OUTPUT_INDEX = 2;

    function setUp() public {
        tokens = new address[](3);
        tokens[0] = USDC;
        tokens[1] = WETH;
        tokens[2] = AAVE;

        vm.createSelectFork(vm.rpcUrl("mainnet"), FORK_BLOCK);

        adapter = new LiquidityPartySwapAdapter(PLANNER, INFO);

        vm.label(address(PLANNER), "PartyPlanner");
        vm.label(address(INFO), "PartyInfo");
        vm.label(address(MINT_IMPL), "PartyPoolMintImpl");
        vm.label(address(EXTRA_IMPL), "PartyPoolExtraImpl");
        vm.label(address(POOL), "PartyPool");
        vm.label(address(adapter), "LiquidityPartySwapAdapter");
        for (uint256 i = 0; i < tokens.length; i++) {
            vm.label(address(tokens[i]), IERC20Metadata(tokens[i]).symbol());
        }
    }

    function testPrice() public view {
        uint256[] memory amounts = new uint256[](3);
        uint256 balance = IERC20(INPUT_TOKEN).balanceOf(address(POOL));
        // cannot use 1: the fee will round up and take
        // everything, resulting in a zero-output reversion
        amounts[0] = 2;
        amounts[1] = balance;
        amounts[2] = balance * 2;

        Fraction[] memory prices =
            adapter.price(POOL_ID, INPUT_TOKEN, OUTPUT_TOKEN, amounts);

        for (uint256 i = 0; i < prices.length; i++) {
            assertGt(prices[i].numerator, 0);
            assertGt(prices[i].denominator, 0);
        }
    }

    function testPriceDecreasing() public view {
        uint256[] memory limits =
            adapter.getLimits(POOL_ID, INPUT_TOKEN, OUTPUT_TOKEN);

        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            // The first entry will be a zero amount which returns the current
            // marginal price.
            amounts[i] = limits[0] * i / (TEST_ITERATIONS - 1);
        }

        Fraction[] memory prices =
            adapter.price(POOL_ID, INPUT_TOKEN, OUTPUT_TOKEN, amounts);

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertEq(prices[i].compareFractions(prices[i + 1]), 1);
        }
    }

    function testSwapFuzz(uint256 amount) public {
        uint256[] memory limits =
            adapter.getLimits(POOL_ID, INPUT_TOKEN, OUTPUT_TOKEN);
        // 1 will not work because we take fee-on-input
        // and round up, leaving nothing to trade
        vm.assume(amount > 1);
        vm.assume(amount <= limits[0]);

        deal(INPUT_TOKEN, address(this), amount);
        IERC20(INPUT_TOKEN).approve(address(adapter), amount);

        uint256 usdtBalance = IERC20(INPUT_TOKEN).balanceOf(address(this));
        uint256 wethBalance = IERC20(OUTPUT_TOKEN).balanceOf(address(this));

        Trade memory trade = adapter.swap(
            POOL_ID, INPUT_TOKEN, OUTPUT_TOKEN, OrderSide.Sell, amount
        );

        if (trade.calculatedAmount > 0) {
            assertEq(
                amount,
                usdtBalance - IERC20(INPUT_TOKEN).balanceOf(address(this))
            );
            assertEq(
                trade.calculatedAmount,
                IERC20(OUTPUT_TOKEN).balanceOf(address(this)) - wethBalance
            );
        }
    }

    function testSwapSellIncreasing() public {
        uint256[] memory limits =
            adapter.getLimits(POOL_ID, INPUT_TOKEN, OUTPUT_TOKEN);
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);
        Trade[] memory trades = new Trade[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = limits[0] * (i + 1) / (TEST_ITERATIONS - 1);

            uint256 beforeSwap = vm.snapshot();

            deal(INPUT_TOKEN, address(this), amounts[i]);
            IERC20(INPUT_TOKEN).approve(address(adapter), amounts[i]);
            trades[i] = adapter.swap(
                POOL_ID, INPUT_TOKEN, OUTPUT_TOKEN, OrderSide.Sell, amounts[i]
            );

            vm.revertTo(beforeSwap);
        }

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertLe(trades[i].calculatedAmount, trades[i + 1].calculatedAmount);
            assertEq(
                trades[i].price.denominator, trades[i + 1].price.denominator
            ); // must share a basis
            assertGe(trades[i].price.numerator, trades[i + 1].price.numerator);
        }
    }

    function testGetLimits() public view {
        uint256[] memory limits =
            adapter.getLimits(POOL_ID, INPUT_TOKEN, OUTPUT_TOKEN);

        assert(limits.length == 2);
        assert(limits[0] > 0);
        assert(limits[1] > 0);
    }

    function testGetTokens() public view {
        address[] memory adapterTokens = adapter.getTokens(POOL_ID);
        for (uint256 i = 0; i < tokens.length; i++) {
            assertEq(adapterTokens[i], tokens[i]);
        }
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

    // Use WETH/AAVE pair — USDC's 6 decimals cause precision failures at tiny
    // pool sizes (~$1) with large relative trade sizes.
    function testLiquidityPartyPoolBehaviour() public {
        IERC20(WETH).approve(address(adapter), type(uint256).max);
        IERC20(AAVE).approve(address(adapter), type(uint256).max);
        testPricesForPair(adapter, POOL_ID, WETH, AAVE, true);
        testPricesForPair(adapter, POOL_ID, AAVE, WETH, true);
    }
}
