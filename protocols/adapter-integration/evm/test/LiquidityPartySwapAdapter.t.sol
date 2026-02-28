// SPDX-License-Identifier: UNLICENSED
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
        IPartyPlanner(0x7692e502FB8cE1c13A97DbBE380Be05A545ee0a9);
    IPartyInfo internal constant INFO =
        IPartyInfo(0xAAb5751696d081bF077793a6d86EddF9DF512Ac2);
    address internal constant MINT_IMPL =
        0x92bb4799Ef9e622Cb9C5bc7c8655ea43c18E7660;
    address internal constant SWAP_IMPL =
        0xE64605889C32cC8ec858146b428Fa38302B5baA9;
    IPartyPool internal constant POOL =
        IPartyPool(0xfA0be6148F66A6499666cf790d647D00daB76904);
    bytes32 internal constant POOL_ID = bytes32(bytes20(address(POOL)));
    uint256 internal constant FORK_BLOCK = 24537169; // block in which the pool
    // was created

    LiquidityPartySwapAdapter internal adapter;
    uint256 internal constant TEST_ITERATIONS = 10;

    address[] internal tokens;
    address internal constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant UNI = 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984;
    address internal constant WSOL = 0xD31a59c85aE9D8edEFeC411D448f90841571b89c;
    address internal constant TRX = 0x50327c6c5a14DCaDE707ABad2E27eB517df87AB5;
    address internal constant AAVE = 0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9;
    address internal constant PEPE = 0x6982508145454Ce325dDbE47a25d4ec3d2311933;
    address internal constant SHIB = 0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE;

    address private constant INPUT_TOKEN = WBTC;
    uint8 private constant INPUT_INDEX = 2;
    address private constant OUTPUT_TOKEN = SHIB;
    uint8 private constant OUTPUT_INDEX = 9;

    function setUp() public {
        tokens = new address[](10);
        tokens[0] = USDT;
        tokens[1] = USDC;
        tokens[2] = WBTC;
        tokens[3] = WETH;
        tokens[4] = UNI;
        tokens[5] = WSOL;
        tokens[6] = TRX;
        tokens[7] = AAVE;
        tokens[8] = PEPE;
        tokens[9] = SHIB;

        vm.createSelectFork(vm.rpcUrl("mainnet"), FORK_BLOCK);

        adapter = new LiquidityPartySwapAdapter(PLANNER, INFO);

        vm.label(address(PLANNER), "PartyPlanner");
        vm.label(address(INFO), "PartyInfo");
        vm.label(address(MINT_IMPL), "PartyPoolMintImpl");
        vm.label(address(SWAP_IMPL), "PartyPoolSwapImpl");
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

    // Many of the tests above seem entirely redundant with runPoolBehaviorTest
    // :shrug:
    function testLiquidityPartyPoolBehaviour() public {
        bytes32[] memory poolIds = new bytes32[](1);
        poolIds[0] = POOL_ID;
        runPoolBehaviourTest(adapter, poolIds);
    }
}
