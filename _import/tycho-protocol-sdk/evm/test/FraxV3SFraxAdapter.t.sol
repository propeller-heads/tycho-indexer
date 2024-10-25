// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "./AdapterTest.sol";
import "forge-std/Test.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";
import "src/libraries/FractionMath.sol";
import "src/sfrax/FraxV3SFraxAdapter.sol";

/// @title TemplateSwapAdapterTest
/// @dev This is a template for a swap adapter test.
/// Test all functions that are implemented in your swap adapter, the two test
/// included here are just an example.
/// Feel free to use UniswapV2SwapAdapterTest and BalancerV2SwapAdapterTest as a
/// reference.
contract FraxV3SFraxAdapterTest is Test, ISwapAdapterTypes, AdapterTest {
    using FractionMath for Fraction;

    FraxV3SFraxAdapter adapter;
    ISFrax constant SFRAX = ISFrax(0xA663B02CF0a4b149d2aD41910CB81e23e1c41c32);
    IERC20 constant FRAX = IERC20(0x853d955aCEf822Db058eb8505911ED77F175b99e);
    address constant FRAX_ADDRESS = address(FRAX);
    address constant SFRAX_ADDRESS = address(SFRAX);

    uint256 constant TEST_ITERATIONS = 100;
    uint256 constant AMOUNT0 = 1000000000000000000;

    function setUp() public {
        uint256 forkBlock = 19270612;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        adapter = new FraxV3SFraxAdapter(SFRAX_ADDRESS, FRAX_ADDRESS);
        vm.label(address(FRAX), "FRAX");
        vm.label(address(SFRAX), "SFRAX");
    }

    /// @dev set lower limit to greater than 1, because previewDeposit returns 0
    /// with an amountIn == 1
    function testPriceFuzzFraxV3SFrax(uint256 amount0, uint256 amount1)
        public
    {
        uint256[] memory limits =
            adapter.getLimits(bytes32(0), FRAX_ADDRESS, SFRAX_ADDRESS);
        vm.assume(amount0 < limits[0]);
        vm.assume(amount0 > 1);
        vm.assume(amount1 < limits[0]);
        vm.assume(amount1 > 1);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amount0;
        amounts[1] = amount1;

        Fraction[] memory prices =
            adapter.price(bytes32(0), FRAX_ADDRESS, SFRAX_ADDRESS, amounts);

        for (uint256 i = 0; i < prices.length; i++) {
            assertGt(prices[i].numerator, 0);
            assertGt(prices[i].denominator, 0);
        }
    }

    function testSwapFuzzFraxV3WithFrax(uint256 specifiedAmount, bool isBuy)
        public
    {
        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;

        bytes32 pair = bytes32(0);
        uint256[] memory limits =
            adapter.getLimits(pair, FRAX_ADDRESS, SFRAX_ADDRESS);

        if (side == OrderSide.Buy) {
            vm.assume(specifiedAmount < limits[1]);

            deal(address(FRAX), address(this), type(uint256).max);
            FRAX.approve(address(adapter), type(uint256).max);
        } else {
            vm.assume(specifiedAmount < limits[0]);

            deal(address(FRAX), address(this), specifiedAmount);
            FRAX.approve(address(adapter), specifiedAmount);
        }

        uint256 frax_balance = FRAX.balanceOf(address(this));
        uint256 sfrax_balance = IERC20(SFRAX_ADDRESS).balanceOf(address(this));

        ISFrax(SFRAX_ADDRESS).totalAssets();

        Trade memory trade = adapter.swap(
            pair, FRAX_ADDRESS, SFRAX_ADDRESS, side, specifiedAmount
        );

        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(
                    specifiedAmount,
                    IERC20(SFRAX_ADDRESS).balanceOf(address(this))
                        - sfrax_balance
                );
                assertEq(
                    trade.calculatedAmount,
                    frax_balance - FRAX.balanceOf(address(this))
                );
            } else {
                assertEq(
                    specifiedAmount,
                    frax_balance - FRAX.balanceOf(address(this))
                );
                assertEq(
                    trade.calculatedAmount,
                    IERC20(SFRAX_ADDRESS).balanceOf(address(this))
                        - sfrax_balance
                );
            }
        }
    }

    function testSwapFuzzFraxV3WithSFrax(uint256 specifiedAmount, bool isBuy)
        public
    {
        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;

        bytes32 pair = bytes32(0);
        uint256[] memory limits =
            adapter.getLimits(pair, SFRAX_ADDRESS, FRAX_ADDRESS);

        if (side == OrderSide.Buy) {
            vm.assume(specifiedAmount < limits[1]);

            deal(SFRAX_ADDRESS, address(this), type(uint256).max);
            IERC20(SFRAX_ADDRESS).approve(address(adapter), type(uint256).max);
        } else {
            vm.assume(specifiedAmount < limits[0]);

            deal(address(SFRAX_ADDRESS), address(this), specifiedAmount);
            IERC20(SFRAX_ADDRESS).approve(address(adapter), specifiedAmount);
        }

        uint256 sfrax_balance = IERC20(SFRAX_ADDRESS).balanceOf(address(this));
        uint256 frax_balance = FRAX.balanceOf(address(this));

        Trade memory trade = adapter.swap(
            pair, SFRAX_ADDRESS, FRAX_ADDRESS, side, specifiedAmount
        );

        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(
                    specifiedAmount,
                    FRAX.balanceOf(address(this)) - frax_balance
                );
                assertEq(
                    trade.calculatedAmount,
                    sfrax_balance
                        - IERC20(SFRAX_ADDRESS).balanceOf(address(this))
                );
            } else {
                assertEq(
                    specifiedAmount,
                    sfrax_balance
                        - IERC20(SFRAX_ADDRESS).balanceOf(address(this))
                );
                assertEq(
                    trade.calculatedAmount,
                    FRAX.balanceOf(address(this)) - frax_balance
                );
            }
        }
    }

    function testSwapSellIncreasingFraxV3() public {
        executeIncreasingSwapsFraxV3(OrderSide.Sell, true);
        executeIncreasingSwapsFraxV3(OrderSide.Sell, false);
    }

    function testSwapBuyIncreasingFraxV3() public {
        executeIncreasingSwapsFraxV3(OrderSide.Buy, true);
        executeIncreasingSwapsFraxV3(OrderSide.Buy, false);
    }

    function executeIncreasingSwapsFraxV3(OrderSide side, bool isFrax)
        internal
    {
        bytes32 pair = bytes32(0);

        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);
        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 1000 * (i + 1) * 10 ** 18;
        }

        Trade[] memory trades = new Trade[](TEST_ITERATIONS);
        uint256 beforeSwap;
        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            beforeSwap = vm.snapshot();

            if (isFrax) {
                deal(FRAX_ADDRESS, address(this), type(uint256).max);
                FRAX.approve(address(adapter), type(uint256).max);
                trades[i] = adapter.swap(
                    pair, FRAX_ADDRESS, SFRAX_ADDRESS, side, amounts[i]
                );
            } else {
                deal(SFRAX_ADDRESS, address(this), amounts[i]);
                IERC20(SFRAX_ADDRESS).approve(address(adapter), amounts[i]);
                trades[i] = adapter.swap(
                    pair, SFRAX_ADDRESS, FRAX_ADDRESS, side, amounts[i]
                );
            }

            vm.revertTo(beforeSwap);
        }

        for (uint256 i = 1; i < TEST_ITERATIONS - 1; i++) {
            assertLe(trades[i].calculatedAmount, trades[i + 1].calculatedAmount);
            assertLe(trades[i].gasUsed, trades[i + 1].gasUsed);
        }
    }

    function testGetLimitsFraxV3() public {
        uint256[] memory limits =
            adapter.getLimits(bytes32(0), FRAX_ADDRESS, SFRAX_ADDRESS);
        assertEq(limits.length, 2);
    }

    function testGetTokensFraxV3() public {
        address[] memory tokens = adapter.getTokens(bytes32(0));

        assertEq(tokens[0], FRAX_ADDRESS);
        assertEq(tokens[1], SFRAX_ADDRESS);
    }

    function testGetCapabilitiesFraxV3SFrax() public {
        Capability[] memory res =
            adapter.getCapabilities(bytes32(0), FRAX_ADDRESS, SFRAX_ADDRESS);

        assertEq(res.length, 5);
    }

    // This test is currently broken due to a bug in runPoolBehaviour
    // with constant price pools.
    // function testPoolBehaviourFraxV3Sfrax() public {
    //     bytes32[] memory poolIds = new bytes32[](1);
    //     poolIds[0] = bytes32(0);
    //     runPoolBehaviourTest(adapter, poolIds);
    // }
}
