// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "./AdapterTest.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";
import "src/sfraxeth/FraxV3FrxEthAdapter.sol";

contract FraxV3FrxEthAdapterTest is Test, ISwapAdapterTypes, AdapterTest {
    using FractionMath for Fraction;

    FraxV3FrxEthAdapter adapter;

    address FRAXETH_ADDRESS;
    address constant SFRAXETH_ADDRESS =
        0xac3E018457B222d93114458476f3E3416Abbe38F;
    address constant FRAXETHMINTER_ADDRESS =
        0xbAFA44EFE7901E04E39Dad13167D089C559c1138;
    address constant ETH_ADDRESS = address(0);

    IERC20 FRAXETH;
    IERC20 constant SFRAXETH =
        IERC20(0xac3E018457B222d93114458476f3E3416Abbe38F);
    IERC20 constant WBTC = IERC20(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);

    uint256 constant TEST_ITERATIONS = 10;
    uint256 constant AMOUNT0 = 1000000000000000000;
    bytes32 constant PAIR = bytes32(0);

    function setUp() public {
        uint256 forkBlock = 19341682;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        adapter =
            new FraxV3FrxEthAdapter(FRAXETHMINTER_ADDRESS, SFRAXETH_ADDRESS);
        FRAXETH = IERC20(address(ISfrxEth(address(SFRAXETH)).asset()));
        FRAXETH_ADDRESS = address(FRAXETH);
    }

    /////////////////////////////////////// PRICE
    // ////////////////////////////////////

    /// @dev set lower limit to greater than 1, because previewDeposit returns 0
    /// with an amountIn == 1
    function testPriceFuzzFraxEthV3FraxEth(uint256 amount0, uint256 amount1)
        public
    {
        uint256[] memory limits =
            adapter.getLimits(PAIR, FRAXETH_ADDRESS, SFRAXETH_ADDRESS);
        vm.assume(amount0 < limits[0]);
        vm.assume(amount0 > 1);
        vm.assume(amount1 < limits[0]);
        vm.assume(amount1 > 1);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amount0;
        amounts[1] = amount1;

        Fraction[] memory prices =
            adapter.price(PAIR, FRAXETH_ADDRESS, SFRAXETH_ADDRESS, amounts);

        for (uint256 i = 0; i < prices.length; i++) {
            assertGt(prices[i].numerator, 0);
            assertGt(prices[i].denominator, 0);
        }
    }

    /// @dev The price is kept among swaps if no FRAX rewards are distributed in
    /// the contract during time
    function testPriceKeepingSellFraxEthFraxEthV3() public {
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 1000 * (i + 1) * 10 ** 18;
        }

        Fraction[] memory prices =
            adapter.price(PAIR, FRAXETH_ADDRESS, SFRAXETH_ADDRESS, amounts);

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertEq(prices[i].compareFractions(prices[i + 1]), 0);
            assertGt(prices[i].denominator, 0);
            assertGt(prices[i + 1].denominator, 0);
        }
    }

    function testPriceKeepingSellSFraxEthFraxEthV3() public {
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 1000 * (i + 1) * 10 ** 18;
        }

        Fraction[] memory prices =
            adapter.price(PAIR, SFRAXETH_ADDRESS, FRAXETH_ADDRESS, amounts);

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertEq(prices[i].compareFractions(prices[i + 1]), 0);
            assertGt(prices[i].denominator, 0);
            assertGt(prices[i + 1].denominator, 0);
        }
    }

    function testPriceKeepingSellEthFraxEthV3() public {
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 1000 * (i + 1) * 10 ** 18;
        }

        Fraction[] memory prices =
            adapter.price(PAIR, ETH_ADDRESS, SFRAXETH_ADDRESS, amounts);

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertEq(prices[i].compareFractions(prices[i + 1]), 0);
            assertGt(prices[i].denominator, 0);
            assertGt(prices[i + 1].denominator, 0);
        }
    }

    //////////////////////////////////////// SWAP
    // ///////////////////////////////////

    function testSwapFuzzsFraxEthV3WithFraxEth(
        uint256 specifiedAmount,
        bool isBuy
    ) public {
        vm.assume(specifiedAmount > 1);

        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;

        uint256[] memory limits =
            adapter.getLimits(PAIR, FRAXETH_ADDRESS, SFRAXETH_ADDRESS);

        if (side == OrderSide.Buy) {
            vm.assume(specifiedAmount < limits[1]);

            deal(address(FRAXETH), address(this), type(uint256).max);
            FRAXETH.approve(address(adapter), type(uint256).max);
        } else {
            vm.assume(specifiedAmount < limits[0]);

            deal(address(FRAXETH), address(this), specifiedAmount);
            FRAXETH.approve(address(adapter), specifiedAmount);
        }

        uint256 frxEth_balance_before = FRAXETH.balanceOf(address(this));
        uint256 sfrxEth_balance_before = SFRAXETH.balanceOf(address(this));

        Trade memory trade = adapter.swap(
            PAIR, FRAXETH_ADDRESS, SFRAXETH_ADDRESS, side, specifiedAmount
        );

        uint256 frxEth_balance_after = FRAXETH.balanceOf(address(this));
        uint256 sfrxEth_balance_after = SFRAXETH.balanceOf(address(this));

        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(
                    specifiedAmount,
                    sfrxEth_balance_after - sfrxEth_balance_before
                );
                assertEq(
                    trade.calculatedAmount,
                    frxEth_balance_before - frxEth_balance_after
                );
            } else {
                assertEq(
                    specifiedAmount,
                    frxEth_balance_before - frxEth_balance_after
                );
                assertEq(
                    trade.calculatedAmount,
                    sfrxEth_balance_after - sfrxEth_balance_before
                );
            }
        }
    }

    function testSwapFuzzFraxEthV3WithSFraxEth(
        uint256 specifiedAmount,
        bool isBuy
    ) public {
        vm.assume(specifiedAmount > 1);

        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;

        uint256[] memory limits =
            adapter.getLimits(PAIR, SFRAXETH_ADDRESS, FRAXETH_ADDRESS);

        if (side == OrderSide.Buy) {
            vm.assume(specifiedAmount < limits[1]);

            deal(address(SFRAXETH), address(this), type(uint256).max);
            SFRAXETH.approve(address(adapter), type(uint256).max);
        } else {
            vm.assume(specifiedAmount < limits[0]);

            deal(address(SFRAXETH), address(this), specifiedAmount);
            SFRAXETH.approve(address(adapter), specifiedAmount);
        }

        uint256 frxEth_balance_before = FRAXETH.balanceOf(address(this));
        uint256 sfrxEth_balance_before = SFRAXETH.balanceOf(address(this));

        ISfrxEth(SFRAXETH_ADDRESS).totalAssets();

        Trade memory trade = adapter.swap(
            PAIR, SFRAXETH_ADDRESS, FRAXETH_ADDRESS, side, specifiedAmount
        );

        uint256 frxEth_balance_after = FRAXETH.balanceOf(address(this));
        uint256 sfrxEth_balance_after = SFRAXETH.balanceOf(address(this));

        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(
                    specifiedAmount,
                    frxEth_balance_after - frxEth_balance_before
                );
                assertEq(
                    trade.calculatedAmount,
                    sfrxEth_balance_before - sfrxEth_balance_after
                );
            } else {
                assertEq(
                    specifiedAmount,
                    sfrxEth_balance_before - sfrxEth_balance_after
                );
                assertEq(
                    trade.calculatedAmount,
                    frxEth_balance_after - frxEth_balance_before
                );
            }
        }
    }

    function testGetTokensFraxEthV3() public {
        address[] memory tokens = adapter.getTokens(bytes32(0));

        assertEq(tokens[0], FRAXETH_ADDRESS);
        assertEq(tokens[1], SFRAXETH_ADDRESS);
    }

    function testGetLimitsFraxEthV3() public {
        uint256[] memory limits =
            adapter.getLimits(bytes32(0), FRAXETH_ADDRESS, SFRAXETH_ADDRESS);
        assertEq(limits.length, 2);

        adapter.getLimits(bytes32(0), ETH_ADDRESS, SFRAXETH_ADDRESS);
        assertEq(limits.length, 2);

        adapter.getLimits(bytes32(0), SFRAXETH_ADDRESS, FRAXETH_ADDRESS);
        assertEq(limits.length, 2);
    }

    function testGetCapabilitiesFraxEthV3() public {
        Capability[] memory res =
            adapter.getCapabilities(bytes32(0), ETH_ADDRESS, FRAXETH_ADDRESS);

        assertEq(res.length, 4);
    }
    // This test is currently broken due to a bug in runPoolBehaviour
    // with constant price pools.
    //
    //    function testPoolBehaviourFraxV3Sfrax() public {
    //        bytes32[] memory poolIds = new bytes32[](1);
    //        poolIds[0] = bytes32(0);
    //        runPoolBehaviourTest(adapter, poolIds);
    //    }
}
