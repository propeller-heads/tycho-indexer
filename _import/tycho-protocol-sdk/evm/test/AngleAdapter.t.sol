// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import "src/angle/AngleAdapter.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";

contract AngleAdapterTest is Test, ISwapAdapterTypes {
    using FractionMath for Fraction;

    AngleAdapter adapter;
    IERC20 agEUR;
    IERC20 constant EURC = IERC20(0x1aBaEA1f7C830bD89Acc67eC4af516284b1bC33c);
    ITransmuter constant transmuter = ITransmuter(0x00253582b2a3FE112feEC532221d9708c64cEFAb);

    uint256 constant TEST_ITERATIONS = 100;

    function setUp() public {
        uint256 forkBlock = 18921770;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        adapter = new
            AngleAdapter(transmuter);
        agEUR = IERC20(transmuter.agToken());

        vm.label(address(adapter), "AngleAdapter");
        vm.label(address(agEUR), "agEUR");
        vm.label(address(EURC), "EURC");
    }

    function testPriceFuzzAngle(uint256 amount0, uint256 amount1) public {
        bytes32 pair = bytes32(0);
        uint256[] memory limits = adapter.getLimits(pair, EURC, agEUR);
        vm.assume(amount0 < limits[0] && amount0 > 0);
        vm.assume(amount1 < limits[0] && amount1 > 0);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amount0;
        amounts[1] = amount1;

        Fraction[] memory prices = adapter.price(pair, EURC, agEUR, amounts);

        for (uint256 i = 0; i < prices.length; i++) {
            assertGt(prices[i].numerator, 0);
            assertGt(prices[i].denominator, 0);
        }
    }


    function testPriceDecreasingAngle() public {
        bytes32 pair = bytes32(0);
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 1000 * (i+1) * 10 ** 18;
        }

        Fraction[] memory prices = adapter.price(pair, agEUR, EURC, amounts);

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertEq(prices[i].compareFractions(prices[i + 1]), 1);
            assertGt(prices[i].denominator, 0);
            assertGt(prices[i + 1].denominator, 0);
        }
    }

    function testSwapFuzzAngleMint(uint256 specifiedAmount, bool isBuy) public {
        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;

        bytes32 pair = bytes32(0);
        uint256[] memory limits = adapter.getLimits(pair, EURC, agEUR);

        if (side == OrderSide.Buy) {
            vm.assume(specifiedAmount < limits[1] && specifiedAmount > 0);

            deal(address(EURC), address(this), type(uint256).max);
            EURC.approve(address(adapter), type(uint256).max);
        } else {
            vm.assume(specifiedAmount < limits[0] && specifiedAmount > 0);

            deal(address(EURC), address(this), specifiedAmount);
            EURC.approve(address(adapter), specifiedAmount);
        }

        uint256 eurc_balance = EURC.balanceOf(address(this));
        uint256 agEUR_balance = agEUR.balanceOf(address(this));

        Trade memory trade =
            adapter.swap(pair, EURC, agEUR, side, specifiedAmount);

        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(
                    specifiedAmount,
                    agEUR.balanceOf(address(this)) - agEUR_balance
                );
                assertEq(
                    trade.calculatedAmount,
                    eurc_balance - EURC.balanceOf(address(this))
                );
            } else {
                assertEq(
                    specifiedAmount,
                    eurc_balance - EURC.balanceOf(address(this))
                );
                assertEq(
                    trade.calculatedAmount,
                    agEUR.balanceOf(address(this)) - agEUR_balance
                );
            }
        }
    }

    function testSwapFuzzAngleRedeem(uint256 specifiedAmount, bool isBuy) public {
        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;

        bytes32 pair = bytes32(0);
        uint256[] memory limits = adapter.getLimits(pair, agEUR, EURC);
        console.log(limits[0], limits[1]);

        if (side == OrderSide.Buy) {
            vm.assume(specifiedAmount < limits[1] && specifiedAmount > 0);

            deal(address(agEUR), address(this), type(uint256).max);
            agEUR.approve(address(adapter), type(uint256).max);
        } else {
            vm.assume(specifiedAmount < limits[0] && specifiedAmount > 0);

            deal(address(agEUR), address(this), specifiedAmount);
            agEUR.approve(address(adapter), specifiedAmount);
        }

        uint256 eurc_balance = EURC.balanceOf(address(this));
        uint256 agEUR_balance = agEUR.balanceOf(address(this));

        Trade memory trade =
            adapter.swap(pair, agEUR, EURC, side, specifiedAmount);

        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(
                    specifiedAmount,
                    EURC.balanceOf(address(this)) - eurc_balance
                );
                assertEq(
                    trade.calculatedAmount,
                    agEUR_balance - agEUR.balanceOf(address(this))
                );
            } else {
                assertEq(
                    specifiedAmount,
                    agEUR_balance - agEUR.balanceOf(address(this))
                );
                assertEq(
                    trade.calculatedAmount,
                    EURC.balanceOf(address(this)) - eurc_balance
                );
            }
        }
    }

    function testSwapSellIncreasingAngle() public {
        executeIncreasingSwapsAngle(OrderSide.Sell);
    }

    function executeIncreasingSwapsAngle(OrderSide side) internal {
        bytes32 pair = bytes32(0);

        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);
        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 
                side == OrderSide.Sell ? (100 * i * 10 ** 18) : (100 * i * 10 ** 6);
        }

        Trade[] memory trades = new Trade[](TEST_ITERATIONS);
        uint256 beforeSwap;
        for (uint256 i = 1; i < TEST_ITERATIONS; i++) {
            beforeSwap = vm.snapshot();

            if(side == OrderSide.Sell) {
                deal(address(agEUR), address(this), amounts[i]);
                agEUR.approve(address(adapter), amounts[i]);
            }
            else {
                deal(address(agEUR), address(this), type(uint256).max);
                agEUR.approve(address(adapter), type(uint256).max);                
            }

            trades[i] = adapter.swap(pair, agEUR, EURC, side, amounts[i]);
            vm.revertTo(beforeSwap);
        }

        for (uint256 i = 1; i < TEST_ITERATIONS - 1; i++) {
            assertLe(trades[i].calculatedAmount, trades[i + 1].calculatedAmount);
            assertEq(trades[i].price.compareFractions(trades[i + 1].price), 1);
        }
    }

    function testSwapBuyIncreasingAngle() public {
        executeIncreasingSwapsAngle(OrderSide.Buy);
    }

    function testGetCapabilitiesAngle(bytes32 pair, address t0, address t1) public {
        Capability[] memory res =
            adapter.getCapabilities(pair, IERC20(t0), IERC20(t1));

        assertEq(res.length, 3);
    }

    function testGetTokensAngle() public {
        IERC20[] memory tokens = adapter.getTokens(bytes32(0));

        assertGe(tokens.length, 2);
    }

    function testGetLimits() public {
        bytes32 pair = bytes32(0);
        uint256[] memory limits = adapter.getLimits(pair, agEUR, EURC);

        assertEq(limits.length, 2);
    }
}
