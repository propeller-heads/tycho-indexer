// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "./AdapterTest.sol";
import {
    BalancerV2SwapAdapter,
    IERC20,
    IVault
} from "src/balancer-v2/BalancerV2SwapAdapter.sol";
import {FractionMath} from "src/libraries/FractionMath.sol";

contract BalancerV2SwapAdapterTest is AdapterTest {
    using FractionMath for Fraction;

    IVault constant balancerV2Vault =
        IVault(payable(0xBA12222222228d8Ba445958a75a0704d566BF2C8));
    BalancerV2SwapAdapter adapter;

    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant BAL = 0xba100000625a3754423978a60c9317c58a424e3D;
    address constant B_80BAL_20WETH = 0x5c6Ee304399DBdB9C8Ef030aB642B10820DB8F56;
    bytes32 constant B_80BAL_20WETH_POOL_ID =
        0x5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014;

    uint256 constant TEST_ITERATIONS = 100;

    function setUp() public {
        uint256 forkBlock = 18710000;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        adapter = new BalancerV2SwapAdapter(payable(address(balancerV2Vault)));

        vm.label(address(balancerV2Vault), "IVault");
        vm.label(address(adapter), "BalancerV2SwapAdapter");
        vm.label(address(WETH), "WETH");
        vm.label(BAL, "BAL");
        vm.label(address(B_80BAL_20WETH), "B_80BAL_20WETH");
    }

    function testPrice() public {
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1e18;
        amounts[1] = 2e18;

        Fraction[] memory prices =
            adapter.price(B_80BAL_20WETH_POOL_ID, BAL, WETH, amounts);

        for (uint256 i = 0; i < prices.length; i++) {
            assertGt(prices[i].numerator, 0);
            assertGt(prices[i].denominator, 0);
        }
    }

    function testPriceSingleFuzz() public {
        uint256 specifiedAmount = 100 * 10 ** 18;
        // Assume OrderSide.Sell
        uint256[] memory limits =
            adapter.getLimits(B_80BAL_20WETH_POOL_ID, BAL, WETH);

        vm.assume(specifiedAmount > 0);
        vm.assume(specifiedAmount < limits[0]);

        Fraction memory price = adapter.priceSingle(
            B_80BAL_20WETH_POOL_ID, BAL, WETH, specifiedAmount
        );

        assertGt(price.numerator, 0);
        assertGt(price.denominator, 0);
    }

    function testPriceDecreasing() public {
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);
        Fraction[] memory prices = new Fraction[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 1000 * (i + 1) * 10 ** 18;
            prices[i] = adapter.priceSingle(
                B_80BAL_20WETH_POOL_ID, BAL, WETH, amounts[i]
            );
        }

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertEq(prices[i].compareFractions(prices[i + 1]), 1);
            assertGt(prices[i].denominator, 0);
            assertGt(prices[i + 1].denominator, 0);
        }
    }

    function testSwapFuzz(uint256 specifiedAmount, bool isBuy) public {
        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;
        vm.assume(specifiedAmount > 0);

        uint256[] memory limits =
            adapter.getLimits(B_80BAL_20WETH_POOL_ID, BAL, WETH);

        if (side == OrderSide.Buy) {
            vm.assume(specifiedAmount < limits[1]);

            // TODO calculate the amountIn by using price function as in
            // testPriceDecreasing
            deal(BAL, address(this), type(uint256).max);
            IERC20(BAL).approve(address(adapter), type(uint256).max);
        } else {
            vm.assume(specifiedAmount < limits[0]);

            deal(BAL, address(this), specifiedAmount);
            IERC20(BAL).approve(address(adapter), specifiedAmount);
        }

        uint256 bal_balance = IERC20(BAL).balanceOf(address(this));
        uint256 weth_balance = IERC20(WETH).balanceOf(address(this));

        Trade memory trade = adapter.swap(
            B_80BAL_20WETH_POOL_ID, BAL, WETH, side, specifiedAmount, mockData
        );

        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(
                    specifiedAmount,
                    IERC20(WETH).balanceOf(address(this)) - weth_balance
                );
                assertEq(
                    trade.calculatedAmount,
                    bal_balance - IERC20(BAL).balanceOf(address(this))
                );
            } else {
                assertEq(
                    specifiedAmount,
                    bal_balance - IERC20(BAL).balanceOf(address(this))
                );
                assertEq(
                    trade.calculatedAmount,
                    IERC20(WETH).balanceOf(address(this)) - weth_balance
                );
            }
        }
    }

    function testSwapSellIncreasing() public {
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);
        Trade[] memory trades = new Trade[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 1000 * (i + 1) * 10 ** 18;

            uint256 beforeSwap = vm.snapshot();

            deal(BAL, address(this), amounts[i]);
            IERC20(BAL).approve(address(adapter), amounts[i]);
            trades[i] = adapter.swap(
                B_80BAL_20WETH_POOL_ID,
                BAL,
                WETH,
                OrderSide.Sell,
                amounts[i],
                mockData
            );

            vm.revertTo(beforeSwap);
        }

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertLe(trades[i].calculatedAmount, trades[i + 1].calculatedAmount);
            assertLe(trades[i].gasUsed, trades[i + 1].gasUsed);
            assertEq(trades[i].price.compareFractions(trades[i + 1].price), 1);
        }
    }

    function testSwapBuyIncreasing() public {
        uint256[] memory amounts = new uint256[](TEST_ITERATIONS);
        Trade[] memory trades = new Trade[](TEST_ITERATIONS);

        for (uint256 i = 0; i < TEST_ITERATIONS; i++) {
            amounts[i] = 10 * (i + 1) * 10 ** 18;

            uint256 beforeSwap = vm.snapshot();

            Fraction memory price = adapter.priceSingle(
                B_80BAL_20WETH_POOL_ID, BAL, WETH, amounts[i]
            );
            uint256 amountIn =
                (amounts[i] * price.denominator / price.numerator) * 2;

            deal(BAL, address(this), amountIn);
            IERC20(BAL).approve(address(adapter), amountIn);
            trades[i] = adapter.swap(
                B_80BAL_20WETH_POOL_ID,
                BAL,
                WETH,
                OrderSide.Buy,
                amounts[i],
                mockData
            );

            vm.revertTo(beforeSwap);
        }

        for (uint256 i = 0; i < TEST_ITERATIONS - 1; i++) {
            assertLe(trades[i].calculatedAmount, trades[i + 1].calculatedAmount);
            assertLe(trades[i].gasUsed, trades[i + 1].gasUsed);
            assertEq(trades[i].price.compareFractions(trades[i + 1].price), 1);
        }
    }

    function testGetLimits() public view {
        uint256[] memory limits =
            adapter.getLimits(B_80BAL_20WETH_POOL_ID, BAL, WETH);

        assert(limits.length == 2);
        assert(limits[0] > 0);
        assert(limits[1] > 0);
    }

    function testGetCapabilitiesFuzz(bytes32 pool, address t0, address t1)
        public
    {
        Capability[] memory res = adapter.getCapabilities(pool, t0, t1);

        assertEq(res.length, 4);
        assertEq(uint256(res[0]), uint256(Capability.SellOrder));
        assertEq(uint256(res[1]), uint256(Capability.BuyOrder));
        assertEq(uint256(res[2]), uint256(Capability.PriceFunction));
        assertEq(uint256(res[3]), uint256(Capability.HardLimits));
    }

    function testGetTokens() public {
        address[] memory tokens = adapter.getTokens(B_80BAL_20WETH_POOL_ID);

        assertEq(tokens[0], BAL);
        assertEq(tokens[1], address(WETH));
    }

    function testGetPoolIds() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                NotImplemented.selector, "BalancerV2SwapAdapter.getPoolIds"
            )
        );
        adapter.getPoolIds(100, 200);
    }

    function testBalancerV2PoolBehaviour() public {
        bytes32[] memory poolIds = new bytes32[](1);
        poolIds[0] = B_80BAL_20WETH_POOL_ID;
        testPoolBehaviour(adapter, poolIds);
    }
}
