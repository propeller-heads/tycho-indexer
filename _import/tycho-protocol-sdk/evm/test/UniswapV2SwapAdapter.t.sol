// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import "src/uniswap-v2/UniswapV2SwapAdapter.sol";
import "interfaces/ISwapAdapterTypes.sol";

contract UniswapV2PairFunctionTest is Test, ISwapAdapterTypes {
    UniswapV2SwapAdapter pairFunctions;
    IERC20 constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address constant USDC_WETH_PAIR = 0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc;

    function setUp() public {
        uint256 forkBlock = 17000000;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        pairFunctions = new
            UniswapV2SwapAdapter(0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f);
    }

    function testPriceFuzz(uint256 amount0, uint256 amount1) public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory limits = pairFunctions.getLimits(pair, SwapSide.Sell);
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
        uint256[] memory amounts = new uint256[](100);

        for (uint256 i = 0; i < 100; i++) {
            amounts[i] = 1000 * i * 10 ** 6;
        }

        Fraction[] memory prices =
            pairFunctions.price(pair, WETH, USDC, amounts);

        for (uint256 i = 0; i < 99; i++) {
            assertEq(compareFractions(prices[i], prices[i + 1]), 1);
            assertGt(prices[i].denominator, 0);
            assertGt(prices[i + 1].denominator, 0);
        }
    }

    function compareFractions(Fraction memory frac1, Fraction memory frac2)
        internal
        pure
        returns (int8)
    {
        uint256 crossProduct1 = frac1.numerator * frac2.denominator;
        uint256 crossProduct2 = frac2.numerator * frac1.denominator;

        // fractions are equal
        if (crossProduct1 == crossProduct2) return 0;
        // frac1 is greater than frac2
        else if (crossProduct1 > crossProduct2) return 1;
        // frac1 is less than frac2
        else return -1;
    }

    function testSwapFuzz(uint256 amount, bool isBuy) public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        SwapSide side = SwapSide.Sell;
        if (isBuy) {
            side = SwapSide.Buy;
        }
        uint256[] memory limits = pairFunctions.getLimits(pair, side);
        vm.assume(amount < limits[0]);
        deal(address(USDC), address(this), amount);
        USDC.approve(address(pairFunctions), amount);

        pairFunctions.swap(pair, USDC, WETH, side, amount);
    }

    function testSwapSellIncreasing() public {
        executeIncreasingSwaps(SwapSide.Sell);
    }

    function executeIncreasingSwaps(SwapSide side) internal {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));

        uint256[] memory amounts = new uint256[](100);
        for (uint256 i = 0; i < 100; i++) {
            amounts[i] = 1000 * i * 10 ** 6;
        }

        Trade[] memory trades = new Trade   [](100);
        uint256 beforeSwap;
        for (uint256 i = 0; i < 100; i++) {
            beforeSwap = vm.snapshot();
            deal(address(USDC), address(this), amounts[i]);
            USDC.approve(address(pairFunctions), amounts[i]);
            trades[i] = pairFunctions.swap(pair, USDC, WETH, side, amounts[i]);
            vm.revertTo(beforeSwap);
        }

        for (uint256 i = 1; i < 99; i++) {
            assertLe(trades[i].receivedAmount, trades[i + 1].receivedAmount);
            assertLe(trades[i].gasUsed, trades[i + 1].gasUsed);
            assertEq(compareFractions(trades[i].price, trades[i + 1].price), 1);
        }
    }

    function testSwapBuyIncreasing() public {
        executeIncreasingSwaps(SwapSide.Buy);
    }

    function testGetCapabilities(bytes32 pair, address t0, address t1) public {
        Capabilities[] memory res =
            pairFunctions.getCapabilities(pair, IERC20(t0), IERC20(t1));

        assertEq(res.length, 3);
    }

    function testGetLimits() public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory limits = pairFunctions.getLimits(pair, SwapSide.Sell);
    }
}
