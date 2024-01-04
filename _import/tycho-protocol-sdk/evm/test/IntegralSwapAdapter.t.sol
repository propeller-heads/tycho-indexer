// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;
 
import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";
import "src/integral/IntegralSwapAdapter.sol";
 
contract IntegralSwapAdapterTest is Test, ISwapAdapterTypes {
    using FractionMath for Fraction;
 
    IntegralSwapAdapter adapter;
    ITwapRelayer relayer;
    IERC20 constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address constant USDC_WETH_PAIR =
        0x2fe16Dd18bba26e457B7dD2080d5674312b026a2;
    address constant relayerAddress =
        0xd17b3c9784510E33cD5B87b490E79253BcD81e2E;
 
    uint256 constant TEST_ITERATIONS = 100;
 
    function setUp() public {
        uint256 forkBlock = 18835309;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        adapter = new IntegralSwapAdapter(relayerAddress);
        relayer = ITwapRelayer(relayerAddress);
 
        vm.label(address(WETH), "WETH");
        vm.label(address(USDC), "USDC");
        vm.label(address(USDC_WETH_PAIR), "USDC_WETH_PAIR");
    }
 
    function getMinLimits(IERC20 sellToken, IERC20 buyToken) public view returns (uint256[] memory limits) {
        (
            uint256 price_,
            uint256 fee,
            uint256 limitMin0,
            uint256 limitMax0,
            uint256 limitMin1,
            uint256 limitMax1
        ) = relayer.getPoolState(address(sellToken), address(buyToken));
 
        uint256[] memory limits_ = new uint256[](2);
        limits_[0] = limitMin0;
        limits_[1] = limitMin1;
    }
 
    function testPriceFuzzIntegral(uint256 amount0, uint256 amount1) public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory limits = adapter.getLimits(pair, USDC, WETH);
        vm.assume(amount0 < limits[0]);
        vm.assume(amount1 < limits[1]);
 
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amount0;
        amounts[1] = amount1;
 
        Fraction[] memory prices = adapter.price(pair, WETH, USDC, amounts);
 
        for (uint256 i = 0; i < prices.length; i++) {
            assertGt(prices[i].numerator, 0);
            assertGt(prices[i].denominator, 0);
        }
    }
 
    /// @dev Since TwapRelayer's calculateAmountOut function is internal, and using quoteSell would
    /// revert the transaction if calculateAmountOut is not enough,
    /// we need a threshold to cover this internal amount, applied to 
    function testSwapFuzzIntegral(uint256 specifiedAmount, bool isBuy) public {
        // Fails at times | FAIL. Reason: revert: TR03;
        //
        //
        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;
 
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory limits = new uint256[](2);
        uint256[] memory limitsMin = new uint256[](2);
 
        if (side == OrderSide.Buy) {
            limits = adapter.getLimits(pair, USDC, WETH);
            vm.assume(specifiedAmount < limits[1]);
 
            limitsMin = getMinLimits(USDC, WETH);
            vm.assume(specifiedAmount > limitsMin[1] * 115 / 100);
 
            deal(address(USDC), address(this), type(uint256).max);
            USDC.approve(address(adapter), type(uint256).max);
        } else {
            limits = adapter.getLimits(pair, USDC, WETH);
            vm.assume(specifiedAmount < limits[0]);
 
            limitsMin = getMinLimits(USDC, WETH);
            vm.assume(specifiedAmount > limitsMin[0] * 115 / 100);
 
            deal(address(USDC), address(this), type(uint256).max);
            USDC.approve(address(adapter), specifiedAmount);
        }
 
        uint256 usdc_balance_before = USDC.balanceOf(address(this));
        uint256 weth_balance_before = WETH.balanceOf(address(this));
 
        Trade memory trade = adapter.swap(
            pair,
            USDC,
            WETH,
            side,
            specifiedAmount
        );
 
        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(
                    specifiedAmount,
                    WETH.balanceOf(address(this)) + weth_balance_before
                );
 
                assertEq(
                    trade.calculatedAmount,
                    usdc_balance_before - USDC.balanceOf(address(this))
                );
            } else {
                assertEq(
                    specifiedAmount,
                    usdc_balance_before - USDC.balanceOf(address(this))
                );
 
                assertEq(
                    trade.calculatedAmount,
                    weth_balance_before + WETH.balanceOf(address(this))
                );
            }
        }
    }
 
    function executeIncreasingSwapsIntegral(OrderSide side) internal {
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
            USDC.approve(address(adapter), amounts[i]);
 
            trades[i] = adapter.swap(pair, USDC, WETH, side, amounts[i]);
            vm.revertTo(beforeSwap);
        }
 
        for (uint256 i = 1; i < TEST_ITERATIONS - 1; i++) {
            assertLe(
                trades[i].calculatedAmount,
                trades[i + 1].calculatedAmount
            );
            assertLe(trades[i].gasUsed, trades[i + 1].gasUsed);
            assertEq(trades[i].price.compareFractions(trades[i + 1].price), 1);
        }
    }
 
    function testGetCapabilitiesIntegral(
        bytes32 pair,
        address t0,
        address t1
    ) public {
        Capability[] memory res = adapter.getCapabilities(
            pair,
            IERC20(t0),
            IERC20(t1)
        );
 
        assertEq(res.length, 3);
    }
 
    function testGetTokensIntegral() public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        IERC20[] memory tokens = adapter.getTokens(pair);
 
        assertEq(tokens.length, 2);
    }
 
    function testGetLimitsIntegral() public {
        bytes32 pair = bytes32(bytes20(USDC_WETH_PAIR));
        uint256[] memory limits = adapter.getLimits(pair, USDC, WETH);
 
        assertEq(limits.length, 2);
    }
}