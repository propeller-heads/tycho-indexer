// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "@src/executors/LiquidityPartyExecutor.sol";
import {Constants} from "../Constants.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract LiquidityPartyExecutorExposed is LiquidityPartyExecutor {
    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            IPartyPool pool,
            address tokenIn,
            address tokenOut,
            uint8 indexIn,
            uint8 indexOut
        )
    {
        return _decodeData(data);
    }
}

contract LiquidityPartyExecutorTest is Constants, TestUtils {
    using SafeERC20 for IERC20;

    LiquidityPartyExecutorExposed liquidityPartyExposed;
    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 USDC = IERC20(USDC_ADDR);
    IERC20 WBTC = IERC20(WBTC_ADDR);
    IERC20 USDT = IERC20(USDT_ADDR);
    IERC20 UNI = IERC20(0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984);
    IERC20 PEPE = IERC20(PEPE_ADDR);

    // LiquidityParty pool address
    address constant LIQUIDITY_PARTY_POOL =
        0xfA0be6148F66A6499666cf790d647D00daB76904;

    // Token indices in the pool
    uint8 constant USDT_INDEX = 0;
    uint8 constant USDC_INDEX = 1;
    uint8 constant WBTC_INDEX = 2;
    uint8 constant WETH_INDEX = 3;
    uint8 constant UNI_INDEX = 4;
    uint8 constant WSOL_INDEX = 5;
    uint8 constant TRX_INDEX = 6;
    uint8 constant AAVE_INDEX = 7;
    uint8 constant PEPE_INDEX = 8;
    uint8 constant SHIB_INDEX = 9;

    address constant WSOL_ADDR =
        address(0xD31a59c85aE9D8edEFeC411D448f90841571b89c);

    // Mock pool address for decode testing
    address constant MOCK_POOL =
        address(0x1234567890123456789012345678901234567890);

    function setUp() public {
        uint256 forkBlock = 24537169;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        liquidityPartyExposed = new LiquidityPartyExecutorExposed();
    }

    function testDecodeParams() public view {
        bytes memory params = abi.encodePacked(
            MOCK_POOL, WETH_ADDR, USDC_ADDR, uint8(0), uint8(1)
        );

        (
            IPartyPool pool,
            address tokenIn,
            address tokenOut,
            uint8 indexIn,
            uint8 indexOut
        ) = liquidityPartyExposed.decodeParams(params);

        assertEq(address(pool), MOCK_POOL);
        assertEq(tokenIn, WETH_ADDR);
        assertEq(tokenOut, USDC_ADDR);
        assertEq(indexIn, 0);
        assertEq(indexOut, 1);
    }

    function testDecodeParamsCorrectLength() public view {
        // Verify that exactly 62 bytes works correctly
        bytes memory params = abi.encodePacked(
            MOCK_POOL, // 20 bytes
            WETH_ADDR, // 20 bytes
            USDC_ADDR, // 20 bytes
            uint8(0), // 1 byte
            uint8(1) // 1 byte
        );

        assertEq(params.length, 62);

        (
            IPartyPool pool,
            address tokenIn,
            address tokenOut,
            uint8 indexIn,
            uint8 indexOut
        ) = liquidityPartyExposed.decodeParams(params);

        assertEq(address(pool), MOCK_POOL);
        assertEq(tokenIn, WETH_ADDR);
        assertEq(tokenOut, USDC_ADDR);
        assertEq(indexIn, 0);
        assertEq(indexOut, 1);
    }

    function testDecodeParamsInvalidDataLength() public {
        // Data too short (only 40 bytes instead of 62)
        bytes memory invalidParams = abi.encodePacked(MOCK_POOL, WETH_ADDR);

        vm.expectRevert();
        liquidityPartyExposed.decodeParams(invalidParams);
    }

    function testDecodeParamsWithRealPool() public view {
        bytes memory params = abi.encodePacked(
            LIQUIDITY_PARTY_POOL, WETH_ADDR, USDC_ADDR, WETH_INDEX, USDC_INDEX
        );

        (
            IPartyPool pool,
            address tokenIn,
            address tokenOut,
            uint8 indexIn,
            uint8 indexOut
        ) = liquidityPartyExposed.decodeParams(params);

        assertEq(address(pool), LIQUIDITY_PARTY_POOL);
        assertEq(tokenIn, WETH_ADDR);
        assertEq(tokenOut, USDC_ADDR);
        assertEq(indexIn, WETH_INDEX);
        assertEq(indexOut, USDC_INDEX);
    }

    /// @dev Mimics what the Dispatcher does in production: transfers tokens to the pool
    /// before calling swap(). We transfer via address(this) rather than using deal() directly
    /// on the pool, so the pool's internal balance tracking sees a real incoming transfer
    /// rather than a storage slot overwrite that would wipe its existing reserves.
    function _fundPool(address token, uint256 amount) internal {
        deal(token, address(this), amount);
        IERC20(token).safeTransfer(LIQUIDITY_PARTY_POOL, amount);
    }

    function testDecodeSwap() public {
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_liquidityparty");
        uint256 amountIn = 1000000;
        uint256 amountOut = 4643054;
        // This receiver address must match the encoding in liquidity_party.rs test_encode_liquidityparty()
        address expectedReceiver =
            address(0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e);
        _fundPool(USDC_ADDR, amountIn);
        liquidityPartyExposed.swap(amountIn, protocolData, expectedReceiver);

        uint256 finalBalance = IERC20(WSOL_ADDR).balanceOf(expectedReceiver);
        assertGe(finalBalance, amountOut);
    }

    function testSwapWETHToUSDC() public {
        // Pool has only 7500705 [7.5e6] USDC available, use 0.001 ether to get ~3 USDC
        uint256 amountIn = 0.001 ether;
        bytes memory protocolData = abi.encodePacked(
            LIQUIDITY_PARTY_POOL, WETH_ADDR, USDC_ADDR, WETH_INDEX, USDC_INDEX
        );

        uint256 balanceBefore = USDC.balanceOf(BOB);
        _fundPool(WETH_ADDR, amountIn);
        liquidityPartyExposed.swap(amountIn, protocolData, BOB);

        uint256 balanceAfter = USDC.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
    }

    function testSwapUSDCToWETH() public {
        // Pool has 7500705 [7.5e6] USDC, use 5% = 375035
        uint256 amountIn = 375035;
        bytes memory protocolData = abi.encodePacked(
            LIQUIDITY_PARTY_POOL, USDC_ADDR, WETH_ADDR, USDC_INDEX, WETH_INDEX
        );

        uint256 balanceBefore = WETH.balanceOf(BOB);
        _fundPool(USDC_ADDR, amountIn);
        liquidityPartyExposed.swap(amountIn, protocolData, BOB);

        uint256 balanceAfter = WETH.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
    }

    function testSwapUSDTToUSDC() public {
        // Pool has 7431790 [7.431e6] USDT, use 5% = 371589
        uint256 amountIn = 371589;
        bytes memory protocolData = abi.encodePacked(
            LIQUIDITY_PARTY_POOL, USDT_ADDR, USDC_ADDR, USDT_INDEX, USDC_INDEX
        );

        uint256 balanceBefore = USDC.balanceOf(BOB);
        _fundPool(USDT_ADDR, amountIn);
        liquidityPartyExposed.swap(amountIn, protocolData, BOB);

        uint256 balanceAfter = USDC.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
    }

    function testSwapWBTCToWETH() public {
        // Pool has 11007 [1.1e4] WBTC (8 decimals), use 5% = 550
        uint256 amountIn = 550;
        bytes memory protocolData = abi.encodePacked(
            LIQUIDITY_PARTY_POOL, WBTC_ADDR, WETH_ADDR, WBTC_INDEX, WETH_INDEX
        );

        uint256 balanceBefore = WETH.balanceOf(BOB);
        _fundPool(WBTC_ADDR, amountIn);
        liquidityPartyExposed.swap(amountIn, protocolData, BOB);

        uint256 balanceAfter = WETH.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
    }

    function testSwapUNIToUSDC() public {
        // Pool has 1838224140769039670 [1.838e18] UNI, use 5% = 0.092 ether
        uint256 amountIn = 0.092 ether;
        bytes memory protocolData = abi.encodePacked(
            LIQUIDITY_PARTY_POOL, address(UNI), USDC_ADDR, UNI_INDEX, USDC_INDEX
        );

        uint256 balanceBefore = USDC.balanceOf(BOB);
        _fundPool(address(UNI), amountIn);
        liquidityPartyExposed.swap(amountIn, protocolData, BOB);

        uint256 balanceAfter = USDC.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
    }

    function testSwapPEPEToWETH() public {
        // Pool has 1777240401501820332402892 [1.777e24] PEPE, use 5% = 88862020075091016620144
        uint256 amountIn = 88862020075091016620144;
        bytes memory protocolData = abi.encodePacked(
            LIQUIDITY_PARTY_POOL, PEPE_ADDR, WETH_ADDR, PEPE_INDEX, WETH_INDEX
        );

        uint256 balanceBefore = WETH.balanceOf(BOB);
        _fundPool(PEPE_ADDR, amountIn);
        liquidityPartyExposed.swap(amountIn, protocolData, BOB);

        uint256 balanceAfter = WETH.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
    }
}
