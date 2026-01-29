// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TychoRouterTestSetup.sol";
import "@src/executors/CurveExecutor.sol";
import {Constants} from "../Constants.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";

interface ICurvePool {
    function coins(uint256 i) external view returns (address);
}

// Curve pool registry
// This is the registry that contains the information about the pool
// The naming convention is different because it is in vyper
interface MetaRegistry {
    function get_n_coins(address pool) external view returns (uint256);

    function get_coin_indices(address pool, address from, address to)
        external
        view
        returns (int128, int128, bool);
}

contract CurveExecutorExposed is CurveExecutor {
    constructor(address _nativeToken, address _stEthAddress)
        CurveExecutor(_nativeToken, _stEthAddress)
    {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            address tokenIn,
            address tokenOut,
            address pool,
            uint8 poolType,
            int128 i,
            int128 j,
            address receiver
        )
    {
        return _decodeData(data);
    }
}

contract CurveExecutorTest is Test, TestUtils, Constants {
    using SafeERC20 for IERC20;

    CurveExecutorExposed curveExecutorExposed;
    MetaRegistry metaRegistry;

    function setUp() public {
        uint256 forkBlock = 22031795;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        curveExecutorExposed =
            new CurveExecutorExposed(ETH_ADDR_FOR_CURVE, STETH_ADDR);
        metaRegistry = MetaRegistry(CURVE_META_REGISTRY);
    }

    function testDecodeParams() public view {
        bytes memory data = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            TRICRYPTO_POOL,
            uint8(3),
            uint8(2),
            uint8(0),
            ALICE
        );

        (
            address tokenIn,
            address tokenOut,
            address pool,
            uint8 poolType,
            int128 i,
            int128 j,
            address receiver
        ) = curveExecutorExposed.decodeData(data);

        assertEq(tokenIn, WETH_ADDR);
        assertEq(tokenOut, USDC_ADDR);
        assertEq(pool, TRICRYPTO_POOL);
        assertEq(poolType, 3);
        assertEq(i, 2);
        assertEq(j, 0);
        assertEq(receiver, ALICE);
    }

    function testGetTransferData() public {
        bytes memory data = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            TRICRYPTO_POOL,
            uint8(3),
            uint8(2),
            uint8(0),
            ALICE
        );

        (, address receiver, address tokenIn) =
            curveExecutorExposed.getTransferData(data);

        assertEq(tokenIn, WETH_ADDR);
        assertEq(receiver, TRICRYPTO_POOL);
    }

    function testTriPool() public {
        // Swapping DAI -> USDC on TriPool 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7
        uint256 amountIn = 1 ether;
        deal(DAI_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data = _getData(DAI_ADDR, USDC_ADDR, TRIPOOL, 1, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(DAI_ADDR).approve(TRIPOOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 999797);
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, USDC_ADDR);
        assertEq(receiver, ALICE);
    }

    function testStEthPool() public {
        // Swapping ETH -> stETH on StEthPool 0xDC24316b9AE028F1497c275EB9192a3Ea0f67022
        uint256 amountIn = 1 ether;
        deal(address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(ETH_ADDR_FOR_CURVE, STETH_ADDR, STETH_POOL, 1, ALICE);

        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 1001072414418410896);
        assertEq(IERC20(STETH_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, STETH_ADDR);
        assertEq(receiver, ALICE);
    }

    // This test verifies that amountOut for stETH is calculated correctly by
    // accounting for an existing stETH balance in the executor prior to the swap
    function testStEthPoolWithInitialstETH() public {
        // Swapping ETH -> stETH on StEthPool 0xDC24316b9AE028F1497c275EB9192a3Ea0f67022 twice
        uint256 amountIn = 2 ether;
        deal(address(curveExecutorExposed), amountIn);

        uint256 amountInForTest = 1 ether;

        bytes memory data1 =
            _getData(ETH_ADDR_FOR_CURVE, STETH_ADDR, STETH_POOL, 1, ALICE);

        (uint256 amountOut1, address tokenOut1, address receiver1) =
            curveExecutorExposed.swap(amountInForTest, data1);

        bytes memory data2 =
            _getData(ETH_ADDR_FOR_CURVE, STETH_ADDR, STETH_POOL, 1, ALICE);

        (uint256 amountOut2, address tokenOut2, address receiver2) =
            curveExecutorExposed.swap(amountInForTest, data2);

        assertEq(amountOut1, 1001072414418410896);
        assertEq(amountOut2, 1001072213238226892);
        assertEq(IERC20(STETH_ADDR).balanceOf(ALICE), amountOut1 + amountOut2);
        assertEq(tokenOut1, STETH_ADDR);
        assertEq(tokenOut2, STETH_ADDR);
        assertEq(receiver1, ALICE);
        assertEq(receiver2, ALICE);
    }

    function testTricrypto2Pool() public {
        // Swapping WETH -> WBTC on Tricrypto2Pool 0xD51a44d3FaE010294C616388b506AcdA1bfAAE46
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(WETH_ADDR, WBTC_ADDR, TRICRYPTO2_POOL, 3, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(WETH_ADDR).approve(TRICRYPTO2_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 2279618);
        assertEq(IERC20(WBTC_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, WBTC_ADDR);
        assertEq(receiver, ALICE);
    }

    function testSUSDPool() public {
        // Swapping USDC -> SUSD on SUSDPool 0xA5407eAE9Ba41422680e2e00537571bcC53efBfD
        uint256 amountIn = 100 * 10 ** 6;
        deal(USDC_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data = _getData(USDC_ADDR, SUSD_ADDR, SUSD_POOL, 1, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(USDC_ADDR).approve(SUSD_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 100488101605550214590);
        assertEq(IERC20(SUSD_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, SUSD_ADDR);
        assertEq(receiver, ALICE);
    }

    function testFraxUsdcPool() public {
        // Swapping FRAX -> USDC on FraxUsdcPool 0xDcEF968d416a41Cdac0ED8702fAC8128A64241A2
        uint256 amountIn = 1 ether;
        deal(FRAX_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(FRAX_ADDR, USDC_ADDR, FRAX_USDC_POOL, 1, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(FRAX_ADDR).approve(FRAX_USDC_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 998097);
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, USDC_ADDR);
        assertEq(receiver, ALICE);
    }

    function testUsdeUsdcPool() public {
        // Swapping USDC -> USDE on a CryptoSwapNG, deployed by factory 0x6A8cbed756804B16E05E741eDaBd5cB544AE21bf (plain pool)
        uint256 amountIn = 100 * 10 ** 6;
        deal(USDC_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(USDC_ADDR, USDE_ADDR, USDE_USDC_POOL, 1, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(USDC_ADDR).approve(USDE_USDC_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 100064812138999986170);
        assertEq(IERC20(USDE_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, USDE_ADDR);
        assertEq(receiver, ALICE);
    }

    function testDolaFraxPyusdPool() public {
        // Swapping DOLA -> FRAXPYUSD on a CryptoSwapNG, deployed by factory 0x6A8cbed756804B16E05E741eDaBd5cB544AE21bf (meta pool)
        uint256 amountIn = 100 * 10 ** 6;
        deal(DOLA_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(DOLA_ADDR, FRAXPYUSD_POOL, DOLA_FRAXPYUSD_POOL, 1, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(DOLA_ADDR).approve(DOLA_FRAXPYUSD_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 99688992);
        assertEq(IERC20(FRAXPYUSD_POOL).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, FRAXPYUSD_POOL);
        assertEq(receiver, ALICE);
    }

    function testCryptoPoolWithETH() public {
        // Swapping XYO -> ETH on a CryptoPool, deployed by factory 0xF18056Bbd320E96A48e3Fbf8bC061322531aac99
        uint256 amountIn = 1 ether;
        uint256 initialBalance = address(ALICE).balance; // this address already has some ETH assigned to it
        deal(XYO_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(XYO_ADDR, ETH_ADDR_FOR_CURVE, ETH_XYO_POOL, 2, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(XYO_ADDR).approve(ETH_XYO_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 6081816039338);
        assertEq(ALICE.balance, initialBalance + amountOut);
        assertEq(tokenOut, address(0));
        assertEq(receiver, ALICE);
    }

    function testCryptoPool() public {
        // Swapping BSGG -> USDT on a CryptoPool, deployed by factory 0xF18056Bbd320E96A48e3Fbf8bC061322531aac99
        uint256 amountIn = 1000 ether;
        deal(BSGG_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(BSGG_ADDR, USDT_ADDR, BSGG_USDT_POOL, 2, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(BSGG_ADDR).approve(BSGG_USDT_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 23429);
        assertEq(IERC20(USDT_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, USDT_ADDR);
        assertEq(receiver, ALICE);
    }

    function testTricryptoPool() public {
        // Swapping WETH -> USDC on a Tricrypto pool, deployed by factory 0x0c0e5f2fF0ff18a3be9b835635039256dC4B4963
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(WETH_ADDR, USDC_ADDR, TRICRYPTO_POOL, 2, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(WETH_ADDR).approve(TRICRYPTO_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 1861130974);
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, USDC_ADDR);
        assertEq(receiver, ALICE);
    }

    function testTwoCryptoPool() public {
        // Swapping UWU -> WETH on a Twocrypto pool, deployed by factory 0x98ee851a00abee0d95d08cf4ca2bdce32aeaaf7f
        uint256 amountIn = 1 ether;
        deal(UWU_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(UWU_ADDR, WETH_ADDR, UWU_WETH_POOL, 2, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(UWU_ADDR).approve(UWU_WETH_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 2873786684675);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, WETH_ADDR);
        assertEq(receiver, ALICE);
    }

    function testStableSwapPool() public {
        // Swapping CRVUSD -> USDT on a StableSwap pool, deployed by factory 0x4F8846Ae9380B90d2E71D5e3D042dff3E7ebb40d (plain pool)
        uint256 amountIn = 1 ether;
        deal(USDT_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(USDT_ADDR, CRVUSD_ADDR, CRVUSD_USDT_POOL, 1, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(USDT_ADDR).forceApprove(CRVUSD_USDT_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 10436946786333182306400100);
        assertEq(IERC20(CRVUSD_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, CRVUSD_ADDR);
        assertEq(receiver, ALICE);
    }

    function testMetaPool() public {
        // Swapping WTAO -> WSTTAO on a MetaPool deployed by factory 0xB9fC157394Af804a3578134A6585C0dc9cc990d4 (plain pool)
        uint256 amountIn = 100 * 10 ** 9; // 9 decimals
        deal(WTAO_ADDR, address(curveExecutorExposed), amountIn);

        bytes memory data =
            _getData(WTAO_ADDR, WSTTAO_ADDR, WSTTAO_WTAO_POOL, 1, ALICE);

        vm.prank(address(curveExecutorExposed));
        IERC20(WTAO_ADDR).approve(WSTTAO_WTAO_POOL, amountIn);
        (uint256 amountOut, address tokenOut, address receiver) =
            curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 32797923610);
        assertEq(IERC20(WSTTAO_ADDR).balanceOf(ALICE), amountOut);
        assertEq(tokenOut, WSTTAO_ADDR);
        assertEq(receiver, ALICE);
    }

    function _getData(
        address tokenIn,
        address tokenOut,
        address pool,
        uint8 poolType,
        address receiver
    ) internal view returns (bytes memory data) {
        (int128 i, int128 j) = _getIndexes(tokenIn, tokenOut, pool);
        data = abi.encodePacked(
            tokenIn,
            tokenOut,
            pool,
            poolType,
            uint8(uint256(uint128(i))),
            uint8(uint256(uint128(j))),
            receiver
        );
    }

    function _getIndexes(address tokenIn, address tokenOut, address pool)
        internal
        view
        returns (int128, int128)
    {
        (int128 coinInIndex, int128 coinOutIndex,) =
            metaRegistry.get_coin_indices(pool, tokenIn, tokenOut);
        return (coinInIndex, coinOutIndex);
    }
}

contract TychoRouterForCurveTest is TychoRouterTestSetup {
    function testSingleCurveIntegration() public {
        deal(UWU_ADDR, ALICE, 1 ether);

        vm.startPrank(ALICE);
        IERC20(UWU_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_curve");
        (bool success,) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 2877855391767);

        vm.stopPrank();
    }
}
