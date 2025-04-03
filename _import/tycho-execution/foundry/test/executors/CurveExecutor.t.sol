// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/CurveExecutor.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";

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

interface IAaveLendingPool {
    function deposit(
        address asset,
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode
    ) external;

    function withdraw(address asset, uint256 amount, address to)
        external
        returns (uint256);
}

contract CurveExecutorExposed is CurveExecutor {
    constructor(address _curveRouter, address _nativeToken)
        CurveExecutor(_curveRouter, _nativeToken)
    {}

    function decodeParams(bytes calldata data)
        external
        pure
        returns (CurveSwapParams memory params)
    {
        return _decodeData(data);
    }
}

contract CurveExecutorTest is Test, Constants {
    using SafeERC20 for IERC20;

    CurveExecutorExposed curveExecutorExposed;
    MetaRegistry metaRegistry;

    function setUp() public {
        uint256 forkBlock = 22031795;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        curveExecutorExposed = new CurveExecutorExposed(CURVE_ROUTER, ETH_ADDR);
        metaRegistry = MetaRegistry(CURVE_META_REGISTRY);
    }

    function testDecodeParams() public view {
        address[11] memory route =
            _getRoute(WETH_ADDR, USDC_ADDR, TRICRYPTO_POOL);

        // The meta registry does not have information about the pool.
        // We manually set the swap params.
        uint256[5][5] memory swapParams;
        swapParams[0][0] = 2; // tokenIn Index
        swapParams[0][1] = 0; // tokenOut Index
        swapParams[0][2] = 1; // swap type
        swapParams[0][3] = 3; // pool type
        swapParams[0][4] = 3; // n_coins

        bytes memory data = abi.encode(route, swapParams, address(this), true);

        CurveExecutor.CurveSwapParams memory params =
            curveExecutorExposed.decodeParams(data);

        assertEq(params.route[0], WETH_ADDR);
        assertEq(params.route[1], TRICRYPTO_POOL);
        assertEq(params.route[2], USDC_ADDR);
        assertEq(params.swapParams[0][0], 2);
        assertEq(params.swapParams[0][1], 0);
        assertEq(params.swapParams[0][2], 1);
        assertEq(params.swapParams[0][3], 3);
        assertEq(params.swapParams[0][4], 3);
        assertEq(params.receiver, address(this));
        assertEq(params.needsApproval, true);
    }

    function testTriPool() public {
        // Swapping DAI -> USDC on TriPool 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7
        address[11] memory route = _getRoute(DAI_ADDR, USDC_ADDR, TRIPOOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(TRIPOOL, DAI_ADDR, USDC_ADDR, 1, 1);

        uint256 amountIn = 1 ether;

        deal(DAI_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(route, swapParams, address(this), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 999796);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(this)), amountOut);
    }

    function testStEthPool() public {
        // Swapping ETH -> stETH on StEthPool 0xDC24316b9AE028F1497c275EB9192a3Ea0f67022
        address[11] memory route = _getRoute(ETH_ADDR, STETH_ADDR, STETH_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(STETH_POOL, ETH_ADDR, STETH_ADDR, 1, 1);

        uint256 amountIn = 1 ether;

        deal(address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(route, swapParams, address(this), false);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertTrue(amountOut == 1001072414418410898);
        assertEq(IERC20(STETH_ADDR).balanceOf(address(this)), amountOut - 1); //// Gets 1 wei less than amountOut
    }

    function testTricrypto2Pool() public {
        // Swapping WETH -> WBTC on Tricrypto2Pool 0xD51a44d3FaE010294C616388b506AcdA1bfAAE46
        address[11] memory route =
            _getRoute(WETH_ADDR, WBTC_ADDR, TRICRYPTO2_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(TRICRYPTO2_POOL, WETH_ADDR, WBTC_ADDR, 1, 3);

        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data =
            abi.encode(route, swapParams, address(curveExecutorExposed), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 2279618);
        assertEq(
            IERC20(WBTC_ADDR).balanceOf(address(curveExecutorExposed)),
            amountOut
        );
    }

    function testSUSDPool() public {
        // Swapping USDC -> SUSD on SUSDPool 0xA5407eAE9Ba41422680e2e00537571bcC53efBfD
        address[11] memory route = _getRoute(USDC_ADDR, SUSD_ADDR, SUSD_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(SUSD_POOL, USDC_ADDR, SUSD_ADDR, 1, 1);

        uint256 amountIn = 100 * 10 ** 6;

        deal(USDC_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data =
            abi.encode(route, swapParams, address(curveExecutorExposed), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 100488101605550214590);
        assertEq(
            IERC20(SUSD_ADDR).balanceOf(address(curveExecutorExposed)),
            amountOut
        );
    }

    function testFraxUsdcPool() public {
        // Swapping FRAX -> USDC on FraxUsdcPool 0xDcEF968d416a41Cdac0ED8702fAC8128A64241A2
        address[11] memory route =
            _getRoute(FRAX_ADDR, USDC_ADDR, FRAX_USDC_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(FRAX_USDC_POOL, FRAX_ADDR, USDC_ADDR, 1, 1);

        uint256 amountIn = 1 ether;

        deal(FRAX_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data =
            abi.encode(route, swapParams, address(curveExecutorExposed), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 998096);
        assertEq(
            IERC20(USDC_ADDR).balanceOf(address(curveExecutorExposed)),
            amountOut
        );
    }

    function testUsdeUsdcPool() public {
        // Swapping USDC -> USDE on a CryptoSwapNG, deployed by factory 0x6A8cbed756804B16E05E741eDaBd5cB544AE21bf (plain pool)
        address[11] memory route =
            _getRoute(USDC_ADDR, USDE_ADDR, USDE_USDC_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(USDE_USDC_POOL, USDC_ADDR, USDE_ADDR, 1, 1);

        uint256 amountIn = 100 * 10 ** 6;

        deal(USDC_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data =
            abi.encode(route, swapParams, address(curveExecutorExposed), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 100064812138999986170);
        assertEq(
            IERC20(USDE_ADDR).balanceOf(address(curveExecutorExposed)),
            amountOut
        );
    }

    function testDolaFraxPyusdPool() public {
        // Swapping DOLA -> FRAXPYUSD on a CryptoSwapNG, deployed by factory 0x6A8cbed756804B16E05E741eDaBd5cB544AE21bf (meta pool)
        address[11] memory route =
            _getRoute(DOLA_ADDR, FRAXPYUSD_POOL, DOLA_FRAXPYUSD_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(DOLA_FRAXPYUSD_POOL, DOLA_ADDR, FRAXPYUSD_POOL, 1, 1);

        uint256 amountIn = 100 * 10 ** 6;

        deal(DOLA_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data =
            abi.encode(route, swapParams, address(curveExecutorExposed), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 99688991);
        assertEq(
            IERC20(FRAXPYUSD_POOL).balanceOf(address(curveExecutorExposed)),
            amountOut
        );
    }

    function testCryptoPoolWithETH() public {
        // Swapping XYO -> ETH on a CryptoPool, deployed by factory 0xF18056Bbd320E96A48e3Fbf8bC061322531aac99
        address[11] memory route = _getRoute(XYO_ADDR, ETH_ADDR, ETH_XYO_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(ETH_XYO_POOL, XYO_ADDR, ETH_ADDR, 1, 2);

        uint256 amountIn = 1 ether;
        uint256 initialBalance = address(curveExecutorExposed).balance; // this address already has some ETH assigned to it
        deal(XYO_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data =
            abi.encode(route, swapParams, address(curveExecutorExposed), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 6081816039338);
        assertEq(
            address(curveExecutorExposed).balance, initialBalance + amountOut
        );
    }

    function testCryptoPool() public {
        // Swapping BSGG -> USDT on a CryptoPool, deployed by factory 0xF18056Bbd320E96A48e3Fbf8bC061322531aac99
        address[11] memory route =
            _getRoute(BSGG_ADDR, USDT_ADDR, BSGG_USDT_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(BSGG_USDT_POOL, BSGG_ADDR, USDT_ADDR, 1, 2);

        uint256 amountIn = 1000 ether;

        deal(BSGG_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data =
            abi.encode(route, swapParams, address(curveExecutorExposed), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 23429);
        assertEq(
            IERC20(USDT_ADDR).balanceOf(address(curveExecutorExposed)),
            amountOut
        );
    }

    function testTricryptoPool() public {
        // Swapping WETH -> USDC on a Tricrypto pool, deployed by factory 0x0c0e5f2fF0ff18a3be9b835635039256dC4B4963
        address[11] memory route =
            _getRoute(WETH_ADDR, USDC_ADDR, TRICRYPTO_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(TRICRYPTO_POOL, WETH_ADDR, USDC_ADDR, 1, 2);

        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(route, swapParams, address(this), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 1861130973);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(this)), amountOut);
    }

    function testTwoCryptoPool() public {
        // Swapping UWU -> WETH on a Twocrypto pool, deployed by factory 0x98ee851a00abee0d95d08cf4ca2bdce32aeaaf7f
        address[11] memory route = _getRoute(UWU_ADDR, WETH_ADDR, UWU_WETH_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(UWU_WETH_POOL, UWU_ADDR, WETH_ADDR, 1, 2);

        uint256 amountIn = 1 ether;

        deal(UWU_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data =
            abi.encode(route, swapParams, address(curveExecutorExposed), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 2873786684675);
        assertEq(
            IERC20(WETH_ADDR).balanceOf(address(curveExecutorExposed)),
            amountOut
        );
    }

    function testStableSwapPool() public {
        // Swapping CRVUSD -> USDT on a StableSwap pool, deployed by factory 0x4F8846Ae9380B90d2E71D5e3D042dff3E7ebb40d (plain pool)
        address[11] memory route =
            _getRoute(CRVUSD_ADDR, USDT_ADDR, CRVUSD_USDT_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(CRVUSD_USDT_POOL, CRVUSD_ADDR, USDT_ADDR, 1, 1);

        uint256 amountIn = 1 ether;

        deal(CRVUSD_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data =
            abi.encode(route, swapParams, address(curveExecutorExposed), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 999910);
        assertEq(
            IERC20(USDT_ADDR).balanceOf(address(curveExecutorExposed)),
            amountOut
        );
    }

    function testMetaPool() public {
        // Swapping WTAO -> WSTTAO on a MetaPool deployed by factory 0xB9fC157394Af804a3578134A6585C0dc9cc990d4 (plain pool)
        address[11] memory route =
            _getRoute(WTAO_ADDR, WSTTAO_ADDR, WSTTAO_WTAO_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(WSTTAO_WTAO_POOL, WTAO_ADDR, WSTTAO_ADDR, 1, 1);

        uint256 amountIn = 100 * 10 ** 9; // 9 decimals

        deal(WTAO_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data =
            abi.encode(route, swapParams, address(curveExecutorExposed), true);

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 32797923609);
        assertEq(
            IERC20(WSTTAO_ADDR).balanceOf(address(curveExecutorExposed)),
            amountOut
        );
    }

    function _getRoute(address tokenIn, address tokenOut, address pool)
        internal
        pure
        returns (address[11] memory route)
    {
        route[0] = tokenIn;
        route[2] = tokenOut;
        route[1] = pool;
    }

    function _getSwapParams(
        address pool,
        address tokenIn,
        address tokenOut,
        uint256 swapType,
        uint256 poolType
    ) internal view returns (uint256[5][5] memory swapParams) {
        uint256 nCoins = metaRegistry.get_n_coins(pool);
        (int128 coinInIndex, int128 coinOutIndex,) =
            metaRegistry.get_coin_indices(pool, tokenIn, tokenOut);

        swapParams[0][0] = uint256(int256(coinInIndex));
        swapParams[0][1] = uint256(int256(coinOutIndex));
        swapParams[0][2] = swapType;
        swapParams[0][3] = poolType;
        swapParams[0][4] = nCoins;
    }

    function dealAaveDai() internal {
        deal(DAI_ADDR, address(curveExecutorExposed), 100_000 * 10 ** 18);
        IAaveLendingPool aave =
            IAaveLendingPool(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);

        vm.startPrank(address(curveExecutorExposed));
        IERC20(DAI_ADDR).approve(address(aave), type(uint256).max);
        aave.deposit(
            DAI_ADDR, 100_000 * 10 ** 18, address(curveExecutorExposed), 0
        );
        vm.stopPrank();
    }
}
