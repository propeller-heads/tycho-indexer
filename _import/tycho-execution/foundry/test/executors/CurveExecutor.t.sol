// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/CurveExecutor.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";


interface ICurvePool {
    function coins(uint256 i) external view returns (address);
}

interface ILendingPool {
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
    constructor(address _curveRouter, address _ethAddress) CurveExecutor(_curveRouter, _ethAddress) {}

    function decodeParams(bytes calldata data)
        external
        pure
        returns (CurveRouterParams memory params)
    {
        return _decodeData(data);
    }
}

contract CurveExecutorTest is Test, Constants {
    using SafeERC20 for IERC20;

    CurveExecutorExposed curveExecutorExposed;

    function setUp() public {
        uint256 forkBlock = 22031795;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        curveExecutorExposed = new CurveExecutorExposed(CURVE_ROUTER, ETH_ADDR);
    }

    function testDecodeParams() public view {
        address[11] memory route;
        route[0] = WETH_ADDR;
        route[1] = TRICRYPTO_USDC_WBTC_WETH;
        route[2] = USDC_ADDR;

        uint256[5][5] memory swapParams;
        swapParams[0][0] = 2; // tokenIn Index
        swapParams[0][1] = 0; // tokenOut Index
        swapParams[0][2] = 1; // swap type
        swapParams[0][3] = 3; // pool type
        swapParams[0][4] = 3; // n_coins

        uint256 amountIn = 1 ether;
        uint256 minAmountOut = 0;
        address[5] memory pools;

        bytes memory data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(this)
        );

        CurveRouterParams memory params =
            curveExecutorExposed.decodeParams(data);

        assertEq(params.route[0], WETH_ADDR);
        assertEq(params.route[1], TRICRYPTO_USDC_WBTC_WETH);
        assertEq(params.route[2], USDC_ADDR);
        assertEq(params.swapParams[0][0], 2);
        assertEq(params.swapParams[0][1], 0);
        assertEq(params.swapParams[0][2], 1);
        assertEq(params.swapParams[0][3], 3);
    }


    function testCurveSwapPoolType0() public {
        address[11] memory route = _getRoute(ADAI_ADDR, AUSDC_ADDR, AAVE_POOL);
        uint256[5][5] memory swapParams = _getSwapParams(AAVE_POOL, ADAI_ADDR, AUSDC_ADDR, 1, 1);

        uint256 amountIn = 1 ether;
        uint256 minAmountOut = 0;
        address[5] memory pools;

        dealAaveDai();
        bytes memory data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(curveExecutorExposed)
        );

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 999734);
        assertEq(IERC20(AUSDC_ADDR).balanceOf(address(curveExecutorExposed)), amountOut);
    }

     function testCurveSwapPoolType1() public {
        address[11] memory route =
            _getRoute(DAI_ADDR, USDC_ADDR, TRIPOOL_USDT_USDC_DAI);
        uint256[5][5] memory swapParams =
            _getSwapParams(TRIPOOL_USDT_USDC_DAI, DAI_ADDR, USDC_ADDR, 1, 1);

        uint256 amountIn = 1 ether;
        uint256 minAmountOut = 0;
        address[5] memory pools;

        deal(DAI_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(this)
        );

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 999796);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(this)), amountOut);
    }

    function testCurveSwapPoolType3() public {
        address[11] memory route =
            _getRoute(WETH_ADDR, USDC_ADDR, TRICRYPTO_USDC_WBTC_WETH);
        uint256[5][5] memory swapParams =
            _getSwapParams(TRICRYPTO_USDC_WBTC_WETH, WETH_ADDR, USDC_ADDR, 1, 3);

        uint256 amountIn = 1 ether;
        uint256 minAmountOut = 0;
        address[5] memory pools;

        deal(WETH_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(this)
        );

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 1861130973);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(this)), amountOut);
    }

    function testCurveSwapPoolType4() public {
        address[11] memory route =
            _getRoute(ETH_ADDR, STETH_ADDR, STETH_POOL);
        uint256[5][5] memory swapParams =
            _getSwapParams(STETH_POOL, ETH_ADDR, STETH_ADDR, 1, 1);

        uint256 amountIn = 1 ether;
        uint256 minAmountOut = 0;
        address[5] memory pools;

        deal(address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(curveExecutorExposed)
        );

        uint256 amountOut = curveExecutorExposed.swap(
            amountIn, data
        );

        assertTrue(amountOut >= 1 ether);
        assertEq(IERC20(STETH_ADDR).balanceOf(address(curveExecutorExposed)), amountOut - 1); // Gets 1 wei less than amountOut

        // Now reverse the swap
        amountIn = amountOut - 1;
        route =
            _getRoute(STETH_ADDR, ETH_ADDR, STETH_POOL);
        swapParams =
            _getSwapParams(STETH_POOL, STETH_ADDR, ETH_ADDR, 1, 1);

        data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(curveExecutorExposed)
        );

        amountOut = curveExecutorExposed.swap(
            amountIn, data
        );

        assertEq(address(curveExecutorExposed).balance, 999800010006950374);
    }


    function testCurveSwapPoolType5() public {
        address[11] memory route =
        _getRoute(LUSD_ADDR, USDT_ADDR, LUSD_POOL);
        uint256[5][5] memory swapParams =
        _getSwapParams(LUSD_POOL, LUSD_ADDR, USDT_ADDR, 2, 1);

        // pool.coins(index) reverts, defaulting tokenOut index to 0
        swapParams[0][1] = 3;

        uint256 amountIn = 1 ether;
        uint256 minAmountOut = 0;
        address[5] memory pools;

        deal(LUSD_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(curveExecutorExposed)
        );

        uint256 amountOut = curveExecutorExposed.swap(
            amountIn, data
        );

        assertEq(amountOut, 1001785);
        assertEq(IERC20(USDT_ADDR).balanceOf(address(curveExecutorExposed)), amountOut);
    }


    function testCurveSwapPoolType6() public {
        address[11] memory route =
        _getRoute(DAI_ADDR, USDC_ADDR, CPOOL);
        uint256[5][5] memory swapParams =
        _getSwapParams(CPOOL, DAI_ADDR, USDC_ADDR, 2, 1);
        
        // pool.coins(index) reverts, defaulting tokenOut index to 0
        swapParams[0][1] = 1;

        uint256 amountIn = 1 ether;
        uint256 minAmountOut = 0;
        address[5] memory pools;

        deal(DAI_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(curveExecutorExposed)
        );

        uint256 amountOut = curveExecutorExposed.swap(
            amountIn, data);

        assertEq(amountOut, 999549);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(curveExecutorExposed)), amountOut);
    }

    function testCurveSwapPoolType7() public {
        address[11] memory route = _getRoute(WETH_ADDR, LDO_ADDR, LDO_POOL);
        uint256[5][5] memory swapParams = _getSwapParams(LDO_POOL, WETH_ADDR, LDO_ADDR, 1, 4);

        // pool.coins(index) reverts, defaulting tokenOut index to 0
        swapParams[0][1] = 1;

        uint256 amountIn = 1 ether;
        uint256 minAmountOut = 0;
        address[5] memory pools;

        deal(WETH_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(curveExecutorExposed)
        );

        uint256 amountOut = curveExecutorExposed.swap(
            amountIn, data);
            

        assertEq(amountOut, 2075236672516568049094);
        assertEq(IERC20(LDO_ADDR).balanceOf(address(curveExecutorExposed)), amountOut);
    }
    
    function testCurveSwapPoolType8() public {
        address[11] memory route = _getRoute(CRV_ADDR, WETH_ADDR, CRV_POOL);
        uint256[5][5] memory swapParams = _getSwapParams(CRV_POOL, CRV_ADDR, WETH_ADDR, 1, 4);

        uint256 amountIn = 1 ether;
        uint256 minAmountOut = 0;
        address[5] memory pools;

        deal(CRV_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(curveExecutorExposed)
        );

        uint256 amountOut = curveExecutorExposed.swap(
            amountIn, data);

        assertEq(amountOut, 21806692849);
        assertEq(IERC20(WETH_ADDR).balanceOf(address(curveExecutorExposed)), amountOut);
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
        // Get number of coins in pool and their indices
        uint256 coinInIndex;
        uint256 coinOutIndex;
        uint256 nCoins;
        address lastCoinAddress = address(1);
        while (lastCoinAddress != address(0)) {
            try ICurvePool(pool).coins(nCoins) returns (address coin) {
                lastCoinAddress = coin;
                nCoins++;
                if (coin == tokenIn) {
                    coinInIndex = nCoins - 1;
                }
                if (coin == tokenOut) {
                    coinOutIndex = nCoins - 1;
                }
            } catch {
                lastCoinAddress = address(0);
            }
        }

        swapParams[0][0] = coinInIndex;
        swapParams[0][1] = coinOutIndex;
        swapParams[0][2] = swapType;
        swapParams[0][3] = poolType;
        swapParams[0][4] = nCoins;
    }


       function dealAaveDai() internal {
        deal(DAI_ADDR,  address(curveExecutorExposed), 100_000 * 10 ** 18);
        ILendingPool aave =
            ILendingPool(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);

        vm.startPrank(address(curveExecutorExposed));
        IERC20(DAI_ADDR).approve(address(aave), type(uint256).max);
        aave.deposit(DAI_ADDR, 100_000 * 10 ** 18, address(curveExecutorExposed), 0);
        vm.stopPrank();
    }
}

