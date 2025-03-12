// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/CurveExecutor.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";

contract CurveExecutorExposed is CurveExecutor {
    constructor(address _curveRouter) CurveExecutor(_curveRouter) {}

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
        curveExecutorExposed = new CurveExecutorExposed(CURVE_ROUTER);
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

    function testSwapCurve() public {
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

        deal(WETH_ADDR, address(curveExecutorExposed), amountIn);
        bytes memory data = abi.encode(
            route, swapParams, amountIn, minAmountOut, pools, address(this)
        );

        uint256 amountOut = curveExecutorExposed.swap(amountIn, data);

        assertEq(amountOut, 1861130973);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(this)), amountOut);
    }
}
