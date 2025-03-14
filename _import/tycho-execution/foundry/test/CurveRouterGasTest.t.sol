// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {Constants} from "./Constants.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ICurveRouter} from "../interfaces/ICurveRouter.sol";

contract CurveRouterGasTest is Constants {
    ICurveRouter curveRouter = ICurveRouter(CURVE_ROUTER);

    function setUp() public {
        uint256 forkBlock = 22031795;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
    }

    function testCurveRouter() public {
        address[11] memory route;
        route[0] = WETH_ADDR;
        route[1] = TRICRYPTO_POOL;
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

        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(curveRouter), amountIn);
        curveRouter.exchange(
            route, swapParams, amountIn, minAmountOut, pools, address(this)
        );
        vm.stopPrank();
    }
}
