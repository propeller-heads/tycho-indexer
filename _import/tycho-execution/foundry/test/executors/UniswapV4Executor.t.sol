// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "./UniswapV4Utils.sol";
import "@src/executors/UniswapV4Executor.sol";
import {Constants} from "../Constants.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {console} from "forge-std/console.sol";

contract UniswapV4ExecutorExposed is UniswapV4Executor {
    constructor(IPoolManager _poolManager) UniswapV4Executor(_poolManager) {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            address tokenIn,
            address tokenOut,
            bool isExactInput,
            uint256 amount
        )
    {
        return _decodeData(data);
    }
}

contract UniswapV4ExecutorTest is Test, Constants {
    using SafeERC20 for IERC20;

    UniswapV4ExecutorExposed uniswapV4Exposed;
    IERC20 USDE = IERC20(USDE_ADDR);
    IERC20 USDT = IERC20(USDT_ADDR);
    address poolManager = 0x000000000004444c5dc75cB358380D2e3dE08A90;

    function setUp() public {
        uint256 forkBlock = 21817316;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        uniswapV4Exposed =
            new UniswapV4ExecutorExposed(IPoolManager(poolManager));
    }

    function testDecodeParams() public view {
        uint24 expectedPoolFee = 500;
        uint128 expectedAmount = 100;

        bytes memory data = UniswapV4Utils.encodeExactInputSingle(
            USDE_ADDR, USDT_ADDR, expectedPoolFee, false, 1, expectedAmount
        );

        (address tokenIn, address tokenOut, bool isExactInput, uint256 amount) =
            uniswapV4Exposed.decodeData(data);

        assertEq(tokenIn, USDE_ADDR);
        assertEq(tokenOut, USDT_ADDR);
        assertTrue(isExactInput);
        assertEq(amount, expectedAmount);
    }

    function testSwap() public {
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, address(uniswapV4Exposed), amountIn);
        uint256 usdeBalanceBeforePool = USDE.balanceOf(poolManager);
        uint256 usdeBalanceBeforeSwapExecutor =
            USDE.balanceOf(address(uniswapV4Exposed));

        bytes memory data = UniswapV4Utils.encodeExactInputSingle(
            USDE_ADDR, USDT_ADDR, 100, true, 1, uint128(amountIn)
        );

        uint256 amountOut = uniswapV4Exposed.swap(amountIn, data);
        assertEq(USDE.balanceOf(poolManager), usdeBalanceBeforePool + amountIn);
        assertEq(
            USDE.balanceOf(address(uniswapV4Exposed)),
            usdeBalanceBeforeSwapExecutor - amountIn
        );
        assertTrue(USDT.balanceOf(address(uniswapV4Exposed)) == amountOut);
    }
}
