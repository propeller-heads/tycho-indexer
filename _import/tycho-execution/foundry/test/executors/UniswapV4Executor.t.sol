// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";

contract UniswapV4ExecutorExposed is UniswapV4Executor {
    constructor(IPoolManager _poolManager) UniswapV4Executor(_poolManager) {}

    function decodeData(
        bytes calldata data
    )
        external
        pure
        returns (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver,
            bool zeroForOne,
            uint24 tickSpacing
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

    function setUp() public {
        uint256 forkBlock = 21817316;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        uniswapV4Exposed = new UniswapV4ExecutorExposed(
            IPoolManager(0x000000000004444c5dc75cB358380D2e3dE08A90)
        );
    }

    function testDecodeParamsUniswapV4() public view {
        uint24 expectedPoolFee = 500;
        bytes memory data = abi.encodePacked(
            USDE_ADDR,
            USDT_ADDR,
            expectedPoolFee,
            address(2),
            false,
            int24(1)
        );

        (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver,
            bool zeroForOne,
            uint24 tickSpacing
        ) = uniswapV4Exposed.decodeData(data);

        assertEq(tokenIn, USDE_ADDR);
        assertEq(tokenOut, USDT_ADDR);
        assertEq(fee, expectedPoolFee);
        assertEq(receiver, address(2));
        assertEq(zeroForOne, false);
        assertEq(tickSpacing, 1);
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory data = abi.encodePacked(USDE_ADDR, USDT_ADDR);

        vm.expectRevert(UniswapV4Executor__InvalidDataLength.selector);
        uniswapV4Exposed.decodeData(data);
    }

    function testSwapUniswapV4() public {
        uint256 amountIn = 1 ether;
        deal(USDE_ADDR, address(uniswapV4Exposed), amountIn);
        assertEq(USDE.balanceOf(address(uniswapV4Exposed)), amountIn);

        bytes memory data = abi.encodePacked(
            USDE_ADDR,
            USDT_ADDR,
            uint24(100), // 0.01% fee tier
            address(this),
            true,
            int24(1)
        );

        uint256 amountOut = uniswapV4Exposed.swap(amountIn, data);
        assertEq(USDE.balanceOf(address(uniswapV4Exposed)), 0);
    }
}
