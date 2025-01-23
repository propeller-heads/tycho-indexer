// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@src/executors/Uniswapv2SwapExecutor.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";

contract UniswapV2SwapExecutorExposed is UniswapV2SwapExecutor {
    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            IERC20 inToken,
            address target,
            address receiver,
            bool zeroForOne,
            bool exactOut
        )
    {
        return _decodeData(data);
    }

    function getAmountOut(address target, uint256 amountIn, bool zeroForOne)
        external
        view
        returns (uint256 amount)
    {
        return _getAmountOut(target, amountIn, zeroForOne);
    }
}

contract UniswapV2SwapExecutorTest is
    UniswapV2SwapExecutorExposed,
    Test,
    Constants
{
    using SafeERC20 for IERC20;

    UniswapV2SwapExecutorExposed uniswapV2Exposed;
    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 DAI = IERC20(DAI_ADDR);
    address WETH_DAI_POOL = 0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11;

    function setUp() public {
        uint256 forkBlock = 17323404;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        uniswapV2Exposed = new UniswapV2SwapExecutorExposed();
    }

    function testDecodeParams() public view {
        bytes memory params =
            abi.encodePacked(WETH_ADDR, address(2), address(3), false, true);

        (
            IERC20 tokenIn,
            address target,
            address receiver,
            bool zeroForOne,
            bool exactOut
        ) = uniswapV2Exposed.decodeParams(params);

        assertEq(address(tokenIn), WETH_ADDR);
        assertEq(target, address(2));
        assertEq(receiver, address(3));
        assertEq(zeroForOne, false);
        assertEq(exactOut, true);
    }

    function testAmountOut() public view {
        uint256 amountOut =
            uniswapV2Exposed.getAmountOut(WETH_DAI_POOL, 10 ** 18, false);
        uint256 expAmountOut = 1847751195973566072891;
        assertEq(amountOut, expAmountOut);
    }

    // triggers a uint112 overflow on purpose
    function testAmountOutInt112Overflow() public view {
        address target = 0x0B9f5cEf1EE41f8CCCaA8c3b4c922Ab406c980CC;
        uint256 amountIn = 83638098812630667483959471576;

        uint256 amountOut =
            uniswapV2Exposed.getAmountOut(target, amountIn, true);

        assertGe(amountOut, 0);
    }

    function testSwap() public {
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        bool zeroForOne = false;
        bool exactOut = true;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR, WETH_DAI_POOL, BOB, zeroForOne, exactOut
        );

        vm.startPrank(ADMIN);
        deal(WETH_ADDR, address(uniswapV2Exposed), amountIn);
        uniswapV2Exposed.swap(amountIn, protocolData);
        vm.stopPrank();

        uint256 finalBalance = DAI.balanceOf(BOB);
        assertGe(finalBalance, amountOut);
    }
}
