// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@src/executors/UniswapV3Executor.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";

contract UniswapV3ExecutorExposed is UniswapV3Executor {
    function decodeData(bytes calldata data)
        external
        pure
        returns (
            address inToken,
            address outToken,
            uint24 fee,
            address receiver,
            address target,
            bool zeroForOne
        )
    {
        return _decodeData(data);
    }
}

contract UniswapV3ExecutorTest is UniswapV3ExecutorExposed, Test, Constants {
    using SafeERC20 for IERC20;

    UniswapV3ExecutorExposed uniswapV3Exposed;
    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 DAI = IERC20(DAI_ADDR);

    function setUp() public {
        uint256 forkBlock = 17323404;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        uniswapV3Exposed = new UniswapV3ExecutorExposed();
    }

    function testDecodeParams() public view {
        uint24 expectedPoolFee = 500;
        bytes memory data = abi.encodePacked(
            WETH_ADDR, DAI_ADDR, expectedPoolFee, address(2), address(3), false
        );

        (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver,
            address target,
            bool zeroForOne
        ) = uniswapV3Exposed.decodeData(data);

        assertEq(tokenIn, WETH_ADDR);
        assertEq(tokenOut, DAI_ADDR);
        assertEq(fee, expectedPoolFee);
        assertEq(receiver, address(2));
        assertEq(target, address(3));
        assertEq(zeroForOne, false);
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams =
            abi.encodePacked(WETH_ADDR, address(2), address(3));

        vm.expectRevert(UniswapV3Executor__InvalidDataLength.selector);
        uniswapV3Exposed.decodeData(invalidParams);
    }
}
