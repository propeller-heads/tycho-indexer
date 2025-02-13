// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "@src/executors/UniswapV3Executor.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";

contract UniswapV3ExecutorExposed is UniswapV3Executor {
    constructor(address _factory) UniswapV3Executor(_factory) {}

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

contract UniswapV3ExecutorTest is Test, Constants {
    using SafeERC20 for IERC20;

    UniswapV3ExecutorExposed uniswapV3Exposed;
    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 DAI = IERC20(DAI_ADDR);
    address factory = 0x1F98431c8aD98523631AE4a59f267346ea31F984;

    function setUp() public {
        uint256 forkBlock = 17323404;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        uniswapV3Exposed = new UniswapV3ExecutorExposed(factory);
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

    function testUSV3Callback() public {
        uint24 poolFee = 3000;
        uint256 amountOwed = 1000000000000000000;
        deal(WETH_ADDR, address(uniswapV3Exposed), amountOwed);
        uint256 initialPoolReserve = IERC20(WETH_ADDR).balanceOf(DAI_WETH_USV3);

        vm.startPrank(DAI_WETH_USV3);
        bytes memory callbackData = _encodeUSV3CallbackData(
            int256(amountOwed), // amount0Delta
            int256(0), // amount1Delta
            WETH_ADDR,
            DAI_ADDR,
            poolFee
        );
        uniswapV3Exposed.handleCallback(callbackData);
        vm.stopPrank();

        uint256 finalPoolReserve = IERC20(WETH_ADDR).balanceOf(DAI_WETH_USV3);
        assertEq(finalPoolReserve - initialPoolReserve, amountOwed);
    }

    function _encodeUSV3CallbackData(
        int256 amount0Delta,
        int256 amount1Delta,
        address tokenIn,
        address tokenOut,
        uint24 fee
    ) internal pure returns (bytes memory) {
        // Dummy selector for handleCallback
        bytes4 selector =
            bytes4(keccak256("handleCallback(int256,int256,bytes)"));

        bytes memory tokenData = abi.encodePacked(tokenIn, tokenOut, fee);

        // [0:4]   - function selector
        // [4:68]  - abi.encode(amount0Delta, amount1Delta)
        // [68:end] - abi.encode(tokenData) where tokenData is the packed bytes
        return abi.encodePacked(
            selector,
            abi.encode(amount0Delta, amount1Delta),
            abi.encode(tokenData)
        );
    }
}
