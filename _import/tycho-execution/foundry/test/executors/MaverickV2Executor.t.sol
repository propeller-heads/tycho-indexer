// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/MaverickV2Executor.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";

contract MaverickV2ExecutorExposed is MaverickV2Executor {
    constructor(address _factory) MaverickV2Executor(_factory) {}
    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            IERC20 tokenIn,
            address target,
            address receiver
        )
    {
        return _decodeData(data);
    }
}

contract MaverickV2ExecutorTest is
    Test,
    Constants
{
    using SafeERC20 for IERC20;

    MaverickV2ExecutorExposed maverickV2Exposed;
    IERC20 GHO = IERC20(GHO_ADDR);
    IERC20 USDC = IERC20(USDC_ADDR);

    function setUp() public {
        uint256 forkBlock = 20127232;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        maverickV2Exposed = new MaverickV2ExecutorExposed(MAVERICK_V2_FACTORY);
    }

    function testDecodeParams() public view {
        bytes memory params = abi.encodePacked(
            GHO_ADDR, GHO_USDC_POOL, address(2)
        );

        (
            IERC20 tokenIn,
            address target,
            address receiver
        ) = maverickV2Exposed.decodeParams(params);

        assertEq(address(tokenIn), GHO_ADDR);
        assertEq(target, GHO_USDC_POOL);
        assertEq(receiver, address(2));
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams =
            abi.encodePacked(GHO_ADDR, GHO_USDC_POOL, address(2), true);

        vm.expectRevert(MaverickV2Executor__InvalidDataLength.selector);
        maverickV2Exposed.decodeParams(invalidParams);
    }

    function testSwap() public {
        uint256 amountIn = 10 ** 18;
        bytes memory protocolData =
            abi.encodePacked(GHO_ADDR, GHO_USDC_POOL, address(2));

        deal(GHO_ADDR, address(maverickV2Exposed), amountIn);
        uint256 balanceBefore = GHO.balanceOf(BOB);

        uint256 amountOut = maverickV2Exposed.swap(amountIn, protocolData);

        uint256 balanceAfter = GHO.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
    }
}
