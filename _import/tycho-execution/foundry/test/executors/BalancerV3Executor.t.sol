// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../../src/executors/BalancerV3Executor.sol";
import "../TestUtils.sol";
import "@src/executors/BalancerV3Executor.sol";
import {Constants} from "../Constants.sol";

contract BalancerV3ExecutorExposed is BalancerV3Executor {
    constructor(address _permit2) BalancerV3Executor(_permit2) {}

    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            uint256 amountGiven,
            IERC20 tokenIn,
            IERC20 tokenOut,
            address poolId,
            TransferType transferType,
            address receiver
        )
    {
        return _decodeData(data);
    }
}

contract BalancerV3ExecutorTest is Constants, TestUtils {
    using SafeERC20 for IERC20;

    BalancerV3ExecutorExposed balancerV3Exposed;
    address WETH_osETH_pool =
        address(0x57c23c58B1D8C3292c15BEcF07c62C5c52457A42);
    address osETH_ADDR = address(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
    address waEthWETH_ADDR = address(0x0bfc9d54Fc184518A81162F8fB99c2eACa081202);

    function setUp() public {
        uint256 forkBlock = 22625131;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        balancerV3Exposed = new BalancerV3ExecutorExposed(PERMIT2_ADDRESS);
    }

    function testDecodeParams() public view {
        bytes memory params = abi.encodePacked(
            uint256(1 ether),
            osETH_ADDR,
            waEthWETH_ADDR,
            WETH_osETH_pool,
            RestrictTransferFrom.TransferType.None,
            BOB
        );

        (
            uint256 amountGiven,
            IERC20 tokenIn,
            IERC20 tokenOut,
            address poolId,
            RestrictTransferFrom.TransferType transferType,
            address receiver
        ) = balancerV3Exposed.decodeParams(params);

        assertEq(amountGiven, 1 ether);
        assertEq(address(tokenIn), osETH_ADDR);
        assertEq(address(tokenOut), waEthWETH_ADDR);
        assertEq(poolId, WETH_osETH_pool);
        assertEq(
            uint8(transferType), uint8(RestrictTransferFrom.TransferType.None)
        );
        assertEq(receiver, BOB);
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams = abi.encodePacked(
            osETH_ADDR,
            waEthWETH_ADDR,
            WETH_osETH_pool,
            RestrictTransferFrom.TransferType.None
        );

        vm.expectRevert(BalancerV3Executor__InvalidDataLength.selector);
        balancerV3Exposed.decodeParams(invalidParams);
    }

    function testSwap() public {
        uint256 amountIn = 10 ** 18;
        bytes memory protocolData = abi.encodePacked(
            osETH_ADDR,
            waEthWETH_ADDR,
            WETH_osETH_pool,
            RestrictTransferFrom.TransferType.Transfer,
            BOB
        );

        deal(osETH_ADDR, address(balancerV3Exposed), amountIn);

        uint256 balanceBefore = IERC20(waEthWETH_ADDR).balanceOf(BOB);

        uint256 amountOut = balancerV3Exposed.swap(amountIn, protocolData);

        uint256 balanceAfter = IERC20(waEthWETH_ADDR).balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
    }
}
