// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "@src/executors/LidoExecutor.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";

contract LidoExecutorExposed is LidoExecutor {
    constructor(
        address _st_eth_address,
        address _wst_eth_address,
        address _permit2
    ) LidoExecutor(_st_eth_address, _wst_eth_address, _permit2) {}

    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            address receiver,
            TransferType transferType,
            LidoPoolType pool,
            LidoPoolDirection direction
        )
    {
        return _decodeData(data);
    }
}

contract LidoExecutorTest is Constants, Permit2TestHelper, TestUtils {
    using SafeERC20 for IERC20;

    LidoExecutorExposed LidoExposed;

    function setUp() public {
        uint256 forkBlock = 23934489; //change for a newer block
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        LidoExposed = new LidoExecutorExposed(
            STETH_ADDR,
            WSTETH_ADDR,
            PERMIT2_ADDRESS
        );
    }

    function testDecodeParams() public view {
        bytes memory params = abi.encodePacked(
            BOB,
            RestrictTransferFrom.TransferType.None,
            LidoPoolType.stETH,
            LidoPoolDirection.Stake
        );

        (
            address receiver,
            RestrictTransferFrom.TransferType transferType,
            LidoPoolType pool,
            LidoPoolDirection direction
        ) = LidoExposed.decodeParams(params);

        assertEq(receiver, BOB);
        assertEq(
            uint8(transferType),
            uint8(RestrictTransferFrom.TransferType.None)
        );
        assertEq(uint8(pool), uint8(LidoPoolType.stETH));
        assertEq(uint8(direction), uint8(LidoPoolDirection.Stake));
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams = abi.encodePacked(
            BOB,
            RestrictTransferFrom.TransferType.None,
            LidoPoolType.stETH
        );

        vm.expectRevert(LidoExecutor__InvalidDataLength.selector);
        LidoExposed.decodeParams(invalidParams);
    }

    function testStaking() public {
        uint256 amountIn = 1 ether;
        uint256 expectedAmountOut = 999999999999999998;

        bytes memory protocolData = abi.encodePacked(
            BOB,
            RestrictTransferFrom.TransferType.None,
            LidoPoolType.stETH,
            LidoPoolDirection.Stake
        );

        deal(BOB, amountIn);
        vm.prank(BOB);
        uint256 calculatedAmount =
            LidoExposed.swap{value: amountIn}(amountIn, protocolData);

        uint256 finalBalance = IERC20(STETH_ADDR).balanceOf(BOB);
        assertEq(calculatedAmount, finalBalance);
        assertEq(finalBalance, expectedAmountOut);
        assertEq(BOB.balance, 0);
    }

    function testWrapping() public {
        uint256 amountIn = 1 ether;
        uint256 expectedAmountOut = 819085003283072217;

        // Need to mint STETH before, just dealing won't work because stETH does some internal accounting
        deal(address(LidoExposed), amountIn);
        vm.startPrank(address(LidoExposed));
        LidoPool(STETH_ADDR).submit{value: amountIn}(address(LidoExposed));
        uint256 stETHAmount = IERC20(STETH_ADDR).balanceOf(address(LidoExposed));

        bytes memory protocolData = abi.encodePacked(
            BOB,
            RestrictTransferFrom.TransferType.None,
            LidoPoolType.wstETH,
            LidoPoolDirection.Wrap
        );

        IERC20(STETH_ADDR).approve(WSTETH_ADDR, amountIn);

        uint256 amountOut = LidoExposed.swap(stETHAmount, protocolData);

        uint256 finalBalance = IERC20(WSTETH_ADDR).balanceOf(BOB);
        assertEq(amountOut, expectedAmountOut);
        assertEq(finalBalance, expectedAmountOut);
        // there is 1 wei left in the contract
        assertEq(IERC20(STETH_ADDR).balanceOf(address(LidoExposed)), 1);

    vm.stopPrank();
    }

    function testUnwrapping() public {
        uint256 amountIn = 1 ether;
        uint256 expectedAmountOut = 1220874507519708969;

        deal(WSTETH_ADDR, address(LidoExposed), amountIn);
        bytes memory protocolData = abi.encodePacked(
            BOB,
            RestrictTransferFrom.TransferType.None,
            LidoPoolType.wstETH,
            LidoPoolDirection.Unwrap
        );
        vm.startPrank(address(LidoExposed));
        uint256 amountOut = LidoExposed.swap(amountIn, protocolData);

        uint256 finalBalance = IERC20(STETH_ADDR).balanceOf(BOB);
        assertEq(amountOut, expectedAmountOut);
        assertEq(finalBalance, expectedAmountOut);
        assertEq(IERC20(WSTETH_ADDR).balanceOf(address(LidoExposed)), 0);
        vm.stopPrank();
    }
}
