// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "@src/executors/LidoExecutor.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import "../TychoRouterTestSetup.sol";

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
            LidoPoolDirection direction,
            bool approvalNeeded
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
            LidoPoolDirection.Stake,
            false
        );

        (
            address receiver,
            RestrictTransferFrom.TransferType transferType,
            LidoPoolType pool,
            LidoPoolDirection direction,
            bool approvalNeeded
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
            LidoPoolDirection.Stake,
            false
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
            LidoPoolDirection.Wrap,
            true
        );

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
            LidoPoolDirection.Unwrap,
            false
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

contract TychoRouterForLidoTest is TychoRouterTestSetup {
    LidoExecutorExposed LidoExposed;

    function testSingleStakeLidoIntegration() public {
        deal(ALICE, 1 ether);

        vm.startPrank(ALICE);

        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_steth_lido"
        );

        (bool success, ) = tychoRouterAddr.call{value: 1 ether}(callData);

        assertTrue(success, "Call Failed");
        assertEq(ALICE.balance, 0);
    }

    function testSingleWrapLidoIntegration() public {
        deal(address(ALICE), 1 ether);

        vm.startPrank(ALICE);
        LidoPool(STETH_ADDR).submit{value: 1 ether}(address(ALICE));

        IERC20(STETH_ADDR).approve(tychoRouterAddr, type(uint256).max - 1);
        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_wrap_wsteth_lido"
        );
        (bool success, ) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(STETH_ADDR).balanceOf(ALICE), 0);
    }

    function testSingleUnwrapLidoIntegration() public {
        vm.startPrank(ALICE);

        deal(WSTETH_ADDR, address(ALICE), 1 ether);

        IERC20(WSTETH_ADDR).approve(tychoRouterAddr, type(uint256).max - 1);
        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_unwrap_wsteth_lido"
        );
        (bool success, ) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(WSTETH_ADDR).balanceOf(ALICE), 0);
    }

    function testSingleLidoIntegrationGroupedSwap() public {
        // Test created with calldata from our router encoder.

        // Performs a single swap from USDC to stETH though ETH using two
        //  USV4  and Lido pools. It's a single swap because it is a consecutive grouped swaps
        //
        //   USDC ──(USV4)──> ETH ───(Lido)──> stETH
        //

        uint256 balanceBefore = IERC20(STETH_ADDR).balanceOf(ALICE);

        // Approve
        vm.startPrank(ALICE);

        deal(USDC_ADDR, ALICE, 1000_000000);

        uint256 balanceBefore1 = IERC20(USDC_ADDR).balanceOf(ALICE);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, type(uint256).max);

        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_usv4_lido_2"
        );
        (bool success, ) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        console.log(balanceBefore1, ALICE.balance);

        assertTrue(success, "Call Failed");
    }

    function testSingleCurveLidoIntegrationGroupedSwap() public {
        // Test created with calldata from our router encoder.

        // Performs a single swap from USDC to stETH though ETH using two
        //  USV4  and Lido pools. It's a single swap because it is a consecutive grouped swaps
        //
        //   ETH ──(Curve)──> stETH (Lido)──> wstETH
        //

        deal(ALICE, 1 ether);

        vm.startPrank(ALICE);

        IERC20(STETH_ADDR).approve(tychoRouterAddr, type(uint256).max - 1);

        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_curve_lido_grouped_swap"
        );

        (bool success, ) = tychoRouterAddr.call{value: 1 ether}(callData);

        assertTrue(success, "Call Failed");
        assertEq(ALICE.balance, 0);
    }
}
