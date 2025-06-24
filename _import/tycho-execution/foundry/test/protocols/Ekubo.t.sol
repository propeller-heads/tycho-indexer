// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "../TychoRouterTestSetup.sol";
import "@src/executors/EkuboExecutor.sol";
import {Constants} from "../Constants.sol";
import {ICore} from "@ekubo/interfaces/ICore.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {NATIVE_TOKEN_ADDRESS} from "@ekubo/math/constants.sol";
import {console} from "forge-std/Test.sol";

contract EkuboExecutorTest is Constants, TestUtils {
    address constant EXECUTOR_ADDRESS =
        0xcA4F73Fe97D0B987a0D12B39BBD562c779BAb6f6; // Same address as in swap_encoder.rs tests
    EkuboExecutor executor;

    IERC20 USDC = IERC20(USDC_ADDR);
    IERC20 USDT = IERC20(USDT_ADDR);

    address constant CORE_ADDRESS = 0xe0e0e08A6A4b9Dc7bD67BCB7aadE5cF48157d444;
    address constant MEV_RESIST_ADDRESS =
        0x553a2EFc570c9e104942cEC6aC1c18118e54C091;

    bytes32 constant ORACLE_CONFIG =
        0x51d02a5948496a67827242eabc5725531342527c000000000000000000000000;

    // 0.01% fee and 0.02% tick spacing
    bytes32 constant MEV_RESIST_POOL_CONFIG =
        0x553a2EFc570c9e104942cEC6aC1c18118e54C09100068db8bac710cb000000c8;

    modifier setUpFork(uint256 blockNumber) {
        vm.createSelectFork(vm.rpcUrl("mainnet"), blockNumber);

        deployCodeTo(
            "executors/EkuboExecutor.sol",
            abi.encode(CORE_ADDRESS, MEV_RESIST_ADDRESS, PERMIT2_ADDRESS),
            EXECUTOR_ADDRESS
        );
        executor = EkuboExecutor(payable(EXECUTOR_ADDRESS));
        _;
    }

    function testSingleSwapEth() public setUpFork(22722989) {
        uint256 amountIn = 1 ether;

        deal(address(executor), amountIn);

        uint256 ethBalanceBeforeCore = CORE_ADDRESS.balance;
        uint256 ethBalanceBeforeExecutor = address(executor).balance;

        uint256 usdcBalanceBeforeCore = USDC.balanceOf(CORE_ADDRESS);
        uint256 usdcBalanceBeforeExecutor = USDC.balanceOf(address(executor));

        bytes memory data = abi.encodePacked(
            uint8(RestrictTransferFrom.TransferType.Transfer), // transfer type (transfer from executor to core)
            address(executor), // receiver
            NATIVE_TOKEN_ADDRESS, // tokenIn
            USDC_ADDR, // tokenOut
            ORACLE_CONFIG // poolConfig
        );

        uint256 gasBefore = gasleft();
        uint256 amountOut = executor.swap(amountIn, data);
        console.log(gasBefore - gasleft());

        console.log(amountOut);

        assertEq(CORE_ADDRESS.balance, ethBalanceBeforeCore + amountIn);
        assertEq(address(executor).balance, ethBalanceBeforeExecutor - amountIn);

        assertEq(
            USDC.balanceOf(CORE_ADDRESS), usdcBalanceBeforeCore - amountOut
        );
        assertEq(
            USDC.balanceOf(address(executor)),
            usdcBalanceBeforeExecutor + amountOut
        );
    }

    function testSingleSwapERC20() public setUpFork(22722989) {
        uint256 amountIn = 1_000_000_000;

        deal(USDC_ADDR, address(executor), amountIn);

        uint256 usdcBalanceBeforeCore = USDC.balanceOf(CORE_ADDRESS);
        uint256 usdcBalanceBeforeExecutor = USDC.balanceOf(address(executor));

        uint256 ethBalanceBeforeCore = CORE_ADDRESS.balance;
        uint256 ethBalanceBeforeExecutor = address(executor).balance;

        bytes memory data = abi.encodePacked(
            uint8(RestrictTransferFrom.TransferType.Transfer), // transferNeeded (transfer from executor to core)
            address(executor), // receiver
            USDC_ADDR, // tokenIn
            NATIVE_TOKEN_ADDRESS, // tokenOut
            ORACLE_CONFIG // config
        );

        uint256 gasBefore = gasleft();
        uint256 amountOut = executor.swap(amountIn, data);
        console.log(gasBefore - gasleft());

        console.log(amountOut);

        assertEq(USDC.balanceOf(CORE_ADDRESS), usdcBalanceBeforeCore + amountIn);
        assertEq(
            USDC.balanceOf(address(executor)),
            usdcBalanceBeforeExecutor - amountIn
        );

        assertEq(CORE_ADDRESS.balance, ethBalanceBeforeCore - amountOut);
        assertEq(
            address(executor).balance, ethBalanceBeforeExecutor + amountOut
        );
    }

    function testMevResist() public setUpFork(22722989) {
        uint256 amountIn = 1_000_000_000;

        deal(USDC_ADDR, address(executor), amountIn);

        uint256 usdcBalanceBeforeCore = USDC.balanceOf(CORE_ADDRESS);
        uint256 usdcBalanceBeforeExecutor = USDC.balanceOf(address(executor));

        uint256 ethBalanceBeforeCore = CORE_ADDRESS.balance;
        uint256 ethBalanceBeforeExecutor = address(executor).balance;

        bytes memory data = abi.encodePacked(
            uint8(RestrictTransferFrom.TransferType.Transfer), // transferNeeded (transfer from executor to core)
            address(executor), // receiver
            USDC_ADDR, // tokenIn
            NATIVE_TOKEN_ADDRESS, // tokenOut
            MEV_RESIST_POOL_CONFIG // config
        );

        uint256 gasBefore = gasleft();
        uint256 amountOut = executor.swap(amountIn, data);
        console.log(gasBefore - gasleft());

        console.log(amountOut);

        assertEq(USDC.balanceOf(CORE_ADDRESS), usdcBalanceBeforeCore + amountIn);
        assertEq(
            USDC.balanceOf(address(executor)),
            usdcBalanceBeforeExecutor - amountIn
        );

        assertEq(CORE_ADDRESS.balance, ethBalanceBeforeCore - amountOut);
        assertEq(
            address(executor).balance, ethBalanceBeforeExecutor + amountOut
        );
    }

    // Expects input that encodes the same test case as swap_encoder::tests::ekubo::test_encode_swap_multi
    function multiHopSwap(bytes memory data) internal {
        uint256 amountIn = 1 ether;

        deal(address(executor), amountIn);

        uint256 ethBalanceBeforeCore = CORE_ADDRESS.balance;
        uint256 ethBalanceBeforeExecutor = address(executor).balance;

        uint256 usdtBalanceBeforeCore = USDT.balanceOf(CORE_ADDRESS);
        uint256 usdtBalanceBeforeExecutor = USDT.balanceOf(address(executor));

        uint256 gasBefore = gasleft();
        uint256 amountOut = executor.swap(amountIn, data);
        console.log(gasBefore - gasleft());

        console.log(amountOut);

        assertEq(CORE_ADDRESS.balance, ethBalanceBeforeCore + amountIn);
        assertEq(address(executor).balance, ethBalanceBeforeExecutor - amountIn);

        assertEq(
            USDT.balanceOf(CORE_ADDRESS), usdtBalanceBeforeCore - amountOut
        );
        assertEq(
            USDT.balanceOf(address(executor)),
            usdtBalanceBeforeExecutor + amountOut
        );
    }

    // Same test case as in swap_encoder::tests::ekubo::test_encode_swap_multi
    function testMultiHopSwap() public setUpFork(22082754) {
        bytes memory data = abi.encodePacked(
            uint8(RestrictTransferFrom.TransferType.Transfer), // transferNeeded (transfer from executor to core)
            address(executor), // receiver
            NATIVE_TOKEN_ADDRESS, // tokenIn
            USDC_ADDR, // tokenOut of 1st swap
            ORACLE_CONFIG, // config of 1st swap
            USDT_ADDR, // tokenOut of 2nd swap
            bytes32(
                0x00000000000000000000000000000000000000000001a36e2eb1c43200000032
            ) // config of 2nd swap (0.0025% fee & 0.005% base pool)
        );
        multiHopSwap(data);
    }

    // Data is generated by test case in swap_encoder::tests::ekubo::test_encode_swap_multi
    function testMultiHopSwapIntegration() public setUpFork(22082754) {
        multiHopSwap(loadCallDataFromFile("test_ekubo_encode_swap_multi"));
    }
}

contract TychoRouterForBalancerV3Test is TychoRouterTestSetup {
    function testSingleEkuboIntegration() public {
        vm.stopPrank();

        deal(ALICE, 1 ether);
        uint256 balanceBefore = IERC20(USDC_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_ekubo");
        (bool success,) = tychoRouterAddr.call{value: 1 ether}(callData);

        uint256 balanceAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertGe(balanceAfter - balanceBefore, 26173932);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }
}
