// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TychoRouterTestSetup.sol";
import {CommonBase} from "../../lib/forge-std/src/Base.sol";
import {Constants} from "../Constants.sol";
import {RestrictTransferFrom} from "../../src/RestrictTransferFrom.sol";
import {
    RocketpoolExecutor,
    RocketpoolExecutor__InvalidDataLength,
    IRocketTokenRETH
} from "../../src/executors/RocketpoolExecutor.sol";
import {StdAssertions} from "../../lib/forge-std/src/StdAssertions.sol";
import {StdChains} from "../../lib/forge-std/src/StdChains.sol";
import {StdCheats, StdCheatsSafe} from "../../lib/forge-std/src/StdCheats.sol";
import {StdUtils} from "../../lib/forge-std/src/StdUtils.sol";
import {TestUtils} from "../TestUtils.sol";

contract RocketpoolExecutorExposed is RocketpoolExecutor {
    constructor(address _permit2) RocketpoolExecutor(_permit2) {}

    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            bool isDeposit,
            RestrictTransferFrom.TransferType transferType,
            address receiver
        )
    {
        return _decodeData(data);
    }
}

contract RocketpoolExecutorTest is TestUtils, Constants {
    RocketpoolExecutorExposed rocketpoolExecutor;

    modifier setUpFork(uint256 blockNumber) {
        vm.createSelectFork(vm.rpcUrl("mainnet"), blockNumber);
        rocketpoolExecutor = new RocketpoolExecutorExposed(PERMIT2_ADDRESS);
        _;
    }

    function setUp() public setUpFork(23899254) {}

    function testDecodeParams() public view {
        bytes memory params = abi.encodePacked(
            uint8(1), // isDeposit = true
            RestrictTransferFrom.TransferType.Transfer,
            BOB
        );

        (
            bool isDeposit,
            RestrictTransferFrom.TransferType transferType,
            address receiver
        ) = rocketpoolExecutor.decodeParams(params);

        assertTrue(isDeposit);
        assertEq(
            uint8(transferType),
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
        assertEq(receiver, BOB);
    }

    function testDecodeParamsBurn() public view {
        bytes memory params = abi.encodePacked(
            uint8(0), // isDeposit = false (burn)
            RestrictTransferFrom.TransferType.Transfer,
            ALICE
        );

        (
            bool isDeposit,
            RestrictTransferFrom.TransferType transferType,
            address receiver
        ) = rocketpoolExecutor.decodeParams(params);

        assertFalse(isDeposit);
        assertEq(
            uint8(transferType),
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
        assertEq(receiver, ALICE);
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams = abi.encodePacked(uint8(1), BOB);

        vm.expectRevert(RocketpoolExecutor__InvalidDataLength.selector);
        rocketpoolExecutor.decodeParams(invalidParams);
    }

    /// Test against real transaction deposit on Rocketpool
    /// 0x6213b6c235c52d2132711c18a1c66934832722fd71c098e843bc792ecdbd11b3 where user deposited
    /// exactly 4.5 ETH and received 3.905847020555141679 rETH
    function testSwapDeposit() public setUpFork(23899254) {
        // ETH -> rETH
        IRocketTokenRETH RETH = IRocketTokenRETH(RETH_ADDR);
        uint256 amountIn = 4.5 ether;
        bytes memory protocolData = abi.encodePacked(
            uint8(1), // isDeposit = true
            RestrictTransferFrom.TransferType.Transfer,
            BOB
        );

        // Fund the executor with ETH
        vm.deal(address(rocketpoolExecutor), amountIn);

        uint256 rethBalanceBefore = RETH.balanceOf(BOB);
        uint256 amountOut = rocketpoolExecutor.swap(amountIn, protocolData);
        uint256 rethBalanceAfter = RETH.balanceOf(BOB);

        // Check balances
        assertEq(rethBalanceAfter - rethBalanceBefore, amountOut);
        assertEq(amountOut, 3_905_847_020_555_141_679);
    }

    /// Test against real transaction burn on Rocketpool
    /// 0xf461ace5ae15d1db7a9f83da2e5a62745e91ecd1908274fb6583f70a29d8f68d where user burned
    /// exactly 1 rETH and received 1.151971256664605227 ETH
    function testSwapBurn() public setUpFork(23939127) {
        // rETH -> ETH
        uint256 amountIn = 1 ether;
        bytes memory protocolData = abi.encodePacked(
            uint8(0), // isDeposit = false (burn)
            RestrictTransferFrom.TransferType.Transfer,
            BOB
        );

        // Fund the executor with rETH
        deal(RETH_ADDR, address(rocketpoolExecutor), amountIn);

        uint256 ethBalanceBefore = BOB.balance;
        uint256 amountOut = rocketpoolExecutor.swap(amountIn, protocolData);
        uint256 ethBalanceAfter = BOB.balance;

        // Check balances
        assertEq(ethBalanceAfter - ethBalanceBefore, amountOut);
        assertEq(amountOut, 1_151_971_256_664_605_227);
    }

    function testDecodeIntegration() public view {
        // Generated by the SwapEncoder - test_encode_rocketpool
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_rocketpool");

        (
            bool isDeposit,
            RestrictTransferFrom.TransferType transferType,
            address receiver
        ) = rocketpoolExecutor.decodeParams(protocolData);

        assertTrue(isDeposit);
        assertEq(
            uint8(transferType),
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
        assertEq(receiver, BOB);
    }

    /// Test against real transaction deposit on Rocketpool
    /// 0x6213b6c235c52d2132711c18a1c66934832722fd71c098e843bc792ecdbd11b3 where user deposited
    /// exactly 4.5 ETH and received 3.905847020555141679 rETH
    function testSwapDepositIntegration() public setUpFork(23899254) {
        // Generated by the SwapEncoder - test_encode_rocketpool
        IRocketTokenRETH RETH = IRocketTokenRETH(RETH_ADDR);
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_rocketpool");

        uint256 amountIn = 4.5 ether;

        // Fund the executor with ETH
        vm.deal(address(rocketpoolExecutor), amountIn);

        uint256 rethBalanceBefore = RETH.balanceOf(BOB);
        uint256 amountOut = rocketpoolExecutor.swap(amountIn, protocolData);
        uint256 rethBalanceAfter = RETH.balanceOf(BOB);

        // Check balances
        assertEq(rethBalanceAfter - rethBalanceBefore, amountOut);
        assertEq(amountOut, 3_905_847_020_555_141_679);
    }

    function testExportContract() public {
        exportRuntimeBytecode(address(rocketpoolExecutor), "Rocketpool");
    }
}

contract TychoRouterForRocketpoolTest is TychoRouterTestSetup {
    function getForkBlock() public pure override returns (uint256) {
        return 23899254;
    }

    function testSingleSwap() public {
        IRocketTokenRETH RETH = IRocketTokenRETH(RETH_ADDR);

        uint256 amountIn = 4.5e18;
        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_rocketpool");

        // Fund ALICE with ETH to send with the call
        vm.deal(ALICE, amountIn);

        vm.startPrank(ALICE);

        uint256 rethBalanceBefore = RETH.balanceOf(ALICE);
        (bool success,) = tychoRouterAddr.call{value: amountIn}(callData);
        uint256 rethBalanceAfter = RETH.balanceOf(ALICE);

        // Check balances
        assertTrue(success, "Call Failed");
        assertEq(
            rethBalanceAfter - rethBalanceBefore, 3_905_847_020_555_141_679
        );
        assertEq(RETH.balanceOf(tychoRouterAddr), 0);
        assertEq(tychoRouterAddr.balance, 0);
    }

    function testExportContract() public {
        exportRuntimeBytecode(address(rocketpoolExecutor), "Rocketpool");
    }
}
