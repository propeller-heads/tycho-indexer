// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "../TychoRouterTestSetup.sol";
import "@src/executors/BebopExecutor.sol";
import {Constants} from "../Constants.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {SafeERC20} from
    "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract BebopExecutorExposed is BebopExecutor {
    constructor(address _bebopSettlement, address _permit2)
        BebopExecutor(_bebopSettlement, _permit2)
    {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            address tokenIn,
            address tokenOut,
            TransferType transferType,
            uint8 partialFillOffset,
            uint256 originalFilledTakerAmount,
            bool approvalNeeded,
            address receiver,
            bytes memory bebopCalldata
        )
    {
        return _decodeData(data);
    }
}

contract BebopExecutorTest is Constants, Permit2TestHelper, TestUtils {
    using SafeERC20 for IERC20;

    BebopExecutorExposed bebopExecutor;

    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 USDC = IERC20(USDC_ADDR);
    IERC20 DAI = IERC20(DAI_ADDR);
    IERC20 WBTC = IERC20(WBTC_ADDR);
    IERC20 ONDO = IERC20(ONDO_ADDR);
    IERC20 USDT = IERC20(USDT_ADDR);

    function setUp() public {
        // Fork will be created in individual tests to allow different fork blocks
    }

    function testDecodeData() public {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);
        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        bytes memory bebopCalldata = abi.encodePacked(
            bytes4(0x4dcebcba), // swapSingle selector
            hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000068470140"
        );

        uint256 originalAmountIn = 200000000; // 200 USDC
        bytes memory params = abi.encodePacked(
            USDC_ADDR,
            ONDO_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(2),
            originalAmountIn,
            true,
            address(123),
            bebopCalldata
        );

        (
            address tokenIn,
            address tokenOut,
            RestrictTransferFrom.TransferType transferType,
            uint8 decodedPartialFillOffset,
            uint256 decodedOriginalAmountIn,
            bool decodedApprovalNeeded,
            address decodedReceiver,
            bytes memory decodedBebopCalldata
        ) = bebopExecutor.decodeData(params);

        assertEq(tokenIn, USDC_ADDR, "tokenIn mismatch");
        assertEq(tokenOut, ONDO_ADDR, "tokenOut mismatch");
        assertEq(
            uint8(transferType),
            uint8(RestrictTransferFrom.TransferType.Transfer),
            "transferType mismatch"
        );
        assertEq(
            keccak256(decodedBebopCalldata),
            keccak256(bebopCalldata),
            "bebopCalldata mismatch"
        );
        assertEq(decodedPartialFillOffset, 2, "partialFillOffset mismatch");
        assertEq(
            decodedOriginalAmountIn,
            originalAmountIn,
            "originalAmountIn mismatch"
        );
        assertTrue(decodedApprovalNeeded, "approvalNeeded should be true");
        assertEq(decodedReceiver, address(123), "receiver mismatch");
    }

    // Single Order Tests
    function testSingleOrder() public {
        // 1 WETH -> WBTC
        vm.createSelectFork(vm.rpcUrl("mainnet"), 23124275);

        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Quote made manually using the BebopExecutor as the taker and receiver
        bytes memory bebopCalldata =
            hex"4dcebcba00000000000000000000000000000000000000000000000000000000689b137a0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f000000000000000000000000bee3211ab312a8d065c4fef0247448e17a8da000000000000000000000000000000000000000000000000000279ead5d9683d8a5000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c5990000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000037337c0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f0000000000000000000000000000000000000000000000000000000000000000f71248bc6c123bbf12adc837470f75640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000418e9b0fb72ed9b86f7a7345026269c02b9056efcdfb67a377c7ff6c4a62a4807a7671ae759edf29aea1b2cb8efc8659e3aedac72943cd3607985a1849256358641c00000000000000000000000000000000000000000000000000000000000000";
        address tokenIn = WETH_ADDR;
        address tokenOut = WBTC_ADDR;
        RestrictTransferFrom.TransferType transferType =
            RestrictTransferFrom.TransferType.None;
        uint8 partialFillOffset = 12;
        uint256 amountIn = 1000000000000000000;
        bool approvalNeeded = true;
        uint256 expectedAmountOut = 3617660;

        deal(tokenIn, address(bebopExecutor), amountIn);

        bytes memory params = abi.encodePacked(
            tokenIn,
            tokenOut,
            transferType,
            partialFillOffset,
            amountIn,
            approvalNeeded,
            address(bebopExecutor),
            bebopCalldata
        );

        uint256 initialTokenOutBalance =
            IERC20(tokenOut).balanceOf(address(bebopExecutor));

        uint256 amountOut = bebopExecutor.swap(amountIn, params);

        assertEq(amountOut, expectedAmountOut, "Incorrect amount out");
        assertEq(
            IERC20(tokenOut).balanceOf(address(bebopExecutor))
                - initialTokenOutBalance,
            expectedAmountOut,
            "WBTC should be at receiver"
        );
        assertEq(
            IERC20(tokenIn).balanceOf(address(bebopExecutor)),
            0,
            "WETH left in executor"
        );
    }

    function testSingleOrderSellingETH() public {
        // 1 WETH -> WBTC
        vm.createSelectFork(vm.rpcUrl("mainnet"), 23124275);

        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Quote made manually using the BebopExecutor as the taker and receiver
        bytes memory bebopCalldata =
            hex"4dcebcba00000000000000000000000000000000000000000000000000000000689ca0cd0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f00000000000000000000000051c72848c68a965f66fa7a88855f9f7784502a7f0000000000000000000000000000000000000000000000002a65384e77863d8e000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c5990000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000003a96a10000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f0000000000000000000000000000000000000000000000000000000000000001c6d9e514c7a64e5c0e239b532e1a3ea00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000041905d474b362c4a7c901c6a4ccb5c30670a0c602456f52761b47a0a35fc3944ec1fa224bc3bc6e8925cb15258efad2cf79e22ce9720f2302d4a1a2811c54fb4341c00000000000000000000000000000000000000000000000000000000000000";
        address tokenIn = address(0);
        address tokenOut = WBTC_ADDR;
        RestrictTransferFrom.TransferType transferType =
            RestrictTransferFrom.TransferType.None;
        uint8 partialFillOffset = 12;
        uint256 amountIn = 1000000000000000000;
        bool approvalNeeded = false;
        uint256 expectedAmountOut = 3839649;

        vm.deal(address(bebopExecutor), amountIn);

        bytes memory params = abi.encodePacked(
            tokenIn,
            tokenOut,
            transferType,
            partialFillOffset,
            amountIn,
            approvalNeeded,
            address(bebopExecutor),
            bebopCalldata
        );

        uint256 initialTokenOutBalance =
            IERC20(tokenOut).balanceOf(address(bebopExecutor));

        uint256 amountOut = bebopExecutor.swap(amountIn, params);

        assertEq(amountOut, expectedAmountOut, "Incorrect amount out");
        assertEq(
            IERC20(tokenOut).balanceOf(address(bebopExecutor))
                - initialTokenOutBalance,
            expectedAmountOut,
            "WBTC should be at receiver"
        );
        assertEq(address(bebopExecutor).balance, 0, "ETH left in executor");
    }

    function testSingleOrder_PartialFill() public {
        // 0.5 WETH -> WBTC with a quote for 1 WETH
        vm.createSelectFork(vm.rpcUrl("mainnet"), 23124275);

        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Quote made manually using the BebopExecutor as the taker and receiver (the same as testSingleOrder)
        bytes memory bebopCalldata =
            hex"4dcebcba00000000000000000000000000000000000000000000000000000000689b137a0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f000000000000000000000000bee3211ab312a8d065c4fef0247448e17a8da000000000000000000000000000000000000000000000000000279ead5d9683d8a5000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c5990000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000037337c0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f0000000000000000000000000000000000000000000000000000000000000000f71248bc6c123bbf12adc837470f75640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000418e9b0fb72ed9b86f7a7345026269c02b9056efcdfb67a377c7ff6c4a62a4807a7671ae759edf29aea1b2cb8efc8659e3aedac72943cd3607985a1849256358641c00000000000000000000000000000000000000000000000000000000000000";
        address tokenIn = WETH_ADDR;
        address tokenOut = WBTC_ADDR;
        RestrictTransferFrom.TransferType transferType =
            RestrictTransferFrom.TransferType.None;
        uint8 partialFillOffset = 12;
        // filling only half of the quote
        uint256 amountIn = 1000000000000000000 / 2;
        bool approvalNeeded = true;
        uint256 expectedAmountOut = 3617660 / 2;

        deal(tokenIn, address(bebopExecutor), amountIn);

        bytes memory params = abi.encodePacked(
            tokenIn,
            tokenOut,
            transferType,
            partialFillOffset,
            amountIn * 2, // this is the original amount in
            approvalNeeded,
            address(bebopExecutor),
            bebopCalldata
        );

        uint256 initialTokenOutBalance =
            IERC20(tokenOut).balanceOf(address(bebopExecutor));

        uint256 amountOut = bebopExecutor.swap(amountIn, params);

        assertEq(amountOut, expectedAmountOut, "Incorrect partial amount out");
        assertEq(
            IERC20(tokenOut).balanceOf(address(bebopExecutor))
                - initialTokenOutBalance,
            expectedAmountOut,
            "WETH should be at receiver"
        );
        assertEq(
            IERC20(tokenIn).balanceOf(address(bebopExecutor)),
            0,
            "WBTC left in executor"
        );
    }

    // Aggregate Order Tests
    function testAggregateOrder() public {
        // 20k USDC -> ONDO
        vm.createSelectFork(vm.rpcUrl("mainnet"), 23126278);
        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Quote made manually using the BebopExecutor as the taker and receiver
        bytes memory bebopCalldata =
            hex"a2f7489300000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000689b715d0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000003e000000000000000000000000000000000000000000000000000000000000004c00000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f00000000000000000000000000000000000000000000000000000000000005a0e0c07568b14a2d2c1b4d196000fc12bc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000051c72848c68a965f66fa7a88855f9f7784502a7f000000000000000000000000ce79b081c0c924cb67848723ed3057234d10fc6b00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000002a65384e777abcfe0000000000000000000000000000000000000000000000002a65384e777abcff0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000faba6f8e4a5e8ab82f62fe7c39859fa577269be30000000000000000000000000000000000000000000000000000000000000001000000000000000000000000faba6f8e4a5e8ab82f62fe7c39859fa577269be300000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000236ddb7a7000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000002713a105900000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000001e7dc63f0c1d9d93df4000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000021960567af238bcfd0000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000041275c4b7c3df4bfa5c33da3443d817cc6ab568ec8b0fddc30445adff2e870cdcd7d8738e23b795c2fb1ee112e12716bcef1cf648bd1ded17ef10ae493d687322e1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004187ef3d632a640b09df5f39b2fb4c5b9afb7ab4f2782fee450b17e2363d27303b45ec55b154a63993106bfc28bb4accc10fb40f7927509fed554fac01a5d88bae1c00000000000000000000000000000000000000000000000000000000000000";
        address tokenIn = USDC_ADDR;
        address tokenOut = ONDO_ADDR;
        RestrictTransferFrom.TransferType transferType =
            RestrictTransferFrom.TransferType.None;
        uint8 partialFillOffset = 2;
        // filling only half of the quote
        uint256 amountIn = 20000000000;
        bool approvalNeeded = true;
        // maker amounts from quote
        uint256 expectedAmountOut =
            (8999445165322964385268 + 9912843438638420000000);

        deal(tokenIn, address(bebopExecutor), amountIn);

        bytes memory params = abi.encodePacked(
            tokenIn,
            tokenOut,
            transferType,
            partialFillOffset,
            amountIn,
            approvalNeeded,
            address(bebopExecutor),
            bebopCalldata
        );

        uint256 initialTokenOutBalance =
            IERC20(tokenOut).balanceOf(address(bebopExecutor));

        uint256 amountOut = bebopExecutor.swap(amountIn, params);

        assertEq(amountOut, expectedAmountOut, "Incorrect amount out");

        assertEq(
            IERC20(tokenOut).balanceOf(address(bebopExecutor))
                - initialTokenOutBalance,
            expectedAmountOut,
            "ONDO should be at receiver"
        );
        assertEq(
            IERC20(tokenIn).balanceOf(address(bebopExecutor)),
            0,
            "USDC left in executor"
        );
    }

    function testAggregateOrder_PartialFill() public {
        // 10k USDC -> ONDO with a quote for 20k USDC
        vm.createSelectFork(vm.rpcUrl("mainnet"), 23126278);
        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Quote made manually using the BebopExecutor as the taker and receiver
        bytes memory bebopCalldata =
            hex"a2f7489300000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000689b715d0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000003e000000000000000000000000000000000000000000000000000000000000004c00000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f00000000000000000000000000000000000000000000000000000000000005a0e0c07568b14a2d2c1b4d196000fc12bc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000051c72848c68a965f66fa7a88855f9f7784502a7f000000000000000000000000ce79b081c0c924cb67848723ed3057234d10fc6b00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000002a65384e777abcfe0000000000000000000000000000000000000000000000002a65384e777abcff0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000faba6f8e4a5e8ab82f62fe7c39859fa577269be30000000000000000000000000000000000000000000000000000000000000001000000000000000000000000faba6f8e4a5e8ab82f62fe7c39859fa577269be300000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000236ddb7a7000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000002713a105900000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000001e7dc63f0c1d9d93df4000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000021960567af238bcfd0000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000041275c4b7c3df4bfa5c33da3443d817cc6ab568ec8b0fddc30445adff2e870cdcd7d8738e23b795c2fb1ee112e12716bcef1cf648bd1ded17ef10ae493d687322e1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004187ef3d632a640b09df5f39b2fb4c5b9afb7ab4f2782fee450b17e2363d27303b45ec55b154a63993106bfc28bb4accc10fb40f7927509fed554fac01a5d88bae1c00000000000000000000000000000000000000000000000000000000000000";
        address tokenIn = USDC_ADDR;
        address tokenOut = ONDO_ADDR;
        RestrictTransferFrom.TransferType transferType =
            RestrictTransferFrom.TransferType.None;
        uint8 partialFillOffset = 2;
        // filling only half of the quote
        uint256 amountIn = 20000000000 / 2;
        bool approvalNeeded = true;
        // maker amounts from quote
        uint256 expectedAmountOut =
            (8999445165322964385268 + 9912843438638420000000) / 2;

        deal(tokenIn, address(bebopExecutor), amountIn);

        bytes memory params = abi.encodePacked(
            tokenIn,
            tokenOut,
            transferType,
            partialFillOffset,
            amountIn * 2, // this is the original amount from the quote
            approvalNeeded,
            address(bebopExecutor),
            bebopCalldata
        );

        uint256 initialTokenOutBalance =
            IERC20(tokenOut).balanceOf(address(bebopExecutor));

        uint256 amountOut = bebopExecutor.swap(amountIn, params);

        assertEq(amountOut, expectedAmountOut, "Incorrect amount out");

        assertEq(
            IERC20(tokenOut).balanceOf(address(bebopExecutor))
                - initialTokenOutBalance,
            expectedAmountOut,
            "ONDO should be at receiver"
        );
        assertEq(
            IERC20(tokenIn).balanceOf(address(bebopExecutor)),
            1, // because of integer division, there is 1 USDC left in the executor
            "USDC left in executor"
        );
    }

    function testInvalidDataLength() public {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);
        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Create a mock bebop calldata
        bytes memory bebopCalldata = hex"47fb5891" // swapSingle selector
            hex"1234567890abcdef"; // some mock data

        // Create params with correct length first
        uint256 originalAmountIn = 1e18;
        bytes memory validParams = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(2),
            originalAmountIn,
            true,
            address(bebopExecutor),
            bebopCalldata
        );

        // Verify valid params work
        bebopExecutor.decodeData(validParams);

        // In the new format, adding extra bytes at the end doesn't fail
        // because bebopCalldata is variable length at the end
        // So test with extra bytes should not revert
        bytes memory paramsWithExtra = abi.encodePacked(validParams, hex"ff");
        // This should work as the extra byte becomes part of bebopCalldata
        bebopExecutor.decodeData(paramsWithExtra);

        // Try with insufficient data, should fail
        bytes memory tooShortParams = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
        // Missing rest of the data

        vm.expectRevert(BebopExecutor.BebopExecutor__InvalidDataLength.selector);
        bebopExecutor.decodeData(tooShortParams);
    }
}

contract TychoRouterForBebopTest is TychoRouterTestSetup {
    // Override the fork block for Bebop tests
    function getForkBlock() public pure override returns (uint256) {
        return 22667986;
    }

    function testSingleBebopIntegration() public {
        // The calldata swaps 200 USDC for ONDO
        address user = 0xd2068e04Cf586f76EEcE7BA5bEB779D7bB1474A1;
        deal(USDC_ADDR, user, 200000000); // 200 USDC
        uint256 expAmountOut = 194477331556159832309; // Expected ONDO amount from quote

        uint256 ondoBefore = IERC20(ONDO_ADDR).balanceOf(user);
        vm.startPrank(user);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, type(uint256).max);

        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_bebop");

        (bool success,) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");

        uint256 ondoReceived = IERC20(ONDO_ADDR).balanceOf(user) - ondoBefore;
        assertEq(ondoReceived, expAmountOut);
        assertEq(
            IERC20(USDC_ADDR).balanceOf(tychoRouterAddr),
            0,
            "USDC left in router"
        );

        vm.stopPrank();
    }

    function testBebopAggregateIntegration() public {
        // The calldata swaps 20k USDC for ONDO using multiple market makers
        address user = 0xd2068e04Cf586f76EEcE7BA5bEB779D7bB1474A1;
        deal(USDC_ADDR, user, 20000000000); // 20k USDC
        uint256 expAmountOut = 18699321819466078474202; // Expected ONDO amount from quote

        uint256 ondoBefore = IERC20(ONDO_ADDR).balanceOf(user);
        vm.startPrank(user);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, type(uint256).max);

        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_bebop_aggregate"
        );

        (bool success,) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");

        uint256 ondoReceived = IERC20(ONDO_ADDR).balanceOf(user) - ondoBefore;
        assertEq(ondoReceived, expAmountOut);
        assertEq(
            IERC20(USDC_ADDR).balanceOf(tychoRouterAddr),
            0,
            "USDC left in router"
        );

        vm.stopPrank();
    }
}
