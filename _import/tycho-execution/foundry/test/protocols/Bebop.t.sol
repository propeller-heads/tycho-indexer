// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "../TychoRouterTestSetup.sol";
import "./BebopExecutionHarness.t.sol";
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
        // Fork to ensure consistent setup
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);

        // Deploy Bebop executor harness
        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Create a simple bebop calldata
        bytes memory bebopCalldata = abi.encodePacked(
            bytes4(0x4dcebcba), // swapSingle selector
            hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000068470140"
        );

        uint256 originalAmountIn = 200000000; // 200 USDC

        // Create the executor params
        bytes memory params = abi.encodePacked(
            USDC_ADDR,
            ONDO_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(2), // partialFillOffset for swapSingle (68 = 4 + 2*32)
            originalAmountIn,
            true,
            address(123),
            bebopCalldata
        );

        // Test decoding
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
            "WETH should be at receiver"
        );
        assertEq(
            IERC20(tokenIn).balanceOf(address(bebopExecutor)),
            0,
            "WBTC left in executor"
        );
    }

    function testSingleOrder_PartialFill() public {
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

        // filling only half of the order
        uint256 amountOut = bebopExecutor.swap(amountIn / 2, params);

        assertEq(
            amountOut, expectedAmountOut / 2, "Incorrect partial amount out"
        );
        assertEq(
            IERC20(tokenOut).balanceOf(address(bebopExecutor))
                - initialTokenOutBalance,
            expectedAmountOut / 2,
            "WETH should be at receiver"
        );
        // half of the amount in should remain in the executor
        assertEq(
            IERC20(tokenIn).balanceOf(address(bebopExecutor)),
            amountIn / 2,
            "Wrong amount of WBTC left in executor"
        );
    }

    // Aggregate Order Tests
    //    function testAggregateOrder() public {
    //        // Fork at the block just before the actual transaction
    //        vm.createSelectFork(vm.rpcUrl("mainnet"), 22410851);
    //
    //        // Deploy Bebop executor harness that uses vm.prank
    //        bebopExecutor =
    //            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);
    //
    //        // Store the initial ETH balance (dust from forked state)
    //        uint256 initialExecutorBalance = address(bebopExecutor).balance;
    //
    //        // Create test data from real mainnet transaction
    //        // https://etherscan.io/tx/0xec88410136c287280da87d0a37c1cb745f320406ca3ae55c678dec11996c1b1c
    //        address originalTakerAddress =
    //            0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6;
    //
    //        // Create the 2D arrays for tokens and amounts
    //        address[][] memory takerTokens = new address[][](2);
    //        takerTokens[0] = new address[](1);
    //        takerTokens[0][0] = WETH_ADDR; // WETH for first maker
    //        takerTokens[1] = new address[](1);
    //        takerTokens[1][0] = WETH_ADDR; // WETH for second maker
    //
    //        address[][] memory makerTokens = new address[][](2);
    //        makerTokens[0] = new address[](1);
    //        makerTokens[0][0] = USDC_ADDR; // USDC from first maker
    //        makerTokens[1] = new address[](1);
    //        makerTokens[1][0] = USDC_ADDR; // USDC from second maker
    //
    //        uint256[][] memory takerAmounts = new uint256[][](2);
    //        takerAmounts[0] = new uint256[](1);
    //        takerAmounts[0][0] = 5812106401997138; // First maker takes ~0.0058 ETH
    //        takerAmounts[1] = new uint256[](1);
    //        takerAmounts[1][0] = 4037893598002862; // Second maker takes ~0.0040 ETH
    //
    //        uint256[][] memory makerAmounts = new uint256[][](2);
    //        makerAmounts[0] = new uint256[](1);
    //        makerAmounts[0][0] = 10607211; // First maker gives ~10.6 USDC
    //        makerAmounts[1] = new uint256[](1);
    //        makerAmounts[1][0] = 7362350; // Second maker gives ~7.36 USDC
    //
    //        // Create makers array
    //        address[] memory makerAddresses = new address[](2);
    //        makerAddresses[0] = 0x67336Cec42645F55059EfF241Cb02eA5cC52fF86;
    //        makerAddresses[1] = 0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE;
    //
    //        // Create maker nonces array
    //        uint256[] memory makerNonces = new uint256[](2);
    //        makerNonces[0] = 1746367197308;
    //        makerNonces[1] = 15460096;
    //
    //        // Create the aggregate order
    //        IBebopSettlement.Aggregate memory order = IBebopSettlement.Aggregate({
    //            expiry: 1746367285, // Original expiry that matches the signatures
    //            taker_address: originalTakerAddress,
    //            maker_addresses: makerAddresses,
    //            maker_nonces: makerNonces,
    //            taker_tokens: takerTokens,
    //            maker_tokens: makerTokens,
    //            taker_amounts: takerAmounts,
    //            maker_amounts: makerAmounts,
    //            receiver: originalTakerAddress,
    //            commands: hex"00040004",
    //            flags: 95769172144825922628485191511070792431742484643425438763224908097896054784000
    //        });
    //
    //        // Total amounts
    //        uint256 totalTakerAmount = takerAmounts[0][0] + takerAmounts[1][0]; // 0.00985 ETH total
    //        uint256 totalMakerAmount = makerAmounts[0][0] + makerAmounts[1][0]; // 17.969561 USDC total
    //
    //        // Fund makers with USDC and approve settlement
    //        deal(USDC_ADDR, makerAddresses[0], makerAmounts[0][0]);
    //        deal(USDC_ADDR, makerAddresses[1], makerAmounts[1][0]);
    //
    //        vm.prank(makerAddresses[0]);
    //        USDC.approve(BEBOP_SETTLEMENT, makerAmounts[0][0]);
    //
    //        vm.prank(makerAddresses[1]);
    //        USDC.approve(BEBOP_SETTLEMENT, makerAmounts[1][0]);
    //
    //        // For native ETH, settlement pulls from taker; fund taker with ETH
    //        vm.deal(originalTakerAddress, totalTakerAmount + 1 ether);
    //
    //        // Create maker signatures
    //        IBebopSettlement.MakerSignature[] memory signatures =
    //            new IBebopSettlement.MakerSignature[](2);
    //        signatures[0] = IBebopSettlement.MakerSignature({
    //            signatureBytes: hex"d5abb425f9bac1f44d48705f41a8ab9cae207517be8553d2c03b06a88995f2f351ab8ce7627a87048178d539dd64fd2380245531a0c8e43fdc614652b1f32fc71c",
    //            flags: 0 // ETH_SIGN
    //        });
    //        signatures[1] = IBebopSettlement.MakerSignature({
    //            signatureBytes: hex"f38c698e48a3eac48f184bc324fef0b135ee13705ab38cc0bbf5a792f21002f051e445b9e7d57cf24c35e17629ea35b3263591c4abf8ca87ffa44b41301b89c41b",
    //            flags: 0 // ETH_SIGN
    //        });
    //
    //        // Build the bebop calldata for swapAggregate
    //        // Manually encode with correct selector since abi.encodeCall generates wrong selector
    //        bytes memory bebopCalldata = abi.encodePacked(
    //            bytes4(0xa2f74893), // swapAggregate selector
    //            abi.encode(order, signatures, totalTakerAmount) // Use totalTakerAmount when filledTakerAmount would be 0
    //        );
    //
    //        // Create packed params for executor with native ETH as input
    //        bytes memory params = abi.encodePacked(
    //            address(0), // tokenIn: native ETH
    //            USDC_ADDR, // tokenOut
    //            uint8(RestrictTransferFrom.TransferType.Transfer),
    //            uint8(2), // partialFillOffset for swapAggregate (68 = 4 + 2*32)
    //            totalTakerAmount, // originalAmountIn
    //            uint8(0), // approvalNeeded: false for native ETH
    //            originalTakerAddress, // receiver from order
    //            bebopCalldata
    //        );
    //
    //        // Check initial USDC balance of receiver
    //        uint256 initialUsdcBalance = USDC.balanceOf(originalTakerAddress);
    //
    //        // Execute the aggregate swap with ETH value
    //        uint256 amountOut = bebopExecutor.swap{value: totalTakerAmount}(
    //            totalTakerAmount, params
    //        );
    //
    //        // Verify results
    //        assertEq(amountOut, totalMakerAmount, "Incorrect amount out");
    //        // Since we're using real order data, tokens go to the original receiver
    //        assertEq(
    //            USDC.balanceOf(originalTakerAddress) - initialUsdcBalance,
    //            totalMakerAmount,
    //            "USDC should be at receiver"
    //        );
    //        // With pranking, settlement pulls ETH from taker; executor keeps msg.value on top of initial dust
    //        assertEq(
    //            address(bebopExecutor).balance,
    //            initialExecutorBalance + totalTakerAmount,
    //            "Executor ETH balance should be initial + msg.value for aggregate ETH flow"
    //        );
    //    }
    //
    //    function testAggregateOrder_PartialFill() public {
    //        // Fork at the block just before the actual transaction
    //        vm.createSelectFork(vm.rpcUrl("mainnet"), 22410851);
    //
    //        // Deploy Bebop executor harness that uses vm.prank
    //        bebopExecutor =
    //            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);
    //
    //        // Store the initial ETH balance (dust from forked state)
    //        uint256 initialExecutorBalance = address(bebopExecutor).balance;
    //
    //        // Same aggregate order as before, but with partial fill
    //        address originalTakerAddress =
    //            0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6;
    //
    //        // Create the 2D arrays for tokens and amounts
    //        address[][] memory takerTokens = new address[][](2);
    //        takerTokens[0] = new address[](1);
    //        takerTokens[0][0] = WETH_ADDR;
    //        takerTokens[1] = new address[](1);
    //        takerTokens[1][0] = WETH_ADDR;
    //
    //        address[][] memory makerTokens = new address[][](2);
    //        makerTokens[0] = new address[](1);
    //        makerTokens[0][0] = USDC_ADDR;
    //        makerTokens[1] = new address[](1);
    //        makerTokens[1][0] = USDC_ADDR;
    //
    //        uint256[][] memory takerAmounts = new uint256[][](2);
    //        takerAmounts[0] = new uint256[](1);
    //        takerAmounts[0][0] = 5812106401997138;
    //        takerAmounts[1] = new uint256[](1);
    //        takerAmounts[1][0] = 4037893598002862;
    //
    //        uint256[][] memory makerAmounts = new uint256[][](2);
    //        makerAmounts[0] = new uint256[](1);
    //        makerAmounts[0][0] = 10607211;
    //        makerAmounts[1] = new uint256[](1);
    //        makerAmounts[1][0] = 7362350;
    //
    //        // Create makers array
    //        address[] memory makerAddresses = new address[](2);
    //        makerAddresses[0] = 0x67336Cec42645F55059EfF241Cb02eA5cC52fF86;
    //        makerAddresses[1] = 0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE;
    //
    //        // Create maker nonces array
    //        uint256[] memory makerNonces = new uint256[](2);
    //        makerNonces[0] = 1746367197308;
    //        makerNonces[1] = 15460096;
    //
    //        // Create the aggregate order
    //        IBebopSettlement.Aggregate memory order = IBebopSettlement.Aggregate({
    //            expiry: 1746367285, // Original expiry that matches the signatures
    //            taker_address: originalTakerAddress,
    //            maker_addresses: makerAddresses,
    //            maker_nonces: makerNonces,
    //            taker_tokens: takerTokens,
    //            maker_tokens: makerTokens,
    //            taker_amounts: takerAmounts,
    //            maker_amounts: makerAmounts,
    //            receiver: originalTakerAddress,
    //            commands: hex"00040004",
    //            flags: 95769172144825922628485191511070792431742484643425438763224908097896054784000
    //        });
    //
    //        // Total amounts
    //        uint256 totalTakerAmount = takerAmounts[0][0] + takerAmounts[1][0];
    //        uint256 totalMakerAmount = makerAmounts[0][0] + makerAmounts[1][0];
    //
    //        // We'll do a 50% partial fill
    //        uint256 partialFillAmount = totalTakerAmount / 2;
    //        uint256 expectedPartialOutput = totalMakerAmount / 2;
    //
    //        // Fund makers with FULL amounts (they need enough for any partial fill)
    //        deal(USDC_ADDR, makerAddresses[0], makerAmounts[0][0]);
    //        deal(USDC_ADDR, makerAddresses[1], makerAmounts[1][0]);
    //
    //        vm.prank(makerAddresses[0]);
    //        USDC.approve(BEBOP_SETTLEMENT, makerAmounts[0][0]);
    //
    //        vm.prank(makerAddresses[1]);
    //        USDC.approve(BEBOP_SETTLEMENT, makerAmounts[1][0]);
    //
    //        // For native ETH, settlement pulls from taker; fund taker with ETH
    //        vm.deal(originalTakerAddress, partialFillAmount + 1 ether);
    //
    //        // Create maker signatures
    //        IBebopSettlement.MakerSignature[] memory signatures =
    //            new IBebopSettlement.MakerSignature[](2);
    //        signatures[0] = IBebopSettlement.MakerSignature({
    //            signatureBytes: hex"d5abb425f9bac1f44d48705f41a8ab9cae207517be8553d2c03b06a88995f2f351ab8ce7627a87048178d539dd64fd2380245531a0c8e43fdc614652b1f32fc71c",
    //            flags: 0
    //        });
    //        signatures[1] = IBebopSettlement.MakerSignature({
    //            signatureBytes: hex"f38c698e48a3eac48f184bc324fef0b135ee13705ab38cc0bbf5a792f21002f051e445b9e7d57cf24c35e17629ea35b3263591c4abf8ca87ffa44b41301b89c41b",
    //            flags: 0
    //        });
    //
    //        // Build the bebop calldata for swapAggregate with partial fill
    //        // Manually encode with correct selector since abi.encodeCall generates wrong selector
    //        bytes memory bebopCalldata = abi.encodePacked(
    //            bytes4(0xa2f74893), // swapAggregate selector
    //            abi.encode(order, signatures, partialFillAmount) // Specify partial fill amount
    //        );
    //
    //        // Create packed params for executor with partial fill amount
    //        bytes memory params = abi.encodePacked(
    //            address(0), // tokenIn: native ETH
    //            USDC_ADDR,
    //            uint8(RestrictTransferFrom.TransferType.Transfer),
    //            uint8(2), // partialFillOffset for swapAggregate (68 = 4 + 2*32)
    //            totalTakerAmount, // originalAmountIn (full order amount)
    //            uint8(0), // approvalNeeded: false for native ETH
    //            originalTakerAddress, // receiver from order
    //            bebopCalldata
    //        );
    //
    //        // Check initial USDC balance of receiver
    //        uint256 initialUsdcBalance = USDC.balanceOf(originalTakerAddress);
    //
    //        // Execute the partial aggregate swap with ETH value
    //        uint256 amountOut = bebopExecutor.swap{value: partialFillAmount}(
    //            partialFillAmount, params
    //        );
    //
    //        // Verify results - should be proportional to the partial fill
    //        assertEq(
    //            amountOut, expectedPartialOutput, "Incorrect partial amount out"
    //        );
    //        // Since we're using real order data, tokens go to the original receiver
    //        assertEq(
    //            USDC.balanceOf(originalTakerAddress) - initialUsdcBalance,
    //            expectedPartialOutput,
    //            "USDC should be at receiver"
    //        );
    //        // With pranking, settlement pulls ETH from taker; executor keeps msg.value on top of initial dust
    //        assertEq(
    //            address(bebopExecutor).balance,
    //            initialExecutorBalance + partialFillAmount,
    //            "Executor ETH balance should be initial + msg.value for aggregate ETH flow"
    //        );
    //    }

    function testInvalidDataLength() public {
        // Fork to ensure consistent setup
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);

        // Deploy Bebop executor with real settlement contract
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
            uint8(2), // partialFillOffset for swapSingle (68 = 4 + 2*32)
            originalAmountIn,
            uint8(1), // approvalNeeded: true
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

    //    function testBebopAggregateIntegration() public {
    //        // Test aggregate order integration
    //        address orderTaker = 0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6;
    //        uint256 ethAmount = 9850000000000000; // 0.00985 WETH
    //        uint256 expAmountOut = 17969561; // 17.969561 USDC expected output
    //
    //        // Fund makers with USDC
    //        address maker1 = 0x67336Cec42645F55059EfF241Cb02eA5cC52fF86;
    //        address maker2 = 0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE;
    //        deal(USDC_ADDR, maker1, 10607211);
    //        deal(USDC_ADDR, maker2, 7362350);
    //
    //        vm.prank(maker1);
    //        IERC20(USDC_ADDR).approve(BEBOP_SETTLEMENT, type(uint256).max);
    //        vm.prank(maker2);
    //        IERC20(USDC_ADDR).approve(BEBOP_SETTLEMENT, type(uint256).max);
    //
    //        // Fund taker with WETH
    //        deal(WETH_ADDR, orderTaker, ethAmount);
    //
    //        vm.startPrank(orderTaker);
    //        IERC20(WETH_ADDR).approve(tychoRouterAddr, ethAmount);
    //
    //        // Load calldata from file
    //        bytes memory callData = loadCallDataFromFile(
    //            "test_single_encoding_strategy_bebop_aggregate"
    //        );
    //
    //        (bool success,) = tychoRouterAddr.call(callData);
    //
    //        uint256 finalBalance = IERC20(USDC_ADDR).balanceOf(orderTaker);
    //
    //        assertTrue(success, "Call Failed");
    //        assertEq(finalBalance, expAmountOut);
    //
    //        vm.stopPrank();
    //    }
}
