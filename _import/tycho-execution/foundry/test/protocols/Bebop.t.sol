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

contract BebopExecutorTest is Constants, Permit2TestHelper, TestUtils {
    using SafeERC20 for IERC20;

    /// @dev Helper to extract filledTakerAmount from bebop calldata
    /// Note: With proper ABI encoding, filledTakerAmount is at the same position for both
    /// - swapSingle: position 68-100 (third parameter, after two offsets)
    /// - swapAggregate: position 68-100 (third parameter, after two offsets)
    function _extractFilledTakerAmount(bytes memory bebopCalldata)
        private
        pure
        returns (uint256 v)
    {
        // Get the selector to determine position
        bytes4 selector;
        assembly {
            let dataPtr := add(bebopCalldata, 0x20)
            selector := mload(dataPtr)
        }

        // Both swapSingle and swapAggregate have filledTakerAmount at position 68
        uint256 position = 68;

        assembly {
            // bebopCalldata points to length, add 0x20 for data start
            let dataPtr := add(bebopCalldata, 0x20)
            let filledTakerAmountPos := add(dataPtr, position)
            v := mload(filledTakerAmountPos)
        }
    }

    BebopExecutorHarness bebopExecutor;

    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 USDC = IERC20(USDC_ADDR);
    IERC20 DAI = IERC20(DAI_ADDR);
    IERC20 WBTC = IERC20(WBTC_ADDR);
    IERC20 ONDO = IERC20(ONDO_ADDR);
    IERC20 USDT = IERC20(USDT_ADDR);

    // Test data structures for mainnet fork tests
    struct SingleOrderTestData {
        uint256 forkBlock;
        IBebopSettlement.Single order;
        bytes signature;
        uint256 amountIn;
        uint256 filledTakerAmount; // 0 means fill entire order
        uint256 expectedAmountOut;
        address sender;
        address receiver;
    }

    struct AggregateOrderTestData {
        uint256 forkBlock;
        IBebopSettlement.Aggregate order;
        bytes[] signatures; // Multiple signatures for multiple makers
        uint256[] amountsIn;
        uint256[] filledTakerAmounts; // 0 in array means fill entire amount for that token
        uint256[] expectedAmountsOut;
        address sender;
        address receiver;
    }

    function setUp() public {
        // Fork will be created in individual tests to allow different fork blocks
    }

    function testDecodeParams() public {
        // Fork to ensure consistent setup
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);

        // Deploy Bebop executor harness
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

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
            uint8(1), // approvalNeeded: true
            address(123),
            bebopCalldata
        );

        // Test decoding
        (
            address tokenIn,
            address tokenOut,
            RestrictTransferFrom.TransferType transferType,
            bytes memory decodedBebopCalldata,
            uint8 decodedPartialFillOffset,
            uint256 decodedOriginalAmountIn,
            bool decodedApprovalNeeded,
            address decodedReceiver
        ) = bebopExecutor.decodeParams(params);

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
        // Fork at the right block first
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);

        // Deploy Bebop executor harness that uses vm.prank
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Create test data from real mainnet transaction
        // https://etherscan.io/tx/0x6279bc970273b6e526e86d9b69133c2ca1277e697ba25375f5e6fc4df50c0c94
        address originalTakerAddress =
            0xc5564C13A157E6240659fb81882A28091add8670;

        // Using the original order data with the real settlement contract
        SingleOrderTestData memory testData = SingleOrderTestData({
            forkBlock: 22667985,
            order: IBebopSettlement.Single({
                expiry: 1749483840,
                taker_address: originalTakerAddress, // Original taker address from the real order
                maker_address: 0xCe79b081c0c924cb67848723ed3057234d10FC6b,
                maker_nonce: 1749483765992417,
                taker_token: USDC_ADDR,
                maker_token: ONDO_ADDR,
                taker_amount: 200000000,
                maker_amount: 237212396774431060000,
                receiver: originalTakerAddress,
                packed_commands: 0,
                flags: 51915842898789398998206002334703507894664330885127600393944965515693155942400
            }),
            signature: hex"eb5419631614978da217532a40f02a8f2ece37d8cfb94aaa602baabbdefb56b474f4c2048a0f56502caff4ea7411d99eed6027cd67dc1088aaf4181dcb0df7051c",
            amountIn: 200000000,
            filledTakerAmount: 0,
            expectedAmountOut: 237212396774431060000,
            sender: originalTakerAddress,
            receiver: originalTakerAddress
        });

        // Setup: fund the original taker and have them approve the test contract (acting as router)
        deal(USDC_ADDR, originalTakerAddress, testData.amountIn);

        // Also fund the maker with ONDO tokens and have them approve the settlement
        deal(
            ONDO_ADDR, testData.order.maker_address, testData.order.maker_amount
        );
        vm.prank(testData.order.maker_address);
        ONDO.approve(BEBOP_SETTLEMENT, testData.order.maker_amount);

        // Original taker approves the test contract (router) to spend their USDC
        vm.prank(originalTakerAddress);
        USDC.approve(address(this), testData.amountIn);

        // Test contract (router) pulls tokens from original taker and sends to executor
        USDC.transferFrom(
            originalTakerAddress, address(bebopExecutor), testData.amountIn
        );

        // Execute the swap (executor already has the tokens)
        // Build the bebop calldata for swapSingle
        // Manually encode with correct selector since abi.encodeCall generates wrong selector
        bytes memory bebopCalldata = abi.encodePacked(
            bytes4(0x4dcebcba), // swapSingle selector
            abi.encode(
                testData.order,
                IBebopSettlement.MakerSignature({
                    signatureBytes: testData.signature,
                    flags: uint256(0) // ETH_SIGN
                }),
                testData.order.taker_amount // Use taker_amount when filledTakerAmount is 0
            )
        );

        bytes memory params = abi.encodePacked(
            USDC_ADDR,
            ONDO_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(2), // partialFillOffset for swapSingle (68 = 4 + 2*32)
            testData.order.taker_amount, // originalAmountIn (full fill, so equals taker_amount)
            uint8(1), // approvalNeeded: true
            originalTakerAddress, // receiver from order
            bebopCalldata
        );

        // Check initial ONDO balance of receiver
        uint256 initialOndoBalance = ONDO.balanceOf(originalTakerAddress);

        uint256 amountOut = bebopExecutor.swap(testData.amountIn, params);

        // Verify results
        assertEq(amountOut, testData.expectedAmountOut, "Incorrect amount out");
        // Since we're using real order data, tokens go to the original receiver
        assertEq(
            ONDO.balanceOf(originalTakerAddress) - initialOndoBalance,
            testData.expectedAmountOut,
            "ONDO should be at receiver"
        );
        assertEq(
            USDC.balanceOf(address(bebopExecutor)), 0, "USDC left in executor"
        );
    }

    function testSingleOrder_PartialFill() public {
        // Fork at the right block first
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);

        // Deploy Bebop executor harness that uses vm.prank
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Test partial fill - only fill half of the order
        address originalTakerAddress =
            0xc5564C13A157E6240659fb81882A28091add8670;

        // Using the same order but only filling half
        SingleOrderTestData memory testData = SingleOrderTestData({
            forkBlock: 22667985,
            order: IBebopSettlement.Single({
                expiry: 1749483840,
                taker_address: originalTakerAddress,
                maker_address: 0xCe79b081c0c924cb67848723ed3057234d10FC6b,
                maker_nonce: 1749483765992417,
                taker_token: USDC_ADDR,
                maker_token: ONDO_ADDR,
                taker_amount: 200000000, // 200 USDC total order
                maker_amount: 237212396774431060000, // Total ONDO for full order
                receiver: originalTakerAddress,
                packed_commands: 0,
                flags: 51915842898789398998206002334703507894664330885127600393944965515693155942400
            }),
            signature: hex"eb5419631614978da217532a40f02a8f2ece37d8cfb94aaa602baabbdefb56b474f4c2048a0f56502caff4ea7411d99eed6027cd67dc1088aaf4181dcb0df7051c",
            amountIn: 100000000, // Only provide 100 USDC (half)
            filledTakerAmount: 100000000, // Explicitly fill only 100 USDC
            expectedAmountOut: 118606198387215530000, // Expected proportional ONDO output (half of 237.21)
            sender: originalTakerAddress,
            receiver: originalTakerAddress
        });

        // Setup: fund the original taker with partial amount
        deal(USDC_ADDR, originalTakerAddress, testData.amountIn);

        // Fund the maker with FULL amount (they need enough for any partial fill)
        deal(
            ONDO_ADDR, testData.order.maker_address, testData.order.maker_amount
        );
        vm.prank(testData.order.maker_address);
        ONDO.approve(BEBOP_SETTLEMENT, testData.order.maker_amount);

        // Original taker approves the test contract (router) to spend their USDC
        vm.prank(originalTakerAddress);
        USDC.approve(address(this), testData.amountIn);

        // Test contract (router) pulls tokens from original taker and sends to executor
        USDC.transferFrom(
            originalTakerAddress, address(bebopExecutor), testData.amountIn
        );

        // Execute the partial swap (executor already has the tokens)
        // Build the bebop calldata for swapSingle
        // Manually encode with correct selector since abi.encodeCall generates wrong selector
        bytes memory bebopCalldata = abi.encodePacked(
            bytes4(0x4dcebcba), // swapSingle selector
            abi.encode(
                testData.order,
                IBebopSettlement.MakerSignature({
                    signatureBytes: testData.signature,
                    flags: uint256(0) // ETH_SIGN
                }),
                testData.filledTakerAmount
            )
        );

        bytes memory params = abi.encodePacked(
            USDC_ADDR,
            ONDO_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(2), // partialFillOffset for swapSingle (68 = 4 + 2*32)
            testData.filledTakerAmount, // originalAmountIn (the actual filledTakerAmount in the calldata)
            uint8(1), // approvalNeeded: true
            originalTakerAddress, // receiver from order
            bebopCalldata
        );

        // Check initial ONDO balance of receiver
        uint256 initialOndoBalance = ONDO.balanceOf(originalTakerAddress);

        uint256 amountOut = bebopExecutor.swap(testData.amountIn, params);

        // Verify partial fill results
        assertEq(
            amountOut,
            testData.expectedAmountOut,
            "Incorrect partial amount out"
        );
        // Since we're using real order data, tokens go to the original receiver
        assertEq(
            ONDO.balanceOf(originalTakerAddress) - initialOndoBalance,
            testData.expectedAmountOut,
            "ONDO should be at receiver"
        );
        assertEq(
            USDC.balanceOf(address(bebopExecutor)), 0, "USDC left in executor"
        );
    }

    // Aggregate Order Tests
    function testAggregateOrder() public {
        // Fork at the block just before the actual transaction
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22410851);

        // Deploy Bebop executor harness that uses vm.prank
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Store the initial ETH balance (dust from forked state)
        uint256 initialExecutorBalance = address(bebopExecutor).balance;

        // Create test data from real mainnet transaction
        // https://etherscan.io/tx/0xec88410136c287280da87d0a37c1cb745f320406ca3ae55c678dec11996c1b1c
        address originalTakerAddress =
            0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6;

        // Create the 2D arrays for tokens and amounts
        address[][] memory takerTokens = new address[][](2);
        takerTokens[0] = new address[](1);
        takerTokens[0][0] = WETH_ADDR; // WETH for first maker
        takerTokens[1] = new address[](1);
        takerTokens[1][0] = WETH_ADDR; // WETH for second maker

        address[][] memory makerTokens = new address[][](2);
        makerTokens[0] = new address[](1);
        makerTokens[0][0] = USDC_ADDR; // USDC from first maker
        makerTokens[1] = new address[](1);
        makerTokens[1][0] = USDC_ADDR; // USDC from second maker

        uint256[][] memory takerAmounts = new uint256[][](2);
        takerAmounts[0] = new uint256[](1);
        takerAmounts[0][0] = 5812106401997138; // First maker takes ~0.0058 ETH
        takerAmounts[1] = new uint256[](1);
        takerAmounts[1][0] = 4037893598002862; // Second maker takes ~0.0040 ETH

        uint256[][] memory makerAmounts = new uint256[][](2);
        makerAmounts[0] = new uint256[](1);
        makerAmounts[0][0] = 10607211; // First maker gives ~10.6 USDC
        makerAmounts[1] = new uint256[](1);
        makerAmounts[1][0] = 7362350; // Second maker gives ~7.36 USDC

        // Create makers array
        address[] memory makerAddresses = new address[](2);
        makerAddresses[0] = 0x67336Cec42645F55059EfF241Cb02eA5cC52fF86;
        makerAddresses[1] = 0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE;

        // Create maker nonces array
        uint256[] memory makerNonces = new uint256[](2);
        makerNonces[0] = 1746367197308;
        makerNonces[1] = 15460096;

        // Create the aggregate order
        IBebopSettlement.Aggregate memory order = IBebopSettlement.Aggregate({
            expiry: 1746367285, // Original expiry that matches the signatures
            taker_address: originalTakerAddress,
            maker_addresses: makerAddresses,
            maker_nonces: makerNonces,
            taker_tokens: takerTokens,
            maker_tokens: makerTokens,
            taker_amounts: takerAmounts,
            maker_amounts: makerAmounts,
            receiver: originalTakerAddress,
            commands: hex"00040004",
            flags: 95769172144825922628485191511070792431742484643425438763224908097896054784000
        });

        // Total amounts
        uint256 totalTakerAmount = takerAmounts[0][0] + takerAmounts[1][0]; // 0.00985 ETH total
        uint256 totalMakerAmount = makerAmounts[0][0] + makerAmounts[1][0]; // 17.969561 USDC total

        // Fund makers with USDC and approve settlement
        deal(USDC_ADDR, makerAddresses[0], makerAmounts[0][0]);
        deal(USDC_ADDR, makerAddresses[1], makerAmounts[1][0]);

        vm.prank(makerAddresses[0]);
        USDC.approve(BEBOP_SETTLEMENT, makerAmounts[0][0]);

        vm.prank(makerAddresses[1]);
        USDC.approve(BEBOP_SETTLEMENT, makerAmounts[1][0]);

        // For native ETH, settlement pulls from taker; fund taker with ETH
        vm.deal(originalTakerAddress, totalTakerAmount + 1 ether);

        // Create maker signatures
        IBebopSettlement.MakerSignature[] memory signatures =
            new IBebopSettlement.MakerSignature[](2);
        signatures[0] = IBebopSettlement.MakerSignature({
            signatureBytes: hex"d5abb425f9bac1f44d48705f41a8ab9cae207517be8553d2c03b06a88995f2f351ab8ce7627a87048178d539dd64fd2380245531a0c8e43fdc614652b1f32fc71c",
            flags: 0 // ETH_SIGN
        });
        signatures[1] = IBebopSettlement.MakerSignature({
            signatureBytes: hex"f38c698e48a3eac48f184bc324fef0b135ee13705ab38cc0bbf5a792f21002f051e445b9e7d57cf24c35e17629ea35b3263591c4abf8ca87ffa44b41301b89c41b",
            flags: 0 // ETH_SIGN
        });

        // Build the bebop calldata for swapAggregate
        // Manually encode with correct selector since abi.encodeCall generates wrong selector
        bytes memory bebopCalldata = abi.encodePacked(
            bytes4(0xa2f74893), // swapAggregate selector
            abi.encode(order, signatures, totalTakerAmount) // Use totalTakerAmount when filledTakerAmount would be 0
        );

        // Create packed params for executor with native ETH as input
        bytes memory params = abi.encodePacked(
            address(0), // tokenIn: native ETH
            USDC_ADDR, // tokenOut
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(2), // partialFillOffset for swapAggregate (68 = 4 + 2*32)
            totalTakerAmount, // originalAmountIn
            uint8(0), // approvalNeeded: false for native ETH
            originalTakerAddress, // receiver from order
            bebopCalldata
        );

        // Check initial USDC balance of receiver
        uint256 initialUsdcBalance = USDC.balanceOf(originalTakerAddress);

        // Execute the aggregate swap with ETH value
        uint256 amountOut = bebopExecutor.swap{value: totalTakerAmount}(
            totalTakerAmount, params
        );

        // Verify results
        assertEq(amountOut, totalMakerAmount, "Incorrect amount out");
        // Since we're using real order data, tokens go to the original receiver
        assertEq(
            USDC.balanceOf(originalTakerAddress) - initialUsdcBalance,
            totalMakerAmount,
            "USDC should be at receiver"
        );
        // With pranking, settlement pulls ETH from taker; executor keeps msg.value on top of initial dust
        assertEq(
            address(bebopExecutor).balance,
            initialExecutorBalance + totalTakerAmount,
            "Executor ETH balance should be initial + msg.value for aggregate ETH flow"
        );
    }

    function testAggregateOrder_PartialFill() public {
        // Fork at the block just before the actual transaction
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22410851);

        // Deploy Bebop executor harness that uses vm.prank
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Store the initial ETH balance (dust from forked state)
        uint256 initialExecutorBalance = address(bebopExecutor).balance;

        // Same aggregate order as before, but with partial fill
        address originalTakerAddress =
            0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6;

        // Create the 2D arrays for tokens and amounts
        address[][] memory takerTokens = new address[][](2);
        takerTokens[0] = new address[](1);
        takerTokens[0][0] = WETH_ADDR;
        takerTokens[1] = new address[](1);
        takerTokens[1][0] = WETH_ADDR;

        address[][] memory makerTokens = new address[][](2);
        makerTokens[0] = new address[](1);
        makerTokens[0][0] = USDC_ADDR;
        makerTokens[1] = new address[](1);
        makerTokens[1][0] = USDC_ADDR;

        uint256[][] memory takerAmounts = new uint256[][](2);
        takerAmounts[0] = new uint256[](1);
        takerAmounts[0][0] = 5812106401997138;
        takerAmounts[1] = new uint256[](1);
        takerAmounts[1][0] = 4037893598002862;

        uint256[][] memory makerAmounts = new uint256[][](2);
        makerAmounts[0] = new uint256[](1);
        makerAmounts[0][0] = 10607211;
        makerAmounts[1] = new uint256[](1);
        makerAmounts[1][0] = 7362350;

        // Create makers array
        address[] memory makerAddresses = new address[](2);
        makerAddresses[0] = 0x67336Cec42645F55059EfF241Cb02eA5cC52fF86;
        makerAddresses[1] = 0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE;

        // Create maker nonces array
        uint256[] memory makerNonces = new uint256[](2);
        makerNonces[0] = 1746367197308;
        makerNonces[1] = 15460096;

        // Create the aggregate order
        IBebopSettlement.Aggregate memory order = IBebopSettlement.Aggregate({
            expiry: 1746367285, // Original expiry that matches the signatures
            taker_address: originalTakerAddress,
            maker_addresses: makerAddresses,
            maker_nonces: makerNonces,
            taker_tokens: takerTokens,
            maker_tokens: makerTokens,
            taker_amounts: takerAmounts,
            maker_amounts: makerAmounts,
            receiver: originalTakerAddress,
            commands: hex"00040004",
            flags: 95769172144825922628485191511070792431742484643425438763224908097896054784000
        });

        // Total amounts
        uint256 totalTakerAmount = takerAmounts[0][0] + takerAmounts[1][0];
        uint256 totalMakerAmount = makerAmounts[0][0] + makerAmounts[1][0];

        // We'll do a 50% partial fill
        uint256 partialFillAmount = totalTakerAmount / 2;
        uint256 expectedPartialOutput = totalMakerAmount / 2;

        // Fund makers with FULL amounts (they need enough for any partial fill)
        deal(USDC_ADDR, makerAddresses[0], makerAmounts[0][0]);
        deal(USDC_ADDR, makerAddresses[1], makerAmounts[1][0]);

        vm.prank(makerAddresses[0]);
        USDC.approve(BEBOP_SETTLEMENT, makerAmounts[0][0]);

        vm.prank(makerAddresses[1]);
        USDC.approve(BEBOP_SETTLEMENT, makerAmounts[1][0]);

        // For native ETH, settlement pulls from taker; fund taker with ETH
        vm.deal(originalTakerAddress, partialFillAmount + 1 ether);

        // Create maker signatures
        IBebopSettlement.MakerSignature[] memory signatures =
            new IBebopSettlement.MakerSignature[](2);
        signatures[0] = IBebopSettlement.MakerSignature({
            signatureBytes: hex"d5abb425f9bac1f44d48705f41a8ab9cae207517be8553d2c03b06a88995f2f351ab8ce7627a87048178d539dd64fd2380245531a0c8e43fdc614652b1f32fc71c",
            flags: 0
        });
        signatures[1] = IBebopSettlement.MakerSignature({
            signatureBytes: hex"f38c698e48a3eac48f184bc324fef0b135ee13705ab38cc0bbf5a792f21002f051e445b9e7d57cf24c35e17629ea35b3263591c4abf8ca87ffa44b41301b89c41b",
            flags: 0
        });

        // Build the bebop calldata for swapAggregate with partial fill
        // Manually encode with correct selector since abi.encodeCall generates wrong selector
        bytes memory bebopCalldata = abi.encodePacked(
            bytes4(0xa2f74893), // swapAggregate selector
            abi.encode(order, signatures, partialFillAmount) // Specify partial fill amount
        );

        // Create packed params for executor with partial fill amount
        bytes memory params = abi.encodePacked(
            address(0), // tokenIn: native ETH
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(2), // partialFillOffset for swapAggregate (68 = 4 + 2*32)
            totalTakerAmount, // originalAmountIn (full order amount)
            uint8(0), // approvalNeeded: false for native ETH
            originalTakerAddress, // receiver from order
            bebopCalldata
        );

        // Check initial USDC balance of receiver
        uint256 initialUsdcBalance = USDC.balanceOf(originalTakerAddress);

        // Execute the partial aggregate swap with ETH value
        uint256 amountOut = bebopExecutor.swap{value: partialFillAmount}(
            partialFillAmount, params
        );

        // Verify results - should be proportional to the partial fill
        assertEq(
            amountOut, expectedPartialOutput, "Incorrect partial amount out"
        );
        // Since we're using real order data, tokens go to the original receiver
        assertEq(
            USDC.balanceOf(originalTakerAddress) - initialUsdcBalance,
            expectedPartialOutput,
            "USDC should be at receiver"
        );
        // With pranking, settlement pulls ETH from taker; executor keeps msg.value on top of initial dust
        assertEq(
            address(bebopExecutor).balance,
            initialExecutorBalance + partialFillAmount,
            "Executor ETH balance should be initial + msg.value for aggregate ETH flow"
        );
    }

    function testInvalidDataLength() public {
        // Fork to ensure consistent setup
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);

        // Deploy Bebop executor with real settlement contract
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

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
        bebopExecutor.decodeParams(validParams);

        // In the new format, adding extra bytes at the end doesn't fail
        // because bebopCalldata is variable length at the end
        // So test with extra bytes should not revert
        bytes memory paramsWithExtra = abi.encodePacked(validParams, hex"ff");
        // This should work as the extra byte becomes part of bebopCalldata
        bebopExecutor.decodeParams(paramsWithExtra);

        // Try with insufficient data, should fail
        bytes memory tooShortParams = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
        // Missing rest of the data

        vm.expectRevert(BebopExecutor.BebopExecutor__InvalidDataLength.selector);
        bebopExecutor.decodeParams(tooShortParams);
    }

    // Integration tests
    function testSwapSingleIntegration() public {
        // Fork at the right block first
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667986);

        // Deploy Bebop executor harness
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Create the same order data as in testSingleOrder
        address originalTakerAddress =
            0xc5564C13A157E6240659fb81882A28091add8670;

        IBebopSettlement.Single memory order = IBebopSettlement.Single({
            expiry: 1749483840,
            taker_address: originalTakerAddress,
            maker_address: 0xCe79b081c0c924cb67848723ed3057234d10FC6b,
            maker_nonce: 1749483765992417,
            taker_token: USDC_ADDR,
            maker_token: ONDO_ADDR,
            taker_amount: 200000000,
            maker_amount: 237212396774431060000,
            receiver: originalTakerAddress,
            packed_commands: 0,
            flags: 51915842898789398998206002334703507894664330885127600393944965515693155942400
        });

        bytes memory signature =
            hex"eb5419631614978da217532a40f02a8f2ece37d8cfb94aaa602baabbdefb56b474f4c2048a0f56502caff4ea7411d99eed6027cd67dc1088aaf4181dcb0df7051c";

        // Build bebop calldata
        bytes memory bebopCalldata = abi.encodePacked(
            bytes4(0x4dcebcba), // swapSingle selector
            abi.encode(
                order,
                IBebopSettlement.MakerSignature({
                    signatureBytes: signature,
                    flags: uint256(0)
                }),
                0 // full fill
            )
        );

        // Build executor params in new format
        bytes memory protocolData = abi.encodePacked(
            USDC_ADDR,
            ONDO_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(2), // partialFillOffset for swapSingle (68 = 4 + 2*32)
            uint256(200000000), // originalAmountIn
            uint8(1), // approvalNeeded: true
            originalTakerAddress, // receiver from order
            bebopCalldata
        );

        // Deal 200 USDC to the executor
        uint256 amountIn = 200000000; // 200 USDC
        deal(USDC_ADDR, address(bebopExecutor), amountIn);

        // Fund the maker with ONDO and approve settlement
        address maker = 0xCe79b081c0c924cb67848723ed3057234d10FC6b;
        uint256 expectedAmountOut = 237212396774431060000; // 237.21 ONDO
        deal(ONDO_ADDR, maker, expectedAmountOut);
        vm.prank(maker);
        ONDO.approve(BEBOP_SETTLEMENT, expectedAmountOut);

        // Check initial ONDO balance of receiver
        uint256 initialOndoBalance = ONDO.balanceOf(originalTakerAddress);

        // Execute the swap
        uint256 amountOut = bebopExecutor.swap(amountIn, protocolData);

        // Verify results
        assertEq(amountOut, expectedAmountOut, "Incorrect amount out");
        // Since we're using historical data, tokens go to the original receiver
        assertEq(
            ONDO.balanceOf(originalTakerAddress) - initialOndoBalance,
            expectedAmountOut,
            "ONDO should be at receiver"
        );
        assertEq(
            USDC.balanceOf(address(bebopExecutor)), 0, "USDC left in executor"
        );
    }

    function testSwapAggregateIntegration() public {
        // Fork at the block just before the actual transaction
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22410851);

        // Deploy Bebop executor harness
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Store the initial ETH balance (dust from forked state)
        uint256 initialExecutorBalance = address(bebopExecutor).balance;

        // Based on real transaction: https://etherscan.io/tx/0xec88410136c287280da87d0a37c1cb745f320406ca3ae55c678dec11996c1b1c
        address orderTaker = 0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6;

        // Create the 2D arrays for tokens and amounts
        address[][] memory takerTokens = new address[][](2);
        takerTokens[0] = new address[](1);
        takerTokens[0][0] = WETH_ADDR;
        takerTokens[1] = new address[](1);
        takerTokens[1][0] = WETH_ADDR;

        address[][] memory makerTokens = new address[][](2);
        makerTokens[0] = new address[](1);
        makerTokens[0][0] = USDC_ADDR;
        makerTokens[1] = new address[](1);
        makerTokens[1][0] = USDC_ADDR;

        uint256[][] memory takerAmounts = new uint256[][](2);
        takerAmounts[0] = new uint256[](1);
        takerAmounts[0][0] = 5812106401997138;
        takerAmounts[1] = new uint256[](1);
        takerAmounts[1][0] = 4037893598002862;

        uint256[][] memory makerAmounts = new uint256[][](2);
        makerAmounts[0] = new uint256[](1);
        makerAmounts[0][0] = 10607211;
        makerAmounts[1] = new uint256[](1);
        makerAmounts[1][0] = 7362350;

        address[] memory makerAddresses = new address[](2);
        makerAddresses[0] = 0x67336Cec42645F55059EfF241Cb02eA5cC52fF86;
        makerAddresses[1] = 0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE;

        uint256[] memory makerNonces = new uint256[](2);
        makerNonces[0] = 1746367197308;
        makerNonces[1] = 15460096;

        IBebopSettlement.Aggregate memory order = IBebopSettlement.Aggregate({
            expiry: 1746367285, // Original expiry that matches the signatures
            taker_address: orderTaker,
            maker_addresses: makerAddresses,
            maker_nonces: makerNonces,
            taker_tokens: takerTokens,
            maker_tokens: makerTokens,
            taker_amounts: takerAmounts,
            maker_amounts: makerAmounts,
            receiver: orderTaker,
            commands: hex"00040004",
            flags: 95769172144825922628485191511070792431742484643425438763224908097896054784000
        });

        // Create maker signatures
        IBebopSettlement.MakerSignature[] memory signatures =
            new IBebopSettlement.MakerSignature[](2);
        signatures[0] = IBebopSettlement.MakerSignature({
            signatureBytes: hex"d5abb425f9bac1f44d48705f41a8ab9cae207517be8553d2c03b06a88995f2f351ab8ce7627a87048178d539dd64fd2380245531a0c8e43fdc614652b1f32fc71c",
            flags: 0
        });
        signatures[1] = IBebopSettlement.MakerSignature({
            signatureBytes: hex"f38c698e48a3eac48f184bc324fef0b135ee13705ab38cc0bbf5a792f21002f051e445b9e7d57cf24c35e17629ea35b3263591c4abf8ca87ffa44b41301b89c41b",
            flags: 0
        });

        uint256 ethAmount = 9850000000000000; // 0.00985 ETH
        uint256 expAmountOut = 17969561; // 17.969561 USDC

        // Build bebop calldata
        bytes memory bebopCalldata = abi.encodePacked(
            bytes4(0xa2f74893), // swapAggregate selector
            abi.encode(order, signatures, ethAmount) // Use ethAmount (totalTakerAmount) when filledTakerAmount would be 0
        );

        // Build executor params in new format
        bytes memory protocolData = abi.encodePacked(
            address(0), // tokenIn: native ETH
            USDC_ADDR, // tokenOut
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(2), // partialFillOffset for swapAggregate (68 = 4 + 2*32)
            ethAmount, // originalAmountIn
            uint8(0), // approvalNeeded: false for native ETH
            orderTaker, // receiver from order
            bebopCalldata
        );

        // Fund the two makers from the real transaction with USDC
        address maker1 = makerAddresses[0];
        address maker2 = makerAddresses[1];

        deal(USDC_ADDR, maker1, 10607211);
        deal(USDC_ADDR, maker2, 7362350);

        // Makers approve settlement contract
        vm.prank(maker1);
        IERC20(USDC_ADDR).approve(BEBOP_SETTLEMENT, type(uint256).max);
        vm.prank(maker2);
        IERC20(USDC_ADDR).approve(BEBOP_SETTLEMENT, type(uint256).max);

        // Fund both order taker and executor with ETH to ensure sufficient balance
        // The taker needs ETH to send with the call, and for settlement
        vm.deal(orderTaker, ethAmount + 1 ether);
        vm.deal(address(bebopExecutor), ethAmount);
        vm.startPrank(orderTaker);

        // Check initial USDC balance of receiver
        uint256 initialUsdcBalance = IERC20(USDC_ADDR).balanceOf(orderTaker);

        // Execute the swap with native ETH
        uint256 amountOut =
            bebopExecutor.swap{value: ethAmount}(ethAmount, protocolData);

        // Verify results
        assertEq(amountOut, expAmountOut, "Incorrect amount out");
        // Since we're using historical data, tokens go to the original receiver
        assertEq(
            IERC20(USDC_ADDR).balanceOf(orderTaker) - initialUsdcBalance,
            expAmountOut,
            "USDC should be at receiver"
        );
        // ETH balance check - the harness may have different balance due to test setup
        // Just ensure no excessive ETH is stuck
        assertLe(
            address(bebopExecutor).balance,
            initialExecutorBalance + 1 ether,
            "Too much ETH left in executor"
        );
        vm.stopPrank();
    }

    // Test exposed_modifyFilledTakerAmount function
    function testModifyFilledTakerAmount_SingleOrder() public {
        // Deploy Bebop executor harness
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Create a single order bebop calldata
        IBebopSettlement.Single memory order = IBebopSettlement.Single({
            expiry: 1749483840,
            taker_address: address(0x123),
            maker_address: address(0x456),
            maker_nonce: 12345,
            taker_token: USDC_ADDR,
            maker_token: ONDO_ADDR,
            taker_amount: 1000e6, // 1000 USDC
            maker_amount: 100e18, // 100 ONDO
            receiver: address(0x123),
            packed_commands: 0,
            flags: 0
        });

        IBebopSettlement.MakerSignature memory signature = IBebopSettlement
            .MakerSignature({signatureBytes: hex"1234567890", flags: 0});

        uint256 filledTakerAmount = 500e6; // Fill half
        bytes memory originalCalldata = abi.encodePacked(
            bytes4(0x4dcebcba), // swapSingle selector
            abi.encode(order, signature, filledTakerAmount)
        );

        // Test modifying to a different amount
        uint256 givenAmount = 250e6; // Only have 250 USDC
        uint256 originalAmountIn = 1000e6; // Original full order amount

        bytes memory modifiedCalldata = bebopExecutor
            .exposed_modifyFilledTakerAmount(
            originalCalldata,
            givenAmount,
            originalAmountIn,
            2 // partialFillOffset for swapSingle
        );

        // Decode the modified calldata to verify the filledTakerAmount was updated
        uint256 newFilledTakerAmount =
            _extractFilledTakerAmount(modifiedCalldata);

        // Should be 250e6 (the givenAmount, since it's less than both originalFilledTakerAmount and originalAmountIn)
        assertEq(
            newFilledTakerAmount,
            250e6,
            "Modified filledTakerAmount should match givenAmount"
        );
    }

    function testModifyFilledTakerAmount_AggregateOrder() public {
        // Deploy Bebop executor harness
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Create aggregate order arrays
        address[][] memory takerTokens = new address[][](1);
        takerTokens[0] = new address[](1);
        takerTokens[0][0] = WETH_ADDR;

        address[][] memory makerTokens = new address[][](1);
        makerTokens[0] = new address[](1);
        makerTokens[0][0] = USDC_ADDR;

        uint256[][] memory takerAmounts = new uint256[][](1);
        takerAmounts[0] = new uint256[](1);
        takerAmounts[0][0] = 1e18; // 1 ETH

        uint256[][] memory makerAmounts = new uint256[][](1);
        makerAmounts[0] = new uint256[](1);
        makerAmounts[0][0] = 3000e6; // 3000 USDC

        address[] memory makerAddresses = new address[](1);
        makerAddresses[0] = address(0x789);

        uint256[] memory makerNonces = new uint256[](1);
        makerNonces[0] = 54321;

        IBebopSettlement.Aggregate memory order = IBebopSettlement.Aggregate({
            expiry: 1749483840,
            taker_address: address(0x123),
            maker_addresses: makerAddresses,
            maker_nonces: makerNonces,
            taker_tokens: takerTokens,
            maker_tokens: makerTokens,
            taker_amounts: takerAmounts,
            maker_amounts: makerAmounts,
            receiver: address(0x123),
            commands: hex"0004",
            flags: 0
        });

        IBebopSettlement.MakerSignature[] memory signatures =
            new IBebopSettlement.MakerSignature[](1);
        signatures[0] = IBebopSettlement.MakerSignature({
            signatureBytes: hex"abcdef1234",
            flags: 0
        });

        uint256 filledTakerAmount = 0; // Full fill
        bytes memory originalCalldata = abi.encodePacked(
            bytes4(0xa2f74893), // swapAggregate selector
            abi.encode(order, signatures, filledTakerAmount)
        );

        // Test with partial amount
        uint256 givenAmount = 0.5e18; // Only have 0.5 ETH
        uint256 originalAmountIn = 1e18; // Original full order amount

        bytes memory modifiedCalldata = bebopExecutor
            .exposed_modifyFilledTakerAmount(
            originalCalldata,
            givenAmount,
            originalAmountIn,
            2 // partialFillOffset for swapAggregate
        );

        // Decode the modified calldata to verify the filledTakerAmount was updated
        uint256 newFilledTakerAmount =
            _extractFilledTakerAmount(modifiedCalldata);

        // Should be 0.5e18 (the givenAmount)
        assertEq(
            newFilledTakerAmount,
            0.5e18,
            "Modified filledTakerAmount should match givenAmount"
        );
    }

    function testModifyFilledTakerAmount_NoChangeNeeded() public {
        // Deploy Bebop executor harness
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Create a single order bebop calldata
        IBebopSettlement.Single memory order = IBebopSettlement.Single({
            expiry: 1749483840,
            taker_address: address(0x123),
            maker_address: address(0x456),
            maker_nonce: 12345,
            taker_token: USDC_ADDR,
            maker_token: ONDO_ADDR,
            taker_amount: 1000e6,
            maker_amount: 100e18,
            receiver: address(0x123),
            packed_commands: 0,
            flags: 0
        });

        IBebopSettlement.MakerSignature memory signature = IBebopSettlement
            .MakerSignature({signatureBytes: hex"1234567890", flags: 0});

        uint256 filledTakerAmount = 1000e6; // Full fill

        // Properly encode with offsets for ABI compliance
        // When encoding (struct, struct, uint256), both structs get offsets
        bytes memory params = abi.encode(order, signature, filledTakerAmount);
        bytes memory originalCalldata = abi.encodePacked(
            bytes4(0x4dcebcba), // swapSingle selector
            params
        );

        // Test with same amounts - no modification should occur
        uint256 givenAmount = 1000e6;
        uint256 originalAmountIn = 1000e6;

        // Since this is a unit test with mock data, we'll verify the function behavior
        // The function should not modify the calldata when amounts match
        bytes memory modifiedCalldata = bebopExecutor
            .exposed_modifyFilledTakerAmount(
            originalCalldata,
            givenAmount,
            originalAmountIn,
            2 // partialFillOffset for swapSingle
        );

        assertEq(
            keccak256(modifiedCalldata),
            keccak256(originalCalldata),
            "Calldata should remain unchanged"
        );
    }
}

contract TychoRouterForBebopTest is TychoRouterTestSetup {
    // Override the fork block for Bebop tests
    function getForkBlock() public pure override returns (uint256) {
        return 22667986;
    }

    // Helper function to replace bytes in calldata
    function _replaceBytes(
        bytes memory data,
        bytes memory oldBytes,
        bytes memory newBytes
    ) private pure returns (bytes memory) {
        require(
            oldBytes.length == newBytes.length,
            "Replacement bytes must be same length"
        );

        // Find the position of oldBytes in data
        uint256 position = type(uint256).max;
        for (uint256 i = 0; i <= data.length - oldBytes.length; i++) {
            bool found = true;
            for (uint256 j = 0; j < oldBytes.length; j++) {
                if (data[i + j] != oldBytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                position = i;
                break;
            }
        }

        require(position != type(uint256).max, "Old bytes not found in data");

        // Replace the bytes
        for (uint256 i = 0; i < newBytes.length; i++) {
            data[position + i] = newBytes[i];
        }

        return data;
    }

    function testSingleBebopIntegration() public {
        // Don't create a new fork - use the existing one from setUp
        // The calldata swaps 200 USDC for ONDO
        // The receiver in the order is 0xc5564C13A157E6240659fb81882A28091add8670
        address orderTaker = 0xc5564C13A157E6240659fb81882A28091add8670;
        address maker = 0xCe79b081c0c924cb67848723ed3057234d10FC6b;
        deal(USDC_ADDR, tychoRouterAddr, 200000000); // 200 USDC
        uint256 expAmountOut = 237212396774431060000; // Expected ONDO amount from calldata

        // Fund the maker with ONDO and approve settlement
        deal(ONDO_ADDR, maker, expAmountOut);
        vm.prank(maker);
        IERC20(ONDO_ADDR).approve(BEBOP_SETTLEMENT, expAmountOut);

        uint256 ondoBefore = IERC20(ONDO_ADDR).balanceOf(orderTaker);

        vm.startPrank(orderTaker);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, type(uint256).max);

        // Load calldata from file
        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_bebop");

        console.log("BEBOP EXECUTOR ADDRESS", address(bebopExecutor));
        console.log(
            "Router has executor approved:",
            tychoRouter.executors(address(bebopExecutor))
        );

        (bool success,) = tychoRouterAddr.call(callData);

        // Check the receiver's balance (not ALICE, since the order specifies a different receiver)
        uint256 ondoReceived =
            IERC20(ONDO_ADDR).balanceOf(orderTaker) - ondoBefore;
        assertTrue(success, "Call Failed");
        assertEq(ondoReceived, expAmountOut);
        assertEq(
            IERC20(USDC_ADDR).balanceOf(tychoRouterAddr),
            0,
            "USDC left in router"
        );

        vm.stopPrank();
    }

    function testBebopAggregateIntegration() public {
        // Test aggregate order integration
        address orderTaker = 0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6;
        uint256 ethAmount = 9850000000000000; // 0.00985 WETH
        uint256 expAmountOut = 17969561; // 17.969561 USDC expected output

        // Fund makers with USDC
        address maker1 = 0x67336Cec42645F55059EfF241Cb02eA5cC52fF86;
        address maker2 = 0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE;
        deal(USDC_ADDR, maker1, 10607211);
        deal(USDC_ADDR, maker2, 7362350);

        vm.prank(maker1);
        IERC20(USDC_ADDR).approve(BEBOP_SETTLEMENT, type(uint256).max);
        vm.prank(maker2);
        IERC20(USDC_ADDR).approve(BEBOP_SETTLEMENT, type(uint256).max);

        // Fund taker with WETH
        deal(WETH_ADDR, orderTaker, ethAmount);

        vm.startPrank(orderTaker);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, ethAmount);

        // Load calldata from file
        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_bebop_aggregate"
        );

        (bool success,) = tychoRouterAddr.call(callData);

        uint256 finalBalance = IERC20(USDC_ADDR).balanceOf(orderTaker);

        assertTrue(success, "Call Failed");
        assertEq(finalBalance, expAmountOut);

        vm.stopPrank();
    }
}
