// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "@src/executors/BebopExecutor.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {Test, console} from "forge-std/Test.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SafeERC20} from
    "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract MockToken is ERC20 {
    uint8 private _decimals;

    constructor(string memory name_, string memory symbol_, uint8 decimals_)
        ERC20(name_, symbol_)
    {
        _decimals = decimals_;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }
}

contract BebopExecutorHarness is BebopExecutor, Test {
    using SafeERC20 for IERC20;

    constructor(address _bebopSettlement, address _permit2)
        BebopExecutor(_bebopSettlement, _permit2)
    {}

    // Expose the internal decodeData function for testing
    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            address tokenIn,
            address tokenOut,
            RestrictTransferFrom.TransferType transferType,
            BebopExecutor.OrderType orderType,
            uint256 filledTakerAmount,
            bytes memory quoteData,
            bytes memory makerSignaturesData,
            bool // approvalNeeded - unused in test harness
        )
    {
        return _decodeData(data);
    }

    // Expose the internal getActualFilledTakerAmount function for testing
    function exposed_getActualFilledTakerAmount(
        uint256 givenAmount,
        uint256 orderTakerAmount,
        uint256 filledTakerAmount
    ) external pure returns (uint256 actualFilledTakerAmount) {
        return _getActualFilledTakerAmount(
            givenAmount,
            orderTakerAmount,
            filledTakerAmount
        );
    }

    // Override to prank the taker address before calling the real settlement
    function _executeSingleRFQ(
        address tokenIn,
        address tokenOut,
        TransferType transferType,
        uint256 givenAmount,
        uint256 filledTakerAmount,
        bytes memory quoteData,
        bytes memory makerSignaturesData,
        bool
    ) internal virtual override returns (uint256 amountOut) {
        // Decode the order from quoteData
        IBebopSettlement.Single memory order =
            abi.decode(quoteData, (IBebopSettlement.Single));

        // Decode the MakerSignature array (should contain exactly 1 signature for Single orders)
        IBebopSettlement.MakerSignature[] memory signatures =
            abi.decode(makerSignaturesData, (IBebopSettlement.MakerSignature[]));

        // Validate that there is exactly one maker signature
        if (signatures.length != 1) {
            revert BebopExecutor__InvalidInput();
        }

        // Get the maker signature from the first and only element of the array
        IBebopSettlement.MakerSignature memory sig = signatures[0];

        uint256 actualFilledTakerAmount = _getActualFilledTakerAmount(
            givenAmount, order.taker_amount, filledTakerAmount
        );

        if (tokenIn != address(0)) {
            // Transfer tokens to executor
            _transfer(address(this), transferType, tokenIn, givenAmount);
        }

        // NOTE: NOT NEEDED FOR TESTING
        // // Approve Bebop settlement to spend tokens if needed
        // if (approvalNeeded) {
        //     // slither-disable-next-line unused-return
        //     IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
        // }

        // NOTE: SETUP FOR TESTING

        // Record balances before swap to calculate amountOut
        uint256 balanceBefore = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        // Execute the swap with ETH value if needed
        uint256 ethValue = tokenIn == address(0) ? actualFilledTakerAmount : 0;

        // For testing: transfer tokens from executor to taker address
        // This simulates the taker having the tokens with approval
        if (tokenIn != address(0)) {
            IERC20(tokenIn).safeTransfer(
                order.taker_address, actualFilledTakerAmount
            );

            // Approve settlement from taker's perspective
            // Stop any existing prank first
            vm.stopPrank();
            vm.startPrank(order.taker_address);
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
            vm.stopPrank();
        } else {
            vm.stopPrank();
            // For native ETH, send it to the taker address
            payable(order.taker_address).transfer(actualFilledTakerAmount);
        }

        // IMPORTANT: Prank as the taker address to pass the settlement validation
        vm.stopPrank();
        vm.startPrank(order.taker_address);

        // Set block timestamp to ensure order is valid regardless of fork block
        uint256 currentTimestamp = block.timestamp;
        vm.warp(order.expiry - 1); // Set timestamp to just before expiry

        // Use swapSingle - tokens are now in taker's wallet with approval
        // slither-disable-next-line arbitrary-send-eth
        IBebopSettlement(bebopSettlement).swapSingle{value: ethValue}(
            order, sig, actualFilledTakerAmount
        );

        // Restore original timestamp
        vm.warp(currentTimestamp);
        vm.stopPrank();

        // NOTE: END SETUP FOR TESTING

        // Calculate actual amount received
        uint256 balanceAfter = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        amountOut = balanceAfter - balanceBefore;
    }

    // Override to execute aggregate orders through the real settlement
    function _executeAggregateRFQ(
        address tokenIn,
        address tokenOut,
        TransferType transferType,
        uint256 givenAmount,
        uint256 filledTakerAmount,
        bytes memory quoteData,
        bytes memory makerSignaturesData,
        bool // approvalNeeded - unused in test harness
    ) internal virtual override returns (uint256 amountOut) {
        // Decode the Aggregate order
        IBebopSettlement.Aggregate memory order =
            abi.decode(quoteData, (IBebopSettlement.Aggregate));

        // Decode the MakerSignature array (can contain multiple signatures for Aggregate orders)
        IBebopSettlement.MakerSignature[] memory signatures =
            abi.decode(makerSignaturesData, (IBebopSettlement.MakerSignature[]));

        // Aggregate orders should have at least one signature
        if (signatures.length == 0) {
            revert BebopExecutor__InvalidInput();
        }

        // For aggregate orders, calculate total taker amount across all amounts of the 2D array
        uint256 totalTakerAmount;
        for (uint256 i = 0; i < order.taker_amounts.length; i++) {
            for (uint256 j = 0; j < order.taker_amounts[i].length; j++) {
                totalTakerAmount += order.taker_amounts[i][j];
            }
        }

        uint256 actualFilledTakerAmount = _getActualFilledTakerAmount(
            givenAmount, totalTakerAmount, filledTakerAmount
        );

        if (tokenIn != address(0)) {
            // Transfer tokens to executor
            _transfer(address(this), transferType, tokenIn, givenAmount);
        }

        // NOTE: NOT NEEDED FOR TESTING
        // // Approve Bebop settlement to spend tokens if needed
        // if (approvalNeeded) {
        //     // slither-disable-next-line unused-return
        //     IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
        // }

        // NOTE: SETUP FOR TESTING

        // Record balances before swap to calculate amountOut
        uint256 balanceBefore = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        // Execute the swap with ETH value if needed
        uint256 ethValue = tokenIn == address(0) ? actualFilledTakerAmount : 0;

        // For testing: transfer tokens from executor to taker address
        // This simulates the taker having the tokens with approval
        if (tokenIn != address(0)) {
            IERC20(tokenIn).safeTransfer(
                order.taker_address, actualFilledTakerAmount
            );

            // Approve settlement from taker's perspective
            // Stop any existing prank first
            vm.stopPrank();
            vm.startPrank(order.taker_address);
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
            vm.stopPrank();
        } else {
            vm.stopPrank();
            // For native ETH, send it to the taker address
            payable(order.taker_address).transfer(actualFilledTakerAmount);
        }

        // IMPORTANT: Prank as the taker address to pass the settlement validation
        vm.stopPrank();
        vm.startPrank(order.taker_address);

        // Set block timestamp to ensure order is valid regardless of fork block
        uint256 currentTimestamp = block.timestamp;
        vm.warp(order.expiry - 1); // Set timestamp to just before expiry

        // Use swapAggregate - tokens are now in taker's wallet with approval
        // slither-disable-next-line arbitrary-send-eth
        IBebopSettlement(bebopSettlement).swapAggregate{value: ethValue}(
            order, signatures, actualFilledTakerAmount
        );

        // Restore original timestamp
        vm.warp(currentTimestamp);
        vm.stopPrank();

        // NOTE: END SETUP FOR TESTING

        // Calculate actual amount received
        uint256 balanceAfter = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        amountOut = balanceAfter - balanceBefore;
    }
}

contract BebopExecutorTest is Constants, Permit2TestHelper, TestUtils {
    using SafeERC20 for IERC20;

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

        // Deploy Bebop executor harness with real settlement contract
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);
        bytes memory quoteData = hex"1234567890abcdef";
        bytes memory signature = hex"aabbccdd";

        // Create ABI-encoded MakerSignature array
        IBebopSettlement.MakerSignature[] memory signatures =
            new IBebopSettlement.MakerSignature[](1);
        signatures[0] = IBebopSettlement.MakerSignature({
            signatureBytes: signature,
            flags: uint256(1) // EIP712 signature type
        });
        bytes memory makerSignaturesData = abi.encode(signatures);

        uint256 filledTakerAmount = 1e18; // 1 WETH

        bytes memory params = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(0), // OrderType.Single
            filledTakerAmount,
            uint32(quoteData.length),
            quoteData,
            uint32(makerSignaturesData.length),
            makerSignaturesData,
            uint8(1) // approvalNeeded: true
        );

        (
            address tokenIn,
            address tokenOut,
            RestrictTransferFrom.TransferType transferType,
            BebopExecutor.OrderType orderType,
            uint256 decodedFilledTakerAmount,
            bytes memory decodedQuoteData,
            bytes memory decodedMakerSignaturesData,
            bool decodedApprovalNeeded
        ) = bebopExecutor.decodeParams(params);

        assertEq(tokenIn, WETH_ADDR);
        assertEq(tokenOut, USDC_ADDR);
        assertEq(
            uint8(transferType),
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
        assertEq(uint8(orderType), uint8(BebopExecutor.OrderType.Single));
        assertEq(decodedFilledTakerAmount, filledTakerAmount);
        assertEq(keccak256(decodedQuoteData), keccak256(quoteData));
        assertEq(
            keccak256(decodedMakerSignaturesData),
            keccak256(makerSignaturesData)
        );
        assertTrue(decodedApprovalNeeded); // Approval needed should be true

        // Also verify we can decode the signatures back
        IBebopSettlement.MakerSignature[] memory decodedSignatures = abi.decode(
            decodedMakerSignaturesData, (IBebopSettlement.MakerSignature[])
        );
        assertEq(decodedSignatures.length, 1);
        assertEq(
            keccak256(decodedSignatures[0].signatureBytes), keccak256(signature)
        );
        assertEq(decodedSignatures[0].flags, 1); // EIP712
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

        // Record initial balances
        uint256 ondoBefore = ONDO.balanceOf(originalTakerAddress);

        // Execute the swap (executor already has the tokens)
        bytes memory quoteData = abi.encode(testData.order);
        IBebopSettlement.MakerSignature[] memory signatures =
            new IBebopSettlement.MakerSignature[](1);
        signatures[0] = IBebopSettlement.MakerSignature({
            signatureBytes: testData.signature,
            flags: uint256(0) // ETH_SIGN
        });
        bytes memory makerSignaturesData = abi.encode(signatures);

        bytes memory params = abi.encodePacked(
            USDC_ADDR,
            ONDO_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(BebopExecutor.OrderType.Single),
            testData.filledTakerAmount,
            uint32(quoteData.length),
            quoteData,
            uint32(makerSignaturesData.length),
            makerSignaturesData,
            uint8(1) // approvalNeeded: true
        );

        uint256 amountOut = bebopExecutor.swap(testData.amountIn, params);

        // Verify results
        assertEq(amountOut, testData.expectedAmountOut, "Incorrect amount out");
        assertEq(
            ONDO.balanceOf(originalTakerAddress) - ondoBefore,
            testData.expectedAmountOut,
            "ONDO balance mismatch"
        );
        assertEq(
            USDC.balanceOf(address(bebopExecutor)), 0, "USDC left in executor"
        );
        assertEq(
            ONDO.balanceOf(address(bebopExecutor)), 0, "ONDO left in executor"
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

        // Record initial balances
        uint256 ondoBefore = ONDO.balanceOf(originalTakerAddress);

        // Execute the partial swap (executor already has the tokens)
        bytes memory quoteData = abi.encode(testData.order);
        IBebopSettlement.MakerSignature[] memory signatures =
            new IBebopSettlement.MakerSignature[](1);
        signatures[0] = IBebopSettlement.MakerSignature({
            signatureBytes: testData.signature,
            flags: uint256(0) // ETH_SIGN
        });
        bytes memory makerSignaturesData = abi.encode(signatures);

        bytes memory params = abi.encodePacked(
            USDC_ADDR,
            ONDO_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(BebopExecutor.OrderType.Single),
            testData.filledTakerAmount, // Partial fill amount
            uint32(quoteData.length),
            quoteData,
            uint32(makerSignaturesData.length),
            makerSignaturesData,
            uint8(1) // approvalNeeded: true
        );

        uint256 amountOut = bebopExecutor.swap(testData.amountIn, params);

        // Verify partial fill results
        assertEq(
            amountOut,
            testData.expectedAmountOut,
            "Incorrect partial amount out"
        );
        assertEq(
            ONDO.balanceOf(originalTakerAddress) - ondoBefore,
            testData.expectedAmountOut,
            "ONDO balance mismatch"
        );

        // Verify no tokens left in executor
        assertEq(
            USDC.balanceOf(address(bebopExecutor)), 0, "USDC left in executor"
        );
        assertEq(
            ONDO.balanceOf(address(bebopExecutor)), 0, "ONDO left in executor"
        );
    }

    // Aggregate Order Tests
    function testAggregateOrder() public {
        // Fork at a suitable block for aggregate order testing
        vm.createSelectFork(vm.rpcUrl("mainnet"), 21370890);

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
            expiry: 1746367285,
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

        // ETH will be sent directly with the swap call
        // Fund the test contract with ETH to send with the swap
        vm.deal(address(this), totalTakerAmount);

        // Record initial balances
        uint256 usdcBefore = USDC.balanceOf(originalTakerAddress);

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

        // Encode order and signatures
        bytes memory quoteData = abi.encode(order);
        bytes memory makerSignaturesData = abi.encode(signatures);

        // Create packed params for executor with native ETH as input
        bytes memory params = abi.encodePacked(
            address(0), // tokenIn: native ETH
            USDC_ADDR, // tokenOut
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(BebopExecutor.OrderType.Aggregate),
            uint256(0), // filledTakerAmount: 0 for full fill
            uint32(quoteData.length),
            quoteData,
            uint32(makerSignaturesData.length),
            makerSignaturesData,
            uint8(0) // approvalNeeded: false for native ETH
        );

        // Execute the aggregate swap with ETH value
        uint256 amountOut = bebopExecutor.swap{value: totalTakerAmount}(
            totalTakerAmount, params
        );

        // Verify results
        assertEq(amountOut, totalMakerAmount, "Incorrect amount out");
        assertEq(
            USDC.balanceOf(originalTakerAddress) - usdcBefore,
            totalMakerAmount,
            "USDC balance mismatch"
        );
        assertEq(
            USDC.balanceOf(address(bebopExecutor)), 0, "USDC left in executor"
        );
        assertEq(
            address(bebopExecutor).balance,
            initialExecutorBalance,
            "ETH left in executor should match initial dust amount"
        );
    }

    function testAggregateOrder_PartialFill() public {
        // Fork at a suitable block for aggregate order testing
        vm.createSelectFork(vm.rpcUrl("mainnet"), 21370890);

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
            expiry: 1746367285,
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

        // ETH will be sent directly with the swap call
        // Fund the test contract with ETH to send with the swap
        vm.deal(address(this), partialFillAmount);

        // Record initial balances
        uint256 usdcBefore = USDC.balanceOf(originalTakerAddress);

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

        // Encode order and signatures
        bytes memory quoteData = abi.encode(order);
        bytes memory makerSignaturesData = abi.encode(signatures);

        // Create packed params for executor with partial fill amount
        bytes memory params = abi.encodePacked(
            address(0), // tokenIn: native ETH
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(BebopExecutor.OrderType.Aggregate),
            partialFillAmount, // Specify partial fill amount
            uint32(quoteData.length),
            quoteData,
            uint32(makerSignaturesData.length),
            makerSignaturesData,
            uint8(0) // approvalNeeded: false for native ETH
        );

        // Execute the partial aggregate swap with ETH value
        uint256 amountOut = bebopExecutor.swap{value: partialFillAmount}(
            partialFillAmount, params
        );

        // Verify results - should be proportional to the partial fill
        assertEq(
            amountOut, expectedPartialOutput, "Incorrect partial amount out"
        );
        assertEq(
            USDC.balanceOf(originalTakerAddress) - usdcBefore,
            expectedPartialOutput,
            "USDC balance mismatch for partial fill"
        );
        assertEq(
            USDC.balanceOf(address(bebopExecutor)), 0, "USDC left in executor"
        );
        assertEq(
            address(bebopExecutor).balance,
            initialExecutorBalance,
            "ETH left in executor should match initial dust amount"
        );
    }

    function testInvalidDataLength() public {
        // Fork to ensure consistent setup
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);

        // Deploy Bebop executor with real settlement contract
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);
        bytes memory quoteData = hex"1234567890abcdef";
        bytes memory signature = hex"aabbccdd";

        // Create ABI-encoded MakerSignature array
        IBebopSettlement.MakerSignature[] memory signatures =
            new IBebopSettlement.MakerSignature[](1);
        signatures[0] = IBebopSettlement.MakerSignature({
            signatureBytes: signature,
            flags: uint256(1) // EIP712 signature type
        });
        bytes memory makerSignaturesData = abi.encode(signatures);

        // Create params with correct length first
        uint256 filledTakerAmount = 1e18;
        bytes memory validParams = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(0), // OrderType.Single
            filledTakerAmount,
            uint32(quoteData.length),
            quoteData,
            uint32(makerSignaturesData.length),
            makerSignaturesData,
            uint8(1) // approvalNeeded: true
        );

        // Verify valid params work
        bebopExecutor.decodeParams(validParams);

        // Add extra bytes at the end, this should fail
        bytes memory invalidParams = abi.encodePacked(validParams, hex"ff");

        vm.expectRevert(BebopExecutor.BebopExecutor__InvalidDataLength.selector);
        bebopExecutor.decodeParams(invalidParams);

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
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);

        // Deploy Bebop executor harness
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Load encoded data from test_encode_bebop_single (USDC → ONDO swap)
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_bebop_single");

        // Deal 200 USDC to the executor
        uint256 amountIn = 200000000; // 200 USDC
        deal(USDC_ADDR, address(bebopExecutor), amountIn);

        // Fund the maker with ONDO and approve settlement
        address maker = 0xCe79b081c0c924cb67848723ed3057234d10FC6b;
        uint256 expectedAmountOut = 237212396774431060000; // 237.21 ONDO
        deal(ONDO_ADDR, maker, expectedAmountOut);
        vm.prank(maker);
        ONDO.approve(BEBOP_SETTLEMENT, expectedAmountOut);

        // Record receiver's initial ONDO balance
        address receiver = 0xc5564C13A157E6240659fb81882A28091add8670;
        uint256 ondoBefore = ONDO.balanceOf(receiver);

        // Execute the swap
        uint256 amountOut = bebopExecutor.swap(amountIn, protocolData);

        // Verify results
        assertEq(amountOut, expectedAmountOut, "Incorrect amount out");
        assertEq(
            ONDO.balanceOf(receiver) - ondoBefore,
            expectedAmountOut,
            "ONDO balance mismatch"
        );
        assertEq(
            USDC.balanceOf(address(bebopExecutor)), 0, "USDC left in executor"
        );
        assertEq(
            ONDO.balanceOf(address(bebopExecutor)), 0, "ONDO left in executor"
        );
    }

    function testSwapAggregateIntegration() public {
        // Fork at a suitable block for aggregate order testing
        vm.createSelectFork(vm.rpcUrl("mainnet"), 21370890);

        // Deploy Bebop executor harness
        bebopExecutor =
            new BebopExecutorHarness(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Store the initial ETH balance (dust from forked state)
        uint256 initialExecutorBalance = address(bebopExecutor).balance;

        // Based on real transaction: https://etherscan.io/tx/0xec88410136c287280da87d0a37c1cb745f320406ca3ae55c678dec11996c1b1c
        address orderTaker = 0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6; // This is both taker and receiver in the order
        uint256 ethAmount = 9850000000000000; // 0.00985 WETH
        uint256 expAmountOut = 17969561; // 17.969561 USDC expected output

        // Fund the two makers from the real transaction with USDC
        address maker1 = 0x67336Cec42645F55059EfF241Cb02eA5cC52fF86;
        address maker2 = 0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE;

        deal(USDC_ADDR, maker1, 10607211); // Maker 1 provides 10.607211 USDC
        deal(USDC_ADDR, maker2, 7362350); // Maker 2 provides 7.362350 USDC

        // Makers approve settlement contract
        vm.prank(maker1);
        IERC20(USDC_ADDR).approve(BEBOP_SETTLEMENT, type(uint256).max);
        vm.prank(maker2);
        IERC20(USDC_ADDR).approve(BEBOP_SETTLEMENT, type(uint256).max);

        // Fund ALICE with ETH as it will send the transaction
        vm.deal(ALICE, ethAmount);
        vm.startPrank(ALICE);

        // Load encoded data from test_encode_bebop_aggregate (ETH → USDC multi-maker swap)
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_bebop_aggregate");

        // Record initial USDC balance
        uint256 usdcBefore = IERC20(USDC_ADDR).balanceOf(orderTaker);

        // Execute the swap with native ETH
        uint256 amountOut =
            bebopExecutor.swap{value: ethAmount}(ethAmount, protocolData);

        // Verify results
        assertEq(amountOut, expAmountOut, "Incorrect amount out");
        assertEq(
            IERC20(USDC_ADDR).balanceOf(orderTaker) - usdcBefore,
            expAmountOut,
            "USDC balance mismatch"
        );
        assertEq(
            IERC20(USDC_ADDR).balanceOf(address(bebopExecutor)),
            0,
            "USDC left in executor"
        );
        assertEq(
            address(bebopExecutor).balance,
            initialExecutorBalance,
            "ETH left in executor should match initial dust amount"
        );
        vm.stopPrank();
    }
}
