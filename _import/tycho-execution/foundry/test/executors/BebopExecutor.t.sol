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
            bool approvalNeeded
        )
    {
        return _decodeData(data);
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

        // Transfer tokens to executor
        _transfer(address(this), transferType, tokenIn, givenAmount);

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
        }

        // Record balances before swap to calculate amountOut
        uint256 balanceBefore = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        // Execute the swap with ETH value if needed
        uint256 ethValue = tokenIn == address(0) ? actualFilledTakerAmount : 0;

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
        bool approvalNeeded
    ) internal virtual override returns (uint256 amountOut) {
        // // Decode the Aggregate order
        // IBebopSettlement.Aggregate memory order =
        //     abi.decode(quoteData, (IBebopSettlement.Aggregate));

        // // Decode the MakerSignature array (can contain multiple signatures for Aggregate orders)
        // IBebopSettlement.MakerSignature[] memory signatures =
        //     abi.decode(makerSignaturesData, (IBebopSettlement.MakerSignature[]));

        // // Aggregate orders should have at least one signature
        // if (signatures.length == 0) {
        //     revert BebopExecutor__InvalidInput();
        // }

        // // For aggregate orders, calculate total taker amount across all makers
        // uint256 totalTakerAmount = 0;
        // for (uint256 i = 0; i < order.taker_amounts.length; i++) {
        //     totalTakerAmount += order.taker_amounts[i][0];
        // }
        // uint256 actualFilledTakerAmount = _getActualFilledTakerAmount(
        //     givenAmount, totalTakerAmount, filledTakerAmount
        // );

        // // Transfer tokens to executor
        // _transfer(address(this), transferType, tokenIn, givenAmount);

        // // For testing: transfer tokens from executor to taker address
        // // This simulates the taker having the tokens with approval
        // if (tokenIn != address(0)) {
        //     IERC20(tokenIn).safeTransfer(
        //         order.taker_address, actualFilledTakerAmount
        //     );

        //     // Approve settlement from taker's perspective
        //     // Stop any existing prank first
        //     vm.stopPrank();
        //     vm.startPrank(order.taker_address);
        //     IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
        //     vm.stopPrank();
        // }

        // // Record balances before swap to calculate amountOut
        // uint256 balanceBefore = tokenOut == address(0)
        //     ? order.receiver.balance
        //     : IERC20(tokenOut).balanceOf(order.receiver);

        // // Execute the swap with ETH value if needed
        // uint256 ethValue = tokenIn == address(0) ? actualFilledTakerAmount : 0;

        // // IMPORTANT: Prank as the taker address to pass the settlement validation
        // vm.stopPrank();
        // vm.startPrank(order.taker_address);

        // // Set block timestamp to ensure order is valid regardless of fork block
        // uint256 currentTimestamp = block.timestamp;
        // vm.warp(order.expiry - 1); // Set timestamp to just before expiry

        // // Execute the swap - tokens are now in taker's wallet with approval
        // // slither-disable-next-line arbitrary-send-eth
        // IBebopSettlement(bebopSettlement).swapAggregate{value: ethValue}(
        //     order, signatures, actualFilledTakerAmount
        // );

        // // Restore original timestamp
        // vm.warp(currentTimestamp);
        // vm.stopPrank();

        // // Calculate actual amount received
        // uint256 balanceAfter = tokenOut == address(0)
        //     ? order.receiver.balance
        //     : IERC20(tokenOut).balanceOf(order.receiver);

        // amountOut = balanceAfter - balanceBefore;
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

    // Allow test contract to receive ETH
    receive() external payable {}

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
        vm.skip(true);
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
}
