// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "@src/executors/BebopExecutor.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {Test} from "forge-std/Test.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SafeERC20} from
    "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {BebopSettlementMock} from "../mock/BebopSettlementMock.sol";

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

contract BebopExecutorExposed is BebopExecutor {
    constructor(address _bebopSettlement, address _permit2)
        BebopExecutor(_bebopSettlement, _permit2)
    {}

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

        // Deploy Bebop executor with real settlement contract
        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);
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

        // Deploy our mock Bebop settlement and use vm.etch to replace the real one
        BebopSettlementMock mockSettlement = new BebopSettlementMock();
        bytes memory mockCode = address(mockSettlement).code;
        vm.etch(BEBOP_SETTLEMENT, mockCode);

        // Deploy Bebop executor with the (now mocked) settlement contract
        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Create test data from real mainnet transaction
        // https://etherscan.io/tx/0x6279bc970273b6e526e86d9b69133c2ca1277e697ba25375f5e6fc4df50c0c94
        address originalTakerAddress =
            0xc5564C13A157E6240659fb81882A28091add8670;

        // Now we can use the original order data since our mock skips taker validation
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

        // Deploy our mock Bebop settlement and use vm.etch to replace the real one
        BebopSettlementMock mockSettlement = new BebopSettlementMock();
        bytes memory mockCode = address(mockSettlement).code;
        vm.etch(BEBOP_SETTLEMENT, mockCode);

        // Deploy Bebop executor with the (now mocked) settlement contract
        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

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

    // Aggregate Order Helper Functions
    function _setupAggregateOrder(AggregateOrderTestData memory testData)
        internal
    {
        // Fund the sender with all input tokens
        for (uint256 i = 0; i < testData.order.taker_tokens.length; i++) {
            deal(
                testData.order.taker_tokens[i],
                testData.sender,
                testData.amountsIn[i]
            );

            // Approve executor
            vm.prank(testData.sender);
            IERC20(testData.order.taker_tokens[i]).approve(
                address(bebopExecutor), testData.amountsIn[i]
            );
        }
    }

    // Aggregate Order Tests
    function testAggregateOrder_MultipleMakers() public {
        // Fork at block 21732669 (around the time of the etherscan tx)
        vm.createSelectFork(vm.rpcUrl("mainnet"), 21732669);

        // Deploy our mock Bebop settlement and use vm.etch to replace the real one
        BebopSettlementMock mockSettlement = new BebopSettlementMock();
        bytes memory mockCode = address(mockSettlement).code;
        vm.etch(BEBOP_SETTLEMENT, mockCode);

        // Deploy Bebop executor with the (now mocked) settlement contract
        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);

        // Based on etherscan tx data
        address originalTakerAddress =
            0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6;
        address maker1 = 0x67336Cec42645F55059EfF241Cb02eA5cC52fF86;
        address maker2 = 0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE;

        // Build aggregate order: WETH -> USDC from two makers
        address[] memory maker_addresses = new address[](2);
        maker_addresses[0] = maker1;
        maker_addresses[1] = maker2;

        // Single input token (WETH) - aggregate orders have single taker token
        address[] memory taker_tokens = new address[](1);
        taker_tokens[0] = WETH_ADDR;

        uint256[] memory taker_amounts = new uint256[](1);
        taker_amounts[0] = 9850000000000000; // Total WETH amount (sum of both makers)

        // Output tokens from each maker
        address[][] memory maker_tokens = new address[][](2);
        maker_tokens[0] = new address[](1);
        maker_tokens[0][0] = USDC_ADDR;
        maker_tokens[1] = new address[](1);
        maker_tokens[1][0] = USDC_ADDR;

        uint256[][] memory maker_amounts = new uint256[][](2);
        maker_amounts[0] = new uint256[](1);
        maker_amounts[0][0] = 10607211; // ~10.6 USDC from maker1
        maker_amounts[1] = new uint256[](1);
        maker_amounts[1][0] = 7362350; // ~7.36 USDC from maker2

        AggregateOrderTestData memory testData = AggregateOrderTestData({
            forkBlock: 21732669,
            order: IBebopSettlement.Aggregate({
                expiry: 1746367285,
                taker_address: originalTakerAddress,
                taker_nonce: 0, // Aggregate orders use taker_nonce
                taker_tokens: taker_tokens,
                taker_amounts: taker_amounts,
                maker_addresses: maker_addresses,
                maker_tokens: maker_tokens,
                maker_amounts: maker_amounts,
                receiver: originalTakerAddress,
                packed_commands: 0x00040004,
                flags: 95769172144825922628485191511070792431742484643425438763224908097896054784000
            }),
            signatures: new bytes[](2),
            amountsIn: new uint256[](1),
            filledTakerAmounts: new uint256[](1),
            expectedAmountsOut: new uint256[](1),
            sender: originalTakerAddress,
            receiver: originalTakerAddress
        });

        // Signatures from the etherscan tx
        testData.signatures[0] =
            hex"d5abb425f9bac1f44d48705f41a8ab9cae207517be8553d2c03b06a88995f2f351ab8ce7627a87048178d539dd64fd2380245531a0c8e43fdc614652b1f32fc71c";
        testData.signatures[1] =
            hex"f38c698e48a3eac48f184bc324fef0b135ee13705ab38cc0bbf5a792f21002f051e445b9e7d57cf24c35e17629ea35b3263591c4abf8ca87ffa44b41301b89c41b";

        // Total amounts
        uint256 totalWethIn = taker_amounts[0];
        uint256 totalUsdcOut = maker_amounts[0][0] + maker_amounts[1][0];

        testData.amountsIn[0] = totalWethIn;
        testData.filledTakerAmounts[0] = 0; // Full fill
        testData.expectedAmountsOut[0] = totalUsdcOut;

        // Fund the original taker with WETH
        deal(WETH_ADDR, originalTakerAddress, totalWethIn);

        // Fund makers with USDC and have them approve the settlement
        deal(USDC_ADDR, maker1, maker_amounts[0][0]);
        deal(USDC_ADDR, maker2, maker_amounts[1][0]);

        vm.prank(maker1);
        USDC.approve(BEBOP_SETTLEMENT, type(uint256).max);
        vm.prank(maker2);
        USDC.approve(BEBOP_SETTLEMENT, type(uint256).max);

        // Original taker approves the test contract (router) to spend their tokens
        vm.prank(originalTakerAddress);
        WETH.approve(address(this), totalWethIn);

        // Test contract (router) pulls tokens from original taker and sends to executor
        WETH.transferFrom(
            originalTakerAddress, address(bebopExecutor), totalWethIn
        );

        // Record initial balances
        uint256 usdcBefore = USDC.balanceOf(originalTakerAddress);

        // Execute the aggregate swap
        bytes memory quoteData = abi.encode(testData.order);
        IBebopSettlement.MakerSignature[] memory signatures =
            new IBebopSettlement.MakerSignature[](2);
        signatures[0] = IBebopSettlement.MakerSignature({
            signatureBytes: testData.signatures[0],
            flags: uint256(0) // ECDSA from etherscan data
        });
        signatures[1] = IBebopSettlement.MakerSignature({
            signatureBytes: testData.signatures[1],
            flags: uint256(0) // ECDSA
        });
        bytes memory makerSignaturesData = abi.encode(signatures);

        // Encode params for the aggregate order
        bytes memory params = abi.encodePacked(
            WETH_ADDR, // token_in
            USDC_ADDR, // token_out
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(BebopExecutor.OrderType.Aggregate),
            uint256(0), // filledTakerAmount: 0 for full fill
            uint32(quoteData.length),
            quoteData,
            uint32(makerSignaturesData.length),
            makerSignaturesData,
            uint8(1) // approvalNeeded: true
        );

        // Execute swap
        uint256 amountOut = bebopExecutor.swap(totalWethIn, params);

        // Verify results
        assertEq(amountOut, totalUsdcOut, "Incorrect amount out");
        assertEq(
            USDC.balanceOf(originalTakerAddress) - usdcBefore,
            totalUsdcOut,
            "USDC balance mismatch"
        );

        // Verify no tokens left in executor
        assertEq(
            WETH.balanceOf(address(bebopExecutor)), 0, "WETH left in executor"
        );
        assertEq(
            USDC.balanceOf(address(bebopExecutor)), 0, "USDC left in executor"
        );
    }

    function testInvalidDataLength() public {
        // Fork to ensure consistent setup
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22667985);

        // Deploy Bebop executor with real settlement contract
        bebopExecutor =
            new BebopExecutorExposed(BEBOP_SETTLEMENT, PERMIT2_ADDRESS);
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
