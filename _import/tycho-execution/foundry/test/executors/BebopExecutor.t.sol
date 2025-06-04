// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "@src/executors/BebopExecutor.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {Test, console2} from "forge-std/Test.sol";
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

contract BebopExecutorExposed is BebopExecutor {
    constructor(
        address _bebopSettlement,
        address _nativeToken,
        address _permit2
    ) BebopExecutor(_bebopSettlement, _nativeToken, _permit2) {}

    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            address tokenIn,
            address tokenOut,
            RestrictTransferFrom.TransferType transferType,
            BebopExecutor.OrderType orderType,
            bytes memory quoteData,
            uint8 signatureType,
            bytes memory signature,
            bool approvalNeeded
        )
    {
        return _decodeData(data);
    }
}

/// @notice Mock Bebop settlement contract for testing
contract MockBebopSettlement is Test, Constants {
    function swapSingle(
        IBebopSettlement.Single calldata order,
        IBebopSettlement.MakerSignature calldata, /* makerSignature */
        uint256 filledTakerAmount
    ) external payable returns (uint256 filledMakerAmount) {
        // Basic validation
        require(order.expiry >= block.timestamp, "Order expired");
        require(filledTakerAmount <= order.taker_amount, "Exceeds order amount");

        // Mock implementation handles input tokens
        if (order.taker_token == ETH_ADDR_FOR_CURVE) {
            // For ETH input, validate msg.value
            require(msg.value >= filledTakerAmount, "Insufficient ETH sent");
        } else {
            // For ERC20 input, transfer from sender
            IERC20(order.taker_token).transferFrom(
                msg.sender, address(this), filledTakerAmount
            );
        }

        // Calculate proportional maker amount
        filledMakerAmount =
            (filledTakerAmount * order.maker_amount) / order.taker_amount;

        // Send output tokens to receiver, or back to sender if receiver is zero
        address recipient =
            order.receiver != address(0) ? order.receiver : msg.sender;

        if (order.maker_token == ETH_ADDR_FOR_CURVE) {
            // For ETH output, send ETH directly
            vm.deal(recipient, recipient.balance + filledMakerAmount);
        } else {
            // For ERC20 output, mint tokens to recipient
            deal(
                order.maker_token,
                recipient,
                IERC20(order.maker_token).balanceOf(recipient)
                    + filledMakerAmount
            );
        }

        return filledMakerAmount;
    }
}

contract BebopExecutorTest is Constants, Permit2TestHelper, TestUtils {
    using SafeERC20 for IERC20;

    BebopExecutorExposed bebopExecutor;
    MockBebopSettlement mockBebopSettlement;

    MockToken WETH;
    MockToken USDC;

    function setUp() public {
        // Deploy mock tokens
        WETH = new MockToken("Wrapped Ether", "WETH", 18);
        USDC = new MockToken("USD Coin", "USDC", 6);

        // Deploy at expected addresses
        vm.etch(WETH_ADDR, address(WETH).code);
        vm.etch(USDC_ADDR, address(USDC).code);

        // Update references
        WETH = MockToken(WETH_ADDR);
        USDC = MockToken(USDC_ADDR);

        // Deploy mock contracts
        mockBebopSettlement = new MockBebopSettlement();

        // Deploy Bebop executor
        bebopExecutor = new BebopExecutorExposed(
            address(mockBebopSettlement),
            ETH_ADDR_FOR_CURVE, // Native token address
            PERMIT2_ADDRESS
        );

        // Fund test accounts
        WETH.mint(address(this), 100e18);
        USDC.mint(address(this), 100_000e6); // Mint USDC to test contract
        USDC.mint(address(mockBebopSettlement), 100_000e6);
    }

    // Allow test contract to receive ETH
    receive() external payable {}

    function testDecodeParams() public view {
        bytes memory quoteData = hex"1234567890abcdef";
        bytes memory signature = hex"aabbccdd";

        bytes memory params = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(0), // OrderType.Single
            uint32(quoteData.length),
            quoteData,
            uint8(0), // signatureType: ECDSA
            uint32(signature.length),
            signature,
            uint8(1) // approvalNeeded: true
        );

        (
            address tokenIn,
            address tokenOut,
            RestrictTransferFrom.TransferType transferType,
            BebopExecutor.OrderType orderType,
            bytes memory decodedQuoteData,
            uint8 decodedSignatureType,
            bytes memory decodedSignature,
            bool decodedApprovalNeeded
        ) = bebopExecutor.decodeParams(params);

        assertEq(tokenIn, WETH_ADDR);
        assertEq(tokenOut, USDC_ADDR);
        assertEq(
            uint8(transferType),
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
        assertEq(uint8(orderType), uint8(BebopExecutor.OrderType.Single));
        assertEq(keccak256(decodedQuoteData), keccak256(quoteData));
        assertEq(decodedSignatureType, 0); // ECDSA signature type
        assertEq(keccak256(decodedSignature), keccak256(signature));
        assertTrue(decodedApprovalNeeded); // Approval needed should be true
    }

    function testRFQSwap() public {
        uint256 amountIn = 1e18; // 1 WETH
        uint256 expectedAmountOut = 3000e6; // 3000 USDC

        // Create a valid Bebop order
        IBebopSettlement.Single memory order = IBebopSettlement.Single({
            expiry: block.timestamp + 3600,
            taker_address: address(0), // Any taker
            maker_address: address(mockBebopSettlement),
            maker_nonce: 1,
            taker_token: WETH_ADDR,
            maker_token: USDC_ADDR,
            taker_amount: amountIn,
            maker_amount: expectedAmountOut,
            receiver: address(bebopExecutor), // Output should go to executor
            packed_commands: 0,
            flags: 0
        });

        // Encode order as quote data
        bytes memory quoteData = abi.encode(order);
        bytes memory signature = hex"aabbccdd"; // Mock signature

        bytes memory params = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(0), // OrderType.Single
            uint32(quoteData.length),
            quoteData,
            uint8(0), // signatureType: ECDSA
            uint32(signature.length),
            signature,
            uint8(1) // approvalNeeded: true
        );

        // Transfer WETH to executor first
        WETH.transfer(address(bebopExecutor), amountIn);

        // Execute swap
        uint256 executorBalanceBefore = USDC.balanceOf(address(bebopExecutor));
        uint256 amountOut = bebopExecutor.swap(amountIn, params);
        uint256 executorBalanceAfter = USDC.balanceOf(address(bebopExecutor));

        // Check that tokens ended up in the executor for the router to collect
        assertEq(amountOut, expectedAmountOut);
        assertEq(executorBalanceAfter - executorBalanceBefore, amountOut);
    }

    function testETHInput() public {
        uint256 amountIn = 1e18; // 1 ETH
        uint256 expectedAmountOut = 3000e6; // 3000 USDC

        // Create a valid Bebop order with ETH input
        IBebopSettlement.Single memory order = IBebopSettlement.Single({
            expiry: block.timestamp + 3600,
            taker_address: address(0), // Any taker
            maker_address: address(mockBebopSettlement),
            maker_nonce: 1,
            taker_token: ETH_ADDR_FOR_CURVE, // ETH input
            maker_token: USDC_ADDR,
            taker_amount: amountIn,
            maker_amount: expectedAmountOut,
            receiver: address(bebopExecutor), // Output should go to executor
            packed_commands: 0,
            flags: 0
        });

        // Encode order as quote data
        bytes memory quoteData = abi.encode(order);
        bytes memory signature = hex"aabbccdd"; // Mock signature

        bytes memory params = abi.encodePacked(
            ETH_ADDR_FOR_CURVE, // ETH input
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.None), // ETH comes via msg.value
            uint8(0), // OrderType.Single
            uint32(quoteData.length),
            quoteData,
            uint8(0), // signatureType: ECDSA
            uint32(signature.length),
            signature,
            uint8(0) // approvalNeeded: false for ETH
        );

        // Fund test contract with ETH
        vm.deal(address(this), 10e18);

        uint256 executorBalanceBefore = USDC.balanceOf(address(bebopExecutor));
        uint256 amountOut =
            bebopExecutor.swap{value: amountIn}(amountIn, params);
        uint256 executorBalanceAfter = USDC.balanceOf(address(bebopExecutor));

        // Check that tokens ended up in the executor for the router to collect
        assertEq(amountOut, expectedAmountOut);
        assertEq(executorBalanceAfter - executorBalanceBefore, amountOut);
    }

    function testETHOutput() public {
        uint256 amountIn = 1000e6; // 1000 USDC
        uint256 expectedAmountOut = 1e18; // 1 ETH

        // Create a valid Bebop order with ETH output
        IBebopSettlement.Single memory order = IBebopSettlement.Single({
            expiry: block.timestamp + 3600,
            taker_address: address(0), // Any taker
            maker_address: address(mockBebopSettlement),
            maker_nonce: 1,
            taker_token: USDC_ADDR,
            maker_token: ETH_ADDR_FOR_CURVE, // ETH output
            taker_amount: amountIn,
            maker_amount: expectedAmountOut,
            receiver: address(bebopExecutor), // Output should go to executor
            packed_commands: 0,
            flags: 0
        });

        // Encode order as quote data
        bytes memory quoteData = abi.encode(order);
        bytes memory signature = hex"aabbccdd"; // Mock signature

        bytes memory params = abi.encodePacked(
            USDC_ADDR,
            ETH_ADDR_FOR_CURVE, // ETH output
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(0), // OrderType.Single
            uint32(quoteData.length),
            quoteData,
            uint8(0), // signatureType: ECDSA
            uint32(signature.length),
            signature,
            uint8(1) // approvalNeeded: true for USDC
        );

        // Transfer USDC to executor first
        USDC.transfer(address(bebopExecutor), amountIn);

        uint256 executorEthBalanceBefore = address(bebopExecutor).balance;
        uint256 amountOut = bebopExecutor.swap(amountIn, params);
        uint256 executorEthBalanceAfter = address(bebopExecutor).balance;

        // Make sure the ETH ended up in the executor for the router to collect
        assertEq(amountOut, expectedAmountOut);
        assertEq(executorEthBalanceAfter - executorEthBalanceBefore, amountOut);
    }

    function testExpiredQuote() public {
        uint256 amountIn = 1e18;
        uint256 expectedAmountOut = 3000e6;

        // Create an order with expired timestamp
        IBebopSettlement.Single memory order = IBebopSettlement.Single({
            expiry: block.timestamp - 1, // Already expired
            taker_address: address(0),
            maker_address: address(mockBebopSettlement),
            maker_nonce: 1,
            taker_token: WETH_ADDR,
            maker_token: USDC_ADDR,
            taker_amount: amountIn,
            maker_amount: expectedAmountOut,
            receiver: address(bebopExecutor), // Output should go to executor
            packed_commands: 0,
            flags: 0
        });

        bytes memory quoteData = abi.encode(order);
        bytes memory signature = hex"aabbccdd";

        bytes memory params = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(0), // OrderType.Single
            uint32(quoteData.length),
            quoteData,
            uint8(0), // signatureType: ECDSA
            uint32(signature.length),
            signature,
            uint8(1) // approvalNeeded: true
        );

        // Transfer WETH to executor
        WETH.transfer(address(bebopExecutor), amountIn);

        // Should revert due to expired order
        vm.expectRevert(BebopExecutor.BebopExecutor__SettlementFailed.selector);
        bebopExecutor.swap(amountIn, params);
    }

    function testInvalidDataLength() public {
        bytes memory quoteData = hex"1234567890abcdef";
        bytes memory signature = hex"aabbccdd";

        // Create params with correct length first
        bytes memory validParams = abi.encodePacked(
            WETH_ADDR,
            USDC_ADDR,
            uint8(RestrictTransferFrom.TransferType.Transfer),
            uint8(0), // OrderType.Single
            uint32(quoteData.length),
            quoteData,
            uint8(0), // signatureType: ECDSA
            uint32(signature.length),
            signature,
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
            // Missing rest of the data
        );
        
        vm.expectRevert(BebopExecutor.BebopExecutor__InvalidDataLength.selector);
        bebopExecutor.decodeParams(tooShortParams);
    }
}
