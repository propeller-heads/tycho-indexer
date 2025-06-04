// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../../interfaces/IExecutor.sol";
import "../RestrictTransferFrom.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";

/// @dev Bebop settlement interface for PMM RFQ swaps
interface IBebopSettlement {
    struct Single {
        uint256 expiry;
        address taker_address;
        address maker_address;
        uint256 maker_nonce;
        address taker_token;
        address maker_token;
        uint256 taker_amount;
        uint256 maker_amount;
        address receiver;
        uint256 packed_commands;
        uint256 flags;
    }

    struct Multi {
        uint256 expiry;
        address taker_address;
        address maker_address;
        uint256 maker_nonce;
        address[] taker_tokens;
        address[] maker_tokens;
        uint256[] taker_amounts;
        uint256[] maker_amounts;
        address receiver;
        uint256 packed_commands;
        uint256 flags;
    }

    struct Aggregate {
        uint256 expiry;
        address taker_address;
        uint256 taker_nonce;
        address[] taker_tokens;
        uint256[] taker_amounts;
        address[] maker_addresses;
        address[][] maker_tokens;
        uint256[][] maker_amounts;
        address receiver;
        uint256 packed_commands;
        uint256 flags;
    }

    struct MakerSignature {
        uint8 signatureType;
        bytes signatureBytes;
    }

    struct TakerSignature {
        uint8 signatureType;
        bytes signatureBytes;
    }

    /// @notice Executes a single RFQ order
    function swapSingle(
        Single calldata order,
        MakerSignature calldata makerSignature,
        uint256 filledTakerAmount
    ) external payable;

    /// @notice Executes a multi-token RFQ order
    function swapMulti(
        Multi calldata order,
        MakerSignature calldata makerSignature,
        uint256[] calldata filledTakerAmounts
    ) external payable;

    /// @notice Executes an aggregate RFQ order with multiple makers
    function swapAggregate(
        Aggregate calldata order,
        MakerSignature[] calldata makerSignatures,
        uint256[] calldata filledTakerAmounts
    ) external payable;
}

/// @title BebopExecutor
/// @notice Executor for Bebop PMM RFQ (Request for Quote) swaps
/// @dev Handles Single, Multi, and Aggregate RFQ swaps through Bebop settlement contract
contract BebopExecutor is IExecutor, IExecutorErrors, RestrictTransferFrom {
    using Math for uint256;
    using SafeERC20 for IERC20;

    /// @notice Bebop order types
    enum OrderType {
        Single, // 0: Single token pair trade
        Multi, // 1: Multi-token trade with single maker
        Aggregate // 2: Multi-maker trade

    }

    /// @notice Bebop-specific errors
    error BebopExecutor__SettlementFailed();
    error BebopExecutor__UnsupportedOrderType(uint8 orderType);
    error BebopExecutor__InvalidDataLength();

    /// @notice The Bebop settlement contract address
    address public immutable bebopSettlement;


    constructor(
        address _bebopSettlement,
        address _permit2
    ) RestrictTransferFrom(_permit2) {
        bebopSettlement = _bebopSettlement;
    }

    /// @notice Executes a swap through Bebop's PMM RFQ system
    /// @param givenAmount The amount of input token to swap
    /// @param data Encoded swap data containing tokens and quote information
    /// @return calculatedAmount The amount of output token received
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        override
        returns (uint256 calculatedAmount)
    {
        // Decode the packed data
        (
            address tokenIn,
            address tokenOut,
            TransferType transferType,
            OrderType orderType,
            bytes memory quoteData,
            uint8 signatureType,
            bytes memory signature,
            bool approvalNeeded
        ) = _decodeData(data);

        _transfer(address(this), transferType, tokenIn, givenAmount);

        if (approvalNeeded) {
            // slither-disable-next-line unused-return
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
        }

        // Execute RFQ swap based on order type
        if (orderType == OrderType.Single) {
            calculatedAmount = _executeSingleRFQ(
                tokenIn,
                tokenOut,
                givenAmount,
                quoteData,
                signatureType,
                signature
            );
        } else {
            revert BebopExecutor__UnsupportedOrderType(uint8(orderType));
        }
    }

    /// @dev Executes a Single RFQ swap through Bebop settlement
    function _executeSingleRFQ(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        bytes memory quoteData,
        uint8 signatureType,
        bytes memory signature
    ) private returns (uint256 amountOut) {
        // Decode the order and signature from quoteData
        (
            IBebopSettlement.Single memory order,
            IBebopSettlement.MakerSignature memory sig
        ) = _decodeQuoteData(quoteData, signatureType, signature);

        // Record balances before swap to calculate amountOut
        uint256 balanceBefore = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        // Handle ETH vs ERC20 execution
        if (tokenIn == address(0)) {
            // For ETH input, use msg.value
            try IBebopSettlement(bebopSettlement).swapSingle{value: amountIn}(
                order, sig, amountIn
            ) {
                // Success, calculate amountOut from balance difference
            } catch {
                revert BebopExecutor__SettlementFailed();
            }
        } else {
            // For ERC20 input, call settlement
            try IBebopSettlement(bebopSettlement).swapSingle(
                order, sig, amountIn
            ) {
                // Success, calculate amountOut from balance difference
            } catch {
                revert BebopExecutor__SettlementFailed();
            }
        }

        // Calculate actual amount received
        uint256 balanceAfter = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        amountOut = balanceAfter - balanceBefore;
    }

    /// @dev Decodes quote data into Bebop order and signature structures
    function _decodeQuoteData(
        bytes memory quoteData,
        uint8 signatureType,
        bytes memory signatureBytes
    )
        private
        pure
        returns (
            IBebopSettlement.Single memory order,
            IBebopSettlement.MakerSignature memory signature
        )
    {
        // Decode the order from quoteData
        order = abi.decode(quoteData, (IBebopSettlement.Single));

        // Create signature struct with configurable type
        signature = IBebopSettlement.MakerSignature({
            signatureType: signatureType,
            signatureBytes: signatureBytes
        });
    }

    /// @dev Decodes the packed calldata
    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            TransferType transferType,
            OrderType orderType,
            bytes memory quoteData,
            uint8 signatureType,
            bytes memory signature,
            bool approvalNeeded
        )
    {
        // Need at least 52 bytes for the fixed fields before we can read anything
        if (data.length < 52) revert BebopExecutor__InvalidDataLength();

        // Get the variable lengths so we know what to expect
        uint32 quoteDataLength = uint32(bytes4(data[42:46]));
        uint32 signatureLength = uint32(bytes4(data[47 + quoteDataLength:51 + quoteDataLength]));

        // Make sure we got exactly what we expected, no more no less
        uint256 expectedLength = 52 + quoteDataLength + signatureLength;
        if (data.length != expectedLength) {
            revert BebopExecutor__InvalidDataLength();
        }

        // All good, decode everything
        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        transferType = TransferType(uint8(data[40]));
        orderType = OrderType(uint8(data[41]));
        
        // Quote data starts after the length field
        quoteData = data[46:46 + quoteDataLength];
        
        // Signature stuff comes after the quote data
        signatureType = uint8(data[46 + quoteDataLength]);
        signature = data[51 + quoteDataLength:51 + quoteDataLength + signatureLength];
        
        // Last byte tells us if we need approval
        approvalNeeded = data[51 + quoteDataLength + signatureLength] != 0;
    }
}
