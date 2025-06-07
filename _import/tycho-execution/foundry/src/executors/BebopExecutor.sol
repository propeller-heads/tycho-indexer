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

    /// @notice Executes a single RFQ order using tokens from contract balance
    function swapSingleFromContract(
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
    error BebopExecutor__InvalidDataLength();

    /// @notice The Bebop settlement contract address
    address public immutable bebopSettlement;

    constructor(address _bebopSettlement, address _permit2)
        RestrictTransferFrom(_permit2)
    {
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

        // For Single orders, transfer directly to settlement and use swapSingleFromContract
        // For Multi/Aggregate orders, transfer to executor and approve settlement
        if (orderType == OrderType.Single) {
            _transfer(bebopSettlement, transferType, tokenIn, givenAmount);
        } else {
            _transfer(address(this), transferType, tokenIn, givenAmount);

            if (approvalNeeded) {
                // slither-disable-next-line unused-return
                IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
            }
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
        } else if (orderType == OrderType.Multi) {
            calculatedAmount = _executeMultiRFQ(
                tokenIn,
                tokenOut,
                givenAmount,
                quoteData,
                signatureType,
                signature
            );
        } else if (orderType == OrderType.Aggregate) {
            calculatedAmount = _executeAggregateRFQ(
                tokenIn,
                tokenOut,
                givenAmount,
                quoteData,
                signatureType,
                signature
            );
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

        // Execute the swap with ETH value if needed
        uint256 ethValue = tokenIn == address(0) ? amountIn : 0;

        // Use swapSingleFromContract since tokens are already in the settlement contract
        IBebopSettlement(bebopSettlement).swapSingleFromContract{
            value: ethValue
        }(order, sig, amountIn);

        // Calculate actual amount received
        uint256 balanceAfter = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        amountOut = balanceAfter - balanceBefore;

        // Note: We don't validate amountOut against order.maker_amount because:
        // 1. The settlement contract already validates the quote and amounts
        // 2. For partial fills, output is proportional to input
        // 3. The router validates against minAmountOut for slippage protection
    }

    /// @dev Executes a Multi RFQ swap through Bebop settlement
    function _executeMultiRFQ(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        bytes memory quoteData,
        uint8 signatureType,
        bytes memory signature
    ) private returns (uint256 amountOut) {
        // Decode the Multi order
        IBebopSettlement.Multi memory order =
            abi.decode(quoteData, (IBebopSettlement.Multi));

        // Create signature struct
        IBebopSettlement.MakerSignature memory sig = IBebopSettlement
            .MakerSignature({
            signatureType: signatureType,
            signatureBytes: signature
        });

        // Find which token index we're swapping
        uint256 tokenInIndex = type(uint256).max;
        uint256 tokenOutIndex = type(uint256).max;

        for (uint256 i = 0; i < order.taker_tokens.length; i++) {
            if (order.taker_tokens[i] == tokenIn) {
                tokenInIndex = i;
                break;
            }
        }

        for (uint256 i = 0; i < order.maker_tokens.length; i++) {
            if (order.maker_tokens[i] == tokenOut) {
                tokenOutIndex = i;
                break;
            }
        }

        // Prepare filled amounts array (only fill the token we're swapping)
        uint256[] memory filledTakerAmounts =
            new uint256[](order.taker_tokens.length);
        filledTakerAmounts[tokenInIndex] = amountIn;

        // Record balance before swap
        uint256 balanceBefore = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        // Execute the swap
        uint256 ethValue = tokenIn == address(0) ? amountIn : 0;

        // Execute the swap (tokens are in executor, approved to settlement)
        IBebopSettlement(bebopSettlement).swapMulti{value: ethValue}(
            order, sig, filledTakerAmounts
        );

        // Calculate actual amount received
        uint256 balanceAfter = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        amountOut = balanceAfter - balanceBefore;
    }

    /// @dev Executes an Aggregate RFQ swap through Bebop settlement
    function _executeAggregateRFQ(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        bytes memory quoteData,
        uint8 signatureType,
        bytes memory signatureData
    ) private returns (uint256 amountOut) {
        // For aggregate orders, we need to decode both the order and multiple signatures
        // The signatureData contains all maker signatures encoded
        (
            IBebopSettlement.Aggregate memory order,
            IBebopSettlement.MakerSignature[] memory signatures
        ) = _decodeAggregateData(quoteData, signatureType, signatureData);

        // Find which token index we're swapping
        uint256 tokenInIndex = type(uint256).max;
        for (uint256 i = 0; i < order.taker_tokens.length; i++) {
            if (order.taker_tokens[i] == tokenIn) {
                tokenInIndex = i;
                break;
            }
        }

        // Prepare filled amounts array
        uint256[] memory filledTakerAmounts =
            new uint256[](order.taker_tokens.length);
        filledTakerAmounts[tokenInIndex] = amountIn;

        // Record balance before swap for all possible output tokens from all makers
        uint256 balanceBefore = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        // Execute the swap
        uint256 ethValue = tokenIn == address(0) ? amountIn : 0;

        // Execute the swap (tokens are in executor, approved to settlement)
        IBebopSettlement(bebopSettlement).swapAggregate{value: ethValue}(
            order, signatures, filledTakerAmounts
        );

        // Calculate actual amount received
        uint256 balanceAfter = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        amountOut = balanceAfter - balanceBefore;
    }

    /// @dev Decodes aggregate order data and signatures
    function _decodeAggregateData(
        bytes memory quoteData,
        uint8 signatureType,
        bytes memory signatureData
    )
        private
        pure
        returns (
            IBebopSettlement.Aggregate memory order,
            IBebopSettlement.MakerSignature[] memory signatures
        )
    {
        order = abi.decode(quoteData, (IBebopSettlement.Aggregate));

        // Decode multiple signatures
        // First 4 bytes contain the number of signatures
        uint32 numSignatures;
        assembly {
            numSignatures := mload(add(signatureData, 0x20))
            numSignatures := and(numSignatures, 0xffffffff)
        }
        signatures = new IBebopSettlement.MakerSignature[](numSignatures);

        uint256 offset = 4;
        for (uint256 i = 0; i < numSignatures; i++) {
            // Each signature is prefixed with its length
            uint32 sigLength;
            assembly {
                let data := add(signatureData, add(0x20, offset))
                sigLength := mload(data)
                sigLength := and(sigLength, 0xffffffff)
            }
            offset += 4;

            // Extract signature bytes
            bytes memory sigBytes = new bytes(sigLength);
            assembly {
                let src := add(signatureData, add(0x20, offset))
                let dst := add(sigBytes, 0x20)

                // Copy sigLength bytes from src to dst
                let end := add(dst, sigLength)
                for {} lt(dst, end) {
                    dst := add(dst, 0x20)
                    src := add(src, 0x20)
                } { mstore(dst, mload(src)) }
            }

            signatures[i] = IBebopSettlement.MakerSignature({
                signatureType: signatureType,
                signatureBytes: sigBytes
            });

            offset += sigLength;
        }
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
        uint32 signatureLength =
            uint32(bytes4(data[47 + quoteDataLength:51 + quoteDataLength]));

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
        signature =
            data[51 + quoteDataLength:51 + quoteDataLength + signatureLength];

        // Last byte tells us if we need approval
        approvalNeeded = data[51 + quoteDataLength + signatureLength] != 0;
    }
}
