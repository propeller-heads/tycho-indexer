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

    struct Aggregate {
        uint256 expiry;
        address taker_address;
        address[] maker_addresses;
        uint256[] maker_nonces;
        address[][] taker_tokens;
        address[][] maker_tokens;
        uint256[][] taker_amounts;
        uint256[][] maker_amounts;
        address receiver;
        bytes commands;
        uint256 flags; // `hashAggregateOrder` doesn't use this field for AggregateOrder hash
    }

    struct MakerSignature {
        bytes signatureBytes;
        uint256 flags;
    }

    function swapSingle(
        Single calldata order,
        MakerSignature calldata makerSignature,
        uint256 filledTakerAmount
    ) external payable;

    function swapAggregate(
        Aggregate calldata order,
        MakerSignature[] calldata makerSignatures,
        uint256 filledTakerAmount
    ) external payable;
}

/// @title BebopExecutor
/// @notice Executor for Bebop PMM RFQ (Request for Quote) swaps
/// @dev Handles Single and Aggregate RFQ swaps through Bebop settlement contract
/// @dev Only supports single token in to single token out swaps
contract BebopExecutor is IExecutor, IExecutorErrors, RestrictTransferFrom {
    using Math for uint256;
    using SafeERC20 for IERC20;

    /// @notice Bebop order types
    enum OrderType {
        Single, // 0: Single token pair trade
        Aggregate // 1: Multi-maker trade with single token in/out

    }

    /// @notice Bebop-specific errors
    error BebopExecutor__InvalidDataLength();
    error BebopExecutor__InvalidInput();
    error BebopExecutor__InvalidSignatureLength();
    error BebopExecutor__InvalidSignatureType();
    error BebopExecutor__ZeroAddress();

    /// @notice The Bebop settlement contract address
    address public immutable bebopSettlement;

    constructor(address _bebopSettlement, address _permit2)
        RestrictTransferFrom(_permit2)
    {
        if (_bebopSettlement == address(0)) revert BebopExecutor__ZeroAddress();
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
            uint256 filledTakerAmount,
            bytes memory quoteData,
            bytes memory makerSignaturesData,
            bool approvalNeeded
        ) = _decodeData(data);

        // Execute RFQ swap based on order type
        if (orderType == OrderType.Single) {
            calculatedAmount = _executeSingleRFQ(
                tokenIn,
                tokenOut,
                transferType,
                givenAmount,
                filledTakerAmount,
                quoteData,
                makerSignaturesData,
                approvalNeeded
            );
        } else if (orderType == OrderType.Aggregate) {
            calculatedAmount = _executeAggregateRFQ(
                tokenIn,
                tokenOut,
                transferType,
                givenAmount,
                filledTakerAmount,
                quoteData,
                makerSignaturesData,
                approvalNeeded
            );
        } else {
            revert BebopExecutor__InvalidInput();
        }
    }

    /**
     * @dev Determines the actual taker amount to be filled for a Bebop order
     * @notice This function handles two scenarios:
     *         1. When filledTakerAmount is 0: Uses the full order amount if givenAmount is sufficient,
     *            otherwise returns 0 to indicate the order cannot be filled
     *         2. When filledTakerAmount > 0: Caps the fill at the minimum of filledTakerAmount and givenAmount
     *            to ensure we don't attempt to fill more than available
     * @param givenAmount The amount of tokens available from the router for this swap
     * @param orderTakerAmount The full taker amount specified in the Bebop order
     * @param filledTakerAmount The requested fill amount (0 means fill entire order)
     * @return actualFilledTakerAmount The amount that will actually be filled
     */
    function _getActualFilledTakerAmount(
        uint256 givenAmount,
        uint256 orderTakerAmount,
        uint256 filledTakerAmount
    ) internal pure returns (uint256 actualFilledTakerAmount) {
        actualFilledTakerAmount = filledTakerAmount == 0
            ? (givenAmount >= orderTakerAmount ? orderTakerAmount : 0)
            : (filledTakerAmount > givenAmount ? givenAmount : filledTakerAmount);
    }

    /// @dev Executes a Single RFQ swap through Bebop settlement
    function _executeSingleRFQ(
        address tokenIn,
        address tokenOut,
        TransferType transferType,
        uint256 givenAmount,
        uint256 filledTakerAmount,
        bytes memory quoteData,
        bytes memory makerSignaturesData,
        bool approvalNeeded
    ) internal virtual returns (uint256 amountOut) {
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

        // Approve Bebop settlement to spend tokens if needed
        if (approvalNeeded) {
            // slither-disable-next-line unused-return
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
        }

        // Record balances before swap to calculate amountOut
        uint256 balanceBefore = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        // Execute the swap with ETH value if needed
        uint256 ethValue = tokenIn == address(0) ? actualFilledTakerAmount : 0;

        // Use swapSingle since tokens are in the executor with approval
        // slither-disable-next-line arbitrary-send-eth
        IBebopSettlement(bebopSettlement).swapSingle{value: ethValue}(
            order, sig, actualFilledTakerAmount
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
        TransferType transferType,
        uint256 givenAmount,
        uint256 filledTakerAmount,
        bytes memory quoteData,
        bytes memory makerSignaturesData,
        bool approvalNeeded
    ) internal virtual returns (uint256 amountOut) {
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

        // For aggregate orders, calculate total taker amount across all makers
        uint256 totalTakerAmount = 0;
        for (uint256 i = 0; i < order.taker_amounts.length; i++) {
            totalTakerAmount += order.taker_amounts[i][0];
        }

        uint256 actualFilledTakerAmount = _getActualFilledTakerAmount(
            givenAmount, totalTakerAmount, filledTakerAmount
        );

        // Transfer single input token
        _transfer(address(this), transferType, tokenIn, givenAmount);

        // Approve if needed
        if (approvalNeeded) {
            // slither-disable-next-line unused-return
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
        }

        // Record balance before swap
        uint256 balanceBefore = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        // Execute the swap
        uint256 ethValue = tokenIn == address(0) ? actualFilledTakerAmount : 0;

        // Execute the swap (tokens are in executor, approved to settlement)
        // slither-disable-next-line arbitrary-send-eth
        IBebopSettlement(bebopSettlement).swapAggregate{value: ethValue}(
            order, signatures, actualFilledTakerAmount
        );

        // Calculate actual amount received
        uint256 balanceAfter = tokenOut == address(0)
            ? order.receiver.balance
            : IERC20(tokenOut).balanceOf(order.receiver);

        amountOut = balanceAfter - balanceBefore;
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
            uint256 filledTakerAmount,
            bytes memory quoteData,
            bytes memory makerSignaturesData,
            bool approvalNeeded
        )
    {
        // Need at least 83 bytes for the minimum fixed fields
        // 20 + 20 + 1 + 1 + 32 (filledTakerAmount) + 4 (quote length) + 4 (maker sigs length) + 1 (approval) = 83
        if (data.length < 83) revert BebopExecutor__InvalidDataLength();

        // Decode fixed fields
        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        transferType = TransferType(uint8(data[40]));
        orderType = OrderType(uint8(data[41]));
        filledTakerAmount = uint256(bytes32(data[42:74]));

        // Get quote data length and validate
        uint32 quoteDataLength = uint32(bytes4(data[74:78]));
        if (data.length < 78 + quoteDataLength + 4) {
            revert BebopExecutor__InvalidDataLength();
        }

        // Extract quote data
        quoteData = data[78:78 + quoteDataLength];

        // Get maker signatures data length
        uint32 makerSignaturesLength =
            uint32(bytes4(data[78 + quoteDataLength:82 + quoteDataLength]));

        // Validate total length
        // 78 + quoteDataLength + 4 + makerSignaturesLength + 1 (approval)
        uint256 expectedLength = 83 + quoteDataLength + makerSignaturesLength;
        if (data.length != expectedLength) {
            revert BebopExecutor__InvalidDataLength();
        }

        // Extract maker signatures data (ABI encoded MakerSignature array)
        makerSignaturesData = data[
            82 + quoteDataLength:82 + quoteDataLength + makerSignaturesLength
        ];

        // Extract approval flag
        approvalNeeded = data[82 + quoteDataLength + makerSignaturesLength] != 0;
    }
}
