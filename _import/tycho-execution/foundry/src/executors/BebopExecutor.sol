// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
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

    /// @notice Function selectors for Bebop settlement methods
    bytes4 constant SWAP_SINGLE_SELECTOR = 0x47fb5891;
    bytes4 constant SWAP_AGGREGATE_SELECTOR = 0x80d2cf33;

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
    /// @param data Encoded swap data containing tokens and bebop calldata
    /// @return calculatedAmount The amount of output token received
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        virtual
        override
        returns (uint256 calculatedAmount)
    {
        calculatedAmount = _swap(givenAmount, data);
    }

    function _swap(uint256 givenAmount, bytes calldata data)
        internal
        returns (uint256 calculatedAmount)
    {
        // Decode the packed data
        (
            address tokenIn,
            address tokenOut,
            TransferType transferType,
            bytes memory bebopCalldata,
            uint256 originalFilledTakerAmount,
            bool approvalNeeded
        ) = _decodeData(data);

        // Determine if we need to modify filledTakerAmount based on slippage
        bytes memory finalCalldata = bebopCalldata;
        if (givenAmount != originalFilledTakerAmount) {
            // Need to modify the filledTakerAmount in the calldata
            finalCalldata = _modifyFilledTakerAmount(
                bebopCalldata, givenAmount, originalFilledTakerAmount
            );
        }

        // Transfer tokens if needed
        if (tokenIn != address(0)) {
            _transfer(address(this), transferType, tokenIn, givenAmount);
        }

        // Approve Bebop settlement to spend tokens if needed
        if (approvalNeeded && tokenIn != address(0)) {
            // slither-disable-next-line unused-return
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
        }

        // Bebop orders specify the receiver, so we need to check the receiver's balance
        // We'll use the executor's balance since Bebop should send tokens here for the router to collect
        uint256 balanceBefore = _balanceOf(tokenOut, address(this));

        // Execute the swap with the forwarded calldata
        uint256 ethValue = tokenIn == address(0) ? givenAmount : 0;

        // slither-disable-next-line arbitrary-send-eth
        (bool success, bytes memory result) =
            bebopSettlement.call{value: ethValue}(finalCalldata);
        if (!success) {
            // If the call failed, bubble up the revert reason
            assembly {
                revert(add(result, 0x20), mload(result))
            }
        }

        // Calculate actual amount received by the executor
        uint256 balanceAfter = _balanceOf(tokenOut, address(this));
        calculatedAmount = balanceAfter - balanceBefore;
    }

    /// @dev Decodes the packed calldata
    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            TransferType transferType,
            bytes memory bebopCalldata,
            uint256 originalFilledTakerAmount,
            bool approvalNeeded
        )
    {
        // Need at least 78 bytes for the minimum fixed fields
        // 20 + 20 + 1 + 4 (calldata length) + 32 (original amount) + 1 (approval) = 78
        if (data.length < 78) revert BebopExecutor__InvalidDataLength();

        // Decode fixed fields
        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        transferType = TransferType(uint8(data[40]));

        // Get bebop calldata length and validate
        uint32 bebopCalldataLength = uint32(bytes4(data[41:45]));
        if (data.length != 78 + bebopCalldataLength) {
            revert BebopExecutor__InvalidDataLength();
        }

        // Extract bebop calldata
        bebopCalldata = data[45:45 + bebopCalldataLength];

        // Extract original amount in
        originalFilledTakerAmount = uint256(
            bytes32(data[45 + bebopCalldataLength:77 + bebopCalldataLength])
        );

        // Extract approval flag
        approvalNeeded = data[77 + bebopCalldataLength] != 0;
    }

    /// @dev Determines the actual taker amount to be filled for a Bebop order
    /// @notice The encoder ensures filledTakerAmount is never 0 by extracting from order data when needed.
    ///         This function simply caps the fill amount at the available tokens from the router.
    /// @param givenAmount The amount of tokens available from the router for this swap
    /// @param filledTakerAmount The requested fill amount (guaranteed to be non-zero by encoder)
    /// @return actualFilledTakerAmount The amount that will actually be filled
    function _getActualFilledTakerAmount(
        uint256 givenAmount,
        uint256 filledTakerAmount
    ) internal pure returns (uint256 actualFilledTakerAmount) {
        actualFilledTakerAmount =
            filledTakerAmount > givenAmount ? givenAmount : filledTakerAmount;
    }

    /// @dev Modifies the filledTakerAmount in the bebop calldata to handle slippage
    /// @param bebopCalldata The original calldata for the bebop settlement
    /// @param givenAmount The actual amount available from the router
    /// @param originalFilledTakerAmount The original amount expected when the quote was generated
    /// @return modifiedCalldata The modified calldata with updated filledTakerAmount
    function _modifyFilledTakerAmount(
        bytes memory bebopCalldata,
        uint256 givenAmount,
        uint256 originalFilledTakerAmount
    ) internal pure returns (bytes memory) {
        // Check the function selector to determine order type
        bytes4 selector;
        assembly {
            selector := mload(add(bebopCalldata, 32))
        }

        if (
            selector == SWAP_SINGLE_SELECTOR
                || selector == SWAP_AGGREGATE_SELECTOR
        ) {
            // Both swapSingle and swapAggregate have filledTakerAmount as the last parameter
            // For swapSingle: (Single calldata order, MakerSignature calldata makerSignature, uint256 filledTakerAmount)
            // For swapAggregate: (Aggregate calldata order, MakerSignature[] calldata makerSignatures, uint256 filledTakerAmount)
            // The filledTakerAmount is always the last 32 bytes of the calldata

            // Calculate the new filledTakerAmount based on available amount
            // The encoder guarantees originalFilledTakerAmount is never 0

            uint256 calldataLength = bebopCalldata.length;
            if (calldataLength < 36) revert BebopExecutor__InvalidInput(); // 4 bytes selector + at least 32 bytes

            // Calculate new filledTakerAmount using _getActualFilledTakerAmount
            uint256 newFilledTakerAmount = _getActualFilledTakerAmount(
                givenAmount, originalFilledTakerAmount
            );

            // If the new filledTakerAmount is the same as the original, return the original calldata
            if (newFilledTakerAmount == originalFilledTakerAmount) {
                return bebopCalldata;
            }

            // Create modified calldata
            bytes memory modifiedCalldata = new bytes(calldataLength);

            // Copy all data except the last 32 bytes
            for (uint256 i = 0; i < calldataLength - 32; i++) {
                modifiedCalldata[i] = bebopCalldata[i];
            }

            // Write the new filledTakerAmount in the last 32 bytes
            assembly {
                mstore(
                    add(modifiedCalldata, calldataLength), newFilledTakerAmount
                )
            }

            return modifiedCalldata;
        } else {
            revert BebopExecutor__InvalidInput();
        }
    }

    /// @dev Returns the balance of a token or ETH for an account
    /// @param token The token address, or address(0) for ETH
    /// @param account The account to get the balance of
    /// @return balance The balance of the token or ETH for the account
    function _balanceOf(address token, address account)
        internal
        view
        returns (uint256)
    {
        return token == address(0)
            ? account.balance
            : IERC20(token).balanceOf(account);
    }
}
