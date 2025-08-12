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
import {console} from "forge-std/Test.sol";

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
    using Address for address;

    /// @notice Function selectors for Bebop settlement methods
    bytes4 public constant SWAP_SINGLE_SELECTOR = 0x4dcebcba;
    bytes4 public constant SWAP_AGGREGATE_SELECTOR = 0xa2f74893;

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
            uint8 partialFillOffset,
            uint256 originalFilledTakerAmount,
            bool approvalNeeded,
            address receiver,
            bytes memory bebopCalldata
        ) = _decodeData(data);

        _transfer(address(this), transferType, address(tokenIn), givenAmount);

        // Modify the filledTakerAmount in the calldata
        // If the filledTakerAmount is the same as the original, the original calldata is returned
        bytes memory finalCalldata = _modifyFilledTakerAmount(
            bebopCalldata,
            givenAmount,
            originalFilledTakerAmount,
            partialFillOffset
        );

        // Approve Bebop settlement to spend tokens if needed
        if (approvalNeeded) {
            // slither-disable-next-line unused-return
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
        }

        // Check the receiver's balance before the swap
        uint256 balanceBefore = _balanceOf(tokenOut, receiver);

        // Execute the swap with the forwarded calldata
        uint256 ethValue = tokenIn == address(0) ? givenAmount : 0;

        // Debug: Check msg.sender before settlement call
        console.log(
            "BebopExecutor: About to call settlement, msg.sender:", msg.sender
        );

        // Debug: Let's check what's in the calldata
        bytes4 selector = _getSelector(finalCalldata);
        if (selector == SWAP_AGGREGATE_SELECTOR) {
            // Try to extract taker_address from the aggregate order
            if (finalCalldata.length > 100) {
                // Read the offset to the order struct
                uint256 orderOffset;
                assembly {
                    orderOffset := mload(add(finalCalldata, 0x24))
                }
                // The taker_address is at orderOffset + 4 (selector) + 32 (after expiry)
                address orderTaker;
                assembly {
                    orderTaker :=
                        mload(add(finalCalldata, add(0x24, add(orderOffset, 32))))
                }
                console.log("Order taker_address in calldata:", orderTaker);
            }
        }

        // Use OpenZeppelin's Address library for safe call with value
        // This will revert if the call fails
        bytes memory returnData =
            bebopSettlement.functionCallWithValue(finalCalldata, ethValue);

        // Check if any tokens were actually transferred
        if (returnData.length > 0) {
            // Bebop might return some data, log it for debugging
        }

        // Calculate actual amount received by the receiver
        uint256 balanceAfter = _balanceOf(tokenOut, receiver);
        calculatedAmount = balanceAfter - balanceBefore;
    }

    /// @dev Decodes the packed calldata
    function _decodeData(bytes calldata data)
        public
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
        // Need at least 95 bytes for the minimum fixed fields
        // 20 + 20 + 1 + 1 (offset) + 32 (original amount) + 1 (approval) + 20 (receiver) = 95
        if (data.length < 95) revert BebopExecutor__InvalidDataLength();

        // Decode fixed fields
        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        transferType = TransferType(uint8(data[40]));

        // Extract partial fill offset
        partialFillOffset = uint8(data[41]);

        // Extract original amount in
        originalFilledTakerAmount = uint256(bytes32(data[42:74]));

        // Extract approval flag
        approvalNeeded = data[74] != 0;

        // Extract receiver address
        receiver = address(bytes20(data[75:95]));

        // Extract bebop calldata (all remaining bytes)
        bebopCalldata = data[95:];
    }

    /// @dev Modifies the filledTakerAmount in the bebop calldata to handle slippage
    /// @param bebopCalldata The original calldata for the bebop settlement
    /// @param givenAmount The actual amount available from the router
    /// @param originalFilledTakerAmount The original amount expected when the quote was generated
    /// @param partialFillOffset The offset from Bebop API indicating where filledTakerAmount is located
    /// @return The modified calldata with updated filledTakerAmount
    function _modifyFilledTakerAmount(
        bytes memory bebopCalldata,
        uint256 givenAmount,
        uint256 originalFilledTakerAmount,
        uint8 partialFillOffset
    ) public pure returns (bytes memory) {
        // Use the offset from Bebop API to locate filledTakerAmount
        // Position = 4 bytes (selector) + offset * 32 bytes
        uint256 filledTakerAmountPos = 4 + uint256(partialFillOffset) * 32;

        // Cap the fill amount at what we actually have available
        uint256 newFilledTakerAmount = originalFilledTakerAmount > givenAmount
            ? givenAmount
            : originalFilledTakerAmount;

        // If the new filledTakerAmount is the same as the original, return the original calldata
        if (newFilledTakerAmount == originalFilledTakerAmount) {
            return bebopCalldata;
        }

        // Use assembly to modify the filledTakerAmount at the correct position
        assembly {
            // Get pointer to the data portion of the bytes array
            let dataPtr := add(bebopCalldata, 0x20)

            // Calculate the actual position and store the new value
            let actualPos := add(dataPtr, filledTakerAmountPos)
            mstore(actualPos, newFilledTakerAmount)
        }

        return bebopCalldata;
    }

    /// @dev Helper function to extract selector from bytes
    function _getSelector(bytes memory data) internal pure returns (bytes4) {
        return bytes4(
            uint32(uint8(data[0])) << 24 | uint32(uint8(data[1])) << 16
                | uint32(uint8(data[2])) << 8 | uint32(uint8(data[3]))
        );
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

    /**
     * @dev Allow receiving ETH for settlement calls that require ETH
     * This is needed when the executor handles native ETH swaps
     * In production, ETH typically comes from router or settlement contracts
     * In tests, it may come from EOA addresses via the test harness
     */
    receive() external payable {
        // Allow ETH transfers for Bebop settlement functionality
    }
}
