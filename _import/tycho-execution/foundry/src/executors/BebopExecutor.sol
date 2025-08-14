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

/// @title BebopExecutor
/// @notice Executor for Bebop PMM RFQ (Request for Quote) swaps
/// @dev Handles Single and Aggregate RFQ swaps through Bebop settlement contract
/// @dev Only supports single token in to single token out swaps
contract BebopExecutor is IExecutor, RestrictTransferFrom {
    using Math for uint256;
    using SafeERC20 for IERC20;
    using Address for address;

    /// @notice Bebop-specific errors
    error BebopExecutor__InvalidDataLength();
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

        uint256 balanceBefore = _balanceOf(tokenOut, receiver);
        uint256 ethValue = tokenIn == address(0) ? givenAmount : 0;

        // Use OpenZeppelin's Address library for safe call with value
        // This will revert if the call fails
        // slither-disable-next-line unused-return
        bebopSettlement.functionCallWithValue(finalCalldata, ethValue);

        uint256 balanceAfter = _balanceOf(tokenOut, receiver);
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

        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        transferType = TransferType(uint8(data[40]));
        partialFillOffset = uint8(data[41]);
        originalFilledTakerAmount = uint256(bytes32(data[42:74]));
        approvalNeeded = data[74] != 0;
        receiver = address(bytes20(data[75:95]));
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
    ) internal pure returns (bytes memory) {
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
        // slither-disable-next-line assembly
        assembly {
            // Get pointer to the data portion of the bytes array
            let dataPtr := add(bebopCalldata, 0x20)

            // Calculate the actual position and store the new value
            let actualPos := add(dataPtr, filledTakerAmountPos)
            mstore(actualPos, newFilledTakerAmount)
        }

        return bebopCalldata;
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
