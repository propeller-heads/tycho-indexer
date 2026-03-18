pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {TransferManager} from "../TransferManager.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

/// @title BebopExecutor
/// @notice Executor for Bebop PMM RFQ (Request for Quote) swaps
/// @dev Handles Single and Aggregate RFQ swaps through Bebop settlement contract
/// @dev Only supports single token in to single token out swaps
contract BebopExecutor is IExecutor {
    using Math for uint256;
    using SafeERC20 for IERC20;
    using Address for address;

    /// @notice Bebop-specific errors
    error BebopExecutor__InvalidDataLength();
    error BebopExecutor__ZeroAddress();

    /// @notice The Bebop settlement contract address
    address public immutable bebopSettlement;

    constructor(address bebopSettlement_) {
        if (bebopSettlement_ == address(0)) {
            revert BebopExecutor__ZeroAddress();
        }
        bebopSettlement = bebopSettlement_;
    }

    function fundsExpectedAddress(
        bytes calldata /* data */
    )
        external
        view
        returns (address receiver)
    {
        return msg.sender;
    }

    /// @notice Executes a swap through Bebop's PMM RFQ system
    /// @param amountIn The amount of input token to swap
    /// @param data Encoded swap data containing tokens and bebop calldata
    /// @param receiver The address to receive output tokens
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
    {
        uint8 partialFillOffset;
        uint256 originalFilledTakerAmount;
        bytes memory bebopCalldata;
        (partialFillOffset, originalFilledTakerAmount, bebopCalldata) =
            _decodeData(data);

        // Modify the filledTakerAmount in the calldata
        // If the filledTakerAmount is the same as the original, the original calldata is returned
        bytes memory finalCalldata = _modifyFilledTakerAmount(
            bebopCalldata,
            amountIn,
            originalFilledTakerAmount,
            partialFillOffset
        );

        // Use OpenZeppelin's Address library for safe call
        // This will revert if the call fails
        // slither-disable-next-line unused-return
        bebopSettlement.functionCall(finalCalldata);
    }

    /// @dev Decodes the packed calldata
    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            uint8 partialFillOffset,
            uint256 originalFilledTakerAmount,
            bytes memory bebopCalldata
        )
    {
        // Need at least 73 bytes for the minimum fixed fields
        // 20 (tokenIn) + 20 (tokenOut) + 1 (offset) + 32 (amount) = 73
        if (data.length < 73) revert BebopExecutor__InvalidDataLength();

        partialFillOffset = uint8(data[40]);
        originalFilledTakerAmount = uint256(bytes32(data[41:73]));
        bebopCalldata = data[73:];
    }

    /// @dev Modifies the filledTakerAmount in the bebop calldata to handle slippage
    /// @param bebopCalldata The original calldata for the bebop settlement
    /// @param amountIn The actual amount available from the router
    /// @param originalFilledTakerAmount The original amount expected when the quote was generated
    /// @param partialFillOffset The offset from Bebop API indicating where filledTakerAmount is located
    /// @return The modified calldata with updated filledTakerAmount
    function _modifyFilledTakerAmount(
        bytes memory bebopCalldata,
        uint256 amountIn,
        uint256 originalFilledTakerAmount,
        uint8 partialFillOffset
    ) internal pure returns (bytes memory) {
        // Use the offset from Bebop API to locate filledTakerAmount
        // Position = 4 bytes (selector) + offset * 32 bytes
        uint256 filledTakerAmountPos = 4 + uint256(partialFillOffset) * 32;

        // Cap the fill amount at what we actually have available
        uint256 newFilledTakerAmount = originalFilledTakerAmount > amountIn
            ? amountIn
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

    /**
     * @dev Allow receiving ETH for settlement calls that require ETH
     * This is needed when the executor handles native ETH swaps
     * In production, ETH typically comes from router or settlement contracts
     * In tests, it may come from EOA addresses via the test harness
     */
    receive() external payable {
        // Allow ETH transfers for Bebop settlement functionality
    }

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            address tokenOut,
            bool outputToRouter
        )
    {
        if (data.length < 73) {
            revert BebopExecutor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        transferType = TransferManager.TransferType.ProtocolWillDebit;
        receiver = bebopSettlement;
        outputToRouter = true;
    }
}
