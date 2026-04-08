// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {TransferManager} from "../TransferManager.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

/// @title LiquoriceExecutor
/// @notice Executor for Liquorice RFQ (Request for Quote) swaps
/// @dev Handles RFQ swaps through Liquorice settlement contracts
///      with support for partial fills and dynamic allowance management
contract LiquoriceExecutor is IExecutor {
    using SafeERC20 for IERC20;
    using Address for address;

    error LiquoriceExecutor__InvalidDataLength();
    error LiquoriceExecutor__ZeroAddress();
    error LiquoriceExecutor__AmountBelowMinimum();

    /// @notice The Liquorice settlement contract address
    address public immutable liquoriceSettlement;

    /// @notice The Liquorice balance manager contract address
    address public immutable liquoriceBalanceManager;

    constructor(
        address _liquoriceSettlement,
        address _liquoriceBalanceManager
    ) {
        if (
            _liquoriceSettlement == address(0)
                || _liquoriceBalanceManager == address(0)
        ) {
            revert LiquoriceExecutor__ZeroAddress();
        }
        liquoriceSettlement = _liquoriceSettlement;
        liquoriceBalanceManager = _liquoriceBalanceManager;
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

    /// @notice Executes a swap through Liquorice's RFQ system
    /// @param amountIn The amount of input token to swap
    /// @param data Encoded swap data containing tokens and liquorice
    ///     calldata
    /// @param receiver The address to receive output tokens
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
    {
        (
            uint32 partialFillOffset,
            uint256 originalBaseTokenAmount,
            uint256 minBaseTokenAmount,
            bool approvalNeeded,
            bytes memory liquoriceCalldata
        ) = _decodeData(data);

        // Grant approval to Liquorice balance manager if needed
        address tokenIn = address(bytes20(data[0:20]));

        amountIn =
            _clampAmount(amountIn, originalBaseTokenAmount, minBaseTokenAmount);

        // Modify the fill amount in the calldata if partial fill is
        // supported. If partialFillOffset is 0, partial fill is not
        // supported.
        bytes memory finalCalldata = liquoriceCalldata;
        if (partialFillOffset > 0 && originalBaseTokenAmount > amountIn) {
            finalCalldata = _modifyFilledTakerAmount(
                liquoriceCalldata, amountIn, partialFillOffset
            );
        }

        uint256 ethValue = tokenIn == address(0) ? amountIn : 0;

        // Execute the swap by forwarding calldata to settlement contract
        // slither-disable-next-line unused-return
        liquoriceSettlement.functionCallWithValue(finalCalldata, ethValue);
    }

    /// @dev Decodes the packed calldata
    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            uint32 partialFillOffset,
            uint256 originalBaseTokenAmount,
            uint256 minBaseTokenAmount,
            bool approvalNeeded,
            bytes memory liquoriceCalldata
        )
    {
        // Minimum fixed fields:
        // tokenIn (20) + tokenOut (20) + partialFillOffset (4) +
        // originalBaseTokenAmount (32) + minBaseTokenAmount (32) +
        // approvalNeeded (1) = 109 bytes
        if (data.length < 109) {
            revert LiquoriceExecutor__InvalidDataLength();
        }

        // tokenIn at data[0:20] and tokenOut at data[20:40] are read
        // via getTransferData
        partialFillOffset = uint32(bytes4(data[40:44]));
        originalBaseTokenAmount = uint256(bytes32(data[44:76]));
        minBaseTokenAmount = uint256(bytes32(data[76:108]));
        approvalNeeded = data[108] != 0;
        liquoriceCalldata = data[109:];
    }

    /// @dev Clamps the given amount to be within the valid range
    function _clampAmount(
        uint256 givenAmount,
        uint256 originalBaseTokenAmount,
        uint256 minBaseTokenAmount
    ) internal pure returns (uint256) {
        if (givenAmount < minBaseTokenAmount) {
            revert LiquoriceExecutor__AmountBelowMinimum();
        }
        if (givenAmount > originalBaseTokenAmount) {
            return originalBaseTokenAmount;
        }
        return givenAmount;
    }

    /// @dev Modifies the filledTakerAmount in the liquorice calldata
    function _modifyFilledTakerAmount(
        bytes memory liquoriceCalldata,
        uint256 givenAmount,
        uint32 partialFillOffset
    ) internal pure returns (bytes memory) {
        uint256 fillAmountPos =
            4 + uint256(partialFillOffset);

        // slither-disable-next-line assembly
        assembly {
            let dataPtr := add(liquoriceCalldata, 0x20)
            let actualPos := add(dataPtr, fillAmountPos)
            mstore(actualPos, givenAmount)
        }

        return liquoriceCalldata;
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
        if (data.length < 109) {
            revert LiquoriceExecutor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        transferType = TransferManager.TransferType.ProtocolWillDebit;
        receiver = liquoriceBalanceManager;
        outputToRouter = true;
    }

    receive() external payable {}
}
