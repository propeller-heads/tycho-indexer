// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.10;

import "../../src/executors/BebopExecutor.sol";
import {Test, console} from "forge-std/Test.sol";

contract BebopExecutorHarness is BebopExecutor, Test {
    using SafeERC20 for IERC20;

    constructor(address _bebopSettlement, address _permit2)
        BebopExecutor(_bebopSettlement, _permit2)
    {}

    /// @dev Helper function to strip selector from bytes using assembly
    function _stripSelector(bytes memory data)
        internal
        pure
        returns (bytes memory bebopCalldataWithoutSelector)
    {
        require(data.length >= 4, "BE: data too short for selector");

        // Create new array with length - 4
        bebopCalldataWithoutSelector = new bytes(data.length - 4);

        assembly {
            // Get pointers to the data
            let srcPtr := add(data, 0x24) // Skip length (0x20) and selector (0x04)
            let destPtr := add(bebopCalldataWithoutSelector, 0x20) // Skip length

            // Copy all bytes after the selector
            let length := sub(mload(data), 4)

            // Copy word by word for efficiency
            let words := div(length, 32)
            let remainder := mod(length, 32)

            // Copy full words
            for { let i := 0 } lt(i, words) { i := add(i, 1) } {
                mstore(add(destPtr, mul(i, 32)), mload(add(srcPtr, mul(i, 32))))
            }

            // Copy remaining bytes if any
            if remainder {
                let lastWord := mload(add(srcPtr, mul(words, 32)))
                mstore(add(destPtr, mul(words, 32)), lastWord)
            }
        }
    }

    // Expose the internal decodeData function for testing
    function decodeParams(bytes calldata data)
        external
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
        return _decodeData(data);
    }

    // Expose the internal getActualFilledTakerAmount function for testing
    function exposed_getActualFilledTakerAmount(
        uint256 givenAmount,
        uint256 filledTakerAmount
    ) external pure returns (uint256 actualFilledTakerAmount) {
        return _getActualFilledTakerAmount(givenAmount, filledTakerAmount);
    }

    // Expose the internal modifyFilledTakerAmount function for testing
    function exposed_modifyFilledTakerAmount(
        bytes memory bebopCalldata,
        uint256 givenAmount,
        uint256 originalFilledTakerAmount
    ) external pure returns (bytes memory) {
        return _modifyFilledTakerAmount(
            bebopCalldata, givenAmount, originalFilledTakerAmount
        );
    }

    // Override to prank the taker address before calling the real settlement
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        override
        returns (uint256 calculatedAmount)
    {
        // Decode the packed data
        (
            address tokenIn,
            ,
            TransferType transferType,
            bytes memory bebopCalldata,
            uint256 originalFilledTakerAmount,
        ) = _decodeData(data);

        uint256 actualFilledTakerAmount =
            _getActualFilledTakerAmount(givenAmount, originalFilledTakerAmount);

        // Extract taker address and expiry from bebop calldata
        bytes4 sel = _getSelector(bebopCalldata);
        address takerAddress;
        uint256 expiry;

        bytes memory bebopCalldataWithoutSelector;

        if (sel == SWAP_SINGLE_SELECTOR) {
            bebopCalldataWithoutSelector = _stripSelector(bebopCalldata);
            (IBebopSettlement.Single memory ord,,) = abi.decode(
                bebopCalldataWithoutSelector,
                (
                    IBebopSettlement.Single,
                    IBebopSettlement.MakerSignature,
                    uint256
                )
            );
            takerAddress = ord.taker_address;
            expiry = ord.expiry;
        } else {
            bebopCalldataWithoutSelector = _stripSelector(bebopCalldata);
            (IBebopSettlement.Aggregate memory ord,,) = abi.decode(
                bebopCalldataWithoutSelector,
                (
                    IBebopSettlement.Aggregate,
                    IBebopSettlement.MakerSignature[],
                    uint256
                )
            );
            takerAddress = ord.taker_address;
            expiry = ord.expiry;
        }

        // For testing: transfer tokens from executor to taker address
        // This simulates the taker having the tokens with approval
        if (tokenIn != address(0)) {
            _transfer(
                address(this), transferType, tokenIn, actualFilledTakerAmount
            );
            IERC20(tokenIn).safeTransfer(takerAddress, actualFilledTakerAmount);

            // Approve settlement from taker's perspective
            // Stop any existing prank first
            vm.stopPrank();
            vm.startPrank(takerAddress);
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
            vm.stopPrank();
        } else {
            vm.stopPrank();
            // For native ETH, send it to the taker address
            payable(takerAddress).transfer(actualFilledTakerAmount);
        }

        // IMPORTANT: Prank as the taker address to pass the settlement validation
        vm.stopPrank();
        vm.startPrank(takerAddress);

        // Set block timestamp to ensure order is valid regardless of fork block
        uint256 currentTimestamp = block.timestamp;
        vm.warp(expiry - 1); // Set timestamp to just before expiry

        // Execute the single swap with the original data
        // The parent's _swap will handle the modification of filledTakerAmount
        calculatedAmount = _swap(givenAmount, data);

        // Restore original timestamp
        vm.warp(currentTimestamp);
        vm.stopPrank();
    }
}
