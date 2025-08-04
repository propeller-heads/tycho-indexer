// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.10;

import "../../src/executors/BebopExecutor.sol";
import {Test, console} from "forge-std/Test.sol";

contract BebopExecutorHarness is BebopExecutor, Test {
    using SafeERC20 for IERC20;

    constructor(address _bebopSettlement, address _permit2)
        BebopExecutor(_bebopSettlement, _permit2)
    {}

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
        address takerAddress;
        uint256 expiry;

        // Both swapSingle and swapAggregate have the same order structure position
        // Read the offset to the order struct (first parameter after selector)
        uint256 orderOffset;
        assembly {
            orderOffset := mload(add(bebopCalldata, 36)) // 4 (selector) + 32 (offset)
        }

        // Navigate to the order struct data
        // Order struct starts at: 4 (selector) + orderOffset
        uint256 orderDataStart = 4 + orderOffset;

        // Extract expiry (first field of the order struct)
        assembly {
            expiry := mload(add(bebopCalldata, add(orderDataStart, 32)))
        }

        // Extract taker_address (second field of the order struct)
        assembly {
            takerAddress := mload(add(bebopCalldata, add(orderDataStart, 64)))
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

        // Execute the single swap, let's test the actual settlement logic
        calculatedAmount = _swap(givenAmount, data);

        // Restore original timestamp
        vm.warp(currentTimestamp);
        vm.stopPrank();
    }
}
