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
            RestrictTransferFrom.TransferType transferType,
            BebopExecutor.OrderType orderType,
            uint256 filledTakerAmount,
            bytes memory quoteData,
            bytes memory makerSignaturesData,
            bool // approvalNeeded - unused in test harness
        )
    {
        return _decodeData(data);
    }

    // Expose the internal getActualFilledTakerAmount function for testing
    function exposed_getActualFilledTakerAmount(
        uint256 givenAmount,
        uint256 orderTakerAmount,
        uint256 filledTakerAmount
    ) external pure returns (uint256 actualFilledTakerAmount) {
        return _getActualFilledTakerAmount(
            givenAmount, orderTakerAmount, filledTakerAmount
        );
    }

    // Override to prank the taker address before calling the real settlement
    function _executeSingleRFQ(
        address tokenIn,
        address tokenOut,
        TransferType transferType,
        uint256 givenAmount,
        uint256 filledTakerAmount,
        bytes memory quoteData,
        bytes memory makerSignaturesData,
        bool approvalNeeded
    ) internal virtual override returns (uint256 amountOut) {
        // Decode the order from quoteData
        IBebopSettlement.Single memory order =
            abi.decode(quoteData, (IBebopSettlement.Single));

        uint256 actualFilledTakerAmount = _getActualFilledTakerAmount(
            givenAmount, order.taker_amount, filledTakerAmount
        );

        // For testing: transfer tokens from executor to taker address
        // This simulates the taker having the tokens with approval
        if (tokenIn != address(0)) {
            _transfer(
                address(this), transferType, tokenIn, actualFilledTakerAmount
            );
            IERC20(tokenIn).safeTransfer(
                order.taker_address, actualFilledTakerAmount
            );

            // Approve settlement from taker's perspective
            // Stop any existing prank first
            vm.stopPrank();
            vm.startPrank(order.taker_address);
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
            vm.stopPrank();
        } else {
            vm.stopPrank();
            // For native ETH, send it to the taker address
            payable(order.taker_address).transfer(actualFilledTakerAmount);
        }

        // IMPORTANT: Prank as the taker address to pass the settlement validation
        vm.stopPrank();
        vm.startPrank(order.taker_address);

        // Set block timestamp to ensure order is valid regardless of fork block
        uint256 currentTimestamp = block.timestamp;
        vm.warp(order.expiry - 1); // Set timestamp to just before expiry

        // Execute the single swap, let's test the actual settlement logic
        amountOut = super._executeSingleRFQ(
            tokenIn,
            tokenOut,
            TransferType.None, // We set transfer type to none for testing in order to keep the taker's balance unchanged as it will execute the swap
            givenAmount,
            filledTakerAmount,
            quoteData,
            makerSignaturesData,
            approvalNeeded
        );

        // Restore original timestamp
        vm.warp(currentTimestamp);
        vm.stopPrank();
    }

    // Override to execute aggregate orders through the real settlement
    function _executeAggregateRFQ(
        address tokenIn,
        address tokenOut,
        TransferType transferType,
        uint256 givenAmount,
        uint256 filledTakerAmount,
        bytes memory quoteData,
        bytes memory makerSignaturesData,
        bool approvalNeeded
    ) internal virtual override returns (uint256 amountOut) {
        // Decode the Aggregate order
        IBebopSettlement.Aggregate memory order =
            abi.decode(quoteData, (IBebopSettlement.Aggregate));

        // For aggregate orders, calculate total taker amount across all amounts of the 2D array
        uint256 totalTakerAmount = 0;
        for (uint256 i = 0; i < order.taker_amounts.length; i++) {
            for (uint256 j = 0; j < order.taker_amounts[i].length; j++) {
                totalTakerAmount += order.taker_amounts[i][j];
            }
        }

        uint256 actualFilledTakerAmount = _getActualFilledTakerAmount(
            givenAmount, totalTakerAmount, filledTakerAmount
        );

        // For testing: transfer tokens from executor to taker address
        // This simulates the taker having the tokens with approval
        if (tokenIn != address(0)) {
            _transfer(
                address(this), transferType, tokenIn, actualFilledTakerAmount
            );
            IERC20(tokenIn).safeTransfer(
                order.taker_address, actualFilledTakerAmount
            );

            // Approve settlement from taker's perspective
            // Stop any existing prank first
            vm.stopPrank();
            vm.startPrank(order.taker_address);
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
            vm.stopPrank();
        } else {
            vm.stopPrank();
            // For native ETH, send it to the taker address
            payable(order.taker_address).transfer(actualFilledTakerAmount);
        }

        // IMPORTANT: Prank as the taker address to pass the settlement validation
        vm.stopPrank();
        vm.startPrank(order.taker_address);

        // Set block timestamp to ensure order is valid regardless of fork block
        uint256 currentTimestamp = block.timestamp;
        vm.warp(order.expiry - 1); // Set timestamp to just before expiry

        // Execute the aggregate swap, let's test the actual settlement logic
        amountOut = super._executeAggregateRFQ(
            tokenIn,
            tokenOut,
            TransferType.None, // We set transfer type to none for testing in order to keep the taker's balance unchanged as it will execute the swap
            givenAmount,
            filledTakerAmount,
            quoteData,
            makerSignaturesData,
            approvalNeeded
        );

        // Restore original timestamp
        vm.warp(currentTimestamp);
        vm.stopPrank();
    }
}
