// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.10;

import "../../src/executors/BebopExecutor.sol";
import {Test, console, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract BebopExecutorHarness is BebopExecutor, Test {
    using SafeERC20 for IERC20;
    using Address for address;

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
        uint256 outLen = data.length - 4;
        bebopCalldataWithoutSelector = new bytes(outLen);
        // Safe byte-by-byte copy to avoid writing past the end of the target bytes array
        for (uint256 i = 0; i < outLen; i++) {
            bebopCalldataWithoutSelector[i] = data[i + 4];
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
            uint8 partialFillOffset,
            uint256 originalFilledTakerAmount,
            bool approvalNeeded,
            address receiver
        )
    {
        return _decodeData(data);
    }

    // Expose the internal modifyFilledTakerAmount function for testing
    function exposed_modifyFilledTakerAmount(
        bytes memory bebopCalldata,
        uint256 givenAmount,
        uint256 originalFilledTakerAmount,
        uint8 partialFillOffset
    ) external pure returns (bytes memory) {
        return _modifyFilledTakerAmount(
            bebopCalldata,
            givenAmount,
            originalFilledTakerAmount,
            partialFillOffset
        );
    }

    // Override swap so router integration tests impersonate the taker when calling settlement
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        override
        returns (uint256 calculatedAmount)
    {
        console.log("BebopExecutorHarness::swap called");
        console.log("  Given amount:", givenAmount);
        console.log("  Data length:", data.length);
        console.log("  Msg.sender:", msg.sender);
        // Decode the data to get the bebop calldata
        (
            address tokenIn,
            address tokenOut,
            TransferType transferType,
            bytes memory bebopCalldata,
            uint8 partialFillOffset,
            uint256 originalFilledTakerAmount,
            bool approvalNeeded,
            address receiver
        ) = _decodeData(data);

        // Extract the selector to determine order type
        bytes4 selector = bytes4(bebopCalldata);

        // Extract taker address from the order - Bebop validates msg.sender == order.taker_address
        address takerAddress;
        if (selector == SWAP_SINGLE_SELECTOR) {
            // For single orders with inline encoding, taker_address is at position 36
            // Position: 4 (selector) + 352 (inline order) + 32 (signature offset) = 388
            // But we need taker_address which is at: 4 (selector) + 32 (expiry) = 36
            assembly {
                let dataPtr := add(bebopCalldata, 0x20)
                takerAddress := mload(add(dataPtr, 36))
            }
        } else if (selector == SWAP_AGGREGATE_SELECTOR) {
            // For aggregate orders, extract taker_address from the calldata
            // The aggregate order struct is passed as a calldata parameter
            // We need to read the offset to the order struct, then extract taker_address
            assembly {
                let dataPtr := add(bebopCalldata, 0x20)
                // Read the offset to the order struct (first parameter after selector)
                let orderOffset := mload(add(dataPtr, 0x04))
                // The taker_address is at orderOffset + 4 (selector) + 32 (after expiry)
                takerAddress :=
                    mload(add(dataPtr, add(0x04, add(orderOffset, 32))))
            }
            console.log(
                "Extracted taker address from aggregate order:", takerAddress
            );
        }

        // For ERC20 tokens, we need to handle the flow differently
        // The taker needs to have the tokens and approve the settlement
        if (tokenIn != address(0)) {
            // When called via delegatecall from the router, address(this) is the router
            // So we check the balance of address(this) which will be the router
            uint256 balance = IERC20(tokenIn).balanceOf(address(this));
            console.log("Balance of tokenIn at address(this):", balance);
            console.log("Address(this):", address(this));

            // If we don't have tokens, the taker should have them
            if (balance < givenAmount) {
                // Try to transfer from the taker (who should have approved the router)
                console.log("Transferring from taker to address(this)");
                IERC20(tokenIn).transferFrom(
                    takerAddress, address(this), givenAmount
                );
                balance = IERC20(tokenIn).balanceOf(address(this));
                console.log("Balance after transfer:", balance);
            }

            // Calculate the modified filledTakerAmount (what will actually be used)
            bytes memory modifiedCalldata = _modifyFilledTakerAmount(
                bebopCalldata,
                givenAmount,
                originalFilledTakerAmount,
                partialFillOffset
            );

            // Extract the actual filledTakerAmount that will be used
            uint256 actualFilledAmount = originalFilledTakerAmount > givenAmount
                ? givenAmount
                : originalFilledTakerAmount;

            console.log(
                "Original filled taker amount:", originalFilledTakerAmount
            );
            console.log("Actual filled amount to use:", actualFilledAmount);

            // Only transfer what's needed to the taker, keep the rest in router
            IERC20(tokenIn).transfer(takerAddress, actualFilledAmount);
            console.log("Transferred tokens to taker:", actualFilledAmount);

            // Check balances after transfer
            uint256 takerBalance = IERC20(tokenIn).balanceOf(takerAddress);
            uint256 routerBalance = IERC20(tokenIn).balanceOf(address(this));
            console.log("After transfer - Taker balance:", takerBalance);
            console.log(
                "After transfer - Router balance (dust):", routerBalance
            );

            // Impersonate the taker and approve settlement for what they have
            vm.startPrank(takerAddress);
            IERC20(tokenIn).approve(bebopSettlement, actualFilledAmount);
            console.log("Taker approved settlement for:", actualFilledAmount);
            vm.stopPrank();

            // Check if taker still has the tokens
            takerBalance = IERC20(tokenIn).balanceOf(takerAddress);
            console.log("After approval - Taker balance:", takerBalance);

            // Start pranking as taker for the actual swap
            vm.startPrank(takerAddress);
        } else {
            // For ETH, start pranking as taker
            vm.startPrank(takerAddress);
        }

        // Log the actual bebop call details
        console.log("Calling Bebop settlement with:");
        console.log("  Taker address:", takerAddress);
        console.log("  Token in:", tokenIn);
        console.log("  Token out:", tokenOut);
        console.log("  Given amount:", givenAmount);
        console.log("  Receiver:", receiver);
        console.log("  Bebop calldata length:", bebopCalldata.length);
        console.log("  Natural msg.sender (no prank):", msg.sender);

        // Call the parent implementation which handles the actual swap
        // The taker prank is already active from above
        console.log("About to call _swap, msg.sender is:", msg.sender);
        console.log("Pranked as taker:", takerAddress);
        calculatedAmount = _swap(givenAmount, data);

        vm.stopPrank();

        console.log("Calculated amount returned:", calculatedAmount);
    }
}
