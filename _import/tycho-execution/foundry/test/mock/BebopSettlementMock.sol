// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/BebopExecutor.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title BebopSettlementMock
 * @notice Mock Bebop settlement contract that skips taker_address validation
 * @dev This is used for testing purposes to work around the msg.sender == taker_address check
 *      while maintaining all other Bebop settlement logic
 */
contract BebopSettlementMock {
    error InvalidSignature();
    error OrderExpired();
    error InsufficientMakerBalance();

    // Nonce tracking to prevent replay attacks
    mapping(address => mapping(uint256 => bool)) public makerNonceUsed;

    function swapSingle(
        IBebopSettlement.Single calldata order,
        IBebopSettlement.MakerSignature calldata makerSignature,
        uint256 filledTakerAmount
    ) external payable {
        // Check order expiry
        if (block.timestamp > order.expiry) revert OrderExpired();

        // Check nonce hasn't been used
        if (makerNonceUsed[order.maker_address][order.maker_nonce]) {
            revert InvalidSignature();
        }

        // IMPORTANT: We skip the taker_address validation that would normally be here:
        // if (msg.sender != order.taker_address) revert InvalidCaller();

        // For testing, we'll do a simplified signature validation
        // In reality, Bebop would validate the full order signature
        // Accept both proper 65-byte signatures and test placeholders
        if (makerSignature.signatureBytes.length < 4) {
            revert InvalidSignature();
        }

        // Mark nonce as used
        makerNonceUsed[order.maker_address][order.maker_nonce] = true;

        // Calculate amounts
        uint256 actualTakerAmount =
            filledTakerAmount == 0 ? order.taker_amount : filledTakerAmount;
        uint256 actualMakerAmount = filledTakerAmount == 0
            ? order.maker_amount
            : (order.maker_amount * filledTakerAmount) / order.taker_amount;

        // Transfer taker tokens from msg.sender to maker
        if (order.taker_token == address(0)) {
            // ETH transfer
            require(msg.value == actualTakerAmount, "Incorrect ETH amount");
            payable(order.maker_address).transfer(actualTakerAmount);
        } else {
            // ERC20 transfer
            IERC20(order.taker_token).transferFrom(
                msg.sender, order.maker_address, actualTakerAmount
            );
        }

        // Transfer maker tokens from maker to receiver
        if (order.maker_token == address(0)) {
            // ETH transfer - this shouldn't happen in practice
            revert("ETH output not supported");
        } else {
            // In the real contract, maker would need to have tokens and approve
            // For testing, we'll check if maker has balance, if not we assume they're funded
            uint256 makerBalance =
                IERC20(order.maker_token).balanceOf(order.maker_address);
            if (makerBalance < actualMakerAmount) {
                revert InsufficientMakerBalance();
            }

            // Transfer from maker to receiver
            // This assumes the maker has pre-approved the settlement contract
            IERC20(order.maker_token).transferFrom(
                order.maker_address, order.receiver, actualMakerAmount
            );
        }
    }

    function swapAggregate(
        IBebopSettlement.Aggregate calldata order,
        IBebopSettlement.MakerSignature[] calldata makerSignatures,
        uint256 filledTakerAmount
    ) external payable {
        // Check order expiry
        if (block.timestamp > order.expiry) revert OrderExpired();

        // Check we have at least one maker
        if (makerSignatures.length == 0) revert InvalidSignature();

        // For testing, we'll do a simplified signature validation
        for (uint256 i = 0; i < makerSignatures.length; i++) {
            if (makerSignatures[i].signatureBytes.length < 4) {
                revert InvalidSignature();
            }
        }

        // Aggregate orders only support full fills
        require(
            filledTakerAmount == 0,
            "Partial fills not supported for aggregate orders"
        );

        // Transfer taker tokens from msg.sender to makers
        for (uint256 i = 0; i < order.taker_tokens.length; i++) {
            uint256 takerAmount = order.taker_amounts[i];
            // Split proportionally among makers
            for (uint256 j = 0; j < order.maker_addresses.length; j++) {
                uint256 makerShare = takerAmount / order.maker_addresses.length;
                if (j == order.maker_addresses.length - 1) {
                    // Last maker gets any remainder
                    makerShare = takerAmount
                        - (makerShare * (order.maker_addresses.length - 1));
                }
                IERC20(order.taker_tokens[i]).transferFrom(
                    msg.sender, order.maker_addresses[j], makerShare
                );
            }
        }

        // Transfer maker tokens from each maker to receiver
        for (uint256 i = 0; i < order.maker_addresses.length; i++) {
            address maker = order.maker_addresses[i];

            // Fund maker with tokens if they don't have enough (for testing)
            for (uint256 j = 0; j < order.maker_tokens[i].length; j++) {
                address token = order.maker_tokens[i][j];
                uint256 amount = order.maker_amounts[i][j];

                uint256 makerBalance = IERC20(token).balanceOf(maker);
                if (makerBalance < amount) {
                    revert InsufficientMakerBalance();
                }

                // Transfer from maker to receiver
                IERC20(token).transferFrom(maker, order.receiver, amount);
            }
        }
    }
}
