// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/**
 * @title FeeStructs
 * @notice Shared fee-related data structures used across the protocol
 */

struct FeeRecipient {
    address recipient;
    uint256 feeAmount;
}
