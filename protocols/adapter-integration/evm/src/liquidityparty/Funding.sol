// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

library Funding {
    /// @notice a constant passed to swap as the fundingSelector to indicate
    /// that the payer has used regular ERC20 approvals to allow the pool to
    /// move the necessary input tokens.
    // Slither analysis of this line is literally wrong and broken. The extra zero digits are REQUIRED by Solidity since it is a bytes4 literal.
    // slither-disable-next-line too-many-digits
    bytes4 internal constant APPROVALS = 0x00000000;

    /// @notice a constant passed to swap as the fundingSelector to indicate
    /// that the payer has already sent sufficient input tokens to the pool
    /// before calling swap, so no movement of input tokens is required.
    // Slither analysis of this line is literally wrong and broken. The extra zero digits are REQUIRED by Solidity since it is a bytes4 literal.
    // slither-disable-next-line too-many-digits
    bytes4 internal constant PREFUNDING = 0x00000001;
}
