// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

interface ILocker {
    function locked(uint256 id) external;
}

interface IPayer {
    function payCallback(uint256 id, address token) external;
}

interface IFlashAccountant {
    // Forward the lock from the current locker to the given address
    // Any additional calldata is also passed through to the forwardee, with no additional encoding
    // In addition, any data returned from IForwardee#forwarded is also returned from this function exactly as is, i.e. with no additional encoding or decoding
    // Reverts are also bubbled up
    function forward(address to) external;

    // Withdraws a token amount from the accountant to the given recipient.
    // The contract must be locked, as it tracks the withdrawn amount against the current locker's delta.
    function withdraw(
        address token,
        address recipient,
        uint128 amount
    ) external;
}
