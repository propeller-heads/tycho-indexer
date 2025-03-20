// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

interface ILocker {
    function locked(uint256 id) external;
}

interface IPayer {
    function payCallback(uint256 id, address token) external;
}

interface IFlashAccountant {
    // Withdraws a token amount from the accountant to the given recipient.
    // The contract must be locked, as it tracks the withdrawn amount against the current locker's delta.
    function withdraw(address token, address recipient, uint128 amount) external;
}
