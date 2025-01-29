// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

interface ICallbackVerifier {
    error UnauthorizedCaller(string exchange, address sender);

    /**
     * @dev This method should revert if the sender is not a verified sender of the exchange.
     */
    function verifyCallback(address sender, bytes calldata data)
        external
        returns (
            uint256 amountOwed,
            address tokenOwed
        );
}
