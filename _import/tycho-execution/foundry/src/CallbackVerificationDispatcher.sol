// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/**
 * @title Dispatch callback verification to external contracts
 * @author PropellerHeads Devs
 * @dev Provides the ability call external contracts to perform callback
 *  verification. This allows dynamically adding new supported protocols
 *  without needing to upgrade any contracts.
 *
 *  Note Verifier contracts need to implement the ICallbackVerifier interface
 */
contract CallbackVerificationDispatcher {
    mapping(address => bool) public callbackVerifiers;
}
