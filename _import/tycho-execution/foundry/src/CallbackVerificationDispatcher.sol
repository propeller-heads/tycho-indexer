// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/**
 * @title Dispatch callback verification to external contracts
 * @author PropellerHeads Devs
 * @dev Provides the ability to delegate callback verification to external
 *  contracts. This allows dynamically adding new supported protocols
 *  without needing to upgrade any contracts. External contracts will
 *  be called using delegatecall so they can share state with the main
 *  contract if needed.
 *
 *  Note Verifier contracts need to implement the ICallbackVerifier interface
 */
contract CallbackVerificationDispatcher {
    mapping(address => bool) public callbackVerifiers;
}
