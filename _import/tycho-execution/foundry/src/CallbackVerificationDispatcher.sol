// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@interfaces/ICallbackVerifier.sol";

error CallbackVerificationDispatcher__UnapprovedVerifier();
error CallbackVerificationDispatcher__NonContractVerifier();

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

    event CallbackVerifierSet(address indexed callbackVerifier);
    event CallbackVerifierRemoved(address indexed callbackVerifier);

    /**
     * @dev Adds or replaces an approved callback verifier contract address if it is a
     *  contract.
     * @param target address of the callback verifier contract
     */
    function _setCallbackVerifier(address target) internal {
        if (target.code.length == 0) {
            revert CallbackVerificationDispatcher__NonContractVerifier();
        }
        callbackVerifiers[target] = true;
        emit CallbackVerifierSet(target);
    }

    /**
     * @dev Removes an approved callback verifier contract address
     * @param target address of the callback verifier contract
     */
    function _removeCallbackVerifier(address target) internal {
        delete callbackVerifiers[target];
        emit CallbackVerifierRemoved(target);
    }

    /**
     * @dev Calls a callback verifier. This should revert if the callback verification fails.
     */
    // slither-disable-next-line dead-code
    function _callVerifyCallback(bytes calldata data)
        internal
        view
        returns (uint256 amountOwed, address tokenOwed)
    {
        address verifier;
        bytes4 decodedSelector;
        bytes memory verifierData;

        (verifier, decodedSelector, verifierData) =
            _decodeVerifierAndSelector(data);

        if (!callbackVerifiers[verifier]) {
            revert CallbackVerificationDispatcher__UnapprovedVerifier();
        }

        bytes4 selector = decodedSelector == bytes4(0)
            ? ICallbackVerifier.verifyCallback.selector
            : decodedSelector;

        address sender = msg.sender;

        // slither-disable-next-line low-level-calls
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSelector(selector, sender, verifierData)
        );

        if (!success) {
            if (result.length > 0) {
                revert(string(result));
            } else {
                revert("Callback verification failed");
            }
        }

        (amountOwed, tokenOwed) = abi.decode(result, (uint256, address));
    }

    // slither-disable-next-line dead-code
    function _decodeVerifierAndSelector(bytes calldata data)
        internal
        pure
        returns (address verifier, bytes4 selector, bytes memory verifierData)
    {
        require(data.length >= 20, "Invalid data length");
        verifier = address(uint160(bytes20(data[:20])));
        selector = bytes4(data[20:24]);
        verifierData = data[24:];
    }
}
