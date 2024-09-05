// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import "openzeppelin-contracts/contracts/utils/Address.sol";

/**
 * @title Propellerheads Safe ERC20 Transfer Library
 * @author PropellerHeads Developers
 * @dev Gas-efficient version of Openzeppelin's SafeERC20 contract.
 * This is a mix between SafeERC20 and GPv2SafeERC20 libraries. It
 * provides efficient transfers optimised for router contracts, while
 * keeping the Openzeppelins compatibility for approvals.
 */
library EfficientERC20 {
    using Address for address;

    error TransferFailed(uint256 balance, uint256 amount);
    error TransferFromFailed(uint256 balance, uint256 amount);

    bytes4 private constant _balanceOfSelector = hex"70a08231";
    bytes4 private constant _transferSelector = hex"a9059cbb";

    /// @dev Wrapper around a call to the ERC20 function `transfer` that reverts
    /// also when the token returns `false`.
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let freeMemoryPointer := mload(0x40)
            mstore(freeMemoryPointer, _transferSelector)
            mstore(
                add(freeMemoryPointer, 4),
                and(to, 0xffffffffffffffffffffffffffffffffffffffff)
            )
            mstore(add(freeMemoryPointer, 36), value)

            if iszero(call(gas(), token, 0, freeMemoryPointer, 68, 0, 0)) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }

        if (!getLastTransferResult(token)) {
            uint256 balance = token.balanceOf(address(this));
            revert TransferFailed(balance, value);
        }
    }

    /**
     * @dev Transfers the callers balance - 1. This effectively leaves dust on
     * the contract
     *     which will lead to more gas efficient transfers in the future.
     */
    function transferBalanceLeavingDust(IERC20 token, address to) internal {
        uint256 amount;
        assembly {
            // Load free memory pointer
            let input := mload(0x40)
            // Prepare call data: function selector (4 bytes) + contract address
            // (32 bytes)
            mstore(input, _balanceOfSelector)
            mstore(add(input, 0x04), address())

            // Call 'balanceOf' function and store result in 'amount'
            let success := staticcall(gas(), token, input, 0x24, input, 0x20)

            if iszero(success) {
                // Get the size of the returned error message and forward it
                let returnSize := returndatasize()
                returndatacopy(input, 0, returnSize)
                revert(input, returnSize)
            }

            amount := sub(mload(input), 1)

            // Prepare call data: function selector (4 bytes) + to (32 bytes) +
            // amount (32 bytes)
            mstore(input, _transferSelector)
            mstore(add(input, 0x04), to)
            mstore(add(input, 0x24), amount)

            if iszero(call(gas(), token, 0, input, 0x44, 0, 0)) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }

        if (!getLastTransferResult(token)) {
            uint256 balance = token.balanceOf(address(this));
            revert TransferFailed(balance, amount);
        }
    }

    /**
     * @dev Wrapper around a call to the ERC20 function `transferFrom` that
     *  reverts also when the token returns `false`.
     */
    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        bytes4 selector_ = token.transferFrom.selector;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            let freeMemoryPointer := mload(0x40)
            mstore(freeMemoryPointer, selector_)
            mstore(
                add(freeMemoryPointer, 4),
                and(from, 0xffffffffffffffffffffffffffffffffffffffff)
            )
            mstore(
                add(freeMemoryPointer, 36),
                and(to, 0xffffffffffffffffffffffffffffffffffffffff)
            )
            mstore(add(freeMemoryPointer, 68), value)

            if iszero(call(gas(), token, 0, freeMemoryPointer, 100, 0, 0)) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }

        if (!getLastTransferResult(token)) {
            uint256 balance = token.balanceOf(address(this));
            revert TransferFailed(balance, value);
        }
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(IERC20 token, address spender, uint256 value)
        internal
    {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(
            token,
            abi.encodeWithSelector(token.approve.selector, spender, value)
        );
    }

    /**
     * @dev Set the calling contract's allowance toward `spender` to `value`. If
     * `token` returns no value,
     * non-reverting calls are assumed to be successful. Meant to be used with
     * tokens that require the approval
     * to be set to zero before setting it to a non-zero value, such as USDT.
     */
    function forceApprove(IERC20 token, address spender, uint256 value)
        internal
    {
        bytes memory approvalCall =
            abi.encodeCall(token.approve, (spender, value));

        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(
                token, abi.encodeCall(token.approve, (spender, 0))
            );
            _callOptionalReturn(token, approvalCall);
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to
     * a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is
     * returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its
     * variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return
        // data size checking mechanism, since
        // we're implementing it ourselves. We use {Address-functionCall} to
        // perform this call, which verifies that
        // the target address contains contract code and also asserts for
        // success in the low-level call.

        bytes memory returndata = address(token).functionCall(data);
        if (returndata.length > 0) {
            // Return data is optional
            require(
                abi.decode(returndata, (bool)),
                "SafeERC20: ERC20 operation did not succeed"
            );
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to
     * a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is
     * returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its
     * variants).
     *
     * This is a variant of {_callOptionalReturn} that silently catches all
     * reverts and returns a bool instead.
     */
    function _callOptionalReturnBool(IERC20 token, bytes memory data)
        private
        returns (bool)
    {
        // We need to perform a low level call here, to bypass Solidity's return
        // data size checking mechanism, since
        // we're implementing it ourselves. We cannot use {Address-functionCall}
        // here since this should return false
        // and not revert is the subcall reverts.

        (bool success, bytes memory returndata) = address(token).call(data);
        return success
            && (returndata.length == 0 || abi.decode(returndata, (bool)))
            && address(token).code.length > 0;
    }

    /// @dev Verifies that the last return was a successful `transfer*` call.
    /// This is done by checking that the return data is either empty, or
    /// is a valid ABI encoded boolean.
    function getLastTransferResult(IERC20 token)
        private
        view
        returns (bool success)
    {
        // NOTE: Inspecting previous return data requires assembly. Note that
        // we write the return data to memory 0 in the case where the return
        // data size is 32, this is OK since the first 64 bytes of memory are
        // reserved by Solidy as a scratch space that can be used within
        // assembly blocks.
        // <https://docs.soliditylang.org/en/v0.7.6/internals/layout_in_memory.html>
        // solhint-disable-next-line no-inline-assembly
        assembly {
            /// @dev Revert with an ABI encoded Solidity error with a message
            /// that fits into 32-bytes.
            ///
            /// An ABI encoded Solidity error has the following memory layout:
            ///
            /// ------------+----------------------------------
            ///  byte range | value
            /// ------------+----------------------------------
            ///  0x00..0x04 |        selector("Error(string)")
            ///  0x04..0x24 |      string offset (always 0x20)
            ///  0x24..0x44 |                    string length
            ///  0x44..0x64 | string value, padded to 32-bytes
            function revertWithMessage(length, message) {
                mstore(0x00, "\x08\xc3\x79\xa0")
                mstore(0x04, 0x20)
                mstore(0x24, length)
                mstore(0x44, message)
                revert(0x00, 0x64)
            }

            switch returndatasize()
            // Non-standard ERC20 transfer without return.
            case 0 {
                // NOTE: When the return data size is 0, verify that there
                // is code at the address. This is done in order to maintain
                // compatibility with Solidity calling conventions.
                // <https://docs.soliditylang.org/en/v0.7.6/control-structures.html#external-function-calls>
                if iszero(extcodesize(token)) {
                    revertWithMessage(20, "GPv2: not a contract")
                }

                success := 1
            }
            // Standard ERC20 transfer returning boolean success value.
            case 32 {
                returndatacopy(0, 0, returndatasize())

                // NOTE: For ABI encoding v1, any non-zero value is accepted
                // as `true` for a boolean. In order to stay compatible with
                // OpenZeppelin's `SafeERC20` library which is known to work
                // with the existing ERC20 implementation we care about,
                // make sure we return success for any non-zero return value
                // from the `transfer*` call.
                success := iszero(iszero(mload(0)))
            }
            default { revertWithMessage(31, "GPv2: malformed transfer result") }
        }
    }
}
