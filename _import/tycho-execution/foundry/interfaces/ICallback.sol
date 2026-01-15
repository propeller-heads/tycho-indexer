// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../src/RestrictTransferFrom.sol";

interface ICallback {
    /**
     * @notice Handles callback data from a protocol or contract interaction.
     * @dev This method processes callback data and returns a result. Implementations
     * should handle the specific callback logic required by the protocol.
     *
     * @param data The encoded callback data to be processed.
     * @return result The encoded result of the callback processing.
     */
    function handleCallback(
        bytes calldata data
    ) external returns (bytes memory result);

    /**
     * @notice Verifies the validity of callback data.
     * @dev This view function checks if the provided callback data is valid according
     * to the protocol's requirements. It should revert if the data is invalid.
     *
     * @param data The encoded callback data to verify.
     */
    function verifyCallback(bytes calldata data) external view;


    /**
     * @notice Gets transfer data for callback-based token transfers.
     * @dev Used by the Dispatcher during protocol callbacks to determine
     * if and how to transfer tokens. Some protocols require all token transfers
     * to happen within the callback context rather than before swap execution.
     *
     * @param data The encoded callback data.
     * @return transferType The type of transfer to perform during the callback.
     * @return receiver The address that should receive the pre swap tokens (usually a pool or the TychoRouter - depending on the protocol)
     * @return tokenIn The address of the input token to transfer.
     * @return amountIn The amount of tokens to transfer.
     */
    function getCallbackTransferData(bytes calldata data)
    external
    payable
    returns (
        RestrictTransferFrom.TransferType transferType,
        address receiver,
        address tokenIn,
        uint256 amountIn
    );
}
