// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../src/TransferManager.sol";

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
     * @notice Gets transfer data for callback-based token transfers.
     * @dev Used by the Dispatcher during protocol callbacks to determine
     * if and how to transfer tokens. Some protocols require all token transfers
     * to happen within the callback context rather than before swap execution.
     *
     * The input token is read from transient storage (set by getTransferData before
     * the swap) and returned here. This prevents protocols from injecting a false
     * token via crafted callback data while avoiding a redundant tload in the
     * Dispatcher.
     *
     * @param data The encoded callback data.
     * @return transferType The transfer type for this executor (None, ProtocolWillDebit, or Transfer).
     * @return receiver The address that should receive the pre swap tokens (usually a pool or the TychoRouter - depending on the protocol)
     * @return tokenIn The address of the input token to transfer.
     */
    function getCallbackTransferData(bytes calldata data)
    external
    payable
    returns (
        TransferManager.TransferType transferType,
        address receiver,
        address tokenIn
    );
}
