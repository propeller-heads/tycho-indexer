// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

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
}
