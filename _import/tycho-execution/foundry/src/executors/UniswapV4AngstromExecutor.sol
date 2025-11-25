// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "./UniswapV4Executor.sol";

error UniswapV4AngstromExecutor__NoAttestationsProvided();
error UniswapV4AngstromExecutor__NoAttestationForBlock(uint256 blockNumber);
error UniswapV4AngstromExecutor__InvalidAttestationDataLength(uint256 length);

/// @title UniswapV4AngstromExecutor
/// @notice Executor for swapping on Uniswap V4 pools with Angstrom hooks
/// @dev This executor extends UniswapV4Executor to handle attestation selection
///      based on the current block number and injects the appropriate attestation
///      data into the hook data for Angstrom pools
contract UniswapV4AngstromExecutor is UniswapV4Executor {
    /// @notice Struct representing attestation data for a specific block
    struct AttestationData {
        uint64 blockNumber;
        bytes attestation;
    }

    constructor(IPoolManager _poolManager, address _permit2)
        UniswapV4Executor(_poolManager, _permit2)
    {}

    /// @notice Selects the appropriate attestation for the current block number
    /// @param attestationData Encoded attestation data for several blocks
    /// @return The attestation bytes for the current or next valid block
    function _selectAttestation(bytes memory attestationData)
        internal
        view
        returns (bytes memory)
    {
        AttestationData[] memory attestations =
            _decodeAttestations(attestationData);

        if (attestations.length == 0) {
            revert UniswapV4AngstromExecutor__NoAttestationsProvided();
        }

        for (uint256 i = 0; i < attestations.length; i++) {
            // slither-disable-next-line incorrect-equality
            if (attestations[i].blockNumber == block.number) {
                return attestations[i].attestation;
            }
        }

        revert UniswapV4AngstromExecutor__NoAttestationForBlock(block.number);
    }

    /// @notice Decodes attestation data
    /// @dev Each attestation is exactly 93 bytes: 8 bytes blockNumber + 85 bytes attestation
    /// @param attestationData Raw bytes containing attestations
    /// @return attestations Array of AttestationData structs
    function _decodeAttestations(bytes memory attestationData)
        internal
        pure
        returns (AttestationData[] memory attestations)
    {
        uint256 TOTAL_LENGTH = 93;

        // Calculate number of attestations from data length
        if (attestationData.length % TOTAL_LENGTH != 0) {
            revert UniswapV4AngstromExecutor__InvalidAttestationDataLength(attestationData.length);
        }

        uint256 attestationCount = attestationData.length / TOTAL_LENGTH;
        attestations = new AttestationData[](attestationCount);

        for (uint256 i = 0; i < attestationCount; i++) {
            uint256 offset = i * TOTAL_LENGTH;

            // Assembly is used because attestationData is bytes memory
            uint64 blockNumber;
            bytes memory attestation = new bytes(85);
            // slither-disable-next-line assembly
            assembly {
                // Load block number (8 bytes) - shift right to get the first 8 bytes
                blockNumber := shr(
                    192,
                    mload(add(add(attestationData, 0x20), offset))
                )

                // Copy attestation (85 bytes)
                let src := add(add(attestationData, 0x20), add(offset, 8))
                let dst := add(attestation, 0x20)

                // Copy 85 bytes (2 full words + 21 bytes)
                mstore(dst, mload(src)) // Copy first 32 bytes
                mstore(add(dst, 0x20), mload(add(src, 0x20))) // Copy next 32 bytes
                mstore(add(dst, 0x40), mload(add(src, 0x40))) // Copy remaining 21 bytes (loads 32, but we only need 21)
            }

            attestations[i] = AttestationData({
                blockNumber: blockNumber, attestation: attestation
            });
        }
    }

    /// @notice Override of parent's _decodeData to inject attestation selection
    /// @dev Decodes swap data and selects appropriate attestation for first pool
    function _decodeData(bytes calldata data)
        internal
        view
        override
        returns (
            address tokenIn,
            address tokenOut,
            bool zeroForOne,
            TransferType transferType,
            address receiver,
            UniswapV4Pool[] memory pools
        )
    {
        if (data.length < 108) {
            revert UniswapV4Executor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        zeroForOne = data[40] != 0;
        transferType = TransferType(uint8(data[41]));
        receiver = address(bytes20(data[42:62]));

        bytes calldata remaining = data[62:];

        // Decode first pool with hook data
        if (remaining.length < 48) {
            // 20 + 3 + 3 + 20 + 2 = 48 minimum
            revert UniswapV4Executor__InvalidDataLength();
        }

        address firstToken = address(bytes20(remaining[0:20]));
        uint24 firstFee = uint24(bytes3(remaining[20:23]));
        int24 firstTickSpacing = int24(uint24(bytes3(remaining[23:26])));
        address firstHook = address(bytes20(remaining[26:46]));
        uint16 firstHookDataLength = uint16(bytes2(remaining[46:48]));

        uint256 firstPoolTotalLength = 48 + firstHookDataLength;
        if (remaining.length < firstPoolTotalLength) {
            revert UniswapV4Executor__InvalidDataLength();
        }

        // Select attestation from first pool's hook data
        // Convert calldata to memory since _selectAttestation requires bytes memory
        bytes memory firstHookData =
            _selectAttestation(bytes(remaining[48:48 + firstHookDataLength]));

        // Remaining after first pool are ple encoded
        bytes[] memory encodedPools = LibPrefixLengthEncodedByteArray.toArray(
            remaining[firstPoolTotalLength:]
        );

        pools = new UniswapV4Pool[](1 + encodedPools.length);
        pools[0] = UniswapV4Pool(
            firstToken, firstFee, firstTickSpacing, firstHook, firstHookData
        );

        // Decode subsequent pools
        for (uint256 i = 0; i < encodedPools.length; i++) {
            bytes memory poolData = encodedPools[i];

            address intermediaryToken;
            uint24 fee;
            int24 tickSpacing;
            address hook;
            uint16 hookDataLength;

            // slither-disable-next-line assembly
            assembly {
                let dataPtr := add(poolData, 0x20)
                intermediaryToken := shr(96, mload(dataPtr))
                fee := and(shr(232, mload(add(dataPtr, 20))), 0xffffff)
                tickSpacing := and(shr(208, mload(add(dataPtr, 20))), 0xffffff)
                hook := shr(96, mload(add(dataPtr, 26)))
                hookDataLength := and(shr(240, mload(add(dataPtr, 46))), 0xffff)
            }

            if (poolData.length < 48 + hookDataLength) {
                revert UniswapV4Executor__InvalidDataLength();
            }

            // Extract hookData bytes for this pool
            // We copy byte-by-byte because we cannot slice bytes memory in Solidity
            bytes memory rawHookData = new bytes(hookDataLength);
            for (uint256 j = 0; j < hookDataLength; j++) {
                rawHookData[j] = poolData[48 + j];
            }

            // Select attestation from hookData
            bytes memory hookData = _selectAttestation(rawHookData);

            pools[i + 1] = UniswapV4Pool(
                intermediaryToken, fee, tickSpacing, hook, hookData
            );
        }
    }
}
