// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library CustomBytesAppend {
    // Constants for the custom prefix used in the bytes32 format
    string private constant CUSTOM = "_CUSTOM_";

    /**
     * @dev Extracts an address from a bytes32 input, assuming it is either
     * prepended or appended with `_CUSTOM_`.
     * @param input The bytes32 input containing the address and custom
     * prefix/suffix.
     * @return extractedAddress The extracted address.
     */
    function extractAddress(bytes32 input)
        public
        pure
        returns (address extractedAddress)
    {
        // Convert the bytes32 input into a dynamic bytes array for manipulation
        bytes memory inputBytes = abi.encodePacked(input);

        // Check if the bytes contain the custom prefix
        if (hasPrefix(inputBytes)) {
            // If prefixed, extract the 20 bytes after the prefix as the address
            extractedAddress =
                bytesToAddress(slice(inputBytes, bytes(CUSTOM).length, 20));
        }
        // Check if the bytes contain the custom suffix
        else if (hasSuffix(inputBytes)) {
            // If suffixed, extract the first 20 bytes as the address
            extractedAddress = bytesToAddress(slice(inputBytes, 0, 20));
        } else {
            // Revert if neither prefix nor suffix is found
            revert("Invalid input format");
        }
    }

    /**
     * @dev Checks if the bytes data has the custom prefix.
     * @param data The bytes array to check.
     * @return True if the prefix matches, false otherwise.
     */
    function hasPrefix(bytes memory data) internal pure returns (bool) {
        // Compare the first bytes of the input with the prefix using keccak256
        // for hashing
        return keccak256(slice(data, 0, bytes(CUSTOM).length))
            == keccak256(bytes(CUSTOM));
    }

    /**
     * @dev Checks if the bytes data has the custom suffix.
     * @param data The bytes array to check.
     * @return True if the suffix matches, false otherwise.
     */
    function hasSuffix(bytes memory data) internal pure returns (bool) {
        // Compare the last bytes of the input with the suffix using keccak256
        // for hashing
        return keccak256(
            slice(
                data, data.length - bytes(CUSTOM).length, bytes(CUSTOM).length
            )
        ) == keccak256(bytes(CUSTOM));
    }

    /**
     * @dev Slices a bytes array.
     * @param data The bytes array to slice.
     * @param start The starting index of the slice.
     * @param length The length of the slice.
     * @return The sliced bytes array.
     */
    function slice(bytes memory data, uint256 start, uint256 length)
        internal
        pure
        returns (bytes memory)
    {
        // Ensure the slice operation does not exceed the bounds of the array
        require(data.length >= start + length, "Invalid slice");

        // Create a new bytes array to hold the sliced data
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }

    /**
     * @dev Converts a bytes array of length 20 into an address.
     * @param data The bytes array (must be 20 bytes long).
     * @return addr The converted address.
     */
    function bytesToAddress(bytes memory data)
        internal
        pure
        returns (address addr)
    {
        // Ensure the input length is exactly 20 bytes (size of an Ethereum
        // address)
        require(data.length == 20, "Invalid address length");

        // Use inline assembly to efficiently convert the bytes to an address
        assembly {
            addr := mload(add(data, 20))
        }
    }
}
