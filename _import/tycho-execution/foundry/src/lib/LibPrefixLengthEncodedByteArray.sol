// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

error LibPrefixLengthEncodedByteArray__InvalidEncoding();

library LibPrefixLengthEncodedByteArray {
    /**
     * @dev Pop the first element of an array and returns it with the remaining data.
     */
    function next(bytes calldata encoded)
        internal
        pure
        returns (bytes calldata elem, bytes calldata res)
    {
        // Handle empty input
        if (encoded.length == 0) {
            return (encoded[:0], encoded[:0]);
        }

        // Ensure we have at least 2 bytes for length prefix
        if (encoded.length < 2) revert LibPrefixLengthEncodedByteArray__InvalidEncoding();
        // Extract the length prefix (first 2 bytes)
        uint16 length = uint16(bytes2(encoded[:2]));
        
        // Check if length is valid
        if (2 + length > encoded.length) revert LibPrefixLengthEncodedByteArray__InvalidEncoding();
        
        // Extract the element (after length prefix)
        elem = encoded[2:2+length];
        
        // Extract the remaining data
        res = encoded[2+length:];
        
        return (elem, res);
    }

    /**
     * @dev Gets the size of the encoded array.
     */
    function size(bytes calldata encoded) internal pure returns (uint256 s) {
        uint256 offset = 0;

        while (offset < encoded.length) {
            // Ensure we have at least 2 bytes for length prefix
            if (offset + 2 > encoded.length) revert LibPrefixLengthEncodedByteArray__InvalidEncoding();
            
            uint16 length = uint16(bytes2(encoded[offset:offset + 2]));
            
            // Check if length is valid
            if (offset + 2 + length > encoded.length) revert LibPrefixLengthEncodedByteArray__InvalidEncoding();
            
            offset += length + 2;
            s++;
        }
    }

    /**
     * @dev Cast an encoded array into a Solidity array.
     */
    function toArray(bytes calldata encoded)
        internal
        pure
        returns (bytes[] memory arr)
    {
        bytes calldata elem;
        uint256 idx = 0;
        arr = new bytes[](LibPrefixLengthEncodedByteArray.size(encoded));
        while (encoded.length > 0) {
            (elem, encoded) = LibPrefixLengthEncodedByteArray.next(encoded);
            arr[idx] = elem;
            idx++;
        }
    }
}