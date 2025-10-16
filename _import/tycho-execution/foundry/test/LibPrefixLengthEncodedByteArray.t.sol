// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {
    LibPrefixLengthEncodedByteArray
} from "../lib/bytes/LibPrefixLengthEncodedByteArray.sol";

contract LibPrefixLengthEncodedByteArrayTest is Test {
    using LibPrefixLengthEncodedByteArray for bytes;

    function testNextEmpty() public view {
        bytes memory encoded = "";
        (bytes memory elem, bytes memory remaining) = this.next(encoded);
        assertEq(elem.length, 0);
        assertEq(remaining.length, 0);
    }

    function testNextSingleElement() public view {
        // Create encoded data: length prefix (0003) followed by "ABC"
        bytes memory encoded = hex"0003414243";
        (bytes memory elem, bytes memory remaining) = this.next(encoded);

        assertEq(elem.length, 3);
        assertEq(elem, hex"414243"); // "ABC"
        assertEq(remaining.length, 0);
    }

    function testNextMultipleElements() public view {
        // Encoded data: [0003]ABC[0002]DE
        bytes memory encoded = hex"000341424300024445";

        // First next()
        (bytes memory elem1, bytes memory remaining1) = this.next(encoded);
        assertEq(elem1, hex"414243"); // "ABC"
        assertEq(remaining1, hex"00024445");

        // Second next()
        (bytes memory elem2, bytes memory remaining2) = this.next(remaining1);
        assertEq(elem2, hex"4445"); // "DE"
        assertEq(remaining2.length, 0);
    }

    function testSize() public view {
        bytes memory empty = "";
        assertEq(this.size(empty), 0);

        bytes memory single = hex"0003414243";
        assertEq(this.size(single), 1);

        bytes memory multiple = hex"0003414243000244450001FF";
        assertEq(this.size(multiple), 3);
    }

    function testInvalidLength() public {
        // Length prefix larger than remaining data
        vm.expectRevert();
        bytes memory invalid = hex"0004414243";
        this.next(invalid);
    }

    function testIncompletePrefix() public {
        // Only 1 byte instead of 2 bytes prefix
        vm.expectRevert();
        bytes memory invalid = hex"01";
        this.next(invalid);
    }

    function testLargeElement() public view {
        // Test with a large but manageable size (1000 bytes)
        bytes memory large = new bytes(1002); // 2 bytes prefix + 1000 bytes data
        large[0] = bytes1(uint8(0x03)); // 03
        large[1] = bytes1(uint8(0xe8)); // E8 (1000 in hex)

        // Fill data bytes
        for (uint256 i = 2; i < large.length; i++) {
            large[i] = bytes1(uint8(0x01));
        }

        (bytes memory elem, bytes memory remaining) = this.next(large);
        assertEq(elem.length, 1000);
        assertEq(remaining.length, 0);
    }

    function testSizeWithLargeElements() public view {
        // Two elements: 1000 bytes + 500 bytes
        bytes memory data = new bytes(1504); // 1000 + 2 + 500 + 2

        // First element (1000 bytes)
        data[0] = bytes1(uint8(0x03)); // 03
        data[1] = bytes1(uint8(0xe8)); // E8 (1000 in hex)

        // Second element (500 bytes)
        data[1002] = bytes1(uint8(0x01)); // 01
        data[1003] = bytes1(uint8(0xf4)); // F4 (500 in hex)

        assertEq(this.size(data), 2);
    }

    function next(bytes calldata data)
        external
        pure
        returns (bytes memory elem, bytes memory remaining)
    {
        (elem, remaining) = data.next();
    }

    function size(bytes calldata data) external pure returns (uint256 s) {
        s = data.size();
    }
}
