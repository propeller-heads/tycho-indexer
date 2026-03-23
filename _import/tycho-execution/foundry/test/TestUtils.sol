pragma solidity ^0.8.10;

import "forge-std/Test.sol";

contract TestUtils is Test {
    constructor() {}

    function loadCallDataFromFile(string memory testName)
        internal
        view
        returns (bytes memory)
    {
        string memory fileContent = vm.readFile("./test/assets/calldata.txt");
        string[] memory lines = vm.split(fileContent, "\n");

        for (uint256 i = 0; i < lines.length; i++) {
            string[] memory parts = vm.split(lines[i], ":");
            if (
                parts.length >= 2
                    && keccak256(bytes(parts[0])) == keccak256(bytes(testName))
            ) {
                return vm.parseBytes(parts[1]);
            }
        }

        revert("Test calldata not found");
    }
}

// Fake Slipstream pool that accepts any swap call and does nothing.
contract FakeSlipstreamPool {
    function swap(
        address, /* recipient */
        bool, /* zeroForOne */
        int256, /* amountSpecified */
        uint160, /* sqrtPriceLimitX96 */
        bytes calldata /* data */
    )
        external
        returns (int256, int256)
    {
        return (0, 0);
    }
}

