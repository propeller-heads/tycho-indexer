pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

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

// Fake Curve pool that accepts any swap call tries to steal because we gave it allowances
contract FakeCurvePool {
    using SafeERC20 for IERC20;

    function exchange(uint256 i, uint256 j, uint256 dx, uint256 minDy)
        external
    {
        // ignoring the indices for simplicity
        address token = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
        IERC20(token).transferFrom(msg.sender, address(this), dx);
    }
}
