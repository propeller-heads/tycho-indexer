// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

contract Constants is Test {
    address ADMIN = makeAddr("admin"); //admin=us
    address BOB = makeAddr("bob"); //bob=someone!=us
    address FUND_RESCUER = makeAddr("fundRescuer");
    address FEE_SETTER = makeAddr("feeSetter");
    address FEE_RECEIVER = makeAddr("feeReceiver");

    // dummy contracts
    address DUMMY = makeAddr("dummy");

    address WETH_ADDR = address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address DAI_ADDR = address(0x6B175474E89094C44Da98b954EedeAC495271d0F);

    /**
     * @dev Deploys a dummy contract with non-empty bytecode
     */
    function deployDummyContract() internal {
        bytes memory minimalBytecode = hex"01"; // Single-byte bytecode
        vm.etch(DUMMY, minimalBytecode); // Deploy minimal bytecode
    }
}
