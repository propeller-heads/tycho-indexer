// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

contract Constants is Test {
    address ADMIN = makeAddr("admin"); //admin=us
    address BOB = makeAddr("bob"); //bob=someone!=us
    address FUND_RESCUER = makeAddr("fundRescuer");
    address FEE_SETTER = makeAddr("feeSetter");
    // dummy contracts
    address DUMMY = makeAddr("dummy");
    address FEE_RECEIVER = makeAddr("feeReceiver");
}
