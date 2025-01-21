// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {TychoRouter} from "@src/TychoRouter.sol";

contract TychoRouterTest is Test {
    TychoRouter public tychoRouter;

    function setupTychoRouter() public {
        address permit2Address =
            address(0x000000000022D473030F116dDEE9F6B43aC78BA3);
        tychoRouter = new TychoRouter(permit2Address);
    }

    function testSetupTychoRouter() public {
        setupTychoRouter();
    }
}
