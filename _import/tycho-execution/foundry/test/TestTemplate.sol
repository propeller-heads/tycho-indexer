// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "@src/TychoRouter.sol";
import "./Constants.sol";

contract TychoRouterTestTemplate is Test, Constants {
    TychoRouter tychoRouter;
    address tychoRouterAddress;
    address executorSetter;

    function deployTychoRouter() internal {
        vm.startPrank(ADMIN);

        address permit2Address =
            address(0x000000000022D473030F116dDEE9F6B43aC78BA3);
        tychoRouter = new TychoRouter(permit2Address);
        tychoRouterAddress = address(tychoRouter);
        tychoRouter.grantRole(keccak256("EXECUTOR_SETTER_ROLE"), BOB);
        executorSetter = BOB;

        vm.stopPrank();
    }

    /**
     * @dev Deploys a dummy contract with non-empty bytecode
     */
    function deployDummyContract() internal {
        bytes memory minimalBytecode = hex"01"; // Single-byte bytecode
        vm.etch(DUMMY, minimalBytecode); // Deploy minimal bytecode
    }
}
