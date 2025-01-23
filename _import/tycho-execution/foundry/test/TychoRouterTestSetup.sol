// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@src/TychoRouter.sol";
import "./Constants.sol";
import "./mock/MockERC20.sol";

contract TychoRouterTestSetup is Test, Constants {
    TychoRouter tychoRouter;
    address executorSetter;
    address permit2Address = address(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    MockERC20[] tokens;

    function setUp() public {
        vm.startPrank(ADMIN);
        tychoRouter = new TychoRouter(permit2Address);
        tychoRouter.grantRole(keccak256("EXECUTOR_SETTER_ROLE"), BOB);
        tychoRouter.grantRole(keccak256("FUND_RESCUER_ROLE"), FUND_RESCUER);
        tychoRouter.grantRole(keccak256("FEE_SETTER_ROLE"), FEE_SETTER);
        executorSetter = BOB;
        deployDummyContract();
        vm.stopPrank();

        vm.startPrank(BOB);
        tokens.push(new MockERC20("Token A", "A"));
        tokens.push(new MockERC20("Token B", "B"));
        tokens.push(new MockERC20("Token C", "C"));
        vm.stopPrank();
    }

    /**
     * @dev Deploys a dummy contract with non-empty bytecode
     */
    function deployDummyContract() internal {
        bytes memory minimalBytecode = hex"01"; // Single-byte bytecode
        vm.etch(DUMMY, minimalBytecode); // Deploy minimal bytecode
    }

    /**
     * @dev Mints tokens to the given address
     * @param amount The amount of tokens to mint
     * @param to The address to mint tokens to
     */
    function mintTokens(uint256 amount, address to) internal {
        for (uint256 i = 0; i < tokens.length; i++) {
            // slither-disable-next-line calls-loop
            tokens[i].mint(to, amount);
        }
    }
}
