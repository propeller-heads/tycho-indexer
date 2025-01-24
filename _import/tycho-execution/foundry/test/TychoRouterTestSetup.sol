// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@src/TychoRouter.sol";
import "./Constants.sol";
import "./mock/MockERC20.sol";
import {WETH} from "../lib/permit2/lib/solmate/src/tokens/WETH.sol";

contract TychoRouterExposed is TychoRouter {
    constructor(address _permit2, address weth) TychoRouter(_permit2, weth) {}

    function wrapETH(uint256 amount) external payable {
        return _wrapETH(amount);
    }

    function unwrapETH(uint256 amount) external {
        return _unwrapETH(amount);
    }
}

contract TychoRouterTestSetup is Test, Constants {
    TychoRouterExposed tychoRouter;
    address executorSetter;
    address permit2Address = address(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    MockERC20[] tokens;

    function setUp() public {
        uint256 forkBlock = 21000000;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        vm.startPrank(ADMIN);
        tychoRouter = new TychoRouterExposed(permit2Address, WETH_ADDR);
        tychoRouter.grantRole(keccak256("EXECUTOR_SETTER_ROLE"), BOB);
        tychoRouter.grantRole(keccak256("FUND_RESCUER_ROLE"), FUND_RESCUER);
        tychoRouter.grantRole(keccak256("FEE_SETTER_ROLE"), FEE_SETTER);
        tychoRouter.grantRole(keccak256("PAUSER_ROLE"), PAUSER);
        tychoRouter.grantRole(keccak256("UNPAUSER_ROLE"), UNPAUSER);
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
