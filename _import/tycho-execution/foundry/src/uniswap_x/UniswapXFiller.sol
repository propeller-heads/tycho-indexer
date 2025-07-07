// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "./IReactor.sol";
import "./IReactorCallback.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Address.sol";

error UniswapXFiller__AddressZero();

contract UniswapXFiller is AccessControl, IReactorCallback {
    using SafeERC20 for IERC20;

    // UniswapX V2DutchOrder Reactor
    IReactor public constant USXEDAReactor =
        IReactor(0x00000011F84B9aa48e5f8aA8B9897600006289Be);
    address public immutable tychoRouter;

    // keccak256("NAME_OF_ROLE") : save gas on deployment
    bytes32 public constant REACTOR_ROLE =
        0x39dd1d7269516fc1f719706a5e9b05cdcb1644978808b171257d9a8eab55dd57;
    bytes32 public constant EXECUTOR_ROLE =
        0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63;

    event Withdrawal(
        address indexed token, uint256 amount, address indexed receiver
    );

    constructor(address _tychoRouter) {
        if (_tychoRouter == address(0)) revert UniswapXFiller__AddressZero();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REACTOR_ROLE, address(USXEDAReactor));
        tychoRouter = _tychoRouter;
    }

    function execute(SignedOrder calldata order, bytes calldata callbackData)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        USXEDAReactor.executeWithCallback(order, callbackData);
    }

    function reactorCallback(
        ResolvedOrder[] calldata resolvedOrders,
        bytes calldata callbackData
    ) external onlyRole(REACTOR_ROLE) {
        // TODO
    }

    /**
     * @dev Allows granting roles to multiple accounts in a single call.
     */
    function batchGrantRole(bytes32 role, address[] memory accounts)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        for (uint256 i = 0; i < accounts.length; i++) {
            _grantRole(role, accounts[i]);
        }
    }

    /**
     * @dev Allows withdrawing any ERC20 funds if funds get stuck in case of a bug.
     */
    function withdraw(IERC20[] memory tokens, address receiver)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (receiver == address(0)) revert UniswapXFiller__AddressZero();

        for (uint256 i = 0; i < tokens.length; i++) {
            // slither-disable-next-line calls-loop
            uint256 tokenBalance = tokens[i].balanceOf(address(this));
            if (tokenBalance > 0) {
                emit Withdrawal(address(tokens[i]), tokenBalance, receiver);
                tokens[i].safeTransfer(receiver, tokenBalance);
            }
        }
    }

    /**
     * @dev Allows withdrawing any NATIVE funds if funds get stuck in case of a bug.
     * The contract should never hold any NATIVE tokens for security reasons.
     */
    function withdrawNative(address receiver)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (receiver == address(0)) revert UniswapXFiller__AddressZero();

        uint256 amount = address(this).balance;
        if (amount > 0) {
            emit Withdrawal(address(0), amount, receiver);
            Address.sendValue(payable(receiver), amount);
        }
    }

    /**
     * @dev Allows this contract to receive native token with empty msg.data from contracts
     */
    receive() external payable {
        require(msg.sender.code.length != 0);
    }
}
