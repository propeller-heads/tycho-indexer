// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC6909/ERC6909.sol";

error Vault__InsufficientBalance(
    address user, address token, uint256 requested, uint256 available
);
error Vault__AmountZero();
error Vault__UnexpectedNegativeDelta(uint256 negativeCount);
error Vault__InvalidInputDelta(address token, int256 expected, int256 actual);
error Vault__UnexpectedInputDelta(int256 inputDelta);

/**
 * @title Vault - ERC6909-compliant multi-token vault
 * @dev Implements ERC6909 for managing user token balances within the router.
 * Users can deposit tokens, use them for swaps, and withdraw them.
 */
abstract contract Vault is ERC6909, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // Vault balances - using our own mapping to avoid expensive Transfer events from ERC6909
    mapping(address => mapping(uint256 => uint256)) private _vaultBalances;

    // ============ ERC6909 Overrides and Extensions ============

    /**
     * @dev Override balanceOf to use our own mapping instead of ERC6909's
     *
     */
    function balanceOf(address owner, uint256 id)
        public
        view
        virtual
        override
        returns (uint256)
    {
        return _vaultBalances[owner][id];
    }

    /**
     * @dev Rewrite _update to use our own mapping and avoid emitting Transfer events
     */
    function _updateWithoutEvent(
        address from,
        address to,
        uint256 id,
        uint256 amount
    ) internal virtual {
        if (from != address(0)) {
            uint256 fromBalance = _vaultBalances[from][id];
            if (fromBalance < amount) {
                revert ERC6909InsufficientBalance(from, fromBalance, amount, id);
            }
            unchecked {
                // Overflow not possible: amount <= fromBalance.
                _vaultBalances[from][id] = fromBalance - amount;
            }
        }
        if (to != address(0)) {
            _vaultBalances[to][id] += amount;
        }
        // Note: We intentionally do NOT emit Transfer events to save gas
    }

    /**
     * @dev Override _update to use our own mapping and emit Transfer events
     * This is called by all balance-changing operations (transfer, mint, etc.)
     */
    function _update(address from, address to, uint256 id, uint256 amount)
        internal
        virtual
        override
    {
        _updateWithoutEvent(from, to, id, amount);
        emit Transfer(msg.sender, from, to, id, amount);
    }

    /**
     * @dev Create new _mint that does not emit a Transfer event. This should be used by inner methods of the
     * TychoRouter to save gas during swapping.
     */
    // TODO: remove this once used
    // slither-disable-next-line dead-code
    function _mintWithoutEvent(address to, uint256 id, uint256 amount)
        internal
    {
        if (to == address(0)) {
            revert ERC6909InvalidReceiver(address(0));
        }
        _updateWithoutEvent(address(0), to, id, amount);
    }

    /**
     * @dev Create new _burn that does not emit a Transfer event. This should be used by inner methods of the
     * TychoRouter to save gas during swapping.
     */
    // TODO: remove this once used
    // slither-disable-next-line dead-code
    function _burnWithoutEvent(address from, uint256 id, uint256 amount)
        internal
    {
        if (from == address(0)) {
            revert ERC6909InvalidSender(address(0));
        }
        _updateWithoutEvent(from, address(0), id, amount);
    }

    // ============ ERC6909 Vault Functions ============

    /**
     * @notice Deposit tokens into the vault for the caller
     * @param token The token address to deposit (use address(0) for native ETH)
     * @param amount The amount to deposit
     */
    function deposit(address token, uint256 amount)
        external
        payable
        nonReentrant
    {
        if (amount == 0) {
            revert Vault__AmountZero();
        }

        uint256 id = _toId(token);

        if (token == address(0)) {
            // Native ETH deposit
            require(msg.value == amount, "Value mismatch");
            _mint(msg.sender, id, amount);
        } else {
            // ERC20 deposit - transfer to this contract (router)
            _mint(msg.sender, id, amount);
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }
    }

    /**
     * @notice Withdraw tokens from the vault
     * @param token The token to withdraw
     * @param amount The amount to withdraw
     */
    function withdraw(address token, uint256 amount) external nonReentrant {
        if (amount == 0) {
            revert Vault__AmountZero();
        }

        uint256 id = _toId(token);
        uint256 balance = balanceOf(msg.sender, id);
        if (balance < amount) {
            revert Vault__InsufficientBalance(
                msg.sender, token, amount, balance
            );
        }

        _burn(msg.sender, id, amount);

        // Transfer tokens from contract to user
        if (token == address(0)) {
            Address.sendValue(payable(msg.sender), amount);
        } else {
            IERC20(token).safeTransfer(msg.sender, amount);
        }
    }

    // ============ Utils methods ============

    /**
     * @dev Converts a token address to an ID
     */
    function _toId(address token) internal view virtual returns (uint256) {
        return uint256(uint160(token));
    }
}
