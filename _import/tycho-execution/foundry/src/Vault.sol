// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC6909/ERC6909.sol";

error TychoVault__InsufficientBalance(
    address user, address token, uint256 requested, uint256 available
);
error TychoVault__AmountZero();
error TychoVault__UnexpectedNegativeDelta(uint256 negativeCount);
error TychoVault__InvalidInputDelta(
    address token, int256 expected, int256 actual
);
error TychoVault__UnexpectedInputDelta(int256 inputDelta);

/**
 * @title Vault - ERC6909-compliant multi-token vault
 * @dev Implements ERC6909 for managing user token balances within the router.
 * Users can deposit tokens, use them for swaps, and withdraw them.
 */
abstract contract Vault is ERC6909, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // Vault balances - using our own mapping to avoid expensive Transfer events from ERC6909
    mapping(address => mapping(uint256 => uint256)) private _vaultBalances;

    // Transient storage slots for tracking deltas during swap sequences
    // keccak256("TychoVault#NEGATIVE_DELTA_COUNT")
    uint256 private constant _NEGATIVE_DELTA_COUNT_SLOT =
        0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b;

    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdrawal(
        address indexed user, address indexed token, uint256 amount
    );

    // ============ ERC6909 Overrides ============

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
     * @dev Override _update to use our own mapping and avoid emitting Transfer events
     * This is called by all balance-changing operations (transfer, approve, etc.)
     */
    function _update(address from, address to, uint256 id, uint256 amount)
        internal
        virtual
        override
    {
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
            revert TychoVault__AmountZero();
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
            revert TychoVault__AmountZero();
        }

        uint256 id = _toId(token);
        uint256 balance = balanceOf(msg.sender, id);
        if (balance < amount) {
            revert TychoVault__InsufficientBalance(
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

    /**
     * @dev Gets balance of a token for a given address. Supports both native ETH and ERC20 tokens.
     */
    function _balanceOf(address token, address owner)
        internal
        view
        virtual
        returns (uint256)
    {
        return token == address(0)
            ? owner.balance
            : IERC20(token).balanceOf(owner);
    }
}
