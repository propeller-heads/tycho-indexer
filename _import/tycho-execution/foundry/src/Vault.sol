// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC6909/ERC6909.sol";

error Vault__InsufficientBalance(
    address user,
    address token,
    uint256 requested,
    uint256 available
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

    // Transient storage slots for tracking deltas during swap sequences
    // keccak256("TychoVault#NEGATIVE_DELTA_COUNT")
    uint256 private constant _NEGATIVE_DELTA_COUNT_SLOT =
        0x675e351c150ddfdbd3bc96ad8c0c5cc3e6f0d3c18723512ac3c7dfed159e94d5;

    // ============ ERC6909 Overrides and Extensions ============

    /**
     * @dev Override balanceOf to use our own mapping instead of ERC6909's
     *
     */
    function balanceOf(
        address owner,
        uint256 id
    ) public view virtual override returns (uint256) {
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
                revert ERC6909InsufficientBalance(
                    from,
                    fromBalance,
                    amount,
                    id
                );
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
    function _update(
        address from,
        address to,
        uint256 id,
        uint256 amount
    ) internal virtual override {
        _updateWithoutEvent(from, to, id, amount);
        emit Transfer(msg.sender, from, to, id, amount);
    }

    /**
     * @dev Create new _mint that does not emit a Transfer event. This should be used by inner methods of the
     * TychoRouter to save gas during swapping.
     */
    // TODO: remove this once used
    // slither-disable-next-line dead-code
    function _mintWithoutEvent(
        address to,
        uint256 id,
        uint256 amount
    ) internal {
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
    function _burnWithoutEvent(
        address from,
        uint256 id,
        uint256 amount
    ) internal {
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
    function deposit(
        address token,
        uint256 amount
    ) external payable nonReentrant {
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
                msg.sender,
                token,
                amount,
                balance
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

    /**
     * @dev Internal helper to get transient storage slot for a token delta
     * @notice Only needs token since transient storage is scoped to current transaction's sender
     */
    function _getDeltaSlot(address token) private pure returns (uint256 slot) {
        // Generate unique slot: keccak256(token, "TychoVault#DELTA")
        slot = uint256(keccak256(abi.encodePacked(token, "TychoVault#DELTA")));
        return slot;
    }

    /**
     * @dev Get the current delta from transient storage
     * @notice Retrieves delta for current transaction's sender
     */
    // Assembly required for transient storage operations (tload)
    // slither-disable-next-line assembly
    function _getDelta(address token) internal view returns (int256 delta) {
        uint256 slot = _getDeltaSlot(token);
        assembly {
            delta := tload(slot)
        }
    }

    /**
     * @dev Set the delta in transient storage
     */
    // Assembly required for transient storage operations (tstore)
    // slither-disable-next-line assembly
    function _setDelta(address token, int256 delta) internal {
        uint256 slot = _getDeltaSlot(token);
        assembly {
            tstore(slot, delta)
        }
    }

    /**
     * @dev Get negative delta count from transient storage
     */
    // Assembly required for transient storage operations (tload)
    // slither-disable-next-line assembly
    function _getNegativeDeltaCount() internal view returns (uint256 count) {
        assembly {
            count := tload(_NEGATIVE_DELTA_COUNT_SLOT)
        }
    }

    /**
     * @dev Set negative delta count in transient storage
     */
    // Assembly required for transient storage operations (tstore)
    // slither-disable-next-line assembly
    function _setNegativeDeltaCount(uint256 count) internal {
        assembly {
            tstore(_NEGATIVE_DELTA_COUNT_SLOT, count)
        }
    }

    /**
     * @dev Update delta accounting (transient storage)
     * @notice This updates the transient delta for the current sender, not the persistent vault balance
     * @param token The token to update
     * @param deltaChange The change to apply (positive to credit, negative to debit)
     */
    function _updateDeltaAccounting(
        address token,
        int256 deltaChange
    ) internal virtual {
        if (deltaChange == 0) return;

        int256 oldDelta = _getDelta(token);
        int256 newDelta = oldDelta + deltaChange;

        // Update negative delta counter based on transitions
        if (oldDelta < 0 && newDelta >= 0) {
            // Was negative, now non-negative: decrement counter
            _setNegativeDeltaCount(_getNegativeDeltaCount() - 1);
        } else if (oldDelta >= 0 && newDelta < 0) {
            // Was non-negative, now negative: increment counter
            _setNegativeDeltaCount(_getNegativeDeltaCount() + 1);
        }

        _setDelta(token, newDelta);
    }

    /**
     * @dev Internal helper to debit user's actual vault balance (persistent storage)
     * @notice This debits the persistent vault balance, not the transient delta
     */
    function _debitVault(
        address user,
        address token,
        uint256 amount
    ) internal virtual {
        if (amount == 0) return;

        uint256 id = uint256(uint160(token));
        uint256 balance = balanceOf(user, id);

        if (balance < amount) {
            revert TychoVault__InsufficientBalance(
                user,
                token,
                amount,
                balance
            );
        }
        _burn(user, id, amount);
    }

    /**
     * @dev Internal helper to credit user's actual vault balance (persistent storage)
     * @notice This credits the persistent vault balance, not the transient delta
     */
    function _creditVault(
        address user,
        address token,
        uint256 amount
    ) internal virtual {
        if (amount == 0) return;

        uint256 id = uint256(uint160(token));

        _mint(user, id, amount);
    }

    // ============ Utils methods ============

    /**
     * @dev Converts a token address to an ID
     */
    function _toId(address token) internal view virtual returns (uint256) {
        return uint256(uint160(token));
    }
}
