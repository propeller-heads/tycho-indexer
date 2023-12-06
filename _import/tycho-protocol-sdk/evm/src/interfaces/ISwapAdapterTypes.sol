// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import {IERC20} from "openzeppelin-contracts/contracts/interfaces/IERC20.sol";

interface ISwapAdapterTypes {
    /// @dev The OrderSide enum represents possible sides of a trade: Sell or
    /// Buy. E.g. if OrderSide is Sell, the sell amount is interpreted to be
    /// fixed.
    enum OrderSide {
        Sell,
        Buy
    }

    /// @dev The Capability enum represents possible features of a trading
    /// pool.
    enum Capability {
        Unset,
        // Support OrderSide.Sell values (required)
        SellOrder,
        // Support OrderSide.Buy values (optional)
        BuyOrder,
        // Support evaluating the price function (optional)
        PriceFunction,
        // Support tokens that charge a fee on transfer (optional)
        FeeOnTransfer,
        // The pool does not suffer from price impact and maintains a constant
        // price for increasingly larger specified amounts. (optional)
        ConstantPrice,
        // Indicates that the pool does not read it's own token balances while
        // swapping. (optional)
        TokenBalanceIndependent,
        // Indicates that prices are returned scaled, else it is assumed prices
        // still require scaling by token decimals. (required)
        ScaledPrices
    }

    /// @dev Representation used for rational numbers such as prices.
    // TODO: Use only uint128 for numerator and denominator.
    struct Fraction {
        uint256 numerator;
        uint256 denominator;
    }

    /// @dev The Trade struct holds data about an executed trade.
    struct Trade {
        // If the side is sell, it is the amount of tokens sold. If the side is
        // buy, it is the amount of tokens bought.
        uint256 calculatedAmount;
        // The amount of gas used in the trade.
        uint256 gasUsed;
        // The price of the pool after the trade. For zero use Fraction(0, 1).
        Fraction price;
    }

    /// @dev The Unavailable error is thrown when a pool or swap is not
    /// available for unexpected reason. E.g. it was paused due to a bug.
    error Unavailable(string reason);

    /// @dev The LimitExceeded error is thrown when a limit has been exceeded.
    /// E.g. the specified amount can't be traded safely.
    error LimitExceeded(uint256 limit);

    /// @dev The NotImplemented error is thrown when a function is not
    /// implemented.
    error NotImplemented(string reason);
}
