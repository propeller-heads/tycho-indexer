// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";

interface IPairFunctionTypes {
    /// @dev The SwapSide enum represents possible sides of a trade: Sell or Buy.
    /// @dev E.g. if SwapSide is Sell, the sell amount is interpreted to be fixed.
    enum SwapSide {
        Sell,
        Buy
    }

    /// @dev The Capabilities enum represents possible features of a trading pair.
    enum Capabilities {
        Unset,
        // Support SwapSide.Sell values (required)
        SellSide,
        // Support SwapSide.Buy values (optional)
        BuySide,
        // Support evaluating the price function (optional)
        PriceFunction,
        // Support tokens that charge a fee on transfer (optional)
        FeeOnTransfer,
        // The pair does not suffer from price impact and mantains
        // a constant price for increasingly larger speficied amounts.
        // (optional)
        ConstantPrice,
        // Indicates that the pair does not read it's own token balances
        // while swapping. (optional)
        TokenBalanceIndependent,
        // Indicates that prices are returned scaled, else it is assumed
        // prices still require scaling by token decimals.
        ScaledPrices
    }

    /// @dev Representation used for rational numbers such as prices.
    struct Fraction {
        // TODO: rename numerator
        uint256 nominator;
        uint256 denominator;
    }

    /// @dev The Trade struct holds data about an executed trade.
    struct Trade {
        uint256 receivedAmount; // The amount received from the trade.
        uint256 gasUsed; // The amount of gas used in the trade.
        Fraction price; // The price of the pair after the trade.
    }

    /// @dev The Unavailable error is thrown when a pool or swap is not
    /// @dev available for unexpected reason, e.g. because it was paused
    /// @dev due to a bug.
    error Unavailable(string reason);

    /// @dev The LimitExceeded error is thrown when a limit has been
    /// @dev exceeded. E.g. the specified amount can't be traded safely.
    error LimitExceeded(uint256 limit);
}
