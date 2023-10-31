// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";

/// @title IPairFunctions
/// @dev Implement this interface to support propeller routing through your pairs.
/// @dev Before implementing the interface we need to introduce three function for a
/// @dev given pair: The swap(x), gas(x) and price(x) functions:
/// @dev The swap function accepts some specified token amount: x and returns the
/// @dev amount y a user can get by swapping x through the venue.
/// @dev The gas function simply returns the estimated gas cost given a specified
/// @dev amount x.
/// @dev Last but not least, the price function is the derivative of the swap
/// @dev function. It represents the best possible price a user can get from a
/// @dev pair after swapping x of the specified token.
/// @dev During calls to price, swap and getLimits, the caller can be assumed to
/// @dev have the required sell or buy token balance as well as unlimited approvals
/// @dev to this contract.
interface IPairFunctions {
    /// @dev The SwapSide enum represents possible sides of a trade: Sell or Buy.
    /// @dev E.g. if SwapSide is Sell, the sell amount is interpreted to be fixed.
    enum SwapSide {
        Sell,
        Buy
    }

    /// @dev The Capabilities enum represents possible features of a trading pair.
    enum Capabilities
    // Support SwapSide.Sell values (required)
    {
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
        TokenBalanceIndependent
    }

    /// @dev Representation used for rational numbers such as prices.
    struct Fraction {
        uint256 nominator;
        uint256 denominator;
    }

    /// @dev The Trade struct holds data about an executed trade.
    struct Trade {
        uint256 receivedAmount; // The amount received from the trade.
        uint256 gasUsed; // The amount of gas used in the trade.
        uint256 Fraction; // The price of the pair after the trade.
    }

    /// @dev The Unavailable error is thrown when a pool or swap is not
    /// @dev available for unexpected reason, e.g. because it was paused
    /// @dev due to a bug.
    error Unavailable(string reason);

    /// @dev The LimitExceeded error is thrown when a limit has been
    /// @dev exceeded. E.g. the specified amount can't be traded safely.
    error LimitExceeded(uint256 limit);

    /// @notice Calculates pair prices for specified amounts (optional).
    /// @dev The returned prices should include all dex fees, in case the fee
    /// @dev is dynamic, the returned price is expected to include the minimum fee.
    /// @dev Ideally this method should be implemented, although it is optional as
    /// @dev the price function can be numerically estimated from the swap function.
    /// @dev In case it is not available it should be flagged via capabilities and
    /// @dev calling it should revert using the `NotImplemented` error. In case implemented
    /// @dev the method should ideally be view as this is usually more efficient
    /// @dev and can be run in parallel. If necessary though, the method is allowed to
    /// @dev be state changing this is still better than not providing a implementation
    /// @dev all.
    /// @param pairId The ID of the trading pair.
    /// @param sellToken The token being sold.
    /// @param buyToken The token being bought.
    /// @param specifiedAmounts The specified amounts used for price calculation.
    /// @return prices array of prices as fractions corresponding to the provided amounts.
    function price(bytes32 pairId, IERC20 sellToken, IERC20 buyToken, uint256[] memory sellAmounts)
        external
        returns (Fraction[] prices);

    /// @notice Simulates swapping tokens on a given pair.
    /// @dev This function should be state modifying meaning it should actually execute
    /// @dev the swap and change the state of the evm accordingly.
    /// @dev Please include a gas usage estimate for each amount. This can be achieved
    /// @dev by using the `gasleft()` function.
    /// @dev
    /// @param pairId The ID of the trading pair.
    /// @param sellToken The token being sold.
    /// @param buyToken The token being bought.
    /// @param side The side of the trade (Sell or Buy).
    /// @param specifiedAmounts The amounts to be traded.
    /// @return trades array of Trade structs representing each executed trade.
    function swap(bytes32 pairId, IERC20 sellToken, IERC20 buyToken, SwapSide side, uint256[] memory specifiedAmounts)
        external
        returns (Trade[] trades);

    /// @notice Retrieves the limits for each token.
    /// @dev Retrieve the maximum limits of a token that can be traded. The limit is reached
    /// @dev when the change in the received amounts is zero or close to zero. If in doubt
    /// @dev over estimate. The swap function should not error with `LimitExceeded` if
    /// @dev called with amounts below the limit.
    /// @param pairId The ID of the trading pair.
    /// @return An array of limits.
    function getLimits(bytes32 pairId, SwapSide side) external returns (uint256[]);

    /// @notice Retrieves the capabilities of the selected pair.
    /// @param pairId The ID of the trading pair.
    /// @return An array of Capabilities.
    function getCapabilities(bytes32 pairId, IERC20 sellToken, IERC20 buyToken) external returns (Capabilities[]);

    /// @notice Retrieves the tokens in the selected pair.
    /// @dev Mainly used for testing as this is redundant with the required substreams
    /// @dev implementation.
    /// @param pairId The ID of the trading pair.
    /// @return tokens array of IERC20 contracts.
    function getTokens(bytes32 pairId) external returns (IERC20[] tokens);

    /// @notice Retrieves a range of pool IDs.
    /// @dev Mainly used for testing it is alright to not return all available pools here.
    /// @dev Nevertheless this is useful to test against the substreams implementation. If
    /// @dev implemented it safes time writing custom tests.
    /// @param offset The starting index from which to retrieve pool IDs.
    /// @param limit The maximum number of pool IDs to retrieve.
    /// @return ids array of pool IDs.
    function getPoolIds(uint256 offset, uint256 limit) external returns (bytes32[] ids);
}
