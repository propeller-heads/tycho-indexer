// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import "interfaces/ISwapAdapterTypes.sol";

/// @title ISwapAdapterTypes
/// @dev Implement this interface to support propeller routing through your
/// pairs. Before implementing the interface we need to introduce three function
/// for a given pair: The swap(x), gas(x) and price(x) functions: The swap
/// function accepts some specified token amount: x and returns the amount y a
/// user can get by swapping x through the venue. The gas function simply
/// returns the estimated gas cost given a specified amount x. Last but not
/// least, the price function is the derivative of the swap function. It
/// represents the best possible price a user can get from a pair after swapping
/// x of the specified token. During calls to swap and getLimits, the caller can
/// be assumed to have the required sell or buy token balance as well as
/// unlimited approvals to this contract.
interface ISwapAdapter is ISwapAdapterTypes {
    /// @notice Calculates pair prices for specified amounts (optional).
    /// @dev The returned prices should include all dex fees, in case the fee is
    /// dynamic, the returned price is expected to include the minimum fee.
    /// Ideally this method should be implemented, although it is optional as
    /// the price function can be numerically estimated from the swap function.
    /// In case it is not available it should be flagged via capabilities and
    /// calling it should revert using the `NotImplemented` error. The method
    /// needs to be implemented as view as this is usually more efficient and
    /// can be run in parallel. all.
    /// @param pairId The ID of the trading pair.
    /// @param sellToken The token being sold.
    /// @param buyToken The token being bought.
    /// @param sellAmounts The specified amounts used for price calculation.
    /// @return prices array of prices as fractions corresponding to the
    /// provided amounts.
    function price(
        bytes32 pairId,
        IERC20 sellToken,
        IERC20 buyToken,
        uint256[] memory sellAmounts
    ) external view returns (Fraction[] memory prices);

    /**
     * @notice Simulates swapping tokens on a given pair.
     * @dev This function should be state modifying meaning it should actually
     * execute the swap and change the state of the evm accordingly. Please
     * include a gas usage estimate for each amount. This can be achieved e.g.
     * by using the `gasleft()` function. The return type trade, has a price
     * attribute which should contain the value of `price(specifiedAmount)`. As
     * this is optional, defined via `Capability.PriceFunction`, it is valid to
     * return a zero value for this price in that case it will be estimated
     * numerically. To return zero use Fraction(0, 1).
     * @param pairId The ID of the trading pair.
     * @param sellToken The token being sold.
     * @param buyToken The token being bought.
     * @param side The side of the trade (Sell or Buy).
     * @param specifiedAmount The amount to be traded.
     * @return trade Trade struct representing the executed trade.
     */
    function swap(
        bytes32 pairId,
        IERC20 sellToken,
        IERC20 buyToken,
        SwapSide side,
        uint256 specifiedAmount
    ) external returns (Trade memory trade);

    /// @notice Retrieves the limits for each token.
    /// @dev Retrieve the maximum limits of a token that can be traded. The
    /// limit is reached when the change in the received amounts is zero or
    /// close to zero. If in doubt over estimate. The swap function should not
    /// error with `LimitExceeded` if called with amounts below the limit.
    /// @param pairId The ID of the trading pair.
    /// @return An array of limits.
    function getLimits(bytes32 pairId, SwapSide side)
        external
        returns (uint256[] memory);

    /// @notice Retrieves the capabilities of the selected pair.
    /// @param pairId The ID of the trading pair.
    /// @return An array of Capabilities.
    function getCapabilities(bytes32 pairId, IERC20 sellToken, IERC20 buyToken)
        external
        returns (Capabilities[] memory);

    /// @notice Retrieves the tokens in the selected pair.
    /// @dev Mainly used for testing as this is redundant with the required
    /// substreams implementation.
    /// @param pairId The ID of the trading pair.
    /// @return tokens array of IERC20 contracts.
    function getTokens(bytes32 pairId)
        external
        returns (IERC20[] memory tokens);

    /// @notice Retrieves a range of pool IDs.
    /// @dev Mainly used for testing it is alright to not return all available
    /// pools here. Nevertheless this is useful to test against the substreams
    /// implementation. If implemented it safes time writing custom tests.
    /// @param offset The starting index from which to retrieve pool IDs.
    /// @param limit The maximum number of pool IDs to retrieve.
    /// @return ids array of pool IDs.
    function getPoolIds(uint256 offset, uint256 limit)
        external
        returns (bytes32[] memory ids);
}
