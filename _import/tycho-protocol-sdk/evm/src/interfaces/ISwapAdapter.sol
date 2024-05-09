// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import {ISwapAdapterTypes} from "src/interfaces/ISwapAdapterTypes.sol";

/// @title ISwapAdapter
/// @dev Implement this interface to support Propeller routing through your
/// pools. Before implementing the interface we need to introduce some function
/// for a given pool. The main one, the swap(x) function, implements a sell
/// order of a specified token.
/// The gas function simply
/// returns the estimated gas cost given a specified amount x. Last but not
/// least, the price function is the derivative of the swap function. It
/// represents the best possible price a user can get from a pool after swapping
/// x of the specified token. During calls to swap and getLimits, the caller can
/// be assumed to have the required sell or buy token balance as well as
/// unlimited approvals to this contract.
interface ISwapAdapter is ISwapAdapterTypes {
    /// @notice Calculates pool prices for specified amounts (optional).
    /// @dev The returned prices should include all dex fees. In case the fee is
    /// dynamic, the returned price is expected to include the minimum fee.
    /// Ideally this method should be implemented, although it is optional as
    /// the price function can be numerically estimated from the swap function.
    /// In case it is not available, it should be flagged via capabilities and
    /// calling it should revert using the `NotImplemented` error. The method
    /// needs to be implemented as view as this is usually more efficient and
    /// can be run in parallel.
    /// @param poolId The ID of the trading pool.
    /// @param sellToken The token being sold.
    /// @param buyToken The token being bought.
    /// @param specifiedAmounts The specified amounts used for price
    /// calculation.
    /// @return prices array of prices as fractions corresponding to the
    /// provided amounts.
    function price(
        bytes32 poolId,
        address sellToken,
        address buyToken,
        uint256[] memory specifiedAmounts
    ) external returns (Fraction[] memory prices);

    /**
     * @notice Simulates swapping tokens on a given pool.
     * @dev This function should be state modifying, meaning it should actually
     * execute the swap and change the state of the EVM accordingly. Please
     * include a gas usage estimate for each amount. This can be achieved e.g. by
     * using the `gasleft()` function. The return type `Trade` has an attribute
     * called price which should contain the value of `price(specifiedAmount)`.
     * As this is optional, defined via `Capability.PriceFunction`, it is valid
     * to return a Fraction(0, 0) value for this price. In that case the price
     * will be estimated numerically.
     * @param poolId The ID of the trading pool.
     * @param sellToken The token being sold.
     * @param buyToken The token being bought.
     * @param side The side of the trade (Sell or Buy).
     * @param specifiedAmount The amount to be traded.
     * @return trade Trade struct representing the executed trade.
     */
    function swap(
        bytes32 poolId,
        address sellToken,
        address buyToken,
        OrderSide side,
        uint256 specifiedAmount
    ) external returns (Trade memory trade);

    /// @notice Retrieves the limits for each token.
    /// @dev Retrieve the maximum limits of a token that can be traded. The
    /// limit is reached when the change in the received amounts is zero or
    /// close to zero or when the swap fails because of the pools restrictions.
    /// Overestimate if in doubt rather than underestimate. The
    /// swap function should not error with `LimitExceeded` if called with
    /// amounts below the limit.
    /// @param poolId The ID of the trading pool.
    /// @param sellToken The token being sold.
    /// @param buyToken The token being bought.
    /// @return limits An array of limits.
    function getLimits(bytes32 poolId, address sellToken, address buyToken)
        external
        returns (uint256[] memory limits);

    /// @notice Retrieves the capabilities of the selected pool.
    /// @param poolId The ID of the trading pool.
    /// @return capabilities An array of Capability.
    function getCapabilities(
        bytes32 poolId,
        address sellToken,
        address buyToken
    ) external returns (Capability[] memory capabilities);

    /// @notice Retrieves the tokens in the selected pool.
    /// @dev Mainly used for testing as this is redundant with the required
    /// substreams implementation.
    /// @param poolId The ID of the trading pool.
    /// @return tokens An array of address contracts.
    function getTokens(bytes32 poolId)
        external
        returns (address[] memory tokens);

    /// @notice Retrieves a range of pool IDs.
    /// @dev Mainly used for testing. It is alright to not return all available
    /// pools here. Nevertheless, this is useful to test against the substreams
    /// implementation. If implemented, it saves time writing custom tests.
    /// @param offset The starting index from which to retrieve pool IDs.
    /// @param limit The maximum number of pool IDs to retrieve.
    /// @return ids An array of pool IDs.
    function getPoolIds(uint256 offset, uint256 limit)
        external
        returns (bytes32[] memory ids);
}
