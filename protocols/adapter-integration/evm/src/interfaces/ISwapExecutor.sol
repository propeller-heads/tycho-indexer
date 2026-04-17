// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.7.5;

import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";

pragma abicoder v2;

interface ISwapExecutor {
    /**
     * @notice Performs a swap on a liquidity pool.
     * @dev This method can either take the amount of the input token or the
     * amount
     * of the output token that we would like to swap. If called with the amount
     * of
     * the  input token, the amount of the output token will be returned, and
     * vice
     * versa. Whether it is the input or output that is given, is encoded in the
     * data
     * parameter.
     *
     * Note Part of the informal interface is that the executor supports sending
     * the received
     *  tokens to a receiver address. If the underlying smart contract does not
     * provide this
     *  functionality consider adding an additional transfer in the
     * implementation.
     *
     *  This function is marked as `payable` to accommodate delegatecalls, which
     * can forward
     *  a potential `msg.value` to it.
     *
     * @param givenAmount The amount of either the input token or output token
     * to swap.
     * @param data Data that holds information necessary to perform the swap.
     * @return calculatedAmount The amount of either the input token or output
     * token
     * swapped, depending on the givenAmount inputted.
     */
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount);
}

interface ISwapExecutorErrors {
    error InvalidParameterLength(uint256);
    error UnknownPoolType(uint8);
}
