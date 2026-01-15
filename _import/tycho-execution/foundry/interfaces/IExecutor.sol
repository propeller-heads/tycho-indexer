// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../src/RestrictTransferFrom.sol";

pragma abicoder v2;

interface IExecutor {
    /**
     * @notice Performs a swap on a liquidity pool.
     * @dev This method takes the amount of the input token and returns the amount of
     * the output token which has been swapped, along with the output token address
     * and the receiver address where tokens were sent.
     *
     * Note Part of the informal interface is that the executor supports sending the received
     *  tokens to a receiver address. If the underlying smart contract does not provide this
     *  functionality consider adding an additional transfer in the implementation.
     *
     * @param amountIn The amount of the input token to swap.
     * @param data Data that holds information necessary to perform the swap.
     * @return calculatedAmount The amount of the output token swapped, depending on
     * the givenAmount inputted.
     * @return tokenOut The address of the output token.
     * @return receiver The address where the output tokens were sent.
     */
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount, address tokenOut, address receiver);

    /**
     * @notice Gets transfer data for pre-swap token transfers.
     * @dev Used by the Dispatcher to determine if tokens need to be transferred
     * before executing the protocol's swap code. Some protocols require tokens
     * to be transferred upfront, while others handle transfers in callbacks.
     *
     * @param data The encoded swap data.
     * @return transferType The type of transfer to perform before the swap.
     * @return receiver The address that should receive the tokens.
     * @return tokenIn The address of the input token to transfer.
     */
    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        );
}

interface IExecutorErrors {
    error InvalidParameterLength(uint256);
    error UnknownPoolType(uint8);
}
