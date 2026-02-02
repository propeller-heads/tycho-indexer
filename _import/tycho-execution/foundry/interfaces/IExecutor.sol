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
     * @param receiver The address where the output tokens will be sent.
     * @return amountOut The amount of the output token swapped, depending on
     * the amountIn.
     * @return tokenOut The address of the output token.
     */
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 amountOut, address tokenOut);

    /**
     * @notice Gets transfer data for pre-swap token transfers.
     * @dev Used by the Dispatcher to determine if tokens need to be transferred
     * before executing the protocol's swap code. Some protocols require tokens
     * to be transferred upfront, while others handle transfers in callbacks.
     *
     * @param data The encoded swap data.
     * @return baseTransferType The base transfer type for this executor (None, ProtocolWillDebit, Transfer or TransferNativeInExecutor).
     * @return receiver The address that should receive the pre swap tokens (usually a pool or the TychoRouter - depending on the protocol).
     * @return tokenIn The address of the input token to transfer.
     */
    function getTransferData(bytes calldata data)
        external
        payable
        returns (RestrictTransferFrom.TransferType baseTransferType, address receiver, address tokenIn);

    /**
     * @dev Defines if the current protocol can be used in an optimization from the previous swap (this is only used for the sequential swap case).
     * For example we might have a swap WETH --(1)--> USDC --(2)--> DAI.
     * Before we perform swap 1 we need to know the receiver of the token out. If the protocol of swap 2 can support
     * optimization then the receiver should be pool 2.
     * @param data The encoded swap data.
     * @return isOptimizable Bool where true means that the transfer is optimizable
     * @return receiver Address where to send the funds to. If the bool is false, it should be set to address(0)
     */
    function canReceiveFromPreviousSwap(bytes calldata data)
    external returns (bool isOptimizable, address receiver);

}

interface IExecutorErrors {
    error InvalidParameterLength(uint256);
    error UnknownPoolType(uint8);
}
