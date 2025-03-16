// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../lib/IWETH.sol";
import "../lib/bytes/LibPrefixLengthEncodedByteArray.sol";

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";
import "./Dispatcher.sol";
import {LibSwap} from "../lib/LibSwap.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";

//                                         ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                                   ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                             ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                          ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                       ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷   ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                   ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷       ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                 ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷      ✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷      ✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//              ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷    ✷✷✷✷✷✷✷✷✷✷✷✷✷
//             ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷      ✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷       ✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//            ✷✷✷✷✷✷✷✷✷✷✷✷           ✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷     ✷✷✷✷✷✷✷✷✷         ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//            ✷✷✷✷✷✷✷✷✷✷✷✷                   ✷✷✷✷✷✷           ✷✷✷✷✷✷         ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//            ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷                                   ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//            ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷                  ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//            ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷                  ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//            ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷                                   ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//            ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷         ✷✷✷✷✷✷           ✷✷✷✷✷✷                   ✷✷✷✷✷✷✷✷✷✷✷✷
//            ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷         ✷✷✷✷✷✷✷✷✷     ✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷           ✷✷✷✷✷✷✷✷✷✷✷✷
//             ✷✷✷✷✷✷✷✷✷✷✷✷✷✷       ✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//              ✷✷✷✷✷✷✷✷✷✷✷✷✷    ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷      ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                 ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷      ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                   ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷      ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷    ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                       ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                          ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                             ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                                  ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//                                         ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//
//
//     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷   ✷✷✷✷✷✷       ✷✷✷✷✷✷       ✷✷✷✷✷✷✷         ✷✷✷✷✷✷      ✷✷✷✷✷✷         ✷✷✷✷✷✷✷
//     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷    ✷✷✷✷✷✷    ✷✷✷✷✷✷✷    ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷     ✷✷✷✷✷✷      ✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//           ✷✷✷✷✷✷           ✷✷✷✷✷✷ ✷✷✷✷✷✷     ✷✷✷✷✷✷     ✷✷✷✷✷✷✷   ✷✷✷✷✷✷      ✷✷✷✷✷✷    ✷✷✷✷✷✷     ✷✷✷✷✷✷✷
//           ✷✷✷✷✷✷            ✷✷✷✷✷✷✷✷✷✷      ✷✷✷✷✷✷✷               ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷   ✷✷✷✷✷✷✷      ✷✷✷✷✷✷
//           ✷✷✷✷✷✷              ✷✷✷✷✷✷✷        ✷✷✷✷✷✷      ✷✷✷✷✷✷   ✷✷✷✷✷✷      ✷✷✷✷✷✷    ✷✷✷✷✷✷      ✷✷✷✷✷✷
//           ✷✷✷✷✷✷               ✷✷✷✷✷          ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷    ✷✷✷✷✷✷      ✷✷✷✷✷✷     ✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷✷
//           ✷✷✷✷✷✷               ✷✷✷✷✷              ✷✷✷✷✷✷✷✷        ✷✷✷✷✷✷      ✷✷✷✷✷✷         ✷✷✷✷✷✷✷✷

error TychoRouter__AddressZero();
error TychoRouter__EmptySwaps();
error TychoRouter__NegativeSlippage(uint256 amount, uint256 minAmount);
error TychoRouter__AmountInDiffersFromConsumed(
    uint256 amountIn, uint256 amountConsumed
);
error TychoRouter__MessageValueMismatch(uint256 value, uint256 amount);
error TychoRouter__InvalidDataLength();
error TychoRouter__UndefinedMinAmountOut();

contract TychoRouter is AccessControl, Dispatcher, Pausable, ReentrancyGuard {
    IAllowanceTransfer public immutable permit2;
    IWETH private immutable _weth;

    using SafeERC20 for IERC20;
    using LibPrefixLengthEncodedByteArray for bytes;
    using LibSwap for bytes;

    //keccak256("NAME_OF_ROLE") : save gas on deployment
    bytes32 public constant EXECUTOR_SETTER_ROLE =
        0x6a1dd52dcad5bd732e45b6af4e7344fa284e2d7d4b23b5b09cb55d36b0685c87;
    bytes32 public constant FEE_SETTER_ROLE =
        0xe6ad9a47fbda1dc18de1eb5eeb7d935e5e81b4748f3cfc61e233e64f88182060;
    bytes32 public constant PAUSER_ROLE =
        0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a;
    bytes32 public constant UNPAUSER_ROLE =
        0x427da25fe773164f88948d3e215c94b6554e2ed5e5f203a821c9f2f6131cf75a;
    bytes32 public constant FUND_RESCUER_ROLE =
        0x912e45d663a6f4cc1d0491d8f046e06c616f40352565ea1cdb86a0e1aaefa41b;

    address public feeReceiver;

    // Fee should be expressed in basis points (1/100th of a percent)
    // For example, 100 = 1%, 500 = 5%, 1000 = 10%
    uint256 public fee;

    event Withdrawal(
        address indexed token, uint256 amount, address indexed receiver
    );
    event FeeReceiverSet(
        address indexed oldFeeReceiver, address indexed newFeeReceiver
    );
    event FeeSet(uint256 indexed oldFee, uint256 indexed newFee);

    constructor(address _permit2, address weth) {
        if (_permit2 == address(0) || weth == address(0)) {
            revert TychoRouter__AddressZero();
        }
        permit2 = IAllowanceTransfer(_permit2);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _weth = IWETH(weth);
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph, supporting internal token amount splits.
     *         This function enables multi-step swaps, optional ETH wrapping/unwrapping, and validates the output amount
     *         against a user-specified minimum. This function expects the input tokens to already be in the router at
     *         the time of calling.
     *
     * @dev
     * - If `wrapEth` is true, the contract wraps the provided native ETH into WETH and uses it as the sell token.
     * - If `unwrapEth` is true, the contract converts the resulting WETH back into native ETH before sending it to the receiver.
     * - Swaps are executed sequentially using the `_swap` function.
     * - A fee is deducted from the output token if `fee > 0`, and the remaining amount is sent to the receiver.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut` and `minAmountOut` is greater than 0.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param wrapEth If true, wraps the input token (native ETH) into WETH.
     * @param unwrapEth If true, unwraps the resulting WETH into native ETH and sends it to the receiver.
     * @param nTokens The total number of tokens involved in the swap graph (used to initialize arrays for internal calculations).
     * @param receiver The address to receive the output tokens.
     * @param swaps Encoded swap graph data containing details of each swap.
     *
     * @return amountOut The total amount of the output token received by the receiver, after deducting fees if applicable.
     */
    function splitSwap(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        bool wrapEth,
        bool unwrapEth,
        uint256 nTokens,
        address receiver,
        bytes calldata swaps
    ) public payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
        return _splitSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            wrapEth,
            unwrapEth,
            nTokens,
            receiver,
            swaps
        );
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph, supporting internal token amount splits.
     *         This function enables multi-step swaps, optional ETH wrapping/unwrapping, and validates the output amount
     *         against a user-specified minimum.
     *
     * @dev
     * - If `wrapEth` is true, the contract wraps the provided native ETH into WETH and uses it as the sell token.
     * - If `unwrapEth` is true, the contract converts the resulting WETH back into native ETH before sending it to the receiver.
     * - For ERC20 tokens, Permit2 is used to approve and transfer tokens from the caller to the router.
     * - Swaps are executed sequentially using the `_swap` function.
     * - A fee is deducted from the output token if `fee > 0`, and the remaining amount is sent to the receiver.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut` and `minAmountOut` is greater than 0.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param wrapEth If true, wraps the input token (native ETH) into WETH.
     * @param unwrapEth If true, unwraps the resulting WETH into native ETH and sends it to the receiver.
     * @param nTokens The total number of tokens involved in the swap graph (used to initialize arrays for internal calculations).
     * @param receiver The address to receive the output tokens.
     * @param permitSingle A Permit2 structure containing token approval details for the input token. Ignored if `wrapEth` is true.
     * @param signature A valid signature authorizing the Permit2 approval. Ignored if `wrapEth` is true.
     * @param swaps Encoded swap graph data containing details of each swap.
     *
     * @return amountOut The total amount of the output token received by the receiver, after deducting fees if applicable.
     */
    function splitSwapPermit2(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        bool wrapEth,
        bool unwrapEth,
        uint256 nTokens,
        address receiver,
        IAllowanceTransfer.PermitSingle calldata permitSingle,
        bytes calldata signature,
        bytes calldata swaps
    ) external payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        // For native ETH, assume funds already in our router. Else, transfer and handle approval.
        if (tokenIn != address(0)) {
            permit2.permit(msg.sender, permitSingle, signature);
            permit2.transferFrom(
                msg.sender,
                address(this),
                uint160(amountIn),
                permitSingle.details.token
            );
        }

        return _splitSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            wrapEth,
            unwrapEth,
            nTokens,
            receiver,
            swaps
        );
    }

    /**
     * @notice Internal implementation of the core swap logic shared between splitSwap() and splitSwapPermit2().
     *
     * @notice This function centralizes the swap execution logic.
     * @notice For detailed documentation on parameters and behavior, see the documentation for
     * splitSwap() and splitSwapPermit2() functions.
     *
     */
    function _splitSwapChecked(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        bool wrapEth,
        bool unwrapEth,
        uint256 nTokens,
        address receiver,
        bytes calldata swaps
    ) internal returns (uint256 amountOut) {
        if (receiver == address(0)) {
            revert TychoRouter__AddressZero();
        }
        if (minAmountOut == 0) {
            revert TychoRouter__UndefinedMinAmountOut();
        }

        // Assume funds are already in the router.
        if (wrapEth) {
            _wrapETH(amountIn);
            tokenIn = address(_weth);
        }

        uint256 initialBalance = tokenIn == address(0)
            ? address(this).balance
            : IERC20(tokenIn).balanceOf(address(this));

        amountOut = _splitSwap(amountIn, nTokens, swaps);
        uint256 currentBalance = tokenIn == address(0)
            ? address(this).balance
            : IERC20(tokenIn).balanceOf(address(this));

        uint256 amountConsumed = initialBalance - currentBalance;

        if (tokenIn != tokenOut && amountConsumed != amountIn) {
            revert TychoRouter__AmountInDiffersFromConsumed(
                amountIn, amountConsumed
            );
        }

        if (fee > 0) {
            uint256 feeAmount = (amountOut * fee) / 10000;
            amountOut -= feeAmount;
            IERC20(tokenOut).safeTransfer(feeReceiver, feeAmount);
        }

        if (amountOut < minAmountOut) {
            revert TychoRouter__NegativeSlippage(amountOut, minAmountOut);
        }

        if (unwrapEth) {
            _unwrapETH(amountOut);
        }
        if (tokenOut == address(0)) {
            Address.sendValue(payable(receiver), amountOut);
        } else {
            IERC20(tokenOut).safeTransfer(receiver, amountOut);
        }
    }

    /**
     * @dev Executes sequential swaps as defined by the provided swap graph.
     *
     * This function processes a series of swaps encoded in the `swaps_` byte array. Each swap operation determines:
     * - The indices of the input and output tokens (via `tokenInIndex()` and `tokenOutIndex()`).
     * - The portion of the available amount to be used for the swap, indicated by the `split` value.
     *
     * Three important notes:
     * - The contract assumes that token indexes follow a specific order: the sell token is at index 0, followed by any
     *  intermediary tokens, and finally the buy token.
     * - A `split` value of 0 is interpreted as 100% of the available amount (i.e., the entire remaining balance).
     *  This means that in scenarios without explicit splits the value should be 0, and when splits are present,
     *  the last swap should also have a split value of 0.
     * - In case of cyclic swaps, the output token is the same as the input token.
     *  `cyclicSwapAmountOut` is used to track the amount of the output token, and is updated when
     *  the `tokenOutIndex` is 0.
     *
     * @param amountIn The initial amount of the sell token to be swapped.
     * @param nTokens The total number of tokens involved in the swap path, used to initialize arrays for internal tracking.
     * @param swaps_ Encoded swap graph data containing the details of each swap operation.
     *
     * @return The total amount of the buy token obtained after all swaps have been executed.
     */
    function _splitSwap(
        uint256 amountIn,
        uint256 nTokens,
        bytes calldata swaps_
    ) internal returns (uint256) {
        if (swaps_.length == 0) {
            revert TychoRouter__EmptySwaps();
        }

        uint256 currentAmountIn;
        uint256 currentAmountOut;
        uint8 tokenInIndex = 0;
        uint8 tokenOutIndex = 0;
        uint24 split;
        bytes calldata swapData;

        uint256[] memory remainingAmounts = new uint256[](nTokens);
        uint256[] memory amounts = new uint256[](nTokens);
        uint256 cyclicSwapAmountOut = 0;
        amounts[0] = amountIn;
        remainingAmounts[0] = amountIn;

        while (swaps_.length > 0) {
            (swapData, swaps_) = swaps_.next();
            tokenInIndex = swapData.tokenInIndex();
            tokenOutIndex = swapData.tokenOutIndex();
            split = swapData.splitPercentage();

            currentAmountIn = split > 0
                ? (amounts[tokenInIndex] * split) / 0xffffff
                : remainingAmounts[tokenInIndex];

            currentAmountOut = _callExecutor(
                swapData.executor(), currentAmountIn, swapData.protocolData()
            );
            // Checks if the output token is the same as the input token
            if (tokenOutIndex == 0) {
                cyclicSwapAmountOut += currentAmountOut;
            } else {
                amounts[tokenOutIndex] += currentAmountOut;
            }
            remainingAmounts[tokenOutIndex] += currentAmountOut;
            remainingAmounts[tokenInIndex] -= currentAmountIn;
        }
        return tokenOutIndex == 0 ? cyclicSwapAmountOut : amounts[tokenOutIndex];
    }

    /**
     * @dev We use the fallback function to allow flexibility on callback.
     */
    fallback() external {
        _handleCallback(msg.data);
    }

    /**
     * @dev Pauses the contract
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @dev Unpauses the contract
     */
    function unpause() external onlyRole(UNPAUSER_ROLE) {
        _unpause();
    }

    /**
     * @dev Allows granting roles to multiple accounts in a single call.
     */
    function batchGrantRole(bytes32 role, address[] memory accounts)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        for (uint256 i = 0; i < accounts.length; i++) {
            _grantRole(role, accounts[i]);
        }
    }

    /**
     * @dev Entrypoint to add or replace an approved executor contract address
     * @param targets address of the executor contract
     */
    function setExecutors(address[] memory targets)
        external
        onlyRole(EXECUTOR_SETTER_ROLE)
    {
        for (uint256 i = 0; i < targets.length; i++) {
            _setExecutor(targets[i]);
        }
    }

    /**
     * @dev Entrypoint to remove an approved executor contract address
     * @param target address of the executor contract
     */
    function removeExecutor(address target)
        external
        onlyRole(EXECUTOR_SETTER_ROLE)
    {
        _removeExecutor(target);
    }

    /**
     * @dev Allows setting the fee receiver.
     */
    function setFeeReceiver(address newfeeReceiver)
        external
        onlyRole(FEE_SETTER_ROLE)
    {
        if (newfeeReceiver == address(0)) revert TychoRouter__AddressZero();
        emit FeeReceiverSet(feeReceiver, newfeeReceiver);
        feeReceiver = newfeeReceiver;
    }

    /**
     * @dev Allows setting the fee.
     */
    function setFee(uint256 newFee) external onlyRole(FEE_SETTER_ROLE) {
        emit FeeSet(fee, newFee);
        fee = newFee;
    }

    /**
     * @dev Allows withdrawing any ERC20 funds if funds get stuck in case of a bug.
     */
    function withdraw(IERC20[] memory tokens, address receiver)
        external
        onlyRole(FUND_RESCUER_ROLE)
    {
        if (receiver == address(0)) revert TychoRouter__AddressZero();

        for (uint256 i = 0; i < tokens.length; i++) {
            // slither-disable-next-line calls-loop
            uint256 tokenBalance = tokens[i].balanceOf(address(this));
            if (tokenBalance > 0) {
                emit Withdrawal(address(tokens[i]), tokenBalance, receiver);
                tokens[i].safeTransfer(receiver, tokenBalance);
            }
        }
    }

    /**
     * @dev Allows withdrawing any NATIVE funds if funds get stuck in case of a bug.
     * The contract should never hold any NATIVE tokens for security reasons.
     */
    function withdrawNative(address receiver)
        external
        onlyRole(FUND_RESCUER_ROLE)
    {
        if (receiver == address(0)) revert TychoRouter__AddressZero();

        uint256 amount = address(this).balance;
        if (amount > 0) {
            emit Withdrawal(address(0), amount, receiver);
            Address.sendValue(payable(receiver), amount);
        }
    }

    /**
     * @dev Wraps a defined amount of ETH.
     * @param amount of native ETH to wrap.
     */
    function _wrapETH(uint256 amount) internal {
        if (msg.value > 0 && msg.value != amount) {
            revert TychoRouter__MessageValueMismatch(msg.value, amount);
        }
        _weth.deposit{value: amount}();
    }

    /**
     * @dev Unwraps a defined amount of WETH.
     * @param amount of WETH to unwrap.
     */
    function _unwrapETH(uint256 amount) internal {
        _weth.withdraw(amount);
    }

    /**
     * @dev Allows this contract to receive native token with empty msg.data from contracts
     */
    receive() external payable {
        require(msg.sender.code.length != 0);
    }

    /**
     * @dev Called by UniswapV3 pool when swapping on it.
     * See in IUniswapV3SwapCallback for documentation.
     */
    function uniswapV3SwapCallback(
        int256, /* amount0Delta */
        int256, /* amount1Delta */
        bytes calldata data
    ) external {
        if (data.length < 24) revert TychoRouter__InvalidDataLength();
        // We are taking advantage of the fact that the data we need is already encoded in the correct format inside msg.data
        // This way we preserve the bytes calldata (and don't need to convert it to bytes memory)
        uint256 dataOffset = 4 + 32 + 32 + 32; // Skip selector + 2 ints + data_offset
        uint256 dataLength =
            uint256(bytes32(msg.data[dataOffset:dataOffset + 32]));

        bytes calldata fullData = msg.data[4:dataOffset + 32 + dataLength];
        _handleCallback(fullData);
    }

    /**
     * @dev Called by UniswapV4 pool manager after achieving unlock state.
     */
    function unlockCallback(bytes calldata data)
        external
        returns (bytes memory)
    {
        if (data.length < 24) revert TychoRouter__InvalidDataLength();
        _handleCallback(data);
        return "";
    }
}
