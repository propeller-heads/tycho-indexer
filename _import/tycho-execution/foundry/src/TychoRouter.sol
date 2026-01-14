// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {
    LibPrefixLengthEncodedByteArray
} from "../lib/bytes/LibPrefixLengthEncodedByteArray.sol";

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    ReentrancyGuard
} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {
    IAllowanceTransfer
} from "@permit2/src/interfaces/IAllowanceTransfer.sol";
import {Dispatcher} from "./Dispatcher.sol";
import {LibSwap} from "../lib/LibSwap.sol";
import {RestrictTransferFrom} from "./RestrictTransferFrom.sol";

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
error TychoRouter__AmountOutNotFullyReceived(
    uint256 amountIn, uint256 amountConsumed
);
error TychoRouter__InvalidDataLength();
error TychoRouter__UndefinedMinAmountOut();

contract TychoRouter is AccessControl, Dispatcher, Pausable, ReentrancyGuard {
    uint16 private _routerFeeOnOutputBps; // Router fee on output amount in basis points
    uint16 private _routerFeeOnSolverFeeBps; // Router fee on solver fee in basis points
    address private _feeTaker; // Address of the fee taker contract
    address private _routerFeeReceiver; // Address whose vault receives router fees

    // Per-user custom router fees on output amount
    // If set, this will override the default router fee on output for the user
    mapping(address => bool) private _hasCustomRouterFeeOnOutput;
    mapping(address => uint16) private _customRouterFeeOnOutput;

    // Per-user custom router fees on solver fee
    // If set, this will override the default router fee on solver fee for the user
    mapping(address => bool) private _hasCustomRouterFeeOnSolverFee;
    mapping(address => uint16) private _customRouterFeeOnSolverFee;
    using SafeERC20 for IERC20;
    using LibPrefixLengthEncodedByteArray for bytes;
    using LibSwap for bytes;

    //keccak256("NAME_OF_ROLE") : save gas on deployment
    bytes32 public constant EXECUTOR_SETTER_ROLE =
        0x6a1dd52dcad5bd732e45b6af4e7344fa284e2d7d4b23b5b09cb55d36b0685c87;
    bytes32 public constant PAUSER_ROLE =
        0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a;
    bytes32 public constant UNPAUSER_ROLE =
        0x427da25fe773164f88948d3e215c94b6554e2ed5e5f203a821c9f2f6131cf75a;
    bytes32 public constant ROUTER_FEE_SETTER_ROLE =
        0x9939157be7760e9462f1d5a0dcad88b616ddc64138e317108b40b1cf55601348;

    event Withdrawal(
        address indexed token, uint256 amount, address indexed receiver
    );
    event RouterFeeOnOutputUpdated(uint16 oldFeeBps, uint16 newFeeBps);
    event RouterFeeOnSolverFeeUpdated(uint16 oldFeeBps, uint16 newFeeBps);
    event CustomRouterFeeOnOutputUpdated(
        address indexed user, uint16 oldFeeBps, uint16 newFeeBps
    );
    event CustomRouterFeeOnSolverFeeUpdated(
        address indexed user, uint16 oldFeeBps, uint16 newFeeBps
    );
    event CustomRouterFeeOnOutputRemoved(address indexed user);
    event CustomRouterFeeOnSolverFeeRemoved(address indexed user);
    event FeeTakerUpdated(address oldExecutor, address newExecutor);
    event RouterFeeReceiverUpdated(address oldReceiver, address newReceiver);

    constructor(address _permit2) Dispatcher(_permit2) {
        if (_permit2 == address(0)) {
            revert TychoRouter__AddressZero();
        }
        permit2 = IAllowanceTransfer(_permit2);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _routerFeeReceiver = msg.sender;
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph, supporting internal token amount splits.
     *         This function enables multi-step swaps and validates the output amount against a user-specified minimum.
     *
     * @dev
     * - Swaps are executed sequentially using the `_swap` function.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut` and `minAmountOut` is greater than 0.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param nTokens The total number of tokens involved in the swap graph (used to initialize arrays for internal calculations).
     * @param receiver The address to receive the output tokens.
     * @param isTransferFromAllowed If false, the contract will assume that the input token is already transferred to the contract and don't allow any transferFroms
     * @param swaps Encoded swap graph data containing details of each swap.
     *
     * @return amountOut The total amount of the output token received by the receiver.
     */
    function splitSwap(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        uint256 nTokens,
        address receiver,
        bool isTransferFromAllowed,
        bytes calldata swaps
    ) public payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        uint256 initialBalanceTokenOut = _balanceOf(tokenOut, receiver);
        _tstoreTransferFromInfo(tokenIn, amountIn, false, isTransferFromAllowed);

        return _splitSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            nTokens,
            receiver,
            swaps
        );
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph, supporting internal token amount splits.
     *         This function enables multi-step swaps and validates the output amount against a user-specified minimum.
     *
     * @dev
     * - For ERC20 tokens, Permit2 is used to approve and transfer tokens from the caller to the router.
     * - Swaps are executed sequentially using the `_swap` function.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut` and `minAmountOut` is greater than 0.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param nTokens The total number of tokens involved in the swap graph (used to initialize arrays for internal calculations).
     * @param receiver The address to receive the output tokens.
     * @param permitSingle A Permit2 structure containing token approval details for the input token.
     * @param signature A valid signature authorizing the Permit2 approval.
     * @param swaps Encoded swap graph data containing details of each swap.
     *
     * @return amountOut The total amount of the output token received by the receiver.
     */
    function splitSwapPermit2(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        uint256 nTokens,
        address receiver,
        IAllowanceTransfer.PermitSingle calldata permitSingle,
        bytes calldata signature,
        bytes calldata swaps
    ) external payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        uint256 initialBalanceTokenOut = _balanceOf(tokenOut, receiver);
        // For native ETH, assume funds already in our router. Else, handle approval.
        if (tokenIn != address(0)) {
            permit2.permit(msg.sender, permitSingle, signature);
        }
        _tstoreTransferFromInfo(tokenIn, amountIn, true, true);

        return _splitSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            nTokens,
            receiver,
            swaps
        );
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph with no split routes.
     *         This function enables multi-step swaps and validates the output amount against a user-specified minimum.
     *
     * @dev
     * - Swaps are executed sequentially using the `_swap` function.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut` and `minAmountOut` is greater than 0.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param receiver The address to receive the output tokens.
     * @param isTransferFromAllowed If false, the contract will assume that the input token is already transferred to the contract and don't allow any transferFroms
     * @param swaps Encoded swap graph data containing details of each swap.
     *
     * @return amountOut The total amount of the output token received by the receiver.
     */
    function sequentialSwap(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        address receiver,
        bool isTransferFromAllowed,
        bytes calldata swaps
    ) public payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        uint256 initialBalanceTokenOut = _balanceOf(tokenOut, receiver);
        _tstoreTransferFromInfo(tokenIn, amountIn, false, isTransferFromAllowed);

        return _sequentialSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            receiver,
            swaps
        );
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph with no split routes.
     *         This function enables multi-step swaps and validates the output amount against a user-specified minimum.
     *
     * @dev
     * - For ERC20 tokens, Permit2 is used to approve and transfer tokens from the caller to the router.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut` and `minAmountOut` is greater than 0.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param receiver The address to receive the output tokens.
     * @param permitSingle A Permit2 structure containing token approval details for the input token.
     * @param signature A valid signature authorizing the Permit2 approval.
     * @param swaps Encoded swap graph data containing details of each swap.
     *
     * @return amountOut The total amount of the output token received by the receiver.
     */
    function sequentialSwapPermit2(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        address receiver,
        IAllowanceTransfer.PermitSingle calldata permitSingle,
        bytes calldata signature,
        bytes calldata swaps
    ) external payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        uint256 initialBalanceTokenOut = _balanceOf(tokenOut, receiver);
        // For native ETH, assume funds already in our router. Else, handle approval.
        if (tokenIn != address(0)) {
            permit2.permit(msg.sender, permitSingle, signature);
        }

        _tstoreTransferFromInfo(tokenIn, amountIn, true, true);

        return _sequentialSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            receiver,
            swaps
        );
    }

    /**
     * @notice Executes a single swap operation.
     *         This function validates the output amount against a user-specified minimum.
     *
     * @dev
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut` and `minAmountOut` is greater than 0.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param receiver The address to receive the output tokens.
     * @param isTransferFromAllowed If false, the contract will assume that the input token is already transferred to the contract and don't allow any transferFroms
     * @param swapData Encoded swap details.
     *
     * @return amountOut The total amount of the output token received by the receiver.
     */
    function singleSwap(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        address receiver,
        bool isTransferFromAllowed,
        bytes calldata swapData
    ) public payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        uint256 initialBalanceTokenOut = _balanceOf(tokenOut, receiver);
        _tstoreTransferFromInfo(tokenIn, amountIn, false, isTransferFromAllowed);

        return _singleSwap(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            receiver,
            swapData
        );
    }

    /**
     * @notice Executes a single swap operation.
     *         This function validates the output amount against a user-specified minimum.
     *
     * @dev
     * - For ERC20 tokens, Permit2 is used to approve and transfer tokens from the caller to the router.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut` and `minAmountOut` is greater than 0.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param receiver The address to receive the output tokens.
     * @param permitSingle A Permit2 structure containing token approval details for the input token.
     * @param signature A valid signature authorizing the Permit2 approval.
     * @param swapData Encoded swap details.
     *
     * @return amountOut The total amount of the output token received by the receiver.
     */
    function singleSwapPermit2(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        address receiver,
        IAllowanceTransfer.PermitSingle calldata permitSingle,
        bytes calldata signature,
        bytes calldata swapData
    ) external payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        uint256 initialBalanceTokenOut = _balanceOf(tokenOut, receiver);
        // For native ETH, assume funds already in our router. Else, handle approval.
        if (tokenIn != address(0)) {
            permit2.permit(msg.sender, permitSingle, signature);
        }
        _tstoreTransferFromInfo(tokenIn, amountIn, true, true);

        return _singleSwap(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            receiver,
            swapData
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
        uint256 initialBalanceTokenOut,
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

        amountOut = _splitSwap(amountIn, nTokens, swaps);

        if (amountOut < minAmountOut) {
            revert TychoRouter__NegativeSlippage(amountOut, minAmountOut);
        }

        _verifyAmountOutWasReceived(
            tokenIn,
            tokenOut,
            initialBalanceTokenOut,
            amountOut,
            receiver,
            amountIn
        );
    }

    /**
     * @notice Internal implementation of the core swap logic shared between singleSwap() and singleSwapPermit2().
     *
     * @notice This function centralizes the swap execution logic.
     * @notice For detailed documentation on parameters and behavior, see the documentation for
     * singleSwap() and singleSwapPermit2() functions.
     *
     */
    function _singleSwap(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        uint256 initialBalanceTokenOut,
        address receiver,
        bytes calldata swap_
    ) internal returns (uint256 amountOut) {
        if (receiver == address(0)) {
            revert TychoRouter__AddressZero();
        }
        if (minAmountOut == 0) {
            revert TychoRouter__UndefinedMinAmountOut();
        }

        (address executor, bytes calldata protocolData) =
            swap_.decodeSingleSwap();

        amountOut = _callSwapOnExecutor(executor, amountIn, protocolData);

        if (amountOut < minAmountOut) {
            revert TychoRouter__NegativeSlippage(amountOut, minAmountOut);
        }

        _verifyAmountOutWasReceived(
            tokenIn,
            tokenOut,
            initialBalanceTokenOut,
            amountOut,
            receiver,
            amountIn
        );
    }

    /**
     * @notice Internal implementation of the core swap logic shared between sequentialSwap() and sequentialSwapPermit2().
     *
     * @notice This function centralizes the swap execution logic.
     * @notice For detailed documentation on parameters and behavior, see the documentation for
     * sequentialSwap() and sequentialSwapPermit2() functions.
     *
     */
    function _sequentialSwapChecked(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        uint256 initialBalanceTokenOut,
        address receiver,
        bytes calldata swaps
    ) internal returns (uint256 amountOut) {
        if (receiver == address(0)) {
            revert TychoRouter__AddressZero();
        }
        if (minAmountOut == 0) {
            revert TychoRouter__UndefinedMinAmountOut();
        }

        amountOut = _sequentialSwap(amountIn, swaps);

        if (amountOut < minAmountOut) {
            revert TychoRouter__NegativeSlippage(amountOut, minAmountOut);
        }

        _verifyAmountOutWasReceived(
            tokenIn,
            tokenOut,
            initialBalanceTokenOut,
            amountOut,
            receiver,
            amountIn
        );
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
        address executor;
        bytes calldata protocolData;
        bytes calldata swapData;

        uint256[] memory remainingAmounts = new uint256[](nTokens);
        uint256[] memory amounts = new uint256[](nTokens);
        uint256 cyclicSwapAmountOut = 0;
        amounts[0] = amountIn;
        remainingAmounts[0] = amountIn;

        while (swaps_.length > 0) {
            (swapData, swaps_) = swaps_.next();

            (tokenInIndex, tokenOutIndex, split, executor, protocolData) =
                swapData.decodeSplitSwap();

            currentAmountIn = split > 0
                ? (amounts[tokenInIndex] * split) / 0xffffff
                : remainingAmounts[tokenInIndex];

            currentAmountOut =
                _callSwapOnExecutor(executor, currentAmountIn, protocolData);
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
     * @dev Executes sequential swaps as defined by the provided swap graph.
     *
     * @param amountIn The initial amount of the sell token to be swapped.
     * @param swaps_ Encoded swap graph data containing the details of each swap operation.
     *
     * @return calculatedAmount The total amount of the buy token obtained after all swaps have been executed.
     */
    function _sequentialSwap(uint256 amountIn, bytes calldata swaps_)
        internal
        returns (uint256 calculatedAmount)
    {
        bytes calldata swap;
        calculatedAmount = amountIn;
        while (swaps_.length > 0) {
            (swap, swaps_) = swaps_.next();

            (address executor, bytes calldata protocolData) =
                swap.decodeSingleSwap();

            calculatedAmount =
                _callSwapOnExecutor(executor, calculatedAmount, protocolData);
        }
    }

    /**
     * @dev We use the fallback function to allow flexibility on callback.
     */
    fallback(bytes calldata data) external returns (bytes memory) {
        return _callHandleCallbackOnExecutor(data);
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
     * @dev Sets the router fee on output amount in basis points
     * @param feeBps The fee in basis points (e.g., 1 = 0.01%, 100 = 1%)
     */
    function setRouterFeeOnOutput(uint16 feeBps)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        uint16 oldFeeBps = _routerFeeOnOutputBps;
        _routerFeeOnOutputBps = feeBps;
        emit RouterFeeOnOutputUpdated(oldFeeBps, feeBps);
    }

    /**
     * @dev Returns the current router fee on output amount in basis points
     * @return The fee in basis points
     */
    function getRouterFeeOnOutput() external view returns (uint16) {
        return _routerFeeOnOutputBps;
    }

    /**
     * @dev Sets a custom router fee on output amount for a specific user
     * @param user The user address to set the custom fee for
     * @param feeBps The fee in basis points (e.g., 1 = 0.01%, 100 = 1%)
     */
    function setCustomRouterFeeOnOutput(address user, uint16 feeBps)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        uint16 oldFeeBps = _hasCustomRouterFeeOnOutput[user]
            ? _customRouterFeeOnOutput[user]
            : _routerFeeOnOutputBps;
        _customRouterFeeOnOutput[user] = feeBps;
        _hasCustomRouterFeeOnOutput[user] = true;
        emit CustomRouterFeeOnOutputUpdated(user, oldFeeBps, feeBps);
    }

    /**
     * @dev Removes the custom router fee on output amount for a specific user, reverting to default
     * @param user The user address to remove the custom fee from
     */
    function removeCustomRouterFeeOnOutput(address user)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        _hasCustomRouterFeeOnOutput[user] = false;
        delete _customRouterFeeOnOutput[user];
        emit CustomRouterFeeOnOutputRemoved(user);
    }

    /**
     * @dev Returns the effective router fee on output amount for a specific user
     * @param user The user address to check
     * @return The fee in basis points (custom if set, otherwise default)
     */
    function getCustomRouterFeeOnOutput(address user)
        external
        view
        returns (uint16)
    {
        return _hasCustomRouterFeeOnOutput[user]
            ? _customRouterFeeOnOutput[user]
            : _routerFeeOnOutputBps;
    }

    /**
     * @dev Sets the router platform fee on solver fee in basis points
     * @param feeBps The fee in basis points (e.g., 1 = 0.01%, 100 = 1%)
     */
    function setRouterFeeOnSolverFee(uint16 feeBps)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        uint16 oldFeeBps = _routerFeeOnSolverFeeBps;
        _routerFeeOnSolverFeeBps = feeBps;
        emit RouterFeeOnSolverFeeUpdated(oldFeeBps, feeBps);
    }

    /**
     * @dev Returns the current router platform fee on solver fee in basis points
     * @return The fee in basis points
     */
    function getRouterFeeOnSolverFee() external view returns (uint16) {
        return _routerFeeOnSolverFeeBps;
    }

    /**
     * @dev Sets a custom router fee on solver fee for a specific user
     * @param user The user address to set the custom fee for
     * @param feeBps The fee in basis points (e.g., 1 = 0.01%, 100 = 1%)
     */
    function setCustomRouterFeeOnSolverFee(address user, uint16 feeBps)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        uint16 oldFeeBps = _hasCustomRouterFeeOnSolverFee[user]
            ? _customRouterFeeOnSolverFee[user]
            : _routerFeeOnSolverFeeBps;
        _customRouterFeeOnSolverFee[user] = feeBps;
        _hasCustomRouterFeeOnSolverFee[user] = true;
        emit CustomRouterFeeOnSolverFeeUpdated(user, oldFeeBps, feeBps);
    }

    /**
     * @dev Removes the custom router fee on solver fee for a specific user, reverting to default
     * @param user The user address to remove the custom fee from
     */
    function removeCustomRouterFeeOnSolverFee(address user)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        _hasCustomRouterFeeOnSolverFee[user] = false;
        delete _customRouterFeeOnSolverFee[user];
        emit CustomRouterFeeOnSolverFeeRemoved(user);
    }

    /**
     * @dev Returns the effective router fee on solver fee for a specific user
     * @param user The user address to check
     * @return The fee in basis points (custom if set, otherwise default)
     */
    function getCustomRouterFeeOnSolverFee(address user)
        external
        view
        returns (uint16)
    {
        return _hasCustomRouterFeeOnSolverFee[user]
            ? _customRouterFeeOnSolverFee[user]
            : _routerFeeOnSolverFeeBps;
    }

    /**
     * @notice Sets the fee taker contract address
     * @param feeTaker The address of the fee taker contract
     */
    function setFeeTaker(address feeTaker)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        if (feeTaker == address(0)) {
            revert TychoRouter__AddressZero();
        }
        address oldExecutor = _feeTaker;
        _feeTaker = feeTaker;
        emit FeeTakerUpdated(oldExecutor, feeTaker);
    }

    /**
     * @dev Returns the current fee taker address
     */
    function getFeeTaker() external view returns (address) {
        return _feeTaker;
    }

    /**
     * @dev Sets the address that receives router fees
     * @param routerFeeReceiver The address to receive router fees
     */
    function setRouterFeeReceiver(address routerFeeReceiver)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        if (routerFeeReceiver == address(0)) {
            revert TychoRouter__AddressZero();
        }
        address oldReceiver = _routerFeeReceiver;
        _routerFeeReceiver = routerFeeReceiver;
        emit RouterFeeReceiverUpdated(oldReceiver, routerFeeReceiver);
    }

    /**
     * @dev Returns the current router fee receiver address
     */
    function getRouterFeeReceiver() external view returns (address) {
        return _routerFeeReceiver;
    }

    /**
     * @dev Allows this contract to receive native token with empty msg.data from contracts
     */
    receive() external payable {
        require(msg.sender.code.length != 0);
    }

    /**
     * @dev Gets balance of a token for a given address. Supports both native ETH and ERC20 tokens.
     */
    function _balanceOf(address token, address owner)
        internal
        view
        returns (uint256)
    {
        return token == address(0)
            ? owner.balance
            : IERC20(token).balanceOf(owner);
    }

    /**
     * @dev Verifies that the expected amount of output tokens was received by the receiver.
     * It also handles the case of arbitrage swaps where the input and output tokens are the same.
     */
    function _verifyAmountOutWasReceived(
        address tokenIn,
        address tokenOut,
        uint256 initialBalanceTokenOut,
        uint256 amountOut,
        address receiver,
        uint256 amountIn
    ) internal view {
        uint256 currentBalanceTokenOut = _balanceOf(tokenOut, receiver);
        if (tokenIn == tokenOut) {
            // If it is an arbitrage, we need to remove the amountIn from the initial balance to get a correct userAmount
            initialBalanceTokenOut -= amountIn;
        }
        uint256 userAmount = currentBalanceTokenOut - initialBalanceTokenOut;
        if (userAmount != amountOut) {
            revert TychoRouter__AmountOutNotFullyReceived(userAmount, amountOut);
        }
    }
}
