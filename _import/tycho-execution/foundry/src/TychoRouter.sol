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
import {ERC6909} from "@openzeppelin/contracts/token/ERC6909/ERC6909.sol";
import {Dispatcher} from "./Dispatcher.sol";
import {LibSwap} from "../lib/LibSwap.sol";
import {RestrictTransferFrom} from "./RestrictTransferFrom.sol";
import {IFeeCalculator} from "@interfaces/IFeeCalculator.sol";
import {FeeRecipient} from "../lib/FeeStructs.sol";

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
error TychoRouter__MsgValueDoesNotMatchAmountIn(
    uint256 msgValue, uint256 amountIn
);
error TychoRouter__MsgValueNotAllowedWithVaultMethod(uint256 msgValue);
error TychoRouter__MsgValueNotAllowedWithPermit2Method(uint256 msgValue);
error TychoRouter__NegativeSlippage(uint256 amount, uint256 minAmount);
error TychoRouter__AmountOutNotFullyReceived(
    uint256 amountIn, uint256 amountConsumed
);
error TychoRouter__InvalidDataLength();
error TychoRouter__UndefinedMinAmountOut();

contract TychoRouter is AccessControl, Dispatcher, Pausable {
    IFeeCalculator private _feeCalculator; // Fee calculator contract

    // Max amount of dust that can stay behind in the TychoRouter when swapping.
    // This is relevant for rebasing tokens like stETH where sometimes 1 WEI is lost per transfer.
    uint256 private constant ALLOWED_DUST = 2;

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
    event FeeCalculatorUpdated(
        address indexed oldCalculator, address indexed newCalculator
    );

    constructor(address _permit2) Dispatcher(_permit2) {
        if (_permit2 == address(0)) {
            revert TychoRouter__AddressZero();
        }
        permit2 = IAllowanceTransfer(_permit2);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Override supportsInterface to resolve conflict between AccessControl and ERC6909
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControl, ERC6909)
        returns (bool)
    {
        return AccessControl.supportsInterface(interfaceId)
            || ERC6909.supportsInterface(interfaceId);
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph, supporting internal token amount splits.
     *         This function enables multi-step swaps and validates the output amount against a user-specified minimum.
     *         Takes funds from the user's wallet using transferFrom.
     *
     * @dev
     * - Swaps are executed sequentially using the `_swap` function.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut`
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param nTokens The total number of tokens involved in the swap graph (used to initialize arrays for internal calculations).
     * @param receiver The address to receive the output tokens.
     * @param solverFeeBps Fee in basis points to be paid to the solver (0-10000, where 10000 = 100%)
     * @param solverFeeReceiver Address to receive the solver fee.
     * @param maxSolverContribution Maximum amount the solver will pay out of pocket to make the trade succeed.
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
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        bytes calldata swaps
    ) public payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        _updateNativeDeltaAccounting(amountIn);
        uint256 initialBalanceTokenOut = _getInitialBalanceTokenOut(
            tokenIn, amountIn, tokenOut, receiver, true
        );
        _tstoreTransferFromInfo(tokenIn, amountIn, false, false);

        return _splitSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            nTokens,
            receiver,
            solverFeeBps,
            solverFeeReceiver,
            maxSolverContribution,
            swaps
        );
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph, supporting internal token amount splits.
     *         This function enables multi-step swaps and validates the output amount against a user-specified minimum.
     *         Takes funds from the user's vault balance.
     *
     * @dev
     * - Swaps are executed sequentially using the `_swap` function.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut`.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param nTokens The total number of tokens involved in the swap graph (used to initialize arrays for internal calculations).
     * @param receiver The address to receive the output tokens.
     * @param solverFeeBps Fee in basis points to be paid to the solver (0-10000, where 10000 = 100%)
     * @param solverFeeReceiver Address to receive the solver fee.
     * @param maxSolverContribution Maximum amount the solver will pay out of pocket to make the trade succeed.
     * @param swaps Encoded swap graph data containing details of each swap.
     *
     * @return amountOut The total amount of the output token received by the receiver.
     */
    function splitSwapUsingVault(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        uint256 nTokens,
        address receiver,
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        bytes calldata swaps
    ) public payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        if (msg.value > 0) {
            revert TychoRouter__MsgValueNotAllowedWithVaultMethod(msg.value);
        }
        uint256 initialBalanceTokenOut = _getInitialBalanceTokenOut(
            tokenIn, amountIn, tokenOut, receiver, false
        );
        _tstoreTransferFromInfo(tokenIn, amountIn, false, true);

        return _splitSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            nTokens,
            receiver,
            solverFeeBps,
            solverFeeReceiver,
            maxSolverContribution,
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
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut`.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param nTokens The total number of tokens involved in the swap graph (used to initialize arrays for internal calculations).
     * @param receiver The address to receive the output tokens.
     * @param solverFeeBps Fee in basis points to be paid to the solver (0-10000, where 10000 = 100%)
     * @param solverFeeReceiver Address to receive the solver fee.
     * @param maxSolverContribution Maximum amount the solver will pay out of pocket to make the trade succeed.
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
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        IAllowanceTransfer.PermitSingle calldata permitSingle,
        bytes calldata signature,
        bytes calldata swaps
    ) external payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        if (msg.value > 0) {
            revert TychoRouter__MsgValueNotAllowedWithPermit2Method(msg.value);
        }
        uint256 initialBalanceTokenOut = _getInitialBalanceTokenOut(
            tokenIn, amountIn, tokenOut, receiver, true
        );
        // For native ETH, assume funds already in our router. Else, handle approval.
        if (tokenIn != address(0)) {
            permit2.permit(msg.sender, permitSingle, signature);
        }
        _tstoreTransferFromInfo(tokenIn, amountIn, true, false);

        return _splitSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            nTokens,
            receiver,
            solverFeeBps,
            solverFeeReceiver,
            maxSolverContribution,
            swaps
        );
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph with no split routes.
     *         This function enables multi-step swaps and validates the output amount against a user-specified minimum.
     *         Takes funds from the user's wallet using transferFrom.
     *
     * @dev
     * - Swaps are executed sequentially using the `_swap` function.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut`.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param receiver The address to receive the output tokens.
     * @param solverFeeBps Fee in basis points to be paid to the solver (0-10000, where 10000 = 100%)
     * @param solverFeeReceiver Address to receive the solver fee.
     * @param maxSolverContribution Maximum amount the solver will pay out of pocket to make the trade succeed.
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
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        bytes calldata swaps
    ) public payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        _updateNativeDeltaAccounting(amountIn);
        uint256 initialBalanceTokenOut = _getInitialBalanceTokenOut(
            tokenIn, amountIn, tokenOut, receiver, true
        );
        _tstoreTransferFromInfo(tokenIn, amountIn, false, false);

        return _sequentialSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            receiver,
            solverFeeBps,
            solverFeeReceiver,
            maxSolverContribution,
            swaps
        );
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph with no split routes.
     *         This function enables multi-step swaps and validates the output amount against a user-specified minimum.
     *         Takes funds from the user's vault balance.
     *
     * @dev
     * - Swaps are executed sequentially using the `_swap` function.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut`.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param receiver The address to receive the output tokens.
     * @param solverFeeBps Fee in basis points to be paid to the solver (0-10000, where 10000 = 100%)
     * @param solverFeeReceiver Address to receive the solver fee.
     * @param maxSolverContribution Maximum amount the solver will pay out of pocket to make the trade succeed.
     * @param swaps Encoded swap graph data containing details of each swap.
     *
     * @return amountOut The total amount of the output token received by the receiver.
     */
    function sequentialSwapUsingVault(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        address receiver,
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        bytes calldata swaps
    ) public payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        if (msg.value > 0) {
            revert TychoRouter__MsgValueNotAllowedWithVaultMethod(msg.value);
        }
        uint256 initialBalanceTokenOut = _getInitialBalanceTokenOut(
            tokenIn, amountIn, tokenOut, receiver, false
        );
        _tstoreTransferFromInfo(tokenIn, amountIn, false, true);

        return _sequentialSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            receiver,
            solverFeeBps,
            solverFeeReceiver,
            maxSolverContribution,
            swaps
        );
    }

    /**
     * @notice Executes a swap operation based on a predefined swap graph with no split routes.
     *         This function enables multi-step swaps and validates the output amount against a user-specified minimum.
     *
     * @dev
     * - For ERC20 tokens, Permit2 is used to approve and transfer tokens from the caller to the router.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut`.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param receiver The address to receive the output tokens.
     * @param solverFeeBps Fee in basis points to be paid to the solver (0-10000, where 10000 = 100%)
     * @param solverFeeReceiver Address to receive the solver fee.
     * @param maxSolverContribution Maximum amount the solver will pay out of pocket to make the trade succeed.
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
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        IAllowanceTransfer.PermitSingle calldata permitSingle,
        bytes calldata signature,
        bytes calldata swaps
    ) external payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        if (msg.value > 0) {
            revert TychoRouter__MsgValueNotAllowedWithPermit2Method(msg.value);
        }
        uint256 initialBalanceTokenOut = _getInitialBalanceTokenOut(
            tokenIn, amountIn, tokenOut, receiver, true
        );
        // For native ETH, assume funds already in our router. Else, handle approval.
        if (tokenIn != address(0)) {
            permit2.permit(msg.sender, permitSingle, signature);
        }

        _tstoreTransferFromInfo(tokenIn, amountIn, true, false);

        return _sequentialSwapChecked(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            receiver,
            solverFeeBps,
            solverFeeReceiver,
            maxSolverContribution,
            swaps
        );
    }

    /**
     * @notice Executes a single swap operation.
     *         This function validates the output amount against a user-specified minimum.
     *         Takes funds from the user's wallet using transferFrom.
     *
     * @dev
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut`.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param receiver The address to receive the output tokens.
     * @param solverFeeBps Fee in basis points to be paid to the solver (0-10000, where 10000 = 100%)
     * @param solverFeeReceiver Address to receive the solver fee.
     * @param maxSolverContribution Maximum amount the solver will pay out of pocket to make the trade succeed.
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
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        bytes calldata swapData
    ) public payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        _updateNativeDeltaAccounting(amountIn);
        uint256 initialBalanceTokenOut = _getInitialBalanceTokenOut(
            tokenIn, amountIn, tokenOut, receiver, true
        );
        _tstoreTransferFromInfo(tokenIn, amountIn, false, false);

        return _singleSwap(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            receiver,
            solverFeeBps,
            solverFeeReceiver,
            maxSolverContribution,
            swapData
        );
    }

    /**
     * @notice Executes a single swap operation.
     *         This function validates the output amount against a user-specified minimum.
     *         Takes funds from the user's vault balance.
     *
     * @dev
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut`.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param receiver The address to receive the output tokens.
     * @param solverFeeBps Fee in basis points to be paid to the solver (0-10000, where 10000 = 100%)
     * @param solverFeeReceiver Address to receive the solver fee.
     * @param maxSolverContribution Maximum amount the solver will pay out of pocket to make the trade succeed.
     * @param swapData Encoded swap details.
     *
     * @return amountOut The total amount of the output token received by the receiver.
     */
    function singleSwapUsingVault(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        address receiver,
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        bytes calldata swapData
    ) public payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        if (msg.value > 0) {
            revert TychoRouter__MsgValueNotAllowedWithVaultMethod(msg.value);
        }
        uint256 initialBalanceTokenOut = _getInitialBalanceTokenOut(
            tokenIn, amountIn, tokenOut, receiver, false
        );
        _tstoreTransferFromInfo(tokenIn, amountIn, false, true);

        return _singleSwap(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            receiver,
            solverFeeBps,
            solverFeeReceiver,
            maxSolverContribution,
            swapData
        );
    }

    /**
     * @notice Executes a single swap operation.
     *         This function validates the output amount against a user-specified minimum.
     *
     * @dev
     * - For ERC20 tokens, Permit2 is used to approve and transfer tokens from the caller to the router.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut`.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. This should always be set to avoid losing funds due to slippage.
     * @param receiver The address to receive the output tokens.
     * @param solverFeeReceiver Address to receive the solver fee.
     * @param maxSolverContribution Maximum amount the solver will pay out of pocket to make the trade succeed.
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
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        IAllowanceTransfer.PermitSingle calldata permitSingle,
        bytes calldata signature,
        bytes calldata swapData
    ) external payable whenNotPaused nonReentrant returns (uint256 amountOut) {
        if (msg.value > 0) {
            revert TychoRouter__MsgValueNotAllowedWithPermit2Method(msg.value);
        }
        uint256 initialBalanceTokenOut = _getInitialBalanceTokenOut(
            tokenIn, amountIn, tokenOut, receiver, true
        );
        // For native ETH, assume funds already in our router. Else, handle approval.
        if (tokenIn != address(0)) {
            permit2.permit(msg.sender, permitSingle, signature);
        }
        _tstoreTransferFromInfo(tokenIn, amountIn, true, false);

        return _singleSwap(
            amountIn,
            tokenIn,
            tokenOut,
            minAmountOut,
            initialBalanceTokenOut,
            receiver,
            solverFeeBps,
            solverFeeReceiver,
            maxSolverContribution,
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
    // State writes in _takeFees after external calls are safe because all public entry points use nonReentrant modifier
    // slither-disable-next-line reentrancy-benign
    function _splitSwapChecked(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        uint256 initialBalanceTokenOut,
        uint256 nTokens,
        address receiver,
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        bytes calldata swaps
    ) internal returns (uint256 amountOut) {
        if (receiver == address(0)) {
            revert TychoRouter__AddressZero();
        }
        if (minAmountOut == 0) {
            revert TychoRouter__UndefinedMinAmountOut();
        }

        uint256 amountOutBeforeFees = _splitSwap(amountIn, nTokens, swaps);
        amountOut = _takeFees(
            tokenOut,
            amountOutBeforeFees,
            msg.sender,
            solverFeeBps,
            solverFeeReceiver
        );

        amountOut = _maybeAddSolverContribution(
            amountOut, minAmountOut, maxSolverContribution, tokenOut, receiver
        );

        int256 outputDelta = _getDelta(tokenOut);
        if (outputDelta > 0) {
            // out tokens are still in the Router and need to be sent to the final receiver
            if (tokenOut == address(0)) {
                Address.sendValue(payable(receiver), amountOut);
            } else {
                IERC20(tokenOut).safeTransfer(receiver, amountOut);
            }
            _updateDeltaAccounting(tokenOut, -int256(amountOut));
        }

        // Finalize all transient deltas to persistent storage
        _finalizeBalances(msg.sender, tokenIn, amountIn);

        _verifyAmountOutWasReceived(
            tokenOut, initialBalanceTokenOut, amountOut, receiver
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
    // State writes in _takeFees after external calls are safe because all public entry points use nonReentrant modifier
    // slither-disable-next-line reentrancy-benign
    function _singleSwap(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        uint256 initialBalanceTokenOut,
        address receiver,
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
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

        uint256 amountOutBeforeFees =
            _callSwapOnExecutor(executor, amountIn, protocolData);
        amountOut = _takeFees(
            tokenOut,
            amountOutBeforeFees,
            msg.sender,
            solverFeeBps,
            solverFeeReceiver
        );

        amountOut = _maybeAddSolverContribution(
            amountOut, minAmountOut, maxSolverContribution, tokenOut, receiver
        );

        int256 outputDelta = _getDelta(tokenOut);
        if (outputDelta > 0) {
            // out tokens are still in the Router and need to be sent to the final receiver
            if (tokenOut == address(0)) {
                Address.sendValue(payable(receiver), amountOut);
            } else {
                IERC20(tokenOut).safeTransfer(receiver, amountOut);
            }
            _updateDeltaAccounting(tokenOut, -int256(amountOut));
        }

        // Finalize all transient deltas to persistent storage
        _finalizeBalances(msg.sender, tokenIn, amountIn);
        _verifyAmountOutWasReceived(
            tokenOut, initialBalanceTokenOut, amountOut, receiver
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
    // State writes in _takeFees after external calls are safe because all public entry points use nonReentrant modifier
    // slither-disable-next-line reentrancy-benign
    function _sequentialSwapChecked(
        uint256 amountIn,
        address tokenIn,
        address tokenOut,
        uint256 minAmountOut,
        uint256 initialBalanceTokenOut,
        address receiver,
        uint16 solverFeeBps,
        address solverFeeReceiver,
        uint256 maxSolverContribution,
        bytes calldata swaps
    ) internal returns (uint256 amountOut) {
        if (receiver == address(0)) {
            revert TychoRouter__AddressZero();
        }
        if (minAmountOut == 0) {
            revert TychoRouter__UndefinedMinAmountOut();
        }

        uint256 amountOutBeforeFees = _sequentialSwap(amountIn, swaps);
        amountOut = _takeFees(
            tokenOut,
            amountOutBeforeFees,
            msg.sender,
            solverFeeBps,
            solverFeeReceiver
        );

        amountOut = _maybeAddSolverContribution(
            amountOut, minAmountOut, maxSolverContribution, tokenOut, receiver
        );

        int256 outputDelta = _getDelta(tokenOut);
        if (outputDelta > 0) {
            // out tokens are still in the Router and need to be sent to the final receiver
            if (tokenOut == address(0)) {
                Address.sendValue(payable(receiver), amountOut);
            } else {
                IERC20(tokenOut).safeTransfer(receiver, amountOut);
            }
            _updateDeltaAccounting(tokenOut, -int256(amountOut));
        }

        // Finalize all transient deltas to persistent storage
        _finalizeBalances(msg.sender, tokenIn, amountIn);

        _verifyAmountOutWasReceived(
            tokenOut, initialBalanceTokenOut, amountOut, receiver
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
     * @notice Sets the fee calculator contract address
     * @param feeCalculator The address of the fee calculator contract
     */
    function setFeeCalculator(address feeCalculator)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        if (feeCalculator == address(0)) {
            revert TychoRouter__AddressZero();
        }
        address oldCalculator = address(_feeCalculator);
        _feeCalculator = IFeeCalculator(feeCalculator);
        emit FeeCalculatorUpdated(oldCalculator, feeCalculator);
    }

    /**
     * @dev Returns the current fee calculator address
     */
    function getFeeCalculator() external view returns (address) {
        return address(_feeCalculator);
    }

    /**
     * @notice Calculates and takes fees using the FeeCalculator contract
     * @param token The token address for which fees are being taken
     * @param amountIn The amount before fee deduction
     * @param user The user address to look up custom router fees for
     * @param solverFeeBps Solver fee in basis points
     * @param solverFeeReceiver Address to receive solver fees
     * @return amountOut The amount remaining after all fee deductions
     */
    function _takeFees(
        address token,
        uint256 amountIn,
        address user,
        uint16 solverFeeBps,
        address solverFeeReceiver
    ) internal returns (uint256 amountOut) {
        // If no fee calculator is set, return the full amount without taking fees
        if (address(_feeCalculator) == address(0)) {
            return amountIn;
        }

        FeeRecipient[] memory fees;
        (amountOut, fees) = _feeCalculator.calculateFee(
            amountIn, user, solverFeeBps, solverFeeReceiver
        );

        for (uint256 i = 0; i < fees.length; i++) {
            if (fees[i].feeAmount > 0) {
                // We still need to update the delta accounting to ensure the funds are
                // in the router after the final swap and have not bypassed the router
                // due to incorrect or malicious encoding. Updating the delta
                // accounting without funds will result in an additional negative
                // delta, and cause the _finalizeBalances method to revert.
                _updateDeltaAccounting(token, -int256(fees[i].feeAmount));
                _creditVault(fees[i].recipient, token, fees[i].feeAmount);
            }
        }
    }

    /**
     * @dev Allows this contract to receive native token with empty msg.data from contracts
     */
    receive() external payable {
        require(msg.sender.code.length != 0);
    }

    /**
     * @dev Updates delta accounting for native ETH received via msg.value
     * @notice This should be called at each entry point to credit the delta when ETH is sent
     */
    function _updateNativeDeltaAccounting(uint256 amountIn) internal {
        if (msg.value > 0) {
            // prevent unpredictable scenarios where the amountIn does not match exactly
            // what the caller sent
            if (msg.value != amountIn) {
                revert TychoRouter__MsgValueDoesNotMatchAmountIn(
                    msg.value, amountIn
                );
            }
            _updateDeltaAccounting(address(0), int256(msg.value));
        }
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
     * @dev Gets balance of token out for the receiver at the beginning of a swap
     */
    function _getInitialBalanceTokenOut(
        address tokenIn,
        uint256 amountIn,
        address tokenOut,
        address receiver,
        bool transferFrom
    ) internal view returns (uint256 initialBalanceTokenOut) {
        initialBalanceTokenOut = _balanceOf(tokenOut, receiver);
        if (tokenIn == tokenOut && transferFrom) {
            // If it is an arbitrage, we need to remove the amountIn from the initial balance to get a correct initial balance
            initialBalanceTokenOut -= amountIn;
        }
    }

    /**
     * @dev Verifies that the expected amount of output tokens was received by the receiver.
     * It also handles the case of arbitrage swaps where the input and output tokens are the same.
     */
    function _verifyAmountOutWasReceived(
        address tokenOut,
        uint256 initialBalanceTokenOut,
        uint256 amountOut,
        address receiver
    ) internal view {
        uint256 currentBalanceTokenOut = _balanceOf(tokenOut, receiver);

        uint256 userAmount = currentBalanceTokenOut - initialBalanceTokenOut;
        if (userAmount < amountOut - ALLOWED_DUST) {
            revert TychoRouter__AmountOutNotFullyReceived(userAmount, amountOut);
        }
    }

    /**
     * @dev If the amountOut is below the minAmountOut, it tries to add a solver contribution (if within limits).
     * If it can't, it raises NegativeSlippage.
     *   - If the out tokens are still in the Tycho Router, it adds the contribution to the amount out
     *     (the transfer will be done later)
     *   - If the out tokens are already in the receiver, it transfers the contribution separately
     */
    function _maybeAddSolverContribution(
        uint256 amountOut,
        uint256 minAmountOut,
        uint256 maxSolverContribution,
        address tokenOut,
        address receiver
    ) internal returns (uint256 amount) {
        if (amountOut < minAmountOut) {
            uint256 requiredContribution =
                minAmountOut - amountOut;
            if (requiredContribution > maxSolverContribution) {
                revert TychoRouter__NegativeSlippage(amountOut, minAmountOut);
            }
            // Debit the solver's vault balance
            _debitVault(msg.sender, tokenOut, requiredContribution);
            int256 outputDelta = _getDelta(tokenOut);
            if (outputDelta > 0) {
                // out tokens are still in the Router
                _updateDeltaAccounting(tokenOut, int256(requiredContribution));
            } else {
                // send contribution separately
                if (tokenOut == address(0)) {
                    Address.sendValue(payable(receiver), requiredContribution);
                } else {
                    IERC20(tokenOut)
                        .safeTransfer(receiver, requiredContribution);
                }
            }
            amount = minAmountOut;
        } else {
            amount = amountOut;
        }
    }
}
