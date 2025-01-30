// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "../lib/IWETH.sol";
import "../lib/bytes/LibPrefixLengthEncodedByteArray.sol";
import "./CallbackVerificationDispatcher.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";
import "@uniswap/v3-updated/CallbackValidationV2.sol";
import "./ExecutionDispatcher.sol";
import "./CallbackVerificationDispatcher.sol";
import {LibSwap} from "../lib/LibSwap.sol";

error TychoRouter__WithdrawalFailed();
error TychoRouter__AddressZero();
error TychoRouter__NegativeSlippage(uint256 amount, uint256 minAmount);
error TychoRouter__MessageValueMismatch(uint256 value, uint256 amount);

contract TychoRouter is
    AccessControl,
    ExecutionDispatcher,
    CallbackVerificationDispatcher,
    Pausable,
    ReentrancyGuard
{
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

    address private immutable _usv3Factory;

    constructor(address _permit2, address weth, address usv3Factory) {
        permit2 = IAllowanceTransfer(_permit2);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _weth = IWETH(weth);

        if (usv3Factory == address(0)) {
            revert TychoRouter__AddressZero();
        }
        _usv3Factory = usv3Factory;
    }

    /**
     * @dev We use the fallback function to allow flexibility on callback.
     * This function will delegate call a verifier contract and should revert if the
     *  caller is not a pool.
     */
    fallback() external {
        _executeGenericCallback(msg.data);
    }

    /**
     * @dev Check if the sender is correct and executes callback actions.
     *  @param msgData encoded data. It must includes data for the verification.
     */
    function _executeGenericCallback(bytes calldata msgData) internal {
        (uint256 amountOwed, address tokenOwed) = _callVerifyCallback(msgData);

        IERC20(tokenOwed).safeTransfer(msg.sender, amountOwed);
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
     * @notice Executes a swap operation based on a predefined swap graph, supporting internal token amount splits.
     *         This function enables multi-step swaps, optional ETH wrapping/unwrapping, and validates the output amount
     *         against a user-specified minimum.
     *
     * @dev
     * - If `wrapEth` is true, the contract wraps the provided native ETH into WETH and uses it as the sell token.
     * - If `unwrapEth` is true, the contract converts the resulting WETH back into native ETH before sending it to the receiver.
     * - For ERC20 tokens, Permit2 is used to approve and transfer tokens from the caller to the router.
     * - Swaps are executed sequentially using the `_splitSwap` function.
     * - A fee is deducted from the output token if `fee > 0`, and the remaining amount is sent to the receiver.
     * - Reverts with `TychoRouter__NegativeSlippage` if the output amount is less than `minAmountOut` and `minAmountOut` is bigger than 0.
     *
     * @param amountIn The input token amount to be swapped.
     * @param tokenIn The address of the input token. Use `address(0)` for native ETH when `wrapEth` is true.
     * @param tokenOut The address of the output token. Use `address(0)` for native ETH when `unwrapEth` is true.
     * @param minAmountOut The minimum acceptable amount of the output token. Reverts if this condition is not met. If it's 0, no check is performed.
     * @param wrapEth If true, treats the input token as native ETH and wraps it into WETH.
     * @param unwrapEth If true, unwraps the resulting WETH into native ETH and sends it to the receiver.
     * @param nTokens The total number of tokens involved in the swap graph (used to initialize arrays for internal calculations).
     * @param receiver The address to receive the output tokens.
     * @param permitSingle A Permit2 structure containing token approval details for the input token. Ignored if `wrapEth` is true.
     * @param signature A valid signature authorizing the Permit2 approval. Ignored if `wrapEth` is true.
     * @param swaps Encoded swap graph data containing details of each swap.
     *
     * @return amountOut The total amount of the output token received by the receiver, after deducting fees if applicable.
     */
    function swap(
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
        if (receiver == address(0)) {
            revert TychoRouter__AddressZero();
        }

        // For native ETH, assume funds already in our router. Else, transfer and handle approval.
        if (wrapEth) {
            _wrapETH(amountIn);
        } else if (tokenIn != address(0)) {
            permit2.permit(msg.sender, permitSingle, signature);
            permit2.transferFrom(
                msg.sender,
                address(this),
                uint160(amountIn),
                permitSingle.details.token
            );
        }

        amountOut = _swap(amountIn, nTokens, swaps);

        if (fee > 0) {
            uint256 feeAmount = (amountOut * fee) / 10000;
            amountOut -= feeAmount;
            IERC20(tokenOut).safeTransfer(feeReceiver, feeAmount);
        }

        if (minAmountOut > 0 && amountOut < minAmountOut) {
            revert TychoRouter__NegativeSlippage(amountOut, minAmountOut);
        }

        if (unwrapEth) {
            _unwrapETH(amountOut);
            // slither-disable-next-line arbitrary-send-eth
            payable(receiver).transfer(amountOut);
        } else {
            IERC20(tokenOut).safeTransfer(receiver, amountOut);
        }
    }

    function _swap(uint256 amountIn, uint256 nTokens, bytes calldata swaps_)
        internal
        returns (uint256)
    {
        uint256 currentAmountIn;
        uint256 currentAmountOut;
        uint8 tokenInIndex = 0;
        uint8 tokenOutIndex = 0;
        uint24 split;
        bytes calldata swapData;

        uint256[] memory remainingAmounts = new uint256[](nTokens);
        uint256[] memory amounts = new uint256[](nTokens);
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
                swapData.executor(),
                swapData.executorSelector(),
                currentAmountIn,
                swapData.protocolData()
            );
            amounts[tokenOutIndex] += currentAmountOut;
            remainingAmounts[tokenOutIndex] += currentAmountOut;
            remainingAmounts[tokenInIndex] -= currentAmountIn;
        }
        return amounts[tokenOutIndex];
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
    function batchSetExecutor(address[] memory targets)
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
     * @dev Entrypoint to add or replace an approved callback verifier contract address
     * @param target address of the callback verifier contract
     */
    function setCallbackVerifier(address target)
        external
        onlyRole(EXECUTOR_SETTER_ROLE)
    {
        _setCallbackVerifier(target);
    }

    /**
     * @dev Entrypoint to remove an approved callback verifier contract address
     * @param target address of the callback verifier contract
     */
    function removeCallbackVerifier(address target)
        external
        onlyRole(EXECUTOR_SETTER_ROLE)
    {
        _removeCallbackVerifier(target);
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
            // slither-disable-next-line arbitrary-send-eth
            bool success = payable(receiver).send(amount);
            if (!success) revert TychoRouter__WithdrawalFailed();
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
        uint256 unwrapAmount =
            amount == 0 ? _weth.balanceOf(address(this)) : amount;
        _weth.withdraw(unwrapAmount);
    }

    /**
     * @dev Allows this contract to receive native token
     */
    receive() external payable {}

    /**
     * @dev Called by UniswapV3 pool when swapping on it.
     * See in IUniswapV3SwapCallback for documentation.
     */
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata msgData
    ) external {
        (uint256 amountOwed, address tokenOwed) =
            _verifyUSV3Callback(amount0Delta, amount1Delta, msgData);
        IERC20(tokenOwed).safeTransfer(msg.sender, amountOwed);
    }

    function _verifyUSV3Callback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) internal view returns (uint256 amountOwed, address tokenOwed) {
        address tokenIn = address(bytes20(data[0:20]));
        address tokenOut = address(bytes20(data[20:40]));
        uint24 poolFee = uint24(bytes3(data[40:43]));

        // slither-disable-next-line unused-return
        CallbackValidationV2.verifyCallback(
            _usv3Factory, tokenIn, tokenOut, poolFee
        );

        amountOwed =
            amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);

        return (amountOwed, tokenOwed);
    }
}
