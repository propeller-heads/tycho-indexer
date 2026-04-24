pragma solidity ^0.8.27;

/// @title PartyPool - LMSR-backed multi-asset pool with LP ERC20 token
/// @notice A multi-asset liquidity pool backed by the LMSRStabilized pricing
/// model. The pool issues an ERC20 LP token representing proportional
/// ownership.
/// It supports:
/// - Proportional minting and burning of LP _tokens,
/// - Single-token mint (swapMint) and single-asset withdrawal (burnSwap),
/// - Exact-input swaps and swaps-to-price-limits,
/// - Flash loans via a callback interface.
interface IPartyPool {
    /// @notice If a security problem is found, the vault owner may call this
    /// function to permanently disable swap and mint functionality, leaving
    /// only burns (withdrawals) working.
    function killed() external view returns (bool);

    /// @notice Returns the number of tokens (n) in the pool.
    function numTokens() external view returns (uint256);

    /// @notice Returns the list of all token addresses in the pool (copy).
    function allTokens() external view returns (address[] memory);

    /// @notice External view to quote exact-in swap amounts (gross input incl.
    /// fee and output), matching swap() computations
    /// @param inputTokenIndex index of input token
    /// @param outputTokenIndex index of output token
    /// @param maxAmountIn maximum gross input allowed (inclusive of fee)
    /// @param limitPrice maximum acceptable marginal price (pass 0 to ignore)
    /// @return amountIn gross input amount to transfer (includes fee),
    /// amountOut output amount user would receive, inFee fee taken from input
    /// amount
    function swapAmounts(
        uint256 inputTokenIndex,
        uint256 outputTokenIndex,
        uint256 maxAmountIn,
        int128 limitPrice
    ) external view returns (uint256 amountIn, uint256 amountOut, uint256 inFee);

    /// @notice Swap input token inputTokenIndex -> token outputTokenIndex.
    /// Payer must approve token inputTokenIndex. @param payer address of the
    /// account that pays for the swap
    /// @param fundingSelector If set to USE_APPROVALS, then the payer must use
    /// regular ERC20 approvals to authorize the pool to move the required input
    /// amount. If this fundingSelector is USE_PREFUNDING, then all of the input
    /// amount is expected to have already been sent to the pool and no
    /// additional transfers are needed. Refunds of excess input amount are NOT
    /// provided and it is illegal to use this funding method with a limit
    /// price. Otherwise, for any other fundingSelector value, a callback style
    /// funding mechanism is used where the given selector is invoked on the
    /// payer, passing the arguments of (address inputToken, uint256
    /// inputAmount). The callback function must send the given amount of input
    /// coin to the pool in order to continue the swap transaction, otherwise
    /// "Insufficient funds" is thrown. @param receiver address that will
    /// receive the output tokens
    /// @param inputTokenIndex index of input asset
    /// @param outputTokenIndex index of output asset
    /// @param maxAmountIn maximum amount of token inputTokenIndex (uint256) to
    /// transfer in (inclusive of fees) @param limitPrice maximum acceptable
    /// marginal price (64.64 fixed point). Pass 0 to ignore.
    /// @param deadline timestamp after which the transaction will revert. Pass
    /// 0 to ignore. @param unwrap If true, then any output of wrapper token
    /// will be unwrapped and native ETH sent to the receiver.
    /// @param cbData callback data if fundingSelector is of the callback type.
    /// @return amountIn actual input used (uint256), amountOut actual output
    /// sent (uint256), inFee fee taken from the input (uint256)
    function swap(
        address payer,
        bytes4 fundingSelector,
        address receiver,
        uint256 inputTokenIndex,
        uint256 outputTokenIndex,
        uint256 maxAmountIn,
        int128 limitPrice,
        uint256 deadline,
        bool unwrap,
        bytes memory cbData
    )
        external
        payable
        returns (uint256 amountIn, uint256 amountOut, uint256 inFee);

    /// @notice Effective combined fee in ppm for the given asset pair (i as
    /// input, j as output).
    function fee(uint256 i, uint256 j) external view returns (uint256);
}
