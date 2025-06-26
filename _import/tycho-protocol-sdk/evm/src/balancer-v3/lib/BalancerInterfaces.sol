// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import {ISwapAdapter} from "../../interfaces/ISwapAdapter.sol";
import {CustomBytesAppend} from "../../libraries/CustomBytesAppend.sol";
import {
    IERC20,
    SafeERC20
} from
    "../../../lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC4626} from
    "../../../lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";

interface IVault {
    type PoolConfigBits is bytes32;

    enum SwapKind {
        EXACT_IN,
        EXACT_OUT
    }

    enum TokenType {
        STANDARD,
        WITH_RATE
    }

    enum WrappingDirection {
        WRAP,
        UNWRAP
    }

    struct VaultSwapParams {
        SwapKind kind;
        address pool;
        IERC20 tokenIn;
        IERC20 tokenOut;
        uint256 amountGivenRaw;
        uint256 limitRaw;
        bytes userData;
    }

    struct BufferWrapOrUnwrapParams {
        SwapKind kind;
        WrappingDirection direction;
        IERC4626 wrappedToken;
        uint256 amountGivenRaw;
        uint256 limitRaw;
    }

    struct PoolData {
        PoolConfigBits poolConfigBits;
        IERC20[] tokens;
        TokenInfo[] tokenInfo;
        uint256[] balancesRaw;
        uint256[] balancesLiveScaled18;
        uint256[] tokenRates;
        uint256[] decimalScalingFactors;
    }

    struct TokenInfo {
        TokenType tokenType;
        IRateProvider rateProvider;
        bool paysYieldFees;
    }

    function swap(VaultSwapParams memory vaultSwapParams)
        external
        returns (
            uint256 amountCalculatedRaw,
            uint256 amountInRaw,
            uint256 amountOutRaw
        );

    function getPoolTokenCountAndIndexOfToken(address pool, IERC20 token)
        external
        view
        returns (uint256 tokenCount, uint256 index);

    function erc4626BufferWrapOrUnwrap(BufferWrapOrUnwrapParams memory params)
        external
        returns (
            uint256 amountCalculatedRaw,
            uint256 amountInRaw,
            uint256 amountOutRaw
        );

    function getPoolData(address pool)
        external
        view
        returns (PoolData memory);

    function getPoolTokenInfo(address pool)
        external
        view
        returns (
            IERC20[] memory tokens,
            TokenInfo[] memory tokenInfo,
            uint256[] memory balancesRaw,
            uint256[] memory lastBalancesLiveScaled18
        );

    function getPoolTokens(address pool)
        external
        view
        returns (IERC20[] memory tokens);
}

interface IRateProvider {
    /**
     * @dev Returns an 18 decimal fixed point number that is the exchange rate
     * of the token to some other underlying
     * token. The meaning of this rate depends on the context.
     */
    function getRate() external view returns (uint256);
}

interface IBatchRouter {
    struct SwapPathStep {
        address pool;
        IERC20 tokenOut;
        // If true, the "pool" is an ERC4626 Buffer. Used to wrap/unwrap tokens
        // if pool doesn't have enough liquidity.
        bool isBuffer;
    }

    struct SwapPathExactAmountIn {
        IERC20 tokenIn;
        // For each step:
        // If tokenIn == pool, use removeLiquidity SINGLE_TOKEN_EXACT_IN.
        // If tokenOut == pool, use addLiquidity UNBALANCED.
        SwapPathStep[] steps;
        uint256 exactAmountIn;
        uint256 minAmountOut;
    }

    struct SwapPathExactAmountOut {
        IERC20 tokenIn;
        // for each step:
        // If tokenIn == pool, use removeLiquidity SINGLE_TOKEN_EXACT_OUT.
        // If tokenOut == pool, use addLiquidity SINGLE_TOKEN_EXACT_OUT.
        SwapPathStep[] steps;
        uint256 maxAmountIn;
        uint256 exactAmountOut;
    }

    function querySwapExactIn(
        SwapPathExactAmountIn[] memory paths,
        address sender,
        bytes calldata userData
    )
        external
        returns (
            uint256[] memory pathAmountsOut,
            address[] memory tokensOut,
            uint256[] memory amountsOut
        );

    function querySwapExactOut(
        SwapPathExactAmountOut[] memory paths,
        address sender,
        bytes calldata userData
    )
        external
        returns (
            uint256[] memory pathAmountsIn,
            address[] memory tokensIn,
            uint256[] memory amountsIn
        );

    function swapExactIn(
        SwapPathExactAmountIn[] memory paths,
        uint256 deadline,
        bool wethIsEth,
        bytes calldata userData
    )
        external
        payable
        returns (
            uint256[] memory pathAmountsOut,
            address[] memory tokensOut,
            uint256[] memory amountsOut
        );

    function swapExactOut(
        SwapPathExactAmountOut[] memory paths,
        uint256 deadline,
        bool wethIsEth,
        bytes calldata userData
    )
        external
        payable
        returns (
            uint256[] memory pathAmountsIn,
            address[] memory tokensIn,
            uint256[] memory amountsIn
        );
}

interface IPermit2 {
    function approve(
        address token,
        address spender,
        uint160 amount,
        uint48 expiration
    ) external;
}
