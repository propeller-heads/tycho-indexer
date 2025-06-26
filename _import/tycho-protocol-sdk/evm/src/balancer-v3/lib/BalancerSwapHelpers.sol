//SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "./BalancerERC4626Helpers.sol";

/**
 * @title Balancer V3 Swap Helpers
 * @dev A wrapped library containing swap functions, helpers and storage for the
 * Balancer V3 Swap Adapter contract
 */
abstract contract BalancerSwapHelpers is
    BalancerERC4626Helpers,
    ISwapAdapter
{
    function getAmountOutMiddleware(
        bytes32 pool,
        address sellToken,
        address buyToken,
        uint256 specifiedAmount
    ) internal returns (uint256 amountOut) {
        address poolAddress = address(bytes20(pool));

        // getTokens() -> [token0, token1] -> if([sellToken,buyToken) in
        // [token0, token1]) -> direct
        IERC20[] memory tokens = vault.getPoolTokens(poolAddress);

        bool sellTokenFound;
        bool buyTokenFound;
        if (sellToken == address(0) || buyToken == address(0)) {
            sellTokenFound = true;
            buyTokenFound = true;
        } else {
            for (uint256 i = 0; i < tokens.length; i++) {
                address token = address(tokens[i]);
                if (token == sellToken) {
                    sellTokenFound = true;
                } else if (token == buyToken) {
                    buyTokenFound = true;
                }
            }
        }

        if (sellTokenFound && buyTokenFound) {
            // Direct Swap
            (IBatchRouter.SwapPathExactAmountIn memory sellPath,,) =
            createERC20Path(
                poolAddress,
                IERC20(sellToken),
                IERC20(buyToken),
                specifiedAmount,
                false,
                sellToken == address(0) || buyToken == address(0)
            );
            return getAmountOut(sellPath);
        } else if (!sellTokenFound && !buyTokenFound) {
            // 3 step (4 tokens)
            (
                CUSTOM_WRAP_KIND kindWrap,
                address sellTokenOutput,
                address buyTokenOutput
            ) = getCustomWrap(sellToken, buyToken, poolAddress);
            return getAmountOutCustomWrap(
                poolAddress,
                sellToken,
                buyToken,
                specifiedAmount,
                kindWrap,
                sellTokenOutput,
                buyTokenOutput
            );
        } else {
            // 2 step (3 tokens)
            (ERC4626_SWAP_TYPE kind, address outputAddress) = getERC4626PathType(
                poolAddress, sellToken, buyToken, sellTokenFound
            );

            if (kind != ERC4626_SWAP_TYPE.NONE) {
                return getAmountOutERC4626AndERC20(
                    poolAddress,
                    sellToken,
                    buyToken,
                    specifiedAmount,
                    kind,
                    outputAddress
                );
            }
        }
    }

    /**
     * @notice Middleware for swaps
     */
    function swapMiddleware(
        bytes32 pool,
        address sellToken,
        address buyToken,
        OrderSide side,
        uint256 specifiedAmount
    ) internal returns (uint256) {
        address poolAddress = address(bytes20(pool));

        // getTokens() -> [token0, token1] -> if([sellToken,buyToken) in
        // [token0, token1]) -> direct
        IERC20[] memory tokens = vault.getPoolTokens(poolAddress);

        bool sellTokenFound;
        bool buyTokenFound;
        if (sellToken == address(0) || buyToken == address(0)) {
            sellTokenFound = true;
            buyTokenFound = true;
        } else {
            for (uint256 i = 0; i < tokens.length; i++) {
                address token = address(tokens[i]);
                if (token == sellToken) {
                    sellTokenFound = true;
                } else if (token == buyToken) {
                    buyTokenFound = true;
                }
            }
        }

        if (sellTokenFound && buyTokenFound) {
            // Direct Swap
            // Fallback (used for ERC20<->ERC20 and ERC4626<->ERC4626 as
            // inherits
            // IERC20 logic)
            if (side == OrderSide.Buy) {
                return buyERC20WithERC20(
                    poolAddress,
                    IERC20(sellToken),
                    IERC20(buyToken),
                    specifiedAmount,
                    true
                );
            } else {
                return sellERC20ForERC20(
                    poolAddress,
                    IERC20(sellToken),
                    IERC20(buyToken),
                    specifiedAmount,
                    true
                );
            }
        } else if (!sellTokenFound && !buyTokenFound) {
            // 3 step (4 tokens)
            (
                CUSTOM_WRAP_KIND kindWrap,
                address sellTokenOutput,
                address buyTokenOutput
            ) = getCustomWrap(sellToken, buyToken, poolAddress);

            if (side == OrderSide.Sell) {
                return sellCustomWrap(
                    poolAddress,
                    sellToken,
                    buyToken,
                    specifiedAmount,
                    kindWrap,
                    sellTokenOutput,
                    buyTokenOutput
                );
            } else {
                return buyCustomWrap(
                    poolAddress,
                    sellToken,
                    buyToken,
                    specifiedAmount,
                    kindWrap,
                    sellTokenOutput,
                    buyTokenOutput
                );
            }
        } else {
            // 2 step (3 tokens)
            (ERC4626_SWAP_TYPE kind, address outputAddress) = getERC4626PathType(
                poolAddress, sellToken, buyToken, sellTokenFound
            );

            return swapERC4626AndERC20(
                poolAddress,
                sellToken,
                buyToken,
                specifiedAmount,
                kind,
                outputAddress,
                side == OrderSide.Buy
            );
        }
    }

    function getLimitsMiddleware(
        bytes32 poolId,
        address sellToken,
        address buyToken
    ) internal view returns (uint256[] memory limits) {
        address poolAddress = address(bytes20(poolId));

        // getTokens() -> [token0, token1] -> if([sellToken,buyToken) in
        // [token0, token1]) -> direct
        IERC20[] memory tokens = vault.getPoolTokens(poolAddress);

        bool sellTokenFound;
        bool buyTokenFound;
        if (sellToken == address(0) || buyToken == address(0)) {
            sellTokenFound = true;
            buyTokenFound = true;
        } else {
            for (uint256 i = 0; i < tokens.length; i++) {
                address token = address(tokens[i]);
                if (token == sellToken) {
                    sellTokenFound = true;
                } else if (token == buyToken) {
                    buyTokenFound = true;
                }
            }
        }

        if (sellTokenFound && buyTokenFound) {
            // Direct Swap
            return getLimitsERC20(poolId, sellToken, buyToken);
        } else if (!sellTokenFound && !buyTokenFound) {
            // 3 step (4 tokens)
            (
                CUSTOM_WRAP_KIND kindWrap,
                address sellTokenOutput,
                address buyTokenOutput
            ) = getCustomWrap(sellToken, buyToken, poolAddress);

            return getLimitsCustomWrap(
                poolId,
                sellToken,
                buyToken,
                kindWrap,
                sellTokenOutput,
                buyTokenOutput
            );
        } else {
            // 2 step (3 tokens)
            (ERC4626_SWAP_TYPE kind, address outputAddress) = getERC4626PathType(
                poolAddress, sellToken, buyToken, sellTokenFound
            );
            return getLimitsERC4626AndERC20(
                poolId, sellToken, buyToken, kind, outputAddress
            );
        }
    }
}
