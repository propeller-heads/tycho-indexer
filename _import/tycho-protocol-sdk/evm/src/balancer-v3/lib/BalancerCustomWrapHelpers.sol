//SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "./BalancerERC20Helpers.sol";

abstract contract BalancerCustomWrapHelpers is BalancerERC20Helpers {
    using SafeERC20 for IERC20;

    function isERC4626(address token) internal view returns (bool) {
        if (token == WETH_ADDRESS) {
            return false;
        }
        try IERC4626(token).asset() {
            try IERC4626(token).maxRedeem(msg.sender) {
                return true;
            } catch {
                // Proceed to the next try-catch
            }
        } catch {
            // return false;
        }

        return false;
    }

    function getCustomWrap(address sellToken, address buyToken, address pool)
        internal
        view
        returns (
            CUSTOM_WRAP_KIND kind,
            address sellTokenOutput,
            address buyTokenOutput
        )
    {
        IERC20[] memory tokens = vault.getPoolTokens(pool);

        if (isERC4626(sellToken) && isERC4626(buyToken)) {
            // 4626-(20-20)-4626
            address sellTokenAsset = IERC4626(sellToken).asset();
            address buyTokenAsset = IERC4626(buyToken).asset();

            for (uint256 i = 0; i < tokens.length; i++) {
                address token = address(tokens[i]);
                if (
                    sellTokenOutput != address(0)
                        && buyTokenOutput != address(0)
                ) {
                    // prevent other findings, use the firsts as default
                    break;
                }

                if (token == sellTokenAsset) {
                    sellTokenOutput = token; // asset
                }
                if (token == buyTokenAsset) {
                    buyTokenOutput = token; // asset
                }
            }

            require(
                sellTokenOutput != address(0) && buyTokenOutput != address(0),
                "CUSTOM_WRAP(4626-4626): Invalid Pool"
            );
            kind = CUSTOM_WRAP_KIND.ERC4626_TO_ERC4626;
        } else if (!isERC4626(sellToken) && !isERC4626(buyToken)) {
            for (uint256 i = 0; i < tokens.length; i++) {
                address token = address(tokens[i]);
                if (isERC4626(token)) {
                    if (
                        sellTokenOutput != address(0)
                            && buyTokenOutput != address(0)
                    ) {
                        // prevent other findings, use the firsts as default
                        break;
                    }

                    if (IERC4626(token).asset() == sellToken) {
                        sellTokenOutput = token; // share
                    }
                    if (IERC4626(token).asset() == buyToken) {
                        buyTokenOutput = token; // share
                    }
                }
            }

            require(
                sellTokenOutput != address(0) && buyTokenOutput != address(0),
                "CUSTOM_WRAP(4626-4626): Invalid Pool"
            );
            kind = CUSTOM_WRAP_KIND.ERC20_TO_ERC20;
        } else {
            revert("CUSTOM_WRAP: Invalid tokens");
        }
    }

    function prepareSellCustomWrap(
        address pool,
        address _sellToken,
        address buyToken,
        uint256 specifiedAmount,
        CUSTOM_WRAP_KIND kind,
        address sellTokenOutput,
        address buyTokenOutput
    )
        internal
        view
        returns (IBatchRouter.SwapPathExactAmountIn[] memory paths)
    {
        IBatchRouter.SwapPathStep[] memory steps =
            new IBatchRouter.SwapPathStep[](3);

        if (kind == CUSTOM_WRAP_KIND.ERC20_TO_ERC20) {
            // Step 1: sellToken.asset() -> sellToken.shares()
            (,, IBatchRouter.SwapPathStep memory step0) = createWrapOrUnwrapPath(
                sellTokenOutput,
                specifiedAmount,
                IVault.WrappingDirection.WRAP,
                false
            );
            steps[0] = step0;

            // Step 2: sellToken.shares() -> buyToken.shares()
            (,, IBatchRouter.SwapPathStep memory step1) = createERC20Path(
                pool,
                IERC20(sellTokenOutput),
                IERC20(buyTokenOutput),
                specifiedAmount,
                false,
                false
            );
            steps[1] = step1;

            // Step 3: buyToken.shares() -> buyToken.asset()
            (,, IBatchRouter.SwapPathStep memory step2) = createWrapOrUnwrapPath(
                buyTokenOutput,
                specifiedAmount,
                IVault.WrappingDirection.UNWRAP,
                false
            );
            steps[2] = step2;

            paths = new IBatchRouter.SwapPathExactAmountIn[](1);
            paths[0] = IBatchRouter.SwapPathExactAmountIn({
                tokenIn: IERC20(_sellToken),
                steps: steps,
                exactAmountIn: specifiedAmount,
                minAmountOut: 1
            });
        } else {
            // ERC4626_TO_ERC4626
            // Step 1: sellToken.shares() -> sellToken.asset()
            (,, IBatchRouter.SwapPathStep memory step0) = createWrapOrUnwrapPath(
                _sellToken,
                specifiedAmount,
                IVault.WrappingDirection.UNWRAP,
                false
            );
            steps[0] = step0;

            // Step 2: sellToken.asset() -> buyToken.asset()
            (,, IBatchRouter.SwapPathStep memory step1) = createERC20Path(
                pool,
                IERC20(sellTokenOutput),
                IERC20(buyTokenOutput),
                specifiedAmount,
                false,
                false
            );
            steps[1] = step1;

            // Step 3: buyToken.asset() -> buyToken.shares()
            (,, IBatchRouter.SwapPathStep memory step2) = createWrapOrUnwrapPath(
                buyToken, specifiedAmount, IVault.WrappingDirection.WRAP, false
            );
            steps[2] = step2;

            paths = new IBatchRouter.SwapPathExactAmountIn[](1);
            paths[0] = IBatchRouter.SwapPathExactAmountIn({
                tokenIn: IERC20(_sellToken),
                steps: steps,
                exactAmountIn: specifiedAmount,
                minAmountOut: 1
            });
        }
    }

    /**
     * @notice Get amount out for custom wrap
     */
    function getAmountOutCustomWrap(
        address pool,
        address _sellToken,
        address buyToken,
        uint256 specifiedAmount,
        CUSTOM_WRAP_KIND kind,
        address sellTokenOutput,
        address buyTokenOutput
    ) internal returns (uint256 calculatedAmount) {
        IBatchRouter.SwapPathExactAmountIn[] memory paths =
        prepareSellCustomWrap(
            pool,
            _sellToken,
            buyToken,
            specifiedAmount,
            kind,
            sellTokenOutput,
            buyTokenOutput
        );

        (,, uint256[] memory amountsOut) =
            router.querySwapExactIn(paths, address(0), bytes(""));

        calculatedAmount = amountsOut[0];
    }

    /**
     * @notice Perform a custom sell with wrap/unwrap
     * @dev
     * - Does not support ETH(gas), use wrapped ETH instead
     * @param pool the ERC4626 pool containing sellToken.share() and
     * buyToken.share(), or the ERC20 pool containing sellToken.asset() and
     * buyToken.asset(), depending on the kind
     * @param _sellToken ERC20 token being sold if kind == ERC20_TO_ERC20,
     * ERC4626 else
     * @param _buyToken ERC20 token being bought if kind == ERC20_TO_ERC20,
     * ERC4626 else
     * @param kind The Custom wrap kind
     * @param sellTokenOutput sellToken.share() if sellToken is kind ==
     * ERC20_TO_ERC20, sellToken.asset() else
     * @param buyTokenOutput buyToken.share() if sellToken is kind ==
     * ERC20_TO_ERC20, buyToken.asset() else
     * @param specifiedAmount The amount of _buyToken bought
     */
    function sellCustomWrap(
        address pool,
        address _sellToken,
        address _buyToken,
        uint256 specifiedAmount,
        CUSTOM_WRAP_KIND kind,
        address sellTokenOutput,
        address buyTokenOutput
    ) internal returns (uint256 calculatedAmount) {
        IERC20 sellToken = IERC20(_sellToken);

        // approve and transfer
        IERC20(sellToken).safeTransferFrom(
            msg.sender, address(this), specifiedAmount
        );
        sellToken.safeIncreaseAllowance(permit2, specifiedAmount);
        IPermit2(permit2).approve(
            address(sellToken),
            address(router),
            type(uint160).max,
            type(uint48).max
        );

        IBatchRouter.SwapPathExactAmountIn[] memory paths =
        prepareSellCustomWrap(
            pool,
            _sellToken,
            _buyToken,
            specifiedAmount,
            kind,
            sellTokenOutput,
            buyTokenOutput
        );

        (,, uint256[] memory amountsOut) =
            router.swapExactIn(paths, type(uint256).max, false, bytes(""));

        calculatedAmount = amountsOut[0];

        IERC20(_buyToken).safeTransfer(msg.sender, calculatedAmount);
    }

    /**
     * @notice Perform a custom sell with wrap/unwrap
     * @param specifiedAmount The amount of buyToken to buy
     * @return calculatedAmount The amount of sellToken spent
     */
    function buyCustomWrap(
        address pool,
        address _sellToken,
        address _buyToken,
        uint256 specifiedAmount,
        CUSTOM_WRAP_KIND kind,
        address sellTokenOutput,
        address buyTokenOutput
    ) internal returns (uint256 calculatedAmount) {
        IBatchRouter.SwapPathStep[] memory steps =
            new IBatchRouter.SwapPathStep[](3);
        IERC20 sellToken = IERC20(_sellToken);

        // get balance of sender
        uint256 initialSenderBalance = IERC20(sellToken).balanceOf(msg.sender);

        // approve and transfer
        IERC20(sellToken).safeTransferFrom(
            msg.sender, address(this), initialSenderBalance
        );
        sellToken.safeIncreaseAllowance(permit2, type(uint256).max);
        IPermit2(permit2).approve(
            address(sellToken),
            address(router),
            type(uint160).max,
            type(uint48).max
        );

        if (kind == CUSTOM_WRAP_KIND.ERC20_TO_ERC20) {
            // Step 1: sellToken.asset() -> sellToken.shares()
            (,, IBatchRouter.SwapPathStep memory step0) = createWrapOrUnwrapPath(
                sellTokenOutput,
                specifiedAmount,
                IVault.WrappingDirection.WRAP,
                false
            );
            steps[0] = step0;

            // Step 2: sellToken.shares() -> buyToken.shares()
            (,, IBatchRouter.SwapPathStep memory step1) = createERC20Path(
                pool,
                IERC4626(sellTokenOutput),
                IERC4626(buyTokenOutput),
                specifiedAmount,
                true,
                false
            );
            steps[1] = step1;

            // Step 3: buyToken.shares() -> buyToken.asset()
            (,, IBatchRouter.SwapPathStep memory step2) = createWrapOrUnwrapPath(
                buyTokenOutput,
                specifiedAmount,
                IVault.WrappingDirection.UNWRAP,
                true
            );
            steps[2] = step2;

            IBatchRouter.SwapPathExactAmountOut[] memory paths =
                new IBatchRouter.SwapPathExactAmountOut[](1);
            paths[0] = IBatchRouter.SwapPathExactAmountOut({
                tokenIn: IERC20(_sellToken),
                steps: steps,
                maxAmountIn: initialSenderBalance,
                exactAmountOut: specifiedAmount
            });

            (,, uint256[] memory amountsIn) =
                router.swapExactOut(paths, type(uint256).max, false, bytes(""));

            calculatedAmount = amountsIn[0];

            IERC20(_buyToken).safeTransfer(msg.sender, specifiedAmount);
        } else {
            // ERC4626_TO_ERC4626
            // Step 1: sellToken.shares() -> sellToken.asset()
            (,, IBatchRouter.SwapPathStep memory step0) = createWrapOrUnwrapPath(
                _sellToken,
                specifiedAmount,
                IVault.WrappingDirection.UNWRAP,
                true
            );
            steps[0] = step0;

            // Step 2: sellToken.asset() -> buyToken.asset()
            (,, IBatchRouter.SwapPathStep memory step1) = createERC20Path(
                pool,
                IERC20(sellTokenOutput),
                IERC20(buyTokenOutput),
                specifiedAmount,
                true,
                false
            );
            steps[1] = step1;

            // Step 3: buyToken.asset() -> buyToken.shares()
            (,, IBatchRouter.SwapPathStep memory step2) = createWrapOrUnwrapPath(
                _buyToken, specifiedAmount, IVault.WrappingDirection.WRAP, false
            );
            steps[2] = step2;

            IBatchRouter.SwapPathExactAmountOut[] memory paths =
                new IBatchRouter.SwapPathExactAmountOut[](1);
            paths[0] = IBatchRouter.SwapPathExactAmountOut({
                tokenIn: IERC20(_sellToken),
                steps: steps,
                maxAmountIn: initialSenderBalance,
                exactAmountOut: specifiedAmount
            });

            (,, uint256[] memory amountsIn) =
                router.swapExactOut(paths, type(uint256).max, false, bytes(""));

            calculatedAmount = amountsIn[0];

            IERC20(_buyToken).safeTransfer(msg.sender, specifiedAmount);
        }

        // transfer back sellToken to sender
        IERC20(sellToken).safeTransferFrom(
            address(this), msg.sender, initialSenderBalance - calculatedAmount
        );
    }

    /**
     * @notice Create a wrap or unwrap path in BalancerV3 router using buffer
     * pools
     * @param token (ERC4626) token to Wrap or Unwrap
     * @param amount Amount to buy if isBuy, amount to sell else
     * @param direction Wrap or Unwrap
     * @param isBuy True if buy, false if sell
     */
    function createWrapOrUnwrapPath(
        address token,
        uint256 amount,
        IVault.WrappingDirection direction,
        bool isBuy
    )
        internal
        view
        returns (
            IBatchRouter.SwapPathExactAmountIn memory sellPath,
            IBatchRouter.SwapPathExactAmountOut memory buyPath,
            IBatchRouter.SwapPathStep memory step
        )
    {
        step = IBatchRouter.SwapPathStep({
            pool: token,
            tokenOut: direction == IVault.WrappingDirection.UNWRAP
                ? IERC20(IERC4626(token).asset())
                : IERC20(token),
            isBuffer: true
        });
        IBatchRouter.SwapPathStep[] memory steps =
            new IBatchRouter.SwapPathStep[](1);
        steps[0] = step;

        if (isBuy) {
            buyPath = IBatchRouter.SwapPathExactAmountOut({
                tokenIn: direction == IVault.WrappingDirection.UNWRAP
                    ? IERC20(token)
                    : IERC20(IERC4626(token).asset()),
                steps: steps,
                maxAmountIn: direction == IVault.WrappingDirection.UNWRAP
                    ? IERC20(token).balanceOf(address(this))
                    : IERC20(IERC4626(token).asset()).balanceOf(address(this)),
                exactAmountOut: amount
            });
        } else {
            sellPath = IBatchRouter.SwapPathExactAmountIn({
                tokenIn: direction == IVault.WrappingDirection.UNWRAP
                    ? IERC20(token)
                    : IERC20(IERC4626(token).asset()),
                steps: steps,
                exactAmountIn: amount,
                minAmountOut: 1
            });
        }
    }

    function getLimitsCustomWrap(
        bytes32 poolId,
        address sellToken,
        address buyToken,
        CUSTOM_WRAP_KIND kind,
        address sellTokenOutput,
        address buyTokenOutput
    ) internal view returns (uint256[] memory limits) {
        limits = new uint256[](2);
        address pool = address(bytes20(poolId));

        (IERC20[] memory tokens,, uint256[] memory balancesRaw,) =
            vault.getPoolTokenInfo(pool);

        if (kind == CUSTOM_WRAP_KIND.ERC20_TO_ERC20) {
            // pool contains sellToken.share() and buyToken.share()
            for (uint256 i = 0; i < tokens.length; i++) {
                address token = address(tokens[i]);

                if (token == sellTokenOutput) {
                    limits[0] = IERC4626(sellTokenOutput).previewRedeem(
                        (balancesRaw[i] * RESERVE_LIMIT_FACTOR) / 10
                    );
                } else if (token == buyTokenOutput) {
                    limits[1] = IERC4626(buyTokenOutput).previewRedeem(
                        (balancesRaw[i] * RESERVE_LIMIT_FACTOR) / 10
                    );
                }
            }

            return limits;
        }

        // pool contains sellToken.asset() and buyToken.asset()
        IERC20 underlyingSellToken = IERC20(IERC4626(sellToken).asset());
        IERC20 underlyingBuyToken = IERC20(IERC4626(buyToken).asset());
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == underlyingSellToken) {
                limits[0] = IERC4626(sellToken).previewDeposit(
                    (balancesRaw[i] * RESERVE_LIMIT_FACTOR) / 10
                );
            }
            if (tokens[i] == underlyingBuyToken) {
                limits[1] = IERC4626(buyToken).previewDeposit(
                    (balancesRaw[i] * RESERVE_LIMIT_FACTOR) / 10
                );
            }
        }
        return limits;
    }
}
