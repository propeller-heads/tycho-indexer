//SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "./BalancerStorage.sol";

abstract contract BalancerERC20Helpers is BalancerStorage {
    using SafeERC20 for IERC20;

    /**
     * @dev Returns the amount of sellToken tokens to spend for a trade
     * @param path The path to get amountIn for
     * @return amountIn The amount of tokens to spend.
     */
    function getAmountIn(IBatchRouter.SwapPathExactAmountOut memory path)
        internal
        returns (uint256 amountIn)
    {
        bytes memory userData; // empty bytes

        IBatchRouter.SwapPathExactAmountOut[] memory paths =
            new IBatchRouter.SwapPathExactAmountOut[](1);
        paths[0] = path;

        (,, uint256[] memory amountsIn) =
            router.querySwapExactOut(paths, address(0), userData);

        // return
        amountIn = amountsIn[0];
    }

    /**
     * @dev Returns the amount of buyToken tokens received from a trade
     * @param path The path of the trade.
     * @return amountOut The amount of tokens to receive.
     */
    function getAmountOut(IBatchRouter.SwapPathExactAmountIn memory path)
        internal
        returns (uint256 amountOut)
    {
        bytes memory userData; // empty bytes

        IBatchRouter.SwapPathExactAmountIn[] memory paths =
            new IBatchRouter.SwapPathExactAmountIn[](1);
        paths[0] = path;

        (,, uint256[] memory amountsOut) =
            router.querySwapExactIn(paths, address(this), userData);

        amountOut = amountsOut[0];
    }

    /**
     * @dev Perform a sell order for ERC20 tokens
     * @param pool The address of the pool to trade in.
     * @param sellToken The token being sold.
     * @param buyToken The token being bought.
     * @param specifiedAmount The amount to be traded.
     * @param performTransfer Whether to perform a transfer to msg.sender or
     * not(keeping tokens in the contract)
     * @return calculatedAmount The amount of tokens received.
     */
    function sellERC20ForERC20(
        address pool,
        IERC20 sellToken,
        IERC20 buyToken,
        uint256 specifiedAmount,
        bool performTransfer
    ) internal returns (uint256 calculatedAmount) {
        // prepare constants
        bytes memory userData;
        bool isETHSell = address(sellToken) == address(0);
        bool isETHBuy = address(buyToken) == address(0);

        // prepare path
        (IBatchRouter.SwapPathExactAmountIn memory sellPath,,) = createERC20Path(
            pool,
            sellToken,
            buyToken,
            specifiedAmount,
            false,
            isETHSell || isETHBuy
        );
        IBatchRouter.SwapPathExactAmountIn[] memory paths =
            new IBatchRouter.SwapPathExactAmountIn[](1);
        paths[0] = sellPath;

        // prepare swap
        uint256[] memory amountsOut;
        if (isETHSell) {
            paths[0].tokenIn = IERC20(WETH_ADDRESS);
        } else {
            if (isETHBuy) {
                // adjust parameters for ETH buy
                paths[0].steps[0].tokenOut = IERC20(WETH_ADDRESS);
            }
            // Approve and Transfer ERC20 token
            sellToken.safeTransferFrom(
                msg.sender, address(this), specifiedAmount
            );

            sellToken.safeIncreaseAllowance(permit2, specifiedAmount);
            IPermit2(permit2).approve(
                address(sellToken),
                address(router),
                type(uint160).max,
                type(uint48).max
            );
        }

        // Swap (incl. WETH)
        if (isETHSell) {
            (,, amountsOut) = router.swapExactIn{value: specifiedAmount}(
                paths, type(uint256).max, isETHSell || isETHBuy, userData
            );
        } else {
            (,, amountsOut) = router.swapExactIn(
                paths, type(uint256).max, isETHSell || isETHBuy, userData
            );
        }

        // transfer if required
        if (performTransfer) {
            if (isETHBuy) {
                (bool sent,) =
                    payable(msg.sender).call{value: amountsOut[0]}("");
                require(sent, "Failed to transfer ETH");
            } else {
                buyToken.safeTransfer(msg.sender, amountsOut[0]);
            }
        }

        // return amount
        calculatedAmount = amountsOut[0];
    }

    /**
     * @dev Perform a buy order for ERC20 tokens
     * @param pool The address of the pool to trade in.
     * @param sellToken The token being sold.
     * @param buyToken The token being bought.
     * @param specifiedAmount The amount to be traded.
     * @param performTransfer Whether to perform a transfer to msg.sender or
     * not(keeping tokens in the contract)
     * @return calculatedAmount The amount of tokens received.
     */
    function buyERC20WithERC20(
        address pool,
        IERC20 sellToken,
        IERC20 buyToken,
        uint256 specifiedAmount,
        bool performTransfer
    ) internal returns (uint256 calculatedAmount) {
        // prepare constants
        bytes memory userData;
        bool isETHSell = address(sellToken) == address(0);
        bool isETHBuy = address(buyToken) == address(0);
        uint256 msgSenderBalance =
            isETHSell ? address(this).balance : sellToken.balanceOf(msg.sender);

        // prepare path
        (, IBatchRouter.SwapPathExactAmountOut memory buyPath,) =
        createERC20Path(
            pool,
            sellToken,
            buyToken,
            specifiedAmount,
            true,
            isETHSell || isETHBuy
        );
        IBatchRouter.SwapPathExactAmountOut[] memory paths =
            new IBatchRouter.SwapPathExactAmountOut[](1);
        paths[0] = buyPath;

        // prepare swap
        uint256[] memory amountsIn;
        if (isETHSell) {
            // Set token in as WETH
            paths[0].tokenIn = IERC20(WETH_ADDRESS);
        } else {
            if (isETHBuy) {
                // adjust parameters for ETH buy
                paths[0].steps[0].tokenOut = IERC20(WETH_ADDRESS);
            }

            // Approve and Transfer ERC20 token
            sellToken.safeTransferFrom(
                msg.sender, address(this), msgSenderBalance
            );
            sellToken.safeIncreaseAllowance(address(router), type(uint256).max);
            sellToken.safeIncreaseAllowance(permit2, type(uint256).max);
            IPermit2(permit2).approve(
                address(sellToken),
                address(router),
                type(uint160).max,
                type(uint48).max
            );
        }

        // perform swap
        if (isETHSell) {
            (,, amountsIn) = router.swapExactOut{value: msgSenderBalance}(
                paths, type(uint256).max, isETHSell || isETHBuy, userData
            );
        } else {
            (,, amountsIn) = router.swapExactOut(
                paths, type(uint256).max, isETHSell || isETHBuy, userData
            );
        }

        // transfer if required
        if (performTransfer) {
            if (isETHBuy) {
                (bool sent,) =
                    payable(msg.sender).call{value: specifiedAmount}("");
                require(sent, "Failed to transfer ETH");
            } else {
                buyToken.safeTransfer(msg.sender, specifiedAmount);
            }
        }

        // return amount
        calculatedAmount = amountsIn[0];

        // re-transfer back funds to msg.sender
        if (isETHSell) {
            (bool sent2,) = payable(msg.sender).call{
                value: msgSenderBalance - calculatedAmount
            }("");
            require(sent2, "Failed to transfer ETH(2)");
        } else {
            sellToken.safeTransfer(
                msg.sender, msgSenderBalance - calculatedAmount
            );
        }
    }

    /**
     * @notice Create a ERC20 swap path in BalancerV3 router
     * @param sellToken (ERC20) token to Sell
     * @param buyToken (ERC20) token to Buy
     * @param specifiedAmount Amount to buy if isBuy, amount to sell else
     * @param isBuy True if buy, false if sell
     */
    function createERC20Path(
        address pool,
        IERC20 sellToken,
        IERC20 buyToken,
        uint256 specifiedAmount,
        bool isBuy,
        bool isETH
    )
        internal
        view
        returns (
            IBatchRouter.SwapPathExactAmountIn memory sellPath,
            IBatchRouter.SwapPathExactAmountOut memory buyPath,
            IBatchRouter.SwapPathStep memory step
        )
    {
        uint256 maxAmountIn_ = address(this).balance;
        if (!isETH) {
            maxAmountIn_ = IERC20(sellToken).balanceOf(msg.sender);
        }

        // prepare steps
        step = IBatchRouter.SwapPathStep({
            pool: pool,
            tokenOut: buyToken,
            isBuffer: false
        });
        IBatchRouter.SwapPathStep[] memory steps =
            new IBatchRouter.SwapPathStep[](1);
        steps[0] = step;

        if (isBuy) {
            buyPath = IBatchRouter.SwapPathExactAmountOut({
                tokenIn: sellToken,
                steps: steps,
                maxAmountIn: maxAmountIn_,
                exactAmountOut: specifiedAmount
            });
        } else {
            sellPath = IBatchRouter.SwapPathExactAmountIn({
                tokenIn: sellToken,
                steps: steps,
                exactAmountIn: specifiedAmount,
                minAmountOut: 1
            });
        }
    }

    function getLimitsERC20(bytes32 poolId, address sellToken, address buyToken)
        internal
        view
        returns (uint256[] memory limits)
    {
        limits = new uint256[](2);
        address pool = address(bytes20(poolId));

        (IERC20[] memory tokens,, uint256[] memory balancesRaw,) =
            vault.getPoolTokenInfo(pool);
        (IERC20 sellTokenERC, IERC20 buyTokenERC) =
            (IERC20(sellToken), IERC20(buyToken));
        // ERC4626-ERC4626, ERC20-ERC20
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == sellTokenERC) {
                limits[0] = (balancesRaw[i] * RESERVE_LIMIT_FACTOR) / 10;
            }
            if (tokens[i] == buyTokenERC) {
                limits[1] = (balancesRaw[i] * RESERVE_LIMIT_FACTOR) / 10;
            }
        }
    }
}
