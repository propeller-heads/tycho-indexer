//SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "./BalancerCustomWrapHelpers.sol";

abstract contract BalancerERC4626Helpers is BalancerCustomWrapHelpers {
    using SafeERC20 for IERC20;

    function getERC4626PathType(
        address pool,
        address sellToken,
        address buyToken,
        bool sellTokenFound
    ) internal view returns (ERC4626_SWAP_TYPE kind, address outputAddress) {
        IERC20[] memory tokens = vault.getPoolTokens(pool);

        if (sellTokenFound) {
            // SWAP_WRAP and SWAP_UNWRAP
            bool isERC4626BuyToken = isERC4626(buyToken);

            if (isERC4626BuyToken) {
                kind = ERC4626_SWAP_TYPE.SWAP_WRAP;
            } else {
                for (uint256 i = 0; i < tokens.length; i++) {
                    address token = address(tokens[i]);
                    if (isERC4626(token) && IERC4626(token).asset() == buyToken)
                    {
                        outputAddress = token; // buyToken share
                        break;
                    }
                }
                require(outputAddress != address(0), "Token not found in pool");
                kind = ERC4626_SWAP_TYPE.SWAP_UNWRAP;
            }
        } else {
            bool isERC4626SellToken = isERC4626(sellToken);

            if (isERC4626SellToken) {
                kind = ERC4626_SWAP_TYPE.UNWRAP_SWAP;
            } else {
                for (uint256 i = 0; i < tokens.length; i++) {
                    address token = address(tokens[i]);
                    if (
                        isERC4626(token) && IERC4626(token).asset() == sellToken
                    ) {
                        outputAddress = token; // sellToken share
                        break;
                    }
                }
                require(outputAddress != address(0), "Token not found in pool");
                kind = ERC4626_SWAP_TYPE.WRAP_SWAP;
            }
        }
    }

    function prepareERC4626SellOrBuy(
        address pool,
        address _sellToken,
        address _buyToken,
        uint256 specifiedAmount,
        ERC4626_SWAP_TYPE kind,
        address outputAddress,
        bool isBuy
    )
        internal
        view
        returns (
            IBatchRouter.SwapPathExactAmountIn[] memory sellPath,
            IBatchRouter.SwapPathExactAmountOut[] memory buyPath
        )
    {
        IBatchRouter.SwapPathStep[] memory steps;

        address sellToken = _sellToken == address(0) ? WETH_ADDRESS : _sellToken;
        address buyToken = _buyToken == address(0) ? WETH_ADDRESS : _buyToken;

        if (kind == ERC4626_SWAP_TYPE.SWAP_WRAP) {
            // !isERC4626(sellToken) && isERC4626(buyToken) and
            // isERC4626(buyToken) && isERC4626(sellToken)
            steps = new IBatchRouter.SwapPathStep[](2);

            // swap: sellToken -> buyToken.asset()
            (,, steps[0]) = createERC20Path(
                pool,
                IERC20(sellToken),
                IERC20(IERC4626(buyToken).asset()),
                specifiedAmount,
                false,
                _sellToken == address(0)
            );

            // wrap: buyToken.asset() -> buyToken.shares()
            (,, steps[1]) = createWrapOrUnwrapPath(
                buyToken, specifiedAmount, IVault.WrappingDirection.WRAP, false
            );
        } else if (kind == ERC4626_SWAP_TYPE.SWAP_UNWRAP) {
            // isERC4626(sellToken) && !isERC4626(buyToken) and
            // !isERC4626(buyToken) && !isERC4626(sellToken)
            steps = new IBatchRouter.SwapPathStep[](2);

            // swap: sellToken -> buyToken.shares()
            (,, steps[0]) = createERC20Path(
                pool,
                IERC20(sellToken),
                IERC20(outputAddress),
                specifiedAmount,
                false,
                _sellToken == address(0)
            );

            // unwrap: buyToken.shares() -> buyToken.asset()
            (,, steps[1]) = createWrapOrUnwrapPath(
                outputAddress,
                specifiedAmount,
                IVault.WrappingDirection.UNWRAP,
                false
            );
        } else if (kind == ERC4626_SWAP_TYPE.WRAP_SWAP) {
            // input is ERC20, output is ERC4626
            steps = new IBatchRouter.SwapPathStep[](2);

            // wrap: sellToken.shares() -> sellToken.asset()
            (,, steps[0]) = createWrapOrUnwrapPath(
                outputAddress,
                specifiedAmount,
                IVault.WrappingDirection.WRAP,
                false
            );
            // swap: sellToken.asset() -> buyToken
            (,, steps[1]) = createERC20Path(
                pool,
                IERC20(outputAddress),
                IERC20(buyToken),
                specifiedAmount,
                false,
                _buyToken == address(0)
            );
        } else if (kind == ERC4626_SWAP_TYPE.UNWRAP_SWAP) {
            steps = new IBatchRouter.SwapPathStep[](2);

            // unwrap: sellToken.shares() -> sellToken.asset()
            (,, steps[0]) = createWrapOrUnwrapPath(
                sellToken,
                specifiedAmount,
                IVault.WrappingDirection.UNWRAP,
                false
            );

            // swap: sellToken.asset() -> buyToken
            (,, steps[1]) = createERC20Path(
                pool,
                IERC20(sellToken),
                IERC20(buyToken),
                specifiedAmount,
                false,
                _buyToken == address(0)
            );
        }

        if (isBuy) {
            buyPath = new IBatchRouter.SwapPathExactAmountOut[](1);
            buyPath[0] = IBatchRouter.SwapPathExactAmountOut({
                tokenIn: IERC20(sellToken),
                steps: steps,
                maxAmountIn: IERC20(sellToken).balanceOf(address(this)),
                exactAmountOut: specifiedAmount
            });
        } else {
            sellPath = new IBatchRouter.SwapPathExactAmountIn[](1);
            sellPath[0] = IBatchRouter.SwapPathExactAmountIn({
                tokenIn: IERC20(sellToken),
                steps: steps,
                exactAmountIn: specifiedAmount,
                minAmountOut: 1
            });
        }
    }

    function swapERC4626AndERC20(
        address pool,
        address _sellToken,
        address _buyToken,
        uint256 specifiedAmount,
        ERC4626_SWAP_TYPE kind,
        address outputAddress,
        bool isBuy
    ) internal returns (uint256 calculatedAmount) {
        // approve
        uint256 approvalAmount = specifiedAmount;

        address sellToken = _sellToken == address(0) ? WETH_ADDRESS : _sellToken;
        address buyToken = _buyToken == address(0) ? WETH_ADDRESS : _buyToken;

        if (_sellToken != address(0)) {
            if (isBuy) {
                approvalAmount = IERC20(sellToken).balanceOf(msg.sender);
            }
            IERC20(sellToken).safeIncreaseAllowance(permit2, approvalAmount);
            IPermit2(permit2).approve(
                address(sellToken),
                address(router),
                type(uint160).max,
                type(uint48).max
            );
        } else {
            if (isBuy) {
                approvalAmount = address(this).balance;
            }
        }

        if (!isBuy) {
            if (_sellToken != address(0)) {
                IERC20(sellToken).safeTransferFrom(
                    msg.sender, address(this), approvalAmount
                );
            }

            (IBatchRouter.SwapPathExactAmountIn[] memory sellPath,) =
            prepareERC4626SellOrBuy(
                pool,
                sellToken,
                buyToken,
                specifiedAmount,
                kind,
                outputAddress,
                isBuy
            );

            uint256[] memory amountsOut;
            if (_sellToken == address(0)) {
                (,, amountsOut) = router.swapExactIn{value: specifiedAmount}(
                    sellPath, type(uint256).max, true, bytes("")
                );
            } else {
                (,, amountsOut) = router.swapExactIn(
                    sellPath, type(uint256).max, false, bytes("")
                );
            }

            calculatedAmount = amountsOut[0];

            if (_buyToken != address(0)) {
                IERC20(buyToken).safeTransfer(msg.sender, calculatedAmount);
            } else {
                (bool sent,) =
                    payable(msg.sender).call{value: calculatedAmount}("");
                require(sent, "Failed to transfer ETH");
            }
        } else {
            uint256 initialSenderBalance = address(this).balance;
            if (_sellToken != address(0)) {
                initialSenderBalance = IERC20(sellToken).balanceOf(msg.sender);
                IERC20(sellToken).safeTransferFrom(
                    msg.sender, address(this), approvalAmount
                );
            }

            (, IBatchRouter.SwapPathExactAmountOut[] memory buyPath) =
            prepareERC4626SellOrBuy(
                pool,
                sellToken,
                buyToken,
                specifiedAmount,
                kind,
                outputAddress,
                true
            );

            uint256[] memory amountsIn;
            if (_sellToken == address(0)) {
                (,, amountsIn) = router.swapExactOut{value: approvalAmount}(
                    buyPath, type(uint256).max, false, bytes("")
                );
            } else {
                (,, amountsIn) = router.swapExactOut(
                    buyPath, type(uint256).max, false, bytes("")
                );
            }

            calculatedAmount = amountsIn[0];

            if (_buyToken != address(0)) {
                IERC20(buyToken).safeTransfer(msg.sender, specifiedAmount);
            } else {
                (bool sent,) =
                    payable(msg.sender).call{value: specifiedAmount}("");
                require(sent, "Failed to transfer ETH");
            }

            // transfer back sellToken to sender
            if (_sellToken != address(0)) {
                IERC20(sellToken).safeTransfer(
                    msg.sender, initialSenderBalance - calculatedAmount
                );
            } else {
                (bool sent,) = payable(msg.sender).call{
                    value: initialSenderBalance - calculatedAmount
                }("");
                require(sent, "Failed to transfer ETH");
            }
        }
    }

    function getAmountOutERC4626AndERC20(
        address pool,
        address sellToken,
        address buyToken,
        uint256 specifiedAmount,
        ERC4626_SWAP_TYPE kind,
        address outputAddress
    ) internal returns (uint256 calculatedAmount) {
        (IBatchRouter.SwapPathExactAmountIn[] memory paths,) =
        prepareERC4626SellOrBuy(
            pool,
            sellToken,
            buyToken,
            specifiedAmount,
            kind,
            outputAddress,
            false
        );
        (,, uint256[] memory amountsOut) =
            router.querySwapExactIn(paths, address(0), bytes(""));
        calculatedAmount = amountsOut[0];
    }

    function getLimitsERC4626AndERC20(
        bytes32 poolId,
        address sellToken,
        address buyToken,
        ERC4626_SWAP_TYPE kind,
        address outputAddress
    ) internal view returns (uint256[] memory limits) {
        limits = new uint256[](2);
        address pool = address(bytes20(poolId));
        (IERC20[] memory tokens,, uint256[] memory balancesRaw,) =
            vault.getPoolTokenInfo(pool);

        uint256 tokenLimit;

        if (kind == ERC4626_SWAP_TYPE.SWAP_WRAP) {
            for (uint256 i = 0; i < tokens.length; i++) {
                address token = address(tokens[i]);
                if (token == sellToken) {
                    limits[0] = balancesRaw[i] * RESERVE_LIMIT_FACTOR / 10;
                }

                if (token == IERC4626(buyToken).asset()) {
                    tokenLimit = balancesRaw[i] * RESERVE_LIMIT_FACTOR / 10;
                }
            }
            limits[1] = IERC4626(buyToken).previewDeposit(tokenLimit);
        } else if (kind == ERC4626_SWAP_TYPE.SWAP_UNWRAP) {
            for (uint256 i = 0; i < tokens.length; i++) {
                address token = address(tokens[i]);
                if (token == sellToken) {
                    limits[0] = balancesRaw[i] * RESERVE_LIMIT_FACTOR / 10;
                } else if (token == outputAddress) {
                    tokenLimit = balancesRaw[i] * RESERVE_LIMIT_FACTOR / 10;
                }
            }
            limits[1] = IERC4626(outputAddress).previewRedeem(tokenLimit);
        } else if (kind == ERC4626_SWAP_TYPE.WRAP_SWAP) {
            for (uint256 i = 0; i < tokens.length; i++) {
                address token = address(tokens[i]);

                if (token == outputAddress) {
                    limits[0] = IERC4626(outputAddress).previewRedeem(
                        balancesRaw[i] * RESERVE_LIMIT_FACTOR / 10
                    );
                }

                if (token == buyToken) {
                    limits[1] = balancesRaw[i] * RESERVE_LIMIT_FACTOR / 10;
                }
            }
        } else if (kind == ERC4626_SWAP_TYPE.UNWRAP_SWAP) {
            for (uint256 i = 0; i < tokens.length; i++) {
                address token = address(tokens[i]);

                if (token == buyToken) {
                    limits[1] = balancesRaw[i] * RESERVE_LIMIT_FACTOR / 10;
                }

                if (token == IERC4626(sellToken).asset()) {
                    limits[0] = IERC4626(sellToken).previewDeposit(
                        balancesRaw[i] * RESERVE_LIMIT_FACTOR / 10
                    );
                }
            }
        }
    }
}
