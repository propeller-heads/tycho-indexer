// SPDX-License-Identifier: AGPL-3.0-or-later
pragma experimental ABIEncoderV2;
pragma solidity ^0.8.13;

import {ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from
    "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title Etherfi Adapter
/// @dev This contract supports the following swaps: ETH->eETH, weETH<->eETH,
/// ETH->weETH
contract EtherfiAdapter is ISwapAdapter {
    using SafeERC20 for IERC20;

    uint256 constant PRECISE_UNIT = 10 ** 18;

    IWeEth immutable weEth;
    IeEth immutable eEth;
    ILiquidityPool immutable liquidityPool;

    constructor(address _weEth) {
        weEth = IWeEth(_weEth);
        eEth = weEth.eETH();
        liquidityPool = eEth.liquidityPool();
    }

    /// @dev Check if swap between provided sellToken and buyToken are supported
    /// by this adapter
    modifier checkInputTokens(address sellToken, address buyToken) {
        if (sellToken == buyToken) {
            revert Unavailable(
                "This pool only supports ETH->eETH, weETH<->eETH and ETH->weETH swaps"
            );
        }
        if (
            sellToken != address(weEth) && sellToken != address(eEth)
                && sellToken != address(0)
        ) {
            revert Unavailable(
                "This pool only supports ETH->eETH, weETH<->eETH and ETH->weETH swaps"
            );
        }
        if (buyToken != address(weEth) && buyToken != address(eEth)) {
            revert Unavailable(
                "This pool only supports ETH->eETH, weETH<->eETH and ETH->weETH swaps"
            );
        }
        _;
    }

    /// @dev enable receive as this contract supports ETH
    receive() external payable {}

    /// @inheritdoc ISwapAdapter
    function price(
        bytes32,
        address sellToken,
        address buyToken,
        uint256[] memory specifiedAmounts
    )
        external
        view
        override
        checkInputTokens(sellToken, buyToken)
        returns (Fraction[] memory prices)
    {
        prices = new Fraction[](specifiedAmounts.length);
        uint256 totalPooledEther = liquidityPool.getTotalPooledEther();
        uint256 eEthTotalShares = eEth.totalShares();

        for (uint256 i = 0; i < specifiedAmounts.length; i++) {
            if (sellToken == address(0)) {
                uint256 sharesForDepositAmount = _sharesForDepositAmount(
                    specifiedAmounts[i], totalPooledEther, eEthTotalShares
                );
                prices[i] = getPriceAt(
                    sellToken,
                    buyToken,
                    specifiedAmounts[i],
                    totalPooledEther + specifiedAmounts[i],
                    eEthTotalShares + sharesForDepositAmount
                );
            } else {
                prices[i] = getPriceAt(
                    sellToken,
                    buyToken,
                    specifiedAmounts[i],
                    totalPooledEther,
                    eEthTotalShares
                );
            }
        }
    }

    /// @inheritdoc ISwapAdapter
    function swap(
        bytes32,
        address sellToken,
        address buyToken,
        OrderSide side,
        uint256 specifiedAmount,
        bytes32
    )
        external
        override
        checkInputTokens(sellToken, buyToken)
        returns (Trade memory trade)
    {
        if (specifiedAmount == 0) {
            return trade;
        }
        uint256 gasBefore = gasleft();
        if (sellToken == address(0)) {
            if (buyToken == address(eEth)) {
                trade.calculatedAmount = swapEthForEeth(specifiedAmount, side);
            } else {
                trade.calculatedAmount = swapEthForWeEth(specifiedAmount, side);
            }
        } else {
            if (sellToken == address(eEth)) {
                trade.calculatedAmount = swapEethForWeEth(specifiedAmount, side);
            } else {
                trade.calculatedAmount = swapWeEthForEeth(specifiedAmount, side);
            }
        }
        trade.gasUsed = gasBefore - gasleft();

        /// @dev as the price is constant for all the traded amounts and depends
        /// only on the totalPooledEther and totalShares, we can use a standard
        /// amount(PRECISE_UNIT) to render a well-formatted price without
        /// precisions loss
        trade.price = getPriceAt(
            sellToken,
            buyToken,
            PRECISE_UNIT,
            liquidityPool.getTotalPooledEther(),
            eEth.totalShares()
        );
    }

    /// @inheritdoc ISwapAdapter
    function getLimits(bytes32, address sellToken, address buyToken)
        external
        view
        override
        checkInputTokens(sellToken, buyToken)
        returns (uint256[] memory limits)
    {
        limits = new uint256[](2);

        /// @dev Limits are underestimated to 90% of totalSupply as both weEth
        /// and eEth have no limits but revert in some cases
        if (sellToken == address(weEth) || buyToken == address(weEth)) {
            limits[0] = IERC20(address(weEth)).totalSupply() * 90 / 100;
        } else {
            limits[0] = IERC20(address(eEth)).totalSupply() * 90 / 100;
        }
        limits[1] = limits[0];
    }

    /// @inheritdoc ISwapAdapter
    function getCapabilities(bytes32, address, address)
        external
        pure
        override
        returns (Capability[] memory capabilities)
    {
        capabilities = new Capability[](3);
        capabilities[0] = Capability.SellOrder;
        capabilities[1] = Capability.BuyOrder;
        capabilities[2] = Capability.PriceFunction;
    }

    /// @inheritdoc ISwapAdapter
    function getTokens(bytes32)
        external
        view
        override
        returns (address[] memory tokens)
    {
        tokens = new address[](3);
        tokens[0] = address(0);
        tokens[1] = address(eEth);
        tokens[2] = address(weEth);
    }

    /// @inheritdoc ISwapAdapter
    function getPoolIds(uint256, uint256)
        external
        view
        override
        returns (bytes32[] memory ids)
    {
        ids = new bytes32[](1);
        ids[0] = bytes20(address(liquidityPool));
    }

    /// @notice Swap ETH for eETH
    /// @param amount amountIn or amountOut depending on side
    function swapEthForEeth(uint256 amount, OrderSide side)
        internal
        returns (uint256)
    {
        if (side == OrderSide.Buy) {
            uint256 amountIn = getAmountIn(address(0), address(eEth), amount);
            liquidityPool.deposit{value: amountIn}();
            IERC20(address(eEth)).safeTransfer(address(msg.sender), amount);
            return amountIn;
        } else {
            uint256 receivedAmount = liquidityPool.deposit{value: amount}();
            uint256 balBeforeUser =
                IERC20(address(eEth)).balanceOf(address(msg.sender));
            IERC20(address(eEth)).safeTransfer(msg.sender, receivedAmount);
            return IERC20(address(eEth)).balanceOf(address(msg.sender))
                - balBeforeUser;
        }
    }

    /// @notice Swap ETH for weEth
    /// @param amount amountIn or amountOut depending on side
    function swapEthForWeEth(uint256 amount, OrderSide side)
        internal
        returns (uint256)
    {
        IERC20 eEth_ = IERC20(address(eEth));
        if (side == OrderSide.Buy) {
            uint256 amountIn = getAmountIn(address(0), address(weEth), amount);

            uint256 receivedAmountEeth =
                liquidityPool.deposit{value: amountIn}();
            eEth_.safeIncreaseAllowance(address(weEth), receivedAmountEeth);
            uint256 receivedAmount = weEth.wrap(receivedAmountEeth);

            IERC20(address(weEth)).safeTransfer(
                address(msg.sender), receivedAmount
            );

            return amountIn;
        } else {
            uint256 receivedAmountEeth = liquidityPool.deposit{value: amount}();
            eEth_.safeIncreaseAllowance(address(weEth), receivedAmountEeth);
            uint256 receivedAmount = weEth.wrap(receivedAmountEeth);

            IERC20(address(weEth)).safeTransfer(
                address(msg.sender), receivedAmount
            );

            return receivedAmount;
        }
    }

    /// @notice Swap eETH for weETH
    /// @param amount amountIn or amountOut depending on side
    function swapEethForWeEth(uint256 amount, OrderSide side)
        internal
        returns (uint256)
    {
        if (side == OrderSide.Buy) {
            uint256 amountIn =
                getAmountIn(address(eEth), address(weEth), amount);
            IERC20(address(eEth)).safeTransferFrom(
                msg.sender, address(this), amountIn
            );
            IERC20(address(eEth)).safeIncreaseAllowance(
                address(weEth), amountIn
            );

            uint256 receivedAmount = weEth.wrap(amountIn);

            IERC20(address(weEth)).safeTransfer(
                address(msg.sender), receivedAmount
            );

            return amountIn;
        } else {
            IERC20(address(eEth)).safeTransferFrom(
                msg.sender, address(this), amount
            );
            IERC20(address(eEth)).safeIncreaseAllowance(address(weEth), amount);
            uint256 receivedAmount = weEth.wrap(amount);

            IERC20(address(weEth)).safeTransfer(
                address(msg.sender), receivedAmount
            );
            return receivedAmount;
        }
    }

    /// @notice Swap weETH for eEth
    /// @param amount amountIn or amountOut depending on side
    function swapWeEthForEeth(uint256 amount, OrderSide side)
        internal
        returns (uint256)
    {
        if (side == OrderSide.Buy) {
            uint256 amountIn =
                getAmountIn(address(weEth), address(eEth), amount);
            IERC20(address(weEth)).safeTransferFrom(
                msg.sender, address(this), amountIn
            );
            uint256 receivedAmount = weEth.unwrap(amountIn);
            IERC20(address(eEth)).safeTransfer(
                address(msg.sender), receivedAmount
            );
            return amountIn;
        } else {
            IERC20(address(weEth)).safeTransferFrom(
                msg.sender, address(this), amount
            );
            uint256 receivedAmount = weEth.unwrap(amount);
            uint256 balBeforeUser =
                IERC20(address(eEth)).balanceOf(address(msg.sender));
            IERC20(address(eEth)).safeTransfer(msg.sender, receivedAmount);
            return IERC20(address(eEth)).balanceOf(address(msg.sender))
                - balBeforeUser;
        }
    }

    /// @dev copy of '_sharesForDepositAmount' internal function in
    /// LiquidityPool, without ether subtraction
    function _sharesForDepositAmount(
        uint256 _depositAmount,
        uint256 _totalPooledEther,
        uint256 _eEthTotalShares
    ) internal pure returns (uint256) {
        if (_totalPooledEther == 0) {
            return _depositAmount;
        }
        return (_depositAmount * _eEthTotalShares) / _totalPooledEther;
    }

    /// @dev copy of 'getWeETHByeEth' function in weETH, dynamic
    function _getWeETHByeEth(
        uint256 _depositAmount,
        uint256 _totalPooledEther,
        uint256 _eEthTotalShares
    ) internal pure returns (uint256) {
        if (_totalPooledEther == 0) {
            return 0;
        }
        return (_depositAmount * _eEthTotalShares) / _totalPooledEther;
    }

    /// @dev copy of 'getEethByWeEth' function in weETH, dynamic
    function _getEethByWeEth(
        uint256 _depositAmount,
        uint256 _totalPooledEther,
        uint256 _eEthTotalShares
    ) internal pure returns (uint256) {
        if (_eEthTotalShares == 0) {
            return 0;
        }
        return (_depositAmount * _totalPooledEther) / _eEthTotalShares;
    }

    /// @notice Get swap price
    /// @param sellToken token to sell
    /// @param buyToken token to buy
    /// @param totalPooledEther total pooled ether after or before trade if
    /// required
    /// @param eEthTotalShares total shares of eETH after or before trade if
    /// required
    function getPriceAt(
        address sellToken,
        address buyToken,
        uint256 amount,
        uint256 totalPooledEther,
        uint256 eEthTotalShares
    ) internal view returns (Fraction memory) {
        if (sellToken == address(0)) {
            if (buyToken == address(eEth)) {
                return Fraction(
                    _sharesForDepositAmount(
                        amount, totalPooledEther, eEthTotalShares
                    ),
                    amount
                );
            } else {
                uint256 eEthOut = _sharesForDepositAmount(
                    amount, totalPooledEther, eEthTotalShares
                );
                return Fraction(
                    _getWeETHByeEth(
                        eEthOut,
                        totalPooledEther + amount,
                        eEthTotalShares + eEthOut
                    ),
                    amount
                );
            }
        } else if (sellToken == address(eEth)) {
            return Fraction(
                _getWeETHByeEth(amount, totalPooledEther, eEthTotalShares),
                amount
            );
        } else {
            return Fraction(
                _getEethByWeEth(amount, totalPooledEther, eEthTotalShares),
                amount
            );
        }
    }

    /// @notice Get amountIn for swap functions with OrderSide buy
    function getAmountIn(address sellToken, address buyToken, uint256 amountOut)
        internal
        view
        returns (uint256)
    {
        if (sellToken == address(0)) {
            if (buyToken == address(eEth)) {
                return liquidityPool.amountForShare(amountOut);
            } else {
                uint256 ethRequiredForEeth =
                    liquidityPool.amountForShare(amountOut);
                return liquidityPool.amountForShare(ethRequiredForEeth);
            }
        } else if (sellToken == address(eEth)) {
            // eEth-weEth
            return weEth.getEETHByWeETH(amountOut);
        } else {
            // weEth-eEth
            return weEth.getWeETHByeETH(amountOut);
        }
    }
}

interface ILiquidityPool {
    function numPendingDeposits() external view returns (uint32);
    function totalValueOutOfLp() external view returns (uint128);
    function totalValueInLp() external view returns (uint128);
    function getTotalEtherClaimOf(address _user)
        external
        view
        returns (uint256);
    function getTotalPooledEther() external view returns (uint256);
    function sharesForAmount(uint256 _amount) external view returns (uint256);
    function sharesForWithdrawalAmount(uint256 _amount)
        external
        view
        returns (uint256);
    function amountForShare(uint256 _share) external view returns (uint256);

    function deposit() external payable returns (uint256);
    function deposit(address _referral) external payable returns (uint256);
    function deposit(address _user, address _referral)
        external
        payable
        returns (uint256);

    function requestWithdraw(address recipient, uint256 amount)
        external
        returns (uint256);
}

interface IeEth {
    function liquidityPool() external view returns (ILiquidityPool);

    function totalShares() external view returns (uint256);

    function shares(address _user) external view returns (uint256);
}

interface IWeEth {
    function eETH() external view returns (IeEth);

    function getWeETHByeETH(uint256 _eETHAmount)
        external
        view
        returns (uint256);

    function getEETHByWeETH(uint256 _weETHAmount)
        external
        view
        returns (uint256);

    function wrap(uint256 _eETHAmount) external returns (uint256);

    function unwrap(uint256 _weETHAmount) external returns (uint256);
}
