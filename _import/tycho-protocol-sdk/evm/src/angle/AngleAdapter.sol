// SPDX-License-Identifier: AGPL-3.0-or-later
pragma experimental ABIEncoderV2;
pragma solidity ^0.8.13;

/// @dev Wrapped imports (incl. ISwapAdapter and IERC20) are included in utils
import "./AngleUtils.sol";

/// @title AngleAdapter
/// @dev Information about prices: When swapping collateral to agEUR, the trade price will not decrease(amountOut);
/// Instead, when swapping agEUR to collateral, it will, because agEUR is minted, and this mechanism is used to
/// stabilize the agEUR price.
contract AngleAdapter is ISwapAdapter {

    ITransmuter transmuter;

    constructor(ITransmuter _transmuter) {
        transmuter = _transmuter;
    }

    /// @inheritdoc ISwapAdapter
    function price(
        bytes32,
        IERC20 _sellToken,
        IERC20 _buyToken,
        uint256[] memory _specifiedAmounts
    ) external view override returns (Fraction[] memory _prices) {
        _prices = new Fraction[](_specifiedAmounts.length);
        address sellTokenAddress = address(_sellToken);
        address buyTokenAddress = address(_buyToken);

        for (uint256 i = 0; i < _specifiedAmounts.length; i++) {
            _prices[i] = getPriceAt(_specifiedAmounts[i], sellTokenAddress, buyTokenAddress, OrderSide.Sell);
        }
    }

    /// @inheritdoc ISwapAdapter
    function swap(
        bytes32 poolId,
        IERC20 sellToken,
        IERC20 buyToken,
        OrderSide side,
        uint256 specifiedAmount
    ) external returns (Trade memory trade) {
        if (specifiedAmount == 0) {
            return trade;
        }

        uint256 gasBefore = gasleft();
        if (side == OrderSide.Sell) {
            trade.calculatedAmount =
                sell(sellToken, buyToken, specifiedAmount);
        } else {
            trade.calculatedAmount =
                buy(sellToken, buyToken, specifiedAmount);
        }
        trade.price = getPriceAt(specifiedAmount, address(sellToken), address(buyToken), side);
        trade.gasUsed = gasBefore - gasleft();
    }

    /// @inheritdoc ISwapAdapter
    /// @dev mint may have no limits, but we underestimate them to make sure, with the same amount of sellToken.
    /// We use the quoteIn (incl. fee), because calculating fee requires a part of the implementation of
    /// the Angle Diamond Storage, and therefore redundant functions and excessive contract size, with an high complexity.
    /// In addition, we underestimate to / RESERVE_LIMIT_FACTOR to ensure swaps with OrderSide.Buy won't fail anyway.
    function getLimits(bytes32, IERC20 sellToken, IERC20 buyToken)
        external
        view
        override
        returns (uint256[] memory limits)
    {
        limits = new uint256[](2);
        address sellTokenAddress = address(sellToken);
        address buyTokenAddress = address(buyToken);
        address transmuterAddress = address(transmuter);

        if(buyTokenAddress == transmuter.agToken()) { // mint(buy agToken)
            Collateral memory collatInfo = transmuter.getCollateralInfo(sellTokenAddress);
            if(collatInfo.isManaged > 0) {
                limits[0] = LibManager.maxAvailable(collatInfo.managerData.config);
            }
            else {
                limits[0] = sellToken.balanceOf(transmuterAddress);
            }
            limits[1] = transmuter.quoteIn(limits[0], sellTokenAddress, buyTokenAddress);
            limits[1] = limits[1] / RESERVE_LIMIT_FACTOR;
            limits[0] = limits[0] / RESERVE_LIMIT_FACTOR;
        }
        else { // burn(sell agToken)
            Collateral memory collatInfo = transmuter.getCollateralInfo(buyTokenAddress);
            uint256 collatLimit;
            if(collatInfo.isManaged > 0) {
                collatLimit = LibManager.maxAvailable(collatInfo.managerData.config);
            }
            else {
                collatLimit = buyToken.balanceOf(transmuterAddress);
            }
            limits[0] = transmuter.quoteIn(collatLimit, buyTokenAddress, sellTokenAddress);
            limits[1] = collatLimit / RESERVE_LIMIT_FACTOR;
            limits[0] = limits[0] / RESERVE_LIMIT_FACTOR;
        }
    }

    function getCapabilities(bytes32 poolId, IERC20 sellToken, IERC20 buyToken)
        external
        returns (Capability[] memory capabilities)
    {
        revert NotImplemented("TemplateSwapAdapter.getCapabilities");
    }

    /// @inheritdoc ISwapAdapter
    /// @dev Since Angle has no pool IDs but supports 3 tokens(agToken and the collaterals),
    /// we return all the available collaterals and the agToken(agEUR)
    function getTokens(bytes32)
        external
        view
        override
        returns (IERC20[] memory tokens)
    {
        address[] memory collateralsAddresses = transmuter.getCollateralList();
        tokens = new IERC20[](collateralsAddresses.length + 1);
        for(uint256 i = 0; i < collateralsAddresses.length; i++) {
            tokens[i] = IERC20(collateralsAddresses[i]);
        }
        tokens[collateralsAddresses.length] = IERC20(transmuter.agToken());
    }

    function getPoolIds(uint256, uint256)
        external
        pure
        override
        returns (bytes32[] memory)
    {
        revert NotImplemented("AngleAdapter.getPoolIds");
    }

    /// @notice Calculates pool prices for specified amounts
    /// @param amount The amount of the token being sold(if side == Sell) or bought(if side == Buy)
    /// @param tokenIn The token being sold
    /// @param tokenOut The token being bought
    /// @param side Order side
    /// @return The price as a fraction corresponding to the provided amount.
    function getPriceAt(uint256 amount, address tokenIn, address tokenOut, OrderSide side)
        internal
        view
        returns (Fraction memory)
    {
        uint256 amountOut;
        uint256 amountIn;
        if(side == OrderSide.Sell) {
            amountIn = amount;
            amountOut = transmuter.quoteIn(amountIn, tokenIn, tokenOut);
        }
        else {
            amountOut = amount;
            amountIn = transmuter.quoteOut(amount, tokenIn, tokenOut);
        }
        return Fraction(
            amountOut,
            amountIn
        );
    }

    /// @notice Executes a sell order on the contract.
    /// @param sellToken The token being sold.
    /// @param buyToken The token being bought.
    /// @param amount The amount to be traded.
    /// @return calculatedAmount The amount of tokens received.
    function sell(
        IERC20 sellToken,
        IERC20 buyToken,
        uint256 amount
    ) internal returns (uint256 calculatedAmount) {
        address sellTokenAddress = address(sellToken);
        address buyTokenAddress = address(buyToken);
        uint256 amountOut = transmuter.quoteIn(amount, sellTokenAddress, buyTokenAddress);

        // TODO: use safeTransferFrom
        sellToken.transferFrom(msg.sender, address(this), amount);
        sellToken.approve(address(transmuter), amount);
        transmuter.swapExactInput(amount, 0, sellTokenAddress, buyTokenAddress, msg.sender, 0);
        return amountOut;
    }

    /// @notice Executes a buy order on the contract.
    /// @param sellToken The token being sold.
    /// @param buyToken The token being bought.
    /// @param amountOut The amount of buyToken to receive.
    /// @return calculatedAmount The amount of tokens received.
    function buy(
        IERC20 sellToken,
        IERC20 buyToken,
        uint256 amountOut
    ) internal returns (uint256 calculatedAmount) {
        address sellTokenAddress = address(sellToken);
        address buyTokenAddress = address(buyToken);
        uint256 amountIn = transmuter.quoteOut(amountOut, sellTokenAddress, buyTokenAddress);

        // TODO: use safeTransferFrom
        sellToken.transferFrom(msg.sender, address(this), amountIn);
        sellToken.approve(address(transmuter), amountIn);
        transmuter.swapExactOutput(amountOut, type(uint256).max, sellTokenAddress, buyTokenAddress, msg.sender, 0);
        return amountIn;
    }
}

abstract contract ITransmuter {

    function implementation() external view returns (address) {}

    function setDummyImplementation(address _implementation) external {}

    function facetAddress(bytes4 _functionSelector) external view returns (address facetAddress_) {}

    function facetAddresses() external view returns (address[] memory facetAddresses_) {}

    function facetFunctionSelectors(address _facet) external view returns (bytes4[] memory _facetFunctionSelectors) {}

    function accessControlManager() external view returns (address) {}

    function agToken() external view returns (address) {}

    function getCollateralBurnFees(
        address collateral
    ) external view returns (uint64[] memory xFeeBurn, int64[] memory yFeeBurn) {}

    function getCollateralDecimals(address collateral) external view returns (uint8) {}

    function getCollateralInfo(address collateral) external view returns (Collateral memory) {}

    function getCollateralList() external view returns (address[] memory) {}

    function getCollateralMintFees(
        address collateral
    ) external view returns (uint64[] memory xFeeMint, int64[] memory yFeeMint) {}

    function getCollateralRatio() external view returns (uint64 collatRatio, uint256 stablecoinsIssued) {}

    function getCollateralWhitelistData(address collateral) external view returns (bytes memory) {}

    function getIssuedByCollateral(
        address collateral
    ) external view returns (uint256 stablecoinsFromCollateral, uint256 stablecoinsIssued) {}

    function getManagerData(address collateral) external view returns (bool, address[] memory, bytes memory) {}

    function getOracle(
        address collateral
    ) external view returns (uint8 oracleType, uint8 targetType, bytes memory oracleData, bytes memory targetData) {}

    function getOracleValues(
        address collateral
    ) external view returns (uint256 mint, uint256 burn, uint256 ratio, uint256 minRatio, uint256 redemption) {}

    function getRedemptionFees()
        external
        view
        returns (uint64[] memory xRedemptionCurve, int64[] memory yRedemptionCurve)
    {}

    function getTotalIssued() external view returns (uint256) {}

    function isPaused(address collateral, uint8 action) external view returns (bool) {}

    function isTrusted(address sender) external view returns (bool) {}

    function isTrustedSeller(address sender) external view returns (bool) {}

    function isValidSelector(bytes4 selector) external view returns (bool) {}

    function isWhitelistedCollateral(address collateral) external view returns (bool) {}

    function isWhitelistedForCollateral(address collateral, address sender) external returns (bool) {}

    function isWhitelistedForType(uint8 whitelistType, address sender) external view returns (bool) {}

    function sellRewards(uint256 minAmountOut, bytes memory payload) external returns (uint256 amountOut) {}

    function addCollateral(address collateral) external {}

    function adjustStablecoins(address collateral, uint128 amount, bool increase) external {}

    function changeAllowance(address token, address spender, uint256 amount) external {}

    function recoverERC20(address collateral, address token, address to, uint256 amount) external {}

    function revokeCollateral(address collateral) external {}

    function setAccessControlManager(address _newAccessControlManager) external {}

    function setOracle(address collateral, bytes memory oracleConfig) external {}

    function setWhitelistStatus(address collateral, uint8 whitelistStatus, bytes memory whitelistData) external {}

    function toggleTrusted(address sender, uint8 t) external {}

    function setFees(address collateral, uint64[] memory xFee, int64[] memory yFee, bool mint) external {}

    function setRedemptionCurveParams(uint64[] memory xFee, int64[] memory yFee) external {}

    function togglePause(address collateral, uint8 pausedType) external {}

    function toggleWhitelist(uint8 whitelistType, address who) external {}

    function quoteIn(uint256 amountIn, address tokenIn, address tokenOut) external view returns (uint256 amountOut) {}

    function quoteOut(uint256 amountOut, address tokenIn, address tokenOut) external view returns (uint256 amountIn) {}

    function swapExactInput(
        uint256 amountIn,
        uint256 amountOutMin,
        address tokenIn,
        address tokenOut,
        address to,
        uint256 deadline
    ) external returns (uint256 amountOut) {}

    function swapExactInputWithPermit(
        uint256 amountIn,
        uint256 amountOutMin,
        address tokenIn,
        address to,
        uint256 deadline,
        bytes memory permitData
    ) external returns (uint256 amountOut) {}

    function swapExactOutput(
        uint256 amountOut,
        uint256 amountInMax,
        address tokenIn,
        address tokenOut,
        address to,
        uint256 deadline
    ) external returns (uint256 amountIn) {}

    function swapExactOutputWithPermit(
        uint256 amountOut,
        uint256 amountInMax,
        address tokenIn,
        address to,
        uint256 deadline,
        bytes memory permitData
    ) external returns (uint256 amountIn) {}

    function quoteRedemptionCurve(
        uint256 amount
    ) external view returns (address[] memory tokens, uint256[] memory amounts) {}

    function redeem(
        uint256 amount,
        address receiver,
        uint256 deadline,
        uint256[] memory minAmountOuts
    ) external returns (address[] memory tokens, uint256[] memory amounts) {}

    function redeemWithForfeit(
        uint256 amount,
        address receiver,
        uint256 deadline,
        uint256[] memory minAmountOuts,
        address[] memory forfeitTokens
    ) external returns (address[] memory tokens, uint256[] memory amounts) {}

    function updateNormalizer(uint256 amount, bool increase) external returns (uint256) {}
}
