// SPDX-License-Identifier: AGPL-3.0-or-later
pragma experimental ABIEncoderV2;
pragma solidity ^0.8.13;

import {ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from
    "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from
    "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

/// @dev custom reserve limit factor to prevent revert errors in OrderSide.Buy
uint256 constant RESERVE_LIMIT_FACTOR = 10;
uint256 constant STANDARD_TOKEN_DECIMALS = 10 ** 18;

/// @title AngleAdapter
/// @dev Information about prices: When swapping collateral to agEUR, the trade
/// price will not decrease(amountOut). Instead, when swapping agEUR to
/// collateral, it will, because agEUR is minted, and this mechanism is used to
/// stabilize the agEUR price.
contract AngleAdapter is ISwapAdapter {
    using SafeERC20 for IERC20;

    ITransmuter immutable transmuter;

    constructor(ITransmuter _transmuter) {
        transmuter = _transmuter;
    }

    /// @inheritdoc ISwapAdapter
    /**
     * @dev It is not possible to reproduce the swap in a view mode (like
     * Bancor, Uniswap v2, etc..) as the swap produce a change of storage in
     * the Angle protocol, that impacts the price post trade. Due to the
     * architecture of Angle, it's not possible to calculate the storage
     * modifications of Angle inside the adapter.
     */
    function price(bytes32, address, address, uint256[] memory)
        external
        pure
        override
        returns (Fraction[] memory)
    {
        revert NotImplemented("AngleAdapter.price");
    }

    /// @inheritdoc ISwapAdapter
    /**
     * @dev The price post trade is indipendent by the amount, since is the
     * price with minimal fees with 0 slippage. In Angle there is no price with
     * 0 slippage, so we use the PRECISE_UNIT (10^18, that is a small value) as
     * input amount to have a slippage ---> 0.
     */
    function swap(
        bytes32,
        address sellToken,
        address buyToken,
        OrderSide side,
        uint256 specifiedAmount
    ) external returns (Trade memory trade) {
        if (specifiedAmount == 0) {
            return trade;
        }

        uint256 gasBefore = gasleft();
        if (side == OrderSide.Sell) {
            trade.calculatedAmount = sell(sellToken, buyToken, specifiedAmount);
        } else {
            trade.calculatedAmount = buy(sellToken, buyToken, specifiedAmount);
        }
        trade.gasUsed = gasBefore - gasleft();
        uint8 decimals = side == OrderSide.Sell
            ? IERC20Metadata(sellToken).decimals()
            : IERC20Metadata(buyToken).decimals();
        trade.price =
            getPriceAt(sellToken, buyToken, side, decimals);
    }

    /// @inheritdoc ISwapAdapter
    /// @dev Mint may have no limits, but we underestimate them to make sure,
    /// with the same amount of sellToken. We use the quoteIn (incl. fee),
    /// because calculating fee requires a part of the implementation of the
    /// Angle Diamond Storage, and therefore redundant functions and excessive
    /// contract size, with an high complexity. In addition, we underestimate to
    /// RESERVE_LIMIT_FACTOR to ensure swaps with OrderSide.Buy won't fail
    /// anyway.
    function getLimits(bytes32, address sellToken, address buyToken)
        external
        view
        override
        returns (uint256[] memory limits)
    {
        limits = new uint256[](2);
        address transmuterAddress = address(transmuter);

        if (buyToken == transmuter.agToken()) {
            // mint(buy agToken)
            Collateral memory collatInfo =
                transmuter.getCollateralInfo(sellToken);
            if (collatInfo.isManaged > 0) {
                limits[0] =
                    LibManager.maxAvailable(collatInfo.managerData.config);
            } else {
                limits[0] = IERC20(sellToken).balanceOf(transmuterAddress);
            }
            limits[1] =
                transmuter.quoteIn(limits[0], sellToken, buyToken);
            limits[1] = limits[1] / RESERVE_LIMIT_FACTOR;
            limits[0] = limits[0] / RESERVE_LIMIT_FACTOR;
        } else {
            // burn(sell agToken)
            Collateral memory collatInfo =
                transmuter.getCollateralInfo(buyToken);
            if (collatInfo.isManaged > 0) {
                limits[1] =
                    LibManager.maxAvailable(collatInfo.managerData.config);
            } else {
                limits[1] = IERC20(buyToken).balanceOf(transmuterAddress);
            }
            limits[0] =
                transmuter.quoteIn(limits[1], buyToken, sellToken);
            limits[1] = limits[1] / RESERVE_LIMIT_FACTOR;
            limits[0] = limits[0] / RESERVE_LIMIT_FACTOR;
        }
    }

    /// @inheritdoc ISwapAdapter
    function getCapabilities(bytes32, address, address)
        external
        pure
        override
        returns (Capability[] memory capabilities)
    {
        capabilities = new Capability[](2);
        capabilities[0] = Capability.SellOrder;
        capabilities[1] = Capability.BuyOrder;
    }

    /// @inheritdoc ISwapAdapter
    /// @dev Since Angle has no pool IDs but supports 3 tokens(agToken and the
    /// collaterals), we return all the available collaterals and the
    /// agToken(agEUR)
    function getTokens(bytes32)
        external
        view
        override
        returns (address[] memory tokens)
    {
        address[] memory collateralsAddresses = transmuter.getCollateralList();
        tokens = new address[](collateralsAddresses.length + 1);
        for (uint256 i = 0; i < collateralsAddresses.length; i++) {
            tokens[i] = address(collateralsAddresses[i]);
        }
        tokens[collateralsAddresses.length] = transmuter.agToken();
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
    /// @param tokenIn The token being sold
    /// @param tokenOut The token being bought
    /// @param side Order side
    /// @param decimals Decimals of the sell token
    /// @return The price as a fraction corresponding to the provided amount.
    function getPriceAt(
        address tokenIn,
        address tokenOut,
        OrderSide side,
        uint8 decimals
    ) internal view returns (Fraction memory) {
        uint256 amountOut;
        uint256 amountIn;
        if (side == OrderSide.Sell) {
            amountIn = 10 ** decimals;
            amountOut = transmuter.quoteIn(amountIn, tokenIn, tokenOut);
        } else {
            amountOut = 10 ** decimals;
            amountIn = transmuter.quoteOut(amountOut, tokenIn, tokenOut);
        }
        return Fraction(amountOut, amountIn);
    }

    /// @notice Executes a sell order on the contract.
    /// @param sellToken The token being sold.
    /// @param buyToken The token being bought.
    /// @param amount The amount to be traded.
    /// @return calculatedAmount The amount of tokens received.
    function sell(address sellToken, address buyToken, uint256 amount)
        internal
        returns (uint256 calculatedAmount)
    {
        IERC20(sellToken).safeTransferFrom(msg.sender, address(this), amount);
        IERC20(sellToken).approve(address(transmuter), amount);
        calculatedAmount = transmuter.swapExactInput(
            amount, 0, sellToken, buyToken, msg.sender, 0
        );
    }

    /// @notice Executes a buy order on the contract.
    /// @param sellToken The token being sold.
    /// @param buyToken The token being bought.
    /// @param amountOut The amount of buyToken to receive.
    /// @return calculatedAmount The amount of tokens received.
    function buy(address sellToken, address buyToken, uint256 amountOut)
        internal
        returns (uint256 calculatedAmount)
    {
        calculatedAmount =
            transmuter.quoteOut(amountOut, sellToken, buyToken);

        IERC20(sellToken).safeTransferFrom(msg.sender, address(this), calculatedAmount);
        IERC20(sellToken).approve(address(transmuter), calculatedAmount);
        transmuter.swapExactOutput(
            amountOut,
            type(uint256).max,
            sellToken,
            buyToken,
            msg.sender,
            0
        );
    }
}

interface IAgToken is IERC20 {
    /*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    MINTER ROLE ONLY FUNCTIONS                                            
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

    /// @notice Lets a whitelisted contract mint agTokens
    /// @param account Address to mint to
    /// @param amount Amount to mint
    function mint(address account, uint256 amount) external;

    /// @notice Burns `amount` tokens from a `burner` address after being asked
    /// to by `sender`
    /// @param amount Amount of tokens to burn
    /// @param burner Address to burn from
    /// @param sender Address which requested the burn from `burner`
    /// @dev This method is to be called by a contract with the minter right
    /// after being requested
    /// to do so by a `sender` address willing to burn tokens from another
    /// `burner` address
    /// @dev The method checks the allowance between the `sender` and the
    /// `burner`
    function burnFrom(uint256 amount, address burner, address sender)
        external;

    /// @notice Burns `amount` tokens from a `burner` address
    /// @param amount Amount of tokens to burn
    /// @param burner Address to burn from
    /// @dev This method is to be called by a contract with a minter right on
    /// the AgToken after being
    /// requested to do so by an address willing to burn tokens from its address
    function burnSelf(uint256 amount, address burner) external;

    /*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    TREASURY ONLY FUNCTIONS                                             
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

    /// @notice Adds a minter in the contract
    /// @param minter Minter address to add
    /// @dev Zero address checks are performed directly in the `Treasury`
    /// contract
    function addMinter(address minter) external;

    /// @notice Removes a minter from the contract
    /// @param minter Minter address to remove
    /// @dev This function can also be called by a minter wishing to revoke
    /// itself
    function removeMinter(address minter) external;

    /// @notice Sets a new treasury contract
    /// @param _treasury New treasury address
    function setTreasury(address _treasury) external;

    /*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    EXTERNAL FUNCTIONS                                                
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

    /// @notice Checks whether an address has the right to mint agTokens
    /// @param minter Address for which the minting right should be checked
    /// @return Whether the address has the right to mint agTokens or not
    function isMinter(address minter) external view returns (bool);

    /// @notice Amount of decimals of the stablecoin
    function decimals() external view returns (uint8);
}

enum ManagerType {
    EXTERNAL
}

enum WhitelistType {
    BACKED
}

struct ManagerStorage {
    IERC20[] subCollaterals; // Subtokens handled by the manager or strategies
    bytes config; // Additional configuration data
}

struct Collateral {
    uint8 isManaged; // If the collateral is managed through external strategies
    uint8 isMintLive; // If minting from this asset is unpaused
    uint8 isBurnLive; // If burning to this asset is unpaused
    uint8 decimals; // IERC20Metadata(collateral).decimals()
    uint8 onlyWhitelisted; // If only whitelisted addresses can burn or redeem
        // for this token
    uint216 normalizedStables; // Normalized amount of stablecoins issued from
        // this collateral
    uint64[] xFeeMint; // Increasing exposures in [0,BASE_9[
    int64[] yFeeMint; // Mint fees at the exposures specified in `xFeeMint`
    uint64[] xFeeBurn; // Decreasing exposures in ]0,BASE_9]
    int64[] yFeeBurn; // Burn fees at the exposures specified in `xFeeBurn`
    bytes oracleConfig; // Data about the oracle used for the collateral
    bytes whitelistData; // For whitelisted collateral, data used to verify
        // whitelists
    ManagerStorage managerData; // For managed collateral, data used to handle
        // the strategies
}

struct TransmuterStorage {
    IAgToken agToken; // agToken handled by the system
    uint8 isRedemptionLive; // If redemption is unpaused
    uint8 statusReentrant; // If call is reentrant or not
    uint128 normalizedStables; // Normalized amount of stablecoins issued by the
        // system
    uint128 normalizer; // To reconcile `normalizedStables` values with the
        // actual amount
    address[] collateralList; // List of collateral assets supported by the
        // system
    uint64[] xRedemptionCurve; // Increasing collateral ratios > 0
    int64[] yRedemptionCurve; // Value of the redemption fees at
        // `xRedemptionCurve`
    mapping(address => Collateral) collaterals; // Maps a collateral asset to
        // its parameters
    mapping(address => uint256) isTrusted; // If an address is trusted to update
        // the normalizer value
    mapping(address => uint256) isSellerTrusted; // If an address is trusted to
        // sell accruing reward tokens
    mapping(WhitelistType => mapping(address => uint256)) isWhitelistedForType;
}

interface IManager {
    /// @notice Returns the amount of collateral managed by the Manager
    /// @return balances Balances of all the subCollaterals handled by the
    /// manager
    /// @dev MUST NOT revert
    function totalAssets()
        external
        view
        returns (uint256[] memory balances, uint256 totalValue);

    /// @notice Hook to invest `amount` of `collateral`
    /// @dev MUST revert if the manager cannot accept these funds
    /// @dev MUST have received the funds beforehand
    function invest(uint256 amount) external;

    /// @notice Sends `amount` of `collateral` to the `to` address
    /// @dev Called when `agToken` are burnt and during redemptions
    //  @dev MUST revert if there are not funds enough available
    /// @dev MUST be callable only by the transmuter
    function release(address asset, address to, uint256 amount) external;

    /// @notice Gives the maximum amount of collateral immediately available for
    /// a transfer
    /// @dev Useful for integrators using `quoteIn` and `quoteOut`
    function maxAvailable() external view returns (uint256);
}

/// @title LibManager
/// @author Angle Labs, Inc.
/// @dev Managed collateral assets may be handled through external smart
/// contracts or directly through this library
/// @dev There is no implementation at this point for a managed collateral
/// handled through this library, and
/// a new specific `ManagerType` would need to be added in this case
library LibManager {
    /// @notice Checks to which address managed funds must be transferred
    function transferRecipient(bytes memory config)
        internal
        view
        returns (address recipient)
    {
        (ManagerType managerType, bytes memory data) =
            parseManagerConfig(config);
        recipient = address(this);
        if (managerType == ManagerType.EXTERNAL) {
            return abi.decode(data, (address));
        }
    }

    /// @notice Performs a transfer of `token` for a collateral that is managed
    /// to a `to` address
    /// @dev `token` may not be the actual collateral itself, as some
    /// collaterals have subcollaterals associated
    /// with it
    /// @dev Eventually pulls funds from strategies
    function release(
        address token,
        address to,
        uint256 amount,
        bytes memory config
    ) internal {
        (ManagerType managerType, bytes memory data) =
            parseManagerConfig(config);
        if (managerType == ManagerType.EXTERNAL) {
            abi.decode(data, (IManager)).release(token, to, amount);
        }
    }

    /// @notice Gets the balances of all the tokens controlled through
    /// `managerData`
    /// @return balances An array of size `subCollaterals` with current balances
    /// of all subCollaterals
    /// including the one corresponding to the `managerData` given
    /// @return totalValue The value of all the `subCollaterals` in `collateral`
    /// @dev `subCollaterals` must always have as first token (index 0) the
    /// collateral itself
    function totalAssets(bytes memory config)
        internal
        view
        returns (uint256[] memory balances, uint256 totalValue)
    {
        (ManagerType managerType, bytes memory data) =
            parseManagerConfig(config);
        if (managerType == ManagerType.EXTERNAL) {
            return abi.decode(data, (IManager)).totalAssets();
        }
    }

    /// @notice Calls a hook if needed after new funds have been transfered to a
    /// manager
    function invest(uint256 amount, bytes memory config) internal {
        (ManagerType managerType, bytes memory data) =
            parseManagerConfig(config);
        if (managerType == ManagerType.EXTERNAL) {
            abi.decode(data, (IManager)).invest(amount);
        }
    }

    /// @notice Returns available underlying tokens, for instance if liquidity
    /// is fully used and
    /// not withdrawable the function will return 0
    function maxAvailable(bytes memory config)
        internal
        view
        returns (uint256 available)
    {
        (ManagerType managerType, bytes memory data) =
            parseManagerConfig(config);
        if (managerType == ManagerType.EXTERNAL) {
            return abi.decode(data, (IManager)).maxAvailable();
        }
    }

    /// @notice Decodes the `managerData` associated to a collateral
    function parseManagerConfig(bytes memory config)
        internal
        pure
        returns (ManagerType managerType, bytes memory data)
    {
        (managerType, data) = abi.decode(config, (ManagerType, bytes));
    }
}

interface ITransmuter {
    function implementation() external view returns (address);

    function setDummyImplementation(address _implementation) external;

    function facetAddress(bytes4 _functionSelector)
        external
        view
        returns (address facetAddress_);

    function facetAddresses()
        external
        view
        returns (address[] memory facetAddresses_);

    function facetFunctionSelectors(address _facet)
        external
        view
        returns (bytes4[] memory _facetFunctionSelectors);

    function accessControlManager() external view returns (address);

    function agToken() external view returns (address);

    function getCollateralBurnFees(address collateral)
        external
        view
        returns (uint64[] memory xFeeBurn, int64[] memory yFeeBurn);

    function getCollateralDecimals(address collateral)
        external
        view
        returns (uint8);

    function getCollateralInfo(address collateral)
        external
        view
        returns (Collateral memory);

    function getCollateralList() external view returns (address[] memory);

    function getCollateralMintFees(address collateral)
        external
        view
        returns (uint64[] memory xFeeMint, int64[] memory yFeeMint);

    function getCollateralRatio()
        external
        view
        returns (uint64 collatRatio, uint256 stablecoinsIssued);

    function getCollateralWhitelistData(address collateral)
        external
        view
        returns (bytes memory);

    function getIssuedByCollateral(address collateral)
        external
        view
        returns (uint256 stablecoinsFromCollateral, uint256 stablecoinsIssued);

    function getManagerData(address collateral)
        external
        view
        returns (bool, address[] memory, bytes memory);

    function getOracle(address collateral)
        external
        view
        returns (
            uint8 oracleType,
            uint8 targetType,
            bytes memory oracleData,
            bytes memory targetData
        );

    function getOracleValues(address collateral)
        external
        view
        returns (
            uint256 mint,
            uint256 burn,
            uint256 ratio,
            uint256 minRatio,
            uint256 redemption
        );

    function getRedemptionFees()
        external
        view
        returns (
            uint64[] memory xRedemptionCurve,
            int64[] memory yRedemptionCurve
        );

    function getTotalIssued() external view returns (uint256);

    function isPaused(address collateral, uint8 action)
        external
        view
        returns (bool);

    function isTrusted(address sender) external view returns (bool);

    function isTrustedSeller(address sender) external view returns (bool);

    function isValidSelector(bytes4 selector) external view returns (bool);

    function isWhitelistedCollateral(address collateral)
        external
        view
        returns (bool);

    function isWhitelistedForCollateral(address collateral, address sender)
        external
        returns (bool);

    function isWhitelistedForType(uint8 whitelistType, address sender)
        external
        view
        returns (bool);

    function sellRewards(uint256 minAmountOut, bytes memory payload)
        external
        returns (uint256 amountOut);

    function addCollateral(address collateral) external;

    function adjustStablecoins(
        address collateral,
        uint128 amount,
        bool increase
    ) external;

    function changeAllowance(address token, address spender, uint256 amount)
        external;

    function recoverERC20(
        address collateral,
        address token,
        address to,
        uint256 amount
    ) external;

    function revokeCollateral(address collateral) external;

    function setAccessControlManager(address _newAccessControlManager)
        external;

    function setOracle(address collateral, bytes memory oracleConfig)
        external;

    function setWhitelistStatus(
        address collateral,
        uint8 whitelistStatus,
        bytes memory whitelistData
    ) external;

    function toggleTrusted(address sender, uint8 t) external;

    function setFees(
        address collateral,
        uint64[] memory xFee,
        int64[] memory yFee,
        bool mint
    ) external;

    function setRedemptionCurveParams(uint64[] memory xFee, int64[] memory yFee)
        external;

    function togglePause(address collateral, uint8 pausedType) external;

    function toggleWhitelist(uint8 whitelistType, address who) external;

    function quoteIn(uint256 amountIn, address tokenIn, address tokenOut)
        external
        view
        returns (uint256 amountOut);

    function quoteOut(uint256 amountOut, address tokenIn, address tokenOut)
        external
        view
        returns (uint256 amountIn);

    function swapExactInput(
        uint256 amountIn,
        uint256 amountOutMin,
        address tokenIn,
        address tokenOut,
        address to,
        uint256 deadline
    ) external returns (uint256 amountOut);

    function swapExactInputWithPermit(
        uint256 amountIn,
        uint256 amountOutMin,
        address tokenIn,
        address to,
        uint256 deadline,
        bytes memory permitData
    ) external returns (uint256 amountOut);

    function swapExactOutput(
        uint256 amountOut,
        uint256 amountInMax,
        address tokenIn,
        address tokenOut,
        address to,
        uint256 deadline
    ) external returns (uint256 amountIn);

    function swapExactOutputWithPermit(
        uint256 amountOut,
        uint256 amountInMax,
        address tokenIn,
        address to,
        uint256 deadline,
        bytes memory permitData
    ) external returns (uint256 amountIn);

    function quoteRedemptionCurve(uint256 amount)
        external
        view
        returns (address[] memory tokens, uint256[] memory amounts);

    function redeem(
        uint256 amount,
        address receiver,
        uint256 deadline,
        uint256[] memory minAmountOuts
    ) external returns (address[] memory tokens, uint256[] memory amounts);

    function redeemWithForfeit(
        uint256 amount,
        address receiver,
        uint256 deadline,
        uint256[] memory minAmountOuts,
        address[] memory forfeitTokens
    ) external returns (address[] memory tokens, uint256[] memory amounts);

    function updateNormalizer(uint256 amount, bool increase)
        external
        returns (uint256);
}
