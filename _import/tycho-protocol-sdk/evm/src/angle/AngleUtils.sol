// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
  * @dev Collection of wrapped interfaces, items and libraries for Angle
  * we use them here to maintain integrity and readability of contracts
  * as there are many different imports and items
 */

import {IERC20, ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";

/// @dev custom reserve limit factor to prevent revert errors in OrderSide.Buy
uint256 constant RESERVE_LIMIT_FACTOR = 5;

interface IAgToken is IERC20 {
    /*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                              MINTER ROLE ONLY FUNCTIONS                                            
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

    /// @notice Lets a whitelisted contract mint agTokens
    /// @param account Address to mint to
    /// @param amount Amount to mint
    function mint(address account, uint256 amount) external;

    /// @notice Burns `amount` tokens from a `burner` address after being asked to by `sender`
    /// @param amount Amount of tokens to burn
    /// @param burner Address to burn from
    /// @param sender Address which requested the burn from `burner`
    /// @dev This method is to be called by a contract with the minter right after being requested
    /// to do so by a `sender` address willing to burn tokens from another `burner` address
    /// @dev The method checks the allowance between the `sender` and the `burner`
    function burnFrom(uint256 amount, address burner, address sender) external;

    /// @notice Burns `amount` tokens from a `burner` address
    /// @param amount Amount of tokens to burn
    /// @param burner Address to burn from
    /// @dev This method is to be called by a contract with a minter right on the AgToken after being
    /// requested to do so by an address willing to burn tokens from its address
    function burnSelf(uint256 amount, address burner) external;

    /*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                TREASURY ONLY FUNCTIONS                                             
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

    /// @notice Adds a minter in the contract
    /// @param minter Minter address to add
    /// @dev Zero address checks are performed directly in the `Treasury` contract
    function addMinter(address minter) external;

    /// @notice Removes a minter from the contract
    /// @param minter Minter address to remove
    /// @dev This function can also be called by a minter wishing to revoke itself
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
    IERC20[] subCollaterals;                     // Subtokens handled by the manager or strategies
    bytes config;                                // Additional configuration data
}

struct Collateral {
    uint8 isManaged;                             // If the collateral is managed through external strategies
    uint8 isMintLive;                            // If minting from this asset is unpaused
    uint8 isBurnLive;                            // If burning to this asset is unpaused
    uint8 decimals;                              // IERC20Metadata(collateral).decimals()
    uint8 onlyWhitelisted;                       // If only whitelisted addresses can burn or redeem for this token
    uint216 normalizedStables;                   // Normalized amount of stablecoins issued from this collateral
    uint64[] xFeeMint;                           // Increasing exposures in [0,BASE_9[
    int64[] yFeeMint;                            // Mint fees at the exposures specified in `xFeeMint`
    uint64[] xFeeBurn;                           // Decreasing exposures in ]0,BASE_9]
    int64[] yFeeBurn;                            // Burn fees at the exposures specified in `xFeeBurn`
    bytes oracleConfig;                          // Data about the oracle used for the collateral
    bytes whitelistData;                         // For whitelisted collateral, data used to verify whitelists
    ManagerStorage managerData;                  // For managed collateral, data used to handle the strategies
}

struct TransmuterStorage {
    IAgToken agToken;                            // agToken handled by the system
    uint8 isRedemptionLive;                      // If redemption is unpaused
    uint8 statusReentrant;                        // If call is reentrant or not
    uint128 normalizedStables;                   // Normalized amount of stablecoins issued by the system
    uint128 normalizer;                          // To reconcile `normalizedStables` values with the actual amount
    address[] collateralList;                    // List of collateral assets supported by the system
    uint64[] xRedemptionCurve;                   // Increasing collateral ratios > 0
    int64[] yRedemptionCurve;                    // Value of the redemption fees at `xRedemptionCurve`
    mapping(address => Collateral) collaterals;  // Maps a collateral asset to its parameters
    mapping(address => uint256) isTrusted;       // If an address is trusted to update the normalizer value
    mapping(address => uint256) isSellerTrusted; // If an address is trusted to sell accruing reward tokens
    mapping(WhitelistType => mapping(address => uint256)) isWhitelistedForType;
}

interface IManager {
    /// @notice Returns the amount of collateral managed by the Manager
    /// @return balances Balances of all the subCollaterals handled by the manager
    /// @dev MUST NOT revert
    function totalAssets() external view returns (uint256[] memory balances, uint256 totalValue);

    /// @notice Hook to invest `amount` of `collateral`
    /// @dev MUST revert if the manager cannot accept these funds
    /// @dev MUST have received the funds beforehand
    function invest(uint256 amount) external;

    /// @notice Sends `amount` of `collateral` to the `to` address
    /// @dev Called when `agToken` are burnt and during redemptions
    //  @dev MUST revert if there are not funds enough available
    /// @dev MUST be callable only by the transmuter
    function release(address asset, address to, uint256 amount) external;

    /// @notice Gives the maximum amount of collateral immediately available for a transfer
    /// @dev Useful for integrators using `quoteIn` and `quoteOut`
    function maxAvailable() external view returns (uint256);
}

/// @title LibManager
/// @author Angle Labs, Inc.
/// @dev Managed collateral assets may be handled through external smart contracts or directly through this library
/// @dev There is no implementation at this point for a managed collateral handled through this library, and
/// a new specific `ManagerType` would need to be added in this case
library LibManager {
    /// @notice Checks to which address managed funds must be transferred
    function transferRecipient(bytes memory config) internal view returns (address recipient) {
        (ManagerType managerType, bytes memory data) = parseManagerConfig(config);
        recipient = address(this);
        if (managerType == ManagerType.EXTERNAL) return abi.decode(data, (address));
    }

    /// @notice Performs a transfer of `token` for a collateral that is managed to a `to` address
    /// @dev `token` may not be the actual collateral itself, as some collaterals have subcollaterals associated
    /// with it
    /// @dev Eventually pulls funds from strategies
    function release(address token, address to, uint256 amount, bytes memory config) internal {
        (ManagerType managerType, bytes memory data) = parseManagerConfig(config);
        if (managerType == ManagerType.EXTERNAL) abi.decode(data, (IManager)).release(token, to, amount);
    }

    /// @notice Gets the balances of all the tokens controlled through `managerData`
    /// @return balances An array of size `subCollaterals` with current balances of all subCollaterals
    /// including the one corresponding to the `managerData` given
    /// @return totalValue The value of all the `subCollaterals` in `collateral`
    /// @dev `subCollaterals` must always have as first token (index 0) the collateral itself
    function totalAssets(bytes memory config) internal view returns (uint256[] memory balances, uint256 totalValue) {
        (ManagerType managerType, bytes memory data) = parseManagerConfig(config);
        if (managerType == ManagerType.EXTERNAL) return abi.decode(data, (IManager)).totalAssets();
    }

    /// @notice Calls a hook if needed after new funds have been transfered to a manager
    function invest(uint256 amount, bytes memory config) internal {
        (ManagerType managerType, bytes memory data) = parseManagerConfig(config);
        if (managerType == ManagerType.EXTERNAL) abi.decode(data, (IManager)).invest(amount);
    }

    /// @notice Returns available underlying tokens, for instance if liquidity is fully used and
    /// not withdrawable the function will return 0
    function maxAvailable(bytes memory config) internal view returns (uint256 available) {
        (ManagerType managerType, bytes memory data) = parseManagerConfig(config);
        if (managerType == ManagerType.EXTERNAL) return abi.decode(data, (IManager)).maxAvailable();
    }

    /// @notice Decodes the `managerData` associated to a collateral
    function parseManagerConfig(
        bytes memory config
    ) internal pure returns (ManagerType managerType, bytes memory data) {
        (managerType, data) = abi.decode(config, (ManagerType, bytes));
    }
}
