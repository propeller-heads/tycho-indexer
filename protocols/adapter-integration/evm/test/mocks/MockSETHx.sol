// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol";
import "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract MockSETHx is ERC4626 {
    bool public isBufferInitialized;

    constructor(IERC20 _asset) ERC4626(_asset) ERC20("Staked ETHx", "sETHx") {}

    function _decimals() internal pure returns (uint8) {
        return 18;
    }

    // Override convertToShares to implement 1:1 conversion for testing
    function convertToShares(uint256 assets)
        public
        view
        virtual
        override
        returns (uint256)
    {
        return assets;
    }

    // Override convertToAssets to implement 1:1 conversion for testing
    function convertToAssets(uint256 shares)
        public
        view
        virtual
        override
        returns (uint256)
    {
        return shares;
    }
}
