//SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.26;

import "./BalancerInterfaces.sol";

/**
 * @title Balancer V3 Storage
 */
abstract contract BalancerStorage {
    // Balancer V3 constants
    uint256 constant RESERVE_LIMIT_FACTOR = 3; // 30% as being divided by 10
    uint256 constant SWAP_DEADLINE_SEC = 1000;

    // Balancer V3 contracts
    IVault immutable vault;
    IBatchRouter immutable router;

    // ETH and Wrapped ETH addresses, using ETH as address(0)
    address immutable WETH_ADDRESS;
    address constant ETH_ADDRESS = address(0);

    // permit2 address
    address immutable permit2;

    enum CUSTOM_WRAP_KIND {
        NONE,
        ERC20_TO_ERC20, // swap ERC20 to ERC20, passing through a ERC4626_4626
            // pool
            // pool
        ERC4626_TO_ERC4626 // swap ERC4626 to ERC4626, passing through a
            // ERC20_20_20 pool

    }

    enum ERC4626_SWAP_TYPE {
        NONE,
        SWAP_WRAP,
        SWAP_UNWRAP,
        WRAP_SWAP,
        UNWRAP_SWAP
    }
}
