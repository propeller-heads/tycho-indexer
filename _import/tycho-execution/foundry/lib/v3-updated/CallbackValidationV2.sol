// Updated v3 lib to solidity >=0.7.6

// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity >=0.7.6;

import "./PoolAddressV2.sol";
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";

/// @notice Provides validation for callbacks from Uniswap V3 Pools
library CallbackValidationV2 {
    /// @notice Returns the address of a valid Uniswap V3 Pool
    /// @param factory The contract address of the Uniswap V3 factory
    /// @param tokenA The contract address of either token0 or token1
    /// @param tokenB The contract address of the other token
    /// @param fee The fee collected upon every swap in the pool, denominated in hundredths of a bip
    /// @return pool The V3 pool contract address
    function verifyCallback(
        address factory,
        address tokenA,
        address tokenB,
        uint24 fee,
        bytes32 initCode
    ) internal view returns (IUniswapV3Pool pool) {
        return
            verifyCallback(
                factory,
                PoolAddressV2.getPoolKey(tokenA, tokenB, fee),
                initCode
            );
    }

    /// @notice Returns the address of a valid Uniswap V3 Pool
    /// @param factory The contract address of the Uniswap V3 factory
    /// @param poolKey The identifying key of the V3 pool
    /// @return pool The V3 pool contract address
    function verifyCallback(
        address factory,
        PoolAddressV2.PoolKey memory poolKey,
        bytes32 initCode
    ) internal view returns (IUniswapV3Pool pool) {
        pool = IUniswapV3Pool(PoolAddressV2.computeAddress(factory, poolKey, initCode));
        require(msg.sender == address(pool), "CV");
    }
}
