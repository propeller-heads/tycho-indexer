// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

using {extension} for Config global;

// address (20 bytes) | fee (8 bytes) | tickSpacing (4 bytes)
type Config is bytes32;

// Each pool has its own state associated with this key
struct PoolKey {
    address token0;
    address token1;
    Config config;
}

function extension(Config config) pure returns (address e) {
    assembly ("memory-safe") {
        e := shr(96, config)
    }
}
