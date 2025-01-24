// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

library Swap {
    /// Returns the InToken index into an array of tokens
    function tokenInIndex(bytes calldata swap)
        internal
        pure
        returns (uint8 res)
    {
        res = uint8(swap[0]);
    }

    /// The OutToken index into an array of tokens
    function tokenOutIndex(bytes calldata swap)
        internal
        pure
        returns (uint8 res)
    {
        res = uint8(swap[1]);
    }

    /// The relative amount of token quantity routed into this swap
    function splitPercentage(bytes calldata swap)
        internal
        pure
        returns (uint24 res)
    {
        res = uint24(bytes3(swap[2:5]));
    }

    /// Remaining bytes are interpreted as protocol data
    function protocolData(bytes calldata swap)
        internal
        pure
        returns (bytes calldata res)
    {
        res = swap[5:];
    }
}
