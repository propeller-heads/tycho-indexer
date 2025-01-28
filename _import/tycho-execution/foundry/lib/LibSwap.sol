// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

library LibSwap {
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

    /// The address of the executor contract
    function executor(bytes calldata swap)
        internal
        pure
        returns (address res)
    {
        res = address(uint160(bytes20(swap[5:25])));
    }

    /// The selector to be used of the executor contract
    function executorSelector(bytes calldata swap)
        internal
        pure
        returns (bytes4 res)
    {
        res = bytes4(swap[25:29]);
    }

    /// Remaining bytes are interpreted as protocol data
    function protocolData(bytes calldata swap)
        internal
        pure
        returns (bytes calldata res)
    {
        res = swap[29:];
    }
}
