// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

library LibSwap {
    /**
     * @dev Returns arguments required to perform a single swap
     */
    function decodeSingleSwap(bytes calldata swap)
        internal
        pure
        returns (address executor, bytes calldata protocolData)
    {
        executor = address(uint160(bytes20(swap[0:20])));
        protocolData = swap[20:];
    }

    /**
     * @dev Returns arguments required to perform a sequential swap
     */
    function decodeSequentialSwap(bytes calldata swap)
        internal
        pure
        returns (address executor, bytes calldata protocolData)
    {
        executor = address(uint160(bytes20(swap[0:20])));
        protocolData = swap[20:];
    }

    /**
     * @dev Returns arguments required to perform a split swap
     */
    function decodeSplitSwap(bytes calldata swap)
        internal
        pure
        returns (uint8 tokenInIndex, uint8 tokenOutIndex, uint24 split, address executor, bytes calldata protocolData)
    {
        tokenInIndex = uint8(swap[0]);
        tokenOutIndex = uint8(swap[1]);
        split = uint24(bytes3(swap[2:5]));
        executor = address(uint160(bytes20(swap[5:25])));
        protocolData = swap[25:];
    }

    /**
    * @dev Returns executor
     */
    function decodeExecutor(bytes calldata swap)
    internal
    pure
    returns (address executor)
    {
        executor = address(uint160(bytes20(swap[0:20])));
    }

    /**
     * @dev Returns target of the swap assuming that it is in the first position.
     */
    function decodeTarget(bytes calldata swap)
    internal
    pure
    returns (address target)
    {
        target = address(uint160(bytes20(swap[20:40])));
    }
}
