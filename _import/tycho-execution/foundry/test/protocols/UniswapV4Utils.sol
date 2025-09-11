// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";

library UniswapV4Utils {
    function encodeExactInput(
        address tokenIn,
        address tokenOut,
        bool zeroForOne,
        RestrictTransferFrom.TransferType transferType,
        address receiver,
        address hook,
        bytes memory hookData,
        UniswapV4Executor.UniswapV4Pool[] memory pools
    ) public pure returns (bytes memory) {
        require(pools.length > 0, "Must have at least one pool");

        bytes memory firstPool = abi.encodePacked(
            pools[0].intermediaryToken,
            bytes3(pools[0].fee),
            pools[0].tickSpacing
        );

        bytes[] memory encodedExtraPools = new bytes[](pools.length - 1);
        for (uint256 i = 1; i < pools.length; i++) {
            encodedExtraPools[i - 1] = abi.encodePacked(
                pools[i].intermediaryToken,
                bytes3(pools[i].fee),
                pools[i].tickSpacing
            );
        }

        return abi.encodePacked(
            tokenIn,
            tokenOut,
            zeroForOne,
            transferType,
            receiver,
            hook,
            firstPool,
            pleEncode(encodedExtraPools),
            hookData
        );
    }

    function pleEncode(bytes[] memory data)
        public
        pure
        returns (bytes memory encoded)
    {
        for (uint256 i = 0; i < data.length; i++) {
            encoded = bytes.concat(
                encoded,
                abi.encodePacked(bytes2(uint16(data[i].length)), data[i])
            );
        }
    }
}
