// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";

library UniswapV4Utils {
    function encodeExactInputSingle(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        address receiver,
        bool zeroForOne,
        uint24 tickSpacing,
        uint128 amountIn
    ) public pure returns (bytes memory) {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(zeroForOne ? tokenIn : tokenOut),
            currency1: Currency.wrap(zeroForOne ? tokenOut : tokenIn),
            fee: fee,
            tickSpacing: int24(tickSpacing),
            hooks: IHooks(address(0))
        });

        bytes memory actions = abi.encodePacked(
            uint8(Actions.SWAP_EXACT_IN_SINGLE),
            uint8(Actions.SETTLE_ALL),
            uint8(Actions.TAKE)
        );

        bytes[] memory params = new bytes[](3);

        params[0] = abi.encode(
            IV4Router.ExactInputSingleParams({
                poolKey: key,
                zeroForOne: zeroForOne,
                amountIn: amountIn,
                amountOutMinimum: 0,
                hookData: bytes("")
            })
        );

        params[1] = abi.encode(key.currency0, amountIn);
        params[2] = abi.encode(key.currency1, receiver, 0);

        return abi.encode(actions, params);
    }
}
